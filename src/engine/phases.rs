use super::Engine;
use crate::cache::CacheEntry;
use crate::config::{Action, Transport};
use crate::engine::observation::{Observed, response_decision_kind};
use crate::engine::response::{extract_ttl, extract_ttl_for_refresh};
use crate::engine::response_log::ResponseInfo;
use crate::engine::rules::{self, ResponseActionResult, ResponseContext};
use crate::engine::types::EngineInner;
use crate::engine::upstream::UpstreamFailure;
use crate::engine::utils::InflightCleanupGuard;
use crate::engine::utils::engine_helpers::{build_response, build_servfail_response_fast};
use crate::matcher::{RuntimeResponseMatcherWithOp, eval_match_chain};
use crate::observe::{CacheHit, CacheHitKind, RuleEvaluated, RuleMatched, RulePhase};
use crate::proto_utils;
use anyhow::Context;
use bytes::{Bytes, BytesMut};
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{DNSClass, Record, RecordType};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

/// Result of the Forward phase
pub enum ForwardResult {
    /// Request completed with a response (bytes)
    Success(Bytes),
    /// Request needs to continue (e.g. Action::Continue)
    /// Boxed to reduce enum size (ResponseContext is ~256 bytes)
    Continue(Box<Option<ResponseContext>>),
}
use hickory_proto::serialize::binary::BinDecodable;

/// Standard cache check logic that replicates `handle_packet_internal`'s behavior.
/// Checks Moka cache, validates TTL, patches response, and triggers background refresh if needed.
/// Immutable cache lookup data shared by normal and refresh-wait paths.
pub struct CacheLookupContext<'a> {
    pub state: &'a Arc<EngineInner>,
    pub qname: &'a str,
    pub qtype: RecordType,
    pub qclass: DNSClass,
    pub pipeline_id: &'a str,
    pub dedupe_hash: u64,
    pub tx_id: u16,
    pub start: Instant,
    pub peer: &'a std::net::SocketAddr,
    /// Observer context of the request; cache hits are reported through it.
    /// 所属请求的观察者上下文；缓存命中通过它上报。
    pub observed: Observed<'a>,
}

/// Does not emit the `dns_response` record; only the engine request path logs it.
/// 不输出 `dns_response` 记录；该记录只由引擎请求路径输出。
pub fn check_cache(engine: &Engine, context: &CacheLookupContext<'_>) -> Option<Bytes> {
    check_cache_logged(engine, context, &mut ResponseInfo::default())
}

pub(crate) fn check_cache_logged(
    engine: &Engine,
    context: &CacheLookupContext<'_>,
    response: &mut ResponseInfo,
) -> Option<Bytes> {
    let CacheLookupContext {
        state,
        qname: qname_ref,
        qtype,
        qclass,
        pipeline_id,
        dedupe_hash,
        tx_id,
        start: _,
        peer,
        observed,
    } = *context;

    // moka 同步缓存自动处理过期，无需检查 expires_at / moka sync cache automatically handles expiration, no need to check expires_at
    if let Some(hit) = engine.cache_get(&dedupe_hash) {
        // Validate hit against query parameters to avoid collisions
        if hit.qtype == u16::from(qtype)
            && hit.pipeline_id.as_ref() == pipeline_id
            && hit.qname.as_ref() == qname_ref
        {
            let elapsed_secs = hit.inserted_at.elapsed().as_secs();

            // Check manual expiration (in case moka hasn't evicted it yet or for strict TTL compliance)
            if elapsed_secs >= hit.original_ttl as u64 {
                // serve_stale disabled → invalidate and miss
                if !state.pipeline.settings.serve_stale {
                    engine.cache_invalidate(&dedupe_hash);
                    return None;
                }
                // Don't serve SERVFAIL/REFUSED as stale
                if hit.rcode == ResponseCode::ServFail || hit.rcode == ResponseCode::Refused {
                    engine.cache_invalidate(&dedupe_hash);
                    return None;
                }

                // Check serve_stale_expire_ttl: how long past original TTL has this been stale?
                // 检查 serve_stale_expire_ttl：此条目已过期多长时间？
                let stale_age = elapsed_secs - hit.original_ttl as u64;
                if state.pipeline.settings.serve_stale_expire_ttl > 0
                    && stale_age > state.pipeline.settings.serve_stale_expire_ttl
                {
                    // Stale entry has exceeded the maximum stale window
                    // 过期条目已超过最大过期窗口
                    engine.cache_invalidate(&dedupe_hash);
                    debug!(
                        event = "serve_stale_expired",
                        qname = %qname_ref,
                        qtype = ?qtype,
                        stale_age = stale_age,
                        serve_stale_expire_ttl = state.pipeline.settings.serve_stale_expire_ttl,
                        "stale entry exceeded serve_stale_expire_ttl, invalidating"
                    );
                    return None;
                }

                // serve_stale_client_timeout_ms > 0: don't serve stale here, let the caller
                // try upstream first with a short timeout (handled in handle_packet_internal).
                // serve_stale_client_timeout_ms > 0: 不在此处返回 stale，
                // 让调用者先尝试上游查询（在 handle_packet_internal 中处理）。
                if state.pipeline.settings.serve_stale_client_timeout_ms > 0 {
                    // Don't invalidate - we still need the stale entry for the client_timeout path.
                    // Spawn background refresh proactively.
                    if hit.upstream.is_some() {
                        engine.spawn_background_refresh(
                            (*state).clone(),
                            dedupe_hash,
                            pipeline_id,
                            qname_ref,
                            qtype,
                            qclass,
                            peer.ip(),
                        );
                    }
                    return None;
                }

                // serve_stale_client_timeout_ms == 0: Serve stale immediately (optimistic mode)
                // RFC 8767: 立即返回 stale 数据 + 后台刷新
                let stale_ttl = state.pipeline.settings.serve_stale_ttl;
                let mut resp_bytes = BytesMut::with_capacity(hit.bytes.len());
                resp_bytes.extend_from_slice(&hit.bytes);

                // Set all TTLs to serve_stale_ttl
                crate::proto_utils::set_all_ttls(&mut resp_bytes, stale_ttl);

                // Rewrite Transaction ID
                if resp_bytes.len() >= 2 {
                    let id_bytes = tx_id.to_be_bytes();
                    resp_bytes[0] = id_bytes[0];
                    resp_bytes[1] = id_bytes[1];
                }

                // serve_stale_ttl_reset: reset stale expiry timer by re-inserting with shifted inserted_at
                // 重置过期计时器：通过重新插入条目并将 inserted_at 设置为"刚过期"的时间点
                if state.pipeline.settings.serve_stale_ttl_reset {
                    let new_entry = hit.clone_with_refreshed_ttl();
                    engine.cache_insert(dedupe_hash, std::sync::Arc::new(new_entry));
                }

                // Trigger background refresh to get fresh data
                if hit.upstream.is_some() {
                    engine.spawn_background_refresh(
                        (*state).clone(),
                        dedupe_hash,
                        pipeline_id,
                        qname_ref,
                        qtype,
                        qclass,
                        peer.ip(),
                    );
                }

                debug!(
                    event = "serve_stale_on_ttl_expiry",
                    qname = %qname_ref,
                    qtype = ?qtype,
                    rcode = ?hit.rcode,
                    original_ttl = hit.original_ttl,
                    elapsed_secs = elapsed_secs,
                    stale_ttl = stale_ttl,
                    stale_age = stale_age,
                    ttl_reset = state.pipeline.settings.serve_stale_ttl_reset,
                    client_ip = %peer.ip(),
                    pipeline = %pipeline_id,
                    "RFC 8767: serving stale cache entry on TTL expiry"
                );

                if let Some((observer, ctx)) = observed {
                    observer.cache_hit(
                        ctx,
                        &CacheHit {
                            kind: CacheHitKind::Stale,
                            remaining_ttl: None,
                            original_ttl: Some(Duration::from_secs(hit.original_ttl as u64)),
                        },
                    );
                }
                response.cache_hit = true;
                response.upstream =
                    Some(hit.upstream.clone().unwrap_or_else(|| Arc::from("static")));
                return Some(resp_bytes.freeze());
            } else {
                // Cache hit is valid

                // clone bytes and rewrite transaction ID to match requester / 克隆字节并重写事务 ID 以匹配请求者
                let mut resp_bytes = BytesMut::with_capacity(hit.bytes.len());
                resp_bytes.extend_from_slice(&hit.bytes);

                // RFC 1035 §5.2: Patch TTL based on residence time / 根据停留时间修正 TTL
                let elapsed = crate::proto_utils::saturating_u64_to_u32(elapsed_secs);
                if elapsed > 0 {
                    crate::proto_utils::patch_all_ttls(&mut resp_bytes, elapsed);
                }

                // Rewrite Transaction ID
                if resp_bytes.len() >= 2 {
                    let id_bytes = tx_id.to_be_bytes();
                    resp_bytes[0] = id_bytes[0];
                    resp_bytes[1] = id_bytes[1];
                }
                let resp_bytes = resp_bytes.freeze();

                // ========== NEW: Trigger background refresh before returning cached response ==========
                let cfg = &state.pipeline;

                let remaining_ttl = hit.refresh_ttl.saturating_sub(elapsed);

                // Check if we should trigger background refresh
                let should_refresh = if cfg.settings.cache_background_refresh
                    && hit.upstream.is_some()
                    && hit.refresh_ttl >= cfg.settings.cache_refresh_min_ttl
                {
                    let threshold = (hit.refresh_ttl as u64
                        * cfg.settings.cache_refresh_threshold_percent as u64)
                        / 100;
                    remaining_ttl as u64 <= threshold
                } else {
                    false
                };

                if should_refresh {
                    // Trigger background refresh asynchronously
                    debug!(
                        event = "cache_background_refresh_trigger",
                        qname = %qname_ref,
                        qtype = ?qtype,
                        remaining_ttl = remaining_ttl,
                        original_ttl = hit.original_ttl,
                        refresh_ttl = hit.refresh_ttl,
                        "Triggering background refresh for cached entry"
                    );

                    engine.spawn_background_refresh(
                        (*state).clone(),
                        dedupe_hash,
                        pipeline_id,
                        qname_ref,
                        qtype,
                        qclass,
                        peer.ip(),
                    );
                }

                response.cache_hit = true;
                response.upstream =
                    Some(hit.upstream.clone().unwrap_or_else(|| Arc::from("static")));

                if let Some((observer, ctx)) = observed {
                    observer.cache_hit(
                        ctx,
                        &CacheHit {
                            kind: CacheHitKind::Fresh,
                            remaining_ttl: Some(Duration::from_secs(
                                hit.original_ttl.saturating_sub(elapsed) as u64,
                            )),
                            original_ttl: Some(Duration::from_secs(hit.original_ttl as u64)),
                        },
                    );
                }
                return Some(resp_bytes);
            }
        }
    }
    None
}

/// RFC 8767: Check if a stale (expired but still in moka) cache entry exists.
/// Returns the stale response bytes with TTL set to serve_stale_ttl.
/// RFC 8767: 检查是否存在过期但仍在 moka 中的缓存条目。
/// 返回 TTL 设置为 serve_stale_ttl 的过期响应字节。
///
/// `kind` names the stale-serving path for the observer (client timeout or
/// upstream failure). / `kind` 标明过期服务的路径（客户端超时或上游失败），用于上报观察者。
///
/// Does not emit the `dns_response` record; only the engine request path logs it.
/// 不输出 `dns_response` 记录；该记录只由引擎请求路径输出。
pub fn check_stale_cache(
    engine: &Engine,
    context: &CacheLookupContext<'_>,
    kind: CacheHitKind,
) -> Option<Bytes> {
    check_stale_cache_logged(engine, context, kind, &mut ResponseInfo::default())
}

pub(crate) fn check_stale_cache_logged(
    engine: &Engine,
    context: &CacheLookupContext<'_>,
    kind: CacheHitKind,
    response: &mut ResponseInfo,
) -> Option<Bytes> {
    let CacheLookupContext {
        state,
        qname: qname_ref,
        qtype,
        qclass,
        pipeline_id,
        dedupe_hash,
        tx_id,
        start: _,
        peer,
        observed,
    } = *context;
    if !state.pipeline.settings.serve_stale {
        return None;
    }

    if let Some(hit) = engine.cache_get(&dedupe_hash)
        && hit.qtype == u16::from(qtype)
        && hit.pipeline_id.as_ref() == pipeline_id
        && hit.qname.as_ref() == qname_ref
    {
        let elapsed_secs = hit.inserted_at.elapsed().as_secs();

        // Only serve stale when TTL has actually expired
        // 仅当 TTL 已过期时才提供 stale 数据
        if elapsed_secs >= hit.original_ttl as u64 {
            // Don't serve SERVFAIL/REFUSED as stale / 不提供 SERVFAIL/REFUSED 作为 stale
            if hit.rcode == ResponseCode::ServFail || hit.rcode == ResponseCode::Refused {
                return None;
            }

            // Check serve_stale_expire_ttl: max stale age window
            // 检查 serve_stale_expire_ttl：过期数据的最大可用窗口
            let stale_age = elapsed_secs - hit.original_ttl as u64;
            if state.pipeline.settings.serve_stale_expire_ttl > 0
                && stale_age > state.pipeline.settings.serve_stale_expire_ttl
            {
                return None;
            }

            let stale_ttl = state.pipeline.settings.serve_stale_ttl;

            let mut resp_bytes = BytesMut::with_capacity(hit.bytes.len());
            resp_bytes.extend_from_slice(&hit.bytes);

            // RFC 8767 §4: Set all TTLs to serve_stale_ttl
            crate::proto_utils::set_all_ttls(&mut resp_bytes, stale_ttl);

            // Rewrite Transaction ID
            if resp_bytes.len() >= 2 {
                let id_bytes = tx_id.to_be_bytes();
                resp_bytes[0] = id_bytes[0];
                resp_bytes[1] = id_bytes[1];
            }

            // serve_stale_ttl_reset: reset stale expiry timer
            // 重置过期计时器
            if state.pipeline.settings.serve_stale_ttl_reset {
                let new_entry = hit.clone_with_refreshed_ttl();
                engine.cache_insert(dedupe_hash, std::sync::Arc::new(new_entry));
            }

            debug!(
                event = "serve_stale",
                qname = %qname_ref,
                qtype = ?qtype,
                rcode = ?hit.rcode,
                original_ttl = hit.original_ttl,
                elapsed_secs = elapsed_secs,
                stale_age = stale_age,
                stale_ttl = stale_ttl,
                client_ip = %peer.ip(),
                pipeline = %pipeline_id,
                "RFC 8767: serving stale cache entry on upstream failure"
            );

            // Also trigger background refresh to try to get fresh data
            // 同时触发后台刷新以尝试获取新数据
            if hit.upstream.is_some() {
                engine.spawn_background_refresh(
                    (*state).clone(),
                    dedupe_hash,
                    pipeline_id,
                    qname_ref,
                    qtype,
                    qclass,
                    peer.ip(),
                );
            }

            if let Some((observer, ctx)) = observed {
                observer.cache_hit(
                    ctx,
                    &CacheHit {
                        kind,
                        remaining_ttl: None,
                        original_ttl: Some(Duration::from_secs(hit.original_ttl as u64)),
                    },
                );
            }
            response.cache_hit = true;
            response.upstream = Some(hit.upstream.clone().unwrap_or_else(|| Arc::from("static")));
            return Some(resp_bytes.freeze());
        }
    }
    None
}
/// Request data required to build and cache a static DNS response.
pub struct StaticDecisionContext<'a> {
    pub packet: &'a [u8],
    pub qname: &'a str,
    pub qtype: RecordType,
    pub pipeline_id: &'a Arc<str>,
    pub dedupe_hash: u64,
    pub min_ttl: Duration,
    pub start: Instant,
    pub peer: &'a std::net::SocketAddr,
    /// Pipeline uses a client_ip matcher: skip dns_cache to avoid cross-client
    /// reuse (rule_cache already isolates by client IP in that case).
    pub uses_client_ip: bool,
}

/// Handles Decision::Static.
/// Parses request, builds response, updates cache, and returns bytes.
/// Does not emit the `dns_response` record; only the engine request path logs it.
/// 不输出 `dns_response` 记录；该记录只由引擎请求路径输出。
pub fn handle_static_decision(
    engine: &Engine,
    context: &StaticDecisionContext<'_>,
    rcode: ResponseCode,
    answers: Vec<Record>,
) -> anyhow::Result<Bytes> {
    let StaticDecisionContext {
        packet,
        qname,
        qtype,
        pipeline_id: current_pipeline_id,
        dedupe_hash,
        min_ttl,
        start: _,
        peer: _,
        uses_client_ip,
    } = *context;
    // Need full request for building response / 需要完整请求来构建响应
    let req = Message::from_bytes(packet).context("parse request for static")?;
    let resp_bytes = build_response(&req, rcode, answers)?;

    // Skip dns_cache when the pipeline matches on client_ip: dedupe_hash has no
    // client dimension, so a cached static answer could leak across clients.
    // rule_cache already caches static decisions with client-IP isolation.
    if !uses_client_ip && min_ttl > Duration::from_secs(0) {
        let ttl = crate::proto_utils::saturating_u64_to_u32(min_ttl.as_secs());
        engine.insert_dns_cache_entry(
            dedupe_hash,
            CacheEntry::from_response(
                resp_bytes.clone(),
                rcode,
                None, // Static responses have no upstream
                qname,
                current_pipeline_id.clone(),
                u16::from(qtype),
                (ttl, ttl),
            ),
        );
    }

    Ok(resp_bytes)
}

/// Handles Decision::Forward.
/// Manages Singleflight, upstream forwarding, response matching, and caching.
pub struct ForwardDecisionContext<'a> {
    pub state: &'a Arc<EngineInner>,
    pub packet: &'a [u8],
    pub qname: &'a str,
    pub qtype: RecordType,
    pub qclass: DNSClass,
    pub tx_id: u16,
    pub pipeline_id: &'a str,
    pub rule_name: &'a str,
    pub dedupe_hash: u64,
    pub min_ttl: Duration,
    pub upstream_timeout: Duration,
    pub start: Instant,
    pub peer: &'a std::net::SocketAddr,
    pub skip_cache: bool,
    pub upstream: &'a str,
    pub pre_split_upstreams: Option<&'a Arc<Vec<Arc<str>>>>,
    pub response_matchers: &'a [RuntimeResponseMatcherWithOp],
    pub response_actions_on_match: &'a [Action],
    pub response_actions_on_miss: &'a [Action],
    pub transport: Option<Transport>,
    pub ecs: Option<&'a crate::config::EcsMode>,
    pub allow_reuse: bool,
    pub reused_response: &'a mut Option<ResponseContext>,
    /// Observer context of the request / 所属请求的观察者上下文
    pub observed: Observed<'a>,
}

/// Does not emit the `dns_response` record; only the engine request path logs it.
/// 不输出 `dns_response` 记录；该记录只由引擎请求路径输出。
pub async fn handle_forward_decision(
    engine: &Engine,
    context: ForwardDecisionContext<'_>,
) -> anyhow::Result<ForwardResult> {
    handle_forward_decision_logged(engine, context, &mut ResponseInfo::default()).await
}

pub(crate) async fn handle_forward_decision_logged(
    engine: &Engine,
    context: ForwardDecisionContext<'_>,
    response: &mut ResponseInfo,
) -> anyhow::Result<ForwardResult> {
    let ForwardDecisionContext {
        state,
        packet,
        qname,
        qtype,
        qclass,
        tx_id,
        pipeline_id,
        rule_name,
        dedupe_hash,
        min_ttl,
        upstream_timeout,
        start,
        peer,
        skip_cache,
        upstream,
        pre_split_upstreams,
        response_matchers,
        response_actions_on_match,
        response_actions_on_miss,
        transport,
        ecs,
        allow_reuse,
        reused_response,
        observed,
    } = context;

    response.upstream = Some(Arc::from(upstream));
    // ECS request rewriting (RFC 7871): modify outgoing packet before forwarding.
    // Only runs on cache-miss path — cache hits and static responses are unaffected.
    //
    // ECS 请求改写 (RFC 7871)：在转发前修改出站包。
    // 仅在缓存未命中路径执行 — 缓存命中和静态响应不受影响。
    let ecs_packet: std::borrow::Cow<[u8]> = match ecs {
        Some(mode) => {
            let modified = crate::ecs::apply_ecs(packet, mode, peer.ip());
            tracing::debug!(
                ecs_mode = ?mode,
                modified = modified.len() != packet.len(),
                "ECS request rewriting applied / 已应用 ECS 请求改写"
            );
            std::borrow::Cow::Owned(modified)
        }
        None => std::borrow::Cow::Borrowed(packet),
    };
    let packet = ecs_packet.as_ref();

    let mut cleanup_guard = None;

    let resp = if allow_reuse {
        if let Some(ctx) = reused_response.take() {
            Ok((ctx.raw, ctx.upstream.to_string()))
        } else {
            if !skip_cache {
                use dashmap::mapref::entry::Entry;
                let rx = match engine.inflight.entry(dedupe_hash) {
                    Entry::Vacant(entry) => {
                        let (tx, _rx) =
                            tokio::sync::watch::channel(Err(Arc::new(anyhow::anyhow!("Pending"))));
                        entry.insert(tx);
                        cleanup_guard = Some(InflightCleanupGuard::new(
                            engine.inflight.clone(),
                            dedupe_hash,
                        ));
                        None
                    }
                    Entry::Occupied(entry) => {
                        let rx = entry.get().subscribe();
                        Some(rx)
                    }
                };

                if let Some(mut rx) = rx
                    && rx.changed().await.is_ok()
                {
                    let result = rx.borrow().clone();
                    match &result {
                        Ok(bytes) => {
                            let mut resp_mut = BytesMut::from(bytes.as_ref());
                            if resp_mut.len() >= 2 {
                                let id_bytes = tx_id.to_be_bytes();
                                resp_mut[0] = id_bytes[0];
                                resp_mut[1] = id_bytes[1];
                            }
                            response.upstream = Some(Arc::from("inflight"));
                            return Ok(ForwardResult::Success(resp_mut.freeze()));
                        }
                        Err(e) => return Err(anyhow::anyhow!("{}", e)),
                    }
                }
            }
            crate::engine::upstream::forward_upstream(
                engine,
                packet,
                upstream,
                upstream_timeout,
                transport,
                pre_split_upstreams,
                observed,
            )
            .await
        }
    } else {
        if !skip_cache {
            use dashmap::mapref::entry::Entry;
            let rx = match engine.inflight.entry(dedupe_hash) {
                Entry::Vacant(entry) => {
                    let (tx, _rx) =
                        tokio::sync::watch::channel(Err(Arc::new(anyhow::anyhow!("Pending"))));
                    entry.insert(tx);
                    cleanup_guard = Some(InflightCleanupGuard::new(
                        engine.inflight.clone(),
                        dedupe_hash,
                    ));
                    None
                }
                Entry::Occupied(entry) => {
                    let rx = entry.get().subscribe();
                    Some(rx)
                }
            };

            if let Some(mut rx) = rx
                && rx.changed().await.is_ok()
            {
                let result = rx.borrow().clone();
                match &result {
                    Ok(bytes) => {
                        let mut resp_mut = BytesMut::from(bytes.as_ref());
                        if resp_mut.len() >= 2 {
                            let id_bytes = tx_id.to_be_bytes();
                            resp_mut[0] = id_bytes[0];
                            resp_mut[1] = id_bytes[1];
                        }
                        response.upstream = Some(Arc::from("inflight"));
                        return Ok(ForwardResult::Success(resp_mut.freeze()));
                    }
                    Err(e) => return Err(anyhow::anyhow!("{}", e)),
                }
            }
        }
        crate::engine::upstream::forward_upstream(
            engine,
            packet,
            upstream,
            upstream_timeout,
            transport,
            pre_split_upstreams,
            observed,
        )
        .await
    };

    // 被截断的应答改用 TCP 重取一次，取到的结果照常往下走：应答经过响应规则和动作、写进缓存，失败时
    // 走过期缓存和 on_miss 动作。UDP 转发本身已经会用 TCP 重取截断的应答，所以这里只在两种情况下
    // 再试：它拿回的 TCP 应答仍带 TC 位；或者 `tcp+udp://` 上游双发时 TCP 那一路失败，留下了截断的
    // UDP 应答。
    // A truncated answer is fetched once more over TCP, and whatever comes back goes on through
    // everything below: an answer meets the response rules and actions and the cache, a failure
    // the stale cache and the miss actions. The UDP forwarder already fetches truncated answers
    // again over TCP, so this only tries again in two cases: the TCP answer it got still has TC
    // set, or a `tcp+udp://` upstream's TCP leg failed and left the truncated UDP answer.
    let resp = match resp {
        Ok((raw, _))
            if transport == Some(Transport::Udp)
                && state.pipeline.settings.enable_tcp_fallback
                && proto_utils::truncated_response(&raw) =>
        {
            tracing::debug!(event = "tc_flag_retry", upstream = %upstream, "response truncated, retrying with tcp");
            crate::engine::upstream::forward_upstream(
                engine,
                packet,
                upstream,
                upstream_timeout,
                Some(Transport::Tcp),
                pre_split_upstreams,
                observed,
            )
            .await
        }
        resp => resp,
    };

    match resp {
        Ok((raw, actual_upstream)) => {
            response.upstream = Some(Arc::from(actual_upstream.as_str()));
            let (rcode, ttl_secs_cache, ttl_secs_refresh, msg_opt) = if response_matchers.is_empty()
                && response_actions_on_match.is_empty()
                && response_actions_on_miss.is_empty()
            {
                if let Some(qr) = proto_utils::parse_response_quick(&raw) {
                    (qr.rcode, qr.min_ttl as u64, qr.max_ttl as u64, None)
                } else {
                    let msg = Message::from_bytes(&raw).context("parse upstream response")?;
                    let ttl_cache = extract_ttl(&msg);
                    let ttl_refresh = extract_ttl_for_refresh(&msg);
                    (
                        msg.metadata.response_code,
                        ttl_cache,
                        ttl_refresh,
                        Some(msg),
                    )
                }
            } else {
                let msg = Message::from_bytes(&raw).context("parse upstream response")?;
                let ttl_cache = extract_ttl(&msg);
                let ttl_refresh = extract_ttl_for_refresh(&msg);
                (
                    msg.metadata.response_code,
                    ttl_cache,
                    ttl_refresh,
                    Some(msg),
                )
            };

            let effective_ttl = Duration::from_secs(ttl_secs_cache.max(min_ttl.as_secs()));

            // Try to acquire read locks non-blockingly (fast path for concurrent reads)
            // 尝试非阻塞获取读锁（并发读的快速路径）
            let (resp_match_ok, msg) = {
                let mut geoip_manager = engine.geoip_manager.try_read();
                let mut geosite_manager = engine.geosite_manager.try_read();

                // Fallback to blocking read if try_read fails (rare write operation in progress)
                // 如果 try_read 失败则回退到阻塞读取（罕见的写操作进行中）
                if geoip_manager.is_none() || geosite_manager.is_none() {
                    tracing::debug!("GeoIP/GeoSite lock contention, falling back to blocking read");
                    geoip_manager = Some(engine.geoip_manager.read());
                    geosite_manager = Some(engine.geosite_manager.read());
                }

                let geoip_manager_ref = geoip_manager.as_deref();
                let geosite_manager_ref = geosite_manager.as_deref();

                if let Some(m) = msg_opt {
                    if skip_cache {
                        (true, m)
                    } else {
                        let matched = eval_match_chain(
                            response_matchers,
                            |m| m.operator,
                            |matcher_op| {
                                matcher_op.matcher.matches(
                                    upstream,
                                    qname,
                                    qtype,
                                    qclass,
                                    &m,
                                    geoip_manager_ref,
                                    geosite_manager_ref,
                                )
                            },
                        );
                        (matched, m)
                    }
                } else {
                    (
                        false,
                        Message::new(
                            0,
                            hickory_proto::op::MessageType::Query,
                            hickory_proto::op::OpCode::Query,
                        ),
                    )
                }
            };

            if !skip_cache
                && !response_matchers.is_empty()
                && let Some((observer, ctx)) = observed
            {
                observer.rule_evaluated(
                    ctx,
                    &RuleEvaluated {
                        pipeline: pipeline_id,
                        rule: rule_name,
                        phase: RulePhase::Response,
                        matched: resp_match_ok,
                        matchers: response_matchers.len(),
                    },
                );
                if resp_match_ok {
                    observer.rule_matched(
                        ctx,
                        &RuleMatched {
                            pipeline: pipeline_id,
                            rule: rule_name,
                            phase: RulePhase::Response,
                            decision: response_decision_kind(response_actions_on_match),
                            fast_path: false,
                        },
                    );
                }
            }

            let empty_actions = Vec::new();
            let actions_to_run = if skip_cache {
                &empty_actions
            } else if !response_actions_on_match.is_empty() || !response_actions_on_miss.is_empty()
            {
                if resp_match_ok {
                    response_actions_on_match
                } else {
                    response_actions_on_miss
                }
            } else {
                &empty_actions
            };

            if actions_to_run.is_empty() {
                if effective_ttl > Duration::from_secs(0) {
                    let cache_ttl = proto_utils::saturating_u64_to_u32(ttl_secs_cache);
                    let refresh_ttl = proto_utils::saturating_u64_to_u32(ttl_secs_refresh);
                    engine.insert_dns_cache_entry(
                        dedupe_hash,
                        CacheEntry::from_response(
                            raw.clone(),
                            rcode,
                            Some(Arc::from(actual_upstream.as_str())),
                            qname,
                            Arc::from(pipeline_id),
                            u16::from(qtype),
                            (cache_ttl, refresh_ttl),
                        ),
                    );
                }
                if let Some(g) = cleanup_guard.as_mut() {
                    g.defuse();
                }
                engine.notify_inflight_waiters(dedupe_hash, &raw).await;

                return Ok(ForwardResult::Success(raw));
            }

            // Handle Actions
            let req_full = if let Ok(r) = Message::from_bytes(packet) {
                r
            } else {
                Message::new(
                    0,
                    hickory_proto::op::MessageType::Query,
                    hickory_proto::op::OpCode::Query,
                )
            };
            let ctx = ResponseContext {
                raw: raw.clone(),
                msg,
                upstream: Arc::from(actual_upstream.as_str()),
                transport: transport.unwrap_or(Transport::Udp),
            };

            let default_upstream = state.pipeline.settings.default_upstream.as_str();
            let response_jump_limit = state.pipeline.settings.response_jump_limit as usize;

            let ctx = rules::ApplyResponseActionsContext {
                engine,
                actions: actions_to_run,
                ctx_opt: Some(ctx),
                req: &req_full,
                packet,
                upstream_timeout,
                response_matchers,
                qname,
                qtype,
                qclass,
                client_ip: peer.ip(),
                upstream_default: default_upstream,
                pipeline_id,
                rule_name,
                remaining_jumps: response_jump_limit,
            };

            let action_result = rules::apply_response_actions_observed(ctx, observed).await?;

            match action_result {
                ResponseActionResult::Upstream { ctx, resp_match: _ } => {
                    let ttl_secs_cache = extract_ttl(&ctx.msg);
                    let ttl_secs_refresh = extract_ttl_for_refresh(&ctx.msg);
                    let effective_ttl = Duration::from_secs(ttl_secs_cache.max(min_ttl.as_secs()));
                    if effective_ttl > Duration::from_secs(0) {
                        let cache_ttl = proto_utils::saturating_u64_to_u32(ttl_secs_cache);
                        let refresh_ttl = proto_utils::saturating_u64_to_u32(ttl_secs_refresh);
                        engine.insert_dns_cache_entry(
                            dedupe_hash,
                            CacheEntry::from_response(
                                ctx.raw.clone(),
                                ctx.msg.metadata.response_code,
                                Some(ctx.upstream.clone()),
                                qname,
                                Arc::from(pipeline_id),
                                u16::from(qtype),
                                (cache_ttl, refresh_ttl),
                            ),
                        );
                    }
                    if let Some(g) = cleanup_guard.as_mut() {
                        g.defuse();
                    }
                    engine.notify_inflight_waiters(dedupe_hash, &ctx.raw).await;
                    response.upstream = Some(ctx.upstream);
                    Ok(ForwardResult::Success(ctx.raw))
                }
                ResponseActionResult::Static { bytes, rcode, .. } => {
                    if min_ttl > Duration::from_secs(0) {
                        let ttl = proto_utils::saturating_u64_to_u32(min_ttl.as_secs());
                        engine.insert_dns_cache_entry(
                            dedupe_hash,
                            CacheEntry::from_response(
                                bytes.clone(),
                                rcode,
                                None,
                                qname,
                                Arc::from(pipeline_id),
                                u16::from(qtype),
                                (ttl, ttl),
                            ),
                        );
                    }
                    if let Some(g) = cleanup_guard.as_mut() {
                        g.defuse();
                    }
                    engine.notify_inflight_waiters(dedupe_hash, &bytes).await;
                    response.upstream = Some(Arc::from("static"));
                    Ok(ForwardResult::Success(bytes))
                }
                ResponseActionResult::Jump {
                    pipeline,
                    remaining_jumps,
                } => {
                    let edns_present = proto_utils::parse_quick(packet, &mut [0u8; 256])
                        .map(|p| p.edns_present)
                        .unwrap_or(false);

                    let resp_bytes = rules::process_response_jump(
                        engine,
                        rules::ResponseJumpContext {
                            state,
                            pipeline_id: pipeline,
                            remaining_jumps,
                            req: &req_full,
                            packet,
                            peer: *peer,
                            qname,
                            qtype,
                            qclass,
                            edns_present,
                            min_ttl,
                            upstream_timeout,
                            skip_cache,
                            observed,
                        },
                        response,
                    )
                    .await?;

                    if let Some(g) = cleanup_guard.as_mut() {
                        g.defuse();
                    }
                    engine
                        .notify_inflight_waiters(dedupe_hash, &resp_bytes)
                        .await;
                    Ok(ForwardResult::Success(resp_bytes))
                }
                ResponseActionResult::Continue { ctx } => {
                    // Defusing here would leave the inflight entry (dedupe_hash)
                    // in the map without ever notifying it: concurrent same-hash
                    // requests wait on rx.changed() forever, and — worse — the
                    // re-evaluated next rule (execution.rs re-applies rules and
                    // forwards again with the same dedupe_hash) finds the entry
                    // Occupied and hangs until the outer timeout, which surfaces
                    // as a client TIMEOUT instead of a fallback answer.
                    // 此处 defuse 会让 inflight 条目（dedupe_hash）留在 map 中且
                    // 永远不通知：并发同 hash 请求会永久等待 rx.changed()，更糟的
                    // 是——continue 后重新评估的下一条规则（execution.rs 重新
                    // apply_rules 并以相同 dedupe_hash 再次转发）会看到 Occupied
                    // 条目并挂起直到外层超时，表现为客户端 TIMEOUT 而非 fallback。
                    //
                    // So: notify waiters with the response received so far, and
                    // let the cleanup guard (kept active) remove the entry on
                    // return, so the next Forward attempt starts fresh.
                    // 因此：先以已收到的响应通知等待者，并让清理守卫（保持 active）
                    // 在返回时移除条目，使下一次 Forward 尝试从全新条目开始。
                    if let Some(ctx_ref) = ctx.as_ref() {
                        engine
                            .notify_inflight_waiters(dedupe_hash, &ctx_ref.raw)
                            .await;
                    }
                    Ok(ForwardResult::Continue(Box::new(ctx)))
                }
            }
        }
        Err(e) => {
            if response_actions_on_miss.is_empty() {
                // Only send SERVFAIL when upstream attempts are fully exhausted.
                // 仅在所有上游尝试都耗尽时发送 SERVFAIL。
                if e.downcast_ref::<UpstreamFailure>().is_none() {
                    return Err(e);
                }

                // RFC 8767: Try to serve stale cache entry before returning SERVFAIL
                // RFC 8767: 在返回 SERVFAIL 之前尝试提供过期缓存
                if let Some(stale_bytes) = check_stale_cache_logged(
                    engine,
                    &CacheLookupContext {
                        state,
                        qname,
                        qtype,
                        qclass,
                        pipeline_id,
                        dedupe_hash,
                        tx_id,
                        start,
                        peer,
                        // A background refresh never looked the cache up, so it
                        // must not report a hit either / 后台刷新没有查过缓存，也不能上报命中
                        observed: if skip_cache { None } else { observed },
                    },
                    CacheHitKind::StaleUpstreamFailure,
                    response,
                ) {
                    warn!(
                        event = "serve_stale_on_upstream_failure",
                        upstream = %upstream,
                        qname = %qname,
                        qtype = ?qtype,
                        client_ip = %peer.ip(),
                        pipeline = %pipeline_id,
                        error = %e,
                        "RFC 8767: upstream failed, serving stale cache"
                    );
                    if let Some(g) = cleanup_guard.as_mut() {
                        g.defuse();
                    }
                    engine
                        .notify_inflight_waiters(dedupe_hash, &stale_bytes)
                        .await;
                    return Ok(ForwardResult::Success(stale_bytes));
                }

                let rcode = ResponseCode::ServFail;
                warn!(
                   event = "upstream_failure",
                   upstream = %upstream,
                   qname = %qname,
                   qtype = ?qtype,
                   rcode = ?rcode,
                   client_ip = %peer.ip(),
                   error = %e,
                   pipeline = %pipeline_id,
                   transport = ?transport,
                   "upstream failed"
                );
                // Fast build SERVFAIL without full request parse
                let rd = packet.get(2).map(|b| b & 0x01 != 0).unwrap_or(false);
                let resp_bytes = match build_servfail_response_fast(
                    tx_id,
                    qname,
                    u16::from(qtype),
                    u16::from(qclass),
                    rd,
                ) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        // Fallback to full parse if fast build fails
                        let req = match Message::from_bytes(packet) {
                            Ok(r) => r,
                            Err(_) => return Err(e),
                        };
                        build_response(&req, rcode, Vec::new()).unwrap_or_default()
                    }
                };

                if let Some(g) = cleanup_guard.as_mut() {
                    g.defuse();
                }
                engine
                    .notify_inflight_waiters(dedupe_hash, &resp_bytes)
                    .await;

                Ok(ForwardResult::Success(resp_bytes))
            } else {
                let req = match Message::from_bytes(packet) {
                    Ok(r) => r,
                    Err(_) => return Err(e),
                };
                let default_upstream = state.pipeline.settings.default_upstream.as_str();
                let response_jump_limit = state.pipeline.settings.response_jump_limit as usize;

                let ctx = rules::ApplyResponseActionsContext {
                    engine,
                    actions: response_actions_on_miss,
                    ctx_opt: None,
                    req: &req,
                    packet,
                    upstream_timeout,
                    response_matchers,
                    qname,
                    qtype,
                    qclass,
                    client_ip: peer.ip(),
                    upstream_default: default_upstream,
                    pipeline_id,
                    rule_name,
                    remaining_jumps: response_jump_limit,
                };
                let action_result = rules::apply_response_actions_observed(ctx, observed).await?;

                match action_result {
                    ResponseActionResult::Upstream { ctx, resp_match: _ } => {
                        let ttl_secs_cache = extract_ttl(&ctx.msg);
                        let ttl_secs_refresh = extract_ttl_for_refresh(&ctx.msg);
                        let effective_ttl =
                            Duration::from_secs(ttl_secs_cache.max(min_ttl.as_secs()));
                        if effective_ttl > Duration::from_secs(0) {
                            let cache_ttl = proto_utils::saturating_u64_to_u32(ttl_secs_cache);
                            let refresh_ttl = proto_utils::saturating_u64_to_u32(ttl_secs_refresh);
                            engine.insert_dns_cache_entry(
                                dedupe_hash,
                                CacheEntry::from_response(
                                    ctx.raw.clone(),
                                    ctx.msg.metadata.response_code,
                                    Some(ctx.upstream.clone()),
                                    qname,
                                    Arc::from(pipeline_id),
                                    u16::from(qtype),
                                    (cache_ttl, refresh_ttl),
                                ),
                            );
                        }
                        if let Some(g) = cleanup_guard.as_mut() {
                            g.defuse();
                        }
                        engine.notify_inflight_waiters(dedupe_hash, &ctx.raw).await;
                        response.upstream = Some(ctx.upstream);
                        Ok(ForwardResult::Success(ctx.raw))
                    }
                    ResponseActionResult::Static { bytes, rcode, .. } => {
                        if min_ttl > Duration::from_secs(0) {
                            let ttl = proto_utils::saturating_u64_to_u32(min_ttl.as_secs());
                            engine.insert_dns_cache_entry(
                                dedupe_hash,
                                CacheEntry::from_response(
                                    bytes.clone(),
                                    rcode,
                                    None,
                                    qname,
                                    Arc::from(pipeline_id),
                                    u16::from(qtype),
                                    (ttl, ttl),
                                ),
                            );
                        }
                        if let Some(g) = cleanup_guard.as_mut() {
                            g.defuse();
                        }
                        engine.notify_inflight_waiters(dedupe_hash, &bytes).await;
                        response.upstream = Some(Arc::from("static"));
                        Ok(ForwardResult::Success(bytes))
                    }
                    ResponseActionResult::Jump {
                        pipeline,
                        remaining_jumps,
                    } => {
                        let edns_present = proto_utils::parse_quick(packet, &mut [0u8; 256])
                            .map(|p| p.edns_present)
                            .unwrap_or(false);
                        let req = if let Ok(r) = Message::from_bytes(packet) {
                            r
                        } else {
                            Message::new(
                                0,
                                hickory_proto::op::MessageType::Query,
                                hickory_proto::op::OpCode::Query,
                            )
                        };

                        let resp_bytes = rules::process_response_jump(
                            engine,
                            rules::ResponseJumpContext {
                                state,
                                pipeline_id: pipeline,
                                remaining_jumps,
                                req: &req,
                                packet,
                                peer: *peer,
                                qname,
                                qtype,
                                qclass,
                                edns_present,
                                min_ttl,
                                upstream_timeout,
                                skip_cache,
                                observed,
                            },
                            response,
                        )
                        .await?;

                        if let Some(g) = cleanup_guard.as_mut() {
                            g.defuse();
                        }
                        engine
                            .notify_inflight_waiters(dedupe_hash, &resp_bytes)
                            .await;
                        Ok(ForwardResult::Success(resp_bytes))
                    }
                    ResponseActionResult::Continue { ctx } => {
                        // Defuse cleanup guard: we're returning Continue which re-enters
                        // the decision loop. The inflight entry must survive for waiters.
                        // If we don't defuse, Drop will remove the inflight entry without
                        // notifying waiters, causing them to hang forever on rx.changed().
                        if let Some(g) = cleanup_guard.as_mut() {
                            g.defuse();
                        }
                        Ok(ForwardResult::Continue(Box::new(ctx)))
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tcp_fallback_tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use hickory_proto::serialize::binary::BinDecodable;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::engine::Engine;
    use crate::matcher::RuntimePipelineConfig;

    /// The address in the full answer, which only TCP carries.
    /// 完整应答里的地址，只有 TCP 给得出。
    const FULL: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    /// The address a truncated answer may carry.
    /// 截断的应答里可能带的地址。
    const PARTIAL: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 9);

    fn reply(request: &[u8], answer: Option<Ipv4Addr>, truncated: bool) -> Option<Vec<u8>> {
        let request = Message::from_bytes(request).ok()?;
        let question = request.queries.first()?.clone();
        let mut reply = Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
        reply.add_query(question.clone());
        reply.metadata.truncation = truncated;
        if let Some(address) = answer {
            reply.add_answer(Record::from_rdata(
                question.name().clone(),
                300,
                RData::A(A(address)),
            ));
        }
        reply.to_vec().ok()
    }

    /// Holds a TCP port without listening on it: connections are refused, and no other
    /// test can take the port while this lives.
    /// 占着一个 TCP 端口但不监听：连接被拒，而且只要它在，别的测试就拿不走这个端口。
    fn hold_tcp_port(addr: SocketAddr) -> std::io::Result<tokio::net::TcpSocket> {
        let socket = tokio::net::TcpSocket::new_v4()?;
        socket.bind(addr)?;
        Ok(socket)
    }

    /// Serves DNS over TCP, answering `answer` after `delay`, and counts the answers.
    /// 在 TCP 上应答 `answer`（延迟 `delay`），并计数。
    fn serve_tcp(
        listener: tokio::net::TcpListener,
        answer: Ipv4Addr,
        delay: Duration,
    ) -> Arc<AtomicUsize> {
        let answered = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&answered);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let counter = Arc::clone(&counter);
                tokio::spawn(async move {
                    let mut len = [0u8; 2];
                    if stream.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let mut request = vec![0u8; u16::from_be_bytes(len) as usize];
                    if stream.read_exact(&mut request).await.is_err() {
                        return;
                    }
                    tokio::time::sleep(delay).await;
                    if let Some(bytes) = reply(&request, Some(answer), false) {
                        counter.fetch_add(1, Ordering::SeqCst);
                        let _ = stream.write_all(&(bytes.len() as u16).to_be_bytes()).await;
                        let _ = stream.write_all(&bytes).await;
                    }
                });
            }
        });
        answered
    }

    /// An upstream whose UDP answers are truncated and whose TCP answers carry [`FULL`].
    /// UDP 应答被截断、TCP 应答带 [`FULL`] 的上游。
    struct TruncatingUpstream {
        addr: String,
        udp_queries: Arc<AtomicUsize>,
        tcp_answers: Arc<AtomicUsize>,
        _closed_tcp: Option<tokio::net::TcpSocket>,
    }

    /// `tcp` is how long the TCP answers take; with `None` the TCP port is held but nothing
    /// listens. `partial` is a record the truncated UDP answers carry.
    /// `tcp` 是 TCP 应答的延迟；为 `None` 时占着 TCP 端口但不监听。`partial` 是截断的 UDP 应答里带的记录。
    async fn spawn_truncating_upstream(
        tcp: Option<Duration>,
        partial: Option<Ipv4Addr>,
    ) -> TruncatingUpstream {
        let (udp, listener, closed_tcp) = loop {
            let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = udp.local_addr().unwrap();
            let bound = if tcp.is_some() {
                tokio::net::TcpListener::bind(addr)
                    .await
                    .map(|listener| (Some(listener), None))
            } else {
                hold_tcp_port(addr).map(|socket| (None, Some(socket)))
            };
            match bound {
                Ok((listener, closed)) => break (udp, listener, closed),
                Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => continue,
                Err(err) => panic!("bind tcp on the udp port: {err}"),
            }
        };
        let addr = udp.local_addr().unwrap().to_string();
        let udp_queries = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&udp_queries);
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while let Ok((n, peer)) = udp.recv_from(&mut buf).await {
                if let Some(bytes) = reply(&buf[..n], partial, true) {
                    counter.fetch_add(1, Ordering::SeqCst);
                    let _ = udp.send_to(&bytes, peer).await;
                }
            }
        });
        let tcp_answers = match (listener, tcp) {
            (Some(listener), Some(delay)) => serve_tcp(listener, FULL, delay),
            _ => Arc::new(AtomicUsize::new(0)),
        };
        TruncatingUpstream {
            addr,
            udp_queries,
            tcp_answers,
            _closed_tcp: closed_tcp,
        }
    }

    /// A TCP-only upstream: it answers 192.0.2.77 after `delay`, or, with no delay given,
    /// holds the port without listening.
    /// 只走 TCP 的上游：延迟 `delay` 后应答 192.0.2.77；不给延迟时占着端口但不监听。
    async fn spawn_tcp_upstream(
        delay: Option<Duration>,
    ) -> (String, Option<tokio::net::TcpSocket>) {
        match delay {
            Some(delay) => {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                drop(serve_tcp(listener, Ipv4Addr::new(192, 0, 2, 77), delay));
                (format!("tcp://{addr}"), None)
            }
            None => {
                let held = hold_tcp_port("127.0.0.1:0".parse().unwrap()).unwrap();
                let addr = held.local_addr().unwrap();
                (format!("tcp://{addr}"), Some(held))
            }
        }
    }

    fn engine_with_rule(upstream: &str, checks: serde_json::Value) -> Engine {
        engine_with(
            serde_json::json!({ "type": "forward", "upstream": upstream, "transport": "udp" }),
            checks,
            true,
        )
    }

    fn engine_with(
        action: serde_json::Value,
        checks: serde_json::Value,
        tcp_fallback: bool,
    ) -> Engine {
        let mut rule = serde_json::json!({
            "name": "forward",
            "matchers": [{ "type": "any" }],
            "actions": [action]
        });
        for (key, value) in checks.as_object().unwrap() {
            rule[key] = value.clone();
        }
        let raw = serde_json::json!({
            "settings": {
                "default_upstream": "127.0.0.1:9",
                "upstream_timeout_ms": 2000,
                "enable_tcp_fallback": tcp_fallback
            },
            "pipelines": [{ "id": "main", "rules": [rule] }]
        });
        let config = crate::config::parse_config(&raw.to_string()).expect("parse config");
        Engine::new(
            RuntimePipelineConfig::from_config(config).expect("build runtime config"),
            "test".to_string(),
        )
        .expect("engine")
    }

    async fn ask(engine: &Engine) -> Message {
        let mut request = Message::new(0x4b1d, MessageType::Query, OpCode::Query);
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(
            Name::from_str("large.example.").unwrap(),
            RecordType::A,
        ));
        let bytes = tokio::time::timeout(
            Duration::from_secs(5),
            engine.handle_packet(
                &request.to_vec().unwrap(),
                "10.0.0.1:53000".parse().unwrap(),
            ),
        )
        .await
        .expect("must not hang")
        .expect("engine answers");
        Message::from_bytes(&bytes).expect("parse answer")
    }

    fn addresses(answer: &Message) -> Vec<Ipv4Addr> {
        answer
            .answers
            .iter()
            .filter_map(|record| match &record.data {
                RData::A(a) => Some(a.0),
                _ => None,
            })
            .collect()
    }

    /// One UDP upstream: the UDP forwarder itself fetches the truncated answer again over
    /// TCP, once, and the full answer comes back.
    /// 只有一个 UDP 上游：UDP 转发自己用 TCP 重取一次被截断的应答，拿回完整应答。
    #[tokio::test]
    async fn a_truncated_answer_from_a_udp_upstream_is_fetched_over_tcp_once() {
        let upstream = spawn_truncating_upstream(Some(Duration::ZERO), None).await;
        let engine = engine_with_rule(&upstream.addr, serde_json::json!({}));
        assert_eq!(addresses(&ask(&engine).await), [FULL]);
        assert_eq!(upstream.tcp_answers.load(Ordering::SeqCst), 1);
    }

    // With a TCP upstream in the same rule, a failed UDP exchange does not fall back to TCP
    // (so TCP is not sent twice), but a truncated answer is still fetched again over TCP. A
    // slow TCP upstream lets the truncated UDP answer arrive first.
    // 同一条规则里还有 TCP 上游时，UDP 失败不再回退到 TCP（免得 TCP 发两次），但截断的应答照样用 TCP
    // 重取。TCP 上游故意慢一些，让截断的 UDP 应答先到。

    /// The answer check sees the full answer fetched over TCP and acts on it.
    /// 回答检查看到的是经 TCP 取回的完整应答，并按它行事。
    #[tokio::test]
    async fn a_truncated_answer_fetched_over_tcp_goes_through_the_response_rules() {
        let truncating = spawn_truncating_upstream(Some(Duration::ZERO), None).await;
        let (slow, _) = spawn_tcp_upstream(Some(Duration::from_millis(500))).await;
        let engine = engine_with_rule(
            &format!("{},{slow}", truncating.addr),
            serde_json::json!({
                "response_matchers": [{ "type": "response_answer_ip", "cidr": "192.0.2.1/32" }],
                "response_actions_on_match": [{ "type": "static_response", "rcode": "REFUSED" }]
            }),
        );
        let answer = ask(&engine).await;
        assert_eq!(
            answer.metadata.response_code,
            ResponseCode::Refused,
            "the answer check must act on the TCP answer: {answer:?}"
        );
    }

    /// The full answer fetched over TCP is cached like any answer.
    /// 经 TCP 取回的完整应答和其他应答一样写进缓存。
    #[tokio::test]
    async fn a_truncated_answer_fetched_over_tcp_is_cached() {
        let truncating = spawn_truncating_upstream(Some(Duration::ZERO), None).await;
        let (slow, _) = spawn_tcp_upstream(Some(Duration::from_millis(500))).await;
        let engine = engine_with_rule(
            &format!("{},{slow}", truncating.addr),
            serde_json::json!({}),
        );
        assert_eq!(addresses(&ask(&engine).await), [FULL]);
        assert_eq!(addresses(&ask(&engine).await), [FULL]);
        assert_eq!(
            truncating.tcp_answers.load(Ordering::SeqCst),
            1,
            "the second query must be served from the cache"
        );
    }

    /// When the TCP retry fails too, the failure path runs, miss actions included.
    /// TCP 重试也失败时走失败路径，包括 on_miss 动作。
    #[tokio::test]
    async fn a_failed_tcp_retry_takes_the_failure_path() {
        let truncating = spawn_truncating_upstream(None, None).await;
        let (dead, _held) = spawn_tcp_upstream(None).await;
        let engine = engine_with_rule(
            &format!("{},{dead}", truncating.addr),
            serde_json::json!({
                "response_matchers": [{ "type": "response_answer_ip", "cidr": "192.0.2.1/32" }],
                "response_actions_on_miss": [{ "type": "static_response", "rcode": "NXDOMAIN" }]
            }),
        );
        let answer = ask(&engine).await;
        assert_eq!(
            answer.metadata.response_code,
            ResponseCode::NXDomain,
            "the miss actions must answer when the TCP retry fails: {answer:?}"
        );
    }

    /// An upstream written as `udp://` next to a TCP one: its truncated answer is fetched
    /// again over TCP like any UDP upstream's.
    /// 写成 `udp://`、旁边还有 TCP 上游的上游：它截断的应答和其他 UDP 上游一样用 TCP 重取。
    #[tokio::test]
    async fn a_udp_upstream_next_to_a_tcp_one_has_truncated_answers_fetched_over_tcp() {
        let truncating = spawn_truncating_upstream(Some(Duration::ZERO), Some(PARTIAL)).await;
        let (slow, _) = spawn_tcp_upstream(Some(Duration::from_millis(500))).await;
        let engine = engine_with_rule(
            &format!("udp://{},{slow}", truncating.addr),
            serde_json::json!({}),
        );
        let answer = ask(&engine).await;
        assert!(!answer.metadata.truncation, "{answer:?}");
        assert_eq!(addresses(&answer), [FULL]);
        assert_eq!(truncating.tcp_answers.load(Ordering::SeqCst), 1);
    }

    /// `tcp_udp` sends both ways at once. A truncated UDP answer that arrives first does
    /// not win: the TCP leg's full answer does.
    /// `tcp_udp` 两路同时发。先到的截断 UDP 应答不算赢，赢的是 TCP 那一路的完整应答。
    #[tokio::test]
    async fn a_truncated_udp_answer_does_not_win_a_tcp_udp_race() {
        let truncating =
            spawn_truncating_upstream(Some(Duration::from_millis(200)), Some(PARTIAL)).await;
        let engine = engine_with(
            serde_json::json!({ "type": "forward", "upstream": truncating.addr, "transport": "tcp_udp" }),
            serde_json::json!({}),
            true,
        );
        let answer = ask(&engine).await;
        assert!(!answer.metadata.truncation, "{answer:?}");
        assert_eq!(addresses(&answer), [FULL]);
    }

    /// The response-jump path caches through the same place, so a truncated answer is not
    /// cached there either: a request entering the jump target directly asks the upstream.
    /// 响应跳转路径也经同一个地方写缓存，所以截断的应答在那里同样不缓存：直接进入跳转目标的请求照样去问上游。
    #[tokio::test]
    async fn a_truncated_answer_on_the_response_jump_path_is_not_cached() {
        let truncating = spawn_truncating_upstream(None, Some(PARTIAL)).await;
        let forward = |id: &str, then: serde_json::Value| {
            let mut rule = serde_json::json!({
                "name": id,
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": truncating.addr }]
            });
            for (key, value) in then.as_object().unwrap() {
                rule[key] = value.clone();
            }
            serde_json::json!({ "id": id, "rules": [rule] })
        };
        let raw = serde_json::json!({
            "settings": {
                "default_upstream": "127.0.0.1:9",
                "upstream_timeout_ms": 2000,
                "enable_tcp_fallback": false
            },
            "pipeline_select": [
                { "pipeline": "main", "matchers": [{ "type": "client_ip", "cidr": "10.0.0.1/32" }] },
                { "pipeline": "second", "matchers": [{ "type": "client_ip", "cidr": "10.0.0.2/32" }] }
            ],
            "pipelines": [
                forward("main", serde_json::json!({
                    "response_matchers": [{ "type": "upstream_equals", "value": truncating.addr }],
                    "response_actions_on_match": [{ "type": "jump_to_pipeline", "pipeline": "second" }]
                })),
                forward("second", serde_json::json!({}))
            ]
        });
        let config = crate::config::parse_config(&raw.to_string()).expect("parse config");
        let engine = Engine::new(
            RuntimePipelineConfig::from_config(config).expect("build runtime config"),
            "test".to_string(),
        )
        .expect("engine");
        let ask_from = |client: &'static str| {
            let engine = &engine;
            async move {
                let mut request = Message::new(0x4b1d, MessageType::Query, OpCode::Query);
                request.add_query(Query::query(
                    Name::from_str("large.example.").unwrap(),
                    RecordType::A,
                ));
                tokio::time::timeout(
                    Duration::from_secs(5),
                    engine.handle_packet(&request.to_vec().unwrap(), client.parse().unwrap()),
                )
                .await
                .expect("must not hang")
                .expect("engine answers")
            }
        };
        ask_from("10.0.0.1:53000").await;
        let asked = truncating.udp_queries.load(Ordering::SeqCst);
        assert_eq!(asked, 2, "main's forward and the one on the jump path");
        ask_from("10.0.0.2:53000").await;
        assert_eq!(
            truncating.udp_queries.load(Ordering::SeqCst),
            asked + 1,
            "a request entering the jump target must ask the upstream, not get a cached truncated answer"
        );
    }

    /// With TCP fallback turned off the client gets the truncated answer, which is not
    /// cached: the next query asks the upstream again.
    /// 关掉 TCP 回退时客户端拿到截断的应答，它不写缓存：下一次查询照样去问上游。
    #[tokio::test]
    async fn a_truncated_answer_is_never_cached() {
        let truncating = spawn_truncating_upstream(None, Some(PARTIAL)).await;
        let engine = engine_with(
            serde_json::json!({ "type": "forward", "upstream": truncating.addr }),
            serde_json::json!({}),
            false,
        );
        let first = ask(&engine).await;
        assert!(first.metadata.truncation, "{first:?}");
        assert_eq!(addresses(&first), [PARTIAL]);
        ask(&engine).await;
        assert_eq!(
            truncating.udp_queries.load(Ordering::SeqCst),
            2,
            "the second query must ask the upstream again, not use a cached truncated answer"
        );
    }
}
