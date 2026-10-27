use super::Engine;
use crate::cache::{CacheEntry, CachedQuestion};
use crate::config::{Action, Transport};
use crate::ecs_scope::{EcsReach, EcsView, ForwardEcs};
use crate::engine::execution::CacheKeys;
use crate::engine::observation::{Observed, cached_source, response_decision_kind};
use crate::engine::refresh::RefreshTarget;
use crate::engine::response::{extract_ttl, extract_ttl_for_refresh};
use crate::engine::response_log::ResponseInfo;
use crate::engine::rules::{self, ResponseActionResult, ResponseContext};
use crate::engine::types::{EngineInner, InflightEntry, InflightQuestion, inflight_pending};
use crate::engine::upstream::{UpstreamFailure, reject_failure_reply_on_refresh};
use crate::engine::utils::InflightCleanupGuard;
use crate::engine::utils::engine_helpers::{build_response, build_servfail_response_fast};
use crate::matcher::{Requester, RuntimeResponseMatcherWithOp, eval_match_chain};
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
    /// The upstream failed, and this is what the request answers instead: a stale
    /// entry, SERVFAIL, or what the miss actions produced. For a client it is an
    /// answer like any other. For a background refresh it is no new answer from
    /// the route the entry came by, so the refresh does not drop that entry for it
    /// (see the Success arm in `handle_packet_internal`).
    /// 上游失败，这是请求改用的应答：过期条目、SERVFAIL，或 on_miss 动作给出的结果。对客户端
    /// 来说它和别的应答一样。对后台刷新来说，它不是条目来路上的新应答，刷新不会因为它删掉
    /// 那个条目（见 `handle_packet_internal` 里的 Success 分支）。
    Fallback(Bytes),
    /// Request needs to continue (e.g. Action::Continue)
    /// Boxed to reduce enum size (ResponseContext is ~256 bytes)
    Continue {
        ctx: Box<Option<ResponseContext>>,
        /// A miss action's continue after the upstream failed: what the later rules
        /// answer is a fallback, as `Fallback` is
        /// 上游失败之后 on_miss 动作的 continue：后面的规则给出的应答是兜底，和 `Fallback` 一样
        after_failure: bool,
    },
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
    /// Response cache slot / 响应缓存槽位
    pub slot: u64,
    pub tx_id: u16,
    pub start: Instant,
    pub peer: &'a std::net::SocketAddr,
    /// Who is asking: picks the answer in the slot, and a background refresh replays
    /// the request the same way (address, EDNS, the client's own ECS).
    /// 谁在问：据此在槽位里挑应答，后台刷新也照此重放请求（地址、EDNS、客户端自己的 ECS）。
    pub requester: Requester,
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
        slot,
        tx_id,
        start: _,
        peer,
        requester,
        observed,
    } = *context;
    let view = requester.ecs_view();
    let question = CachedQuestion {
        qname: qname_ref,
        pipeline_id,
        qtype: u16::from(qtype),
    };

    // moka 同步缓存自动处理过期，无需检查 expires_at / moka sync cache automatically handles expiration, no need to check expires_at
    let now = Instant::now();
    let hit = engine.cache_get(slot, &view, &question, now)?;
    let elapsed_secs = now.saturating_duration_since(hit.inserted_at).as_secs();

    // Check manual expiration (in case moka hasn't evicted it yet or for strict TTL compliance)
    if elapsed_secs >= hit.original_ttl as u64 {
        // serve_stale disabled → invalidate and miss
        if !state.pipeline.settings.serve_stale {
            engine.cache_invalidate(slot, &hit);
            return None;
        }
        // Don't serve SERVFAIL/REFUSED as stale
        if hit.rcode == ResponseCode::ServFail || hit.rcode == ResponseCode::Refused {
            engine.cache_invalidate(slot, &hit);
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
            engine.cache_invalidate(slot, &hit);
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
                engine.spawn_background_refresh((*state).clone(), &hit, slot, qclass, requester);
            }
            return None;
        }

        // serve_stale_client_timeout_ms == 0: Serve stale immediately (optimistic mode)
        // RFC 8767: 立即返回 stale 数据 + 后台刷新
        let stale_ttl = state.pipeline.settings.serve_stale_ttl;
        let resp_bytes = served_from_cache(&hit, tx_id, &view, ServedTtl::Stale(stale_ttl));

        // serve_stale_ttl_reset: reset stale expiry timer by re-inserting with shifted inserted_at
        // 重置过期计时器：通过重新插入条目并将 inserted_at 设置为"刚过期"的时间点
        if state.pipeline.settings.serve_stale_ttl_reset {
            let new_entry = hit.clone_with_refreshed_ttl();
            engine.cache_replace(slot, &hit, new_entry);
        }

        // Trigger background refresh to get fresh data
        if hit.upstream.is_some() {
            engine.spawn_background_refresh((*state).clone(), &hit, slot, qclass, requester);
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
                    source: cached_source(hit.upstream.as_deref()),
                },
            );
        }
        response.cache_hit = true;
        response.upstream = Some(hit.upstream.clone().unwrap_or_else(|| Arc::from("static")));
        Some(resp_bytes)
    } else {
        // Cache hit is valid

        // RFC 1035 §5.2: Patch TTL based on residence time / 根据停留时间修正 TTL
        let elapsed = crate::proto_utils::saturating_u64_to_u32(elapsed_secs);
        let resp_bytes = served_from_cache(&hit, tx_id, &view, ServedTtl::Elapsed(elapsed));

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

            engine.spawn_background_refresh((*state).clone(), &hit, slot, qclass, requester);
        }

        response.cache_hit = true;
        response.upstream = Some(hit.upstream.clone().unwrap_or_else(|| Arc::from("static")));

        if let Some((observer, ctx)) = observed {
            observer.cache_hit(
                ctx,
                &CacheHit {
                    kind: CacheHitKind::Fresh,
                    remaining_ttl: Some(Duration::from_secs(
                        hit.original_ttl.saturating_sub(elapsed) as u64,
                    )),
                    original_ttl: Some(Duration::from_secs(hit.original_ttl as u64)),
                    source: cached_source(hit.upstream.as_deref()),
                },
            );
        }
        Some(resp_bytes)
    }
}

/// 缓存留一份应答多久：它自己的 TTL（记录里最小的，否定应答用 SOA 的负缓存 TTL）收进
/// `min_ttl..=cache_max_ttl`，和应答带的 TTL 一样（见 `forward_upstream`）；0 就不缓存。
/// 它自己的 TTL 为 0 时不缓存：要么没有可依据的 TTL（没有 SOA 的否定应答，RFC 2308 第 4 节说不要
/// 缓存），要么 min_ttl 为 0 时记录的 TTL 就是 0。
/// How long the cache keeps an answer: its own TTL (the least of its records', the
/// SOA negative TTL for a negative answer) brought into `min_ttl..=cache_max_ttl`,
/// as the TTLs the answer carries are (see `forward_upstream`); 0 means not cached.
/// An own TTL of 0 is not cached: either the answer gives no TTL to go by (a
/// negative answer without SOA, which RFC 2308 section 4 says not to cache), or,
/// with min_ttl 0, its records have TTL 0.
fn ttl_to_cache(engine: &Engine, answer_ttl: u64, min_ttl: Duration) -> u32 {
    if answer_ttl == 0 {
        return 0;
    }
    proto_utils::saturating_u64_to_u32(answer_ttl.max(min_ttl.as_secs())).min(engine.ttl_cap())
}

/// How a reply served from the cache gets its TTLs / 从缓存给出的应答怎样设置 TTL
#[derive(Debug, Clone, Copy)]
pub(crate) enum ServedTtl {
    /// Fresh: every TTL lowered by the seconds the answer has been cached
    /// 新鲜：每个 TTL 减去应答已经缓存的秒数
    Elapsed(u32),
    /// Stale (RFC 8767): every TTL set to this / 过期（RFC 8767）：每个 TTL 设为这个值
    Stale(u32),
}

/// The reply a cache hit sends: the cached answer with the request's ID, its TTLs
/// as `ttl` says, and the ECS option RFC 7871 section 7.2.2 asks for. A client
/// that sent no ECS gets none (the cached answer has none, see
/// `insert_dns_cache_entry`); one that sent ECS gets its own subnet back, with
/// the scope the answer has for it.
/// 缓存命中时发出的应答：缓存的应答，换上请求的 ID，按 `ttl` 设置 TTL，并带上 RFC 7871
/// 第 7.2.2 节要求的 ECS 选项。没带 ECS 的客户端拿到的应答不带 ECS（缓存的应答本就去掉了，
/// 见 `insert_dns_cache_entry`）；带了 ECS 的客户端拿回它自己的子网，作用范围是这份应答
/// 对它的作用范围。
pub(crate) fn served_from_cache(
    hit: &CacheEntry,
    tx_id: u16,
    view: &EcsView,
    ttl: ServedTtl,
) -> Bytes {
    // An ECS option nobody can read gets no echo: there is nothing well-formed to send back
    // 谁也读不懂的 ECS 选项不回显：没有合规的内容可以发回
    let echoed = view
        .client
        .filter(|client| !client.is_opaque())
        .and_then(|client| proto_utils::echo_ecs(&hit.bytes, &client, hit.reach.echo_scope(view)));
    let mut resp_bytes = BytesMut::from(echoed.as_deref().unwrap_or(&hit.bytes));
    match ttl {
        ServedTtl::Elapsed(0) => {}
        ServedTtl::Elapsed(elapsed) => proto_utils::patch_all_ttls(&mut resp_bytes, elapsed),
        ServedTtl::Stale(stale_ttl) => proto_utils::set_all_ttls(&mut resp_bytes, stale_ttl),
    }
    // Rewrite Transaction ID / 改写事务 ID
    if resp_bytes.len() >= 2 {
        resp_bytes[..2].copy_from_slice(&tx_id.to_be_bytes());
    }
    resp_bytes.freeze()
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
        slot,
        tx_id,
        start: _,
        peer,
        requester,
        observed,
    } = *context;
    if !state.pipeline.settings.serve_stale {
        return None;
    }
    let view = requester.ecs_view();
    let question = CachedQuestion {
        qname: qname_ref,
        pipeline_id,
        qtype: u16::from(qtype),
    };

    let now = Instant::now();
    let hit = engine.cache_get(slot, &view, &question, now)?;
    let elapsed_secs = now.saturating_duration_since(hit.inserted_at).as_secs();

    // Only serve stale when TTL has actually expired
    // 仅当 TTL 已过期时才提供 stale 数据
    if elapsed_secs < hit.original_ttl as u64 {
        return None;
    }
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

    // RFC 8767 §4: Set all TTLs to serve_stale_ttl
    let stale_ttl = state.pipeline.settings.serve_stale_ttl;
    let resp_bytes = served_from_cache(&hit, tx_id, &view, ServedTtl::Stale(stale_ttl));

    // serve_stale_ttl_reset: reset stale expiry timer
    // 重置过期计时器
    if state.pipeline.settings.serve_stale_ttl_reset {
        let new_entry = hit.clone_with_refreshed_ttl();
        engine.cache_replace(slot, &hit, new_entry);
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
        engine.spawn_background_refresh((*state).clone(), &hit, slot, qclass, requester);
    }

    if let Some((observer, ctx)) = observed {
        observer.cache_hit(
            ctx,
            &CacheHit {
                kind,
                remaining_ttl: None,
                original_ttl: Some(Duration::from_secs(hit.original_ttl as u64)),
                source: cached_source(hit.upstream.as_deref()),
            },
        );
    }
    response.cache_hit = true;
    response.upstream = Some(hit.upstream.clone().unwrap_or_else(|| Arc::from("static")));
    Some(resp_bytes)
}
/// Request data required to build and cache a static DNS response.
pub struct StaticDecisionContext<'a> {
    pub packet: &'a [u8],
    pub qname: &'a str,
    pub qtype: RecordType,
    pub pipeline_id: &'a Arc<str>,
    /// Response cache slot / 响应缓存槽位
    pub slot: u64,
    /// Whom the answer applies to: the forwards the request passed before it
    /// (see `ForwardDecisionContext::trail`)
    /// 应答适用于谁：请求在它之前经过的转发（见 `ForwardDecisionContext::trail`）
    pub reach: &'a EcsReach,
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
        slot,
        reach,
        min_ttl,
        start: _,
        peer: _,
        uses_client_ip,
    } = *context;
    // Need full request for building response / 需要完整请求来构建响应
    let req = Message::from_bytes(packet).context("parse request for static")?;
    let resp_bytes = build_response(&req, rcode, answers)?;

    // Skip dns_cache when the pipeline matches on client_ip: the slot has no
    // client dimension, so a cached static answer could leak across clients.
    // rule_cache already caches static decisions with client-IP isolation.
    if !uses_client_ip && min_ttl > Duration::from_secs(0) {
        let ttl = crate::proto_utils::saturating_u64_to_u32(min_ttl.as_secs());
        engine.insert_dns_cache_entry(
            slot,
            CacheEntry::from_response(
                resp_bytes.clone(),
                rcode,
                None, // Static responses have no upstream
                qname,
                current_pipeline_id.clone(),
                u16::from(qtype),
                (ttl, ttl),
            )
            .with_reach(reach.clone()),
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
    pub keys: CacheKeys,
    pub min_ttl: Duration,
    pub upstream_timeout: Duration,
    pub start: Instant,
    pub peer: &'a std::net::SocketAddr,
    /// Who is asking (address, EDNS, the client's own ECS) / 谁在问（地址、EDNS、客户端自己的 ECS）
    pub requester: Requester,
    pub skip_cache: bool,
    /// For a background refresh, the entry it renews / 后台刷新时，它要更新的条目
    pub refresh: Option<&'a RefreshTarget>,
    /// The forwards the request passed in this pipeline so far, each with the ECS
    /// it sent and whom its reply applies to; every answer the request caches
    /// applies to the requesters all of them admit (see `CacheEntry::reach`). A
    /// forward adds its own here.
    /// 请求在这个 pipeline 里到目前为止经过的转发，每次都记着它发出的 ECS 和应答适用于谁；
    /// 请求缓存的每份应答适用于它们全都接受的请求方（见 `CacheEntry::reach`）。转发把自己
    /// 的这一次记在这里。
    pub trail: &'a mut EcsReach,
    /// What pipelines the request left by a jump made the answer depend on (see
    /// `client_reply`), for the echo
    /// 请求跳离的 pipeline 让应答依赖的部分（见 `client_reply`），回显时用
    pub echo_floor: u8,
    pub upstream: &'a str,
    pub pre_split_upstreams: Option<&'a Arc<Vec<Arc<str>>>>,
    pub response_matchers: &'a [RuntimeResponseMatcherWithOp],
    pub response_actions_on_match: &'a [Action],
    pub response_actions_on_miss: &'a [Action],
    pub transport: Option<Transport>,
    pub ecs: Option<&'a crate::config::EcsMode>,
    pub allow_reuse: bool,
    pub reused_response: &'a mut Option<ResponseContext>,
    /// The inflight entry this request registered and still holds after a rule
    /// continued. The request keeps it for the rest of the decision loop, so its
    /// waiters get the final answer rather than one a rule continued past; a
    /// request holding an entry never waits on one. The entry's key keeps its
    /// waiters to requesters that the rules run after the continue treat alike
    /// (see `RuntimePipeline::requester`).
    /// 规则 continue 后本请求仍持有的 inflight 条目。它在决策循环余下的部分一直由
    /// 本请求持有，等待者拿到的是最终应答，而不是规则越过的那一个；持有条目的请求
    /// 从不等条目。条目的键只让 continue 之后运行的规则一样对待的请求方等在上面（见
    /// `RuntimePipeline::requester`）。
    pub held_inflight: &'a mut Option<InflightCleanupGuard>,
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
        keys,
        min_ttl,
        upstream_timeout,
        start,
        peer,
        requester,
        skip_cache,
        refresh,
        trail,
        echo_floor,
        upstream,
        pre_split_upstreams,
        response_matchers,
        response_actions_on_match,
        response_actions_on_miss,
        transport,
        ecs,
        allow_reuse,
        reused_response,
        held_inflight,
        observed,
    } = context;

    response.upstream = Some(Arc::from(upstream));
    let view = requester.ecs_view();
    let question = CachedQuestion {
        qname,
        pipeline_id,
        qtype: u16::from(qtype),
    };
    // What this forward sends as ECS, which decides whom its reply applies to
    // 这次转发发出的 ECS，它决定应答适用于谁
    let forward_ecs = ForwardEcs::of(ecs, &view);
    // ECS request rewriting (RFC 7871): modify outgoing packet before forwarding.
    // Only runs on cache-miss path — cache hits and static responses are unaffected.
    //
    // ECS 请求改写 (RFC 7871)：在转发前修改出站包。
    // 仅在缓存未命中路径执行 — 缓存命中和静态响应不受影响。
    let ecs_packet: std::borrow::Cow<[u8]> = match ecs {
        Some(mode) => {
            let modified =
                crate::ecs::apply_ecs_for(packet, mode, peer.ip(), requester.ecs.as_ref());
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
    // The cache relies on `forward_ecs` being what goes out. When it is not (an ECS
    // option the rewrite could not parse goes out as it is, say), or what goes out is
    // an option nobody can read, whom the reply applies to is unknown: nothing the
    // request gets from here on is cached.
    // 缓存依赖 `forward_ecs` 就是实际发出的 ECS。不一致（例如改写解析不了客户端的 ECS 选项，
    // 包原样发出），或者发出的是谁也读不懂的选项时，应答适用于谁说不准：此后请求得到的应答
    // 一律不缓存。
    let actually_sent = proto_utils::sent_subnet(packet);
    if actually_sent != forward_ecs.sent
        || matches!(actually_sent, crate::ecs_scope::Sent::Subnet(subnet) if subnet.is_opaque())
    {
        trail.mark_uncacheable();
    }

    // Only the request that registered an entry hands it an answer. One that
    // forwards under another's entry (a request holding an entry of its own, a
    // waiter forwarding itself after the leader went away, or a background
    // refresh, which registers none) leaves it to its owner.
    // 只有登记了条目的请求才把应答交给它。在别人的条目下转发的请求（持有自己条目的
    // 请求、领头请求离开后自己转发的等待者、不登记条目的后台刷新）把它留给条目的主人。
    let mut cleanup_guard = None;
    // What this forward registers or waits under in the inflight map
    // 这次转发在 inflight 表里登记或等待的问题
    let inflight_question = InflightQuestion {
        namespace: state.cache_namespace(pipeline_id),
        pipeline_id,
        qname: qname.as_bytes(),
        qtype,
        qclass,
        requester: keys.requester,
        client_ecs: requester.ecs,
    };
    debug_assert_eq!(
        inflight_question.key(),
        keys.inflight,
        "the inflight question is what the inflight key was computed from"
    );
    // An answer a rule continued past, reused here: the trail already has its forward
    // 这里复用的、规则越过的应答：它那次转发已经记在 trail 里
    let mut reused = false;

    let resp = if allow_reuse {
        if let Some(ctx) = reused_response.take() {
            reused = true;
            Ok((ctx.raw, ctx.upstream.to_string()))
        } else {
            if !skip_cache {
                use dashmap::mapref::entry::Entry;
                let rx = match engine.inflight.entry(keys.inflight) {
                    Entry::Vacant(entry) => {
                        let (tx, _rx) = tokio::sync::watch::channel(inflight_pending());
                        entry.insert(InflightEntry::new(&inflight_question, tx));
                        cleanup_guard = Some(InflightCleanupGuard::new(
                            engine.inflight.clone(),
                            keys.inflight,
                        ));
                        None
                    }
                    // A request holding an entry (see `held_inflight`) never waits
                    // on one: the entry may be its own, which the next rule forwards
                    // under after a continue, or another request's that waits on
                    // this one in turn (continue, then jump into each other's
                    // pipeline). It forwards itself instead.
                    // 持有条目的请求（见 `held_inflight`）从不等条目：这一条可能就是它
                    // 自己的（continue 后下一条规则以相同 hash 转发），也可能是另一个
                    // 反过来在等它的请求的（continue 后互相跳进对方的 pipeline）。它
                    // 自己转发。
                    Entry::Occupied(_) if held_inflight.is_some() => None,
                    // Another question's entry under the same key: the key is only a hash (see
                    // `InflightQuestion`), and waiting on it would hand this request another
                    // question's answer. It forwards itself instead.
                    // 同一个键下别的问题的条目：键只是哈希（见 `InflightQuestion`），等它就会把
                    // 别的问题的应答交给这个请求。它自己转发。
                    Entry::Occupied(entry) if !entry.get().asks(&inflight_question) => None,
                    Entry::Occupied(entry) => {
                        let rx = entry.get().tx.subscribe();
                        Some(rx)
                    }
                };

                if let Some(mut rx) = rx
                    && rx.changed().await.is_ok()
                {
                    if let Some((observer, ctx)) = observed {
                        observer.inflight_joined(ctx);
                    }
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
            let rx = match engine.inflight.entry(keys.inflight) {
                Entry::Vacant(entry) => {
                    let (tx, _rx) = tokio::sync::watch::channel(inflight_pending());
                    entry.insert(InflightEntry::new(&inflight_question, tx));
                    cleanup_guard = Some(InflightCleanupGuard::new(
                        engine.inflight.clone(),
                        keys.inflight,
                    ));
                    None
                }
                // See the same arm above / 同上
                Entry::Occupied(_) if held_inflight.is_some() => None,
                // See the same arm above / 同上
                Entry::Occupied(entry) if !entry.get().asks(&inflight_question) => None,
                Entry::Occupied(entry) => {
                    let rx = entry.get().tx.subscribe();
                    Some(rx)
                }
            };

            if let Some(mut rx) = rx
                && rx.changed().await.is_ok()
            {
                if let Some((observer, ctx)) = observed {
                    observer.inflight_joined(ctx);
                }
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
            // What comes back is a reply of this forward's own, reused or not before
            // 取回的是这次转发自己的应答，不论之前是不是复用的
            reused = false;
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

    // Now that a refresh runs the response rules, it takes a failure reply as a
    // failed attempt before they see it, as forward_upstream does for a rule with
    // several upstreams: the refresh takes the failure path such a rule takes,
    // miss actions included, and never caches the reply (see
    // reject_failure_reply_on_refresh).
    // 刷新执行响应规则之后，失败应答在响应规则看到之前就被当作一次失败的尝试，和规则有
    // 多个上游时 forward_upstream 的做法一样：刷新走这样的规则会走的失败路径（包括
    // on_miss 动作），也不缓存这个应答（见 reject_failure_reply_on_refresh）。
    let resp = resp
        .and_then(|reply| reject_failure_reply_on_refresh(skip_cache, &reply.0).map(|()| reply));

    // The reply, or the failure, decides whom every answer reached from here applies to
    // 应答（或失败）决定此后得到的每份应答适用于谁
    match &resp {
        Ok(_) if reused => {}
        Ok((raw, _)) => trail.record_reply(forward_ecs, raw),
        Err(_) => trail.record_failure(forward_ecs),
    }

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

            let cache_ttl = ttl_to_cache(engine, ttl_secs_cache, min_ttl);

            // Try to acquire read locks non-blockingly (fast path for concurrent reads)
            // 尝试非阻塞获取读锁（并发读的快速路径）
            let (resp_match_ok, msg) = {
                let (geoip_manager, geosite_manager) = rules::acquire_geo_locks(engine);

                let geoip_manager_ref = geoip_manager.as_deref();
                let geosite_manager_ref = geosite_manager.as_deref();

                if let Some(m) = msg_opt {
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

            // A refresh reports these too: it acts on the response rules like a client
            // request, and the observer tells the two apart by background_refresh.
            // 刷新同样上报：它和客户端请求一样按响应规则行事，观察者按 background_refresh 区分。
            if !response_matchers.is_empty()
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

            // A background refresh applies the response rules as a client request
            // does (a failure reply never gets here, see above): an answer a rule
            // continues past, or replaces, must not be what the refresh caches.
            // 后台刷新和客户端请求一样执行响应规则（失败应答到不了这里，见上）：规则
            // 越过或替换掉的应答，不能成为刷新写进缓存的结果。
            let empty_actions = Vec::new();
            let actions_to_run =
                if !response_actions_on_match.is_empty() || !response_actions_on_miss.is_empty() {
                    if resp_match_ok {
                        response_actions_on_match
                    } else {
                        response_actions_on_miss
                    }
                } else {
                    &empty_actions
                };

            if actions_to_run.is_empty() {
                if cache_ttl > 0 {
                    let refresh_ttl = proto_utils::saturating_u64_to_u32(ttl_secs_refresh);
                    engine.insert_dns_cache_entry(
                        keys.slot,
                        CacheEntry::from_response(
                            raw.clone(),
                            rcode,
                            Some(Arc::from(actual_upstream.as_str())),
                            qname,
                            Arc::from(pipeline_id),
                            u16::from(qtype),
                            (cache_ttl, refresh_ttl),
                        )
                        .with_reach(trail.clone()),
                    );
                }
                if let Some(g) = cleanup_guard.as_mut() {
                    g.defuse();
                    engine
                        .notify_inflight_waiters(keys.inflight, || {
                            for_waiters(&raw, &requester, trail, echo_floor)
                        })
                        .await;
                }

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
                trail: Some((&mut *trail, forward_ecs)),
            };

            let action_result = rules::apply_response_actions_observed(ctx, observed).await?;

            match action_result {
                ResponseActionResult::Upstream { ctx, resp_match: _ } => {
                    // The reply to a response action's forward (see
                    // reject_failure_reply_on_refresh)
                    // 响应动作转发拿到的应答（见 reject_failure_reply_on_refresh）
                    reject_failure_reply_on_refresh(skip_cache, &ctx.raw)?;
                    let ttl_secs_cache = extract_ttl(&ctx.msg);
                    let ttl_secs_refresh = extract_ttl_for_refresh(&ctx.msg);
                    let cache_ttl = ttl_to_cache(engine, ttl_secs_cache, min_ttl);
                    if cache_ttl > 0 {
                        let refresh_ttl = proto_utils::saturating_u64_to_u32(ttl_secs_refresh);
                        engine.insert_dns_cache_entry(
                            keys.slot,
                            CacheEntry::from_response(
                                ctx.raw.clone(),
                                ctx.msg.metadata.response_code,
                                Some(ctx.upstream.clone()),
                                qname,
                                Arc::from(pipeline_id),
                                u16::from(qtype),
                                (cache_ttl, refresh_ttl),
                            )
                            .with_reach(trail.clone()),
                        );
                    }
                    if let Some(g) = cleanup_guard.as_mut() {
                        g.defuse();
                        engine
                            .notify_inflight_waiters(keys.inflight, || {
                                for_waiters(&ctx.raw, &requester, trail, echo_floor)
                            })
                            .await;
                    }
                    response.upstream = Some(ctx.upstream);
                    Ok(ForwardResult::Success(ctx.raw))
                }
                ResponseActionResult::Static { bytes, rcode, .. } => {
                    // A SERVFAIL here mostly means the response actions found no
                    // answer either (a response-phase forward failed or ran past its
                    // limit, or the jump limit was reached); a static SERVFAIL the
                    // rules configure is taken the same way. A refresh ends as a
                    // failure rather than cache SERVFAIL over the entry it was
                    // refreshing.
                    // 这里的 SERVFAIL 多半说明响应动作也没拿到应答（响应阶段的转发失败或
                    // 超过次数上限，或到了跳转上限）；规则里配置的静态 SERVFAIL 也按这个
                    // 处理。刷新以失败结束，而不是把 SERVFAIL 写进缓存、盖掉它要刷新的那条。
                    if skip_cache && rcode == ResponseCode::ServFail {
                        return Err(refresh_found_no_answer(
                            "the response actions found no answer",
                        ));
                    }
                    if min_ttl > Duration::from_secs(0) {
                        let ttl = proto_utils::saturating_u64_to_u32(min_ttl.as_secs());
                        engine.insert_dns_cache_entry(
                            keys.slot,
                            CacheEntry::from_response(
                                bytes.clone(),
                                rcode,
                                None,
                                qname,
                                Arc::from(pipeline_id),
                                u16::from(qtype),
                                (ttl, ttl),
                            )
                            .with_reach(trail.clone()),
                        );
                    } else if skip_cache {
                        // An answer that is not cached cannot renew the entry, so the
                        // refresh drops it and the next client request runs the rules.
                        // 不缓存的应答无法更新这条缓存，所以刷新把它删掉，下一个客户端
                        // 请求自己执行规则。
                        if let Some(target) = refresh {
                            engine.drop_refreshed(keys.slot, &question, &view, target);
                        }
                    }
                    if let Some(g) = cleanup_guard.as_mut() {
                        g.defuse();
                        engine
                            .notify_inflight_waiters(keys.inflight, || {
                                for_waiters(&bytes, &requester, trail, echo_floor)
                            })
                            .await;
                    }
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
                            client_ecs: requester.ecs,
                            upstream_timeout,
                            skip_cache,
                            // The ECS the forward added travels with the packet / 转发加上的 ECS 随包带过去
                            carried: forward_ecs,
                            trail: &mut *trail,
                            echo_floor,
                            observed,
                            held_inflight: [
                                cleanup_guard.as_ref().map(|guard| guard.hash),
                                held_inflight.as_ref().map(|guard| guard.hash),
                            ],
                        },
                        response,
                    )
                    .await?;

                    // The target pipeline's answer is not stored under this key (it
                    // caches under its own, if at all), so on a refresh the entry here
                    // no longer matches the rules and is dropped (see the Static arm).
                    // If the target found no answer, the refresh ends as a failure and
                    // the entry stays.
                    // 目标 pipeline 的应答不会存进这个键（要存也存在它自己的键下），所以刷新
                    // 时这里的条目已经和规则对不上，删掉（同 Static 分支）。目标没拿到应答
                    // 时，刷新以失败结束，条目保留。
                    if skip_cache {
                        if is_servfail(&resp_bytes) || proto_utils::truncated_response(&resp_bytes)
                        {
                            return Err(refresh_found_no_answer("the jump target found no answer"));
                        }
                        if let Some(target) = refresh {
                            engine.drop_refreshed(keys.slot, &question, &view, target);
                        }
                    }
                    if let Some(g) = cleanup_guard.as_mut() {
                        g.defuse();
                        engine
                            .notify_inflight_waiters(keys.inflight, || {
                                for_waiters(&resp_bytes, &requester, trail, echo_floor)
                            })
                            .await;
                    }
                    Ok(ForwardResult::Success(resp_bytes))
                }
                ResponseActionResult::Continue { ctx } => {
                    // The rule continued past this response, so it is not the
                    // answer: keep the entry for the rest of the decision loop
                    // (see `held_inflight`) instead of handing it to waiters. An
                    // entry held from an earlier continue is dropped in its place,
                    // and its waiters forward themselves.
                    // 规则越过了这个应答，它不是最终结果：条目留给决策循环的后续
                    // 部分（见 `held_inflight`），不把它交给等待者。之前 continue
                    // 时持有的条目被它替换掉，那一条的等待者自己转发。
                    if let Some(guard) = cleanup_guard.take() {
                        *held_inflight = Some(guard);
                    }
                    Ok(ForwardResult::Continue {
                        ctx: Box::new(ctx),
                        after_failure: false,
                    })
                }
            }
        }
        Err(e) => {
            if response_actions_on_miss.is_empty() {
                // The stale answer and the SERVFAIL below answer a client once every
                // upstream attempt is exhausted. A background refresh has no client and
                // never registered in `inflight`, so it gets the failure itself, which
                // refresh.rs logs, and neither the cached entry nor other requests'
                // waiters are touched.
                // 下面的过期应答和 SERVFAIL 只在所有上游尝试都耗尽时用来应答客户端。
                // 后台刷新没有客户端，也没在 inflight 里登记，所以把失败原样交回，由
                // refresh.rs 记录；缓存条目和别的请求的等待者都不受影响。
                if skip_cache || e.downcast_ref::<UpstreamFailure>().is_none() {
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
                        slot: keys.slot,
                        tx_id,
                        start,
                        peer,
                        requester,
                        observed,
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
                        engine
                            .notify_inflight_waiters(keys.inflight, || {
                                for_waiters(&stale_bytes, &requester, trail, echo_floor)
                            })
                            .await;
                    }
                    return Ok(ForwardResult::Fallback(stale_bytes));
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
                    engine
                        .notify_inflight_waiters(keys.inflight, || {
                            for_waiters(&resp_bytes, &requester, trail, echo_floor)
                        })
                        .await;
                }

                Ok(ForwardResult::Fallback(resp_bytes))
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
                    trail: Some((&mut *trail, forward_ecs)),
                };
                let action_result = rules::apply_response_actions_observed(ctx, observed).await?;

                match action_result {
                    ResponseActionResult::Upstream { ctx, resp_match: _ } => {
                        // The reply to a miss action's forward / on_miss 动作转发拿到的应答
                        reject_failure_reply_on_refresh(skip_cache, &ctx.raw)?;
                        let ttl_secs_cache = extract_ttl(&ctx.msg);
                        let ttl_secs_refresh = extract_ttl_for_refresh(&ctx.msg);
                        let cache_ttl = ttl_to_cache(engine, ttl_secs_cache, min_ttl);
                        if cache_ttl > 0 {
                            let refresh_ttl = proto_utils::saturating_u64_to_u32(ttl_secs_refresh);
                            engine.insert_dns_cache_entry(
                                keys.slot,
                                CacheEntry::from_response(
                                    ctx.raw.clone(),
                                    ctx.msg.metadata.response_code,
                                    Some(ctx.upstream.clone()),
                                    qname,
                                    Arc::from(pipeline_id),
                                    u16::from(qtype),
                                    (cache_ttl, refresh_ttl),
                                )
                                .with_reach(trail.clone()),
                            );
                        }
                        if let Some(g) = cleanup_guard.as_mut() {
                            g.defuse();
                            engine
                                .notify_inflight_waiters(keys.inflight, || {
                                    for_waiters(&ctx.raw, &requester, trail, echo_floor)
                                })
                                .await;
                        }
                        response.upstream = Some(ctx.upstream);
                        Ok(ForwardResult::Fallback(ctx.raw))
                    }
                    ResponseActionResult::Static { bytes, rcode, .. } => {
                        // The upstream already failed, so a SERVFAIL here means the miss
                        // actions found no answer either. A refresh gets the failure rather
                        // than caching SERVFAIL over the entry it was refreshing.
                        // 上游已经失败，这里的 SERVFAIL 说明 on_miss 动作也没拿到应答。刷新
                        // 把失败交回，而不是把 SERVFAIL 写进缓存、盖掉它要刷新的那条。
                        if skip_cache && rcode == ResponseCode::ServFail {
                            return Err(e);
                        }
                        if min_ttl > Duration::from_secs(0) {
                            let ttl = proto_utils::saturating_u64_to_u32(min_ttl.as_secs());
                            engine.insert_dns_cache_entry(
                                keys.slot,
                                CacheEntry::from_response(
                                    bytes.clone(),
                                    rcode,
                                    None,
                                    qname,
                                    Arc::from(pipeline_id),
                                    u16::from(qtype),
                                    (ttl, ttl),
                                )
                                .with_reach(trail.clone()),
                            );
                        }
                        if let Some(g) = cleanup_guard.as_mut() {
                            g.defuse();
                            engine
                                .notify_inflight_waiters(keys.inflight, || {
                                    for_waiters(&bytes, &requester, trail, echo_floor)
                                })
                                .await;
                        }
                        response.upstream = Some(Arc::from("static"));
                        Ok(ForwardResult::Fallback(bytes))
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
                                client_ecs: requester.ecs,
                                upstream_timeout,
                                skip_cache,
                                // The ECS the forward added travels with the packet / 转发加上的 ECS 随包带过去
                                carried: forward_ecs,
                                trail: &mut *trail,
                                echo_floor,
                                observed,
                                held_inflight: [
                                    cleanup_guard.as_ref().map(|guard| guard.hash),
                                    held_inflight.as_ref().map(|guard| guard.hash),
                                ],
                            },
                            response,
                        )
                        .await?;

                        // The target found no answer either: a refresh gets the upstream
                        // failure, as in the Static arm
                        // 目标也没拿到应答：刷新拿到的是上游的失败，同 Static 分支
                        if skip_cache && is_servfail(&resp_bytes) {
                            return Err(e);
                        }
                        if let Some(g) = cleanup_guard.as_mut() {
                            g.defuse();
                            engine
                                .notify_inflight_waiters(keys.inflight, || {
                                    for_waiters(&resp_bytes, &requester, trail, echo_floor)
                                })
                                .await;
                        }
                        Ok(ForwardResult::Fallback(resp_bytes))
                    }
                    ResponseActionResult::Continue { ctx } => {
                        // Same as the Continue on a response above (see `held_inflight`).
                        // Defusing the guard here used to leave the entry behind with
                        // nobody holding it, so the next Forward waited on it until the
                        // listener timeout.
                        // 同上面有应答时的 Continue（见 `held_inflight`）。以前这里 defuse
                        // 守卫，条目留在表里却没人持有，下一条转发会一直等它到监听器超时。
                        if let Some(guard) = cleanup_guard.take() {
                            *held_inflight = Some(guard);
                        }
                        Ok(ForwardResult::Continue {
                            ctx: Box::new(ctx),
                            after_failure: true,
                        })
                    }
                }
            }
        }
    }
}

/// The error a background refresh ends with when its rules found no answer: the
/// refresh counts as failed and the cached entry stays.
/// 后台刷新的规则没找到应答时以这个错误结束：算作刷新失败，缓存条目保留。
pub(crate) fn refresh_found_no_answer(reason: &'static str) -> anyhow::Error {
    anyhow::Error::new(UpstreamFailure::new(anyhow::anyhow!(reason)))
}

/// The reply as it goes to the client, with the ECS option RFC 7871 section 7.2.2
/// asks for. A client that sent no ECS gets none: a forward may have added one
/// for it (`from_client_ip`, `static`). A client that sent ECS gets its own subnet
/// back, with a scope of at least `at_least`: how many bits of the client's ECS
/// the forwards this request passed made the answer depend on (see
/// `EcsReach::echo_scope`), which is what the cache keeps the answer for. The
/// reply itself may say more: an echo of that subnet keeps a longer scope; an
/// error without ECS, or an echo of another subnet (a forward that replaced the
/// client's), says nothing of how far the answer reaches beyond the client's
/// subnet, so it takes the client's own prefix. Answers from the cache already
/// carry their echo (see `served_from_cache`). An ECS option nobody can read is
/// left alone.
/// 交给客户端的应答，带上 RFC 7871 第 7.2.2 节要求的 ECS 选项。没带 ECS 的客户端拿到的应答
/// 不带 ECS：转发可能替它加过（`from_client_ip`、`static`）。带了 ECS 的客户端拿回自己的子网，
/// 作用范围至少为 `at_least`：这个请求经过的转发让应答依赖客户端 ECS 的多少位（见
/// `EcsReach::echo_scope`），缓存也是按这个范围保存应答的。应答本身可能说得更多：回显了这个
/// 子网就保留更长的作用范围；不带 ECS 的报错、或回显了别的子网（转发换掉了客户端的），没说明
/// 应答在客户端子网之外适用到多大范围，于是取客户端自己的前缀。缓存里的应答已经带着回显（见
/// `served_from_cache`）。谁也读不懂的 ECS 选项不动。
pub(crate) fn client_reply(
    reply: Bytes,
    client: Option<&crate::ecs::EcsKey>,
    at_least: u8,
) -> Bytes {
    use crate::ecs_scope::ReplyEcs;
    let Some(client) = client else {
        return proto_utils::ecs_removed(reply);
    };
    if client.is_opaque() {
        return reply;
    }
    let scope = match proto_utils::reply_ecs(&reply) {
        (ReplyEcs::Subnet { subnet, scope }, _) if subnet == *client => {
            if scope >= at_least {
                return reply;
            }
            at_least
        }
        // The forward cut the client's subnet short (`from_client_ip`, RFC 7871
        // section 7.1): the echo names the client's own network, so its scope holds
        // for the client, as on a cache hit
        // 转发把客户端的子网截短了（`from_client_ip`，RFC 7871 第 7.1 节）：回显的是客户端自己
        // 所在的网段，它的作用范围对客户端同样成立，和命中缓存时一样
        (ReplyEcs::Subnet { subnet, scope }, _)
            if subnet.source_prefix < client.source_prefix
                && client.truncated(subnet.source_prefix) == subnet =>
        {
            scope.max(at_least)
        }
        (ReplyEcs::Subnet { .. }, _) | (ReplyEcs::Absent, false) => {
            client.source_prefix.max(at_least)
        }
        (ReplyEcs::Absent, true) => at_least,
        (ReplyEcs::Unreadable, _) => return reply,
    };
    proto_utils::echo_ecs(&reply, client, scope).map_or(reply, Bytes::from)
}

/// What the waiters on this request's entry get: the reply as this request's
/// own client gets it (see `client_reply`). They send the same ECS, which the
/// inflight key carries, so the echo is theirs too and their own `client_reply`
/// keeps it.
/// 等在这个请求条目上的请求拿到的应答：和这个请求自己的客户端拿到的一样（见
/// `client_reply`）。它们发送的 ECS 相同（inflight 键带着它），回显也就是它们的，它们自己的
/// `client_reply` 会保留它。
pub(crate) fn for_waiters(
    reply: &Bytes,
    requester: &Requester,
    trail: &EcsReach,
    echo_floor: u8,
) -> Bytes {
    match requester.ecs {
        None => reply.clone(),
        Some(client) => client_reply(
            reply.clone(),
            Some(&client),
            echo_floor.max(trail.echo_scope(&requester.ecs_view())),
        ),
    }
}

/// Whether a response carries SERVFAIL / 响应是否为 SERVFAIL
pub(crate) fn is_servfail(bytes: &[u8]) -> bool {
    proto_utils::parse_response_quick(bytes).is_some_and(|qr| qr.rcode == ResponseCode::ServFail)
}

#[cfg(test)]
mod refresh_response_rule_tests {
    use crate::cache::CacheEntry;
    use crate::engine::core::Engine;
    use crate::matcher::RuntimePipelineConfig;
    use bytes::Bytes;
    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
    use hickory_proto::serialize::binary::BinDecodable;
    use serde_json::{Value, json};
    use std::net::{Ipv4Addr, SocketAddr};
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::Duration;

    const CLIENT: &str = "127.0.0.1:53000";
    /// Nothing listens here, so a fall-through to the default upstream fails.
    /// 这里没有监听，落到默认上游的请求会失败。
    const DEAD_UPSTREAM: &str = "127.0.0.1:9";
    /// What the entry being refreshed holds / 要刷新的那条缓存里的应答
    const OLD: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 9);
    /// What the first rule's upstream answers / 第一条规则的上游回的应答
    const PASSED_OVER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    /// What the second rule's upstream answers / 第二条规则的上游回的应答
    const FINAL: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
    const STATIC: &str = "192.0.2.5";

    /// Local UDP upstream that answers every query with one A record.
    /// 本机 UDP 上游：每个查询都回一条 A 记录。
    async fn spawn_upstream_answering(ip: Ipv4Addr) -> String {
        spawn_upstream_answering_with(ip, false).await
    }

    /// The same, the answers truncated (TC set) when `truncated` is
    /// 同上，`truncated` 为真时应答带 TC 位
    async fn spawn_upstream_answering_with(ip: Ipv4Addr, truncated: bool) -> String {
        spawn_upstream_replying(move |query, question| {
            let mut resp = Message::new(query.id, MessageType::Response, OpCode::Query);
            resp.metadata.truncation = truncated;
            resp.add_query(question.clone());
            resp.add_answer(a_record(question, ip));
            resp
        })
        .await
    }

    /// Local UDP upstream that answers every query SERVFAIL.
    /// 本机 UDP 上游：每个查询都回 SERVFAIL。
    async fn spawn_upstream_answering_servfail() -> String {
        spawn_upstream_replying(|query, question| {
            let mut resp = Message::new(query.id, MessageType::Response, OpCode::Query);
            resp.metadata.response_code = ResponseCode::ServFail;
            resp.add_query(question.clone());
            resp
        })
        .await
    }

    /// 本机 UDP 上游：每个带问题的查询都回 `reply(查询, 问题)`
    /// Local UDP upstream answering every query with a question by `reply(query, question)`
    async fn spawn_upstream_replying(
        reply: impl Fn(&Message, &Query) -> Message + Send + 'static,
    ) -> String {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                let Ok(query) = Message::from_bytes(&buf[..n]) else {
                    continue;
                };
                let Some(question) = query.queries.first() else {
                    continue;
                };
                let resp = reply(&query, question);
                let _ = sock.send_to(&resp.to_vec().unwrap(), peer).await;
            }
        });
        addr
    }

    fn a_record(question: &Query, ip: Ipv4Addr) -> Record {
        Record::from_rdata(
            question.name().clone(),
            300,
            RData::A(hickory_proto::rr::rdata::A(ip)),
        )
    }

    fn query() -> Message {
        let mut request = Message::new(0x5157, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(
            Name::from_str("example.com.").unwrap(),
            RecordType::A,
        ));
        request
    }

    fn a_records(bytes: &[u8]) -> Vec<Ipv4Addr> {
        Message::from_bytes(bytes)
            .expect("parse reply")
            .answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::A(a) => Some(a.0),
                _ => None,
            })
            .collect()
    }

    /// A rule that matches every query / 匹配所有查询的规则
    fn rule(name: &str, actions: Value, response_rules: Value) -> Value {
        let mut rule = json!({ "name": name, "matchers": [{ "type": "any" }], "actions": actions });
        for (key, value) in response_rules.as_object().unwrap() {
            rule[key] = value.clone();
        }
        rule
    }

    fn forward(upstream: &str) -> Value {
        json!([{ "type": "forward", "upstream": upstream }])
    }

    fn answer_static() -> Value {
        json!([{ "type": "static_ip_response", "ip": STATIC }])
    }

    fn jump_to(pipeline: &str) -> Value {
        json!([{ "type": "jump_to_pipeline", "pipeline": pipeline }])
    }

    fn continue_() -> Value {
        json!([{ "type": "continue" }])
    }

    /// A jump target answering statically / 静态应答的跳转目标
    fn static_target() -> Value {
        rule("target", answer_static(), json!({}))
    }

    /// A jump target whose upstream never answers / 上游不应答的跳转目标
    fn failing_target() -> Value {
        rule("target", forward(DEAD_UPSTREAM), json!({}))
    }

    /// An engine whose pipeline "main" holds a cached answer with [`OLD`], as a
    /// client request left it; returns the key a refresh of it uses.
    /// 引擎的 "main" pipeline 里缓存着一条 [`OLD`] 应答，就像客户端请求留下的那样；
    /// 返回刷新它时用的键。
    fn engine_with_a_cached_answer(settings: Value, pipelines: Value) -> (Engine, u64) {
        let engine = engine_with(settings, pipelines);
        let key = cache_an_answer(&engine, "main", OLD, 300);
        (engine, key)
    }

    /// The same engine with nothing cached / 同样的引擎，缓存里什么也没有
    fn engine_with(settings: Value, pipelines: Value) -> Engine {
        let mut all_settings =
            json!({ "default_upstream": DEAD_UPSTREAM, "upstream_timeout_ms": 200 });
        for (key, value) in settings.as_object().unwrap() {
            all_settings[key] = value.clone();
        }
        let config: crate::config::PipelineConfig =
            serde_json::from_value(json!({ "settings": all_settings, "pipelines": pipelines }))
                .expect("parse config");
        Engine::new(
            RuntimePipelineConfig::from_config(config).expect("build runtime config"),
            "test".to_string(),
        )
        .expect("engine")
    }

    /// Caches an answer with `ip` for `pipeline` with the given TTL (0: already
    /// stale) and returns its key.
    /// 为 `pipeline` 缓存一条带 `ip` 的应答，TTL 为给定值（0 表示已经过期），返回它的键。
    fn cache_an_answer(engine: &Engine, pipeline: &str, ip: Ipv4Addr, ttl: u32) -> u64 {
        let key = slot_of(engine, pipeline);
        let request = query();
        let mut reply = Message::new(request.id, MessageType::Response, OpCode::Query);
        reply.add_query(request.queries[0].clone());
        reply.add_answer(a_record(&request.queries[0], ip));
        // What a client without ECS gets from a forward without `ecs`: the reach a real
        // request in these pipelines caches with, so a refresh replaces it as usual
        // 不带 ECS 的客户端经不写 `ecs` 的转发得到的应答：这些 pipeline 里真实请求缓存时带的
        // 适用范围，刷新照常取代它
        let mut reach = crate::ecs_scope::EcsReach::default();
        reach.record(
            crate::ecs_scope::ForwardEcs {
                source: crate::ecs_scope::EcsSource::Client,
                sent: crate::ecs_scope::Sent::Absent,
            },
            crate::ecs_scope::ReplyEcs::Absent,
            true,
        );
        engine.insert_dns_cache_entry(
            key,
            CacheEntry::from_response(
                Bytes::from(reply.to_vec().unwrap()),
                ResponseCode::NoError,
                Some(Arc::from(DEAD_UPSTREAM)),
                "example.com",
                Arc::from(pipeline),
                u16::from(RecordType::A),
                (ttl, ttl),
            )
            .with_reach(reach),
        );
        key
    }

    /// [`query`] 在 `pipeline` 里的缓存槽位 / The cache slot of [`query`] in `pipeline`
    fn slot_of(engine: &Engine, pipeline: &str) -> u64 {
        let state = engine.state.load_full();
        Engine::cache_keys(
            state.cache_namespace(pipeline),
            pipeline,
            b"example.com",
            RecordType::A,
            DNSClass::IN,
            &crate::matcher::RequesterKey::NONE,
            None,
        )
        .slot
    }

    /// 三条会写缓存的路径，各一条规则，回答都来自 `upstream`：直接转发、应答之后响应动作的转发、
    /// 上游失败后 on_miss 的转发
    /// The three paths that cache, one rule each with its answer from `upstream`: a
    /// plain forward, a response action's forward after an answer, an on_miss
    /// forward after the upstream failed
    fn caching_paths(upstream: &str) -> [(&'static str, Value); 3] {
        [
            ("forward", rule("all", forward(upstream), json!({}))),
            (
                "response action",
                rule(
                    "all",
                    forward(upstream),
                    json!({
                        "response_matchers": [{ "type": "upstream_equals", "value": upstream }],
                        "response_actions_on_match": forward(upstream)
                    }),
                ),
            ),
            (
                "miss action",
                rule(
                    "all",
                    forward(DEAD_UPSTREAM),
                    json!({ "response_actions_on_miss": forward(upstream) }),
                ),
            ),
        ]
    }

    /// 回答里每条记录的 TTL，按段的先后 / The TTL of every record in a reply, section by section
    fn record_ttls(bytes: &[u8]) -> Vec<u32> {
        let msg = Message::from_bytes(bytes).expect("parse reply");
        msg.answers
            .iter()
            .chain(&msg.authorities)
            .map(|record| record.ttl)
            .collect()
    }

    /// 上游回答里每条记录的 TTL 都收进 min_ttl 到 cache_max_ttl 之间，缓存也照收过的存，客户端留一份
    /// 回答的时间就和缓存一样长；两者冲突时以 cache_max_ttl 为准。此前 min_ttl 只决定存不存，条目还是
    /// 照上游的 TTL 过期；cache_max_ttl 只限制条目存多久，客户端拿到的仍是上游的 TTL。
    /// The TTL of every record in an upstream answer is brought into min_ttl to
    /// cache_max_ttl and the cache keeps what was brought in, so a client keeps an
    /// answer as long as the cache does; cache_max_ttl wins when the two cross.
    /// min_ttl used to decide only whether an answer was cached, the entry still
    /// expiring by the upstream's TTL; cache_max_ttl only bounded how long an entry
    /// was kept, clients still getting the upstream's TTL.
    #[tokio::test]
    async fn answers_carry_and_are_cached_with_ttls_within_min_ttl_and_cache_max_ttl() {
        let upstream = spawn_upstream_replying(|query, question| {
            let mut resp = Message::new(query.id, MessageType::Response, OpCode::Query);
            resp.add_query(question.clone());
            for (ttl, last) in [(5, 1), (100_000, 2)] {
                resp.add_answer(Record::from_rdata(
                    question.name().clone(),
                    ttl,
                    RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(192, 0, 2, last))),
                ));
            }
            resp
        })
        .await;
        let rules = caching_paths(&upstream);
        let cases = [
            (
                json!({ "min_ttl": 60, "cache_max_ttl": 3600 }),
                [60, 3600],
                (60, 3600),
            ),
            (
                json!({ "min_ttl": 600, "cache_max_ttl": 300 }),
                [300, 300],
                (300, 300),
            ),
            (json!({}), [5, 86_400], (5, 86_400)),
        ];
        for (path, rule) in &rules {
            for (settings, carried, cached) in &cases {
                let engine =
                    engine_with(settings.clone(), json!([{ "id": "main", "rules": [rule] }]));
                for round in ["miss", "hit"] {
                    let reply = engine
                        .handle_packet(&query().to_vec().unwrap(), CLIENT.parse().unwrap())
                        .await
                        .expect("answered");
                    let ttls = record_ttls(&reply);
                    // 命中时减去已经缓存的秒数，跨过一秒的边界时少 1 / A hit takes off the seconds cached, 1 past a second boundary
                    assert!(
                        ttls == *carried || ttls == carried.map(|ttl| ttl - 1),
                        "{path} {settings} {round}: {ttls:?}"
                    );
                }
                let entry = engine.cached(slot_of(&engine, "main")).expect("cached");
                assert_eq!(
                    (entry.original_ttl, entry.refresh_ttl),
                    *cached,
                    "{path} {settings}"
                );
            }
        }
    }

    /// 否定回答按 SOA 的负缓存 TTL 缓存，同样收进 min_ttl 到 cache_max_ttl 之间；没有 SOA 的照旧不缓存
    /// （RFC 2308 第 4 节）。
    /// A negative answer is cached by its SOA negative TTL, brought into min_ttl to
    /// cache_max_ttl as well; one without SOA is still not cached (RFC 2308 section 4).
    #[tokio::test]
    async fn negative_answers_are_cached_within_min_ttl_and_cache_max_ttl() {
        for (soa, settings, carried, cached) in [
            (Some((10, 5)), json!({ "min_ttl": 60 }), vec![60], Some(60)),
            (
                Some((100_000, 100_000)),
                json!({ "cache_max_ttl": 3600 }),
                vec![3600],
                Some(3600),
            ),
            (None, json!({ "min_ttl": 60 }), vec![], None),
        ] {
            let upstream = spawn_upstream_replying(move |query, question| {
                let mut resp = Message::new(query.id, MessageType::Response, OpCode::Query);
                resp.metadata.response_code = ResponseCode::NXDomain;
                resp.add_query(question.clone());
                if let Some((ttl, minimum)) = soa {
                    let soa = hickory_proto::rr::rdata::SOA::new(
                        Name::from_str("ns.example.com.").unwrap(),
                        Name::from_str("admin.example.com.").unwrap(),
                        1,
                        3600,
                        900,
                        1_209_600,
                        minimum,
                    );
                    resp.add_authority(Record::from_rdata(
                        Name::from_str("example.com.").unwrap(),
                        ttl,
                        RData::SOA(soa),
                    ));
                }
                resp
            })
            .await;
            for (path, rule) in caching_paths(&upstream) {
                let engine =
                    engine_with(settings.clone(), json!([{ "id": "main", "rules": [rule] }]));
                let reply = engine
                    .handle_packet(&query().to_vec().unwrap(), CLIENT.parse().unwrap())
                    .await
                    .expect("answered");
                assert_eq!(record_ttls(&reply), carried, "{path} {settings}");
                assert_eq!(
                    engine
                        .cached(slot_of(&engine, "main"))
                        .map(|entry| entry.original_ttl),
                    cached,
                    "{path} {settings}"
                );
            }
        }
    }

    /// Runs the call `spawn_background_refresh` makes and returns what the
    /// refreshed key holds afterwards: its A records, or None once dropped.
    /// 执行与 `spawn_background_refresh` 相同的调用，返回之后那个键里的 A 记录，
    /// 被删掉时返回 None。
    async fn refresh(engine: &Engine, key: u64) -> Option<Vec<Ipv4Addr>> {
        refresh_as(engine, key, engine.refresh_of(key)).await
    }

    /// The same, also telling whether the refresh counts as a success, which is
    /// what refresh.rs logs
    /// 同上，另外给出刷新算不算成功，也就是 refresh.rs 记录的结果
    async fn refresh_succeeds(engine: &Engine, key: u64) -> (bool, Option<Vec<Ipv4Addr>>) {
        let result = refresh_result(engine, key).await;
        (
            result.is_ok(),
            engine.cached(key).map(|entry| a_records(&entry.bytes)),
        )
    }

    /// What the refresh call returns / 刷新调用的返回值
    async fn refresh_result(engine: &Engine, key: u64) -> anyhow::Result<Bytes> {
        let client: SocketAddr = CLIENT.parse().unwrap();
        tokio::time::timeout(
            Duration::from_secs(5),
            engine.handle_packet_internal(
                &query().to_vec().unwrap(),
                client,
                true,
                None,
                Some(engine.refresh_of(key)),
                Some(engine.state.load_full()),
            ),
        )
        .await
        .expect("refresh finishes")
    }

    /// The same, renewing what `target` names / 同上，更新 `target` 所指的条目
    async fn refresh_as(
        engine: &Engine,
        key: u64,
        target: crate::engine::refresh::RefreshTarget,
    ) -> Option<Vec<Ipv4Addr>> {
        let client: SocketAddr = CLIENT.parse().unwrap();
        let state = engine.state.load_full();
        let _ = tokio::time::timeout(
            Duration::from_secs(5),
            engine.handle_packet_internal(
                &query().to_vec().unwrap(),
                client,
                true,
                None,
                Some(target),
                Some(state),
            ),
        )
        .await
        .expect("refresh finishes");
        engine.cached(key).map(|entry| a_records(&entry.bytes))
    }

    /// Rule `first` asks the upstream answering [`PASSED_OVER`] with the given
    /// response rules; rule `second` asks the upstream answering [`FINAL`].
    /// 规则 `first` 带着给定的响应规则问回 [`PASSED_OVER`] 的上游；规则 `second`
    /// 问回 [`FINAL`] 的上游。
    async fn refresh_past_the_first_answer(
        response_rules: impl FnOnce(&str, &str) -> Value,
    ) -> Option<Vec<Ipv4Addr>> {
        let first = spawn_upstream_answering(PASSED_OVER).await;
        let second = spawn_upstream_answering(FINAL).await;
        let (engine, key) = engine_with_a_cached_answer(
            json!({}),
            json!([{ "id": "main", "rules": [
                rule("first", forward(&first), response_rules(&first, &second)),
                rule("second", forward(&second), json!({})),
            ]}]),
        );
        refresh(&engine, key).await
    }

    /// Rule `first` asks the upstream answering [`PASSED_OVER`] and runs the
    /// given actions on its answer; `later_rules` follow it, and pipeline
    /// "other", the jump target, has the single rule `target`.
    /// 规则 `first` 问回 [`PASSED_OVER`] 的上游，并对它的应答执行给定的动作；
    /// `later_rules` 跟在它后面，跳转目标 pipeline "other" 只有一条规则 `target`。
    async fn refresh_with_actions_on_the_answer(
        settings: Value,
        actions_on_match: Value,
        later_rules: Vec<Value>,
        target: Value,
    ) -> Option<Vec<Ipv4Addr>> {
        let first = spawn_upstream_answering(PASSED_OVER).await;
        let mut rules = vec![rule(
            "first",
            forward(&first),
            json!({ "response_actions_on_match": actions_on_match }),
        )];
        rules.extend(later_rules);
        let (engine, key) = engine_with_a_cached_answer(
            settings,
            json!([
                { "id": "main", "rules": rules },
                { "id": "other", "rules": [target] }
            ]),
        );
        refresh(&engine, key).await
    }

    #[tokio::test]
    async fn a_refresh_continues_past_an_answer_on_match() {
        let cached = refresh_past_the_first_answer(|first, _| {
            json!({
                "response_matchers": [{ "type": "upstream_equals", "value": first }],
                "response_actions_on_match": continue_()
            })
        })
        .await;
        assert_eq!(cached, Some(vec![FINAL]));
    }

    #[tokio::test]
    async fn a_refresh_continues_past_an_answer_on_miss() {
        let cached = refresh_past_the_first_answer(|_, second| {
            json!({
                "response_matchers": [{ "type": "upstream_equals", "value": second }],
                "response_actions_on_miss": continue_()
            })
        })
        .await;
        assert_eq!(cached, Some(vec![FINAL]));
    }

    #[tokio::test]
    async fn a_refresh_drops_the_entry_for_an_uncached_static_answer() {
        let cached =
            refresh_with_actions_on_the_answer(json!({}), answer_static(), vec![], static_target())
                .await;
        assert_eq!(cached, None);
    }

    /// 刷新进行中，这条过期应答被续用（serve_stale_ttl_reset）：它仍是刷新要更新的那份，
    /// 刷新照样把它删掉，否则续用可以让过时的应答一直留着。
    /// The stale answer renewed (serve_stale_ttl_reset) while its refresh runs is
    /// still the answer the refresh renews, and the refresh drops it all the same;
    /// otherwise renewals could keep an outdated answer forever.
    #[tokio::test]
    async fn a_refresh_drops_the_entry_renewed_while_it_ran() {
        let first = spawn_upstream_answering(PASSED_OVER).await;
        let (engine, key) = engine_with_a_cached_answer(
            json!({}),
            json!([
                { "id": "main", "rules": [rule(
                    "first",
                    forward(&first),
                    json!({ "response_actions_on_match": answer_static() })
                )] },
                { "id": "other", "rules": [static_target()] }
            ]),
        );
        let target = engine.refresh_of(key);
        let original = engine.cached(key).expect("cached");
        engine.cache_replace(key, &original, original.clone_with_refreshed_ttl());
        assert_eq!(refresh_as(&engine, key, target).await, None);
    }

    /// 刷新进行中，另一个请求给同样的请求方写进一份新应答：刷新要删的是它更新的那份，不是这份。
    /// While the refresh runs, another request writes a new answer for the same
    /// requesters: the refresh drops the answer it renews, not this one.
    #[tokio::test]
    async fn a_refresh_leaves_an_answer_another_request_wrote_meanwhile() {
        let first = spawn_upstream_answering(PASSED_OVER).await;
        let (engine, key) = engine_with_a_cached_answer(
            json!({}),
            json!([
                { "id": "main", "rules": [rule(
                    "first",
                    forward(&first),
                    json!({ "response_actions_on_match": answer_static() })
                )] },
                { "id": "other", "rules": [static_target()] }
            ]),
        );
        let target = engine.refresh_of(key);
        let original = engine.cached(key).expect("cached");
        let newer = CacheEntry {
            fetched_at: std::time::Instant::now(),
            ..(*original).clone()
        };
        engine.cache_insert(key, Arc::new(newer));
        assert_eq!(refresh_as(&engine, key, target).await, Some(vec![OLD]));
    }

    #[tokio::test]
    async fn a_refresh_caches_a_static_answer_under_min_ttl() {
        let settings = json!({ "min_ttl": 60 });
        let cached =
            refresh_with_actions_on_the_answer(settings, answer_static(), vec![], static_target())
                .await;
        assert_eq!(cached, Some(vec![STATIC.parse().unwrap()]));
    }

    #[tokio::test]
    async fn a_refresh_drops_the_entry_when_the_answer_jumps() {
        let cached = refresh_with_actions_on_the_answer(
            json!({}),
            jump_to("other"),
            vec![],
            static_target(),
        )
        .await;
        assert_eq!(cached, None);
    }

    #[tokio::test]
    async fn a_refresh_keeps_the_entry_when_the_jump_target_fails() {
        let cached = refresh_with_actions_on_the_answer(
            json!({}),
            jump_to("other"),
            vec![],
            failing_target(),
        )
        .await;
        assert_eq!(cached, Some(vec![OLD]));
    }

    #[tokio::test]
    async fn a_refresh_whose_response_actions_find_no_answer_keeps_the_entry() {
        // With no jumps left the jump action answers SERVFAIL / 跳转次数用完时跳转动作回 SERVFAIL
        let settings = json!({ "min_ttl": 60, "response_jump_limit": 0 });
        let cached =
            refresh_with_actions_on_the_answer(settings, jump_to("other"), vec![], static_target())
                .await;
        assert_eq!(cached, Some(vec![OLD]));
    }

    #[tokio::test]
    async fn a_refresh_keeps_the_entry_when_an_action_forward_answers_servfail() {
        let failing = spawn_upstream_answering_servfail().await;
        let settings = json!({ "min_ttl": 60 });
        let cached = refresh_with_actions_on_the_answer(
            settings,
            forward(&failing),
            vec![],
            static_target(),
        )
        .await;
        assert_eq!(cached, Some(vec![OLD]));
    }

    #[tokio::test]
    async fn a_refresh_runs_the_miss_actions_on_a_failure_reply() {
        let failing = spawn_upstream_answering_servfail().await;
        let backup = spawn_upstream_answering(FINAL).await;
        let (engine, key) = engine_with_a_cached_answer(
            json!({}),
            json!([{ "id": "main", "rules": [rule(
                "first",
                forward(&failing),
                json!({ "response_actions_on_miss": forward(&backup) })
            )]}]),
        );
        assert_eq!(refresh(&engine, key).await, Some(vec![FINAL]));
    }

    #[tokio::test]
    async fn a_refresh_keeps_the_entry_on_a_failure_reply_with_response_rules() {
        let failing = spawn_upstream_answering_servfail().await;
        let (engine, key) = engine_with_a_cached_answer(
            json!({}),
            json!([{ "id": "main", "rules": [rule(
                "first",
                forward(&failing),
                json!({
                    "response_matchers": [{ "type": "upstream_equals", "value": DEAD_UPSTREAM }],
                    "response_actions_on_miss": answer_static()
                })
            )]}]),
        );
        assert_eq!(refresh(&engine, key).await, Some(vec![OLD]));
    }

    #[tokio::test]
    async fn a_refresh_drops_the_entry_when_a_continue_reaches_a_static_answer() {
        let later = vec![rule("static", answer_static(), json!({}))];
        let cached =
            refresh_with_actions_on_the_answer(json!({}), continue_(), later, static_target())
                .await;
        assert_eq!(cached, None);
    }

    #[tokio::test]
    async fn a_refresh_caches_a_static_answer_a_continue_reaches_under_min_ttl() {
        let later = vec![rule("static", answer_static(), json!({}))];
        let settings = json!({ "min_ttl": 60 });
        let cached =
            refresh_with_actions_on_the_answer(settings, continue_(), later, static_target()).await;
        assert_eq!(cached, Some(vec![STATIC.parse().unwrap()]));
    }

    #[tokio::test]
    async fn a_refresh_drops_the_entry_when_a_continue_reaches_a_jump() {
        let later = vec![rule("jump", jump_to("other"), json!({}))];
        let cached =
            refresh_with_actions_on_the_answer(json!({}), continue_(), later, static_target())
                .await;
        assert_eq!(cached, None);
    }

    #[tokio::test]
    async fn a_refresh_drops_the_entry_when_a_continue_jumps_to_an_answering_target() {
        let answering = spawn_upstream_answering(FINAL).await;
        let later = vec![rule("jump", jump_to("other"), json!({}))];
        let target = rule("target", forward(&answering), json!({}));
        let cached =
            refresh_with_actions_on_the_answer(json!({}), continue_(), later, target).await;
        assert_eq!(cached, None);
    }

    #[tokio::test]
    async fn a_refresh_caches_the_answer_of_a_response_action_forward() {
        let replacement = spawn_upstream_answering(FINAL).await;
        let cached = refresh_with_actions_on_the_answer(
            json!({}),
            forward(&replacement),
            vec![],
            static_target(),
        )
        .await;
        assert_eq!(cached, Some(vec![FINAL]));
    }

    #[tokio::test]
    async fn a_refresh_caches_a_deny_under_min_ttl() {
        let first = spawn_upstream_answering(PASSED_OVER).await;
        let (engine, key) = engine_with_a_cached_answer(
            json!({ "min_ttl": 60 }),
            json!([{ "id": "main", "rules": [rule(
                "first",
                forward(&first),
                json!({ "response_actions_on_match": [{ "type": "deny" }] })
            )]}]),
        );
        refresh(&engine, key).await;
        let cached = engine.cached(key).expect("the refresh caches the deny");
        assert_eq!(cached.rcode, ResponseCode::Refused);
    }

    #[tokio::test]
    async fn a_refresh_keeps_the_entry_when_the_jump_target_gets_a_failure_reply() {
        let failing = spawn_upstream_answering_servfail().await;
        let target = rule(
            "target",
            forward(&failing),
            json!({
                "response_matchers": [{ "type": "upstream_equals", "value": DEAD_UPSTREAM }],
                "response_actions_on_miss": answer_static()
            }),
        );
        let cached =
            refresh_with_actions_on_the_answer(json!({}), jump_to("other"), vec![], target).await;
        assert_eq!(cached, Some(vec![OLD]));
    }

    #[tokio::test]
    async fn a_refresh_keeps_the_entry_when_a_continue_jumps_to_a_target_serving_stale() {
        let first = spawn_upstream_answering(PASSED_OVER).await;
        let (engine, key) = engine_with_a_cached_answer(
            json!({ "serve_stale": true }),
            json!([
                { "id": "main", "rules": [
                    rule("first", forward(&first), json!({ "response_actions_on_match": continue_() })),
                    rule("jump", jump_to("other"), json!({})),
                ]},
                { "id": "other", "rules": [failing_target()] }
            ]),
        );
        cache_an_answer(&engine, "other", FINAL, 0);
        assert_eq!(refresh(&engine, key).await, Some(vec![OLD]));
    }

    #[tokio::test]
    async fn a_refresh_keeps_the_entry_when_a_continue_jumps_to_a_failing_target() {
        let later = vec![rule("jump", jump_to("other"), json!({}))];
        let cached =
            refresh_with_actions_on_the_answer(json!({}), continue_(), later, failing_target())
                .await;
        assert_eq!(cached, Some(vec![OLD]));
    }

    #[tokio::test]
    async fn a_refresh_keeps_the_entry_when_a_continue_ends_in_servfail() {
        // A jump to a pipeline that does not exist answers SERVFAIL / 跳到不存在的 pipeline 回 SERVFAIL
        let later = vec![rule("jump", jump_to("nowhere"), json!({}))];
        let settings = json!({ "min_ttl": 60 });
        let cached =
            refresh_with_actions_on_the_answer(settings, continue_(), later, static_target()).await;
        assert_eq!(cached, Some(vec![OLD]));
    }

    #[tokio::test]
    async fn a_refresh_whose_next_rule_fails_keeps_the_entry() {
        let later = vec![rule("dead", forward(DEAD_UPSTREAM), json!({}))];
        let cached =
            refresh_with_actions_on_the_answer(json!({}), continue_(), later, static_target())
                .await;
        assert_eq!(cached, Some(vec![OLD]));
    }

    /// A jump target whose upstream never answers, and whose miss actions answer
    /// with `actions` instead
    /// 上游不应答、改由 on_miss 动作 `actions` 作答的跳转目标
    fn target_falling_back(actions: Value) -> Value {
        rule(
            "target",
            forward(DEAD_UPSTREAM),
            json!({ "response_actions_on_miss": actions }),
        )
    }

    /// Past a continue and a jump, the target's upstream fails and its miss actions
    /// answer: as when the rule's own upstream fails (see the next test), the
    /// refresh has no new answer for the entry, which stays.
    /// continue 再跳转之后，目标的上游失败、由它的 on_miss 动作作答：和规则自己的上游失败
    /// 时一样（见下一个测试），刷新没有拿到这个条目的新应答，条目保留。
    #[tokio::test]
    async fn a_refresh_keeps_the_entry_when_a_continue_jumps_to_a_target_that_falls_back() {
        let backup = spawn_upstream_answering(FINAL).await;
        for actions in [answer_static(), forward(&backup)] {
            let later = vec![rule("jump", jump_to("other"), json!({}))];
            let cached = refresh_with_actions_on_the_answer(
                json!({}),
                continue_(),
                later,
                target_falling_back(actions.clone()),
            )
            .await;
            assert_eq!(cached, Some(vec![OLD]), "{actions}");
        }
    }

    /// The same when the target's miss action jumps to a pipeline that answers
    /// 目标的 on_miss 动作跳到另一个作答的 pipeline 时也一样
    #[tokio::test]
    async fn a_refresh_keeps_the_entry_when_the_target_falls_back_by_a_jump() {
        let first = spawn_upstream_answering(PASSED_OVER).await;
        let (engine, key) = engine_with_a_cached_answer(
            json!({}),
            json!([
                { "id": "main", "rules": [
                    rule("first", forward(&first), json!({ "response_actions_on_match": continue_() })),
                    rule("jump", jump_to("other"), json!({})),
                ]},
                { "id": "other", "rules": [target_falling_back(jump_to("third"))] },
                { "id": "third", "rules": [static_target()] }
            ]),
        );
        assert_eq!(refresh(&engine, key).await, Some(vec![OLD]));
    }

    #[tokio::test]
    async fn a_refresh_whose_next_rule_falls_back_keeps_the_entry() {
        let later = vec![rule(
            "dead",
            forward(DEAD_UPSTREAM),
            json!({ "response_actions_on_miss": answer_static() }),
        )];
        let cached =
            refresh_with_actions_on_the_answer(json!({}), continue_(), later, static_target())
                .await;
        assert_eq!(cached, Some(vec![OLD]));
    }

    /// A refresh is after an answer to renew the entry with; one that ends in
    /// SERVFAIL found none, whatever produced it, and counts as a failure. With a
    /// `min_ttl` the SERVFAIL is not cached over the entry either.
    /// 刷新要的是拿来更新条目的应答；以 SERVFAIL 结束的刷新没拿到应答，不论 SERVFAIL 从
    /// 哪里来，都算失败。设了 `min_ttl` 时也不会把 SERVFAIL 缓存进来盖掉条目。
    #[tokio::test]
    async fn a_refresh_that_ends_in_servfail_fails() {
        let cases = [
            (
                "the jump limit",
                json!({ "response_jump_limit": 1 }),
                json!([
                    { "id": "main", "rules": [rule("jump", jump_to("other"), json!({}))] },
                    { "id": "other", "rules": [rule("back", jump_to("main"), json!({}))] }
                ]),
            ),
            (
                "a jump target that does not exist",
                json!({}),
                json!([{ "id": "main", "rules": [rule("jump", jump_to("nowhere"), json!({}))] }]),
            ),
            (
                "a static SERVFAIL",
                json!({}),
                json!([{ "id": "main", "rules": [rule(
                    "servfail",
                    json!([{ "type": "static_response", "rcode": "SERVFAIL" }]),
                    json!({})
                )] }]),
            ),
            (
                "a miss action jumping to a pipeline that does not exist",
                json!({}),
                json!([{ "id": "main", "rules": [rule(
                    "dead",
                    forward(DEAD_UPSTREAM),
                    json!({ "response_actions_on_miss": jump_to("nowhere") })
                )] }]),
            ),
        ];
        for (case, settings, pipelines) in cases {
            for min_ttl in [0, 60] {
                let mut settings = settings.clone();
                settings["min_ttl"] = json!(min_ttl);
                let (engine, key) = engine_with_a_cached_answer(settings, pipelines.clone());
                assert_eq!(
                    refresh_succeeds(&engine, key).await,
                    (false, Some(vec![OLD])),
                    "{case}, min_ttl {min_ttl}"
                );
            }
        }
    }

    /// After an upstream failure the rules go on (a miss action's continue) and a
    /// later rule answers: that answer is a fallback as well, and the entry stays,
    /// in the pipeline itself and in a jump target, whether the later rule answers
    /// statically or from another upstream.
    /// 上游失败后规则接着往下走（on_miss 的 continue），后面的规则作答：这个应答同样是兜底，
    /// 条目保留。无论在本 pipeline 还是跳转目标里、后面的规则是静态作答还是问另一个上游，
    /// 都一样。
    #[tokio::test]
    async fn a_refresh_keeps_the_entry_when_a_continue_after_a_failure_answers() {
        let first = spawn_upstream_answering(PASSED_OVER).await;
        let backup = spawn_upstream_answering(FINAL).await;
        let passed = || {
            rule(
                "first",
                forward(&first),
                json!({ "response_actions_on_match": continue_() }),
            )
        };
        let failing_then_on = || {
            rule(
                "dead",
                forward(DEAD_UPSTREAM),
                json!({ "response_actions_on_miss": continue_() }),
            )
        };
        let cases = [
            (
                "a static answer in the pipeline itself",
                json!([{ "id": "main", "rules": [
                    passed(), failing_then_on(), rule("static", answer_static(), json!({}))
                ]}]),
            ),
            (
                "a static answer in a jump target",
                json!([
                    { "id": "main", "rules": [passed(), rule("jump", jump_to("other"), json!({}))] },
                    { "id": "other", "rules": [
                        failing_then_on(), rule("static", answer_static(), json!({}))
                    ]}
                ]),
            ),
            (
                "another upstream in a jump target",
                json!([
                    { "id": "main", "rules": [passed(), rule("jump", jump_to("other"), json!({}))] },
                    { "id": "other", "rules": [
                        failing_then_on(), rule("backup", forward(&backup), json!({}))
                    ]}
                ]),
            ),
            // 失败后的 on_miss 先问了另一个上游再 continue：这次 continue 带着应答，也仍在失败之后
            // The miss actions ask another upstream before the continue: that continue
            // carries an answer, and still comes after the failure
            (
                "a continue past a miss action's own answer, in the pipeline itself",
                json!([{ "id": "main", "rules": [
                    rule(
                        "dead",
                        forward(DEAD_UPSTREAM),
                        json!({ "response_actions_on_miss": [
                            { "type": "forward", "upstream": backup }, { "type": "continue" }
                        ] })
                    ),
                    rule("static", answer_static(), json!({}))
                ]}]),
            ),
            (
                "a continue past a miss action's own answer, in a jump target",
                json!([
                    { "id": "main", "rules": [passed(), rule("jump", jump_to("other"), json!({}))] },
                    { "id": "other", "rules": [
                        rule(
                            "dead",
                            forward(DEAD_UPSTREAM),
                            json!({ "response_actions_on_miss": [
                                { "type": "forward", "upstream": backup }, { "type": "continue" }
                            ] })
                        ),
                        rule("static", answer_static(), json!({}))
                    ]}
                ]),
            ),
        ];
        for (case, pipelines) in cases {
            let (engine, key) = engine_with_a_cached_answer(json!({}), pipelines);
            assert_eq!(refresh(&engine, key).await, Some(vec![OLD]), "{case}");
        }
    }

    /// After the failure the rules get a fresh answer and continue past it: they now
    /// pass over an answer they may have given before, so the entry goes, as when no
    /// upstream failed.
    /// 失败之后规则又拿到一个新应答并越过它：规则现在越过了它以前可能给出的应答，所以和没有
    /// 上游失败时一样，删掉条目。
    #[tokio::test]
    async fn a_refresh_drops_the_entry_when_it_passes_a_fresh_answer_after_a_failure() {
        let second = spawn_upstream_answering(PASSED_OVER).await;
        let (engine, key) = engine_with_a_cached_answer(
            json!({}),
            json!([{ "id": "main", "rules": [
                rule(
                    "dead",
                    forward(DEAD_UPSTREAM),
                    json!({ "response_actions_on_miss": continue_() })
                ),
                rule(
                    "second",
                    forward(&second),
                    json!({ "response_actions_on_match": continue_() })
                ),
                rule("static", answer_static(), json!({}))
            ]}]),
        );
        assert_eq!(refresh(&engine, key).await, None);
    }

    /// The upstream failed and the miss action found no answer either: the refresh
    /// reports the upstream's failure, which says why
    /// 上游失败，on_miss 动作也没拿到应答：刷新报的是上游的失败，说明了原因
    #[tokio::test]
    async fn a_refresh_whose_miss_action_finds_nothing_reports_the_upstream_failure() {
        let (engine, key) = engine_with_a_cached_answer(
            json!({}),
            json!([{ "id": "main", "rules": [rule(
                "dead",
                forward(DEAD_UPSTREAM),
                json!({ "response_actions_on_miss": jump_to("nowhere") })
            )] }]),
        );
        let error = format!("{:#}", refresh_result(&engine, key).await.unwrap_err());
        assert!(!error.contains("the rules answered SERVFAIL"), "{error}");
    }

    /// A client still gets the SERVFAIL the rules answer, as a reply
    /// 客户端照样拿到规则给出的 SERVFAIL 应答
    #[tokio::test]
    async fn a_client_gets_the_servfail_the_rules_answer() {
        for actions in [
            json!([{ "type": "static_response", "rcode": "SERVFAIL" }]),
            jump_to("nowhere"),
        ] {
            let engine = engine_with(
                json!({ "min_ttl": 60 }),
                json!([{ "id": "main", "rules": [rule("servfail", actions.clone(), json!({}))] }]),
            );
            let client: SocketAddr = CLIENT.parse().unwrap();
            let reply = tokio::time::timeout(
                Duration::from_secs(5),
                engine.handle_packet(&query().to_vec().unwrap(), client),
            )
            .await
            .expect("answer in time")
            .expect("a reply, not an error");
            assert_eq!(
                Message::from_bytes(&reply).unwrap().metadata.response_code,
                ResponseCode::ServFail,
                "{actions}"
            );
        }
    }

    /// Only a truncated answer comes back (TCP fallback is off): it is not cached, so
    /// there is nothing to renew the entry with, and the refresh fails
    /// 只拿到被截断的应答（关了 TCP 回退）：它不写缓存，没有拿来更新条目的应答，刷新算失败
    #[tokio::test]
    async fn a_refresh_that_gets_only_a_truncated_answer_fails() {
        let truncating = spawn_upstream_answering_with(FINAL, true).await;
        let (engine, key) = engine_with_a_cached_answer(
            json!({ "enable_tcp_fallback": false }),
            json!([{ "id": "main", "rules": [rule("all", forward(&truncating), json!({}))] }]),
        );
        assert_eq!(
            refresh_succeeds(&engine, key).await,
            (false, Some(vec![OLD]))
        );
    }

    /// The same past a continue and a rule-level jump, or through a response jump:
    /// the refresh fails, and the entry stays as on a SERVFAIL there
    /// 越过一个应答再规则级跳转，或者经响应跳转，也一样：刷新失败，条目和那里遇到 SERVFAIL
    /// 时一样保留
    #[tokio::test]
    async fn a_refresh_whose_jump_target_gets_only_a_truncated_answer_keeps_the_entry() {
        let truncating = spawn_upstream_answering_with(FINAL, true).await;
        let target = rule("target", forward(&truncating), json!({}));
        let settings = json!({ "enable_tcp_fallback": false });
        let after_a_continue = refresh_with_actions_on_the_answer(
            settings.clone(),
            continue_(),
            vec![rule("jump", jump_to("other"), json!({}))],
            target.clone(),
        )
        .await;
        assert_eq!(after_a_continue, Some(vec![OLD]));
        let through_a_response_jump =
            refresh_with_actions_on_the_answer(settings, jump_to("other"), vec![], target).await;
        assert_eq!(through_a_response_jump, Some(vec![OLD]));
    }

    #[tokio::test]
    async fn a_refresh_that_gets_an_answer_succeeds() {
        let answering = spawn_upstream_answering(FINAL).await;
        let (engine, key) = engine_with_a_cached_answer(
            json!({}),
            json!([{ "id": "main", "rules": [rule("all", forward(&answering), json!({}))] }]),
        );
        assert_eq!(
            refresh_succeeds(&engine, key).await,
            (true, Some(vec![FINAL]))
        );
    }

    #[tokio::test]
    async fn a_refresh_that_continues_after_a_failure_keeps_the_entry() {
        let (engine, key) = engine_with_a_cached_answer(
            json!({}),
            json!([{ "id": "main", "rules": [
                rule(
                    "first",
                    forward(DEAD_UPSTREAM),
                    json!({ "response_actions_on_miss": continue_() })
                ),
                rule("static", answer_static(), json!({})),
            ]}]),
        );
        assert_eq!(refresh(&engine, key).await, Some(vec![OLD]));
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
