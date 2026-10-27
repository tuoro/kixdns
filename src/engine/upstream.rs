use std::sync::atomic::Ordering;
use std::time::Duration;

use bytes::Bytes;
use futures::future::select;
use hickory_proto::op::ResponseCode;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::debug;

use super::Engine;
use crate::config::Transport;
use crate::observe::{UpstreamAttempt, UpstreamOutcome, UpstreamResult};

use super::observation::Observed;

/// Error indicating that all upstream attempts have been exhausted.
/// 表示所有 upstream 尝试均已耗尽的错误。
#[derive(Debug)]
pub struct UpstreamFailure {
    source: anyhow::Error,
}

impl UpstreamFailure {
    pub fn new(source: anyhow::Error) -> Self {
        Self { source }
    }
}

impl std::fmt::Display for UpstreamFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "all upstreams failed")
    }
}

impl std::error::Error for UpstreamFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

/// Whether a reply's response code makes it a failed attempt: [`forward_upstream`]
/// rejects such a reply for a rule with several upstreams, and hands it back as the
/// answer only when the rule has a single upstream. SERVFAIL and REFUSED are, and so
/// is every extended RCODE (16 and up: BADVERS, the TSIG errors, BADCOOKIE and so on),
/// which reports on the exchange rather than answering the question.
/// 应答的响应码是否表示一次失败的尝试：规则有多个上游时，[`forward_upstream`] 拒绝这样的
/// 应答；只有规则只有一个上游时，才把它当作应答交回。SERVFAIL 和 REFUSED 是，所有扩展
/// RCODE（16 及以上：BADVERS、TSIG 的各种错误、BADCOOKIE 等）也是：它们说的是这次往来出了
/// 问题，不是对问题的回答。
pub(crate) fn is_failure_reply(rcode: ResponseCode) -> bool {
    matches!(rcode, ResponseCode::ServFail | ResponseCode::Refused) || u16::from(rcode) >= 16
}

/// A background refresh does not cache a failure reply (see [`is_failure_reply`]),
/// which a rule with a single upstream gets back as its answer: it would replace the
/// answer cached under the same key, and a lookup never serves such an entry as
/// stale. The refresh gets an error here instead of caching it, and the cached
/// answer stays.
/// 后台刷新不缓存失败应答（见 [`is_failure_reply`]；只有一个上游的规则会把它当作应答
/// 拿回来）：它会替换掉同一个键下缓存的应答，而查缓存时这样的条目不会被当作旧结果返回。
/// 刷新在这里拿到一个错误，不缓存它，缓存的应答保留。
pub(crate) fn reject_failure_reply_on_refresh(
    skip_cache: bool,
    reply: &[u8],
) -> anyhow::Result<()> {
    if !skip_cache {
        return Ok(());
    }
    match crate::proto_utils::parse_response_quick(reply).map(|qr| qr.rcode) {
        Some(rcode) if is_failure_reply(rcode) => Err(anyhow::Error::new(UpstreamFailure::new(
            anyhow::anyhow!("the upstream answered {rcode}"),
        ))),
        _ => Ok(()),
    }
}

/// Whether an upstream address carries a `scheme://` transport prefix, which
/// [`parse_upstream_addr`] lets override the configured transport.
/// 上游地址是否带 `scheme://` 传输前缀（parse_upstream_addr 以前缀覆盖配置的传输）。
pub(crate) fn has_transport_prefix(addr: &str) -> bool {
    addr.contains("://")
}

/// Parse upstream address with optional protocol prefix.
/// 解析带有可选协议前缀的 upstream 地址。
///
/// Returns (address_without_prefix, transport).
/// 返回 (去除前缀的地址, 传输协议)。
///
/// Examples:
/// - "tcp://1.1.1.1:53" -> ("1.1.1.1:53", Transport::Tcp)
/// - "udp://1.1.1.1:53" -> ("1.1.1.1:53", Transport::Udp)
/// - "dot://1.1.1.1:853" -> ("1.1.1.1:853", Transport::Dot)
/// - "doq://dns.example.com:853" -> ("dns.example.com:853", Transport::Doq)
/// - "doh://dns.example.com/dns-query" -> ("dns.example.com/dns-query", Transport::Doh)
/// - "https://dns.example.com/dns-query" -> ("dns.example.com/dns-query", Transport::Doh)
/// - "1.1.1.1:53" -> ("1.1.1.1:53", default_transport)
fn parse_upstream_addr(addr: &str, default_transport: Transport) -> (&str, Transport) {
    if let Some(idx) = addr.find("://") {
        let address = &addr[idx + 3..];
        let transport = transport_for_scheme(&addr[..idx]).unwrap_or(default_transport);
        (address, transport)
    } else {
        (addr, default_transport)
    }
}

/// 上游地址前缀对应的传输；不认识的前缀为 None（[`parse_upstream_addr`] 这时用默认传输）
/// The transport an upstream prefix names; None for a prefix it does not know
/// ([`parse_upstream_addr`] then takes the default transport)
pub(crate) fn transport_for_scheme(scheme: &str) -> Option<Transport> {
    Some(match scheme.to_lowercase().as_str() {
        "tcp" => Transport::Tcp,
        "udp" => Transport::Udp,
        "tcp+udp" | "udp+tcp" => Transport::TcpUdp,
        "doh" | "https" => Transport::Doh,
        "dot" | "tls" => Transport::Dot,
        "doq" | "quic" => Transport::Doq,
        _ => return None,
    })
}

/// 一个上游写得对不对：前缀认识，地址是它的传输读得懂的。说明为什么不对。
/// Whether one upstream is written right: a known prefix, and an address its
/// transport can read. Says why not.
pub(crate) fn upstream_problem(upstream: &str, default_transport: Transport) -> Option<String> {
    if let Some(idx) = upstream.find("://")
        && transport_for_scheme(&upstream[..idx]).is_none()
    {
        return Some(format!(
            "upstream \"{upstream}\" starts with an unknown prefix \"{}://\"",
            &upstream[..idx]
        ));
    }
    let (address, transport) = parse_upstream_addr(upstream, default_transport);
    crate::engine::transport::check_upstream_address(address, transport)
        .err()
        .map(|error| format!("upstream \"{upstream}\" is not usable: {error:#}"))
}

/// 一份配置里的上游在各连接池里的键，按传输分开；DoH 自己清理不用的上游，不在这里
/// The pool keys of a configuration's upstreams, by transport; DoH prunes the upstreams it
/// stops using on its own, so it is not here
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct PoolKeys {
    pub(crate) tcp: rustc_hash::FxHashSet<String>,
    pub(crate) dot: rustc_hash::FxHashSet<String>,
    pub(crate) doq: rustc_hash::FxHashSet<String>,
}

/// `cfg` 用到的每个上游在连接池里的键，和转发时的算法一样（见 [`parse_upstream_addr`]）：默认上游，
/// 以及请求阶段和回答阶段每个转发动作的上游（没写就是默认上游）。UDP 上游在应答被截断或失败时改用
/// TCP，所以也算一个 TCP 键。
/// The pool key of every upstream `cfg` uses, worked out as a forward does (see
/// [`parse_upstream_addr`]): the default upstream, and the upstream of every forward
/// action in the request and response phases (the default upstream when it names none). A
/// UDP upstream falls back to TCP on a truncated or failed answer, so it has a TCP key too.
pub(crate) fn pool_keys(cfg: &crate::matcher::RuntimePipelineConfig) -> PoolKeys {
    let mut keys = PoolKeys::default();
    let mut add = |upstreams: &str, transport: Option<Transport>| {
        for upstream in upstreams
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let (addr, transport) =
                parse_upstream_addr(upstream, transport.unwrap_or(Transport::Udp));
            let set = match transport {
                Transport::Udp | Transport::Tcp | Transport::TcpUdp => &mut keys.tcp,
                Transport::Dot => &mut keys.dot,
                Transport::Doq => &mut keys.doq,
                Transport::Doh => continue,
            };
            set.insert(addr.to_owned());
        }
    };
    add(&cfg.settings.default_upstream, None);
    for rule in cfg.pipelines.iter().flat_map(|pipeline| &pipeline.rules) {
        for action in rule
            .actions
            .iter()
            .chain(&rule.response_actions_on_match)
            .chain(&rule.response_actions_on_miss)
        {
            if let crate::config::Action::Forward {
                upstream,
                transport,
                ..
            } = action
            {
                add(
                    upstream
                        .as_deref()
                        .unwrap_or(&cfg.settings.default_upstream),
                    *transport,
                );
            }
        }
    }
    keys
}

/// Hedge 超时除数：第一次尝试使用 1/N 的时间，为 TCP fallback 预留时间 / Hedge timeout divisor: first attempt uses 1/N of the budget to reserve time for TCP fallback
const HEDGE_TIMEOUT_DIVISOR: u32 = 3;

/// Send both TCP and UDP concurrently, return first successful response (hedged request).
/// 同时发送 TCP 和 UDP，返回第一个成功响应（对冲请求）。
///
/// Returns (response_bytes, protocol_name).
/// 返回 (响应字节, 协议名称)。
async fn fallback_after_primary_failure(
    other_task: tokio::task::JoinHandle<anyhow::Result<Bytes>>,
    remaining: Duration,
    primary_label: &'static str,
    primary_err: anyhow::Error,
    primary_is_task_error: bool,
    other_label: &'static str,
) -> anyhow::Result<(Bytes, &'static str)> {
    if remaining.is_zero() {
        other_task.abort();
        if primary_is_task_error {
            return Err(anyhow::anyhow!(
                "{} task error: {}",
                primary_label,
                primary_err
            ));
        }
        return Err(anyhow::anyhow!(
            "{} failed and no time left for {}: {}",
            primary_label,
            other_label,
            primary_err
        ));
    }

    let prefix = if primary_is_task_error {
        "task error"
    } else {
        "failed"
    };
    match timeout(remaining, other_task).await {
        Ok(Ok(Ok(bytes))) => Ok((bytes, other_label)),
        Ok(Ok(Err(other_err))) => Err(anyhow::anyhow!(
            "{} {}: {}; {} failed: {}",
            primary_label,
            prefix,
            primary_err,
            other_label,
            other_err
        )),
        Ok(Err(join_err)) => Err(anyhow::anyhow!(
            "{} {}: {}; {} task error: {}",
            primary_label,
            prefix,
            primary_err,
            other_label,
            join_err
        )),
        Err(_) => Err(anyhow::anyhow!(
            "{} {}: {}; {} timed out",
            primary_label,
            prefix,
            primary_err,
            other_label
        )),
    }
}

async fn forward_tcp_udp_dual(
    engine: &Engine,
    packet: &[u8],
    addr: &str,
    timeout_dur: Duration,
) -> anyhow::Result<(Bytes, &'static str)> {
    let engine_udp = engine.clone();
    let engine_tcp = engine.clone();
    // Use Bytes for cheap clone (refcount) instead of Vec full copy
    // 使用 Bytes 实现低成本克隆（引用计数）而非 Vec 全量拷贝
    let packet_shared = Bytes::copy_from_slice(packet);
    let packet_udp = packet_shared.clone();
    let packet_tcp = packet_shared.clone();
    let addr_udp = addr.to_string();
    let addr_tcp = addr.to_string();

    let udp_task = tokio::spawn(async move {
        // Disable TCP fallback here to avoid duplicate TCP sends when dual-send is enabled.
        // A truncated answer waits for the TCP leg below instead.
        // 双发时这里不改用 TCP，免得重复发送；截断的应答改为在下面等 TCP 那一路。
        let tcp = UdpTcpFallback {
            retry_truncated: false,
            on_failure: false,
        };
        forward_udp_smart(&engine_udp, &packet_udp, &addr_udp, timeout_dur, tcp).await
    });

    let tcp_task = tokio::spawn(async move {
        engine_tcp
            .tcp_mux
            .send(&packet_tcp, &addr_tcp, timeout_dur)
            .await
    });

    let start = std::time::Instant::now();

    // Wait for first successful response / 等待第一个成功响应
    match select(udp_task, tcp_task).await {
        futures::future::Either::Left((result, mut tcp_task)) => match result {
            // A truncated UDP answer does not win: the TCP leg is asking the same upstream
            // for the full answer, so wait for it, and fall back to the truncated answer only
            // if it fails.
            // 截断的 UDP 应答不算赢：TCP 那一路正在向同一个上游要完整应答，所以等它；它失败了才
            // 退回这个截断的应答。
            Ok(Ok(bytes)) if crate::proto_utils::truncated_response(&bytes) => {
                let remaining = timeout_dur
                    .checked_sub(start.elapsed())
                    .unwrap_or_else(|| Duration::from_millis(0));
                match timeout(remaining, &mut tcp_task).await {
                    Ok(Ok(Ok(full))) => Ok((full, "tcp")),
                    other => {
                        if other.is_err() {
                            tcp_task.abort();
                        }
                        debug!(event = "tc_udp_answer_kept", upstream = %addr, "tcp leg gave no answer, keeping the truncated udp answer");
                        Ok((bytes, "udp"))
                    }
                }
            }
            Ok(Ok(bytes)) => {
                tcp_task.abort();
                Ok((bytes, "udp"))
            }
            Ok(Err(err)) => {
                let remaining = timeout_dur
                    .checked_sub(start.elapsed())
                    .unwrap_or_else(|| Duration::from_millis(0));
                fallback_after_primary_failure(tcp_task, remaining, "udp", err, false, "tcp").await
            }
            Err(join_err) => {
                let remaining = timeout_dur
                    .checked_sub(start.elapsed())
                    .unwrap_or_else(|| Duration::from_millis(0));
                fallback_after_primary_failure(
                    tcp_task,
                    remaining,
                    "udp",
                    anyhow::anyhow!(join_err),
                    true,
                    "tcp",
                )
                .await
            }
        },
        futures::future::Either::Right((result, udp_task)) => match result {
            Ok(Ok(bytes)) => {
                udp_task.abort();
                Ok((bytes, "tcp"))
            }
            Ok(Err(err)) => {
                let remaining = timeout_dur
                    .checked_sub(start.elapsed())
                    .unwrap_or_else(|| Duration::from_millis(0));
                fallback_after_primary_failure(udp_task, remaining, "tcp", err, false, "udp").await
            }
            Err(join_err) => {
                let remaining = timeout_dur
                    .checked_sub(start.elapsed())
                    .unwrap_or_else(|| Duration::from_millis(0));
                fallback_after_primary_failure(
                    udp_task,
                    remaining,
                    "tcp",
                    anyhow::anyhow!(join_err),
                    true,
                    "udp",
                )
                .await
            }
        },
    }
}

/// 默认最小 hedge 超时毫秒数（当计算值过小时使用） / Default minimum hedge timeout in milliseconds (used when calculated value is too small)
const DEFAULT_HEDGE_TIMEOUT_MS: u64 = 100;

/// Forward DNS request to multiple upstreams concurrently (Happy Eyeballs / Hedged Request)
/// 并发转发 DNS 请求到多个上游 (Happy Eyeballs / Hedged Request)
///
/// Returns the first successful response and the name of the winning upstream.
/// 返回第一个成功的响应和获胜的上游名称。
///
/// `observed` is the observer context of the request; every attempt and its
/// result is reported through it. / `observed` 为所属请求的观察者上下文，每次尝试及其结果都经它上报。
///
/// DNS cookie（RFC 7873）只在相邻两跳之间有效，这里两头把关：查询去掉客户端的 cookie 再发出，
/// 应答去掉 cookie 再交回，于是它既不会进缓存，也不会交给别的客户端。所有发往上游的查询都经过这里。
/// DNS cookies (RFC 7873) hold between two neighbouring hops only, so both ends are
/// guarded here: a query goes out without the client's cookie and a reply comes back
/// without any, so no cookie enters the cache or reaches another client. Every query
/// for an upstream passes through here.
///
/// 应答交回之前，每条记录的 TTL 收进 `min_ttl..=cache_max_ttl`：客户端留一份应答的时间和缓存一样长。
/// Before the reply is handed back, the TTL of every record is brought into
/// `min_ttl..=cache_max_ttl`, so a client keeps an answer as long as the cache does.
pub async fn forward_upstream(
    engine: &Engine,
    packet: &[u8],
    upstream: &str,
    timeout_dur: Duration,
    transport: Option<Transport>,
    pre_split_upstreams: Option<&std::sync::Arc<Vec<std::sync::Arc<str>>>>,
    observed: Observed<'_>,
) -> anyhow::Result<(Bytes, String)> {
    let packet = crate::proto_utils::query_without_cookie(packet);
    let (reply, winner) = forward_upstream_as_is(
        engine,
        &packet,
        upstream,
        timeout_dur,
        transport,
        pre_split_upstreams,
        observed,
    )
    .await?;
    let reply = crate::proto_utils::reply_without_cookie(reply);
    // 用当前配置的 min_ttl，而不是请求开始时那份：改 min_ttl 会轮换所有缓存命名空间，一个跨过重载
    // 的应答只会交给它自己的客户端
    // min_ttl comes from the current configuration rather than the request's own:
    // changing it rotates every cache namespace, so a reply in flight across a
    // reload reaches only its own client
    let floor = engine.state.load().pipeline.settings.min_ttl;
    let reply = crate::proto_utils::reply_within_ttls(reply, floor, engine.ttl_cap());
    Ok((reply, winner))
}

/// [`forward_upstream`] 去掉 cookie 之前的部分 / [`forward_upstream`] short of its cookie guard
async fn forward_upstream_as_is(
    engine: &Engine,
    packet: &[u8],
    upstream: &str,
    timeout_dur: Duration,
    transport: Option<Transport>,
    pre_split_upstreams: Option<&std::sync::Arc<Vec<std::sync::Arc<str>>>>,
    observed: Observed<'_>,
) -> anyhow::Result<(Bytes, String)> {
    // 如果 transport 为 None，使用默认 UDP
    let default_transport = transport.unwrap_or(Transport::Udp);

    // 使用预分割数据或动态分割 / Use pre-split data or dynamic splitting
    // 使用 Arc<str> 避免克隆 / Use Arc<str> to avoid cloning
    let upstreams: Vec<std::sync::Arc<str>> = if let Some(pre_split) = pre_split_upstreams {
        pre_split.iter().cloned().collect()
    } else if !upstream.contains(',') {
        // 单个上游：直接转发 / Single upstream: direct forward
        vec![std::sync::Arc::from(upstream)]
    } else {
        upstream
            .split(',')
            .map(|s| s.trim())
            .map(std::sync::Arc::from)
            .filter(|s: &std::sync::Arc<str>| !s.is_empty())
            .collect()
    };

    // 快速路径：只有一个上游时，直接调用避免 spawn 开销
    // Fast path: direct call when only one upstream, avoiding spawn overhead
    if upstreams.len() == 1 {
        let up = &upstreams[0];

        // 解析地址中的协议前缀 / Parse protocol prefix from address
        let (addr, transport_for_addr) = parse_upstream_addr(up, default_transport);
        if let Some((observer, ctx)) = observed {
            observer.upstream_attempt(
                ctx,
                &UpstreamAttempt {
                    upstream: addr,
                    transport: transport_for_addr,
                },
            );
        }

        let start = std::time::Instant::now();
        // `via` is the transport that actually carried the answer (UDP may fall
        // back to TCP) / `via` 为实际带回答案的传输（UDP 可能回退到 TCP）
        let tcp = UdpTcpFallback {
            retry_truncated: true,
            on_failure: true,
        };
        let (res, proto, via) =
            send_to_upstream(engine, packet, addr, timeout_dur, transport_for_addr, tcp).await;
        let dur = start.elapsed();

        let upstream_with_proto = format!("{}:{}", proto, addr);

        match res {
            Ok(ref bytes) => {
                // Quick check rcode / 快速解析响应码
                let quick = crate::proto_utils::parse_response_quick(bytes);
                if let Some((observer, ctx)) = observed {
                    observer.upstream_result(
                        ctx,
                        &UpstreamResult {
                            upstream: addr,
                            transport: transport_for_addr,
                            via,
                            outcome: UpstreamOutcome::Success,
                            latency: dur,
                            rcode: quick.as_ref().map(|qr| qr.rcode),
                            truncated: quick.as_ref().map(|qr| qr.truncated),
                            error: None,
                        },
                    );
                }
                // 记录成功指标 / Record success metrics
                engine
                    .metrics_last_upstream_latency_ns
                    .store(dur.as_nanos() as u64, Ordering::Relaxed);

                if let Some(qr) = quick {
                    tracing::debug!(upstream=%up, upstream_ns = dur.as_nanos() as u64, rcode = %qr.rcode, "upstream call succeeded");
                }
                return Ok((bytes.clone(), upstream_with_proto));
            }
            Err(err) => {
                if let Some((observer, ctx)) = observed {
                    observer.upstream_result(
                        ctx,
                        &UpstreamResult {
                            upstream: addr,
                            transport: transport_for_addr,
                            via: transport_for_addr,
                            outcome: UpstreamOutcome::Error,
                            latency: dur,
                            rcode: None,
                            truncated: None,
                            error: Some(&err),
                        },
                    );
                }
                // 失败时不构造 prefix，只 warn
                tracing::warn!(upstream=%up, error=%err, elapsed_ns = dur.as_nanos() as u64, "single upstream call failed");
                return Err(anyhow::Error::new(UpstreamFailure::new(err)));
            }
        }
    }

    // Multiple upstreams: use JoinSet for concurrency
    // 多个上游：使用 JoinSet 进行并发
    let mut tasks = JoinSet::new();
    // Use Bytes for cheap clone (refcount) instead of Vec full copy
    // 使用 Bytes 实现低成本克隆（引用计数）而非 Vec 全量拷贝
    let packet_owned = Bytes::copy_from_slice(packet);
    let mut last_err: Option<anyhow::Error> = None;
    // Attempts that have not reported a result yet, so losers of the race can
    // be reported as aborted; only tracked for an observer.
    // 尚未上报结果的尝试，用于把竞争失败者上报为已取消；仅在有观察者时跟踪。
    let mut pending: Option<Vec<(String, Transport, std::time::Instant)>> =
        observed.map(|_| Vec::new());

    // If any TCP/TCP+UDP upstream is present, a failed UDP attempt does not fall back to TCP, to
    // prevent duplicate TCP sends (truncated answers are still fetched again over TCP)
    // 如果同一批次已有 TCP/TCP+UDP 上游，UDP 失败时不再回退到 TCP，避免重复 TCP 发送（截断的应答照样用
    // TCP 重取）
    let has_tcp_task = upstreams.iter().any(|up| {
        let (_, t) = parse_upstream_addr(up, default_transport);
        matches!(t, Transport::Tcp | Transport::TcpUdp)
    });

    for up in upstreams {
        // 解析地址中的协议前缀 / Parse protocol prefix from address
        let (addr, transport_for_task) = parse_upstream_addr(&up, default_transport);
        if let Some((observer, ctx)) = observed {
            observer.upstream_attempt(
                ctx,
                &UpstreamAttempt {
                    upstream: addr,
                    transport: transport_for_task,
                },
            );
        }

        if let Some(pending) = pending.as_mut() {
            pending.push((
                addr.to_string(),
                transport_for_task,
                std::time::Instant::now(),
            ));
        }

        let engine = engine.clone();
        let packet = packet_owned.clone();
        let addr_owned = addr.to_string();

        tasks.spawn(async move {
            let start = std::time::Instant::now();
            // A truncated answer is still fetched again over TCP: the batch's TCP
            // upstreams do not give this upstream's full answer.
            // 截断的应答照样用 TCP 重取：同批的 TCP 上游给不出这个上游的完整应答。
            let tcp = UdpTcpFallback {
                retry_truncated: true,
                on_failure: !has_tcp_task,
            };
            let (res, proto, via) = send_to_upstream(
                &engine,
                &packet,
                &addr_owned,
                timeout_dur,
                transport_for_task,
                tcp,
            )
            .await;

            // Note: for TcpUdp, timing includes both tasks' spawn/abort overhead
            // 注意：对于 TcpUdp，计时包含两个任务的 spawn/abort 开销
            let upstream_with_proto = format!("{}:{}", proto, addr_owned);
            let dur = start.elapsed();
            (
                upstream_with_proto,
                addr_owned,
                transport_for_task,
                via,
                res,
                dur,
            )
        });
    }

    // 等待第一个成功响应 / Wait for first successful response
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok((up_proto, addr, transport_for_task, via, res, dur)) => {
                if let Some(pending) = pending.as_mut()
                    && let Some(idx) = pending
                        .iter()
                        .position(|(a, t, _)| *a == addr && *t == transport_for_task)
                {
                    pending.swap_remove(idx);
                }
                // Report the outcome of this attempt / 上报本次尝试的结果
                let report = |outcome: UpstreamOutcome,
                              rcode: Option<ResponseCode>,
                              truncated: Option<bool>,
                              error: Option<&anyhow::Error>| {
                    if let Some((observer, ctx)) = observed {
                        observer.upstream_result(
                            ctx,
                            &UpstreamResult {
                                upstream: &addr,
                                transport: transport_for_task,
                                via,
                                outcome,
                                latency: dur,
                                rcode,
                                truncated,
                                error,
                            },
                        );
                    }
                };
                match res {
                    Ok(bytes) => {
                        // 快速解析响应码 / Quick parse response code
                        let quick = crate::proto_utils::parse_response_quick(&bytes);
                        let rcode = quick.as_ref().map(|qr| qr.rcode);
                        let truncated = quick.as_ref().map(|qr| qr.truncated);
                        let should_accept = quick.is_none_or(|qr| !is_failure_reply(qr.rcode));

                        if should_accept {
                            report(UpstreamOutcome::Success, rcode, truncated, None);
                            engine
                                .metrics_last_upstream_latency_ns
                                .store(dur.as_nanos() as u64, Ordering::Relaxed);

                            // The remaining attempts lose the race / 其余尝试竞争失败
                            if let Some(pending) = pending.as_ref() {
                                report_aborted(observed, pending);
                            }
                            // 显式取消其他正在进行的任务
                            if !tasks.is_empty() {
                                tasks.abort_all();
                            }

                            return Ok((bytes, up_proto));
                        }
                        report(UpstreamOutcome::Rejected, rcode, truncated, None);
                    }
                    Err(err) => {
                        report(UpstreamOutcome::Error, None, None, Some(&err));
                        tracing::warn!(upstream=%up_proto, error=%err, elapsed_ns = dur.as_nanos() as u64, "upstream call failed, waiting for others");
                        last_err = Some(err);
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "upstream task join error, waiting for others");
                last_err = Some(anyhow::anyhow!(e));
            }
        }
    }

    // Attempts whose task never reported (join error) / 任务未能上报结果的尝试（join 错误）
    if let Some(pending) = pending.as_ref() {
        report_aborted(observed, pending);
    }

    // 所有上游都失败 / All upstreams failed
    let err = last_err.unwrap_or_else(|| anyhow::anyhow!("all upstreams failed"));
    Err(anyhow::Error::new(UpstreamFailure::new(err)))
}

/// Report every attempt still in flight as aborted / 把仍在飞的尝试上报为已取消
fn report_aborted(observed: Observed<'_>, pending: &[(String, Transport, std::time::Instant)]) {
    if let Some((observer, ctx)) = observed {
        for (upstream, transport, started) in pending {
            observer.upstream_result(
                ctx,
                &UpstreamResult {
                    upstream,
                    transport: *transport,
                    via: *transport,
                    outcome: UpstreamOutcome::Aborted,
                    latency: started.elapsed(),
                    rcode: None,
                    truncated: None,
                    error: None,
                },
            );
        }
    }
}

/// Sends `packet` to one upstream over `transport`, and returns the answer with the label
/// and the transport that carried it (a UDP query may end up over TCP). Each transport's
/// exchange is allocated on its own, sized to that transport: held inline, it made every
/// query waiting on an upstream reserve room for the largest of them (DoT, about 2 KB),
/// whatever the query went over.
/// 把 `packet` 经 `transport` 发给一个上游，返回应答以及实际带回应答的传输的标签和传输本身（UDP 查询
/// 可能最后走了 TCP）。每种传输的收发单独在堆上分配，大小按这种传输来：放在调用方里时，等上游的每个
/// 查询不管走的是哪种传输，都得按最大的那种（DoT，约 2 KB）预留。
async fn send_to_upstream(
    engine: &Engine,
    packet: &[u8],
    addr: &str,
    timeout_dur: Duration,
    transport: Transport,
    tcp: UdpTcpFallback,
) -> (anyhow::Result<Bytes>, &'static str, Transport) {
    match transport {
        Transport::Udp => {
            let r = Box::pin(forward_udp_smart_via(
                engine,
                packet,
                addr,
                timeout_dur,
                tcp,
            ))
            .await;
            match r {
                Ok((bytes, via)) => (Ok(bytes), via_label(via), via),
                Err(err) => (Err(err), "udp", Transport::Udp),
            }
        }
        Transport::Tcp => {
            let r = Box::pin(engine.tcp_mux.send(packet, addr, timeout_dur)).await;
            (r, "tcp", Transport::Tcp)
        }
        Transport::TcpUdp => {
            // Dual-send: spawn both TCP and UDP concurrently, use first response
            // 双发：同时发送 TCP 和 UDP，使用第一个响应
            match Box::pin(forward_tcp_udp_dual(engine, packet, addr, timeout_dur)).await {
                Ok((bytes, proto)) => (Ok(bytes), proto, label_transport(proto)),
                Err(e) => (Err(e), "udp", Transport::TcpUdp),
            }
        }
        Transport::Doh => {
            let r = Box::pin(engine.doh_client.send(packet, addr, timeout_dur)).await;
            (r, "doh", Transport::Doh)
        }
        Transport::Dot => {
            let r = Box::pin(engine.dot_mux.send(packet, addr, timeout_dur)).await;
            (r, "dot", Transport::Dot)
        }
        Transport::Doq => {
            let r = Box::pin(engine.doq_client.send(packet, addr, timeout_dur)).await;
            (r, "doq", Transport::Doq)
        }
    }
}

/// Label for the transport that carried a UDP-path answer (TC fallback may use TCP) / UDP 路径应答实际承载传输的标签（TC 回退可能走 TCP）
fn via_label(via: Transport) -> &'static str {
    if via == Transport::Tcp { "tcp" } else { "udp" }
}

/// Transport named by a `tcp_udp` race label / `tcp_udp` 竞争标签对应的传输
fn label_transport(label: &str) -> Transport {
    if label == "tcp" {
        Transport::Tcp
    } else {
        Transport::Udp
    }
}

/// The point by which an upstream should have answered: the budget of a UDP
/// query's first attempt, after which it is retried.
/// 上游应当已经应答的时间点：UDP 查询第一次尝试的时间预算，过了就重试。
pub(crate) fn hedge_timeout(timeout_dur: Duration) -> Duration {
    timeout_dur
        .checked_div(HEDGE_TIMEOUT_DIVISOR)
        .unwrap_or_else(|| Duration::from_millis(DEFAULT_HEDGE_TIMEOUT_MS).max(timeout_dur))
}

/// UDP forwarder with hedged retry and TCP fallback for better tail latency.
async fn forward_udp_smart(
    engine: &Engine,
    packet: &[u8],
    upstream: &str,
    timeout_dur: Duration,
    tcp: UdpTcpFallback,
) -> anyhow::Result<Bytes> {
    forward_udp_smart_via(engine, packet, upstream, timeout_dur, tcp)
        .await
        .map(|(bytes, _)| bytes)
}

/// When the UDP forwarder turns to TCP, on top of `enable_tcp_fallback`. A truncated
/// answer and a failed UDP exchange are separate cases: a batch that already sends TCP to
/// other upstreams still needs this upstream's full answer, but should not add a TCP
/// attempt for a UDP failure.
/// UDP 转发在 `enable_tcp_fallback` 之外何时改用 TCP。截断的应答和 UDP 失败是两回事：同批里已经
/// 有别的上游走 TCP 时，这个上游的完整应答照样要取，但 UDP 失败时不再另加一次 TCP 尝试。
#[derive(Clone, Copy)]
struct UdpTcpFallback {
    /// Fetch a truncated answer again over TCP / 截断的应答用 TCP 重取
    retry_truncated: bool,
    /// Try TCP when every UDP attempt failed / UDP 全部失败时试 TCP
    on_failure: bool,
}

/// [`forward_udp_smart`] that also returns the transport that carried the
/// answer: UDP, or TCP after a TC-bit retry or a UDP-failure fallback.
/// 同 [`forward_udp_smart`]，并返回实际带回答案的传输（UDP，或 TC/失败回退后的 TCP）。
async fn forward_udp_smart_via(
    engine: &Engine,
    packet: &[u8],
    upstream: &str,
    timeout_dur: Duration,
    tcp: UdpTcpFallback,
) -> anyhow::Result<(Bytes, Transport)> {
    // 获取 TCP fallback 配置（Copy bool 值，避免持有 Guard 跨 await）
    // Get TCP fallback config (Copy bool value to avoid holding Guard across await)
    let enable_tcp_fallback = engine.state.load().pipeline.settings.enable_tcp_fallback;
    let retry_truncated = tcp.retry_truncated && enable_tcp_fallback;
    let fallback_on_failure = tcp.on_failure && enable_tcp_fallback;

    // Split timeout: first attempt uses 1/N budget (leaving room for TCP fallback)
    // 分割超时：第一次尝试使用 1/N 时间（为 TCP fallback 留出空间）
    let attempts = [hedge_timeout(timeout_dur), timeout_dur];

    for (idx, dur) in attempts.iter().enumerate() {
        match engine.udp_client.send(packet, upstream, *dur).await {
            Ok(bytes) => {
                // RFC 1035: TC (Truncated) flag, read from the header / 从报头读 TC 标志
                if retry_truncated && crate::proto_utils::truncated_response(&bytes) {
                    debug!(event = "tc_flag_fallback", upstream = %upstream, "udp response truncated, retrying with tcp");
                    // TCP 的收发单独在堆上分配：只有截断或 UDP 失败时才走 TCP，等 UDP 应答的查询不必为它
                    // 预留地方
                    // The TCP exchange is allocated on its own: TCP is only taken for a truncated
                    // answer or a UDP failure, so a query waiting on UDP reserves no room for it
                    return Box::pin(engine.tcp_mux.send(packet, upstream, timeout_dur))
                        .await
                        .map(|bytes| (bytes, Transport::Tcp));
                }
                return Ok((bytes, Transport::Udp));
            }
            Err(err) => {
                debug!(
                    event = "udp_forward_retry",
                    upstream = %upstream,
                    attempt = idx + 1,
                    timeout_ms = dur.as_millis() as u64,
                    error = %err,
                    "udp forward attempt failed",
                );
                if idx + 1 == attempts.len() && fallback_on_failure {
                    // Last UDP attempt, try TCP fallback before failing.
                    debug!(event = "udp_forward_fallback_tcp", upstream = %upstream, "falling back to tcp");
                    // 单独在堆上分配，见上 / Allocated on its own, see above
                    return Box::pin(engine.tcp_mux.send(packet, upstream, timeout_dur))
                        .await
                        .map(|bytes| (bytes, Transport::Tcp));
                }
            }
        }
    }

    // Should never reach here because we either return on success or fallback.
    // However, if TCP fallback is disabled, we might reach here if all UDP attempts fail.
    // 如果 TCP fallback 被禁用，若所有 UDP 尝试均失败，可能会到达此处。
    anyhow::bail!("all udp attempts failed and tcp fallback disabled")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GlobalSettings;
    use crate::matcher::RuntimePipelineConfig;
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};
    use rustc_hash::FxHashMap;
    use rustls::crypto::ring;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::io::AsyncReadExt;

    #[test]
    fn test_parse_upstream_addr_with_protocol_prefix() {
        // Test that protocol prefixes are correctly extracted
        // 测试协议前缀是否正确提取

        // DoQ with prefix
        let (addr, transport) = parse_upstream_addr("doq://223.5.5.5:853", Transport::Udp);
        assert_eq!(addr, "223.5.5.5:853");
        assert_eq!(transport, Transport::Doq);

        // DoH with prefix
        let (addr, transport) = parse_upstream_addr("doh://dns.google/dns-query", Transport::Udp);
        assert_eq!(addr, "dns.google/dns-query");
        assert_eq!(transport, Transport::Doh);

        // HTTPS (alias for DoH)
        let (addr, transport) =
            parse_upstream_addr("https://dns.example.com/dns-query", Transport::Udp);
        assert_eq!(addr, "dns.example.com/dns-query");
        assert_eq!(transport, Transport::Doh);

        // DoT with prefix
        let (addr, transport) = parse_upstream_addr("dot://1.1.1.1:853", Transport::Udp);
        assert_eq!(addr, "1.1.1.1:853");
        assert_eq!(transport, Transport::Dot);

        // TLS (alias for DoT)
        let (addr, transport) = parse_upstream_addr("tls://dns.example.com:853", Transport::Udp);
        assert_eq!(addr, "dns.example.com:853");
        assert_eq!(transport, Transport::Dot);

        // TCP with prefix
        let (addr, transport) = parse_upstream_addr("tcp://8.8.8.8:53", Transport::Udp);
        assert_eq!(addr, "8.8.8.8:53");
        assert_eq!(transport, Transport::Tcp);

        // UDP with prefix
        let (addr, transport) = parse_upstream_addr("udp://1.1.1.1:53", Transport::Tcp);
        assert_eq!(addr, "1.1.1.1:53");
        assert_eq!(transport, Transport::Udp);

        // TCP+UDP with prefix
        let (addr, transport) = parse_upstream_addr("tcp+udp://8.8.8.8:53", Transport::Udp);
        assert_eq!(addr, "8.8.8.8:53");
        assert_eq!(transport, Transport::TcpUdp);

        // No prefix - use default
        let (addr, transport) = parse_upstream_addr("8.8.8.8:53", Transport::Udp);
        assert_eq!(addr, "8.8.8.8:53");
        assert_eq!(transport, Transport::Udp);

        // No prefix with different default
        let (addr, transport) = parse_upstream_addr("1.1.1.1:53", Transport::Tcp);
        assert_eq!(addr, "1.1.1.1:53");
        assert_eq!(transport, Transport::Tcp);

        // Case insensitive protocol
        let (addr, transport) = parse_upstream_addr("DOQ://223.5.5.5:853", Transport::Udp);
        assert_eq!(addr, "223.5.5.5:853");
        assert_eq!(transport, Transport::Doq);

        // QUIC (alias for DoQ)
        let (addr, transport) = parse_upstream_addr("quic://dns.example.com:853", Transport::Udp);
        assert_eq!(addr, "dns.example.com:853");
        assert_eq!(transport, Transport::Doq);
    }

    #[test]
    fn test_transport_field_can_be_omitted_with_url_prefix() {
        // This test verifies that when upstream URL contains a protocol prefix,
        // the transport field can be omitted in configuration.
        // 这个测试验证当 upstream URL 包含协议前缀时，
        // 配置中可以省略 transport 字段。

        // Simulate: { "upstream": "doq://223.5.5.5:853" } (no transport field)
        // transport field would be None, which becomes Transport::Udp as default
        let default_transport = Transport::Udp;

        // parse_upstream_addr should extract DoQ from the URL prefix
        let (addr, transport) = parse_upstream_addr("doq://223.5.5.5:853", default_transport);
        assert_eq!(addr, "223.5.5.5:853");
        assert_eq!(
            transport,
            Transport::Doq,
            "URL prefix should override default transport"
        );

        // Simulate: { "upstream": "doh://dns.google/dns-query" } (no transport field)
        let (addr, transport) =
            parse_upstream_addr("doh://dns.google/dns-query", default_transport);
        assert_eq!(addr, "dns.google/dns-query");
        assert_eq!(
            transport,
            Transport::Doh,
            "URL prefix should override default transport"
        );
    }

    #[test]
    fn test_doq_url_with_0rtt_parameter() {
        // Test that DoQ URLs with 0rtt parameter are parsed correctly
        // 测试带 0rtt 参数的 DoQ URL 是否正确解析

        // DoQ with 0rtt=false
        let (addr, transport) =
            parse_upstream_addr("doq://223.5.5.5:853?0rtt=false", Transport::Udp);
        assert_eq!(addr, "223.5.5.5:853?0rtt=false");
        assert_eq!(transport, Transport::Doq);

        // DoQ with 0rtt=true
        let (addr, transport) =
            parse_upstream_addr("doq://dns.google:853?0rtt=true", Transport::Udp);
        assert_eq!(addr, "dns.google:853?0rtt=true");
        assert_eq!(transport, Transport::Doq);

        // DoQ with SNI parameter
        let (addr, transport) = parse_upstream_addr(
            "doq://dns.example.com:853?sni=dns.example.com",
            Transport::Udp,
        );
        assert_eq!(addr, "dns.example.com:853?sni=dns.example.com");
        assert_eq!(transport, Transport::Doq);

        // DoQ with both 0rtt and SNI
        let (addr, transport) = parse_upstream_addr(
            "doq://dns.example.com:853?0rtt=false&sni=dns.example.com",
            Transport::Udp,
        );
        assert_eq!(addr, "dns.example.com:853?0rtt=false&sni=dns.example.com");
        assert_eq!(transport, Transport::Doq);
    }

    fn build_test_engine(enable_tcp_fallback: bool) -> Engine {
        let settings = GlobalSettings {
            default_upstream: "127.0.0.1:0".to_string(),
            enable_tcp_fallback,
            udp_pool_size: 1,
            tcp_pool_size: 1,
            ..GlobalSettings::default()
        };
        let runtime = RuntimePipelineConfig {
            settings,
            pipeline_select: Vec::new(),
            pipelines: Vec::new(),
            pipeline_id_index: FxHashMap::default(),
        };
        Engine::new(runtime, "test".to_string()).expect("initialize test engine")
    }

    fn build_dns_query_packet(qname: &str) -> Vec<u8> {
        let mut msg = Message::new(0x1234, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        let name = Name::from_str(qname).expect("qname");
        msg.add_query(Query::query(name, RecordType::A));
        msg.to_vec().expect("encode dns query")
    }

    /// 在同一个端口上绑好 UDP 与 TCP，返回两者与它们共用的地址
    /// Bind UDP and TCP on one port and return both along with the shared address
    ///
    /// 两个 socket 必须是同一个端口，不能各绑各的：TCP 回退连的就是 upstream 的
    /// host:port，测试正是靠"有没有连到这个端口"来判断有没有回退。别顺手把它
    /// 简化成两个独立端口。
    /// The two sockets have to share one port rather than bind independently:
    /// TCP fallback dials the upstream's own host:port, and the test detects a
    /// fallback precisely by whether that port is connected to. Do not simplify
    /// this into two separate ports.
    ///
    /// 顺序是先 UDP 后 TCP。反过来会偶发 EADDRINUSE：TCP 的临时端口分配器不看
    /// UDP 占用，而整套测试并行跑时各 engine 的上游池都持有临时 UDP socket，
    /// TCP 拿到的端口可能已经被其中一个占着，第二个 UDP 绑上去就是 errno 98。
    /// 先拿 UDP 端口则把冲突面缩到"同进程的 TCP listener"，这套件里基本只有一个。
    /// UDP first, then TCP. The other order flakes with EADDRINUSE: the TCP
    /// ephemeral allocator does not look at UDP occupancy, and with the suite
    /// running in parallel every engine's upstream pool holds ephemeral UDP
    /// sockets, so the port TCP hands out may already be taken and the second
    /// UDP bind returns errno 98. Taking the UDP port first narrows the conflict
    /// to this process's own TCP listeners, of which there is essentially one.
    async fn bind_udp_and_tcp_on_one_port() -> (
        tokio::net::UdpSocket,
        tokio::net::TcpListener,
        std::net::SocketAddr,
    ) {
        // 第二道防线：那个端口偶尔也可能正被别的 TCP listener 占着，重绑即可。
        // 这不是替代上面的顺序，只是兜住剩下的那一小类。
        // Second line of defence: that port can still be held by another TCP
        // listener now and then, so rebind. It does not replace the ordering
        // above, it only covers the small class that is left.
        for _ in 0..16 {
            let udp = tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind udp");
            let addr = udp.local_addr().expect("udp addr");
            match tokio::net::TcpListener::bind(addr).await {
                Ok(tcp) => return (udp, tcp, addr),
                Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => continue,
                Err(err) => panic!("bind tcp on the udp port: {err}"),
            }
        }
        panic!("could not find a port free for both udp and tcp after 16 attempts");
    }

    #[tokio::test]
    async fn udp_truncated_response_does_not_fallback_to_tcp_when_disallowed() {
        let _ = ring::default_provider().install_default();

        let (udp_socket, tcp_listener, upstream_addr) = bind_udp_and_tcp_on_one_port().await;

        let tcp_hits = Arc::new(AtomicUsize::new(0));
        let tcp_hits_clone = Arc::clone(&tcp_hits);
        let tcp_task = tokio::spawn(async move {
            if let Ok(Ok((mut stream, _))) =
                tokio::time::timeout(Duration::from_millis(500), tcp_listener.accept()).await
            {
                tcp_hits_clone.fetch_add(1, Ordering::SeqCst);
                let mut len_buf = [0u8; 2];
                let _ = tokio::time::timeout(
                    Duration::from_millis(200),
                    stream.read_exact(&mut len_buf),
                )
                .await;
            }
        });

        let udp_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (len, peer) = udp_socket.recv_from(&mut buf).await.expect("udp recv");
            let mut resp = buf[..len].to_vec();
            if resp.len() >= 4 {
                resp[2] = 0x82; // QR=1, TC=1
                resp[3] = 0x00;
            }
            let _ = udp_socket.send_to(&resp, peer).await;
            resp
        });

        let engine = build_test_engine(true);
        let packet = build_dns_query_packet("example.com");

        let resp = forward_udp_smart(
            &engine,
            &packet,
            &upstream_addr.to_string(),
            Duration::from_millis(500),
            UdpTcpFallback {
                retry_truncated: false,
                on_failure: false,
            },
        )
        .await
        .expect("udp response");

        let udp_resp = udp_task.await.expect("udp task");
        assert_eq!(resp[2], 0x82, "tc flag should be set in udp response");
        assert_eq!(resp[3], 0x00, "response flags should match truncated reply");
        assert_eq!(
            resp.as_ref()[2..],
            udp_resp.as_slice()[2..],
            "should return udp response without tcp fallback (ignoring txid rewrite)"
        );

        let _ = tcp_task.await;
        assert_eq!(
            tcp_hits.load(Ordering::SeqCst),
            0,
            "tcp fallback should be disabled in dual-send udp path"
        );
    }
}

#[cfg(test)]
mod refresh_failure_reply_tests {
    use super::{UpstreamFailure, is_failure_reply, reject_failure_reply_on_refresh};
    use crate::engine::core::Engine;
    use crate::engine::response_log::ResponseInfo;
    use crate::engine::rules::{ResponseJumpContext, process_response_jump};
    use crate::matcher::RuntimePipelineConfig;
    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
    use hickory_proto::serialize::binary::BinDecodable;
    use serde_json::{Value, json};
    use std::net::{Ipv4Addr, SocketAddr};
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU16, Ordering};
    use std::time::Duration;

    const CLIENT: &str = "127.0.0.1:53000";
    /// Nothing listens here / 这里没有监听
    const DEAD_UPSTREAM: &str = "127.0.0.1:9";

    /// A local UDP upstream answering with one A record while its rcode is
    /// NOERROR, and with that rcode and no records once switched.
    /// 本机 UDP 上游：响应码为 NOERROR 时回一条 A 记录，切换后回该响应码、不带记录。
    struct Upstream {
        addr: String,
        rcode: Arc<AtomicU16>,
    }

    impl Upstream {
        async fn spawn() -> Self {
            let rcode = Arc::new(AtomicU16::new(u16::from(ResponseCode::NoError)));
            let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = sock.local_addr().unwrap().to_string();
            let current = rcode.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 1500];
                while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                    let Ok(query) = Message::from_bytes(&buf[..n]) else {
                        continue;
                    };
                    let Some(question) = query.queries.first().cloned() else {
                        continue;
                    };
                    let code = ResponseCode::from_low(current.load(Ordering::SeqCst) as u8);
                    let mut resp = Message::new(query.id, MessageType::Response, OpCode::Query);
                    resp.metadata.response_code = code;
                    resp.add_query(question.clone());
                    if code == ResponseCode::NoError {
                        resp.add_answer(Record::from_rdata(
                            question.name().clone(),
                            300,
                            RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(192, 0, 2, 1))),
                        ));
                    }
                    let _ = sock.send_to(&resp.to_vec().unwrap(), peer).await;
                }
            });
            Self { addr, rcode }
        }

        fn answer(&self, rcode: ResponseCode) {
            self.rcode.store(u16::from(rcode), Ordering::SeqCst);
        }
    }

    fn engine_with(pipeline: Value) -> Engine {
        let raw = json!({
            "settings": {
                "default_upstream": DEAD_UPSTREAM,
                "upstream_timeout_ms": 200,
                "min_ttl": 60
            },
            "pipelines": [pipeline]
        });
        let config: crate::config::PipelineConfig =
            serde_json::from_value(raw).expect("parse config");
        Engine::new(
            RuntimePipelineConfig::from_config(config).expect("build runtime config"),
            "test".to_string(),
        )
        .expect("engine")
    }

    /// Pipeline `id` with one rule forwarding to `upstream`, plus `response_rules`.
    /// 只有一条规则的 pipeline `id`：转发到 `upstream`，带上 `response_rules`。
    fn forwarding(id: &str, upstream: &str, response_rules: Value) -> Value {
        let mut rule = json!({
            "name": "forward",
            "matchers": [{ "type": "any" }],
            "actions": [{ "type": "forward", "upstream": upstream }]
        });
        for (key, value) in response_rules.as_object().unwrap() {
            rule[key] = value.clone();
        }
        json!({ "id": id, "rules": [rule] })
    }

    fn forward_to(upstream: &str) -> Value {
        json!([{ "type": "forward", "upstream": upstream }])
    }

    fn query() -> Message {
        let mut request = Message::new(0x5157, MessageType::Query, OpCode::Query);
        // A client asks recursively, as the entries here are stored (`QueryFlags::RECURSIVE`)
        // 客户端按递归方式问，和这里存条目时一样（`QueryFlags::RECURSIVE`）
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(
            Name::from_str("example.com.").unwrap(),
            RecordType::A,
        ));
        request
    }

    fn cache_key(engine: &Engine, pipeline: &str) -> u64 {
        let state = engine.state.load_full();
        Engine::cache_keys(
            state.cache_namespace(pipeline),
            pipeline,
            b"example.com",
            RecordType::A,
            DNSClass::IN,
            crate::proto_utils::QueryFlags::RECURSIVE,
            &crate::matcher::RequesterKey::NONE,
            None,
        )
        .slot
    }

    /// The entry a client request leaves under `key`, holding an answer.
    /// 客户端请求在 `key` 下留下的、带应答的缓存条目。
    async fn cache_an_answer(engine: &Engine, key: u64) -> Arc<crate::cache::CacheEntry> {
        let client: SocketAddr = CLIENT.parse().unwrap();
        tokio::time::timeout(
            Duration::from_secs(5),
            engine.handle_packet(&query().to_vec().unwrap(), client),
        )
        .await
        .expect("client request finishes")
        .expect("client request succeeds");
        let cached = engine.cached(key).expect("the client answer is cached");
        assert_eq!(cached.rcode, ResponseCode::NoError);
        cached
    }

    /// Runs the call `spawn_background_refresh` makes / 执行与 `spawn_background_refresh` 相同的调用
    async fn refresh(engine: &Engine, key: u64) {
        let state = engine.state.load_full();
        let client: SocketAddr = CLIENT.parse().unwrap();
        let _ = tokio::time::timeout(
            Duration::from_secs(5),
            engine.handle_packet_internal(
                &query().to_vec().unwrap(),
                client,
                true,
                None,
                Some(engine.refresh_of(key)),
                Some(state),
            ),
        )
        .await
        .expect("refresh finishes");
    }

    /// Enters `pipeline` through a response-phase jump, as a refresh does.
    /// 像刷新那样，经由响应阶段的跳转进入 `pipeline`。
    async fn refresh_through_a_jump_into(engine: &Engine, pipeline: &str) {
        let state = engine.state.load_full();
        let request = query();
        let packet = request.to_vec().unwrap();
        let _ = tokio::time::timeout(
            Duration::from_secs(5),
            process_response_jump(
                engine,
                ResponseJumpContext {
                    state: &state,
                    pipeline_id: Arc::from(pipeline),
                    remaining_jumps: 1,
                    req: &request,
                    packet: &packet,
                    peer: CLIENT.parse().unwrap(),
                    qname: "example.com",
                    qtype: RecordType::A,
                    qclass: DNSClass::IN,
                    edns_present: false,
                    client_ecs: None,
                    upstream_timeout: Duration::from_millis(200),
                    skip_cache: true,
                    carried: crate::ecs_scope::ForwardEcs {
                        source: crate::ecs_scope::EcsSource::Client,
                        sent: crate::ecs_scope::Sent::Absent,
                    },
                    trail: &mut Default::default(),
                    echo_floor: 0,
                    observed: None,
                    held_inflight: [None, None],
                },
                &mut ResponseInfo::default(),
            ),
        )
        .await
        .expect("refresh finishes");
    }

    fn assert_still_cached(engine: &Engine, key: u64, entry: &Arc<crate::cache::CacheEntry>) {
        let cached = engine.cached(key).expect("the entry stays cached");
        assert!(
            Arc::ptr_eq(&cached, entry),
            "the refresh replaced the entry"
        );
    }

    async fn assert_a_refreshed_reply_of(failure: ResponseCode) {
        let upstream = Upstream::spawn().await;
        let engine = engine_with(forwarding("main", &upstream.addr, json!({})));
        let key = cache_key(&engine, "main");
        let entry = cache_an_answer(&engine, key).await;

        upstream.answer(failure);
        refresh(&engine, key).await;
        assert_still_cached(&engine, key, &entry);
    }

    #[tokio::test]
    async fn a_refresh_answered_servfail_keeps_the_entry() {
        assert_a_refreshed_reply_of(ResponseCode::ServFail).await;
    }

    #[tokio::test]
    async fn a_refresh_answered_refused_keeps_the_entry() {
        assert_a_refreshed_reply_of(ResponseCode::Refused).await;
    }

    #[tokio::test]
    async fn a_refresh_keeps_the_entry_when_a_miss_action_forward_answers_servfail() {
        let fallback = Upstream::spawn().await;
        let on_miss = json!({ "response_actions_on_miss": forward_to(&fallback.addr) });
        let engine = engine_with(forwarding("main", DEAD_UPSTREAM, on_miss));
        let key = cache_key(&engine, "main");
        let entry = cache_an_answer(&engine, key).await;

        fallback.answer(ResponseCode::ServFail);
        refresh(&engine, key).await;
        assert_still_cached(&engine, key, &entry);
    }

    #[tokio::test]
    async fn a_refresh_through_a_jump_keeps_the_entry() {
        let upstream = Upstream::spawn().await;
        let engine = engine_with(forwarding("target", &upstream.addr, json!({})));
        let key = cache_key(&engine, "target");
        let entry = cache_an_answer(&engine, key).await;

        upstream.answer(ResponseCode::ServFail);
        refresh_through_a_jump_into(&engine, "target").await;
        assert_still_cached(&engine, key, &entry);
    }

    #[tokio::test]
    async fn a_refresh_through_a_jump_keeps_the_entry_when_a_match_action_forward_answers_servfail()
    {
        let first = Upstream::spawn().await;
        let second = Upstream::spawn().await;
        let on_match = json!({ "response_actions_on_match": forward_to(&second.addr) });
        let engine = engine_with(forwarding("target", &first.addr, on_match));
        let key = cache_key(&engine, "target");
        let entry = cache_an_answer(&engine, key).await;

        second.answer(ResponseCode::ServFail);
        refresh_through_a_jump_into(&engine, "target").await;
        assert_still_cached(&engine, key, &entry);
    }

    /// SERVFAIL、REFUSED 和扩展 RCODE 是失败应答，其余不是。扩展 RCODE 的低 4 位可能和 SERVFAIL
    /// （BADTIME 18）、REFUSED（BADALG 21）、NOERROR（BADVERS 16）一样，读的时候算上 OPT 里的部分
    /// SERVFAIL, REFUSED and the extended RCODEs are failure replies, the rest are not. An
    /// extended RCODE's low 4 bits may equal SERVFAIL's (BADTIME 18), REFUSED's (BADALG
    /// 21) or NOERROR's (BADVERS 16), so it is read with the OPT's part
    #[test]
    fn failure_replies_are_servfail_refused_and_extended_rcodes() {
        let reply = |code: ResponseCode| {
            let mut reply = Message::new(1, MessageType::Response, OpCode::Query);
            reply.metadata.response_code = code;
            if code.high() > 0 {
                reply.set_edns(hickory_proto::op::Edns::new());
            }
            reply.to_vec().unwrap()
        };
        for code in [
            ResponseCode::ServFail,
            ResponseCode::Refused,
            ResponseCode::BADVERS,
            ResponseCode::BADTIME,
            ResponseCode::BADALG,
            ResponseCode::BADCOOKIE,
        ] {
            assert!(is_failure_reply(code), "{code}");
            let err = reject_failure_reply_on_refresh(true, &reply(code)).unwrap_err();
            assert!(err.downcast_ref::<UpstreamFailure>().is_some());
            assert!(reject_failure_reply_on_refresh(false, &reply(code)).is_ok());
        }
        for code in [
            ResponseCode::NoError,
            ResponseCode::NXDomain,
            ResponseCode::FormErr,
            ResponseCode::NotImp,
        ] {
            assert!(!is_failure_reply(code), "{code}");
            assert!(reject_failure_reply_on_refresh(true, &reply(code)).is_ok());
        }
    }
}

#[cfg(test)]
mod pool_key_tests {
    use super::*;

    fn runtime(raw: serde_json::Value) -> crate::matcher::RuntimePipelineConfig {
        let config: crate::config::PipelineConfig =
            serde_json::from_value(raw).expect("parse config");
        crate::matcher::RuntimePipelineConfig::from_config(config).expect("build runtime config")
    }

    fn set(items: &[&str]) -> rustc_hash::FxHashSet<String> {
        items.iter().map(|item| item.to_string()).collect()
    }

    /// 连接池的键和转发时算的一样：带协议前缀的去掉前缀，不带的按动作的传输方式，没写上游的用
    /// 默认上游；回答阶段的转发也算，DoH 不算
    /// Pool keys come out as a forward works them out: a scheme is stripped, an address
    /// without one takes the action's transport, an action naming no upstream uses the
    /// default one; response-phase forwards count too, and DoH does not
    #[test]
    fn pool_keys_follow_how_a_forward_reads_its_upstreams() {
        let keys = pool_keys(&runtime(serde_json::json!({
            "settings": { "default_upstream": "1.1.1.1:53" },
            "pipelines": [{ "id": "main", "rules": [
                { "name": "encrypted", "matchers": [{ "type": "domain_suffix", "value": "a.test" }],
                  "actions": [{ "type": "forward",
                                "upstream": "tls://dns.alidns.com, quic://dns.alidns.com:853?sni=x" }] },
                { "name": "dot by transport", "matchers": [{ "type": "domain_suffix", "value": "b.test" }],
                  "actions": [{ "type": "forward", "upstream": "8.8.8.8:853", "transport": "dot" }] },
                { "name": "dual", "matchers": [{ "type": "domain_suffix", "value": "c.test" }],
                  "actions": [{ "type": "forward", "upstream": "tcp+udp://9.9.9.9:53" }] },
                { "name": "default over doq", "matchers": [{ "type": "domain_suffix", "value": "d.test" }],
                  "actions": [{ "type": "forward", "upstream": null, "transport": "doq" }] },
                { "name": "checked", "matchers": [{ "type": "any" }],
                  "actions": [{ "type": "forward", "upstream": "https://doh.example/dns-query" }],
                  "response_matchers": [{ "type": "response_rcode", "value": "SERVFAIL" }],
                  "response_actions_on_match": [{ "type": "forward", "upstream": "tls://dns.google" }] }
            ] }]
        })));
        assert_eq!(keys.tcp, set(&["1.1.1.1:53", "9.9.9.9:53"]));
        assert_eq!(
            keys.dot,
            set(&["dns.alidns.com", "8.8.8.8:853", "dns.google"])
        );
        assert_eq!(keys.doq, set(&["dns.alidns.com:853?sni=x", "1.1.1.1:53"]));
    }
}
