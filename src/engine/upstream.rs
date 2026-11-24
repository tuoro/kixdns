use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures::future::select;
use hickory_proto::op::ResponseCode;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_util::task::AbortOnDropHandle;
use tracing::debug;

use super::Engine;
use super::concurrency::GaveUp;
use super::transport::UdpExchange;
use crate::config::Transport;
use crate::observe::{
    UpstreamAttempt, UpstreamOutcome, UpstreamResult, UpstreamSkipReason, UpstreamSkipped,
};

use super::observation::Observed;

/// 流控没让一个查询等到上游的回答（见 `PermitManager::ask`、`Asking::wait`）/ Flow control kept a query from
/// waiting for an upstream's answer (see `PermitManager::ask`, `Asking::wait`)
#[derive(Debug)]
enum Withheld {
    /// 没去问：这台设备在这个上游上的等待多半没等到回答 / Not asked: most of this device's waits on
    /// this upstream got no answer
    NotAsked,
    /// 卡住了，这台设备留着等的又已经够多，不等了 / Stuck with enough of this device's kept waiting
    /// already, it waited no more
    GaveUp,
}

impl std::fmt::Display for Withheld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotAsked => {
                "upstream not asked: most of this client's latest queries to it got no answer"
            }
            Self::GaveUp => {
                "gave up waiting: stuck, with enough of this client's queries kept waiting"
            }
        })
    }
}

impl std::error::Error for Withheld {}

/// Error indicating that all upstream attempts have been exhausted.
/// 表示所有 upstream 尝试均已耗尽的错误。
#[derive(Debug)]
pub struct UpstreamFailure {
    source: anyhow::Error,
    /// 几个上游一起问时最先收到的失败应答（见 [`is_failure_reply`]）和回它的上游（`传输:地址`）；
    /// 全是传输出错时没有。规则的回答检查还要看它（见 `rules::check_failure_reply`）
    /// The first failure reply (see [`is_failure_reply`]) received when several upstreams
    /// were asked together, with the upstream that sent it (`transport:address`); none when
    /// every attempt was a transport error. The rule's answer check still reads it (see
    /// `rules::check_failure_reply`)
    reply: Option<(Bytes, Arc<str>)>,
}

impl UpstreamFailure {
    pub fn new(source: anyhow::Error) -> Self {
        Self {
            source,
            reply: None,
        }
    }

    /// `source` 包成「上游都失败了」的错误，调用方据此认出它（见 `downcast_ref`）
    /// `source` wrapped as an "every upstream failed" error, which callers tell by
    /// `downcast_ref`
    pub fn error(source: anyhow::Error) -> anyhow::Error {
        anyhow::Error::new(Self::new(source))
    }

    /// 流控没让等的失败（见 [`Withheld`]）。调用方照上游失败处理，只有三处不同：不逐个记警告日志——拦的时候每秒可以有
    /// 几万个；不把结果交给等在同一个转发上的别的请求——这是这台设备自己的事，别的设备各自去问；这个请求此后得到的应答
    /// 都不写进缓存，规则在上游失败时给的静态应答、改问备用上游得到的回答都一样——缓存是所有设备共用的，别的设备问这个
    /// 上游是有回答的
    /// A failure with flow control keeping the query from waiting (see [`Withheld`]). Callers
    /// treat it as the upstream failing, but for three things: no warning is logged for each, as
    /// held back there can be tens of thousands a second; the outcome is not handed to other
    /// requests waiting on the same forward, this being the device's own affair, so other
    /// devices ask for themselves; and nothing the request gets from then on is written to the
    /// cache, a static answer the rules give on an upstream failure and a fallback upstream's
    /// answer alike, the cache being shared by all devices while the upstream does answer the
    /// others
    fn withheld(why: Withheld) -> anyhow::Error {
        anyhow::Error::new(Self::new(anyhow::Error::new(why)))
    }

    /// `err` 是不是流控没让等的失败（见 [`Self::withheld`]）/ Whether `err` is a failure with flow
    /// control keeping the query from waiting (see [`Self::withheld`])
    pub(crate) fn was_withheld(err: &anyhow::Error) -> bool {
        err.downcast_ref::<Self>()
            .is_some_and(|failure| failure.source.is::<Withheld>())
    }

    /// 同 [`Self::error`]，带着最先收到的失败应答 / As [`Self::error`], carrying the first
    /// failure reply received
    fn with_reply(source: anyhow::Error, reply: Option<(Bytes, Arc<str>)>) -> anyhow::Error {
        anyhow::Error::new(Self { source, reply })
    }

    /// `err` 是上游都失败了、而且带着失败应答时，那个应答和回它的上游
    /// The failure reply `err` carries, and the upstream that sent it, when `err` is an
    /// every-upstream-failed error with one
    pub(crate) fn reply_of(err: &anyhow::Error) -> Option<&(Bytes, Arc<str>)> {
        err.downcast_ref::<Self>()
            .and_then(|failure| failure.reply.as_ref())
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
    background_refresh: bool,
    reply: &[u8],
) -> anyhow::Result<()> {
    if !background_refresh {
        return Ok(());
    }
    match crate::proto_utils::parse_response_quick(reply).map(|qr| qr.rcode) {
        Some(rcode) if is_failure_reply(rcode) => Err(UpstreamFailure::error(anyhow::anyhow!(
            "the upstream answered {rcode}"
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

/// `cfg` 里经 TCP 问的上游地址（去掉前缀，见 [`upstreams`]），启动时据此预热连接；`tcp` 和 `tcp_udp` 算 TCP
/// The addresses (short of their prefix, see [`upstreams`]) of the upstreams `cfg` asks over
/// TCP, whose connections are warmed up at startup; `tcp` and `tcp_udp` count as TCP
pub(crate) fn tcp_upstreams(
    cfg: &crate::matcher::RuntimePipelineConfig,
) -> rustc_hash::FxHashSet<String> {
    upstreams(cfg)
        .into_iter()
        .filter(|(_, transport)| matches!(transport, Transport::Tcp | Transport::TcpUdp))
        .map(|(address, _)| address.to_owned())
        .collect()
}

/// 规则里写的一串上游各自的地址（去掉前缀），`PermitManager::note_answer_took` 就是按它记的 / The address
/// (short of its prefix) of each of the upstreams a rule writes, which is what
/// `PermitManager::note_answer_took` notes by
pub(crate) fn addresses(upstream: &str) -> impl Iterator<Item = &str> {
    upstream
        .split(',')
        .map(str::trim)
        .filter(|member| !member.is_empty())
        .map(|member| parse_upstream_addr(member, Transport::Udp).0)
}

/// 上游地址前缀对应的传输；不认识的前缀为 None（[`parse_upstream_addr`] 这时用默认传输）
/// The transport an upstream prefix names; None for a prefix it does not know
/// ([`parse_upstream_addr`] then takes the default transport)
pub(crate) fn transport_for_scheme(scheme: &str) -> Option<Transport> {
    // 每个转发都要看一次，不为大小写分配内存 / Every forward looks once, so case costs no allocation
    let is = |name: &str| scheme.eq_ignore_ascii_case(name);
    Some(if is("tcp") {
        Transport::Tcp
    } else if is("udp") {
        Transport::Udp
    } else if is("tcp+udp") || is("udp+tcp") {
        Transport::TcpUdp
    } else if is("doh") || is("https") {
        Transport::Doh
    } else if is("dot") || is("tls") {
        Transport::Dot
    } else if is("doq") || is("quic") {
        Transport::Doq
    } else {
        return None;
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

/// 连上 `upstream` 之前要解析的主机名，没写前缀的按 `default_transport` 连（见 `transport::host_name`）
/// The host name to resolve before connecting to `upstream`, one without a prefix connected to
/// by `default_transport` (see `transport::host_name`)
pub(crate) fn host_name(upstream: &str, default_transport: Transport) -> Option<String> {
    let (address, transport) = parse_upstream_addr(upstream, default_transport);
    crate::engine::transport::host_name(address, transport)
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

/// `cfg` 可能转发到的每个上游，各一次，和转发时的算法一样（见 [`parse_upstream_addr`]）：去掉前缀的地址和问它用的
/// 传输。默认上游，以及请求阶段和回答阶段每个转发动作的上游（没写就是默认上游）
/// Every upstream `cfg` may forward to, each once, worked out as a forward does (see
/// [`parse_upstream_addr`]): the address short of its prefix and the transport it is asked
/// over. The default upstream, and the upstream of every forward action in the request and
/// response phases (the default upstream when it names none)
pub(crate) fn upstreams(
    cfg: &crate::matcher::RuntimePipelineConfig,
) -> rustc_hash::FxHashSet<(&str, Transport)> {
    let default = cfg.settings.default_upstream.as_str();
    let forwards = cfg
        .pipelines
        .iter()
        .flat_map(|pipeline| &pipeline.rules)
        .flat_map(crate::matcher::RuntimeRule::all_actions)
        .filter_map(|action| match action {
            crate::config::Action::Forward {
                upstream,
                transport,
                ..
            } => Some((upstream.as_deref().unwrap_or(default), *transport)),
            _ => None,
        });
    std::iter::once((default, None))
        .chain(forwards)
        .flat_map(|(upstreams, transport)| {
            upstreams
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(move |upstream| {
                    parse_upstream_addr(upstream, transport.unwrap_or(Transport::Udp))
                })
        })
        .collect()
}

/// `cfg` 用到的每个上游在连接池里的键（见 [`upstreams`]）。UDP 上游在应答被截断或失败时改用 TCP，所以也算一个
/// TCP 键
/// The pool key of every upstream `cfg` uses (see [`upstreams`]). A UDP upstream falls back
/// to TCP on a truncated or failed answer, so it has a TCP key too
pub(crate) fn pool_keys(cfg: &crate::matcher::RuntimePipelineConfig) -> PoolKeys {
    let mut keys = PoolKeys::default();
    for (address, transport) in upstreams(cfg) {
        let set = match transport {
            Transport::Udp | Transport::Tcp | Transport::TcpUdp => &mut keys.tcp,
            Transport::Dot => &mut keys.dot,
            Transport::Doq => &mut keys.doq,
            Transport::Doh => continue,
        };
        set.insert(address.to_owned());
    }
    keys
}

/// 双发的一路失败以后，在剩下的 `remaining` 里等另一路；返回另一路的应答和它的传输
/// After one leg of a dual send failed, wait up to `remaining` for the other; returns
/// the other leg's answer and its transport
async fn fallback_after_primary_failure(
    other_task: AbortOnDropHandle<anyhow::Result<Bytes>>,
    remaining: Duration,
    primary_label: &'static str,
    primary_err: anyhow::Error,
    primary_is_task_error: bool,
    other: Transport,
) -> anyhow::Result<(Bytes, Transport)> {
    let other_label = transport_label(other);
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
        Ok(Ok(Ok(bytes))) => Ok((bytes, other)),
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

/// Send both TCP and UDP concurrently, return first successful response (hedged request),
/// with the transport that carried it.
/// 同时发送 TCP 和 UDP，返回第一个成功响应（对冲请求），以及带回它的传输。
async fn forward_tcp_udp_dual(
    engine: &Engine,
    packet: &[u8],
    addr: &str,
    timeout_dur: Duration,
) -> anyhow::Result<(Bytes, Transport)> {
    let engine_udp = engine.clone();
    let engine_tcp = engine.clone();
    // Use Bytes for cheap clone (refcount) instead of Vec full copy
    // 使用 Bytes 实现低成本克隆（引用计数）而非 Vec 全量拷贝
    let packet_shared = Bytes::copy_from_slice(packet);
    let packet_udp = packet_shared.clone();
    let packet_tcp = packet_shared.clone();
    let addr_udp = addr.to_string();
    let addr_tcp = addr.to_string();

    // 两路各是一个任务，句柄一丢任务就取消：这次转发被放弃时（外层的时限先到、几个上游竞速它输了），两路不该
    // 接着跑到各自的超时，UDP 那一路还会再发一次
    // Each leg is a task that is cancelled when its handle is dropped: when this forward is given
    // up (an outer deadline comes first, or it loses a race between upstreams) the legs must not
    // run on to their own timeouts, the UDP one sending once more on the way
    let udp_task = AbortOnDropHandle::new(tokio::spawn(async move {
        // Disable TCP fallback here to avoid duplicate TCP sends when dual-send is enabled.
        // A truncated answer waits for the TCP leg below instead.
        // 双发时这里不改用 TCP，免得重复发送；截断的应答改为在下面等 TCP 那一路。
        let tcp = UdpTcpFallback {
            retry_truncated: false,
            on_failure: false,
        };
        forward_udp_smart(&engine_udp, &packet_udp, &addr_udp, timeout_dur, tcp)
            .await
            .map(|(bytes, _)| bytes)
    }));

    let tcp_task = AbortOnDropHandle::new(tokio::spawn(async move {
        let sent = sent_if_timed(&engine_tcp);
        let reply = engine_tcp
            .tcp_mux
            .send(&packet_tcp, &addr_tcp, timeout_dur)
            .await;
        note_round_trip(&engine_tcp, &addr_tcp, timeout_dur, sent, &reply);
        reply
    }));

    let start = std::time::Instant::now();

    // Wait for first successful response / 等待第一个成功响应
    let first = select(udp_task, tcp_task).await;
    let remaining = timeout_dur.saturating_sub(start.elapsed());
    match first {
        futures::future::Either::Left((result, mut tcp_task)) => match result {
            // A truncated UDP answer does not win: the TCP leg is asking the same upstream
            // for the full answer, so wait for it, and fall back to the truncated answer only
            // if it fails.
            // 截断的 UDP 应答不算赢：TCP 那一路正在向同一个上游要完整应答，所以等它；它失败了才
            // 退回这个截断的应答。
            Ok(Ok(bytes)) if crate::proto_utils::truncated_response(&bytes) => {
                match timeout(remaining, &mut tcp_task).await {
                    Ok(Ok(Ok(full))) => Ok((full, Transport::Tcp)),
                    other => {
                        if other.is_err() {
                            tcp_task.abort();
                        }
                        debug!(event = "tc_udp_answer_kept", upstream = %addr, "tcp leg gave no answer, keeping the truncated udp answer");
                        Ok((bytes, Transport::Udp))
                    }
                }
            }
            Ok(Ok(bytes)) => {
                tcp_task.abort();
                Ok((bytes, Transport::Udp))
            }
            Ok(Err(err)) => {
                fallback_after_primary_failure(
                    tcp_task,
                    remaining,
                    "udp",
                    err,
                    false,
                    Transport::Tcp,
                )
                .await
            }
            Err(join_err) => {
                fallback_after_primary_failure(
                    tcp_task,
                    remaining,
                    "udp",
                    anyhow::anyhow!(join_err),
                    true,
                    Transport::Tcp,
                )
                .await
            }
        },
        futures::future::Either::Right((result, udp_task)) => match result {
            Ok(Ok(bytes)) => {
                udp_task.abort();
                Ok((bytes, Transport::Tcp))
            }
            Ok(Err(err)) => {
                fallback_after_primary_failure(
                    udp_task,
                    remaining,
                    "tcp",
                    err,
                    false,
                    Transport::Udp,
                )
                .await
            }
            Err(join_err) => {
                fallback_after_primary_failure(
                    udp_task,
                    remaining,
                    "tcp",
                    anyhow::anyhow!(join_err),
                    true,
                    Transport::Udp,
                )
                .await
            }
        },
    }
}

/// 一个规则的上游，通常一两个，放得下时不分配内存 / A rule's upstreams, usually one or two, which
/// take no allocation while they fit
type Upstreams = smallvec::SmallVec<[Arc<str>; 4]>;

/// Forward DNS request to multiple upstreams concurrently (Happy Eyeballs / Hedged Request)
/// 并发转发 DNS 请求到多个上游 (Happy Eyeballs / Hedged Request)
///
/// Returns the first successful response and the name of the winning upstream.
/// 返回第一个成功的响应和获胜的上游名称。
///
/// `observed` is the observer context of the request; every attempt and its
/// result is reported through it. / `observed` 为所属请求的观察者上下文，每次尝试及其结果都经它上报。
///
/// DNS cookie（RFC 7873）和填充（RFC 7830）只在相邻两跳之间有意义，这里两头把关：查询去掉客户端的 cookie 和
/// 填充再发出，应答去掉它们再交回，于是它们既不会进缓存，也不会交给别的客户端。所有发往上游的查询都经过这里。
/// DNS cookies (RFC 7873) and padding (RFC 7830) mean something between two neighbouring
/// hops only, so both ends are guarded here: a query goes out without the client's cookie
/// and padding and a reply comes back without any, so neither enters the cache or reaches
/// another client. Every query for an upstream passes through here.
///
/// 应答交回之前，每条记录的 TTL 收进 `min_ttl..=cache_max_ttl`：客户端留一份应答的时间和缓存一样长。
/// Before the reply is handed back, the TTL of every record is brought into
/// `min_ttl..=cache_max_ttl`, so a client keeps an answer as long as the cache does.
///
/// 几个上游一起问时，刚回过 429、正在暂停的 DoH 上游这次不问（见 [`without_paused`]）。
/// When several upstreams are asked together, a DoH upstream that answered 429 a moment
/// ago and is paused is not asked this time (see [`without_paused`]).
///
/// `asker` 是替谁问的（后台刷新不替谁问，是 None）。开了流控时：这台设备最近在这个上游上的等待多半没等到回答，这一次
/// 不问（见 `PermitManager::ask`）；问了的卡住了、这台设备留着等的又已经够多，不等了（见 `Asking::wait`）。两样都算上游
/// 失败（见 [`UpstreamFailure::withheld`]）。
/// `asker` is whom this is asked for (None for a background refresh, asked for nobody). With
/// flow control on: with most of this device's latest waits on this upstream unanswered, this
/// one is not asked (see `PermitManager::ask`); one that is asked and gets stuck with enough of
/// the device's kept waiting already waits no more (see `Asking::wait`). Both count as the
/// upstream failing (see [`UpstreamFailure::withheld`]).
pub async fn forward_upstream(
    engine: &Engine,
    packet: &[u8],
    upstream: &str,
    timeout_dur: Duration,
    transport: Option<Transport>,
    pre_split_upstreams: Option<&std::sync::Arc<Vec<std::sync::Arc<str>>>>,
    observed: Observed<'_>,
    asker: Option<std::net::IpAddr>,
) -> anyhow::Result<(Bytes, Arc<str>)> {
    let asking = match (asker, &engine.flow_control_state) {
        (Some(client), Some(flow)) => {
            match engine
                .permit_manager
                .ask(flow, client, upstream, timeout_dur)
            {
                Some(asking) => Some(asking),
                None => return Err(UpstreamFailure::withheld(Withheld::NotAsked)),
            }
        }
        _ => None,
    };
    let packet =
        crate::proto_utils::query_asking_ad(crate::proto_utils::query_without_hop_options(packet));
    let guarded = |reply| {
        let reply = crate::proto_utils::reply_without_aa(
            crate::proto_utils::reply_without_hop_options(reply),
        );
        // 用当前配置的 min_ttl，而不是请求开始时那份：改 min_ttl 会轮换所有缓存命名空间，一个跨过重载
        // 的应答只会交给它自己的客户端
        // min_ttl comes from the current configuration rather than the request's own:
        // changing it rotates every cache namespace, so a reply in flight across a
        // reload reaches only its own client
        let floor = engine.state.load().pipeline.settings.min_ttl;
        crate::proto_utils::reply_within_ttls(reply, floor, engine.ttl_cap())
    };
    // 固定在这里，两条路等的是同一份 / Pinned here, both paths waiting on the one copy
    let mut forward = std::pin::pin!(forward_upstream_as_is(
        engine,
        &packet,
        upstream,
        timeout_dur,
        transport,
        pre_split_upstreams,
        observed,
    ));
    let forwarded = match asking {
        // 流控的等待（定时器、这次等待的记录）单独在堆上分配：放在这里的话，没开流控时每个等上游的查询也得替它留着地方
        // Flow control's wait (its timer and what is kept of this wait) is allocated on its own:
        // held here, every query waiting on an upstream would reserve room for it without flow
        // control too
        Some(asking) => Box::pin(waited_for(asking, forward.as_mut())).await?,
        None => forward.await,
    };
    match forwarded {
        Ok((reply, winner)) => Ok((guarded(reply), winner)),
        // 失败带着的失败应答也可能交到客户端手里（见 `rules::check_failure_reply`），一样把关
        // The failure reply a failure carries may reach a client too (see
        // `rules::check_failure_reply`), so it passes the same guards
        Err(mut err) => {
            if let Some(failure) = err.downcast_mut::<UpstreamFailure>()
                && let Some((reply, _)) = failure.reply.as_mut()
            {
                *reply = guarded(std::mem::take(reply));
            }
            Err(err)
        }
    }
}

/// 开了流控时等一次转发 `forward` 走完（见 `Asking::wait`），并记下上游回了什么：卡住了、留着等的又已经够多时不等了，是外层
/// 的 Err；转发自己的结果原样在里层
/// Waits for one `forward` to be done with flow control on (see `Asking::wait`), noting what
/// the upstream replied: stuck with enough kept waiting already it waits no more, which is the
/// outer Err; the forward's own outcome is the inner one as it is
async fn waited_for<F>(
    mut asking: crate::engine::concurrency::Asking<'_>,
    forward: std::pin::Pin<&mut F>,
) -> anyhow::Result<anyhow::Result<(Bytes, Arc<str>)>>
where
    F: Future<Output = anyhow::Result<(Bytes, Arc<str>)>>,
{
    let Ok(forwarded) = asking.wait(forward).await else {
        return Err(UpstreamFailure::withheld(Withheld::GaveUp));
    };
    match &forwarded {
        // 只有一个上游的规则，失败应答也当作应答交回来：那不是用得上的回答 / A rule with a single
        // upstream gets a failure reply back as its answer, which is no answer of use
        Ok((reply, _)) => asking.replied(!is_failure_reply_packet(reply)),
        // 几个上游都失败了，其中有回了失败应答的：上游是回了的 / Every upstream failed, one of them
        // with a failure reply: the upstreams did reply
        Err(err) if UpstreamFailure::reply_of(err).is_some() => asking.replied(false),
        Err(_) => {}
    }
    Ok(forwarded)
}

/// 等别的请求正在做的、给 `upstream` 的同一个转发（`wait`），`client` 是替谁等的，`limit` 是上游的时限。开了流控时还看卡没卡住：
/// 卡住了、这台设备留着等的又已经够多时不等了，算上游失败；别的都不管（见 `PermitManager::join`）
/// Waits on the same forward to `upstream` another request is making (`wait`), `client` being
/// whom it waits for and `limit` the upstream's timeout. With flow control on it is also seen to
/// for being stuck: stuck with enough of this device's kept waiting already it waits no more,
/// which counts as the upstream failing; nothing else is looked at (see `PermitManager::join`)
pub(crate) async fn wait_for_another<T>(
    engine: &Engine,
    client: std::net::IpAddr,
    upstream: &str,
    limit: Duration,
    wait: impl Future<Output = T>,
) -> anyhow::Result<T> {
    let Some(flow) = &engine.flow_control_state else {
        return Ok(wait.await);
    };
    // 流控的等待单独在堆上分配：只有等别人的查询才用得着，放在调用方里的话每个等上游的查询都得替它留着地方
    // Flow control's wait is allocated on its own: only a query waiting on another's has use for
    // it, and held in the callers every query waiting on an upstream would reserve room for it
    Box::pin(async move {
        let mut joining = engine.permit_manager.join(flow, client, upstream, limit);
        let wait = std::pin::pin!(wait);
        joining
            .wait(wait)
            .await
            .map_err(|GaveUp| UpstreamFailure::withheld(Withheld::GaveUp))
    })
    .await
}

/// 应答报文是不是失败应答（SERVFAIL、REFUSED），只看报头里的 RCODE / Whether a reply packet is a failure
/// reply (SERVFAIL, REFUSED), by the RCODE in its header alone
pub(crate) fn is_failure_reply_packet(reply: &[u8]) -> bool {
    reply
        .get(3)
        .is_some_and(|flags| matches!(flags & 0x0f, 2 | 5))
}

/// [`forward_upstream`] 少了两头把关的部分 / [`forward_upstream`] short of its guards at both ends
async fn forward_upstream_as_is(
    engine: &Engine,
    packet: &[u8],
    upstream: &str,
    timeout_dur: Duration,
    transport: Option<Transport>,
    pre_split_upstreams: Option<&std::sync::Arc<Vec<std::sync::Arc<str>>>>,
    observed: Observed<'_>,
) -> anyhow::Result<(Bytes, Arc<str>)> {
    // 如果 transport 为 None，使用默认 UDP
    let default_transport = transport.unwrap_or(Transport::Udp);

    // 使用预分割数据或动态分割 / Use pre-split data or dynamic splitting
    // 使用 Arc<str> 避免克隆 / Use Arc<str> to avoid cloning
    let upstreams: Upstreams = if let Some(pre_split) = pre_split_upstreams {
        pre_split.iter().cloned().collect()
    } else if !upstream.contains(',') {
        // 单个上游：直接转发 / Single upstream: direct forward
        smallvec::smallvec![std::sync::Arc::from(upstream)]
    } else {
        upstream
            .split(',')
            .map(|s| s.trim())
            .map(std::sync::Arc::from)
            .filter(|s: &std::sync::Arc<str>| !s.is_empty())
            .collect()
    };
    // 剩下一个上游时，它走下面只有一个上游的那条路，和只写了这一个上游一样
    // With one upstream left it takes the single-upstream path below, as if it were the
    // only one written
    let upstreams = without_paused(engine, upstreams, default_transport, observed);
    let mut attempts = Attempts::new(observed);

    // 快速路径：只有一个上游时，直接调用避免 spawn 开销
    // Fast path: direct call when only one upstream, avoiding spawn overhead
    if upstreams.len() == 1 {
        let up = &upstreams[0];

        // 解析地址中的协议前缀 / Parse protocol prefix from address
        let (addr, transport_for_addr) = parse_upstream_addr(up, default_transport);
        let attempt = attempts.start(addr, transport_for_addr);

        let start = std::time::Instant::now();
        // `via` is the transport that actually carried the answer (UDP may fall
        // back to TCP) / `via` 为实际带回答案的传输（UDP 可能回退到 TCP）
        let tcp = UdpTcpFallback {
            retry_truncated: true,
            on_failure: true,
        };
        let (res, via) =
            send_to_upstream(engine, packet, addr, timeout_dur, transport_for_addr, tcp).await;
        let dur = start.elapsed();

        match res {
            Ok(bytes) => {
                // Quick check rcode / 快速解析响应码
                let quick = crate::proto_utils::parse_response_quick(&bytes);
                attempts.finish(
                    attempt,
                    via,
                    UpstreamOutcome::Success,
                    dur,
                    quick.as_ref(),
                    None,
                );
                if let Some(qr) = quick {
                    tracing::debug!(upstream=%up, upstream_ns = dur.as_nanos() as u64, rcode = %qr.rcode, "upstream call succeeded");
                }
                return Ok((bytes, upstream_label(via, addr)));
            }
            Err(err) => {
                let outcome = failed_outcome(&err);
                attempts.finish(attempt, transport_for_addr, outcome, dur, None, Some(&err));
                // 失败时不构造 prefix，只 warn；回了 429 的只记 debug：暂停开始时 DoH 客户端已经记过一条 warn
                // No prefix is built on failure, only a warn; a 429 logs at debug, the DoH
                // client having logged one warn as the pause began
                if outcome == UpstreamOutcome::Throttled {
                    tracing::debug!(upstream=%up, error=%err, elapsed_ns = dur.as_nanos() as u64, "single upstream throttled");
                } else {
                    crate::warn_sparse!(upstream=%up, error=%err, elapsed_ns = dur.as_nanos() as u64, "single upstream call failed");
                }
                return Err(UpstreamFailure::error(err));
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
    // 最先收到的失败应答，全都失败时带出去（见 `UpstreamFailure::reply`）
    // The first failure reply received, carried out when every attempt fails (see
    // `UpstreamFailure::reply`)
    let mut first_failure_reply: Option<(Bytes, Arc<str>)> = None;
    // 最先收到的截断应答：它是传输层用 TCP 也取不到完整应答时留下的（见 `forward_udp_smart`），只在别的上游都给不出
    // 完整应答时交回，客户端看到 TC 自己改用 TCP：先到的截断应答不取消还在路上的完整应答
    // The first truncated answer received: what the transport was left with when TCP could
    // not fetch the whole answer either (see `forward_udp_smart`). It goes back only when no
    // other upstream gives a whole answer, the client turning to TCP itself on seeing TC: coming
    // first, it does not cancel a whole answer still on its way
    let mut first_truncated: Option<(Bytes, Arc<str>)> = None;

    // If any TCP/TCP+UDP upstream is present, a failed UDP attempt does not fall back to TCP, to
    // prevent duplicate TCP sends (truncated answers are still fetched again over TCP)
    // 如果同一批次已有 TCP/TCP+UDP 上游，UDP 失败时不再回退到 TCP，避免重复 TCP 发送（截断的应答照样用
    // TCP 重取）
    let has_tcp_task = upstreams.iter().any(|up| {
        let (_, t) = parse_upstream_addr(up, default_transport);
        matches!(t, Transport::Tcp | Transport::TcpUdp)
    });

    for up in &upstreams {
        // 解析地址中的协议前缀 / Parse protocol prefix from address
        let (addr, transport_for_task) = parse_upstream_addr(up, default_transport);
        let attempt = attempts.start(addr, transport_for_task);

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
            let (res, via) = send_to_upstream(
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
            let upstream_with_proto = upstream_label(via, &addr_owned);
            let dur = start.elapsed();
            (attempt, upstream_with_proto, via, res, dur)
        });
    }

    // 等待第一个成功响应 / Wait for first successful response
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok((attempt, up_proto, via, res, dur)) => {
                // Report the outcome of this attempt / 上报本次尝试的结果
                let mut report = |outcome,
                                  reply: Option<&crate::proto_utils::QuickResponse>,
                                  error: Option<&anyhow::Error>| {
                    attempts.finish(attempt, via, outcome, dur, reply, error);
                };
                match res {
                    Ok(bytes) => {
                        // 快速解析响应码 / Quick parse response code
                        let quick = crate::proto_utils::parse_response_quick(&bytes);
                        let kept = if quick.as_ref().is_some_and(|qr| is_failure_reply(qr.rcode)) {
                            &mut first_failure_reply
                        } else if crate::proto_utils::truncated_response(&bytes) {
                            &mut first_truncated
                        } else {
                            report(UpstreamOutcome::Success, quick.as_ref(), None);
                            // 显式取消其他正在进行的任务，它们的尝试竞争失败（见 `Attempts`）
                            // Cancel the attempts still running, which lose the race (see
                            // `Attempts`)
                            tasks.abort_all();

                            return Ok((bytes, up_proto));
                        };
                        report(UpstreamOutcome::Rejected, quick.as_ref(), None);
                        kept.get_or_insert((bytes, up_proto));
                    }
                    Err(err) => {
                        let outcome = failed_outcome(&err);
                        report(outcome, None, Some(&err));
                        // 回了 429 的只记 debug：暂停开始时 DoH 客户端已经记过一条 warn
                        // A 429 logs at debug: the DoH client logged one warn as the pause began
                        if outcome == UpstreamOutcome::Throttled {
                            tracing::debug!(upstream=%up_proto, error=%err, elapsed_ns = dur.as_nanos() as u64, "upstream throttled, waiting for others");
                        } else {
                            crate::warn_sparse!(upstream=%up_proto, error=%err, elapsed_ns = dur.as_nanos() as u64, "upstream call failed, waiting for others");
                        }
                        last_err = Some(err);
                    }
                }
            }
            Err(e) => {
                crate::warn_sparse!(error = %e, "upstream task join error, waiting for others");
                last_err = Some(anyhow::anyhow!(e));
            }
        }
    }

    if let Some(truncated) = first_truncated {
        return Ok(truncated);
    }
    // 所有上游都失败 / All upstreams failed
    let err = last_err.unwrap_or_else(|| anyhow::anyhow!("all upstreams failed"));
    Err(UpstreamFailure::with_reply(err, first_failure_reply))
}

/// 一组上游里去掉正在暂停的 DoH 上游（见 `DohClient::is_paused`），逐个报给观察者。只有一个上游时，
/// 或者全都在暂停时，一个也不去：暂停只是让别的上游来答，不会让一次转发谁都不问。
/// Takes the paused DoH upstreams out of a set (see `DohClient::is_paused`), reporting each
/// to the observer. A single upstream, or a set whose every upstream is paused, keeps them
/// all: a pause only lets the others answer, it never leaves a forward with nobody to ask.
fn without_paused(
    engine: &Engine,
    upstreams: Upstreams,
    default_transport: Transport,
    observed: Observed<'_>,
) -> Upstreams {
    // 通常没有上游在暂停：只花一次原子读取，地址都不解析
    // Usually no upstream is paused: one atomic load, and no address is parsed
    if upstreams.len() < 2 || !engine.doh_client.any_paused() {
        return upstreams;
    }
    let paused: Vec<bool> = upstreams
        .iter()
        .map(|up| {
            let (addr, transport) = parse_upstream_addr(up, default_transport);
            transport == Transport::Doh && engine.doh_client.is_paused(addr)
        })
        .collect();
    if !paused.contains(&true) || !paused.contains(&false) {
        return upstreams;
    }
    upstreams
        .into_iter()
        .zip(paused)
        .filter_map(|(up, paused)| {
            if !paused {
                return Some(up);
            }
            let (addr, transport) = parse_upstream_addr(&up, default_transport);
            if let Some((observer, ctx)) = observed {
                observer.upstream_skipped(
                    ctx,
                    &UpstreamSkipped {
                        upstream: addr,
                        transport,
                        reason: UpstreamSkipReason::Throttled,
                    },
                );
            }
            debug!(upstream = %up, "DoH upstream paused after a 429, left out of this forward");
            None
        })
        .collect()
}

/// 一次失败的尝试算哪种结果：DoH 上游回了 429 是 Throttled，其余是 Error
/// The outcome of a failed attempt: Throttled for a DoH upstream answering 429, Error
/// otherwise
fn failed_outcome(err: &anyhow::Error) -> UpstreamOutcome {
    if crate::engine::transport::throttle_of(err).is_some() {
        UpstreamOutcome::Throttled
    } else {
        UpstreamOutcome::Error
    }
}

/// 一次转发报给观察者的尝试：每次 `upstream_attempt` 都配一次 `upstream_result`。丢掉时还没报结果的报成
/// [`UpstreamOutcome::Aborted`]：一组上游里别的先答了、任务没交回结果，或者整个转发半路被放下（请求被取消、流控不等了）。
/// 没有观察者时什么也不记
/// The attempts of one forward reported to the observer: every `upstream_attempt` gets one
/// `upstream_result`. Dropped, it reports those still without a result as
/// [`UpstreamOutcome::Aborted`]: another upstream of the set answered first, a task never
/// handed its result back, or the whole forward was dropped halfway (the request cancelled,
/// flow control waiting no more). Without an observer nothing is kept
struct Attempts<'a> {
    observed: Observed<'a>,
    /// 每次尝试的上游、传输和开始的时候，报了结果的是 None / Each attempt's upstream, transport
    /// and start, None once its result is reported
    pending: Vec<Option<(&'a str, Transport, Instant)>>,
}

impl<'a> Attempts<'a> {
    fn new(observed: Observed<'a>) -> Self {
        Self {
            observed,
            pending: Vec::new(),
        }
    }

    /// 报一次尝试，返回它的编号，报结果时用 / Reports an attempt, returning its number for
    /// reporting its result
    fn start(&mut self, upstream: &'a str, transport: Transport) -> usize {
        let attempt = self.pending.len();
        if let Some((observer, ctx)) = self.observed {
            observer.upstream_attempt(
                ctx,
                &UpstreamAttempt {
                    upstream,
                    transport,
                },
            );
            self.pending
                .push(Some((upstream, transport, Instant::now())));
        }
        attempt
    }

    /// 报 `attempt` 的结果：`via` 是带回应答的传输，`reply` 是快速解析出的应答 / Reports the
    /// result of `attempt`: `via` is the transport that carried the answer, `reply` the answer
    /// as quickly parsed
    fn finish(
        &mut self,
        attempt: usize,
        via: Transport,
        outcome: UpstreamOutcome,
        latency: Duration,
        reply: Option<&crate::proto_utils::QuickResponse>,
        error: Option<&anyhow::Error>,
    ) {
        if let Some((observer, ctx)) = self.observed {
            let (upstream, transport, _) = self.pending[attempt]
                .take()
                .expect("one result per attempt");
            observer.upstream_result(
                ctx,
                &UpstreamResult {
                    upstream,
                    transport,
                    via,
                    outcome,
                    latency,
                    rcode: reply.map(|reply| reply.rcode),
                    truncated: reply.map(|reply| reply.truncated),
                    error,
                },
            );
        }
    }
}

impl Drop for Attempts<'_> {
    fn drop(&mut self) {
        if let Some((observer, ctx)) = self.observed {
            for (upstream, transport, started) in self.pending.drain(..).flatten() {
                observer.upstream_result(
                    ctx,
                    &UpstreamResult {
                        upstream,
                        transport,
                        via: transport,
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
}

/// Sends `packet` to one upstream over `transport`, and returns the answer with the
/// transport that carried it (a UDP query may end up over TCP; see [`transport_label`]).
/// Each transport's exchange is allocated on its own, sized to that transport: held
/// inline, it made every query waiting on an upstream reserve room for the largest of
/// them (DoT, about 2 KB), whatever the query went over.
/// 把 `packet` 经 `transport` 发给一个上游，返回应答以及实际带回应答的传输（UDP 查询可能最后走了
/// TCP；见 [`transport_label`]）。每种传输的收发单独在堆上分配，大小按这种传输来：放在调用方里时，
/// 等上游的每个查询不管走的是哪种传输，都得按最大的那种（DoT，约 2 KB）预留。
///
/// 经加密传输发的查询在这里补齐长度（见 `padded_query`），明文传输上不填充（RFC 7830 第 6 节）
/// A query over an encrypted transport is padded here (see `padded_query`); one over a
/// cleartext transport is not (RFC 7830 section 6)
async fn send_to_upstream(
    engine: &Engine,
    packet: &[u8],
    addr: &str,
    timeout_dur: Duration,
    transport: Transport,
    tcp: UdpTcpFallback,
) -> (anyhow::Result<Bytes>, Transport) {
    let packet: &[u8] = &match transport {
        Transport::Doh | Transport::Dot | Transport::Doq => {
            crate::proto_utils::padded_query(packet)
        }
        Transport::Udp | Transport::Tcp | Transport::TcpUdp => std::borrow::Cow::Borrowed(packet),
    };
    match transport {
        Transport::Udp => {
            let r = Box::pin(forward_udp_smart(engine, packet, addr, timeout_dur, tcp)).await;
            match r {
                Ok((bytes, via)) => (Ok(bytes), via),
                Err(err) => (Err(err), Transport::Udp),
            }
        }
        Transport::Tcp => {
            let sent = sent_if_timed(engine);
            let r = Box::pin(engine.tcp_mux.send(packet, addr, timeout_dur)).await;
            note_round_trip(engine, addr, timeout_dur, sent, &r);
            (r, Transport::Tcp)
        }
        Transport::TcpUdp => {
            // Dual-send: spawn both TCP and UDP concurrently, use first response
            // 双发：同时发送 TCP 和 UDP，使用第一个响应
            match Box::pin(forward_tcp_udp_dual(engine, packet, addr, timeout_dur)).await {
                Ok((bytes, via)) => (Ok(bytes), via),
                Err(e) => (Err(e), Transport::TcpUdp),
            }
        }
        Transport::Doh => {
            let sent = sent_if_timed(engine);
            let r = Box::pin(engine.doh_client.send(packet, addr, timeout_dur)).await;
            note_round_trip(engine, addr, timeout_dur, sent, &r);
            (r, Transport::Doh)
        }
        Transport::Dot => {
            let sent = sent_if_timed(engine);
            let r = Box::pin(engine.dot_mux.send(packet, addr, timeout_dur)).await;
            note_round_trip(engine, addr, timeout_dur, sent, &r);
            (r, Transport::Dot)
        }
        Transport::Doq => {
            let sent = sent_if_timed(engine);
            let r = Box::pin(engine.doq_client.send(packet, addr, timeout_dur)).await;
            note_round_trip(engine, addr, timeout_dur, sent, &r);
            (r, Transport::Doq)
        }
    }
}

/// `传输:地址` 里的传输名：实际带回应答的那种传输；双发失败时记 udp
/// The transport name in `transport:address`: the one that carried the answer; udp for a
/// dual send that failed
fn transport_label(via: Transport) -> &'static str {
    match via {
        Transport::Udp | Transport::TcpUdp => "udp",
        Transport::Tcp => "tcp",
        Transport::Doh => "doh",
        Transport::Dot => "dot",
        Transport::Doq => "doq",
    }
}

/// 上游名字（`udp:1.1.1.1:53`，见 [`upstream_label`]）里的地址：去掉前面的传输名。回答检查拿它和配置里写的
/// 上游地址比（见 `RuntimeResponseMatcher::UpstreamEquals`）。不带传输名的原样返回
/// The address in an upstream's name (`udp:1.1.1.1:53`, see [`upstream_label`]): the name less
/// its transport. The answer check compares it with the upstream addresses a configuration
/// writes (see `RuntimeResponseMatcher::UpstreamEquals`). One without a transport comes back
/// as it is
pub(crate) fn answered_address(label: &str) -> &str {
    ["udp:", "tcp:", "doh:", "dot:", "doq:"]
        .iter()
        .find_map(|transport| label.strip_prefix(transport))
        .unwrap_or(label)
}

/// 记住的上游名字最多这么多个，配置里写不了这么多；再多的现算，不记 / The most upstream names kept,
/// more than a configuration writes; any further are built each time and not kept
const UPSTREAM_LABELS: usize = 4096;

/// 上游在应答记录里的名字（`udp:1.1.1.1:53`）。每个转发回来的应答都带一个，而上游只有配置里那几个，
/// 算过就留着：之后不分配内存，所有应答共用一份。
/// An upstream's name in the records of its answers (`udp:1.1.1.1:53`). Every answer back
/// from a forward carries one and the configuration only has so many upstreams, so each is
/// kept once built: no allocation after that, and all answers share one copy.
fn upstream_label(via: Transport, addr: &str) -> Arc<str> {
    type Labels = dashmap::DashMap<Box<str>, Arc<str>, rustc_hash::FxBuildHasher>;
    static LABELS: std::sync::LazyLock<[Labels; 5]> =
        std::sync::LazyLock::new(|| std::array::from_fn(|_| Labels::default()));
    let labels = &LABELS[match via {
        Transport::Udp | Transport::TcpUdp => 0,
        Transport::Tcp => 1,
        Transport::Doh => 2,
        Transport::Dot => 3,
        Transport::Doq => 4,
    }];
    if let Some(label) = labels.get(addr) {
        return Arc::clone(&label);
    }
    let label: Arc<str> = Arc::from(format!("{}:{addr}", transport_label(via)));
    if labels.len() < UPSTREAM_LABELS {
        labels.insert(addr.into(), Arc::clone(&label));
    }
    label
}

/// 现在发出的一次和上游的收发要量用了多久时，现在这一刻：抽着量（见 `PermitManager::times_this_round_trip`），量到的
/// 定 UDP 什么时候重发，开了流控时也定查询等多久算卡住；启动以后还没等到过回答时每一次都量，头一个回答一来就知道回答要多久，
/// 不用等抽到的那一个——这之前开始等的查询是按上游应当已经回答的时间点算卡住、重发的，洪泛时这一段越短，占着内存等到那个
/// 点的查询越少。和 [`note_round_trip`] 一前一后夹着那次收发，不另包一层：包一层的话收发的状态要整块搬进去，每个查询都跟着
/// 多花时间
/// The present, when the exchange with an upstream being sent now is to be timed: one in so
/// many is (see `PermitManager::times_this_round_trip`), what is timed setting when UDP sends
/// again and, with flow control on, how long a query waits before it counts as stuck; while no
/// answer has been seen since the start every one is timed, so the first answer tells at once
/// how long answers take without waiting for a sampled one: a query that began waiting before
/// then counts as stuck and is sent again by the point an upstream should have answered by, and
/// in a flood the shorter that stretch, the fewer queries hold memory until that point. It and
/// [`note_round_trip`] go either side of the exchange with no wrapper round it: a wrapper would
/// have the exchange's whole state moved into it, costing every query
#[inline]
fn sent_if_timed(engine: &Engine) -> Option<Instant> {
    (crate::engine::PermitManager::times_this_round_trip()
        || !engine.permit_manager.has_seen_an_answer())
    .then(Instant::now)
}

/// 一次和 `upstream`（一个地址）的收发在 `sent` 发出（量了的才有值），现在有了结果 `reply`：收到的是用得上的回答（不是
/// SERVFAIL、REFUSED）就记进这个上游的回答要多久（见 `PermitManager::stuck_after`）。记的是这一次收发自己用了多久，不是
/// 查询一共等了多久：第一次没发到、重发才等到回答的查询，一共等了一个重发的间隔，那不是上游回答要多久。`limit` 是上游
/// 的时限：比它还晚才看到的应答，是按时到了、内核晚了这么久才读到，说明不了上游，不记。内核忙时读得晚一些的照常记：
/// 内核看得到的回答就是这么慢，算卡住的时间得跟着它
/// One exchange with `upstream` (one address), sent at `sent` (which has a value only when it
/// was timed), now has its outcome `reply`: an answer of use (no SERVFAIL or REFUSED) is noted
/// in how long this upstream's answers take (see `PermitManager::stuck_after`). What is noted
/// is how long this one exchange took, not how long the query waited in all: a query whose
/// first try was lost and that got its answer by being sent again waited a resend's interval
/// in all, which is not how long the upstream takes to answer. `limit` is the upstream's
/// timeout: a reply seen later than that came in time and was read late, the kernel being that
/// far behind, which says nothing of the upstream and is not noted. One read somewhat late by
/// a busy kernel is noted as usual: answers are that slow as far as the kernel can see, and
/// the time a query counts as stuck after has to follow
#[inline]
fn note_round_trip(
    engine: &Engine,
    upstream: &str,
    limit: Duration,
    sent: Option<Instant>,
    reply: &anyhow::Result<Bytes>,
) {
    if let (Some(sent), Ok(reply)) = (sent, reply)
        && !is_failure_reply_packet(reply)
    {
        let took = sent.elapsed();
        if took <= limit {
            engine.permit_manager.note_answer_took(upstream, took);
        }
    }
}

/// 上游应当已经回答的时间点，上游时限的三分之一：还没等到过一个上游的回答时，它的 UDP 查询等这么久没有回答就重发，等到过
/// 的也最多等这么久（见 `PermitManager::resend_after`）；开了流控时，查询等这么久还没有回答算卡住（见
/// `PermitManager::stuck_after`）。bootstrap 的查询也这样重发
/// The point by which an upstream should have answered, a third of its timeout: with no answer
/// from an upstream yet, a UDP query to it goes unanswered this long before it is sent again, and
/// with answers seen this long at most (see `PermitManager::resend_after`); with flow control on,
/// a query unanswered this long counts as stuck (see `PermitManager::stuck_after`). Bootstrap's
/// queries are sent again so too
pub(crate) fn hedge_timeout(timeout_dur: Duration) -> Duration {
    timeout_dur / 3
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

/// UDP forwarder with a resend and TCP fallback for better tail latency. Returns the answer
/// with the transport that carried it: UDP, or TCP after a TC-bit retry or a UDP-failure
/// fallback. With no reply by the time this upstream's answers are due (see
/// `PermitManager::resend_after`) the query is sent again, and from then on whichever of the two
/// is answered first is used, for the whole of the timeout: the first copy stays registered, so
/// its reply is taken should it arrive only after the resend (see `UdpExchange`).
/// 带重发和 TCP 回退的 UDP 转发。返回应答和实际带回它的传输：UDP，或 TC/失败回退后的 TCP。过了这个上游该有回答的
/// 时候（见 `PermitManager::resend_after`）还没有回答就把查询再发一次，此后一整个时限里，两份谁的回答先到用谁的：第一份
/// 一直登记着，它的回答在重发以后才到也照样收下（见 `UdpExchange`）。
async fn forward_udp_smart(
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
    let failed = |attempt: u8, waited: Duration, error: &anyhow::Error| {
        debug!(
            event = "udp_forward_retry",
            upstream = %upstream,
            attempt,
            timeout_ms = waited.as_millis() as u64,
            error = %error,
            "udp forward attempt failed",
        );
    };
    // UDP 带回来的应答：截断的改用 TCP 重取，TCP 拿不到完整应答时交回截断的这份，客户端看到 TC 自己会改用 TCP，
    // 和双发一样；别的原样交回。上游的 TCP 被挡住时，大应答照样有截断的这份，不成 SERVFAIL
    // A reply UDP brought back: a truncated one is fetched again over TCP, and when TCP gives no
    // full answer the truncated one goes back, the client turning to TCP itself on seeing TC, as
    // a dual send does; any other goes back as it is. With the upstream's TCP blocked, a large
    // answer still has this truncated one rather than a SERVFAIL
    let answered = async |bytes: Bytes| {
        // RFC 1035: TC (Truncated) flag, read from the header / 从报头读 TC 标志
        if retry_truncated && crate::proto_utils::truncated_response(&bytes) {
            debug!(event = "tc_flag_fallback", upstream = %upstream, "udp response truncated, retrying with tcp");
            return over_tcp(engine, packet, upstream, timeout_dur)
                .await
                .or_else(|error| {
                    debug!(event = "tc_udp_answer_kept", upstream = %upstream, error = %error, "tcp gave no answer, keeping the truncated udp answer");
                    Ok((bytes, Transport::Udp))
                });
        }
        Ok((bytes, Transport::Udp))
    };

    // 第一份等到该有回答的时候（见 `PermitManager::resend_after`），还没有回答就再发一份，两份谁的回答先到用谁的，一直等满
    // 时限（见 `UdpExchange`）；再不行留给 TCP
    // The first copy is waited for until an answer is due (see `PermitManager::resend_after`);
    // with no reply by then another is sent, and whichever of the two is answered first is used,
    // for the whole of the timeout (see `UdpExchange`); failing that, TCP is left
    let first_wait = engine.permit_manager.resend_after(upstream, timeout_dur);
    let mut exchange = UdpExchange::new(&engine.udp_client, packet, upstream);
    for (attempt, wait) in [(1, first_wait), (2, timeout_dur)] {
        if let Err(error) = exchange.send(sent_if_timed(engine)).await {
            failed(attempt, wait, &error);
        }
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            match tokio::time::timeout_at(deadline, exchange.reply()).await {
                Ok(Some((reply, sent))) => {
                    // 上游回答要多久，记的是等到回答的那一份从发出到收到 / How long the upstream
                    // takes is noted from the sending of the copy answered to its reply
                    note_round_trip(engine, upstream, timeout_dur, sent, &reply);
                    match reply {
                        Ok(bytes) => return answered(bytes).await,
                        Err(error) => failed(attempt, wait, &error),
                    }
                }
                // 一份也没在等了 / No copy waited for any more
                Ok(None) => break,
                Err(_) => {
                    failed(attempt, wait, &anyhow::anyhow!("upstream timeout"));
                    break;
                }
            }
        }
    }

    if fallback_on_failure {
        // Both UDP queries failed, try TCP fallback before failing.
        debug!(event = "udp_forward_fallback_tcp", upstream = %upstream, "falling back to tcp");
        return over_tcp(engine, packet, upstream, timeout_dur).await;
    }
    // Every UDP attempt failed and none fell back to TCP: the fallback is off, or the
    // caller tries TCP itself (a dual send, a batch with TCP upstreams)
    // UDP 全部失败，也没有改用 TCP：要么回退关着，要么调用方自己会走 TCP（双发、带 TCP 上游的批次）
    anyhow::bail!("all udp attempts failed")
}

/// UDP 转发改用 TCP 问一次（应答截断了，或者 UDP 没等到回答）。TCP 的收发单独在堆上分配：只有这两种情况才走 TCP，
/// 等 UDP 应答的查询不必为它预留地方
/// One exchange over TCP for a UDP forward (a truncated reply, or no reply over UDP). The TCP
/// exchange is allocated on its own: TCP is only taken in those two cases, so a query waiting
/// on UDP reserves no room for it
async fn over_tcp(
    engine: &Engine,
    packet: &[u8],
    upstream: &str,
    timeout_dur: Duration,
) -> anyhow::Result<(Bytes, Transport)> {
    let sent = sent_if_timed(engine);
    let reply = Box::pin(engine.tcp_mux.send(packet, upstream, timeout_dur)).await;
    note_round_trip(engine, upstream, timeout_dur, sent, &reply);
    reply.map(|bytes| (bytes, Transport::Tcp))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 预热收集请求阶段、命中后和未命中时三类动作里用 TCP（含 tcp_udp）转发的上游，逗号分开的各算
    /// 一个，去掉协议前缀；UDP 的不算。只写了 `tcp://` 前缀、没写 `transport` 的也走 TCP，也算：以前只看
    /// `transport`，它们不预热。没写上游、经 TCP 转发的是经 TCP 问默认上游，也算：以前只看写了的上游
    /// Warm-up collects the upstreams forwarded to over TCP (tcp_udp included) by the
    /// request-phase, on-match and on-miss actions, each of a comma-separated list on its
    /// own, protocol prefix removed; UDP ones do not count. One written with a `tcp://`
    /// prefix and no `transport` goes over TCP and counts too: only `transport` used to be
    /// looked at, and such upstreams were not warmed up. A forward over TCP naming no upstream
    /// asks the default one over TCP and counts too: only upstreams written out used to
    #[test]
    fn warm_up_collects_the_tcp_upstreams_of_every_action_phase() {
        let config = crate::matcher::RuntimePipelineConfig::from_config(
            serde_json::from_value(serde_json::json!({
            "settings": { "default_upstream": "127.0.0.1:9" },
            "pipelines": [{ "id": "main", "rules": [{
                "name": "r",
                "matchers": [{ "type": "any" }],
                "actions": [
                    { "type": "forward", "upstream": "192.0.2.1:53, 192.0.2.2:53", "transport": "tcp" },
                    { "type": "forward", "upstream": "192.0.2.9:53", "transport": "udp" },
                    { "type": "forward", "transport": "tcp" }
                ],
                "response_matchers": [{ "type": "upstream_equals", "value": "192.0.2.1:53" }],
                "response_actions_on_match": [
                    { "type": "forward", "upstream": "tcp://192.0.2.3:53", "transport": "tcp_udp" }
                ],
                "response_actions_on_miss": [
                    { "type": "forward", "upstream": "192.0.2.4:53", "transport": "tcp" },
                    { "type": "forward", "upstream": "192.0.2.8:53" },
                    { "type": "forward", "upstream": "tcp://192.0.2.5:53" }
                ]
            }] }]
            }))
            .expect("parse config"),
        )
        .expect("build runtime config");
        let mut upstreams: Vec<String> = tcp_upstreams(&config).into_iter().collect();
        upstreams.sort();
        assert_eq!(
            upstreams,
            [
                "127.0.0.1:9",
                "192.0.2.1:53",
                "192.0.2.2:53",
                "192.0.2.3:53",
                "192.0.2.4:53",
                "192.0.2.5:53"
            ]
        );
    }

    use crate::config::GlobalSettings;
    use crate::matcher::RuntimePipelineConfig;
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};
    use rustc_hash::FxHashMap;
    use rustls::crypto::ring;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};
    use tokio::io::AsyncReadExt;

    /// 上游地址的前缀不分大小写，别的都不认 / An upstream's prefix takes any case, and nothing else
    #[test]
    fn a_scheme_is_read_in_any_case() {
        for (scheme, transport) in [
            ("tcp", Transport::Tcp),
            ("TCP", Transport::Tcp),
            ("udp", Transport::Udp),
            ("Udp", Transport::Udp),
            ("tcp+udp", Transport::TcpUdp),
            ("UDP+tcp", Transport::TcpUdp),
            ("doh", Transport::Doh),
            ("HTTPS", Transport::Doh),
            ("dot", Transport::Dot),
            ("TLS", Transport::Dot),
            ("doq", Transport::Doq),
            ("QuIc", Transport::Doq),
        ] {
            assert_eq!(transport_for_scheme(scheme), Some(transport), "{scheme}");
        }
        for scheme in ["", "tc", "tcpp", "http", "udp+udp", "tc\u{0440}"] {
            assert_eq!(transport_for_scheme(scheme), None, "{scheme}");
        }
    }

    /// 上游的名字算一次，之后所有应答共用；双发算 UDP
    /// An upstream's name is built once and all answers share it; a dual send counts as UDP
    #[test]
    fn an_upstream_name_is_built_once_and_shared() {
        let first = upstream_label(Transport::Udp, "192.0.2.1:53");
        assert_eq!(&*first, "udp:192.0.2.1:53");
        assert!(Arc::ptr_eq(
            &first,
            &upstream_label(Transport::Udp, "192.0.2.1:53")
        ));
        assert!(Arc::ptr_eq(
            &first,
            &upstream_label(Transport::TcpUdp, "192.0.2.1:53")
        ));
        assert_eq!(
            &*upstream_label(Transport::Udp, "192.0.2.2:53"),
            "udp:192.0.2.2:53"
        );
        for (via, label) in [
            (Transport::Tcp, "tcp:192.0.2.1:53"),
            (Transport::Doh, "doh:192.0.2.1:53"),
            (Transport::Dot, "dot:192.0.2.1:53"),
            (Transport::Doq, "doq:192.0.2.1:53"),
        ] {
            assert_eq!(&*upstream_label(via, "192.0.2.1:53"), label);
        }
    }

    /// 记住的名字有上限，再多的现算，名字照样对
    /// The names kept are limited; further ones are built each time, and still right
    #[test]
    fn upstream_names_past_the_limit_are_not_kept() {
        for i in 0..UPSTREAM_LABELS {
            upstream_label(Transport::Doq, &format!("limit-{i}.example"));
        }
        let first = upstream_label(Transport::Doq, "past-the-limit.example");
        let second = upstream_label(Transport::Doq, "past-the-limit.example");
        assert_eq!(&*first, "doq:past-the-limit.example");
        assert_eq!(first, second);
        assert!(!Arc::ptr_eq(&first, &second), "not kept");
    }

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
            warnings: Vec::new(),
        };
        Engine::new(runtime, "test".to_string()).expect("initialize test engine")
    }

    /// 记进回答要多久的只有上游时限以内的应答：比时限还晚才看到的，是内核晚读到的，说明不了上游，不记。CPU 很慢
    /// 又被洪泛占满时，一个晚了八秒才读到的应答要是算数，这以后要等十六秒才算卡住，等于没有这一道
    /// Only a reply within the upstream's timeout is noted in how long answers take: one
    /// seen later than that was read late by the kernel, says nothing of the upstream and
    /// is not noted. On a slow CPU filled by a flood, were a reply read eight seconds late to
    /// count, nothing would count as stuck for sixteen seconds after it, as good as no such
    /// check at all
    #[tokio::test]
    async fn a_reply_seen_later_than_the_upstreams_timeout_is_not_noted() {
        let settings = GlobalSettings {
            default_upstream: "127.0.0.1:0".to_string(),
            flow_control_enabled: true,
            ..GlobalSettings::default()
        };
        let engine = Engine::new(
            RuntimePipelineConfig {
                settings,
                pipeline_select: Vec::new(),
                pipelines: Vec::new(),
                pipeline_id_index: FxHashMap::default(),
                warnings: Vec::new(),
            },
            "test".to_string(),
        )
        .expect("initialize test engine");
        let reply = || {
            let mut reply = Message::new(1, MessageType::Response, OpCode::Query);
            reply.metadata.response_code = ResponseCode::NoError;
            Bytes::from(reply.to_vec().expect("encode reply"))
        };
        let (upstream, limit) = ("198.51.100.1:53", Duration::from_millis(900));
        let stuck_after = || engine.permit_manager.stuck_after(upstream, limit);
        // 每 8 次收发量一次：16 次里一定有量到的 / One exchange in 8 is timed: of 16, some are
        for _ in 0..16 {
            let seen_late = async {
                tokio::time::sleep(Duration::from_millis(60)).await;
                anyhow::Ok(reply())
            };
            let sent = sent_if_timed(&engine);
            let reply = seen_late.await;
            note_round_trip(&engine, upstream, Duration::from_millis(20), sent, &reply);
        }
        assert_eq!(
            stuck_after(),
            hedge_timeout(limit),
            "no answer noted: still by the point an upstream should have answered by"
        );
        // 失败应答也不记：上游自己等不到才放弃的那几秒不是回答要多久 / Nor is a failure reply noted:
        // the seconds an upstream took to give up are not how long answers take
        for _ in 0..16 {
            let failed = async {
                tokio::time::sleep(Duration::from_millis(60)).await;
                let mut reply = Message::new(1, MessageType::Response, OpCode::Query);
                reply.metadata.response_code = ResponseCode::ServFail;
                anyhow::Ok(Bytes::from(reply.to_vec().expect("encode reply")))
            };
            let sent = sent_if_timed(&engine);
            let reply = failed.await;
            note_round_trip(&engine, upstream, limit, sent, &reply);
        }
        assert_eq!(stuck_after(), hedge_timeout(limit), "a failure reply");
        for _ in 0..16 {
            let in_time = async {
                tokio::time::sleep(Duration::from_millis(60)).await;
                anyhow::Ok(reply())
            };
            let sent = sent_if_timed(&engine);
            let reply = in_time.await;
            note_round_trip(&engine, upstream, limit, sent, &reply);
        }
        let after = stuck_after();
        assert!(
            after >= Duration::from_millis(120) && after < Duration::from_millis(300),
            "{after:?}, twice the sixty milliseconds or so the replies took"
        );
    }

    /// 启动以后还没等到过回答时每次收发都量，等到了就抽着量：头一个回答一来就知道回答要多久。开不开流控都量，UDP 什么时候
    /// 重发跟着它
    /// While no answer has been seen since the start every exchange is timed, and one in so
    /// many once one has: the first answer tells at once how long answers take. Timing goes on
    /// with flow control off too, when UDP sends again following it
    #[tokio::test]
    async fn every_exchange_is_timed_until_an_answer_is_seen() {
        let engine = build_test_engine(false);
        assert!((0..64).all(|_| sent_if_timed(&engine).is_some()));
        engine
            .permit_manager
            .note_answer_took("198.51.100.1:53", Duration::from_millis(5));
        let timed = (0..64).filter(|_| sent_if_timed(&engine).is_some()).count();
        assert_eq!(timed, 8, "one in eight once an answer is seen");
    }

    /// 丢了的查询在这个上游该有回答的时候就再发：它还没回答过时按时限的三分之一，回答过了就按它最慢的那些回答，至少 50 毫秒。
    /// 以前一律等三分之一（默认 3 秒）
    /// A lost query is sent again once this upstream's answers are due: by a third of the
    /// timeout while it has not answered yet, by its slowest answers once it has, 50 ms at
    /// least. It used to wait a third every time (3 seconds by default)
    #[tokio::test]
    async fn a_lost_query_is_sent_again_once_the_upstreams_answers_are_due() {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind the upstream");
        let upstream = socket
            .local_addr()
            .expect("read the upstream address")
            .to_string();
        let lose_next = Arc::new(AtomicBool::new(false));
        let losing = Arc::clone(&lose_next);
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
                if losing.swap(false, Ordering::SeqCst) {
                    continue;
                }
                buf[2] |= 0x80;
                let _ = socket.send_to(&buf[..len], peer).await;
            }
        });
        let engine = build_test_engine(false);
        let packet = build_dns_query_packet("example.com");
        let limit = Duration::from_millis(3000);
        let ask = || {
            let tcp = UdpTcpFallback {
                retry_truncated: false,
                on_failure: false,
            };
            forward_udp_smart(&engine, &packet, &upstream, limit, tcp)
        };
        let resend_after = || engine.permit_manager.resend_after(&upstream, limit);
        assert_eq!(
            resend_after(),
            hedge_timeout(limit),
            "no answer from it yet"
        );
        // 收发每 8 次量一次 / One exchange in 8 is timed
        for _ in 0..16 {
            ask().await.expect("answered");
        }
        assert_eq!(resend_after(), Duration::from_millis(50), "quick answers");
        lose_next.store(true, Ordering::SeqCst);
        let started = Instant::now();
        ask().await.expect("answered by the resend");
        let took = started.elapsed();
        assert!(
            took >= Duration::from_millis(50) && took < hedge_timeout(limit),
            "took {took:?}"
        );
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

    /// UDP 应答截断、改用 TCP 却连不上时（上游的 TCP 被挡住了），交回截断的这份：客户端看到 TC 自己会改用 TCP。
    /// 以前整次查询失败，每个大应答都成了 SERVFAIL
    /// With the UDP answer truncated and TCP not reachable (the upstream's TCP blocked), the
    /// truncated answer goes back: the client turns to TCP itself on seeing TC. The whole query
    /// used to fail, every large answer becoming a SERVFAIL
    #[tokio::test]
    async fn a_truncated_answer_is_kept_when_tcp_cannot_fetch_the_full_one() {
        let _ = ring::default_provider().install_default();
        let (udp_socket, tcp_listener, upstream_addr) = bind_udp_and_tcp_on_one_port().await;
        // 这个端口上的 TCP 没人听 / Nobody listens over TCP on this port
        drop(tcp_listener);
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (len, peer) = udp_socket.recv_from(&mut buf).await.expect("udp recv");
            buf[2] = 0x82; // QR=1, TC=1
            buf[3] = 0x00;
            let _ = udp_socket.send_to(&buf[..len], peer).await;
        });
        let engine = build_test_engine(true);
        let packet = build_dns_query_packet("example.com");
        let (reply, via) = forward_udp_smart(
            &engine,
            &packet,
            &upstream_addr.to_string(),
            Duration::from_millis(1000),
            UdpTcpFallback {
                retry_truncated: true,
                on_failure: false,
            },
        )
        .await
        .expect("the truncated answer");
        assert_eq!(via, Transport::Udp);
        assert!(crate::proto_utils::truncated_response(&reply), "TC kept");
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

        let (resp, via) = forward_udp_smart(
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
        assert_eq!(via, Transport::Udp, "the answer came over UDP");

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

    /// 双发的假上游怎样回 / How the dual-send fake upstream answers
    #[derive(Clone, Copy)]
    enum DualLeg {
        /// 隔这么久回完整的应答 / A full answer after this long
        Answer(Duration),
        /// 立刻回一个截断的应答（只有 UDP 用）/ A truncated answer at once (UDP only)
        Truncated,
        /// 不回（UDP），或者不监听、连接被拒（TCP）/ No answer (UDP), or no listener and a refused connection (TCP)
        Absent,
    }

    /// 查询原样回去，置上 QR，`truncated` 时再置上 TC / The query sent back with QR set, and TC when `truncated`
    fn echo_reply(query: &[u8], truncated: bool) -> Vec<u8> {
        let mut reply = query.to_vec();
        reply[2] |= 0x80;
        if truncated {
            reply[2] |= 0x02;
        }
        reply
    }

    /// 同一个端口上的 UDP 和 TCP 假上游，各按 `udp`、`tcp` 回；返回地址
    /// UDP and TCP fake upstreams on one port, answering as `udp` and `tcp` say; returns
    /// the address
    async fn dual_upstream(udp: DualLeg, tcp: DualLeg) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (udp_socket, tcp_listener, addr) = bind_udp_and_tcp_on_one_port().await;
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while let Ok((len, peer)) = udp_socket.recv_from(&mut buf).await {
                let reply = match udp {
                    DualLeg::Answer(delay) => {
                        tokio::time::sleep(delay).await;
                        echo_reply(&buf[..len], false)
                    }
                    DualLeg::Truncated => echo_reply(&buf[..len], true),
                    DualLeg::Absent => continue,
                };
                let _ = udp_socket.send_to(&reply, peer).await;
            }
        });
        match tcp {
            DualLeg::Answer(delay) => {
                tokio::spawn(async move {
                    while let Ok((mut stream, _)) = tcp_listener.accept().await {
                        tokio::spawn(async move {
                            let mut len = [0u8; 2];
                            if stream.read_exact(&mut len).await.is_err() {
                                return;
                            }
                            let mut query = vec![0u8; u16::from_be_bytes(len) as usize];
                            if stream.read_exact(&mut query).await.is_err() {
                                return;
                            }
                            tokio::time::sleep(delay).await;
                            let reply = echo_reply(&query, false);
                            let _ = stream.write_all(&(reply.len() as u16).to_be_bytes()).await;
                            let _ = stream.write_all(&reply).await;
                            let _ = stream.read(&mut [0u8; 1]).await;
                        });
                    }
                });
            }
            DualLeg::Truncated | DualLeg::Absent => drop(tcp_listener),
        }
        addr.to_string()
    }

    /// 双发（tcp+udp）拿回的应答记的是真正带回它的那一路：UDP 截断时等 TCP 的完整应答，UDP 不回时
    /// 用 TCP 的，UDP 先回完整应答时用 UDP 的，TCP 连不上时用 UDP 的
    /// A dual send (tcp+udp) names the leg that really carried the answer: a truncated UDP
    /// answer waits for TCP's full one, TCP's answer counts when UDP gives none, UDP's when
    /// it answers first in full, and UDP's when TCP cannot connect
    #[tokio::test]
    async fn a_dual_send_names_the_leg_that_carried_the_answer() {
        let _ = ring::default_provider().install_default();
        let cases = [
            (
                DualLeg::Truncated,
                DualLeg::Answer(Duration::from_millis(50)),
                Transport::Tcp,
            ),
            (
                DualLeg::Absent,
                DualLeg::Answer(Duration::from_millis(20)),
                Transport::Tcp,
            ),
            (
                DualLeg::Answer(Duration::ZERO),
                DualLeg::Answer(Duration::from_millis(300)),
                Transport::Udp,
            ),
            (
                DualLeg::Answer(Duration::from_millis(100)),
                DualLeg::Absent,
                Transport::Udp,
            ),
        ];
        for (index, (udp, tcp, expected)) in cases.into_iter().enumerate() {
            let engine = build_test_engine(true);
            let addr = dual_upstream(udp, tcp).await;
            let packet = build_dns_query_packet("example.com");
            let (result, via) = send_to_upstream(
                &engine,
                &packet,
                &addr,
                Duration::from_secs(1),
                Transport::TcpUdp,
                UdpTcpFallback {
                    retry_truncated: true,
                    on_failure: true,
                },
            )
            .await;
            let reply = result.unwrap_or_else(|err| panic!("case {index}: {err:#}"));
            assert_eq!(via, expected, "case {index}");
            assert_eq!(
                transport_label(via),
                if expected == Transport::Tcp {
                    "tcp"
                } else {
                    "udp"
                }
            );
            assert_eq!(reply[2] & 0x02, 0, "case {index}: a full answer");
        }
    }

    /// UDP 发了两次都没等到回答，改用 TCP 问到了，带回应答的是 TCP；关着 TCP 重试、或者调用方自己会走 TCP 时不另试，
    /// 算上游失败。开着流控时，TCP 这一次收发的用时也记进「上游回答要多久」
    /// With neither UDP query answered the upstream is asked over TCP, which carries the answer
    /// back; with the TCP retry off, or a caller that takes TCP itself, there is no such try and
    /// the upstream has failed. With flow control on, the exchange over TCP is noted in how long
    /// the upstream takes as well
    #[tokio::test]
    async fn a_udp_upstream_that_does_not_answer_is_asked_over_tcp() {
        let _ = ring::default_provider().install_default();
        // （开没开 TCP 重试，调用方让不让 UDP 失败时试 TCP）/ (whether the TCP retry is on,
        // whether the caller lets a UDP failure try TCP)
        for (enabled, on_failure) in [(true, true), (true, false), (false, true)] {
            let settings = GlobalSettings {
                default_upstream: "127.0.0.1:0".to_string(),
                enable_tcp_fallback: enabled,
                flow_control_enabled: true,
                udp_pool_size: 1,
                tcp_pool_size: 1,
                ..GlobalSettings::default()
            };
            let engine = Engine::new(
                RuntimePipelineConfig {
                    settings,
                    pipeline_select: Vec::new(),
                    pipelines: Vec::new(),
                    pipeline_id_index: FxHashMap::default(),
                    warnings: Vec::new(),
                },
                "test".to_string(),
            )
            .expect("initialize test engine");
            let addr = dual_upstream(DualLeg::Absent, DualLeg::Answer(Duration::ZERO)).await;
            let packet = build_dns_query_packet("example.com");
            let (result, via) = send_to_upstream(
                &engine,
                &packet,
                &addr,
                Duration::from_millis(450),
                Transport::Udp,
                UdpTcpFallback {
                    retry_truncated: true,
                    on_failure,
                },
            )
            .await;
            let over_tcp = enabled && on_failure;
            assert_eq!(result.is_ok(), over_tcp, "{enabled} {on_failure}");
            if over_tcp {
                assert_eq!(via, Transport::Tcp);
            }
            assert_eq!(
                engine.permit_manager.has_seen_an_answer(),
                over_tcp,
                "{enabled} {on_failure}: the exchange over TCP is timed"
            );
        }
    }

    /// 双发的这次转发被放弃时（外层的时限先到、几个上游竞速它输了），它的两路也跟着停：不再重发，不再占着在途的
    /// 条目等到超时。以前两路是各自起的任务，转发被放弃以后没人管它们，UDP 那一路过了三分之一时限照样再发一次
    /// When a dual send's forward is given up (an outer deadline comes first, or it loses a race
    /// between upstreams), its two legs stop with it: no resend, no in-flight entry held until the
    /// timeout. The legs were tasks of their own that nobody looked after once the forward was
    /// given up, and the UDP leg still sent again past a third of the timeout
    #[tokio::test]
    async fn giving_up_a_dual_send_stops_its_legs() {
        let _ = ring::default_provider().install_default();
        let (udp_socket, tcp_listener, addr) = bind_udp_and_tcp_on_one_port().await;
        // TCP 连不上，UDP 收下不回，只数收到几个 / TCP refuses, UDP takes queries without
        // answering and only counts them
        drop(tcp_listener);
        let received = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = Arc::clone(&received);
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while udp_socket.recv_from(&mut buf).await.is_ok() {
                counted.fetch_add(1, Ordering::SeqCst);
            }
        });
        let engine = build_test_engine(true);
        let packet = build_dns_query_packet("example.com");
        let addr = addr.to_string();
        {
            let forward = forward_tcp_udp_dual(&engine, &packet, &addr, Duration::from_millis(600));
            tokio::pin!(forward);
            // 两路都发出去了，转发还在等 / Both legs have sent and the forward still waits
            assert!(
                timeout(Duration::from_millis(60), &mut forward)
                    .await
                    .is_err()
            );
            assert_eq!(received.load(Ordering::SeqCst), 1);
        }
        // 过了三分之一时限（200 毫秒）：放弃了的转发不再重发 / Past a third of the timeout
        // (200 ms): a forward given up does not send again
        tokio::time::sleep(Duration::from_millis(350)).await;
        assert_eq!(
            received.load(Ordering::SeqCst),
            1,
            "no resend after giving up"
        );
    }

    /// UDP 第一次尝试用掉预算的三分之一，过了就再发一次（测试里的「三分之一」都指这个）
    /// A UDP query's first attempt takes a third of the budget and is sent again past it
    /// (what "a third" in the tests refers to)
    #[test]
    fn the_first_udp_attempt_takes_a_third_of_the_budget() {
        assert_eq!(
            hedge_timeout(Duration::from_millis(900)),
            Duration::from_millis(300)
        );
        assert_eq!(
            hedge_timeout(Duration::from_millis(3000)),
            Duration::from_millis(1000)
        );
        assert_eq!(hedge_timeout(Duration::ZERO), Duration::ZERO);
    }
}

#[cfg(test)]
mod refresh_failure_reply_tests {
    use super::{UpstreamFailure, is_failure_reply, reject_failure_reply_on_refresh};
    use crate::engine::core::Engine;

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
        engine_with_pipelines(json!([pipeline]))
    }

    fn engine_with_pipelines(pipelines: Value) -> Engine {
        let raw = json!({
            "settings": {
                "default_upstream": DEAD_UPSTREAM,
                "upstream_timeout_ms": 200,
                "min_ttl": 60
            },
            "pipelines": pipelines
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
                None,
                Some(engine.refresh_of(key)),
                Some(state),
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

    /// `entry` 的应答都经回答检查跳到 `target`，`target` 的规则另带 `target_rules`。跳过去拿到的应答缓存在 `entry` 的键下
    /// Every answer of `entry` jumps to `target` through an answer check, `target`'s rule carrying
    /// `target_rules` besides. The answers got over there are cached under `entry`'s key
    async fn jumping_to(target_upstream: &str, target_rules: Value) -> Engine {
        // 它的任务一直在收发，`Upstream` 丢掉也不停 / Its task keeps answering after the `Upstream` is dropped
        let entry = Upstream::spawn().await.addr;
        let jump = json!({ "response_actions_on_match": [{ "type": "jump_to_pipeline", "pipeline": "target" }] });
        engine_with_pipelines(json!([
            forwarding("entry", &entry, jump),
            forwarding("target", target_upstream, target_rules)
        ]))
    }

    /// 经响应阶段的跳转刷新：跳过去的上游回了失败，刷新以失败结束，条目留着
    /// A refresh through a response-phase jump: the upstream jumped to replies with a failure,
    /// the refresh ends as a failure and the entry stays
    #[tokio::test]
    async fn a_refresh_through_a_jump_keeps_the_entry() {
        let upstream = Upstream::spawn().await;
        let engine = jumping_to(&upstream.addr, json!({})).await;
        let key = cache_key(&engine, "entry");
        let entry = cache_an_answer(&engine, key).await;

        upstream.answer(ResponseCode::ServFail);
        refresh(&engine, key).await;
        assert_still_cached(&engine, key, &entry);
    }

    #[tokio::test]
    async fn a_refresh_through_a_jump_keeps_the_entry_when_a_match_action_forward_answers_servfail()
    {
        let first = Upstream::spawn().await;
        let second = Upstream::spawn().await;
        let on_match = json!({ "response_actions_on_match": forward_to(&second.addr) });
        let engine = jumping_to(&first.addr, on_match).await;
        let key = cache_key(&engine, "entry");
        let entry = cache_an_answer(&engine, key).await;

        second.answer(ResponseCode::ServFail);
        refresh(&engine, key).await;
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
