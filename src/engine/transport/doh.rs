//! DoH（RFC 8484）：握手时选了 h2 的上游直连 HTTP/2（见 `doh_h2`），别的经 reqwest；连续传输错误时重建连接池，回 429
//! 时暂停
//! DoH (RFC 8484): an upstream that picks h2 in the handshake is asked over a direct HTTP/2
//! connection (see `doh_h2`), any other through reqwest; repeated transport errors rebuild the
//! pool, and a 429 pauses the upstream

use super::address::build_doh_url;
use super::connect::{CONNECT_BUDGET, KEEPALIVE_INTERVAL, KEEPALIVE_TIME, build_tls_client_config};
use super::{MAX_DNS_MESSAGE_SIZE, retry_budget};
use crate::engine::bootstrap::{Bootstrap, Resolver};
use crate::engine::doh_h2::{self, H2Link};
use anyhow::Context;
use arc_swap::ArcSwap;
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use dashmap::mapref::entry;
use reqwest::Client as DohHttpClient;
use reqwest::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE, HOST, HeaderValue, RETRY_AFTER};
use rustc_hash::FxBuildHasher;
use rustls::ClientConfig;
#[cfg(test)]
use rustls::RootCertStore;
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;
use tracing::{debug, warn};
use url::Url;
#[cfg(test)]
use webpki_roots::TLS_SERVER_ROOTS;

/// Marker for an answer the server did send but that cannot be used: an HTTP
/// error status, another media type, a body longer than any DNS message, or an
/// answer to another question. The connection itself is healthy, so retrying
/// won't help (only transport-level errors indicate a possibly dead connection).
/// 服务器回了、但用不了的回答的标记：HTTP 错误状态码、别的媒体类型、比任何 DNS 消息都长的正文，或者答的是别的问题。
/// 连接本身正常，重试无益（只有传输层错误才指示连接可能已死）
#[derive(Debug)]
struct DohAnswerError {
    message: String,
    /// 回的是 429 Too Many Requests 时，这个上游因此暂停多久
    /// For a 429 Too Many Requests, how long its upstream is paused because of it
    throttle: Option<Throttle>,
}

impl std::fmt::Display for DohAnswerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for DohAnswerError {}

/// 没连上 DoH 上游：TCP、TLS 或 HTTP/2 握手没成，或者还在建连失败以后的退避里。没有建好的连接可换，重建连接池、
/// 重发都无济于事（见 [`is_transport_error`]）
/// No connection to the DoH upstream: the TCP, TLS or HTTP/2 handshake failed, or a failed
/// connect is still being backed off from. There is no connection made to replace, so neither
/// rebuilding the pool nor sending again helps (see [`is_transport_error`])
#[derive(Debug)]
struct DohNotConnected;

impl std::fmt::Display for DohNotConnected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("no connection to the doh upstream")
    }
}

fn doh_answer_error(message: String) -> anyhow::Error {
    anyhow::Error::new(DohAnswerError {
        message,
        throttle: None,
    })
}

/// 一个 429 让它的上游暂停多久，以及时长是不是照 Retry-After 定的
/// How long a 429 pauses its upstream, and whether Retry-After set the length
#[derive(Debug, Clone, Copy)]
pub(crate) struct Throttle {
    pub(crate) pause: Duration,
    from_retry_after: bool,
}

/// 回了 429 的上游最短、最长暂停的秒数；没带能用的 Retry-After 时取最短的
/// The shortest and longest pause, in seconds, of an upstream that answered 429; the
/// shortest when it gave no usable Retry-After
const DOH_THROTTLE_MIN_SECS: u64 = 1;
const DOH_THROTTLE_MAX_SECS: u64 = 60;

/// 429 回答让上游暂停多久：Retry-After 写的秒数，收进 1 到 60 秒之间；没写、写的是 HTTP 日期或读不懂时
/// 1 秒。数字大得装不下时按最长算：它要的是很久。
/// How long a 429 pauses its upstream: the seconds Retry-After gives, brought into 1 to 60;
/// 1 second without one, or with an HTTP date or anything unreadable. A number too large to
/// hold counts as the longest: what it asks for is a long wait.
fn throttle_after(retry_after: Option<&HeaderValue>) -> Throttle {
    let seconds = retry_after
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .map(|digits| digits.parse::<u64>().unwrap_or(u64::MAX));
    Throttle {
        pause: Duration::from_secs(
            seconds
                .unwrap_or(DOH_THROTTLE_MIN_SECS)
                .clamp(DOH_THROTTLE_MIN_SECS, DOH_THROTTLE_MAX_SECS),
        ),
        from_retry_after: seconds.is_some(),
    }
}

/// 这次失败是上游回了 429 时，它因此暂停多久 / For a failure that was a 429, how long its
/// upstream is paused because of it
pub(crate) fn throttle_of(err: &anyhow::Error) -> Option<Throttle> {
    err.downcast_ref::<DohAnswerError>()
        .and_then(|answer| answer.throttle)
}

/// The media type of DNS messages over HTTPS (RFC 8484 §6)
/// DNS over HTTPS 里 DNS 消息的媒体类型（RFC 8484 第 6 节）
pub(crate) const DOH_MEDIA_TYPE: &str = "application/dns-message";

/// 多久没被用过就算可以清理 / How long an entry must sit unused to be pruned
const DOH_UPSTREAM_IDLE: Duration = Duration::from_secs(600);
/// 两次清理之间的最小间隔 / Shortest gap between two prunes
const DOH_UPSTREAM_PRUNE_EVERY: Duration = Duration::from_secs(60);

/// One DoH upstream's state: its own reqwest client (connection pool), its
/// consecutive transport-error count and its pause after a 429. Rebuilding a pool
/// after repeated failures therefore only evicts that upstream's connections; the
/// other DoH upstreams keep their keep-alive connections.
/// 单个 DoH 上游的状态：独立的 reqwest 客户端（连接池）、连续传输错误计数，以及回了 429 以后的暂停。
/// 连续失败后重建连接池只影响该上游，其它 DoH 上游的 keep-alive 连接不受牵连。
struct DohUpstream {
    /// Hot-swappable reqwest client (its connection pool). Replacing it drops the
    /// old pool, which is the only way to evict half-open/dead connections that
    /// reqwest cannot detect (DoH uses POST, which hyper won't auto-retry).
    /// 可热替换的 reqwest 客户端（其连接池）。替换即丢弃旧池，
    /// 这是清除 reqwest 无法检测的半开/死连接的唯一手段
    /// （DoH 用 POST，hyper 不会自动重试）
    client: ArcSwap<DohHttpClient>,
    /// Consecutive transport errors; cleared by a success or a rebuild.
    /// 连续传输错误数；成功或重建后清零。
    consecutive_errors: AtomicUsize,
    /// 客户端和直连的连接是第几代，重建一次加一。请求记下自己开始时是哪一代，出错时已经换代了就不算（见
    /// [`DohClient::record_error`]）/ Which generation the client and the direct connections are,
    /// raised by each rebuild. A request notes the generation it started under, and an error
    /// found once it has changed does not count (see [`DohClient::record_error`])
    generation: AtomicU64,
    /// 最近一次使用的时刻（从 `DohClient::epoch` 起算的毫秒数），用于清理热重载换掉的旧上游
    /// When the entry was last used (in milliseconds from `DohClient::epoch`), so upstreams
    /// dropped by a reload can be pruned
    last_used_millis: AtomicU64,
    /// 回了 429 以后暂停到什么时候，从 `DohClient::epoch` 起算的毫秒数；没暂停过是 0
    /// Until when a 429 paused it, in milliseconds from `DohClient::epoch`; 0 if it never was
    paused_until: AtomicU64,
    /// 请求发往哪里（见 [`DohTarget`]）：建这个上游的状态时算好，reqwest 客户端也按它建
    /// Where requests go (see [`DohTarget`]): worked out when this upstream's state is made, and
    /// the reqwest client is built for it
    target: DohTarget,
    /// 握手时选了 h2 时直连用的 HTTP/2 连接（见 `doh_h2`）/ The HTTP/2 connection used directly when the upstream picked h2 in the handshake (see `doh_h2`)
    h2: H2Link,
}

/// 一个 DoH 上游的请求发往哪里：URL、覆盖的 Host（见 [`build_doh_url`]），以及直连 HTTP/2 的请求 URI
/// Where a DoH upstream's requests go: the URL, the Host override (see [`build_doh_url`]), and
/// the request URI of the direct HTTP/2 connection
struct DohTarget {
    url: Url,
    host_override: Option<String>,
    /// URL 本身，有覆盖的 Host 时 authority 换成它：HTTP/2 的请求只在 :authority 里说 authority，不许再带一个和它不同的
    /// Host 头（RFC 9113 §8.3.1）。连接和 TLS 照旧按 URL 来。转不成 Uri 的只走 reqwest
    /// The URL, its authority replaced by the Host override when there is one: an HTTP/2 request
    /// gives its authority in :authority alone and may not carry a Host header differing from it
    /// (RFC 9113 §8.3.1). The connection and TLS still follow the URL. One that does not convert
    /// to a Uri goes through reqwest only
    uri: Option<hyper::Uri>,
}

impl DohTarget {
    /// `upstream` 的请求发往哪里；写错的 URL 每次都报同样的错 / Where `upstream`'s requests go; a
    /// malformed URL gives the same error each time
    fn new(upstream: &str) -> anyhow::Result<Self> {
        let (url, host_override) = build_doh_url(upstream)?;
        let uri = request_uri(&url, host_override.as_deref());
        Ok(Self {
            url,
            host_override,
            uri,
        })
    }
}

/// 直连 HTTP/2 的请求 URI（见 [`DohTarget::uri`]）/ The request URI of the direct HTTP/2
/// connection (see [`DohTarget::uri`])
fn request_uri(url: &Url, host_override: Option<&str>) -> Option<hyper::Uri> {
    let mut parts = hyper::Uri::try_from(url.as_str()).ok()?.into_parts();
    if let Some(host) = host_override {
        parts.authority = Some(host.parse().ok()?);
    }
    hyper::Uri::from_parts(parts).ok()
}

pub struct DohClient {
    /// Per-upstream state, created the first time an upstream is used.
    /// 按上游划分的状态，首次使用该上游时创建。
    upstreams: DashMap<Arc<str>, Arc<DohUpstream>, FxBuildHasher>,
    pool_max_idle_per_host: usize,
    /// Threshold of consecutive transport errors that triggers a pool rebuild.
    /// 触发连接池重建的连续传输错误阈值
    health_error_threshold: usize,
    /// 上次清理空闲上游的时刻（从 `epoch` 起算的毫秒数）/ When idle upstreams were last pruned (in
    /// milliseconds from `epoch`)
    last_prune_millis: AtomicU64,
    /// 暂停时刻、清理时刻的起点。用单调时钟，调系统时间不会让它们变长或变短
    /// The origin of pause deadlines and of pruning times. A monotonic clock, so setting the
    /// system time makes none of them longer or shorter
    epoch: std::time::Instant,
    /// 所有上游里最晚的暂停结束时刻（同样从 `epoch` 起算），过了就清回 0。合并转发先看它：
    /// 没有上游在暂停时，判断只花这一次读取
    /// The latest pause end over all upstreams (from `epoch` too), cleared back to 0 once
    /// past. A merged forward looks at it first: with no upstream paused, the check costs
    /// this one load
    latest_pause_end: AtomicU64,
    /// 直连 HTTP/2 用的 TLS 设置：握手时报 h2 和 http/1.1 / The TLS settings of the direct HTTP/2 connection: h2 and http/1.1 offered in the handshake
    tls_h2: Arc<ClientConfig>,
    /// 上游的主机名怎样解析（见 [`Bootstrap`]），直连和 reqwest 都用它 / How upstream host names are
    /// resolved (see [`Bootstrap`]), by the direct connection and reqwest alike
    resolver: Resolver,
    /// 握手时选了 h2 的上游是否直连：设了代理环境变量时不直连，全部照旧交给 reqwest（见 `doh_h2::proxy_configured`）
    /// Whether an upstream that picked h2 is connected to directly: not with a proxy
    /// environment variable set, when everything goes to reqwest as before (see `doh_h2::proxy_configured`)
    direct_h2: bool,
    /// 连接空闲多久就关掉（见 `doh_h2::DOH_IDLE_TIMEOUT`），直连和 reqwest 都是，测试里可以改短
    /// How long a connection may sit idle before it is closed (see `doh_h2::DOH_IDLE_TIMEOUT`),
    /// direct and through reqwest alike, shorter in some tests
    idle_timeout: Duration,
    /// 每个上游最多几条直连：每个工作线程一条，平常只用一条（见 `doh_h2::BUSY_AT`）
    /// How many direct connections an upstream may have at most: one per worker thread, with
    /// one normally in use (see `doh_h2::BUSY_AT`)
    direct_connections: usize,
    /// 测试里改走明文 http，经 reqwest：引擎把 DoH 上游一律当 https，本机的假 DoH 上游只会说 http，直连只说 https
    /// Plain http in tests, through reqwest: the engine takes every DoH upstream as https, the
    /// local fake DoH upstream speaks http only, and the direct connection https only
    #[cfg(test)]
    plain_http: AtomicBool,
    /// 测试里另外信任的证书，直连和 reqwest 都认 / Certificates also trusted in tests, by the direct connection and reqwest alike
    #[cfg(test)]
    test_roots: Vec<rustls::pki_types::CertificateDer<'static>>,
}

impl DohClient {
    pub fn new(
        pool_max_idle_per_host: usize,
        health_error_threshold: usize,
        bootstrap: Arc<Bootstrap>,
    ) -> anyhow::Result<Self> {
        let resolver = Resolver::new(bootstrap, doh_h2::proxy_hosts());
        Ok(Self {
            upstreams: DashMap::with_hasher(FxBuildHasher),
            pool_max_idle_per_host,
            health_error_threshold,
            last_prune_millis: AtomicU64::new(0),
            epoch: std::time::Instant::now(),
            latest_pause_end: AtomicU64::new(0),
            tls_h2: direct_tls_config(build_tls_client_config()?),
            resolver,
            direct_h2: !doh_h2::proxy_configured(),
            idle_timeout: doh_h2::DOH_IDLE_TIMEOUT,
            direct_connections: tokio::runtime::Handle::try_current()
                .map_or(1, |runtime| runtime.metrics().num_workers()),
            #[cfg(test)]
            plain_http: AtomicBool::new(false),
            #[cfg(test)]
            test_roots: Vec::new(),
        })
    }

    /// 测试里另外信任 `cert`：之后建的直连和 reqwest 客户端都认它 / In tests, also trust `cert`: the direct connections and reqwest clients built after accept it
    #[cfg(test)]
    pub(crate) fn trust_for_tests(&mut self, cert: rustls::pki_types::CertificateDer<'static>) {
        let mut roots = RootCertStore::empty();
        roots.extend(TLS_SERVER_ROOTS.iter().cloned());
        self.test_roots.push(cert);
        for root in &self.test_roots {
            roots.add(root.clone()).expect("test root");
        }
        self.tls_h2 = direct_tls_config(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
    }

    /// 测试里看 `upstream` 现在是不是经直连的 HTTP/2 连接问的 / In tests, whether `upstream` is asked over the direct HTTP/2 connection now
    #[cfg(test)]
    pub(crate) fn has_direct_connection(&self, upstream: &str) -> bool {
        self.upstreams
            .get(upstream)
            .is_some_and(|state| state.h2.is_connected())
    }

    /// 测试里看 `upstream` 的连接池重建过几次 / In tests, how many times `upstream`'s pool has been rebuilt
    #[cfg(test)]
    pub(crate) fn rebuilds(&self, upstream: &str) -> u64 {
        self.upstreams
            .get(upstream)
            .map_or(0, |state| state.generation.load(Ordering::Acquire))
    }

    /// 测试里改短连接的空闲时限 / In tests, shorten how long a connection may sit idle
    #[cfg(test)]
    pub(crate) fn set_idle_timeout_for_tests(&mut self, idle: Duration) {
        self.idle_timeout = idle;
    }

    /// 测试里定每个上游最多几条直连 / In tests, set how many direct connections an upstream may have
    #[cfg(test)]
    pub(crate) fn set_direct_connections_for_tests(&mut self, connections: usize) {
        self.direct_connections = connections;
    }

    /// 测试里看 `upstream` 的直连上还有几个请求没答完 / In tests, how many requests are unanswered on `upstream`'s direct connections
    #[cfg(test)]
    pub(crate) fn direct_in_flight(&self, upstream: &str) -> usize {
        self.upstreams
            .get(upstream)
            .map_or(0, |state| state.h2.in_flight())
    }

    /// 测试里关掉直连，全部走 reqwest，和设了代理时一样 / In tests, turn the direct connection off so everything goes through reqwest, as with a proxy set
    #[cfg(test)]
    pub(crate) fn reqwest_only_for_tests(&mut self) {
        self.direct_h2 = false;
    }

    /// 之后的请求都走明文 http（见 `plain_http`）/ Later requests go over plain http (see `plain_http`)
    #[cfg(test)]
    pub(crate) fn use_plain_http(&self) {
        self.plain_http.store(true, Ordering::Relaxed);
    }

    #[cfg(test)]
    fn scheme_for_tests(&self, mut url: Url) -> Url {
        if self.plain_http.load(Ordering::Relaxed) {
            let _ = url.set_scheme("http");
        }
        url
    }

    /// Build a fresh reqwest client for `target`. Used for both initial construction and pool
    /// rebuilds (the latter evicts dead/half-open connections).
    /// 为 `target` 构建新的 reqwest 客户端，用于初始构造和连接池重建（后者驱逐死/半开连接）
    ///
    /// reqwest 说 HTTP/2 时 :authority 只取自 URL，覆盖的 Host 只能另作一个和它不同的 Host 头，RFC 9113 §8.3.1 不许；
    /// 所以有覆盖的上游经 reqwest 时只说 HTTP/1.1，HTTP/2 交给直连（见 [`DohTarget::uri`]）
    /// Under HTTP/2 reqwest takes :authority from the URL alone, so a Host override could only go
    /// as a Host header differing from it, which RFC 9113 §8.3.1 forbids; an upstream with an
    /// override therefore speaks only HTTP/1.1 through reqwest, HTTP/2 being left to the direct
    /// connection (see [`DohTarget::uri`])
    fn build_client(&self, target: &DohTarget) -> anyhow::Result<DohHttpClient> {
        let builder = DohHttpClient::builder();
        let builder = if target.host_override.is_some() {
            builder.http1_only()
        } else {
            builder
        };
        #[cfg(test)]
        let builder = self.test_roots.iter().fold(builder, |builder, root| {
            builder.add_root_certificate(reqwest::Certificate::from_der(root).expect("test root"))
        });
        builder
            // A DoH server has no reason to redirect, and following one could send
            // the query elsewhere, plain HTTP included; a 3xx fails like any other
            // non-success status
            // DoH 服务器没有理由跳转，跟着跳可能把查询发到别处，包括明文 HTTP；3xx 和别的非成功状态一样算失败
            .redirect(reqwest::redirect::Policy::none())
            .dns_resolver(Arc::new(self.resolver.clone()))
            // 建连和直连一样最多 CONNECT_BUDGET（解析名字、TCP 和 TLS 握手都算）：握手卡住的到时报建连错误，算没连上，
            // 不当成在建好的连接上超时（见 [`is_transport_error`]）
            // A connect takes CONNECT_BUDGET at most as a direct one does (resolving the name and
            // the TCP and TLS handshakes all count): a handshake stuck reports a connect error by
            // then, which is no connection, not a timeout on a connection made (see
            // [`is_transport_error`])
            .connect_timeout(CONNECT_BUDGET)
            // HTTP/2 的窗口和直连的一样，理由见 `doh_h2::CONNECTION_WINDOW` / The HTTP/2 windows of the
            // direct connection, for the reasons given at `doh_h2::CONNECTION_WINDOW`
            .http2_initial_stream_window_size(MAX_DNS_MESSAGE_SIZE as u32)
            .http2_initial_connection_window_size(doh_h2::CONNECTION_WINDOW)
            .pool_idle_timeout(self.idle_timeout)
            .pool_max_idle_per_host(self.pool_max_idle_per_host.max(1))
            // 和别的 TCP 连接一样保活，探多少次由系统定 / Kept alive as every other TCP connection is,
            // as many probes as the system sets
            .tcp_keepalive(KEEPALIVE_TIME)
            .tcp_keepalive_interval(KEEPALIVE_INTERVAL)
            .tcp_keepalive_retries(None)
            .build()
            .context("build doh http client")
    }

    /// State for `upstream`, built on first sight. One map read per query on
    /// the hot path; the key is allocated once per upstream.
    /// `upstream` 的状态，首次遇到时创建。热路径每查询一次 map 读取；key 每个上游只分配一次。
    fn upstream(&self, upstream: &str) -> anyhow::Result<Arc<DohUpstream>> {
        self.upstream_at(upstream, self.millis_since_epoch())
    }

    /// [`Self::upstream`]，现在是 `now`（从 `epoch` 起算的毫秒数）/ [`Self::upstream`] with the time now
    /// at `now` (in milliseconds from `epoch`)
    fn upstream_at(&self, upstream: &str, now: u64) -> anyhow::Result<Arc<DohUpstream>> {
        let state = self.lookup_or_create(upstream, now)?;
        // 清理放在查表之后：此刻没有持有任何分片守卫，retain 不会和自己抢锁。
        // Prune after the lookup: no shard guard is held here, so retain cannot
        // contend with this very call.
        self.prune_idle_upstreams(now);
        Ok(state)
    }

    fn lookup_or_create(&self, upstream: &str, now: u64) -> anyhow::Result<Arc<DohUpstream>> {
        if let Some(state) = self.upstreams.get(upstream) {
            state.last_used_millis.store(now, Ordering::Relaxed);
            return Ok(Arc::clone(&state));
        }
        match self.upstreams.entry(Arc::from(upstream)) {
            entry::Entry::Occupied(existing) => {
                existing
                    .get()
                    .last_used_millis
                    .store(now, Ordering::Relaxed);
                Ok(Arc::clone(existing.get()))
            }
            entry::Entry::Vacant(slot) => {
                let target = DohTarget::new(upstream)?;
                let state = Arc::new(DohUpstream {
                    client: ArcSwap::from_pointee(self.build_client(&target)?),
                    consecutive_errors: AtomicUsize::new(0),
                    generation: AtomicU64::new(0),
                    last_used_millis: AtomicU64::new(now),
                    paused_until: AtomicU64::new(0),
                    target,
                    h2: H2Link::new(self.idle_timeout, self.direct_connections),
                });
                slot.insert(Arc::clone(&state));
                Ok(state)
            }
        }
    }

    /// 清理长期不用的上游条目，让热重载换掉的上游不会一直占着连接池
    /// Drop entries nothing has used for a while, so upstreams a reload replaced
    /// do not keep their connection pools for the life of the process
    ///
    /// 每次查表之后都会调用，但受时间间隔节流：一次热重载换掉整批上游、之后再没有
    /// 新上游出现时，旧条目同样会在下一个间隔被清掉，不必等下一次新键插入。
    /// Called after every lookup but throttled by time: when a reload swaps the
    /// whole set of upstreams and no new one ever appears again, the old entries
    /// still go at the next interval instead of waiting for another new key.
    fn prune_idle_upstreams(&self, now: u64) {
        // 节流窗口没到时，这个函数只花一次 relaxed 读就返回；每次查询本身仍有
        // 一次取时钟和一次查表，那是 upstream() 的固有代价。
        // Inside the throttle window this function costs one relaxed load and
        // returns. The per-query clock read and table lookup belong to
        // upstream() itself and are unchanged.
        let last_prune = self.last_prune_millis.load(Ordering::Relaxed);
        let prune_every = u64::try_from(DOH_UPSTREAM_PRUNE_EVERY.as_millis()).unwrap_or(u64::MAX);
        if now.saturating_sub(last_prune) < prune_every {
            return;
        }
        // 先占下这一轮：CAS 成功的调用者负责扫描，其它调用者立刻返回。时间戳在扫描之前就推后，所以无论这轮删没删掉东西，
        // 热路径都要再等一个间隔才会走到这里，不会每个查询都去数一遍条目（DashMap::len() 逐分片取读锁）
        // Claim the round first: the caller that wins the CAS does the scan and the others
        // return. The timestamp moves before the scan, so whether or not this round drops
        // anything the hot path waits another interval to get here, and no lookup counts the
        // entries (a DashMap::len() takes a read lock on every shard)
        if self
            .last_prune_millis
            .compare_exchange(last_prune, now, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let idle_millis = u64::try_from(DOH_UPSTREAM_IDLE.as_millis()).unwrap_or(u64::MAX);
        self.upstreams.retain(|_, state| {
            now.saturating_sub(state.last_used_millis.load(Ordering::Relaxed)) < idle_millis
        });
    }

    pub async fn send(
        &self,
        packet: &[u8],
        upstream: &str,
        timeout_dur: Duration,
    ) -> anyhow::Result<Bytes> {
        let state = self.upstream(upstream)?;
        let target = &state.target;
        let url = &target.url;
        #[cfg(test)]
        let url = &self.scheme_for_tests(url.clone());
        let host = target.host_override.as_deref();
        // 握手时选了 h2 的上游直连（见 `doh_h2`）；设了代理时经 reqwest
        // An upstream that picks h2 in the handshake is connected to directly (see `doh_h2`);
        // with a proxy set it goes through reqwest
        let uri = target.uri.as_ref().filter(|_| self.direct_h2);
        #[cfg(test)]
        let uri = uri.filter(|_| !self.plain_http.load(Ordering::Relaxed));

        let start = tokio::time::Instant::now();
        let generation = state.generation.load(Ordering::Acquire);
        let mut result = self
            .send_once(&state, packet, url, uri, host, timeout_dur)
            .await;
        if let Err(err) = &result
            && is_transport_error(err)
        {
            // 透明重试：DNS 查询语义幂等，单次重试安全。record_error() 可能先重建连接池，重试时就用新客户端（新连接）
            // Transparent retry: DNS queries are semantically idempotent, so a single retry is
            // safe. record_error() may rebuild the pool first, the retry then using the fresh
            // client (new connections)
            let rebuilt = self.record_error(upstream, &state, generation);
            if let Some(remaining) = retry_budget(timeout_dur, start) {
                debug!(
                    upstream = upstream,
                    error = %err,
                    pool_rebuilt = rebuilt,
                    retry_timeout_ms = remaining.as_millis() as u64,
                    "DoH transport error, performing transparent retry"
                );
                result = self
                    .send_once(&state, packet, url, uri, host, remaining)
                    .await;
            }
        }
        match &result {
            // 答上了，第一次就答上还是重试才答上都一样：连续错误数清零。服务器关掉空闲的连接、GOAWAY 赶上请求，都是第一次
            // 失败、重试答上，这样的不该一次次攒到重建
            // Answered, whether at once or by the retry: the errors in a row are cleared. A server
            // closing an idle connection, or a GOAWAY crossing a request, fails the first send and
            // has the retry answered, which must not add up to a rebuild
            Ok(_) => state.consecutive_errors.store(0, Ordering::Release),
            // 429，不管是第一次还是重试时回的：这个上游暂停一会儿
            // A 429, whether to the first send or to the retry: the upstream pauses for a while
            Err(err) => {
                if let Some(throttle) = throttle_of(err) {
                    self.pause(upstream, &state, throttle);
                }
            }
        }
        result.map(|bytes| restore_query_id(packet, bytes))
    }

    /// 从 `epoch` 到现在的毫秒数 / Milliseconds from `epoch` to now
    fn millis_since_epoch(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// `upstream` 回了 429：从现在起暂停 `throttle.pause`。同时回来的几个 429 只把结束时刻往后推，
    /// 不往前拉。暂停开始时记一条 warn，暂停中再回 429 只记 debug。
    /// `upstream` answered 429: it pauses for `throttle.pause` from now. Several 429s at once
    /// only move the end later, never earlier. A pause starting logs one warn; another 429
    /// during the pause logs at debug only.
    fn pause(&self, upstream: &str, state: &DohUpstream, throttle: Throttle) {
        let now = self.millis_since_epoch();
        let until =
            now.saturating_add(u64::try_from(throttle.pause.as_millis()).unwrap_or(u64::MAX));
        let previous = state.paused_until.fetch_max(until, Ordering::Relaxed);
        self.latest_pause_end.fetch_max(until, Ordering::Relaxed);
        if previous <= now {
            warn!(
                upstream = upstream,
                pause_secs = throttle.pause.as_secs(),
                retry_after = throttle.from_retry_after,
                "DoH upstream answered 429 Too Many Requests, leaving it out of forwards with other upstreams for a while"
            );
        } else {
            debug!(
                upstream = upstream,
                pause_secs = throttle.pause.as_secs(),
                retry_after = throttle.from_retry_after,
                "DoH upstream answered 429 Too Many Requests again while paused"
            );
        }
    }

    /// 有没有哪个 DoH 上游正在暂停。通常没有，这时只花一次原子读取
    /// Whether any DoH upstream is paused. Usually none is, and then this costs one atomic load
    pub(crate) fn any_paused(&self) -> bool {
        let latest = self.latest_pause_end.load(Ordering::Relaxed);
        if latest == 0 {
            return false;
        }
        if self.millis_since_epoch() < latest {
            return true;
        }
        // 全都过了：清回 0，之后连时钟都不用读。这期间又有上游暂停时，它的结束时刻比 latest 晚，
        // 交换失败，照样留着
        // All of them are over: back to 0, so later checks read no clock either. An upstream
        // paused meanwhile ends after latest, so the exchange fails and that pause stays
        let _ =
            self.latest_pause_end
                .compare_exchange(latest, 0, Ordering::Relaxed, Ordering::Relaxed);
        false
    }

    /// `upstream` 回了 429、此刻还在暂停 / `upstream` answered 429 and is still paused
    pub(crate) fn is_paused(&self, upstream: &str) -> bool {
        self.upstreams.get(upstream).is_some_and(|state| {
            state.paused_until.load(Ordering::Relaxed) > self.millis_since_epoch()
        })
    }

    /// 问一次，最多 `timeout_dur`：握手时选了 h2 的上游先等直连的连接，再在上面发请求、读回答；别的经 reqwest。等连接用掉的
    /// 时间算在这一次里，等不到算没连上（见 [`DohNotConnected`]）：握手慢说明不了哪条建好的连接坏了。连上以后请求本身超时
    /// 才是传输错误，可以重试（见 [`is_transport_error`]）；正文迟迟不来也算在这个时限里。经 reqwest 的看不到建连和请求
    /// 的分界：建连到 [`CONNECT_BUDGET`] 报建连错误，算没连上，比它短的时限在建连时到了只能算超时
    /// Asks once, within `timeout_dur`: an upstream that picked h2 first waits for its direct
    /// connection, then sends the request on it and reads the answer; any other goes through
    /// reqwest. The wait for the connection counts against this one budget, and running out there
    /// is no connection (see [`DohNotConnected`]): a slow handshake says nothing of a connection
    /// made being broken. Once connected, the request itself timing out is a transport error,
    /// open to a retry (see [`is_transport_error`]); a body slow to come counts against the same
    /// limit. Through reqwest the line between connecting and the request is not seen: a connect
    /// reports a connect error at [`CONNECT_BUDGET`], which is no connection, while a limit
    /// shorter than that running out during the connect can only be a timeout
    async fn send_once(
        &self,
        state: &DohUpstream,
        packet: &[u8],
        url: &Url,
        uri: Option<&hyper::Uri>,
        host_override: Option<&str>,
        timeout_dur: Duration,
    ) -> anyhow::Result<Bytes> {
        let deadline = tokio::time::Instant::now() + timeout_dur;
        let direct = match uri {
            Some(uri) => {
                let connected = tokio::time::timeout_at(
                    deadline,
                    state
                        .h2
                        .sender(url, &self.tls_h2, &self.resolver.bootstrap, deadline),
                )
                .await
                .unwrap_or_else(|_| {
                    Err(anyhow::anyhow!(
                        "doh connect timeout after {}ms",
                        timeout_dur.as_millis()
                    ))
                })
                .context(DohNotConnected)?;
                connected.map(|sender| (uri, sender))
            }
            None => None,
        };
        let answered = tokio::time::timeout_at(deadline, async {
            // 握手时选了 h2 的上游直接经 h2 发，请求和 reqwest 经 HTTP/2 发的一样：同样的方法、地址和头。覆盖的 Host
            // 就是 :authority，不另带 Host 头（见 [`DohTarget::uri`]）。content-length 是 hyper 和 reqwest 自己补的，h2 不补
            // An upstream that picked h2 is asked straight through h2, with the request reqwest
            // would send over HTTP/2: the same method, address and headers. A Host override is the
            // :authority, with no Host header (see [`DohTarget::uri`]). hyper and reqwest add
            // content-length themselves, h2 does not
            if let Some((uri, (sender, _in_flight))) = direct {
                let request = hyper::Request::post(uri.clone())
                    .header(ACCEPT, DOH_MEDIA_TYPE)
                    .header(CONTENT_TYPE, DOH_MEDIA_TYPE)
                    .header(CONTENT_LENGTH, packet.len())
                    .body(())
                    .context("build doh request")?;
                let resp = doh_h2::send(sender, request, Bytes::copy_from_slice(packet))
                    .await
                    .context("doh request send failed")?;
                return doh_answer(packet, resp).await;
            }

            // load_full() 给出自己拿着的 Arc<Client>，跨 await 也是 Send（ArcSwap 的 Guard 不是）
            // load_full() gives an Arc<Client> of its own, Send across awaits (an ArcSwap Guard is not)
            let client = state.client.load_full();
            let mut req = client
                .post(url.clone())
                .header(ACCEPT, DOH_MEDIA_TYPE)
                .header(CONTENT_TYPE, DOH_MEDIA_TYPE)
                .body(packet.to_vec());
            if let Some(host) = host_override {
                req = req.header(HOST, host);
            }
            let resp = req.send().await.context("doh request send failed")?;
            doh_answer(packet, hyper::Response::from(resp)).await
        })
        .await;
        // 内层的错误照原样交出：发送、IO、正文出错可以重试，DohAnswerError、DohNotConnected 不行
        // Inner errors go out as they are: send, IO and body errors can be retried, a
        // DohAnswerError or DohNotConnected cannot
        answered.map_err(|_elapsed| anyhow::anyhow!("doh request timeout"))?
    }

    /// 记下 `upstream` 一个传输错误，出错的请求是在第 `generation` 代开始的。连续错误数到了阈值就换一代：清掉直连的
    /// 连接，重建 reqwest 客户端（丢掉它的连接池），计数清零。换了代返回 true。同一批断掉的请求一起报错时只换一次：换代
    /// 用比较交换，只有一个请求换得成；已经换过代以后，旧连接上迟到的错误不算。一百个在途请求一起超时也只重建一次，
    /// 不会把重试刚连上的新连接一次次拆掉
    /// Records a transport error of `upstream`, from a request started under generation
    /// `generation`. Once errors in a row reach the threshold the generation moves on: the direct
    /// connections are dropped, the reqwest client rebuilt (dropping its pool), and the count
    /// cleared; true when it moved on. Requests broken together, erring together, move it once:
    /// the move is a compare-and-swap only one of them wins, and once it has moved, errors
    /// arriving late from the old connections do not count. A hundred requests in flight timing
    /// out together rebuild once, never tearing down again and again the connections the retries
    /// have just made
    fn record_error(&self, upstream: &str, state: &DohUpstream, generation: u64) -> bool {
        if state.generation.load(Ordering::Acquire) != generation {
            return false;
        }
        let count = state.consecutive_errors.fetch_add(1, Ordering::AcqRel) + 1;
        if self.health_error_threshold == 0
            || count < self.health_error_threshold
            || state
                .generation
                .compare_exchange(
                    generation,
                    generation + 1,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
        {
            debug!(
                upstream = upstream,
                consecutive_errors = count,
                threshold = self.health_error_threshold,
                "DoH transport error recorded"
            );
            return false;
        }
        state.consecutive_errors.store(0, Ordering::Release);
        // 直连的连接一起丢掉，下一个请求重新连 / The direct connections go too, and the next request connects again
        state.h2.reset();
        match self.build_client(&state.target) {
            // 旧池在持有 Arc 副本的在途请求结束后释放 / The old pool is released once the requests in
            // flight holding a clone of its Arc finish
            Ok(new_client) => state.client.store(Arc::new(new_client)),
            Err(e) => {
                warn!(upstream = upstream, error = %e, "failed to rebuild DoH client, keeping old pool")
            }
        }
        crate::warn_sparse!(
            per upstream;
            event = "doh_pool_rebuilt",
            upstream = upstream,
            consecutive_errors = count,
            threshold = self.health_error_threshold,
            "DoH error threshold exceeded, rebuilding connection pool"
        );
        true
    }

    /// [`Self::record_error`] for `upstream` by its name / 按名字找到 `upstream` 再 [`Self::record_error`]
    #[cfg(test)]
    pub(crate) fn record_error_of(&self, upstream: &str) -> bool {
        let state = self.upstream(upstream).expect("doh upstream state");
        let generation = state.generation.load(Ordering::Acquire);
        self.record_error(upstream, &state, generation)
    }

    /// Clear the consecutive error counter of `upstream` (what a successful
    /// send does inline). / 清零 `upstream` 的连续错误计数（成功发送时内联完成）。
    #[cfg(test)]
    fn record_success(&self, upstream: &str) {
        if let Some(state) = self.upstreams.get(upstream) {
            state.consecutive_errors.store(0, Ordering::Release);
        }
    }
}

/// Puts the query's message ID back on a DoH response. HTTP pairs each request with its
/// response, so the ID carries no meaning over DoH (RFC 8484 §4.1) and some servers answer
/// with 0 whatever was sent. Every other transport restores the original ID before the
/// response reaches the engine; without this the client would get a reply whose ID does
/// not match its query and discard it.
/// 把查询原来的消息 ID 换回 DoH 响应。HTTP 已经把请求和响应一一配对，DoH 上的 ID 没有
/// 意义（RFC 8484 §4.1），有的服务端不管收到什么都回 0。其他传输在响应交给引擎之前都会
/// 恢复原 ID；不在这里换回，客户端收到的响应 ID 对不上自己的查询，会直接丢弃。
fn restore_query_id(packet: &[u8], response: Bytes) -> Bytes {
    if packet.len() < 2 || response.len() < 2 || response[..2] == packet[..2] {
        return response;
    }
    let mut restored = BytesMut::from(response.as_ref());
    restored[..2].copy_from_slice(&packet[..2]);
    restored.freeze()
}

/// 上游的 HTTP 应答里的 DNS 回答。直连 HTTP/2 和 reqwest 两种发法的应答都在这里检查：429 记下暂停多久，
/// 别的错误状态、不是 DNS 消息的媒体类型、太长的正文、答的不是这个问题，都算用不了的回答
/// The DNS answer in an upstream's HTTP response. Responses to both ways of sending, the direct
/// HTTP/2 connection and reqwest, are checked here: a 429 notes how long to pause, and any other
/// error status, a media type other than a DNS message, a body too long, or an answer to another
/// question is an unusable answer
async fn doh_answer<B>(packet: &[u8], resp: hyper::Response<B>) -> anyhow::Result<Bytes>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let status = resp.status();
    if status == hyper::StatusCode::TOO_MANY_REQUESTS {
        // 服务器嫌问得太快。和别的错误状态一样不重试，另外记下它要等多久
        // The server finds the queries too fast. No retry, as for any error status,
        // and note how long it wants a wait
        return Err(anyhow::Error::new(DohAnswerError {
            message: format!("doh http status {status}"),
            throttle: Some(throttle_after(resp.headers().get(RETRY_AFTER))),
        }));
    }
    if !status.is_success() {
        // Wrap as DohAnswerError so the caller knows the connection is
        // fine and a retry won't help.
        // 包装为 DohAnswerError，让调用方知道连接正常、重试无益
        return Err(doh_answer_error(format!("doh http status {status}")));
    }
    // Anything but a DNS message (a captive portal's HTML page, say) is
    // not an answer
    // 不是 DNS 消息的（比如强制门户的 HTML 页面）不算回答
    let media_type = resp
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    if !media_type.is_some_and(|media| media.eq_ignore_ascii_case(DOH_MEDIA_TYPE)) {
        return Err(doh_answer_error(format!(
            "doh answer is not {DOH_MEDIA_TYPE} but {}",
            media_type.unwrap_or("untyped")
        )));
    }

    let body = read_doh_body(resp.into_body()).await?;
    // RFC 5452 §9.1, as on the other transports: the answer has to be for
    // this question
    // RFC 5452 §9.1，和别的传输一样：回答必须是这个问题的
    if !crate::proto_utils::answers_query(packet, &body) {
        return Err(doh_answer_error(
            "doh reply does not answer the query".to_string(),
        ));
    }
    Ok(body)
}

/// 读 DoH 回答的正文，最多一条 DNS 消息那么长：读到比这还长就不再往下读，算用不了的回答，不等服务器发完
/// Reads a DoH answer body, one DNS message long at most: once it runs longer, reading stops and
/// it is an unusable answer, without waiting for the server to finish sending
async fn read_doh_body<B>(mut body: B) -> anyhow::Result<Bytes>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    use http_body_util::BodyExt;

    // 回答一般一块就到齐。那一块是从连接的读缓冲上切下来的，交出去之前复制成自己的一份：要存进缓存的话，整块读缓冲
    // 都会跟着它留着
    // An answer usually arrives in one piece. That piece is cut from the connection's read buffer
    // and is copied into an allocation of its own before it is handed on: kept in the cache, it
    // would keep the whole read buffer alive with it
    let mut first: Option<Bytes> = None;
    let mut joined: Option<BytesMut> = None;
    let mut length = 0;
    while let Some(frame) = body.frame().await {
        // 尾部字段（trailers）不是正文 / Trailers are no part of the body
        let Ok(chunk) = frame.context("read doh response body")?.into_data() else {
            continue;
        };
        length += chunk.len();
        if length > MAX_DNS_MESSAGE_SIZE {
            return Err(doh_answer_error(format!(
                "doh answer longer than {MAX_DNS_MESSAGE_SIZE} bytes"
            )));
        }
        match &first {
            None => first = Some(chunk),
            Some(first) => joined
                .get_or_insert_with(|| BytesMut::from(first.as_ref()))
                .extend_from_slice(&chunk),
        }
    }
    Ok(joined.map_or_else(
        || {
            first
                .map(|piece| Bytes::copy_from_slice(&piece))
                .unwrap_or_default()
        },
        BytesMut::freeze,
    ))
}

/// 传输层错误：在建好的连接上收发时出的错，超时也算，连接死了多半就是这样；不是用不了的回答（见 [`DohAnswerError`]），也不是
/// 没连上（见 [`DohNotConnected`]，reqwest 的建连错误也是）。只有它重发一次（DoH 查询语义幂等），算进重建连接池的门槛：
/// 没连上时池里没有坏掉的连接可丢
/// A transport-level error: one sending or receiving on a connection made, a timeout included,
/// which is mostly how a dead connection shows; neither an unusable answer (see
/// [`DohAnswerError`]) nor no connection (see [`DohNotConnected`], reqwest's connect errors too).
/// Only such an error is sent again once (DoH queries are semantically idempotent) and counts
/// toward rebuilding the pool: with no connection, the pool holds no broken one to drop
fn is_transport_error(err: &anyhow::Error) -> bool {
    err.downcast_ref::<DohAnswerError>().is_none()
        && err.downcast_ref::<DohNotConnected>().is_none()
        && !err
            .downcast_ref::<reqwest::Error>()
            .is_some_and(reqwest::Error::is_connect)
}

/// 直连 DoH 上游用的 TLS 设置：`base` 再加上握手时报 h2 和 http/1.1，和 reqwest 一样
/// The TLS settings for a direct DoH connection: `base` with h2 and http/1.1 offered in the
/// handshake, as reqwest offers them
fn direct_tls_config(mut base: ClientConfig) -> Arc<ClientConfig> {
    base.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Arc::new(base)
}

#[cfg(test)]
#[path = "doh_tests.rs"]
mod tests;
