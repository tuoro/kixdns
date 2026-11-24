//! 各传输共用的建连和连接管理：几个地址错开着连（RFC 8305）、TCP 保活、建连和退避（[`Connect`]）、连接老化（[`Aging`]、
//! [`Wear`]）、连接池和挑连接（[`least_busy`]），以及 TLS 设置
//! What the transports share in making and keeping connections: attempts staggered over several
//! addresses (RFC 8305), TCP keepalive, connecting and backing off ([`Connect`]), aging
//! ([`Aging`], [`Wear`]), pools and picking a connection ([`least_busy`]), and the TLS settings

use super::BUSY_AT;
use crate::engine::bootstrap::Bootstrap;
use anyhow::Context;
use arc_swap::ArcSwapOption;
use dashmap::DashMap;
use futures::FutureExt;
use futures::future::{BoxFuture, Shared};
use rustc_hash::FxBuildHasher;
use rustls::{ClientConfig, RootCertStore};
use socket2::{SockRef, TcpKeepalive};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::warn;
use webpki_roots::TLS_SERVER_ROOTS;

/// RFC 8305 第 5 节的 Connection Attempt Delay：一个尝试这么久还没连上，就起下一个 / The Connection
/// Attempt Delay of RFC 8305 section 5: an attempt not through after this long has the next one
/// started
const ATTEMPT_DELAY: Duration = Duration::from_millis(250);

/// 用 `attempt` 连上 `addresses` 里的一个（RFC 8305 第 4、5 节）：地址按族交替排开，第一个地址那一族在前；起一个尝试，
/// 它过了 [`ATTEMPT_DELAY`] 还没连上、或者失败了，就接着起下一个，先连上的那个用，别的放弃；都失败时报最后那个失败。
/// TCP、DoT、直连的 DoH 和 DoQ 都这样连：前面的地址不回应时，后面的不用等到建连的时限才轮到
/// Connects through `attempt` to one of `addresses` (RFC 8305 sections 4 and 5): the addresses
/// alternate by family, the first address's family first; one attempt is started, and once it is
/// not through after [`ATTEMPT_DELAY`], or has failed, the next one is, the first to connect
/// being used and the rest given up; with all failed the last failure is reported. TCP, DoT,
/// direct DoH and DoQ all connect so: with an early address not answering, the later ones have
/// their turn well within the connect's time limit
pub(super) async fn staggered<T, F>(
    addresses: Vec<SocketAddr>,
    attempt: impl Fn(SocketAddr) -> F,
) -> anyhow::Result<T>
where
    F: Future<Output = anyhow::Result<T>>,
{
    use futures::StreamExt;

    let mut waiting = interleaved(addresses).into_iter();
    let mut attempts = futures::stream::FuturesUnordered::new();
    let mut failed = None;
    loop {
        match waiting.next() {
            Some(address) => attempts.push(attempt(address)),
            None if attempts.is_empty() => {
                return Err(failed.unwrap_or_else(|| anyhow::anyhow!("no address to connect to")));
            }
            None => {}
        }
        tokio::select! {
            Some(outcome) = attempts.next() => match outcome {
                Ok(connected) => return Ok(connected),
                Err(error) => failed = Some(error),
            },
            () = tokio::time::sleep(ATTEMPT_DELAY), if !waiting.as_slice().is_empty() => {}
        }
    }
}

/// `addresses` 按族交替排开，第一个地址那一族在前，同一族里照原来的先后（RFC 8305 第 4 节）/ `addresses`
/// alternating by family, the first address's family first and each family in its own order
/// (RFC 8305 section 4)
fn interleaved(addresses: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let first_v4 = addresses.first().is_some_and(SocketAddr::is_ipv4);
    let mut seen = [0usize; 2];
    let mut ranked: Vec<_> = addresses
        .into_iter()
        .map(|address| {
            let family = usize::from(address.is_ipv4() != first_v4);
            seen[family] += 1;
            ((seen[family], family), address)
        })
        .collect();
    ranked.sort_by_key(|(rank, _)| *rank);
    ranked.into_iter().map(|(_, address)| address).collect()
}

/// 连上写成 `主机:端口` 的地址（TCP、DoT 上游，直连的 DoH 上游）：主机名交给 `bootstrap` 解析，几个地址错开着连
/// （见 [`staggered`]），连上的那条再调好（见 [`tune_stream_socket`]）
/// Connects to an address written as `host:port` (TCP and DoT upstreams, a direct DoH one): the
/// host name goes to `bootstrap`, several addresses are connected to staggered (see
/// [`staggered`]), and the one connected is tuned (see [`tune_stream_socket`])
pub(in crate::engine) async fn connect_tcp(
    bootstrap: &Bootstrap,
    address: &str,
) -> anyhow::Result<TcpStream> {
    let addresses = match address.parse::<SocketAddr>() {
        Ok(address) => vec![address],
        Err(_) => {
            let (host, port) = address
                .rsplit_once(':')
                .context("expected a host and a port")?;
            bootstrap
                .addresses(host, port.parse().context("invalid port")?)
                .await?
        }
    };
    let stream = staggered(addresses, |address| async move {
        Ok(TcpStream::connect(address).await?)
    })
    .await?;
    tune_stream_socket(&stream, address);
    Ok(stream)
}

/// TCP 连接的保活，TCP、DoT 和 DoH（直连的和经 reqwest 的）都一样：这么久没有收发就探一次，没回应隔这么久再探，探到系统定的
/// 次数都没回应算断了。连接留着、还没到空闲时限（见 [`Aging`]）的时候，死掉的上游二十来秒就看得出来，NAT 也不会忘掉它；什么
/// 时候关掉不用的连接只由 [`Aging`] 定。DoQ 的保活是 QUIC 自己的 PING，照 `doq_keepalive_interval_ms`
/// The keepalive of TCP connections, the same for TCP, DoT and DoH (direct and through
/// reqwest): a probe after this long with nothing sent or received, again this far apart while
/// unanswered, and dead once as many as the system sets go unanswered. While a connection is kept
/// and short of its idle limit (see [`Aging`]), a dead upstream shows within twenty seconds or
/// so, and no NAT forgets the connection; when an unused one closes is for [`Aging`] alone to
/// say. DoQ keeps alive by QUIC's own PINGs, as `doq_keepalive_interval_ms` sets
pub(super) const KEEPALIVE_TIME: Duration = Duration::from_secs(5);
pub(super) const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(2);

/// 刚建好的 TCP 连接（DoT、直连的 DoH 在握手之前也是）：关掉 Nagle，打开保活（见 [`KEEPALIVE_TIME`]）
/// A freshly connected TCP stream (DoT's and a direct DoH one's too, before their handshakes):
/// Nagle off and the keepalive on (see [`KEEPALIVE_TIME`])
fn tune_stream_socket(stream: &TcpStream, upstream: &str) {
    let _ = stream.set_nodelay(true);
    let sock = SockRef::from(stream);
    let keepalive = TcpKeepalive::new()
        .with_time(KEEPALIVE_TIME)
        .with_interval(KEEPALIVE_INTERVAL);
    // SO_KEEPALIVE 要另外打开，Windows 和 Linux 上都是 / SO_KEEPALIVE is switched on apart, on Windows
    // and Linux alike
    if let Err(e) = sock.set_keepalive(true) {
        warn!(upstream = %upstream, error = %e, "Failed to enable SO_KEEPALIVE");
    }
    if let Err(e) = sock.set_tcp_keepalive(&keepalive) {
        warn!(upstream = %upstream, error = %e, "Failed to set TCP keepalive params");
    }
}

/// `members` 里排在最前、还不忙的那个；都忙时在途最少的那个（见 [`BUSY_AT`]）
/// The first of `members` not busy; with all busy, the one with the fewest in flight (see
/// [`BUSY_AT`])
pub(crate) fn least_busy<T>(members: &[T], in_flight: impl Fn(&T) -> usize) -> &T {
    members
        .iter()
        .find(|member| in_flight(member) < BUSY_AT)
        .or_else(|| members.iter().min_by_key(|member| in_flight(member)))
        .expect("a pool has a member at least")
}

/// 一个查询记在一条连接的在途数上，丢掉时再减掉 / A query counted in a connection's in-flight number, taken off again when dropped
pub(crate) struct InFlight<'a>(&'a AtomicUsize);

impl<'a> InFlight<'a> {
    pub(crate) fn enter(count: &'a AtomicUsize) -> Self {
        count.fetch_add(1, Ordering::Relaxed);
        Self(count)
    }
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// 建一条连接（TCP、DoT、DoQ、DoH 的 HTTP/2）。建连在自己的任务里做，最多 [`CONNECT_BUDGET`]，建好了由这个任务自己装上
/// （各传输给的 `make` 连同装上一起做）：发起它的查询被取消了（几个上游竞速时别的先答完、外层超时），连接照样建完、装上，
/// 从一开始就有人读它、看它关没关，留给接着来的查询。同时要连接的查询都等这同一次，各自最多等到自己的期限。失败以后退避：
/// 从 [`CONNECT_BACKOFF`] 起每失败一次翻倍，最多 [`CONNECT_BACKOFF_AT_MOST`]，从失败的那一刻算，这期间来要连接的查询马上
/// 失败、不去连。时间按 tokio 的单调时钟算，和老化一样（见 [`Aging`]）。它放在各传输自己的锁里，那把锁只在看一眼、起一次建连的
/// 那一下拿着
/// Making a connection (TCP, DoT, DoQ, DoH over HTTP/2). The connect happens in a task of its
/// own, taking at most [`CONNECT_BUDGET`], and that task puts the connection in place itself
/// (the `make` each transport gives does both): with the query that started it cancelled
/// (another upstream answering first in a race, an outer timeout), the connection is made and put
/// in place all the same, read and watched for closing from the start, for the queries coming
/// next. Queries wanting a connection meanwhile all wait for this one connect, each until its own
/// deadline at most. After a failure it backs off, from [`CONNECT_BACKOFF`] doubling on each
/// failure up to [`CONNECT_BACKOFF_AT_MOST`], counted from the failure, the queries asking
/// meanwhile failing at once without connecting. Times run on tokio's monotonic clock, as aging
/// does (see [`Aging`]). It sits under each transport's own lock, held only for the moment of a
/// look and of starting a connect
pub(in crate::engine) struct Connect {
    /// 这一次建连，等它的各拿一份；建完了也留着，下一个来要连接的查询看过结果再丢掉 / This connect, a copy
    /// for each waiting on it; kept once through, until the next query asking for a connection has
    /// looked at what it gave
    attempt: Option<Attempt>,
    /// 退避到什么时候，下一次失败退避多久 / Backing off until when, and for how long after the next failure
    retry_at: Option<tokio::time::Instant>,
    backoff: Duration,
}

/// 一次建连的结果，等着它的各拿一份 / One connect's outcome, a copy for each waiting on it
pub(in crate::engine) type Attempt = Shared<BoxFuture<'static, Result<(), ConnectFailed>>>;

/// 一次建连为什么失败、什么时候失败的 / Why a connect failed, and when
#[derive(Clone, Debug)]
pub(in crate::engine) struct ConnectFailed {
    why: Arc<str>,
    at: tokio::time::Instant,
}

impl std::fmt::Display for ConnectFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.why)
    }
}

impl std::error::Error for ConnectFailed {}

/// 建一条连接最多花多久（解析名字、TCP 或 QUIC 握手、TLS 握手），经 reqwest 的 DoH 也是 / The most a connect may
/// take (resolving the name, the TCP or QUIC handshake, the TLS one), DoH through reqwest's too
pub(super) const CONNECT_BUDGET: Duration = Duration::from_secs(5);
/// 建连第一次失败以后退避多久 / How long to back off after a first failed connect
pub(super) const CONNECT_BACKOFF: Duration = Duration::from_millis(250);
/// 建连接连失败时退避最多多久 / The longest backing off after failed connects in a row
const CONNECT_BACKOFF_AT_MOST: Duration = Duration::from_secs(5);

impl Default for Connect {
    fn default() -> Self {
        Self {
            attempt: None,
            retry_at: None,
            backoff: CONNECT_BACKOFF,
        }
    }
}

impl Connect {
    /// 在建的那一次；没有就用 `make` 起一次，退避期间是 Err。上一次建完了的，先照它的结果定退避：成功了不退避，失败了从
    /// 失败的那一刻起退避
    /// The connect under way; with none, one started with `make`, except while backing off, which
    /// is an Err. One through already sets the backing off first by what it gave: none after a
    /// success, and after a failure counted from when it failed
    pub(in crate::engine) fn attempt<F>(
        &mut self,
        make: impl FnOnce() -> F,
    ) -> anyhow::Result<Attempt>
    where
        F: Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        if let Some(attempt) = &self.attempt {
            match attempt.peek() {
                None => return Ok(attempt.clone()),
                Some(Ok(())) => {
                    self.retry_at = None;
                    self.backoff = CONNECT_BACKOFF;
                }
                Some(Err(failed)) => {
                    self.retry_at = Some(failed.at + self.backoff);
                    self.backoff = (self.backoff * 2).min(CONNECT_BACKOFF_AT_MOST);
                }
            }
            self.attempt = None;
        }
        if let Some(left) = self
            .retry_at
            .and_then(|at| at.checked_duration_since(tokio::time::Instant::now()))
        {
            anyhow::bail!(
                "connect failed lately, trying again in {}ms",
                left.as_millis()
            );
        }
        let made = timeout(CONNECT_BUDGET, make());
        let attempt = async move {
            made.await
                .unwrap_or_else(|_| {
                    Err(anyhow::anyhow!(
                        "connect timeout after {}ms",
                        CONNECT_BUDGET.as_millis()
                    ))
                })
                .map_err(|error| ConnectFailed {
                    why: format!("{error:#}").into(),
                    at: tokio::time::Instant::now(),
                })
        }
        .boxed()
        .shared();
        tokio::spawn(attempt.clone());
        Ok(self.attempt.insert(attempt).clone())
    }

    /// 拿一条连接，没有就等一次建连：`take` 从 `lock` 锁着的东西里拿现成的连接，`connect` 在那里面找到 [`Connect`]。拿不到就
    /// 用 `make` 起一次建连，或者等在建的那一次（见 [`Self::attempt`]），建完了再拿一次。给出连接和它是不是等来的；等来的
    /// 连接在拿到之前就没了时是 None，不再等下一条。锁只在拿和起建连的那一下拿着，等建连时不拿；调用方先不拿锁看一眼的话，
    /// 这里拿着锁再看一次，免得别人的连接刚建好、这里又去建一条
    /// Takes a connection, waiting for a connect when there is none: `take` takes a ready
    /// connection out of what `lock` guards, `connect` finding the [`Connect`] in there. With
    /// none, a connect is started with `make`, or the one under way waited for (see
    /// [`Self::attempt`]), and once it is through `take` tries again. It gives the connection and whether it was waited for; one waited
    /// for and gone before it could be taken gives None, with no wait for another. The lock is held
    /// only for the moments of taking and of starting a connect, never across the wait; a caller
    /// that first looks without the lock has it looked at again here under the lock, so a
    /// connection someone else just made is not made a second time
    pub(in crate::engine) async fn get_or_make<L, T, F>(
        lock: &parking_lot::Mutex<L>,
        connect: impl FnOnce(&mut L) -> &mut Connect,
        take: impl Fn(&mut L) -> Option<T>,
        make: impl FnOnce() -> F,
    ) -> anyhow::Result<Option<(T, bool)>>
    where
        F: Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        let attempt = {
            let mut locked = lock.lock();
            if let Some(ready) = take(&mut locked) {
                return Ok(Some((ready, false)));
            }
            connect(&mut locked).attempt(make)?
        };
        attempt.await?;
        Ok(take(&mut lock.lock()).map(|made| (made, true)))
    }
}

/// 一条上游连接怎样老化，TCP、DoT、DoQ 和直连的 DoH 共用一套：活满 `max_age`，或者空闲满 `idle`，就从池里摘下，接着来的
/// 查询另建一条；它上面还在等的查询照样等到各自的期限，过了最晚的那个再关。空闲从它上面最晚的那个期限算起：那以后没有查询
/// 在等，也这么久没有新的查询（RFC 7766 §6.2.3）。None 是不限。连接自己的任务到了时候就摘下、关掉它（见 [`Aging::worn`]），
/// 不等下一个查询来看，没人用的连接也不会一直开着。时间按单调时钟算，调系统时间不影响
/// How an upstream connection ages, one rule for TCP, DoT, DoQ and direct DoH: once it has lived
/// `max_age`, or sat idle for `idle`, it is taken out of its pool and queries coming next make
/// another; the queries still waiting on it go on to their own deadlines, and it closes once the
/// latest has passed. Idleness counts from the latest of its deadlines: from then on no query
/// waits on it, and none has come for that long (RFC 7766 §6.2.3). None is no limit. The
/// connection's own task takes it out and closes it when the time comes (see [`Aging::worn`]),
/// without waiting for a next query to look, so a connection nobody uses does not stay open.
/// Times run on the monotonic clock, untouched by the system time being set
#[derive(Clone, Copy, Debug)]
pub(in crate::engine) struct Aging {
    pub(in crate::engine) max_age: Option<Duration>,
    pub(in crate::engine) idle: Option<Duration>,
}

impl Aging {
    /// 活满 `max_age`、空闲满 `idle` 就摘下，0 是不限 / Taken out once it has lived `max_age` or sat
    /// idle for `idle`, 0 being no limit
    pub(in crate::engine) fn new(max_age: Duration, idle: Duration) -> Self {
        Self {
            max_age: Some(max_age).filter(|age| !age.is_zero()),
            idle: Some(idle).filter(|idle| !idle.is_zero()),
        }
    }

    /// 等到 `wear` 那条连接该摘下的时候，给出原因：活满了 `max_age`，或者空闲满了 `idle`；都不限时一直等。时限远到时钟
    /// 表示不了的（配置写了极大的值）和不限一样
    /// Waits until the connection of `wear` is to be taken out, giving why: it has lived `max_age`,
    /// or sat idle for `idle`; with neither limited it waits for ever. A limit too far off for the
    /// clock to hold (a huge value configured) is no limit
    pub(in crate::engine) async fn worn(self, wear: &Wear) -> &'static str {
        let after = |since: tokio::time::Instant, limit: Option<Duration>, why| {
            Some((since.checked_add(limit?)?, why))
        };
        loop {
            let old = after(wear.made, self.max_age, "too old");
            let idle = after(wear.latest_deadline(), self.idle, "idle");
            let Some((at, why)) = old.into_iter().chain(idle).min_by_key(|(at, _)| *at) else {
                return std::future::pending().await;
            };
            if tokio::time::Instant::now() >= at {
                return why;
            }
            // 醒来再看一次：这期间来的查询把最晚的期限往后推了 / Looked at again on waking: queries
            // meanwhile have pushed the latest deadline later
            tokio::time::sleep_until(at).await;
        }
    }
}

/// 一条连接用了多久、多久没人用：什么时候建的，用它的查询里最晚的期限 / How long a connection has
/// lived and gone unused: when it was made, and the latest deadline of the queries using it
pub(in crate::engine) struct Wear {
    made: tokio::time::Instant,
    /// 用它的查询里最晚的期限，从 `made` 起的微秒数 / The latest deadline of the queries using it, in
    /// microseconds from `made`
    latest_deadline_us: AtomicU64,
}

impl Wear {
    /// 刚建好的连接，还没有查询用过 / A connection just made, used by no query yet
    pub(in crate::engine) fn new() -> Self {
        Self {
            made: tokio::time::Instant::now(),
            latest_deadline_us: AtomicU64::new(0),
        }
    }

    /// 一个期限在 `deadline` 的查询用上了它 / A query with its deadline at `deadline` uses it
    pub(in crate::engine) fn note(&self, deadline: tokio::time::Instant) {
        let us = deadline.saturating_duration_since(self.made).as_micros();
        self.latest_deadline_us
            .fetch_max(u64::try_from(us).unwrap_or(u64::MAX), Ordering::AcqRel);
    }

    /// 用它的查询里最晚的期限；还没有查询用过时是建好的那一刻 / The latest deadline of the queries
    /// using it; the moment it was made while none has
    pub(in crate::engine) fn latest_deadline(&self) -> tokio::time::Instant {
        self.made + Duration::from_micros(self.latest_deadline_us.load(Ordering::Acquire))
    }

    /// 等到用它的查询都过了各自的期限 / Waits until every query using it is past its deadline
    pub(in crate::engine) async fn settled(&self) {
        loop {
            let at = self.latest_deadline();
            if tokio::time::Instant::now() >= at {
                return;
            }
            tokio::time::sleep_until(at).await;
        }
    }
}

/// 一个上游的连接池：几个客户端，先用排在前面、还不忙的（见 [`least_busy`]）/ One upstream's pool: a
/// few clients, the first not busy taken first (see [`least_busy`])
pub struct ConnectionPool<C> {
    pub(super) clients: Vec<Arc<C>>,
}

impl<C> ConnectionPool<C> {
    pub(super) fn new(clients: Vec<Arc<C>>) -> Self {
        Self { clients }
    }

    /// 排在最前、还不忙的客户端；都忙时在途最少的那个（见 [`least_busy`]）
    /// The first client not busy; with all busy, the one with the fewest in flight (see
    /// [`least_busy`])
    pub(super) fn least_busy(&self, in_flight: impl Fn(&C) -> usize) -> &Arc<C> {
        least_busy(&self.clients, |client| in_flight(client))
    }
}

/// 每个上游一个连接池 / One connection pool per upstream
pub(super) struct UpstreamPools<C> {
    pools: DashMap<Arc<str>, Arc<ConnectionPool<C>>, FxBuildHasher>,
}

impl<C> UpstreamPools<C> {
    pub(super) fn new() -> Self {
        Self {
            pools: DashMap::with_hasher(FxBuildHasher),
        }
    }

    /// 只留下 `keep` 认可的上游的连接池。重载后配置里不再有的上游，连接池就此丢掉：正在用它的
    /// 查询拿着连接池，做完才释放；之后它的连接随之关闭。
    /// Keeps only the pools of the upstreams `keep` accepts. After a reload, the pool of an
    /// upstream the configuration no longer names is dropped: queries using it hold on to
    /// it until they finish, and its connections close after that.
    pub(super) fn retain(&self, keep: impl Fn(&str) -> bool) {
        self.pools.retain(|upstream, _| keep(upstream));
    }

    /// `upstream` 的连接池，还没有就用 `clients` 建一个。平常池已经在，只读一下：不分配键、不拿写锁 / The pool for
    /// `upstream`, built from `clients` if there is none. Normally the pool is there and is only
    /// read: no key allocated and no write lock taken
    pub(super) fn get_or_create(
        &self,
        upstream: &str,
        clients: impl FnOnce(&Arc<str>) -> Vec<Arc<C>>,
    ) -> Arc<ConnectionPool<C>> {
        if let Some(pool) = self.get(upstream) {
            return pool;
        }
        let upstream: Arc<str> = Arc::from(upstream);
        self.pools
            .entry(Arc::clone(&upstream))
            .or_insert_with(|| Arc::new(ConnectionPool::new(clients(&upstream))))
            .clone()
    }

    pub(super) fn get(&self, upstream: &str) -> Option<Arc<ConnectionPool<C>>> {
        self.pools.get(upstream).map(|pool| Arc::clone(&pool))
    }
}

#[cfg(test)]
impl Aging {
    /// 测试里的客户端用的老化：5 分钟、1 分钟，和默认配置一样 / The aging of clients in tests: 5 minutes and
    /// 1 minute, as the default configuration has
    pub(super) fn for_tests() -> Self {
        Self::new(Duration::from_secs(300), Duration::from_secs(60))
    }
}

pub(super) fn build_tls_client_config() -> anyhow::Result<ClientConfig> {
    let mut root_store = RootCertStore::empty();
    root_store.extend(TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Ok(config)
}

/// 把连接 `pooled` 从放它的地方 `pool`（DoQ 客户端的池、DoH 的连接位）拿掉，下一个要连接的新建一条。那里现在的已经不是它
/// （换成了新的，或者已经拿掉了）就什么都不做：几个查询在同一条连接上一起失败时，先失败的那个已经换了新连接，后面的不能把
/// 新连接也拿掉、让每个查询各建一条。不用锁：别人正在建连时也不用等
/// Takes the connection `pooled` out of `pool`, where it is kept (a DoQ client's pool, a DoH
/// slot), so the next to want a connection makes a new one. When what is kept there now is not
/// it (replaced by a new one, or taken out already) nothing is done: with several queries failing
/// together on one connection, the first has had a new one made, and the rest must not take that
/// out too, each making its own. Lock-free: it never waits for another's connect
pub(in crate::engine) fn forget<T>(pool: &ArcSwapOption<T>, pooled: &Arc<T>) {
    pool.rcu(|current| {
        current
            .clone()
            .filter(|current| !Arc::ptr_eq(current, pooled))
    });
}

#[cfg(test)]
#[path = "connect_tests.rs"]
mod tests;
