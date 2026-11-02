//! DoH 上游的 HTTP/2 连接：握手时选了 h2 的上游，请求直接经 h2 发出，不过 reqwest 的那几层（请求构造、
//! URL 和 URI 的来回转换、中间件、连接池检出），也不过 hyper 的客户端（见 [`send`]）。平常所有请求共用
//! 一条连接，一直很忙时才分到更多连接（见 [`BUSY_AT`]）。连接断了、空闲太久或连续出错重建时，下一个请求
//! 重新连。没选 h2 的上游由调用方照旧交给 reqwest。
//! HTTP/2 connections to a DoH upstream: for an upstream that picked h2 in the handshake,
//! requests go straight through h2 without reqwest's layers (request building, URL and URI
//! conversions, middleware, pool checkout) and without hyper's client (see [`send`]). Normally
//! every request shares one connection; only steady heavy load spreads them over more (see
//! [`BUSY_AT`]). When a connection is gone, idle too long or rebuilt after repeated errors, the
//! next request connects again. An upstream that did not pick h2 is handed to reqwest by the
//! caller as before.
//!
//! [`BUSY_AT`]: super::transport::BUSY_AT

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::task::{Context as TaskContext, Poll, Waker, ready};
use std::time::{Duration, Instant};

use anyhow::Context;
use arc_swap::ArcSwapOption;
use bytes::Bytes;
use h2::RecvStream;
use h2::client::SendRequest;
use hyper::body::Frame;
use hyper_util::client::legacy::connect::HttpConnector;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tower_service::Service;
use url::{Host, Url};

use super::transport::{InFlight, least_busy};

/// 请求的发送端 / The sending half requests go through
pub(crate) type H2Sender = SendRequest<Bytes>;

/// 连接空闲这么久就不再用，和 reqwest 连接池的空闲时限（`pool_idle_timeout`）一样：家用路由器的 NAT 会
/// 悄悄忘掉空闲久了的 TCP 连接，在那样的连接上发的请求只会等到超时
/// A connection idle this long is not used again, the same limit as the reqwest pool's
/// (`pool_idle_timeout`): a home router's NAT quietly forgets TCP connections idle that long,
/// and a request sent on one would only wait for its timeout
pub(crate) const DOH_IDLE_TIMEOUT: Duration = Duration::from_secs(90);

/// 连接的接收窗口。每个流的窗口用协议默认的 64 KiB，正好装下最长的 DNS 消息；连接的窗口大得多，同时在途的
/// 回答不用等窗口更新。hyper 用 PING 估算带宽时延积再放大窗口，DNS 回答很小，用不着
/// The connection's receive window. Each stream keeps the protocol's default 64 KiB, which holds
/// the longest DNS message; the connection's is much larger, so answers in flight together never
/// wait for a window update. hyper widens its windows from PING-based bandwidth-delay estimates,
/// which DNS answers are far too small to need
const CONNECTION_WINDOW: u32 = 1 << 20;

/// 一条打开的连接 / One open connection
struct H2Conn {
    sender: H2Sender,
    /// 最后一次用它时离 `H2Link::epoch` 多少毫秒 / When it was last used, in milliseconds since `H2Link::epoch`
    last_used_ms: AtomicU64,
}

/// 一个连接位：最多一条连接 / One connection slot: at most one connection
struct Slot {
    conn: ArcSwapOption<H2Conn>,
    /// 同一时刻只有一个请求去连，其余的等它连好 / One request connects at a time and the others wait for it
    connecting: tokio::sync::Mutex<()>,
    /// 这个位上还没答完的请求数 / Requests on this slot not yet answered
    in_flight: AtomicUsize,
}

/// 一个 DoH 上游的 HTTP/2 连接：每个工作线程一个位，平常只用第一个
/// （见 [`BUSY_AT`](super::transport::BUSY_AT)）
/// One DoH upstream's HTTP/2 connections: a slot per worker thread, normally only the first in
/// use (see [`BUSY_AT`](super::transport::BUSY_AT))
pub(crate) struct H2Link {
    slots: Box<[Slot]>,
    /// 这个上游握手时没选 h2：之后的请求都交给 reqwest / This upstream did not pick h2 in the handshake: later requests all go to reqwest
    no_h2: AtomicBool,
    epoch: Instant,
    idle_timeout: Duration,
}

impl H2Link {
    /// 最多 `connections` 条连接的 H2Link，至少一条 / An H2Link of at most `connections` connections, one at least
    pub(crate) fn new(idle_timeout: Duration, connections: usize) -> Self {
        Self {
            slots: (0..connections.max(1))
                .map(|_| Slot {
                    conn: ArcSwapOption::empty(),
                    connecting: tokio::sync::Mutex::new(()),
                    in_flight: AtomicUsize::new(0),
                })
                .collect(),
            no_h2: AtomicBool::new(false),
            epoch: Instant::now(),
            idle_timeout,
        }
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// `slot` 上还能用的现有连接：能接着开流、也没空闲太久 / The connection on `slot` if it is still usable: open to new streams and not idle too long
    fn usable(&self, slot: &Slot, now: u64) -> Option<H2Sender> {
        let conn = slot.conn.load_full()?;
        let idle =
            Duration::from_millis(now.saturating_sub(conn.last_used_ms.load(Ordering::Relaxed)));
        if idle >= self.idle_timeout {
            return None;
        }
        let sender = open_to_new_streams(&conn.sender)?;
        conn.last_used_ms.store(now, Ordering::Relaxed);
        Some(sender)
    }

    /// 发请求用的发送端和它占着的连接位：位上有能用的连接就用它，没有就连一条。请求答完（或放弃）之前一直
    /// 拿着 [`InFlight`]。上游没选 h2 时是 None，交给 reqwest
    /// The sender for a request and the slot it holds: the slot's connection when usable, a new
    /// one otherwise. The [`InFlight`] is kept until the request is answered (or given up). None
    /// when the upstream did not pick h2, for reqwest to handle
    pub(crate) async fn sender(
        &self,
        url: &Url,
        tls: &Arc<ClientConfig>,
        connector: &HttpConnector,
    ) -> anyhow::Result<Option<(H2Sender, InFlight<'_>)>> {
        if self.no_h2.load(Ordering::Relaxed) {
            return Ok(None);
        }
        let slot = least_busy(&self.slots, |slot| slot.in_flight.load(Ordering::Relaxed));
        let in_flight = InFlight::enter(&slot.in_flight);
        if let Some(sender) = self.usable(slot, self.now_ms()) {
            return Ok(Some((sender, in_flight)));
        }
        let _connecting = slot.connecting.lock().await;
        // 等锁的时候别的请求可能已经连好了 / Another request may have connected while this one waited for the lock
        if let Some(sender) = self.usable(slot, self.now_ms()) {
            return Ok(Some((sender, in_flight)));
        }
        match connect(url, tls, connector).await? {
            Some(sender) => {
                slot.conn.store(Some(Arc::new(H2Conn {
                    sender: sender.clone(),
                    last_used_ms: AtomicU64::new(self.now_ms()),
                })));
                Ok(Some((sender, in_flight)))
            }
            None => {
                self.no_h2.store(true, Ordering::Relaxed);
                Ok(None)
            }
        }
    }

    /// 现在有没有一条直连的连接 / Whether a direct connection is open now
    #[cfg(test)]
    pub(crate) fn is_connected(&self) -> bool {
        self.slots.iter().any(|slot| {
            slot.conn
                .load()
                .as_ref()
                .is_some_and(|conn| open_to_new_streams(&conn.sender).is_some())
        })
    }

    /// 各个位上还没答完的请求加起来有几个 / How many requests are unanswered across the slots
    #[cfg(test)]
    pub(crate) fn in_flight(&self) -> usize {
        self.slots
            .iter()
            .map(|slot| slot.in_flight.load(Ordering::Relaxed))
            .sum()
    }

    /// 丢掉现有连接：下一个请求重新连，也重新看对方选不选 h2（连续出错重建连接池时用）
    /// Drops the current connections: the next request connects again and looks again whether
    /// the peer picks h2 (used when repeated errors rebuild the pool)
    pub(crate) fn reset(&self) {
        for slot in &self.slots {
            slot.conn.store(None);
        }
        self.no_h2.store(false, Ordering::Relaxed);
    }
}

/// 连上 `url`：TCP 走 reqwest 用的同一个连接器（解析域名、IPv6 连不上时退回 IPv4），TLS 握手报 h2 和
/// http/1.1。对方选了 h2 就做 HTTP/2 握手，把连接交给后台任务；没选时是 None
/// Connects to `url`: TCP through the same connector reqwest uses (name resolution, falling
/// back to IPv4 when IPv6 does not connect), a TLS handshake offering h2 and http/1.1. When the
/// peer picks h2 the HTTP/2 handshake follows and a background task drives the connection;
/// otherwise None
async fn connect(
    url: &Url,
    tls: &Arc<ClientConfig>,
    connector: &HttpConnector,
) -> anyhow::Result<Option<H2Sender>> {
    let server_name = match url.host().context("doh url has no host")? {
        Host::Domain(name) => ServerName::try_from(name.to_string()).context("doh server name")?,
        Host::Ipv4(ip) => ServerName::IpAddress(std::net::IpAddr::V4(ip).into()),
        Host::Ipv6(ip) => ServerName::IpAddress(std::net::IpAddr::V6(ip).into()),
    };
    let uri: hyper::Uri = url.as_str().parse().context("doh url as uri")?;
    let tcp = connector
        .clone()
        .call(uri)
        .await
        .map_err(|err| anyhow::anyhow!(err))
        .context("doh connect failed")?
        .into_inner();
    let stream = tokio_rustls::TlsConnector::from(Arc::clone(tls))
        .connect(server_name, tcp)
        .await
        .context("doh tls handshake failed")?;
    if stream.get_ref().1.alpn_protocol() != Some(b"h2") {
        return Ok(None);
    }
    handshake(stream).await.map(Some)
}

/// 在 `io` 上做 HTTP/2 握手，把连接交给后台任务。这几项和 hyper 的客户端一样：不收服务器推送，对方的设置到
/// 之前最多开 100 个流，响应头最多 16 KiB；接收窗口见 [`CONNECTION_WINDOW`]
/// Does the HTTP/2 handshake on `io` and hands the connection to a background task. As in hyper's
/// client: no server push, at most 100 streams before the peer's settings arrive, response
/// headers up to 16 KiB; the receive window is [`CONNECTION_WINDOW`]
pub(crate) async fn handshake<T>(io: T) -> anyhow::Result<H2Sender>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (sender, connection) = h2::client::Builder::new()
        .enable_push(false)
        .initial_max_send_streams(100)
        .max_header_list_size(16 << 10)
        .initial_connection_window_size(CONNECTION_WINDOW)
        .handshake(io)
        .await
        .context("doh http2 handshake failed")?;
    tokio::spawn(async move {
        // 被叫醒以后先让一轮再干活，这一轮里排进来的请求就一次写出去。不让的话，tokio 让刚被叫醒的任务插到
        // 最前面先跑，第一个请求一叫醒连接，连接就只写这一个，一个请求写一次
        // Once woken, yield one round before working, so the requests queued during that round
        // go out in one write. Without it tokio runs a task it was just woken for first, so the
        // first request to wake the connection is written alone, one write per request
        let mut connection = std::pin::pin!(connection);
        let mut yielded = false;
        let ended = std::future::poll_fn(|cx| {
            yielded = !yielded;
            if yielded {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            connection.as_mut().poll(cx)
        })
        .await;
        if let Err(err) = ended {
            tracing::debug!(error = %err, "DoH HTTP/2 connection ended");
        }
    });
    Ok(sender)
}

/// 一个能开新流的发送端；连接断了、出错了、收到 GOAWAY 或流 ID 用完时是 None。新的发送端没有待开的流，
/// `poll_ready` 只查这些，不会等
/// A sender able to open a new stream; None once the connection is gone, has failed, got a GOAWAY
/// or ran out of stream IDs. A fresh sender has no stream waiting to open, so `poll_ready` only
/// checks these and never waits
fn open_to_new_streams(sender: &H2Sender) -> Option<H2Sender> {
    let mut sender = sender.clone();
    match sender.poll_ready(&mut TaskContext::from_waker(Waker::noop())) {
        Poll::Ready(Ok(())) => Some(sender),
        Poll::Ready(Err(_)) | Poll::Pending => None,
    }
}

/// 发一个请求，正文 `body` 一次发完，等回响应头。请求头和正文接连排进连接、中间不让出，连接下一次写出时
/// 一起写出去。hyper 的客户端另起任务送正文，那个任务等到流开了才拿得到发送窗口，请求头总是先单独写出去，
/// 上游要等第二次写才收齐整个请求
/// Sends a request whose body `body` goes in one piece, and waits for the response head. The
/// request head and body are queued on the connection back to back without yielding, so its next
/// write carries both. hyper's client sends the body from a separate task that gets send capacity
/// only once the stream is open, so the head always goes out alone first and the upstream has the
/// whole request only after a second write
pub(crate) async fn send(
    mut sender: H2Sender,
    request: hyper::Request<()>,
    body: Bytes,
) -> Result<hyper::Response<H2Body>, h2::Error> {
    let (response, mut stream) = sender.send_request(request, false)?;
    stream.send_data(body, true)?;
    Ok(response.await?.map(H2Body))
}

/// 响应的正文。读到一块就把这块的接收窗口还给对方：流的窗口正好装下一条最长的 DNS 消息，不还的话，比它长的
/// 正文会停在窗口上，等到超时才知道太长
/// A response body. Each piece read hands its share of the receive window back to the peer: a
/// stream's window holds exactly the longest DNS message, so without this a longer body would
/// stall on the window and be found too long only at the timeout
pub(crate) struct H2Body(RecvStream);

impl hyper::body::Body for H2Body {
    type Data = Bytes;
    type Error = h2::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, h2::Error>>> {
        let Some(chunk) = ready!(self.0.poll_data(cx)) else {
            return Poll::Ready(None);
        };
        Poll::Ready(Some(chunk.map(|chunk| {
            // 还的不会比收到的多，不会出错 / Never more than was received, so this cannot fail
            let _ = self.0.flow_control().release_capacity(chunk.len());
            Frame::data(chunk)
        })))
    }

    fn is_end_stream(&self) -> bool {
        self.0.is_end_stream()
    }
}

/// 和 reqwest 默认一样的 TCP 连接器：关 Nagle，不限 http（TLS 由这里接着做），TCP keepalive 15 秒起、
/// 每 15 秒一次、3 次没回就断
/// A TCP connector set up as reqwest's default: Nagle off, any scheme allowed (TLS follows
/// here), TCP keepalive from 15 seconds, every 15 seconds, given up after 3 unanswered
pub(crate) fn tcp_connector() -> HttpConnector {
    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    connector.set_nodelay(true);
    connector.set_keepalive(Some(Duration::from_secs(15)));
    connector.set_keepalive_interval(Some(Duration::from_secs(15)));
    connector.set_keepalive_retries(Some(3));
    connector
}

/// 设了代理环境变量时，reqwest 会让 https 请求走代理（它默认读这些变量）。这里的直连不认代理，所以那时
/// 全部照旧交给 reqwest
/// With a proxy environment variable set, reqwest sends https requests through the proxy (it
/// reads these by default). The direct connection here knows no proxies, so then everything
/// goes to reqwest as before
pub(crate) fn proxy_configured() -> bool {
    proxy_configured_in(|name| std::env::var_os(name))
}

/// [`proxy_configured`]，环境变量从 `var` 读 / [`proxy_configured`] with the environment read through `var`
pub(crate) fn proxy_configured_in(var: impl Fn(&str) -> Option<std::ffi::OsString>) -> bool {
    ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"]
        .iter()
        .any(|name| var(name).is_some_and(|value| !value.is_empty()))
}
