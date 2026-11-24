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
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::task::{Context as TaskContext, Poll, Waker, ready};
use std::time::Duration;

use anyhow::Context;
use arc_swap::ArcSwapOption;
use bytes::Bytes;
use h2::RecvStream;
use h2::client::SendRequest;
use hyper::body::Frame;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use url::{Host, Url};

use super::bootstrap::Bootstrap;
use super::transport::{Aging, Connect, InFlight, Wear, connect_tcp, least_busy};

/// 请求的发送端 / The sending half requests go through
pub(crate) type H2Sender = SendRequest<Bytes>;

/// 连接空闲这么久就关掉（见 `transport::Aging`），和 reqwest 连接池的空闲时限（`pool_idle_timeout`）一样：家用路由器的
/// NAT 会悄悄忘掉空闲久了的 TCP 连接，在那样的连接上发的请求只会等到超时
/// A connection idle this long is closed (see `transport::Aging`), the same limit as the reqwest
/// pool's (`pool_idle_timeout`): a home router's NAT quietly forgets TCP connections idle that
/// long, and a request sent on one would only wait for its timeout
pub(crate) const DOH_IDLE_TIMEOUT: Duration = Duration::from_secs(90);

/// 连接的接收窗口，DoQ 的连接和经 reqwest 的 HTTP/2 也用它（见 `transport::doq_transport`、
/// `DohClient::build_client`）。每个流的窗口用协议默认的 64 KiB，正好装下最长的 DNS 消息；连接的窗口大得多，同时在途的
/// 回答不用等窗口更新，又给一条连接上缓冲的字节封了顶。hyper 用 PING 估算带宽时延积再放大窗口，DNS 回答很小，用不着
/// The connection's receive window, which DoQ connections and HTTP/2 through reqwest use too
/// (see `transport::doq_transport` and `DohClient::build_client`). Each stream keeps the
/// protocol's default 64 KiB, which holds the longest DNS message; the connection's is much
/// larger, so answers in flight together never wait for a window update, while it caps what one
/// connection can have buffered. hyper widens its windows from PING-based bandwidth-delay
/// estimates, which DNS answers are far too small to need
pub(super) const CONNECTION_WINDOW: u32 = 1 << 20;

/// 一条打开的连接 / One open connection
struct H2Conn {
    sender: H2Sender,
    /// 用它的请求都记上自己的期限，它的看守任务按它老化（见 [`watch`]）/ Every request using it notes its
    /// deadline here, and its watching task ages it by this (see [`watch`])
    wear: Arc<Wear>,
}

/// 一个连接位：最多一条连接 / One connection slot: at most one connection
struct Slot {
    /// 位上的连接，建连的任务建好了放进来 / The slot's connection, put here by the connecting task once made
    conn: ArcSwapOption<H2Conn>,
    /// 在建的连接、建连失败以后的退避（见 [`Connect`]）/ The connection being made and the backing off
    /// after a failed connect (see [`Connect`])
    connecting: parking_lot::Mutex<Connect>,
    /// 这个位上还没答完的请求数 / Requests on this slot not yet answered
    in_flight: AtomicUsize,
}

/// 一个 DoH 上游的 HTTP/2 连接：每个工作线程一个位，平常只用第一个
/// （见 [`BUSY_AT`](super::transport::BUSY_AT)）
/// One DoH upstream's HTTP/2 connections: a slot per worker thread, normally only the first in
/// use (see [`BUSY_AT`](super::transport::BUSY_AT))
pub(crate) struct H2Link {
    slots: Box<[Arc<Slot>]>,
    /// 这个上游握手时没选 h2：之后的请求都交给 reqwest / This upstream did not pick h2 in the handshake: later requests all go to reqwest
    no_h2: Arc<AtomicBool>,
    /// 连接怎样老化：不限最长存活，空闲 [`DOH_IDLE_TIMEOUT`]（测试里可以改短）/ How connections age: no
    /// longest life, idle for [`DOH_IDLE_TIMEOUT`] (shorter in some tests)
    aging: Aging,
}

impl H2Link {
    /// 最多 `connections` 条连接的 H2Link，至少一条 / An H2Link of at most `connections` connections, one at least
    pub(crate) fn new(idle_timeout: Duration, connections: usize) -> Self {
        Self {
            slots: (0..connections.max(1))
                .map(|_| {
                    Arc::new(Slot {
                        conn: ArcSwapOption::empty(),
                        connecting: parking_lot::Mutex::default(),
                        in_flight: AtomicUsize::new(0),
                    })
                })
                .collect(),
            no_h2: Arc::default(),
            aging: Aging::new(Duration::ZERO, idle_timeout),
        }
    }

    /// `slot` 上还能接着开流的现有连接，记上用它的请求的期限 `deadline`；空闲太久的看守任务已经把它从位上拿掉了（见
    /// [`watch`]）
    /// The connection on `slot` if it is still open to new streams, noted with the deadline
    /// `deadline` of the request using it; one idle too long has been taken off the slot by its
    /// watching task already (see [`watch`])
    fn usable(slot: &Slot, deadline: tokio::time::Instant) -> Option<H2Sender> {
        let conn = slot.conn.load_full()?;
        let sender = open_to_new_streams(&conn.sender)?;
        conn.wear.note(deadline);
        Some(sender)
    }

    /// 发请求用的发送端和它占着的连接位：位上有能用的连接就用它，没有就等一条新的（见 [`Connect`]：建连的任务建好了放到
    /// 位上，这个请求再取用；等来的连接在取用之前就没了时不再等下一条）。请求答完（或放弃）之前一直拿着 [`InFlight`]。上游
    /// 没选 h2 时是 None，交给 reqwest。`deadline` 是这个请求的期限
    /// The sender for a request and the slot it holds: the slot's connection when usable, a new
    /// one waited for otherwise (see [`Connect`]: the connecting task puts it on the slot once
    /// made, and this request takes it from there; a connection waited for and gone before it
    /// could be taken is not followed by a wait for another). The [`InFlight`] is kept until the
    /// request is answered (or given up). None when the upstream did not pick h2, for reqwest to
    /// handle. `deadline` is the request's
    pub(crate) async fn sender(
        &self,
        url: &Url,
        tls: &Arc<ClientConfig>,
        bootstrap: &Arc<Bootstrap>,
        deadline: tokio::time::Instant,
    ) -> anyhow::Result<Option<(H2Sender, InFlight<'_>)>> {
        let slot = least_busy(&self.slots, |slot| slot.in_flight.load(Ordering::Relaxed));
        let in_flight = InFlight::enter(&slot.in_flight);
        for waited in [false, true] {
            if self.no_h2.load(Ordering::Relaxed) {
                return Ok(None);
            }
            if let Some(sender) = Self::usable(slot, deadline) {
                return Ok(Some((sender, in_flight)));
            }
            if waited {
                break;
            }
            let attempt = {
                let mut connecting = slot.connecting.lock();
                // 别的请求的连接可能刚放到位上 / Another request's connection may have just been put on the slot
                if let Some(sender) = Self::usable(slot, deadline) {
                    return Ok(Some((sender, in_flight)));
                }
                connecting.attempt(|| {
                    let (url, tls, bootstrap) =
                        (url.clone(), Arc::clone(tls), Arc::clone(bootstrap));
                    let (slot, no_h2, aging) =
                        (Arc::clone(slot), Arc::clone(&self.no_h2), self.aging);
                    async move {
                        match connect(&url, &tls, &bootstrap).await? {
                            Some(sender) => {
                                let wear = Arc::new(Wear::new());
                                let conn = Arc::new(H2Conn {
                                    sender,
                                    wear: Arc::clone(&wear),
                                });
                                tokio::spawn(watch(
                                    Arc::downgrade(&slot),
                                    Arc::downgrade(&conn),
                                    wear,
                                    aging,
                                ));
                                slot.conn.store(Some(conn));
                            }
                            None => no_h2.store(true, Ordering::Relaxed),
                        }
                        Ok(())
                    }
                })?
            };
            attempt.await?;
        }
        anyhow::bail!("doh connection closed as soon as it was made")
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

/// 看着位 `slot` 上的连接 `conn`，用旧了（见 [`Aging`]）就从位上拿掉：接着来的请求另连一条，它自己在还没答完的请求都答完以后
/// 关掉（h2 在最后一个发送端放下、流都结束时发 GOAWAY）。这之前它已经从位上换下去了（断了、连续出错重建）、或者位已经不在了，
/// 就什么都不做
/// Watches the connection `conn` on the slot `slot` and takes it off the slot once worn (see
/// [`Aging`]): requests coming next connect again, and it closes by itself once the requests
/// still unanswered on it are through (h2 sends a GOAWAY once its last sender is let go and its
/// streams are over). One replaced on the slot before then (gone, rebuilt after repeated errors),
/// or a slot gone, is left alone
async fn watch(slot: Weak<Slot>, conn: Weak<H2Conn>, wear: Arc<Wear>, aging: Aging) {
    let why = aging.worn(&wear).await;
    if let (Some(slot), Some(conn)) = (slot.upgrade(), conn.upgrade()) {
        slot.conn.rcu(|current| {
            current
                .clone()
                .filter(|current| !Arc::ptr_eq(current, &conn))
        });
        tracing::debug!(
            why,
            "DoH HTTP/2 connection worn, closing it once its requests are done"
        );
    }
}

/// 连上 `url`：TCP 和 TCP、DoT 上游一样经 `transport::connect_tcp` 连（主机名交给 `bootstrap` 解析，几个地址错开着连），
/// TLS 握手报 h2 和 http/1.1。对方选了 h2 就做 HTTP/2 握手，把连接交给后台任务；没选时是 None
/// Connects to `url`: TCP through `transport::connect_tcp`, as TCP and DoT upstreams are (the
/// host name resolved by `bootstrap`, several addresses connected to staggered), a TLS handshake
/// offering h2 and http/1.1. When the peer picks h2 the HTTP/2 handshake follows and a background
/// task drives the connection; otherwise None
async fn connect(
    url: &Url,
    tls: &Arc<ClientConfig>,
    bootstrap: &Bootstrap,
) -> anyhow::Result<Option<H2Sender>> {
    let host = url.host().context("doh url has no host")?;
    let server_name = match &host {
        Host::Domain(name) => ServerName::try_from(name.to_string()).context("doh server name")?,
        Host::Ipv4(ip) => ServerName::IpAddress(std::net::IpAddr::V4(*ip).into()),
        Host::Ipv6(ip) => ServerName::IpAddress(std::net::IpAddr::V6(*ip).into()),
    };
    let port = url.port_or_known_default().context("doh url has no port")?;
    // 主机写成 URL 里的样子，IPv6 带着方括号 / The host as a URL writes it, an IPv6 one in brackets
    let tcp = connect_tcp(bootstrap, &format!("{host}:{port}"))
        .await
        .context("doh connect failed")?;
    let stream = tokio_rustls::TlsConnector::from(Arc::clone(tls))
        .connect(server_name, tcp)
        .await
        .context("doh tls handshake failed")?;
    if stream.get_ref().1.alpn_protocol() != Some(b"h2") {
        return Ok(None);
    }
    handshake(stream).await.map(Some)
}

/// 一条连接上记着多少个取消了的请求、各记多久。请求被放弃时（时限先到、几个上游竞速它输了）流被取消，上游的回答
/// 可能已经在路上：回答落在还记着的流上就悄悄丢掉；落在忘掉的流上，h2 每一帧都记一次「对方出错」，这个数只增不减，
/// 到 1024 就把连接断开。h2 默认只记 10 个（记 30 秒），照这样，和 UDP 上游一起问、每次都慢一步的 DoH 上游，每个回答都
/// 落在忘掉的流上，一千来个查询连接就断一次。迟到的回答一般几百毫秒内就到，所以记 2 秒、最多记 16384 个：一条连接每秒
/// 取消八千个请求以内都记得住；记满时每个占几百字节，一条连接几兆。超出的照旧算数，那道 1024 的上限留着兜底
/// How many cancelled requests a connection remembers, and for how long each. A request given
/// up (a deadline that came first, a race between upstreams lost) has its stream cancelled while
/// the upstream's answer may be on its way: an answer landing on a stream still remembered is
/// dropped quietly; one landing on a forgotten stream has h2 count each frame as an error by the
/// peer, in a count that only grows, and at 1024 the connection is ended. h2 remembers 10 by
/// default (for 30 seconds), so a DoH upstream asked along with a UDP one and always a step
/// slower would have every answer land on a forgotten stream, its connection ending every
/// thousand queries or so. Late answers mostly arrive within a few hundred milliseconds, so each is
/// remembered for 2 seconds and at most 16384 are: up to eight thousand requests cancelled a
/// second on one connection are all remembered, at a few hundred bytes each when full, a few
/// megabytes a connection. Any beyond that count as before, and the limit of 1024 stays as the
/// backstop
const CANCELLED_REMEMBERED: usize = 16384;
const CANCELLED_REMEMBERED_FOR: Duration = Duration::from_secs(2);

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
        .max_concurrent_reset_streams(CANCELLED_REMEMBERED)
        .reset_stream_duration(CANCELLED_REMEMBERED_FOR)
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
