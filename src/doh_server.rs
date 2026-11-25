//! 入站 DoH（DNS over HTTPS，RFC 8484）服务
//!
//! 架构：TLS 终结 → HTTP/2 或 HTTP/1.1 处理（按 TLS 握手时协商的 ALPN）→ Engine 入口。DNS 报文和 UDP、TCP 走同一个
//! 入口：先由 `Engine::on_the_spot` 当场作答，答不了的交给 `Engine::answer_after_fast_path`，不重复任何 DNS 处理逻辑。
//! TLS 证书/私钥文件变更时热更新 acceptor（如 acme 续期），失败保持旧证书。
//!
//! The inbound DoH (DNS over HTTPS, RFC 8484) server
//!
//! Layout: TLS termination → an HTTP/2 or HTTP/1.1 handler (by the ALPN agreed in the TLS
//! handshake) → the Engine's entry. A DNS message takes the same entry as over UDP and TCP:
//! `Engine::on_the_spot` answers it on the spot when it can, and `Engine::answer_after_fast_path`
//! when it cannot, with no DNS handling of its own. The TLS acceptor is reloaded when the
//! certificate or key file changes (an ACME renewal, say), the old certificate kept on failure.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use arc_swap::ArcSwap;
use bytes::Bytes;
#[cfg(test)]
use hickory_proto::op::{Message, ResponseCode};
#[cfg(test)]
use hickory_proto::serialize::binary::BinDecodable;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::Body;
use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info};

use crate::engine::{Engine, OnTheSpot};
use crate::observe::ClientTransport;
use crate::proto_utils::MAX_QUERY_LEN;
use crate::watcher;

/// 客户端发送完整请求头的时限，也覆盖 keep-alive 连接上等待下一个请求的空闲期；
/// 到期由 hyper 关闭连接。RFC 7766 §6.2.3 建议 DNS 服务端对空闲连接设数秒量级
/// 的超时：10 s 足以让慢链路发完请求头，又不让只发半个请求头的连接无限期占用
/// 一个任务和一个文件描述符。
/// Time a client has to send a complete request head, which also bounds the
/// idle wait for the next request on a keep-alive connection; hyper closes the
/// connection when it expires. RFC 7766 §6.2.3 recommends a DNS server idle
/// timeout in the order of seconds: 10 s leaves a slow link room to finish a
/// request head while keeping half-sent requests from pinning a task and a
/// file descriptor indefinitely.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// POST 请求头之后，客户端最多有这么久发完正文；超时回 408、断开连接。以前只有请求头有时限，
/// 正文发到一半就停的连接会一直占着一个任务和一个文件描述符。
/// Time a client has, once a POST head is in, to send the whole body; past it the
/// server answers 408 and drops the connection. Only the head used to be bounded,
/// so a body that stopped half way held a task and a file descriptor for good.
const BODY_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// A client that connects and never finishes the TLS handshake is dropped after
/// this long, as a silent DNS-over-TCP client is; it used to hold its task and
/// descriptor for good.
/// 连上以后迟迟不完成 TLS 握手的客户端，过这么久就断开，和 DNS over TCP 上不说话的客户端一样；
/// 以前它会一直占着任务和句柄。
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// 写不出去的时限：连接上的一次写或 flush 这么久没有进展，就当它断了（见 [`WriteStall`]）。和 DNS over TCP 写回答的时限
/// 一样
/// How long a write may make no progress: a write or flush on the connection stuck this long
/// means it is gone (see [`WriteStall`]). The same bound as for writing an answer over DNS over TCP
const WRITE_STALL_TIMEOUT: Duration = Duration::from_secs(10);

/// 一条 HTTP/2 连接上最多同时处理这么多个请求（RFC 9113 第 6.5.2 节建议不低于 100）
/// At most this many requests are handled at once on one HTTP/2 connection (RFC 9113
/// section 6.5.2 recommends no fewer than 100)
const MAX_CONCURRENT_STREAMS: u32 = 100;

/// 一条 DoH 连接替客户端缓冲多少。hyper 的默认值是给网页用的：HTTP/1.1 的读缓冲约 400 KiB，HTTP/2 每个流和整条连接的
/// 接收窗口各 1 MiB、每个流的发送缓冲约 400 KiB。一台设备在请求头读完的时限里慢慢发一个超大的头，或者在 GET 的流上
/// 一直发数据，每条连接就能占到几百 KiB 到几 MiB，连接预算（512 条）还没用完，256 MB 的路由器就先没了内存。DNS 消息
/// 最长 [`MAX_QUERY_LEN`]（查询）和 64 KiB（回答），这里留的够装下一个请求头加一条查询，回答比发送缓冲大时分块等窗口
/// How much one DoH connection buffers for a client. hyper's defaults are made for the web:
/// some 400 KiB of HTTP/1.1 read buffer, and for HTTP/2 1 MiB of receive window for each stream
/// and for the connection and some 400 KiB of send buffer per stream. A device sending one huge
/// head slowly within the head-reading deadline, or data on a GET's stream without end, held a
/// few hundred KiB to some MiB per connection, and a 256 MB router ran out of memory before the
/// connection budget (512) did. A DNS message is at most [`MAX_QUERY_LEN`] (a query) and 64 KiB
/// (an answer); what is kept here holds a request head and a query, and an answer larger than
/// the send buffer goes out in pieces as the window allows
mod buffered {
    /// HTTP/1.1 的读缓冲（hyper 最少 8 KiB）/ The HTTP/1.1 read buffer (8 KiB at least in hyper)
    pub(super) const HTTP1: usize = 16 * 1024;
    /// HTTP/2 每个流的接收窗口 / The HTTP/2 receive window of each stream
    pub(super) const STREAM_WINDOW: u32 = 16 * 1024;
    /// HTTP/2 整条连接的接收窗口：正文都是马上读走的，读走的就还回窗口 / The HTTP/2 receive window of
    /// the whole connection: bodies are read at once, and what is read goes back to the window
    pub(super) const CONNECTION_WINDOW: u32 = 64 * 1024;
    /// HTTP/2 每个流的发送缓冲 / The HTTP/2 send buffer of each stream
    pub(super) const SEND: usize = 16 * 1024;
}

/// 入站 DoH 的证书，各个监听口共用：证书或私钥文件换了就换上新的，新的读不了就留着在用的。每个连接握手时取一份当时的，
/// 不用等锁；正在用的连接不受换证书影响。最后一个监听口停下、丢掉它的时候，监视证书文件的线程也停下
/// The inbound DoH certificate, shared by every listener: a change to the certificate or key
/// file brings in the new one, the one in use staying when the new one cannot be read. Each
/// connection takes the one current at its handshake without waiting on a lock, and connections
/// already up are not touched by a change. Dropped with the last listener, it stops the thread
/// watching the files too
pub struct DohCertificate {
    current: Arc<ArcSwap<TlsAcceptor>>,
    /// 证书文件的监视，监视线程起不来时没有 / The watch on the certificate files, none when its thread cannot start
    _watch: Option<watcher::FileWatch>,
}

impl DohCertificate {
    /// 读 `cert_path` 和 `key_path`，读之前先装好监视（见 `watcher::PendingWatch`）：读的时候证书续期了，这次改动排着队，
    /// 照样换上。监视线程起不来只记错误，证书照用，续期的要重启才用上；有位置监视不上的文件（建不起 notify 的监视时是两个
    /// 都是），那里续期的 10 秒以内察觉（见 `watcher::Targets::check`），开始监视时记一条错误。证书读不了时监视不开始，
    /// 什么都不记，只有读不了的那个错误
    /// Reads `cert_path` and `key_path`, watching them before they are read (see
    /// `watcher::PendingWatch`): a renewal made while they are read waits in line and is brought
    /// in all the same. When the watch thread cannot start an error is logged and the
    /// certificate used as read, a renewal waiting for a restart; for a file with places that
    /// cannot be watched (both, when notify's watcher cannot be made), a renewal there is noticed
    /// within 10 s (see `watcher::Targets::check`), an error logged as the watch starts. With the
    /// certificate unreadable the watch does not start and logs nothing, the error being why it
    /// cannot be read alone
    pub fn load(cert_path: &str, key_path: &str) -> anyhow::Result<Arc<Self>> {
        let pending =
            watcher::PendingWatch::new(&[PathBuf::from(cert_path), PathBuf::from(key_path)]);
        let mut read = stamps(cert_path, key_path);
        let current = Arc::new(ArcSwap::from_pointee(build_tls_acceptor(
            cert_path, key_path,
        )?));
        let reloaded = Arc::clone(&current);
        let (cert, key) = (cert_path.to_owned(), key_path.to_owned());
        let watch = pending
            .start("doh-cert-watcher", move |_| {
                reload(&reloaded, &cert, &key, &mut read);
            })
            .inspect_err(|err| error!(cert = cert_path, key = key_path, error = %err, "cannot watch the DoH certificate, a renewed one is not used until restart"))
            .ok();
        Ok(Arc::new(Self {
            current,
            _watch: watch,
        }))
    }
}

/// 证书和私钥读之前什么样（见 `watcher::FileStamp`），不存在的是 None / What the certificate and the
/// key looked like before they were read (see `watcher::FileStamp`), None for one not there
type Stamps = [Option<watcher::FileStamp>; 2];

fn stamps(cert: &str, key: &str) -> Stamps {
    [cert, key].map(|path| watcher::FileStamp::of(Path::new(path)).ok())
}

/// 证书文件改了：换上重新读出来的证书，读不了就留着在用的。两个文件和上次读之前（`read`）一样就不再读：监视给一阵改动
/// 里改了的每个文件各回调一次，续期时证书和私钥一起换，头一次回调已经把两个都读了
///
/// 证书和私钥也会分两阵写到（scp 一个个推，慢路由器上 acme.sh 一个个 `cat >`），先到的那个配着旧的另一个读不了。所以读不了
/// 时在监视线程上等一阵改动最长能等的那么久（见 `watcher::AT_MOST`）再看一次：两个文件这期间又换了就不记，留给那次改动的
/// 回调去读（监视等它写完，Linux 上等写的一方关上文件），只靠核对察觉改动时等下一次核对；还是那一对才记 error，换上了的只记
/// 一条 reloaded。每次回调至多等这一次：一直有人改写读不了的一对，监视线程也照样回去收消息，丢掉监视时不会一直等下去
/// The certificate files changed: the certificate read again goes in, or the one in use stays
/// when it cannot be read. With both files as they were before the last read (`read`) they are
/// not read again: the watch calls back once for each file a burst of changes changed, and a
/// renewal replaces the certificate and the key together, both read by the first callback
///
/// The certificate and the key also arrive in two bursts (pushed one by one with scp, or
/// written one `cat >` at a time by acme.sh on a slow router), the first one in going with the
/// old other one and failing to read. So on a failure the watch thread waits as long as a
/// burst of changes may last (see `watcher::AT_MOST`) and looks once more: with the files
/// changed meanwhile nothing is logged, the read left to that change's own callback (the watch
/// waiting for it to be written, on Linux for the writer to close the file), or to the next
/// check where changes are noticed by the checks alone; only the same pair logs an error, and
/// one brought in logs a single "reloaded". Each callback waits once at most: with a pair that
/// cannot be read rewritten without end the watch thread still goes back to its messages, and
/// dropping the watch does not wait on and on
fn reload(current: &ArcSwap<TlsAcceptor>, cert: &str, key: &str, read: &mut Stamps) {
    let now = stamps(cert, key);
    if now == *read {
        debug!(cert, key, "DoH TLS certificate unchanged, not read again");
        return;
    }
    *read = now;
    let built = build_tls_acceptor(cert, key);
    if built.is_err() {
        std::thread::sleep(watcher::AT_MOST);
        if stamps(cert, key) != *read {
            debug!(cert, key, "DoH TLS certificate changed while waiting");
            return;
        }
    }
    match built {
        Ok(acceptor) => {
            current.store(Arc::new(acceptor));
            info!(cert, key, "DoH TLS certificate reloaded");
        }
        // 默认日志级别是 error：记成 warn 的话，续期失败谁也看不到，直到旧证书过期
        // The default log level is error: logged as a warn, a failed renewal would go unseen
        // until the old certificate expired
        Err(err) => {
            error!(cert, key, error = %format!("{err:#}"), "DoH TLS certificate reload failed, keeping the one in use");
        }
    }
}

/// 在 `listener` 上接入站 DoH 连接，证书是 `certificate`，请求路径是 `doh_path`；一直接下去，不返回。`[::]` 时
/// IPv4、IPv6 各有一个监听口（见 `listeners::bind_tcp_listeners`），各跑一个，共用一份证书
/// Accepts inbound DoH connections on `listener` with `certificate`, requests served on
/// `doh_path`; it goes on for good and never returns. For `[::]` IPv4 and IPv6 each have a
/// listener (see `listeners::bind_tcp_listeners`), each running one, sharing the certificate
pub async fn run_doh(
    listener: TcpListener,
    certificate: Arc<DohCertificate>,
    engine: Engine,
    doh_path: Arc<str>,
) -> ! {
    // 引擎只共享不复制：每个请求只加一次引用计数，不再复制整个 Engine（二十多个 Arc）
    // The engine is shared, not copied: each request takes one reference count instead of
    // copying the whole Engine (twenty-odd Arcs)
    let engine = Arc::new(engine.with_client_transport(ClientTransport::Doh));
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                // 接受出错不退出循环，记法和 TCP 监听器一样（见 `listeners::tcp::run_tcp`）/ Never end the loop
                // on an accept error, logged as the TCP listener logs it (see `listeners::tcp::run_tcp`)
                crate::warn_sparse!(
                    event = "doh_accept_failed",
                    error = %err,
                    "DoH accept failed, retrying"
                );
                tokio::time::sleep(crate::socket_utils::accept_retry_delay(&err)).await;
                continue;
            }
        };
        // 和 DNS over TCP 一样关掉 Nagle：TLS 握手和应答都是几段小写入，开着 Nagle 时后一段要等对端的
        // 延迟确认，新连接上第一个请求多等约 40 ms
        // Nagle is turned off, as for DNS over TCP: the TLS handshake and the answers are a few
        // small writes, and with Nagle on a later one waits for the peer's delayed ACK, adding
        // about 40 ms to the first request on a new connection
        stream.set_nodelay(true).ok();
        // 内存不够时不接新连接，已有的连接照常 / With too little memory no new connection is taken, and those there go on
        let Some(permit) = engine.connection_permit(peer.ip()) else {
            continue;
        };
        let acceptor = certificate.current.load_full();
        let engine = Arc::clone(&engine);
        let doh_path = Arc::clone(&doh_path);
        tokio::spawn(async move {
            let _permit = permit;
            match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                Ok(Ok(tls_stream)) => {
                    // 客户端在握手时选了 h2 就走 HTTP/2，否则 HTTP/1.1 / HTTP/2 when the client
                    // picked h2 during the handshake, HTTP/1.1 otherwise
                    let http2 = tls_stream.get_ref().1.alpn_protocol() == Some(b"h2");
                    // hyper 1.x 需要 TokioIo 适配器包装 IO
                    let io = WriteStall::new(hyper_util::rt::TokioIo::new(tls_stream));
                    if http2 {
                        serve_http2(io, peer, engine, doh_path).await;
                        return;
                    }
                    let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                        let engine = Arc::clone(&engine);
                        let doh_path = Arc::clone(&doh_path);
                        async move { handle_doh_request(req, peer, &engine, &doh_path).await }
                    });
                    // hyper 只在装了 timer 时才执行 header_read_timeout，否则静默
                    // 禁用；TokioTimer 是零大小类型，每连接无额外开销。
                    // hyper only enforces header_read_timeout when a timer is
                    // installed and silently disables it otherwise; TokioTimer is
                    // zero-sized, so this costs nothing per connection.
                    let _ = http1::Builder::new()
                        .timer(hyper_util::rt::TokioTimer::new())
                        .max_buf_size(buffered::HTTP1)
                        .header_read_timeout(HEADER_READ_TIMEOUT)
                        .keep_alive(true)
                        .serve_connection(io, svc)
                        .await;
                }
                Ok(Err(e)) => {
                    crate::warn_sparse!(
                        event = "doh_tls_handshake_failed",
                        error = %e,
                        client_ip = %peer.ip(),
                        "DoH TLS handshake failed"
                    );
                }
                Err(_) => {
                    // Quiet, like a silent DNS-over-TCP client timing out: a flood of
                    // them must not flood the log as well
                    // 不出声，和 DNS over TCP 上不说话的客户端超时一样：一大批这样的连接不能把日志也刷满
                    debug!(%peer, "DoH TLS handshake timed out");
                }
            }
        });
    }
}

/// 一条 HTTP/2 连接上请求的进出：正在处理几个、最后一个什么时候结束
/// The comings and goings of requests on one HTTP/2 connection: how many are being
/// handled, and when the last one ended
struct Http2Activity {
    started: tokio::time::Instant,
    in_flight: std::sync::atomic::AtomicUsize,
    /// 最后一个请求结束时离连接建立多少毫秒 / When the last request ended, in milliseconds since the connection was made
    last_end_ms: std::sync::atomic::AtomicU64,
}

impl Http2Activity {
    fn new() -> Self {
        Self {
            started: tokio::time::Instant::now(),
            in_flight: std::sync::atomic::AtomicUsize::new(0),
            last_end_ms: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// 连接空了多久；有请求在处理时没有空 / How long the connection has been idle; never while a request is being handled
    fn idle_for(&self) -> Option<Duration> {
        use std::sync::atomic::Ordering;

        if self.in_flight.load(Ordering::Acquire) > 0 {
            return None;
        }
        let last_end = Duration::from_millis(self.last_end_ms.load(Ordering::Acquire));
        Some(self.started.elapsed().saturating_sub(last_end))
    }
}

/// 一个请求在处理：放下时记下结束的时间 / A request being handled: dropping it records when it ended
struct Http2Request(Arc<Http2Activity>);

impl Http2Request {
    fn start(activity: &Arc<Http2Activity>) -> Self {
        activity
            .in_flight
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        Self(Arc::clone(activity))
    }
}

impl Drop for Http2Request {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering;

        let ended = u64::try_from(self.0.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.0.last_end_ms.fetch_max(ended, Ordering::AcqRel);
        self.0.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

/// 写不出去就断开的连接：一次写或 flush 卡了 [`WRITE_STALL_TIMEOUT`] 没有进展，报 TimedOut，hyper 随之关掉连接。只发不读
/// 的客户端以前能让连接一直卡在写上：HTTP/1.1 流水线发来的请求答不出去，读请求头的时限也就轮不到
/// A connection dropped once it cannot be written: a write or flush stuck for
/// [`WRITE_STALL_TIMEOUT`] without progress fails with TimedOut, and hyper closes the connection.
/// A client sending without reading used to keep a connection stuck on a write for good: the
/// answers to pipelined HTTP/1.1 requests never went out, so the time limit on reading a
/// request head never came round
struct WriteStall<I> {
    io: I,
    /// 从卡住那一刻起的时限，有进展就清掉 / The deadline from when it got stuck, cleared on progress
    stalled: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
}

impl<I> WriteStall<I> {
    fn new(io: I) -> Self {
        Self { io, stalled: None }
    }

    /// 一次写的结果：有进展就清掉时限，卡住就等着时限 / What a write came to: progress clears the
    /// deadline, being stuck waits on it
    fn progress<T>(
        &mut self,
        cx: &mut std::task::Context<'_>,
        poll: std::task::Poll<std::io::Result<T>>,
    ) -> std::task::Poll<std::io::Result<T>> {
        use std::future::Future;
        use std::task::Poll;

        if poll.is_ready() {
            self.stalled = None;
            return poll;
        }
        let stalled = self
            .stalled
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(WRITE_STALL_TIMEOUT)));
        match stalled.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(Err(std::io::ErrorKind::TimedOut.into())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<I: hyper::rt::Read + Unpin> hyper::rt::Read for WriteStall<I> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl<I: hyper::rt::Write + Unpin> hyper::rt::Write for WriteStall<I> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let poll = std::pin::Pin::new(&mut self.io).poll_write(cx, buf);
        self.progress(cx, poll)
    }

    fn poll_write_vectored(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let poll = std::pin::Pin::new(&mut self.io).poll_write_vectored(cx, bufs);
        self.progress(cx, poll)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let poll = std::pin::Pin::new(&mut self.io).poll_flush(cx);
        self.progress(cx, poll)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let poll = std::pin::Pin::new(&mut self.io).poll_shutdown(cx);
        self.progress(cx, poll)
    }
}

/// HTTP/2 连接：一条连接上的请求同时处理，每个流照样经 [`handle_doh_request`]。空着
/// [`HEADER_READ_TIMEOUT`]（没有请求在处理，也没有新请求来）就发 GOAWAY 关掉，和 HTTP/1.1 keep-alive 连接
/// 空着的时限一样；还没发完的请求由它自己的时限管。GOAWAY 以后再过 [`HEADER_READ_TIMEOUT`] 还没关上就断开：优雅关闭
/// 要等客户端回 PING，不回的客户端以前能让连接一直开着
/// An HTTP/2 connection: its requests are handled at once, each stream through
/// [`handle_doh_request`] as before. Idle for [`HEADER_READ_TIMEOUT`] (nothing being handled and
/// nothing new coming) it is closed with GOAWAY, the same bound as an idle HTTP/1.1 keep-alive
/// connection; a request still arriving is bounded by its own limits. Not closed another
/// [`HEADER_READ_TIMEOUT`] after the GOAWAY, it is dropped: a graceful close waits for the client
/// to answer a PING, and a client that never did used to keep the connection open for good
async fn serve_http2<I>(io: I, peer: SocketAddr, engine: Arc<Engine>, doh_path: Arc<str>)
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let activity = Arc::new(Http2Activity::new());
    let svc = {
        let activity = Arc::clone(&activity);
        service_fn(move |req: Request<hyper::body::Incoming>| {
            let request = Http2Request::start(&activity);
            let engine = Arc::clone(&engine);
            let doh_path = Arc::clone(&doh_path);
            async move {
                let _request = request;
                handle_doh_request(req, peer, &engine, &doh_path).await
            }
        })
    };
    let conn = http2::Builder::new(hyper_util::rt::TokioExecutor::new())
        .timer(hyper_util::rt::TokioTimer::new())
        .max_concurrent_streams(MAX_CONCURRENT_STREAMS)
        .initial_stream_window_size(buffered::STREAM_WINDOW)
        .initial_connection_window_size(buffered::CONNECTION_WINDOW)
        .max_send_buf_size(buffered::SEND)
        .serve_connection(io, svc);
    tokio::pin!(conn);
    // 发了 GOAWAY 以后最晚什么时候断开 / When at the latest to drop it once the GOAWAY is out
    let mut closing: Option<tokio::time::Instant> = None;
    // 被叫醒后先让出一轮再干活，同一轮答好的请求就能一次写出去。不让的话，答完第一个请求时唤醒的连接任务排在
    // 最前面，马上写出这一个回答，一轮的回答各写一次；连接关了 Nagle，每次写就是一个包
    // Once woken, yield one round before working, so the requests answered during that round
    // go out in one write. Without it the connection task woken by the first answer runs
    // next and writes that answer alone, one write per answer; with Nagle off on the
    // connection, each write is a packet
    let mut yielded = false;
    loop {
        // 下一次看看空了没有：最早也要在最后一个请求结束 HEADER_READ_TIMEOUT 以后；关着的时候是断开的期限 / When to
        // look again whether it is idle: no earlier than HEADER_READ_TIMEOUT after the last request
        // ended; while closing, the deadline for dropping it
        let wake = closing.unwrap_or_else(|| {
            tokio::time::Instant::now()
                + HEADER_READ_TIMEOUT.saturating_sub(activity.idle_for().unwrap_or_default())
        });
        let served = std::future::poll_fn(|cx| {
            yielded = !yielded;
            if yielded {
                cx.waker().wake_by_ref();
                return std::task::Poll::Pending;
            }
            conn.as_mut().poll(cx)
        });
        tokio::select! {
            _ = served => return,
            () = tokio::time::sleep_until(wake) => {
                if closing.is_some() {
                    return;
                }
                if activity.idle_for().is_some_and(|idle| idle >= HEADER_READ_TIMEOUT) {
                    conn.as_mut().graceful_shutdown();
                    closing = Some(tokio::time::Instant::now() + HEADER_READ_TIMEOUT);
                }
            }
        }
    }
}

/// 处理单个 DoH 请求 / Handle a single DoH request
async fn handle_doh_request(
    req: Request<hyper::body::Incoming>,
    peer: SocketAddr,
    engine: &Engine,
    doh_path: &str,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    // RFC 8484 §4.1: POST with application/dns-message
    // RFC 8484 §4.1.5: GET with ?dns=base64url
    // 正文只有 POST 读；GET 的先丢掉，免得客户端在它的流上发的数据一直攒在窗口里，攒到回答发出去
    // Only a POST's body is read; a GET's goes at once, lest the data a client sends on its stream
    // pile up in the window until the answer is out
    let (parts, body) = req.into_parts();
    if parts.uri.path() != doh_path {
        return Ok(error_response(StatusCode::NOT_FOUND));
    }
    let dns_wire = match parts.method {
        // RFC 8484 第 4.1 节：POST 的正文是 application/dns-message，别的媒体类型回 415 / RFC 8484
        // section 4.1: a POST's body is application/dns-message, and another media type gets 415
        Method::POST if !is_dns_message(&parts.headers) => {
            return Ok(error_response(StatusCode::UNSUPPORTED_MEDIA_TYPE));
        }
        Method::POST => {
            // 先看 Content-Length：声明超限的请求一个字节都不读；再用 Limited 给
            // body 本身封顶，分块传输或与声明不符的发送方也只能让服务端缓冲
            // MAX_QUERY_LEN 字节。此前 body 先被整个收进内存再比较长度。
            // Check Content-Length first so a request that declares an oversized
            // body is refused without reading any of it, then cap the body itself
            // so chunked or lying senders cannot make the server buffer more than
            // MAX_QUERY_LEN. Previously the whole body was collected before the
            // length was compared.
            let declared = body.size_hint().exact();
            if declared.is_some_and(|len| len > MAX_QUERY_LEN as u64) {
                return Ok(error_response(StatusCode::PAYLOAD_TOO_LARGE));
            }
            let body = Limited::new(body, MAX_QUERY_LEN).collect();
            // 正文几乎总是和请求头一起到：先看一眼，到齐了就不必开定时器；没到齐才计时
            // The body nearly always arrives with the head: a first look that finds it whole
            // needs no timer, which is armed only when it is still coming
            let mut body = std::pin::pin!(body);
            let collected = match futures::FutureExt::now_or_never(body.as_mut()) {
                Some(collected) => Ok(collected),
                None => tokio::time::timeout(BODY_READ_TIMEOUT, body).await,
            };
            match collected {
                Ok(Ok(collected)) => collected.to_bytes(),
                Ok(Err(err)) if err.is::<LengthLimitError>() => {
                    return Ok(error_response(StatusCode::PAYLOAD_TOO_LARGE));
                }
                Ok(Err(_)) => return Ok(error_response(StatusCode::BAD_REQUEST)),
                Err(_) => return Ok(error_response(StatusCode::REQUEST_TIMEOUT)),
            }
        }
        Method::GET => {
            drop(body);
            match extract_get_dns_param(parts.uri.query().unwrap_or("")) {
                Some(data) => data,
                None => return Ok(error_response(StatusCode::BAD_REQUEST)),
            }
        }
        // 路径对、方法不对是 405，带上答得了的方法（RFC 9110 第 15.5.6 节）；以前和路径不对一样回 404
        // The right path with the wrong method is 405, naming the methods answered (RFC 9110
        // section 15.5.6); it used to get 404, as a wrong path does
        _ => {
            let mut response = error_response(StatusCode::METHOD_NOT_ALLOWED);
            response.headers_mut().insert(
                hyper::header::ALLOW,
                hyper::header::HeaderValue::from_static("GET, POST"),
            );
            return Ok(response);
        }
    };

    // QR=1 的应答不是查询，和报文太短时一样回 400（见 `OnTheSpot::Drop`）
    // A response with QR=1 is no query and gets 400, as a message too short does (see
    // `OnTheSpot::Drop`)
    Ok(match process_dns_wire(&dns_wire, peer, engine).await {
        Some(answer) => dns_message_response(&dns_wire, answer),
        None => error_response(StatusCode::BAD_REQUEST),
    })
}

/// 装着 `query` 的 DNS 应答的 200 响应；查询带了填充时应答也填充（见 `reply_padded_as_asked`）
/// A 200 response carrying the DNS answer to `query`, padded when the query was (see
/// `reply_padded_as_asked`)
fn dns_message_response(query: &[u8], answer: Bytes) -> Response<Full<Bytes>> {
    let answer = crate::proto_utils::reply_padded_as_asked(answer, query);
    let mut response = Response::new(Full::new(answer));
    let headers = response.headers_mut();
    headers.insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/dns-message"),
    );
    headers.insert(
        hyper::header::CACHE_CONTROL,
        hyper::header::HeaderValue::from_static("max-age=0"),
    );
    response
}

/// 请求的 Content-Type 是不是 application/dns-message（媒体类型不分大小写，参数不看）
/// Whether the request's Content-Type is application/dns-message (the media type ignoring
/// case, any parameters aside)
fn is_dns_message(headers: &hyper::HeaderMap) -> bool {
    headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/dns-message"))
}

/// 从 GET ?dns=base64url 提取 DNS 报文 / Extract DNS wire from GET ?dns=base64url
fn extract_get_dns_param(query: &str) -> Option<Bytes> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    for pair in query.split('&') {
        if let Some(val) = pair.strip_prefix("dns=") {
            // 不带填充的 base64url 把 n 字节写成 ⌈4n/3⌉ 个字符，比 MAX_QUERY_LEN 字节写出来还长的值不解码，上限和 POST、
            // UDP、TCP 一样 / Unpadded base64url writes n bytes in ⌈4n/3⌉ characters; a value longer than
            // the encoding of MAX_QUERY_LEN bytes is not decoded, the limit POST, UDP and TCP have
            if val.len() > (MAX_QUERY_LEN * 4).div_ceil(3) {
                return None;
            }
            let decoded = URL_SAFE_NO_PAD.decode(val).ok()?;
            if !decoded.is_empty() {
                return Some(Bytes::from(decoded));
            }
        }
    }
    None
}

/// 回答一个 DNS 报文，和 UDP、TCP 走同一个入口（见 `Engine::on_the_spot`）；应答（QR=1）和不足 12 字节的报文没有
/// 回答，为 None
/// Answers one DNS message through the same entry as UDP and TCP (see `Engine::on_the_spot`);
/// None for a response (QR=1) or a message under 12 bytes, which get no answer
async fn process_dns_wire(packet: &[u8], peer: SocketAddr, engine: &Engine) -> Option<Bytes> {
    let mut answer = bytes::BytesMut::new();
    let pre_parsed = match engine.on_the_spot(packet, peer, &mut answer) {
        OnTheSpot::Reply => return Some(answer.freeze()),
        OnTheSpot::Forward(pre_parsed) => pre_parsed,
        OnTheSpot::Drop => return None,
    };
    let Some(_permit) = engine.query_permit(None, peer.ip()) else {
        return Some(crate::proto_utils::servfail_reply(packet));
    };
    // 要等上游的这一路放到堆上：它的状态有 4 KB 多，留在每个请求的 future 里，当场答完的请求也要跟着
    // 搬一遍，HTTP/2 下每个请求还要按这个大小分配
    // The path that waits on an upstream goes on the heap: its state is over 4 KB, and left inside
    // every request's future it is moved along with requests answered on the spot, and under HTTP/2
    // allocated at that size for each of them
    Some(Box::pin(engine.answer_after_fast_path(packet, peer, pre_parsed)).await)
}

fn error_response(status: StatusCode) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

/// Build the TLS acceptor from PEM cert/key files. Single source of truth for
/// both startup and hot reload, so the two paths validate identically.
fn build_tls_acceptor(cert_path: &str, key_path: &str) -> anyhow::Result<TlsAcceptor> {
    let certs = load_certs(cert_path)?;
    anyhow::ensure!(!certs.is_empty(), "no certificates found in {cert_path}");
    let key = load_private_key(key_path)?;

    let mut tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .with_context(|| format!("build TLS server config (cert: {cert_path}, key: {key_path})"))?;
    // 先 HTTP/2 后 HTTP/1.1：两种都会的客户端用 HTTP/2，不发 ALPN 的照旧 HTTP/1.1
    // HTTP/2 before HTTP/1.1: a client that speaks both gets HTTP/2, one that sends no ALPN keeps HTTP/1.1
    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(tls_config)))
}

/// 从 PEM 文件 `path` 读证书链；读不了的错误说是哪个文件 / Reads the certificate chain from the
/// PEM file `path`; an error reading it names the file
fn load_certs(path: &str) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    CertificateDer::pem_file_iter(path)
        .and_then(Iterator::collect)
        .with_context(|| format!("read DoH certificate {path}"))
}

/// 从 PEM 文件 `path` 读私钥；读不了的错误说是哪个文件 / Reads the private key from the PEM file
/// `path`; an error reading it names the file
fn load_private_key(path: &str) -> anyhow::Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_file(path).with_context(|| format!("read DoH private key {path}"))
}

// ============================================================================
// Tests / 单元测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    /// Install rustls crypto provider for tests that create Engine (which internally creates TLS clients).
    #[ctor::ctor]
    fn init_crypto() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

    // ---- extract_get_dns_param ----

    #[test]
    fn test_extract_get_dns_param_valid() {
        // A minimal DNS query for example.com A record
        let dns_wire = [
            0xAB, 0xCD, // TXID
            0x01, 0x00, // Flags: standard query, RD=1
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
            // Question: example.com A IN
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm',
            0, // null terminator
            0x00, 0x01, // QTYPE = A
            0x00, 0x01, // QCLASS = IN
        ];
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(dns_wire);
        let query = format!("dns={encoded}");
        let result = extract_get_dns_param(&query);
        assert!(result.is_some(), "should decode valid base64url");
        assert_eq!(result.unwrap().as_ref(), &dns_wire[..]);
    }

    #[test]
    fn test_extract_get_dns_param_missing_param() {
        assert!(extract_get_dns_param("foo=bar").is_none());
        assert!(extract_get_dns_param("").is_none());
    }

    #[test]
    fn test_extract_get_dns_param_empty_value() {
        assert!(extract_get_dns_param("dns=").is_none());
        assert!(extract_get_dns_param("dns=&foo=bar").is_none());
    }

    #[test]
    fn test_extract_get_dns_param_multiple_params() {
        let dns_wire = [0x00; 12];
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(dns_wire);
        // dns= should be found among multiple params
        let query = format!("foo=bar&dns={encoded}&baz=qux");
        let result = extract_get_dns_param(&query);
        assert!(result.is_some());
        assert_eq!(result.unwrap().as_ref(), &dns_wire[..]);
    }

    #[test]
    fn test_extract_get_dns_param_invalid_base64() {
        assert!(extract_get_dns_param("dns=!!!invalid").is_none());
    }

    /// GET 收的查询和 POST、UDP、TCP 一样最长 `MAX_QUERY_LEN` 字节：不带填充的 base64url 写成 5462 个字符的 4096 字节
    /// 照收，多一个字节的就不解码
    /// A GET query is at most `MAX_QUERY_LEN` bytes, as over POST, UDP and TCP: 4096 bytes,
    /// which unpadded base64url writes in 5462 characters, are taken, and one byte more is not
    /// decoded
    #[test]
    fn a_get_query_is_decoded_up_to_max_query_len() {
        let encode = |len: usize| {
            let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vec![0; len]);
            format!("dns={encoded}")
        };
        let longest = encode(MAX_QUERY_LEN);
        assert_eq!(longest.len() - "dns=".len(), 5462);
        let decoded = extract_get_dns_param(&longest).expect("4096 bytes are decoded");
        assert_eq!(decoded.len(), MAX_QUERY_LEN);
        for len in [MAX_QUERY_LEN + 1, MAX_QUERY_LEN + 2] {
            assert!(extract_get_dns_param(&encode(len)).is_none(), "{len} bytes");
        }
    }

    #[test]
    fn test_extract_get_dns_param_standard_base64url_no_pad() {
        // RFC 8484 uses base64url without padding
        let dns_wire = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x12];
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(dns_wire);
        let result = extract_get_dns_param(&format!("dns={encoded}"));
        assert!(result.is_some());
    }

    // ---- error_response ----

    #[test]
    fn test_error_response_status() {
        let resp = error_response(StatusCode::NOT_FOUND);
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let resp = error_response(StatusCode::BAD_REQUEST);
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let resp = error_response(StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    /// 开着流控、转发给 `upstream` 的引擎，在途已有 1000 个查询，内存剩 `available` 字节
    /// An engine with flow control forwarding to `upstream`, with 1000 queries in flight and
    /// `available` bytes of memory left
    fn engine_with_memory(
        upstream: SocketAddr,
        available: u64,
    ) -> (Engine, Vec<crate::engine::concurrency::PermitGuard>) {
        use crate::engine::memory_watermark::{MemoryLeft, MemoryReading, MemoryWatermark};
        let config: crate::config::PipelineConfig = serde_json::from_value(serde_json::json!({
            "settings": {
                "default_upstream": upstream.to_string(),
                "upstream_timeout_ms": 3000,
                "enable_tcp_fallback": false,
                "flow_control_enabled": true
            },
            "pipelines": [{ "id": "main", "rules": [{
                "name": "all",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": upstream.to_string() }]
            }]}]
        }))
        .unwrap();
        let mut engine = Engine::new(
            crate::matcher::RuntimePipelineConfig::from_config(config).unwrap(),
            "test".to_string(),
        )
        .unwrap();
        let flow = Arc::get_mut(engine.flow_control_state.as_mut().unwrap()).unwrap();
        flow.memory = MemoryWatermark::reading(move || MemoryReading {
            own: 0,
            limits: vec![MemoryLeft {
                total: 1 << 30,
                available,
            }],
        });

        let in_flight = (0..1000).map(|_| engine.permit_manager.acquire()).collect();
        (engine, in_flight)
    }

    /// DoH 进来的查询也看内存：不够时当场回 SERVFAIL，不问上游；够的话算在途，在问上游
    /// A query from DoH goes by memory too: with too little it gets SERVFAIL at once and the
    /// upstream is not asked; with enough it counts as in flight and asks the upstream
    #[tokio::test]
    async fn a_doh_query_is_refused_when_memory_is_short() {
        use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
        use hickory_proto::rr::{Name, RecordType};
        use hickory_proto::serialize::binary::BinDecodable;
        use std::str::FromStr;
        let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = upstream.local_addr().unwrap();
        let mut request = Message::new(7, MessageType::Query, OpCode::Query);
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(
            Name::from_str("short.test.").unwrap(),
            RecordType::A,
        ));
        let query = request.to_vec().unwrap();
        let peer: SocketAddr = "127.0.0.1:53000".parse().unwrap();

        let (engine, _in_flight) = engine_with_memory(address, 0);
        let reply = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            process_dns_wire(&query, peer, &engine),
        )
        .await
        .expect("refused at once");
        let reply = Message::from_bytes(&reply.expect("a DNS answer")).unwrap();
        assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(engine.permit_manager.dropped_requests(), 1);
        let mut buf = [0u8; 512];
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(100),
                upstream.recv_from(&mut buf)
            )
            .await
            .is_err(),
            "the upstream is not asked"
        );

        let (engine, _in_flight) = engine_with_memory(address, 1 << 30);
        let waiting = {
            let (engine, query) = (engine.clone(), query.clone());
            tokio::spawn(async move { process_dns_wire(&query, peer, &engine).await })
        };
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            upstream.recv_from(&mut buf),
        )
        .await
        .expect("the upstream is asked")
        .unwrap();
        assert_eq!(
            engine.permit_manager.inflight(),
            1001,
            "it counts as in flight"
        );
        waiting.abort();
    }

    /// 起一个用自签证书的 DoH 服务端，返回地址、任务和放证书的目录（目录得留着）
    /// Starts a DoH server with a self-signed certificate, giving its address, its task and the
    /// directory holding the certificate (which must be kept)
    async fn doh_server(
        engine: &Engine,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = crate::engine::test_support::write_certificate(dir.path());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let certificate = DohCertificate::load(&cert, &key).unwrap();
        let served = engine.clone();
        let server = tokio::spawn(async move {
            run_doh(listener, certificate, served, Arc::from("/dns-query")).await
        });
        (address, server, dir)
    }

    /// TLS 握手失败的告警说是哪个客户端：客户端连上来发的不是 TLS / The warning of a failed TLS
    /// handshake names the client: one that connects and sends something other than TLS
    #[tokio::test]
    async fn a_failed_tls_handshake_is_logged_with_the_client() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (warnings, guard) = crate::engine::test_support::Warnings::capture();
        let (address, server, _dir) = doh_server(&make_static_engine("NXDOMAIN")).await;
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        // 服务端记下告警、放下连接以后这边才读到头 / The end is read here only after the server has
        // logged the warning and let the connection go
        let mut buf = [0u8; 64];
        while let Ok(Ok(1..)) =
            tokio::time::timeout(std::time::Duration::from_secs(1), stream.read(&mut buf)).await
        {
        }
        drop(guard);
        let lines = warnings.lines();
        assert!(
            lines
                .iter()
                .any(|line| line.contains("DoH TLS handshake failed")
                    && line.contains(r#"event="doh_tls_handshake_failed""#)
                    && line.contains("client_ip=127.0.0.1")),
            "{lines:#?}"
        );
        server.abort();
    }

    /// 内存不够时不接新连接，TLS 握手之前就关掉：连接和握手本身也占内存
    /// With too little memory no new connection is taken, closed before the TLS handshake: a
    /// connection and its handshake hold memory too
    #[tokio::test]
    async fn a_new_doh_connection_is_closed_when_memory_is_short() {
        use tokio::io::AsyncReadExt;
        let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (engine, _in_flight) = engine_with_memory(upstream.local_addr().unwrap(), 0);
        let (address, server, _dir) = doh_server(&engine).await;

        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(std::time::Duration::from_secs(1), stream.read(&mut buf))
            .await
            .expect("closed at once");
        assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
        assert_eq!(engine.permit_manager.dropped_requests(), 1);
        assert_eq!(engine.permit_manager.inflight(), 1000, "it holds nothing");
        server.abort();
    }

    /// 内存紧张时 DoH 也按对端地址算：在途占满的那台设备的请求和新连接被拒，别的设备照常。要从 127.0.0.1 以外的回环地址连，
    /// 只在 Linux 上跑（见 `listeners::tests::connect_from`）
    /// With memory tight DoH goes by the peer address too: the device holding everything in
    /// flight has its requests and new connections refused while another goes on. It connects
    /// from loopback addresses besides 127.0.0.1, so it runs on Linux only (see
    /// `listeners::tests::connect_from`)
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn tight_memory_refuses_only_the_doh_device_holding_the_queries() {
        use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
        use hickory_proto::rr::{Name, RecordType};
        use hickory_proto::serialize::binary::BinDecodable;
        use std::str::FromStr;
        use tokio::io::AsyncReadExt;
        let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut request = Message::new(7, MessageType::Query, OpCode::Query);
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(
            Name::from_str("tight.test.").unwrap(),
            RecordType::A,
        ));
        let query = request.to_vec().unwrap();

        // 余量 64 MiB、两倍 128 MiB：剩 100 MiB 算紧张 / A 64 MiB margin, twice that 128 MiB: 100 MiB left is tight
        let (mut engine, plain) = engine_with_memory(upstream.local_addr().unwrap(), 100 << 20);
        // 测试不必等：内存不够以前问过的设备都算老设备 / A test need not wait: a device that asked before
        // memory ran short counts as known
        Arc::get_mut(engine.flow_control_state.as_mut().unwrap())
            .unwrap()
            .known_before = std::time::Duration::ZERO;
        drop(plain);
        let manager = &engine.permit_manager;
        let heavy: SocketAddr = "127.0.0.4:53000".parse().unwrap();
        // 和它不在同一份的另一台 / Another device, not in the same slot
        let light = (2..=250)
            .map(|n| SocketAddr::from(([127, 0, 0, n], 53000)))
            .find(|peer| {
                manager.slot_of(peer.ip()).counted_in() != manager.slot_of(heavy.ip()).counted_in()
            })
            .unwrap();
        // 它在内存不够以前就在用 / It was in use before memory ran short
        drop(engine.query_permit(None, light.ip()));
        let held: Vec<_> = (0..1000)
            .map(|_| {
                engine
                    .query_permit(None, heavy.ip())
                    .expect("under the floor")
            })
            .collect();

        let reply = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            process_dns_wire(&query, heavy, &engine),
        )
        .await
        .expect("the heavy device is refused at once");
        let reply = Message::from_bytes(&reply.expect("a DNS answer")).unwrap();
        assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
        let waiting = {
            let (engine, query) = (engine.clone(), query.clone());
            tokio::spawn(async move { process_dns_wire(&query, light, &engine).await })
        };
        let mut buf = [0u8; 512];
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            upstream.recv_from(&mut buf),
        )
        .await
        .expect("the light device's request is asked of the upstream")
        .unwrap();

        let (address, server, _dir) = doh_server(&engine).await;
        let connect_from = |local: SocketAddr| async move {
            let socket = tokio::net::TcpSocket::new_v4().unwrap();
            socket.bind(SocketAddr::new(local.ip(), 0)).unwrap();
            socket.connect(address).await.unwrap()
        };
        let mut heavy_stream = connect_from(heavy).await;
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            heavy_stream.read(&mut buf),
        )
        .await
        .expect("its new connection is closed at once");
        assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
        let before = engine.permit_manager.inflight();
        let light_stream = connect_from(light).await;
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while engine.permit_manager.inflight() != before + 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the light device's connection is taken");

        drop((held, light_stream));
        waiting.abort();
        server.abort();
    }

    // ---- process_dns_wire (with static-response Engine) ----

    fn make_static_engine(rcode: &str) -> Engine {
        use crate::config::PipelineConfig;
        use crate::matcher::RuntimePipelineConfig;

        let raw = serde_json::json!({
            "settings": { "default_upstream": "127.0.0.1:5300" },
            "pipelines": [
                {
                    "id": "p",
                    "rules": [
                        {
                            "name": "static",
                            "matchers": [ { "type": "any" } ],
                            "actions": [ { "type": "static_response", "rcode": rcode } ]
                        }
                    ]
                }
            ]
        });
        let cfg: PipelineConfig = serde_json::from_value(raw).expect("parse config");
        let runtime = RuntimePipelineConfig::from_config(cfg).expect("build runtime");
        Engine::new(runtime, "test".to_string()).expect("initialize test engine")
    }

    fn make_dns_query_a(domain: &str, txid: u16) -> Vec<u8> {
        use hickory_proto::op::{Message, OpCode, Query};
        use hickory_proto::rr::{Name, RecordType};
        use std::str::FromStr;

        let mut msg = Message::new(txid, hickory_proto::op::MessageType::Query, OpCode::Query);
        msg.add_query(Query::query(Name::from_str(domain).unwrap(), RecordType::A));
        msg.to_vec().unwrap()
    }

    #[tokio::test]
    async fn test_process_dns_wire_static_nxdomain() {
        let engine = make_static_engine("NXDOMAIN");
        let query = make_dns_query_a("test.example.com", 0x4242);
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let resp = process_dns_wire(&query, peer, &engine)
            .await
            .expect("a DNS answer");

        // Should be a valid DNS response
        assert!(resp.len() >= 12, "response should be >= 12 bytes");
        // TXID preserved
        assert_eq!(resp[0], 0x42, "TXID high byte preserved");
        assert_eq!(resp[1], 0x42, "TXID low byte preserved");
        // QR=1
        assert_eq!(resp[2] & 0x80, 0x80, "QR bit should be set");
        // RCODE = NXDOMAIN (3)
        assert_eq!(resp[3] & 0x0F, 0x03, "RCODE should be NXDOMAIN (3)");
    }

    /// 请求头是标准查询、报文却读不了时回 FORMERR，和 UDP、TCP 一样（RFC 6891 第 6.1.1 节）。以前 DoH 回的是
    /// 只有报文头的 SERVFAIL，客户端分不清是自己发错了还是服务器出了故障，会去重试
    /// A message with a standard query's header that cannot be read is answered FORMERR, as over
    /// UDP and TCP (RFC 6891 section 6.1.1). DoH used to answer a header-only SERVFAIL, from
    /// which a client cannot tell its own mistake from a server failure, and retries
    #[tokio::test]
    async fn an_unreadable_query_is_answered_formerr() {
        let engine = make_static_engine("NOERROR");
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let readable = make_dns_query_a("test.example.com", 0x4242);
        // 两条 OPT 记录（RFC 6891：FORMERR）；问题没写完；问题名里的标签超出报文
        // Two OPT records (RFC 6891: FORMERR); a question cut short; a label in the question
        // name running past the message
        let opt = [0u8, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0];
        let mut two_opts = readable.clone();
        two_opts.extend_from_slice(&opt);
        two_opts.extend_from_slice(&opt);
        two_opts[11] = 2;
        let cut_short = readable[..readable.len() - 3].to_vec();
        let mut long_label = readable[..12].to_vec();
        long_label.extend_from_slice(&[40, b'a', b'b']);
        for (what, query) in [
            ("two OPT records", two_opts),
            ("a question cut short", cut_short),
            ("a label past the message", long_label),
        ] {
            let resp = process_dns_wire(&query, peer, &engine)
                .await
                .expect("a DNS answer");
            assert!(resp.len() >= 12, "{what}");
            assert_eq!(&resp[..2], &[0x42, 0x42], "{what}: the transaction ID");
            assert_eq!(resp[2] & 0x80, 0x80, "{what}: a response");
            assert_eq!(resp[3] & 0x0F, 1, "{what}: FORMERR");
            assert!(
                resp.len() <= query.len(),
                "{what}: no longer than the query"
            );
        }
        // 读得了的照常回答 / A readable one is answered as usual
        let resp = process_dns_wire(&readable, peer, &engine)
            .await
            .expect("a DNS answer");
        assert_eq!(resp[3] & 0x0F, 0);
    }

    #[tokio::test]
    async fn test_process_dns_wire_static_noerror() {
        let engine = make_static_engine("NOERROR");
        let query = make_dns_query_a("ok.example.com", 0x0001);
        let peer: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let resp = process_dns_wire(&query, peer, &engine)
            .await
            .expect("a DNS answer");

        assert!(resp.len() >= 12);
        assert_eq!(resp[0], 0x00, "TXID high byte preserved");
        assert_eq!(resp[1], 0x01, "TXID low byte preserved");
        // RCODE = NOERROR (0)
        assert_eq!(resp[3] & 0x0F, 0x00, "RCODE should be NOERROR (0)");
    }

    /// 不足 12 字节的报文和应答（QR=1）没有 DNS 回答，处理请求时回 400
    /// A message under 12 bytes and a response (QR=1) get no DNS answer, and the request is
    /// answered 400
    #[tokio::test]
    async fn a_short_message_or_a_response_gets_no_dns_answer() {
        let engine = make_static_engine("NXDOMAIN");
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let mut response = make_dns_query_a("test.example.com", 0x4242);
        response[2] |= 0x80;
        for message in [&[0x12, 0x34, 0x00][..], &response] {
            assert_eq!(process_dns_wire(message, peer, &engine).await, None);
        }
    }

    /// 数写了几次的连接：HTTP/2 把攒好的帧写完 flush 一次，一次连接 poll 就 flush 一次，不管有没有东西要写，
    /// 所以只数写过东西的那些 flush
    /// A connection counting its writes: HTTP/2 writes the frames it has gathered, then
    /// flushes. It flushes on every poll of the connection, with or without anything
    /// written, so only the flushes after a write count
    struct CountsWrites<I> {
        inner: hyper_util::rt::TokioIo<I>,
        wrote: bool,
        writes: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl<I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> hyper::rt::Read for CountsWrites<I> {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: hyper::rt::ReadBufCursor<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl<I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> hyper::rt::Write for CountsWrites<I> {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.wrote = true;
            std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if std::mem::take(&mut self.wrote) {
                self.writes
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            std::pin::Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    /// 一条 HTTP/2 连接上同时答好的回答一次写出去，不是答一个写一个：连接关了 Nagle，每次写就是一个包。
    /// 要用多线程运行时：多出来的这些写来自工作线程的 LIFO 优先位，单线程运行时没有它，看不出差别
    /// Answers ready together on an HTTP/2 connection go out in one write, not one write each:
    /// with Nagle off on the connection, each write is a packet. It takes the multi-thread
    /// runtime: those extra writes come from a worker's LIFO slot, which the current-thread
    /// runtime does not have
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn a_round_of_http2_answers_goes_out_in_one_write() {
        use http_body_util::BodyExt;
        use std::sync::atomic::{AtomicUsize, Ordering};

        const REQUESTS: u16 = 32;
        type Sender = hyper::client::conn::http2::SendRequest<http_body_util::Empty<Bytes>>;
        // 用 GET：请求没有正文，一个帧就是一个请求，客户端一次发得完 / GET has no body: one frame is
        // one request, so the client sends them all at once
        async fn ask(mut sender: Sender, txid: u16) {
            let query = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(make_dns_query_a("round.example", txid));
            let request = hyper::Request::get(format!("https://localhost/dns-query?dns={query}"))
                .body(http_body_util::Empty::new())
                .unwrap();
            let response = sender.send_request(request).await.expect("answered");
            assert_eq!(response.status(), hyper::StatusCode::OK);
            let body = response.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(u16::from_be_bytes([body[0], body[1]]), txid);
        }

        let (client, server) = tokio::io::duplex(1 << 20);
        let writes = Arc::new(AtomicUsize::new(0));
        tokio::spawn(serve_http2(
            CountsWrites {
                inner: hyper_util::rt::TokioIo::new(server),
                wrote: false,
                writes: Arc::clone(&writes),
            },
            "127.0.0.1:53000".parse().unwrap(),
            Arc::new(make_static_engine("NXDOMAIN")),
            Arc::from("/dns-query"),
        ));
        let (sender, conn) = hyper::client::conn::http2::handshake(
            hyper_util::rt::TokioExecutor::new(),
            hyper_util::rt::TokioIo::new(client),
        )
        .await
        .expect("http2 handshake");
        tokio::spawn(conn);
        // 先问一次，握手和设置帧的写都算在这之前 / One question first, so that the writes of the
        // handshake and the settings come before the count
        ask(sender.clone(), 0).await;
        let before = writes.load(Ordering::Relaxed);
        // 放在工作线程上一起发：一次 poll 把请求都排好，客户端的连接任务一次发出去，服务端一次读到
        // Sent together on the worker: one poll queues them all, the client's connection task
        // sends them at once and the server reads them at once
        tokio::spawn(futures::future::join_all(
            (1..=REQUESTS).map(|txid| ask(sender.clone(), txid)),
        ))
        .await
        .unwrap();
        let written = writes.load(Ordering::Relaxed) - before;
        assert!(
            written <= usize::from(REQUESTS) / 4,
            "{written} writes for {REQUESTS} answers"
        );
    }

    /// 写卡住 WRITE_STALL_TIMEOUT 没有进展就报 TimedOut：对端不读，写满以后再写的那一次到期失败
    /// A write stuck for WRITE_STALL_TIMEOUT without progress fails with TimedOut: with the peer not
    /// reading, the write after the buffer fills fails at the deadline
    #[tokio::test(start_paused = true)]
    async fn a_write_stuck_for_the_stall_timeout_fails() {
        use hyper::rt::Write;

        let (near, _far) = tokio::io::duplex(16);
        let mut io = WriteStall::new(hyper_util::rt::TokioIo::new(near));
        let room = std::future::poll_fn(|cx| std::pin::Pin::new(&mut io).poll_write(cx, &[0; 16]));
        assert_eq!(room.await.unwrap(), 16, "room for one");
        let started = tokio::time::Instant::now();
        let stuck = std::future::poll_fn(|cx| std::pin::Pin::new(&mut io).poll_write(cx, &[0; 16]))
            .await
            .expect_err("nobody reads");
        assert_eq!(stuck.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(started.elapsed(), WRITE_STALL_TIMEOUT);
    }

    /// 空着的 HTTP/2 连接发了 GOAWAY，客户端不理（连 PING 都不回），再过 HEADER_READ_TIMEOUT 就断开。以前优雅关闭一直等
    /// 客户端回 PING，连接永远开着
    /// An idle HTTP/2 connection sent its GOAWAY and the client ignores it (not even answering the
    /// PING): it is dropped HEADER_READ_TIMEOUT later. The graceful close used to wait for the
    /// client's PING for good, the connection staying open forever
    #[tokio::test(start_paused = true)]
    async fn an_http2_client_ignoring_the_goaway_is_dropped() {
        let (client, server) = tokio::io::duplex(1 << 16);
        let started = tokio::time::Instant::now();
        let served = tokio::spawn(serve_http2(
            hyper_util::rt::TokioIo::new(server),
            "127.0.0.1:53000".parse().unwrap(),
            Arc::new(make_static_engine("NXDOMAIN")),
            Arc::from("/dns-query"),
        ));
        // 握手以后客户端的连接不再驱动：它什么也不读、什么也不回 / After the handshake the client's
        // connection is driven no more: it reads nothing and answers nothing
        let (_requests, connection) = h2::client::handshake(client).await.expect("handshake");
        tokio::time::timeout(HEADER_READ_TIMEOUT * 3, served)
            .await
            .expect("dropped")
            .unwrap();
        assert_eq!(started.elapsed(), HEADER_READ_TIMEOUT * 2);
        drop(connection);
    }

    /// HTTP/2 的流最多替客户端缓冲一个窗口（[`buffered::STREAM_WINDOW`]）：正文还没发的 POST 开着流，客户端最多能往里塞
    /// 这么多。以前窗口是 hyper 默认的 1 MiB，每个这样的流能占 1 MiB
    /// An HTTP/2 stream buffers at most one window for the client ([`buffered::STREAM_WINDOW`]):
    /// with a POST whose body is yet to come holding its stream open, the client may put this
    /// much in and no more. The window used to be hyper's default 1 MiB, each such stream
    /// holding 1 MiB
    #[tokio::test]
    async fn an_http2_stream_buffers_at_most_its_window() {
        let (client, server) = tokio::io::duplex(1 << 20);
        tokio::spawn(serve_http2(
            hyper_util::rt::TokioIo::new(server),
            "127.0.0.1:53000".parse().unwrap(),
            Arc::new(make_static_engine("NXDOMAIN")),
            Arc::from("/dns-query"),
        ));
        let (requests, connection) = h2::client::handshake(client).await.expect("handshake");
        tokio::spawn(connection);
        let mut requests = requests.ready().await.expect("ready");
        // 先答完一个，双方的设置就都交换过了 / One answered first, so both sides' settings are exchanged
        let query = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(make_dns_query_a("window.example", 1));
        let get = hyper::Request::get(format!("https://localhost/dns-query?dns={query}"))
            .body(())
            .unwrap();
        let (answered, _) = requests.send_request(get, true).expect("sent");
        assert_eq!(answered.await.expect("answered").status(), StatusCode::OK);

        let post = hyper::Request::post("https://localhost/dns-query")
            .header(hyper::header::CONTENT_TYPE, "application/dns-message")
            .body(())
            .unwrap();
        let (_answer, mut body) = requests.send_request(post, false).expect("sent");
        body.reserve_capacity(1 << 20);
        let granted = std::future::poll_fn(|cx| body.poll_capacity(cx))
            .await
            .expect("capacity")
            .expect("granted");
        assert_eq!(granted, buffered::STREAM_WINDOW as usize);
    }

    // ---- build_tls_acceptor ----

    #[test]
    fn test_build_tls_acceptor_rejects_empty_cert_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, "").expect("write empty cert");
        std::fs::write(&key_path, "not a pem").expect("write key");

        let Err(err) = build_tls_acceptor(cert_path.to_str().unwrap(), key_path.to_str().unwrap())
        else {
            panic!("empty cert file must be rejected");
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("no certificates"), "unexpected error: {msg}");
    }

    #[test]
    fn test_build_tls_acceptor_accepts_generated_pair() {
        use rcgen::{CertificateParams, KeyPair};

        let dir = tempfile::tempdir().expect("tempdir");
        let params = CertificateParams::new(vec!["localhost".to_string()]).expect("params");
        let key_pair = KeyPair::generate().expect("generate key pair");
        let cert = params.self_signed(&key_pair).expect("self-signed cert");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, cert.pem()).expect("write cert pem");
        std::fs::write(&key_path, key_pair.serialize_pem()).expect("write key pem");

        assert!(
            build_tls_acceptor(cert_path.to_str().unwrap(), key_path.to_str().unwrap()).is_ok(),
            "valid cert/key pair must build an acceptor"
        );
    }

    /// 读完证书马上续期，续上的照样换上：监视在读证书之前就装好了。以前先读后监视，这中间的续期要等下一次改动才用上
    /// A renewal right after the certificate is read is brought in all the same: the watch is
    /// in place before the certificate is read. It used to be read before being watched, and a
    /// renewal in between was used only after the next change
    #[tokio::test]
    async fn a_renewal_right_after_the_certificate_is_read_is_used() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = crate::engine::test_support::write_certificate(dir.path());
        let certificate = DohCertificate::load(&cert, &key).unwrap();
        let read = certificate.current.load_full();
        crate::engine::test_support::write_certificate(dir.path());
        tokio::time::timeout(Duration::from_secs(5), async {
            while Arc::ptr_eq(&certificate.current.load_full(), &read) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the renewed certificate is used");
    }

    /// 证书的文件有位置监视不上（这里是进得去、列不出的目录，像 inotify 的监视数用完时那样装不上监视）：证书照样用上，
    /// 开始监视时每个这样的文件记一条错误，说那里的改动 10 秒以内察觉，日志里只有这两条；之后那里续期了，核对看出来，换上
    /// 新证书。root 列得出这样的目录，也监视得上，没有要看的
    /// The certificate's files have places that cannot be watched (here a directory that can
    /// be entered, not listed, refusing a watch as when inotify's watches run out): the
    /// certificate is used all the same, and as the watch starts one error is logged for each
    /// such file, saying changes there are noticed within 10 s, those two being all the log has;
    /// a renewal there afterwards is told by the check and the new certificate goes in. root
    /// lists such a directory and watches it, with nothing to see
    #[cfg(target_os = "linux")]
    #[test]
    fn a_renewal_where_the_watch_cannot_see_is_used_after_the_check() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = crate::engine::test_support::write_certificate(dir.path());
        let mode = |mode| {
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(mode)).unwrap();
        };
        mode(0o300);
        if std::fs::read_dir(dir.path()).is_ok() {
            mode(0o700);
            return;
        }
        let _check = crate::watcher::check_every(Duration::from_millis(100));
        let (warnings, guard) = crate::engine::test_support::Warnings::capture();
        let certificate = DohCertificate::load(&cert, &key);
        drop(guard);
        let renewed = certificate.as_ref().ok().map(|certificate| {
            let read = certificate.current.load_full();
            crate::engine::test_support::write_certificate(dir.path());
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while Arc::ptr_eq(&certificate.current.load_full(), &read)
                && std::time::Instant::now() < deadline
            {
                std::thread::sleep(Duration::from_millis(20));
            }
            !Arc::ptr_eq(&certificate.current.load_full(), &read)
        });
        mode(0o700);
        assert!(certificate.is_ok(), "the certificate is used as read");
        let lines = warnings.lines();
        assert_eq!(lines.len(), 2, "{lines:#?}");
        for file in [&cert, &key] {
            let said: Vec<&String> = lines
                .iter()
                .filter(|line| line.contains(&format!("path={file} ")))
                .collect();
            assert_eq!(said.len(), 1, "one error for {file}: {lines:#?}");
            assert!(
                said[0].contains(crate::watcher::SEEN_WITHIN),
                "{file}: {lines:#?}"
            );
        }
        assert_eq!(renewed, Some(true), "the renewal is told by the check");
    }

    /// 证书读不了（证书目录还不存在：还没跑 certbot、目录名写错）时监视不开始，日志里不说续期怎样，只有读不了的那个错误
    /// （由调用的一方记）
    /// With the certificate unreadable (its directory not there yet: certbot not run, the
    /// directory misspelled) the watch does not start, and the log says nothing of renewals, the
    /// error being why it cannot be read alone (logged by the caller)
    #[test]
    fn an_unreadable_certificate_logs_nothing_of_its_watch() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("live/example.org");
        let (cert, key) = (missing.join("cert.pem"), missing.join("key.pem"));
        let (warnings, guard) = crate::engine::test_support::Warnings::capture();
        let certificate = DohCertificate::load(cert.to_str().unwrap(), key.to_str().unwrap());
        drop(guard);
        assert!(certificate.is_err());
        assert_eq!(warnings.lines(), Vec::<String>::new());
    }

    /// 证书和私钥在 A/tls 里，A 改名换掉（换发布目录那样，`mv A A.old; mv A.new A`）：只有 A/tls 在监视，事件一个都没有，
    /// inotify 的监视跟着 A.old/tls 走；核对看出来，换上新目录里的证书
    /// The certificate and key in A/tls, A swapped by renames (as a release directory is,
    /// `mv A A.old; mv A.new A`): A/tls alone is watched, no event comes, and inotify's watch
    /// follows A.old/tls; the check tells, and the certificate in the new directory goes in
    #[cfg(unix)]
    #[tokio::test]
    async fn a_certificate_directory_swapped_above_is_used_after_the_check() {
        let root = tempfile::tempdir().unwrap();
        let real = std::fs::canonicalize(root.path()).unwrap();
        for at in ["A/tls", "A.new/tls"] {
            std::fs::create_dir_all(real.join(at)).unwrap();
            crate::engine::test_support::write_certificate(&real.join(at));
        }
        let (cert, key) = (real.join("A/tls/cert.pem"), real.join("A/tls/key.pem"));
        let _check = crate::watcher::check_every(Duration::from_millis(100));
        let certificate =
            DohCertificate::load(cert.to_str().unwrap(), key.to_str().unwrap()).unwrap();
        let read = certificate.current.load_full();

        std::fs::rename(real.join("A"), real.join("A.old")).unwrap();
        std::fs::rename(real.join("A.new"), real.join("A")).unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while Arc::ptr_eq(&certificate.current.load_full(), &read) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the certificate in the new directory is used");
    }

    /// notify 的监视建不起来（像 inotify 的 max_user_instances 用完了）：证书和私钥都监视不上，续期了，核对看出来，换上
    /// 新证书。以前整个监视装不上，续期的证书要重启才用上
    /// notify's watcher cannot be made (as when inotify's max_user_instances have run out): the
    /// certificate and key cannot be watched, and once renewed the check tells, bringing the new
    /// certificate in. The whole watch used to go uninstalled, a renewed certificate used only
    /// after a restart
    #[tokio::test]
    async fn without_notify_a_renewal_is_used_after_the_check() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = crate::engine::test_support::write_certificate(dir.path());
        let _check = crate::watcher::check_every(Duration::from_millis(100));
        let _notify = crate::watcher::without_notify();
        let certificate = DohCertificate::load(&cert, &key).unwrap();
        let read = certificate.current.load_full();

        crate::engine::test_support::write_certificate(dir.path());
        tokio::time::timeout(Duration::from_secs(5), async {
            while Arc::ptr_eq(&certificate.current.load_full(), &read) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the renewed certificate is used");
    }

    /// 私钥先换上、隔 0.2 秒证书才到（分两阵写到）：读到新私钥配旧证书读不了，等了一会儿看出证书也换了，由证书那次改动的
    /// 回调读，换上新的一对，不记 error（日志由 `tests/doh_renewal.rs` 在真程序上看）
    /// The key replaced first and the certificate 0.2 s later (arriving in two bursts): the new
    /// key with the old certificate fails to read, and having waited a while it tells the
    /// certificate changed too, left to the certificate's change's own callback, which brings the
    /// new pair in, logging no error (the log is looked at on the real binary by
    /// `tests/doh_renewal.rs`)
    #[test]
    fn a_renewal_arriving_in_two_bursts_is_brought_in() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = crate::engine::test_support::write_certificate(dir.path());
        let certificate = DohCertificate::load(&cert, &key).unwrap();
        let in_use = certificate.current.load_full();
        let renewal = dir.path().join("renewal");
        std::fs::create_dir(&renewal).unwrap();
        let (new_cert, new_key) = crate::engine::test_support::write_certificate(&renewal);

        std::fs::rename(&new_key, &key).unwrap();
        std::thread::sleep(Duration::from_millis(200));
        std::fs::rename(&new_cert, &cert).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while Arc::ptr_eq(&certificate.current.load_full(), &in_use) {
            assert!(
                std::time::Instant::now() < deadline,
                "the renewed pair is used"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// 读不了的一对一直被改写（这里每 0.3 秒一次）时，监视线程不会一直等下去：丢掉证书（最后一个监听口停下）以后，至多等
    /// 手上那阵改动的两次回调（证书、私钥各一次）各等一次就停下。以前读不了就等、看到又换了就再读，一直改写就一直不返回，
    /// 丢掉证书要等改写停了才停得下来
    /// With a pair that cannot be read rewritten without end (every 0.3 s here) the watch thread
    /// does not wait on and on: once the certificate is dropped (the last listener stopping), it
    /// stops after at most one wait in each of the two callbacks of the burst at hand (the
    /// certificate's and the key's). It used to wait on a failure, and read again on seeing the
    /// files changed, never returning while they were rewritten, so dropping the certificate
    /// waited for the rewriting to stop
    #[test]
    fn a_pair_rewritten_without_end_does_not_hold_the_watch() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = crate::engine::test_support::write_certificate(dir.path());
        let certificate = DohCertificate::load(&cert, &key).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let rewriting = {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let until = std::time::Instant::now() + Duration::from_secs(10);
                for round in 0.. {
                    if stop.load(Ordering::Relaxed) || std::time::Instant::now() > until {
                        break;
                    }
                    std::fs::write(&cert, format!("not a certificate {round}")).unwrap();
                    std::fs::write(&key, format!("not a key {round}")).unwrap();
                    std::thread::sleep(Duration::from_millis(300));
                }
            })
        };

        std::thread::sleep(Duration::from_secs(1));
        let dropping = std::time::Instant::now();
        drop(certificate);
        let dropped = dropping.elapsed();
        stop.store(true, Ordering::Relaxed);
        rewriting.join().unwrap();
        assert!(
            dropped < watcher::AT_MOST * 2 + Duration::from_secs(1),
            "dropping took {dropped:?}"
        );
    }

    /// 最后一个监听口停下时证书的监视也停下：监视线程结束，放下它手里的证书。以前这个线程谁也停不了，进程活着它就一直在
    /// The certificate's watch stops with the last listener: the watching thread ends and lets
    /// go of the certificate it holds. Nothing could stop that thread before, and it stayed for
    /// as long as the process did
    #[tokio::test]
    async fn the_certificate_watch_stops_with_the_last_listener() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = crate::engine::test_support::write_certificate(dir.path());
        let certificate = DohCertificate::load(&cert, &key).unwrap();
        let held = Arc::downgrade(&certificate.current);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = tokio::spawn(run_doh(
            listener,
            certificate,
            make_static_engine("NXDOMAIN"),
            Arc::from("/dns-query"),
        ));
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
        assert!(held.upgrade().is_none(), "the watching thread has let go");
    }

    // ---- 快速路径之后 / After the fast path ----

    /// 把查询都用 UDP 转发给 `upstream` 的引擎，`settings` 覆盖在默认设置上
    /// An engine forwarding every query over UDP to `upstream`, with `settings` on top of
    /// the defaults
    fn forwarding_engine(upstream: &str, settings: serde_json::Value) -> Engine {
        let mut all = serde_json::json!({ "default_upstream": upstream });
        all.as_object_mut()
            .unwrap()
            .extend(settings.as_object().unwrap().clone());
        crate::engine::test_support::engine_from(serde_json::json!({
            "settings": all,
            "pipelines": [{
                "id": "p",
                "rules": [{
                    "name": "forward",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "forward", "upstream": upstream, "transport": "udp" }]
                }]
            }]
        }))
    }

    /// 经 DoH 问一次，读回回答 / Ask once over DoH and read the answer back
    async fn ask(engine: &Engine, query: &[u8]) -> Message {
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        Message::from_bytes(
            &process_dns_wire(query, peer, engine)
                .await
                .expect("a DNS answer"),
        )
        .expect("dns answer")
    }

    /// 缓存命中的应答带着这条查询自己的事务 ID；TTL 按应答在缓存里停留的整秒数调低（RFC 1035
    /// 第 5.2 节），停留不到一秒时原样不动
    /// A cache hit carries the query's own transaction ID, and its TTLs are lowered by the
    /// whole seconds the answer sat in the cache (RFC 1035 section 5.2), untouched under a
    /// second
    #[tokio::test]
    async fn a_cache_hit_carries_the_query_id_and_ages_its_ttls() {
        let upstream = crate::engine::test_support::answering_upstream(
            std::net::Ipv4Addr::new(192, 0, 2, 7),
            300,
        )
        .await;
        let engine = forwarding_engine(&upstream.address, serde_json::json!({}));

        // 第一次转发给上游，写进缓存 / The first goes to the upstream and into the cache
        let forwarded = ask(&engine, &make_dns_query_a("cached.test", 1)).await;
        assert_eq!((forwarded.metadata.id, forwarded.answers[0].ttl), (1, 300));

        // 停留不到一秒：只换 ID / Under a second in the cache: only the ID changes
        let hit = ask(&engine, &make_dns_query_a("cached.test", 2)).await;
        assert_eq!((hit.metadata.id, hit.answers[0].ttl), (2, 300));

        // 停留过一秒：TTL 跟着调低 / Past a second in the cache the TTL goes down too
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let aged = ask(&engine, &make_dns_query_a("cached.test", 3)).await;
        assert_eq!(aged.metadata.id, 3);
        let ttl = aged.answers[0].ttl;
        assert!((295..300).contains(&ttl), "aged TTL {ttl}");
    }

    /// 引擎在请求时限内答不上来时，到点回 SERVFAIL：不早于时限，也不等引擎自己放弃。快速解析读得了的
    /// 查询和要从头解析的一样
    /// When the engine cannot answer within the request timeout, the answer is SERVFAIL
    /// when it runs out: not before, and without waiting for the engine to give up. A query
    /// the quick parse reads and one parsed from scratch alike
    #[tokio::test]
    async fn the_answer_is_servfail_when_the_request_timeout_runs_out() {
        // 上游从不回答：引擎先用 UDP 试三分之一个时限、再试一个时限，再改用 TCP 等一个时限，加起来比
        // 请求时限长得多，所以先到点的是这里的计时
        // The upstream never answers: the engine tries UDP for a third of the timeout and
        // then a whole one, then TCP for another, far longer than the request timeout, so
        // the timer here runs out first
        const TIMEOUT: Duration = Duration::from_millis(300);
        let upstream = crate::engine::test_support::silent_upstream().await;
        let engine = forwarding_engine(
            &upstream.to_string(),
            serde_json::json!({
                "upstream_timeout_ms": TIMEOUT.as_millis() as u64,
                "request_timeout_ms": TIMEOUT.as_millis() as u64,
                "enable_tcp_fallback": true
            }),
        );
        // 第一个标签里有一个空格：快速解析读不了，要从头解析
        // A space in the first label: the quick parse cannot read it, so it is parsed
        // from scratch
        let mut parsed_from_scratch = make_dns_query_a("xslow.test", 8);
        parsed_from_scratch[13] = b' ';
        assert!(crate::proto_utils::parse_quick(&parsed_from_scratch, &mut [0u8; 256]).is_none());

        for (case, query) in [
            ("quick parse", make_dns_query_a("quick.test", 7)),
            ("full parse", parsed_from_scratch),
        ] {
            let start = std::time::Instant::now();
            let answer = ask(&engine, &query).await;
            let took = start.elapsed();
            assert_eq!(
                (answer.metadata.id, answer.metadata.response_code),
                (
                    u16::from_be_bytes([query[0], query[1]]),
                    ResponseCode::ServFail
                ),
                "{case}"
            );
            assert!(
                took >= TIMEOUT && took < TIMEOUT * 2,
                "{case} took {took:?}"
            );
        }
    }

    /// 名字超长的查询和 UDP、TCP 一样回只有报文头的 FORMERR：快速解析不收它（线上最多 255 字节，和完整解析一样），
    /// 完整解析也读不了。以前快速解析收下了、构造应答时才出错，DoH 回的是 SERVFAIL
    /// A query with an overlong name is answered a header-only FORMERR as over UDP and TCP: the
    /// quick parse does not take it (at most 255 bytes on the wire, as for the full parse), and
    /// neither can the full parse read it. The quick parse used to take it and fail only when
    /// building the answer, and DoH answered SERVFAIL
    #[tokio::test]
    async fn an_overlong_name_is_answered_formerr() {
        let engine = make_static_engine("NXDOMAIN");
        // 线上 256 字节（点分形式 254 字节）/ 256 bytes on the wire (254 dotted)
        let mut query = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(62),
        ] {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.extend_from_slice(&[0, 0, 1, 0, 1]); // root, QTYPE A, QCLASS IN
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        assert!(engine.handle_packet_fast(&query, peer).is_none());

        let answer = process_dns_wire(&query, peer, &engine)
            .await
            .expect("a DNS answer");
        assert_eq!(
            &answer[..],
            [0x12, 0x34, 0x81, 0x81, 0, 0, 0, 0, 0, 0, 0, 0],
            "TXID, QR + RD, RA + FORMERR, no records"
        );
    }
}
