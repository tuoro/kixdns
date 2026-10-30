use anyhow::Context;
use arc_swap::ArcSwap;
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use dashmap::mapref::entry;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{
    Connection as QuicConnection, Endpoint as QuicEndpoint, TransportConfig as QuicTransportConfig,
};
use reqwest::Client as DohHttpClient;
use reqwest::header::{ACCEPT, CONTENT_TYPE, HOST, HeaderValue, RETRY_AFTER};
use rustc_hash::FxBuildHasher;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use socket2::{Domain, Protocol, SockRef, Socket, TcpKeepalive, Type};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{
    TcpStream,
    tcp::{OwnedReadHalf, OwnedWriteHalf},
};
use tokio::sync::{Mutex, oneshot};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use url::Url;
use webpki_roots::TLS_SERVER_ROOTS;

#[inline]
fn unix_time_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            duration.as_millis().min(u64::MAX as u128) as u64
        })
}

/// Least budget worth spending on a transparent retry over a fresh connection.
/// A retry has to reconnect (SYN, plus a TLS handshake for DoT and DoH) and
/// then wait for an answer; with less than this left it cannot complete on a
/// realistic path and would only add a second failure after the caller's
/// deadline. The caller's deadline itself is never extended.
/// 值得为透明重试花的最小剩余预算。重试要先重连（SYN，DoT/DoH 还有 TLS 握手）再等应答，
/// 剩余不足这个值时现实路径上跑不完，只会在调用方截止后再失败一次。绝不延长调用方的截止。
const MIN_RETRY_BUDGET: Duration = Duration::from_millis(50);

/// Type alias for UDP inflight request tracking
/// ID -> (OriginalID, ExpectedAddr, SentQuery, Sender)
/// The sent query (ID already rewritten) stays in the entry so the reader can
/// match the answer's question section against it (RFC 5452 §9.1).
/// 条目保留已改写 ID 的查询报文，供 reader 比对应答的 question 段（RFC 5452 §9.1）。
type UdpInflightMap = DashMap<
    u16,
    (
        u16,
        SocketAddr,
        Bytes,
        oneshot::Sender<anyhow::Result<Bytes>>,
    ),
    FxBuildHasher,
>;

/// drop 时从 `map` 里删掉 `id` 那一条，取消、提前返回或 panic 时也一样
/// Removes `id` from `map` on drop, on cancellation, an early return or a panic too
struct RemoveOnDrop<V> {
    map: Arc<DashMap<u16, V, FxBuildHasher>>,
    id: u16,
}

impl<V> Drop for RemoveOnDrop<V> {
    fn drop(&mut self) {
        self.map.remove(&self.id);
    }
}

struct UdpSocketState {
    socket: Arc<tokio::net::UdpSocket>,
    /// Inflight map: ID -> (OriginalID, ExpectedAddr, SentQuery, Sender)
    /// Note: Using FxBuildHasher for performance
    inflight: Arc<UdpInflightMap>,
}

/// 上游 UDP socket 接收出错以后，歇多久再接着收；None 是马上接着收。
///
/// Windows 上没有连接的 UDP socket 收到 ICMP 端口不可达时，`recv_from` 会报 ConnectionReset
/// （WSAECONNRESET）。这只说明之前发出的某个查询没人收，socket 本身好好的；歇着只会耽误这个 socket
/// 上别的查询的应答，所以马上接着收。别的错误照旧歇 100 ms，免得反复出错时空转。
///
/// How long to pause after a receive error on an upstream UDP socket before reading on;
/// None reads on at once.
///
/// On Windows, an unconnected UDP socket that gets an ICMP port unreachable reports
/// ConnectionReset (WSAECONNRESET) from `recv_from`. That only says some earlier query
/// reached nobody; the socket itself is fine, and pausing would only delay the answers to
/// the other queries on it, so it reads on at once. Any other error still pauses 100 ms,
/// so a repeating one does not spin.
fn recv_error_pause(error: &std::io::Error) -> Option<Duration> {
    match error.kind() {
        std::io::ErrorKind::ConnectionReset => None,
        _ => Some(Duration::from_millis(100)),
    }
}

pub struct UdpClient {
    /// IPv4 sockets, one ephemeral port each. / IPv4 socket，各占一个临时端口。
    pool: Vec<UdpSocketState>,
    /// IPv6 sockets (IPV6_V6ONLY), built on the first query to an IPv6 upstream
    /// so a deployment without one pays for nothing.
    /// IPv6 socket（IPV6_V6ONLY），第一次查询 IPv6 上游时才建立，
    /// 没有 IPv6 上游的部署不付出任何代价。
    pool_v6: tokio::sync::OnceCell<Vec<UdpSocketState>>,
    pool_size: usize,
}

impl UdpClient {
    pub fn new(size: usize) -> anyhow::Result<Self> {
        // Prevent port exhaustion by enforcing minimum pool size
        let effective_size = if size == 0 { 1 } else { size };
        Ok(Self {
            pool: Self::build_pool(
                effective_size,
                Domain::IPV4,
                SocketAddr::from(([0, 0, 0, 0], 0)),
            )?,
            pool_v6: tokio::sync::OnceCell::new(),
            pool_size: effective_size,
        })
    }

    /// 建立一个地址族的完整 socket 池 / Build the whole socket pool of one family
    ///
    /// 先把所有 socket 建出来，全部成功之后才启动接收任务：中途失败时已经建好的
    /// socket 随错误一起丢弃，不会留下收不回的 fd 与任务。
    /// Every socket is created first and the readers start only once they have
    /// all succeeded: on a failure part way through, the sockets created so far
    /// are dropped with the error, leaving no unreachable descriptors or tasks.
    fn build_pool(
        size: usize,
        domain: Domain,
        bind_addr: SocketAddr,
    ) -> anyhow::Result<Vec<UdpSocketState>> {
        let mut sockets = Vec::with_capacity(size);
        for _ in 0..size {
            sockets.push(Self::create_socket(domain, bind_addr)?);
        }
        Ok(sockets
            .into_iter()
            .enumerate()
            .map(|(idx, socket)| Self::spawn_reader(idx, socket))
            .collect())
    }

    /// 建立一个池内 socket，不启动接收任务 / Create one pool socket without its reader
    fn create_socket(
        domain: Domain,
        bind_addr: SocketAddr,
    ) -> anyhow::Result<Arc<tokio::net::UdpSocket>> {
        // Use socket2 to set buffer sizes
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
            .context("create UDP pool socket")?;
        // IPv6 socket 只收发 IPv6：IPv4 上游始终走 IPv4 池，两边互不重叠。
        // Keep the IPv6 socket to IPv6 only: IPv4 upstreams always use the IPv4
        // pool, so the two never overlap.
        if domain == Domain::IPV6 {
            socket
                .set_only_v6(true)
                .context("set UDP pool socket IPV6_V6ONLY")?;
        }
        // Set buffer sizes to 4MB to prevent packet loss under load
        if let Err(e) = socket.set_recv_buffer_size(4 * 1024 * 1024) {
            warn!("failed to set udp recv buffer size: {}", e);
        }
        if let Err(e) = socket.set_send_buffer_size(4 * 1024 * 1024) {
            warn!("failed to set udp send buffer size: {}", e);
        }
        socket
            .bind(&bind_addr.into())
            .context("bind UDP pool socket")?;
        socket
            .set_nonblocking(true)
            .context("set UDP pool socket nonblocking")?;

        let std_sock: std::net::UdpSocket = socket.into();
        Ok(Arc::new(
            tokio::net::UdpSocket::from_std(std_sock).context("create Tokio UDP pool socket")?,
        ))
    }

    /// 为一个建好的 socket 启动接收任务 / Start the reader task of a ready socket
    fn spawn_reader(idx: usize, socket: Arc<tokio::net::UdpSocket>) -> UdpSocketState {
        let inflight = Arc::new(DashMap::with_hasher(FxBuildHasher));

        let state = UdpSocketState {
            socket: socket.clone(),
            inflight: inflight.clone(),
        };

        tokio::spawn(async move {
            // Use BytesMut for efficient buffer management. It holds the largest DNS
            // message: EDNS lets a UDP answer be negotiated up to 65535 bytes, and a
            // datagram longer than the buffer loses its tail without notice, so a
            // 4096-byte buffer turned such answers into parse failures. Most of the
            // buffer is never written; with the default 64 sockets the resident set
            // measured about 1 MiB larger than with 4096-byte buffers.
            // 缓冲区容得下最大的 DNS 报文：EDNS 允许把 UDP 应答协商到 65535 字节，比缓冲区长的
            // 数据报会被悄悄截掉尾部，4096 字节的缓冲区因此把这样的应答变成了解析失败。缓冲区大部分
            // 从不被写到；默认 64 个 socket 时，实测常驻内存比 4096 字节的缓冲区多约 1 MiB。
            let mut buf = BytesMut::with_capacity(MAX_DNS_MESSAGE_SIZE);
            loop {
                // Reset buffer: keep capacity but length=0
                // 重置缓冲区：保留容量但长度设为 0
                buf.clear();

                // Use recv_buf_from to write directly into uninitialized memory part of BytesMut
                // avoid zero-filling overhead from resize(). The buffer is never split, so it
                // keeps the capacity it was built with.
                // 使用 recv_buf_from 直接写入 BytesMut 的未初始化内存部分，避免 resize() 的置零开销。
                // 缓冲区从不被切开，容量一直是建的时候那么大。

                match socket.recv_buf_from(&mut buf).await {
                    Ok((_len, src)) => {
                        let len = buf.len();
                        if len >= 2 {
                            let id = u16::from_be_bytes([buf[0], buf[1]]);
                            // 修复：使用 Entry API 原子操作，避免 remove-then-insert 导致的竞态条件
                            // Fix: Use Entry API for atomic operations to avoid remove-then-insert race condition
                            if let entry::Entry::Occupied(entry) = inflight.entry(id) {
                                let (_, expected_addr, query, _) = entry.get();
                                if src != *expected_addr {
                                    // Address mismatch: keep entry and wait for correct response
                                    // 地址不匹配：保留条目等待正确响应（可能是网络攻击或路由异常）
                                    tracing::warn!(
                                        socket_idx = idx,
                                        response_id = id,
                                        expected_addr = %expected_addr,
                                        actual_addr = %src,
                                        "UDP response address mismatch, possible spoofing or routing anomaly"
                                    );
                                } else if !crate::proto_utils::answers_query(query, &buf) {
                                    // RFC 5452 §9.1: matching ID and address are not enough,
                                    // the question must match too, in a reply to this query
                                    // (see `answers_query`). Keep waiting for the real one.
                                    // RFC 5452 §9.1：ID 和地址相符还不够，question 段也必须一致，
                                    // 而且得是这个查询的应答（见 `answers_query`）；保留条目继续
                                    // 等待真正的应答。
                                    tracing::warn!(
                                        socket_idx = idx,
                                        response_id = id,
                                        upstream = %src,
                                        "UDP response does not answer the query, possible spoofing"
                                    );
                                } else {
                                    let (_, (original_id, _, _, tx)) = entry.remove_entry();

                                    // Restore original TXID
                                    let orig_bytes = original_id.to_be_bytes();
                                    buf[0] = orig_bytes[0];
                                    buf[1] = orig_bytes[1];

                                    // 拷出一份正好大小的应答，缓冲区留着下次接着收。以前切下缓冲区的一段交出去
                                    // （split_to），应答就一直挂在 4 KiB 的缓冲区上：缓存里每条应答平均占着
                                    // 148 字节，缓冲区也要不停重新分配。TCP 和 DoT 的读取同样处理。
                                    // Copy out an answer of exactly its size and keep the buffer for the
                                    // next read. Handing out a slice of the buffer (split_to) kept each
                                    // answer on a 4 KiB buffer: every cached answer held 148 bytes of one
                                    // on average, and the buffer kept being reallocated. The TCP and DoT
                                    // readers do the same.
                                    let response = Bytes::copy_from_slice(&buf[..len]);
                                    let resp_len = response.len();

                                    if tx.send(Ok(response)).is_err() {
                                        tracing::debug!(
                                            socket_idx = idx,
                                            original_id = original_id,
                                            response_id = id,
                                            response_len = resp_len,
                                            "Failed to send UDP response, channel already closed"
                                        );
                                    } else {
                                        tracing::trace!(
                                            socket_idx = idx,
                                            original_id = original_id,
                                            response_id = id,
                                            response_len = resp_len,
                                            "UDP response sent successfully"
                                        );
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("UDP pool recv error: {}", e);
                        if let Some(pause) = recv_error_pause(&e) {
                            tokio::time::sleep(pause).await;
                        }
                    }
                }
            }
        });

        state
    }

    #[inline]
    pub async fn send(
        &self,
        packet: &[u8],
        upstream: &str,
        timeout_dur: Duration,
    ) -> anyhow::Result<Bytes> {
        let addr: SocketAddr = upstream.parse().context("invalid upstream address")?;
        // 按目标地址族选池：IPv4 路径只多一次判别
        // Pick the pool by address family; the IPv4 path only gains one check.
        let pool = if addr.is_ipv6() {
            self.pool_v6
                .get_or_try_init(|| async {
                    Self::build_pool(
                        self.pool_size,
                        Domain::IPV6,
                        SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0)),
                    )
                })
                .await
                .context("create the IPv6 UDP pool")?
        } else {
            &self.pool
        };
        // RFC 5452 §4.3 / §9.2: neither the transaction ID nor the source port
        // may be predictable, or a forged answer only has to guess the next
        // value. One draw from the thread-local RNG serves both: the high half
        // picks the socket (each pool socket sits on its own ephemeral port),
        // the low half seeds the ID.
        // RFC 5452 §4.3/§9.2：TXID 和源端口都不能可预测，否则伪造应答只需猜下一个值。
        // 从线程本地 RNG 取一次 32 位：高 16 位随机选 socket（池内每个 socket 各占
        // 一个临时端口），低 16 位作为 ID 起点。
        let draw: u32 = rand::random();
        let idx = (draw >> 16) as usize % pool.len();
        let state = &pool[idx];

        if packet.len() < 2 {
            return Err(anyhow::anyhow!("packet too short"));
        }
        let original_id = u16::from_be_bytes([packet[0], packet[1]]);

        // Copy the packet once so the ID can be rewritten; the same buffer is
        // sent and kept in the inflight entry for the answer's question check.
        // 只拷贝一次报文用于改写 ID；同一份缓冲既用于发送，也留在在途条目里供应答比对。
        let mut new_packet = BytesMut::with_capacity(packet.len());
        new_packet.extend_from_slice(packet);

        // Claim a free ID using the atomic entry API; on a collision with an
        // in-flight query draw a fresh random ID rather than the next one.
        // 使用原子 Entry API 占用空闲 ID；与在途查询冲突时重新随机，而不是取下一个。
        let mut attempts = 0;
        let mut new_id = draw as u16;
        let (tx, rx) = oneshot::channel();

        let new_packet = loop {
            match state.inflight.entry(new_id) {
                entry::Entry::Vacant(e) => {
                    new_packet[0..2].copy_from_slice(&new_id.to_be_bytes());
                    let new_packet = new_packet.freeze();
                    e.insert((original_id, addr, new_packet.clone(), tx));
                    break new_packet;
                }
                entry::Entry::Occupied(_) => {
                    new_id = rand::random();
                    attempts += 1;
                    if attempts > 100 {
                        warn!(
                            "udp pool exhausted: socket_idx={} inflight_count={}",
                            idx,
                            state.inflight.len()
                        );
                        return Err(anyhow::anyhow!(
                            "udp pool exhausted (too many inflight requests)"
                        ));
                    }
                }
            }
        };

        // RAII Guard: ensures entry is removed from map when guard is dropped
        // (e.g. timeout, cancel, early return)
        // RAII Guard：确保在 guard 丢弃时（超时、取消、提前返回）移除条目
        let _guard = RemoveOnDrop {
            map: state.inflight.clone(),
            id: new_id,
        };

        if let Err(e) = state.socket.send_to(&new_packet, addr).await {
            // Guard will remove inflight entry automatically
            return Err(e.into());
        }

        match timeout(timeout_dur, rx).await {
            Ok(Ok(res)) => res,
            Ok(Err(_)) => {
                // Channel closed by receiver (should not happen normally unless logic error or panic)
                Err(anyhow::anyhow!("channel closed"))
            }
            Err(_) => Err(anyhow::anyhow!("upstream timeout")),
        }
    }
}

// ===================== TCP and DoT (DNS over TCP, DNS over TLS) =====================

/// 用两字节长度前缀收发 DNS 报文的流式传输：TCP（RFC 7766）和 DoT（RFC 7858）。两者共用下面同一套
/// 多路复用器、连接池和客户端，只在怎样建连上不同。
/// A stream transport carrying DNS messages behind a two-byte length prefix: TCP (RFC
/// 7766) and DoT (RFC 7858). Both share the multiplexer, pool and client below and
/// differ only in how they connect.
pub trait StreamTransport: Send + Sync + 'static {
    type Read: tokio::io::AsyncRead + Unpin + Send + 'static;
    type Write: tokio::io::AsyncWrite + Unpin + Send + 'static;
    /// 每次建连都要用、整个多路复用器共用的东西（DoT 的 TLS 配置）/ What every connect
    /// needs, shared by the whole multiplexer (DoT's TLS configuration)
    type Shared: Clone + Send + Sync + 'static;
    /// 错误文字里的名字 / The name in error texts
    const LABEL: &'static str;
    /// 日志里的名字 / The name in logs
    const NAME: &'static str;
    /// 日志的 `target` 字段 / The logs' `target` field
    const LOG_TARGET: &'static str;

    /// 在 `budget` 内建好一条到 `upstream` 的连接 / Connect to `upstream` within `budget`
    fn connect(
        shared: &Self::Shared,
        upstream: &str,
        budget: Duration,
    ) -> impl Future<Output = anyhow::Result<(Self::Read, Self::Write)>> + Send;
}

/// DNS over TCP（RFC 7766）/ DNS over TCP (RFC 7766)
pub struct Tcp;

impl StreamTransport for Tcp {
    type Read = OwnedReadHalf;
    type Write = OwnedWriteHalf;
    type Shared = ();
    const LABEL: &'static str = "tcp";
    const NAME: &'static str = "TCP";
    const LOG_TARGET: &'static str = "tcp_mux";

    async fn connect(
        _: &(),
        upstream: &str,
        budget: Duration,
    ) -> anyhow::Result<(OwnedReadHalf, OwnedWriteHalf)> {
        // Establish TCP connection within the budget. Unbounded, a blackholed
        // SYN blocks here until the kernel gives up (minutes) while every
        // other request on this client waits for the lock.
        // 在预算内建立 TCP 连接。不设限时 SYN 被黑洞会在此阻塞到内核放弃（分钟级），
        // 期间该客户端的其他请求都在等这把锁。
        let stream = match timeout(budget, TcpStream::connect(upstream)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => anyhow::bail!("tcp connect failed: {e}"),
            Err(_) => anyhow::bail!("tcp connect timeout after {}ms", budget.as_millis()),
        };
        tune_stream_socket(&stream, upstream);
        Ok(stream.into_split())
    }
}

/// 刚建好的 TCP 连接（DoT 在握手之前也是）：关掉 Nagle，打开激进的 keepalive
/// A freshly connected TCP stream (DoT's too, before its handshake): Nagle off and an
/// aggressive keepalive on
fn tune_stream_socket(stream: &TcpStream, upstream: &str) {
    // Configure socket options for robustness
    // 配置 socket 选项以增强健壮性
    let _ = stream.set_nodelay(true);

    // Set Check to 5s to detect dead connections faster (Aggressive Keepalive)
    let sock = SockRef::from(stream);
    let ka = TcpKeepalive::new()
        .with_time(Duration::from_secs(5))
        .with_interval(Duration::from_secs(2));

    // Explicitly enable SO_KEEPALIVE (Essential for Windows/Linux)
    if let Err(e) = sock.set_keepalive(true) {
        warn!(upstream = %upstream, error = %e, "Failed to enable SO_KEEPALIVE");
    }
    if let Err(e) = sock.set_tcp_keepalive(&ka) {
        warn!(upstream = %upstream, error = %e, "Failed to set TCP keepalive params");
    }
}

/// 一个上游的连接池：几个客户端轮流用 / One upstream's pool: a few clients taken in turn
pub struct ConnectionPool<C> {
    clients: Vec<Arc<C>>,
    next_idx: AtomicUsize,
}

impl<C> ConnectionPool<C> {
    fn new(clients: Vec<Arc<C>>) -> Self {
        Self {
            clients,
            next_idx: AtomicUsize::new(0),
        }
    }

    /// 轮到的那个客户端 / The client whose turn it is
    fn pick(&self) -> &Arc<C> {
        &self.clients[self.next_idx.fetch_add(1, Ordering::Relaxed) % self.clients.len()]
    }
}

/// 每个上游一个连接池 / One connection pool per upstream
struct UpstreamPools<C> {
    pools: DashMap<Arc<str>, Arc<ConnectionPool<C>>, FxBuildHasher>,
}

impl<C> UpstreamPools<C> {
    fn new() -> Self {
        Self {
            pools: DashMap::with_hasher(FxBuildHasher),
        }
    }

    /// 只留下 `keep` 认可的上游的连接池。重载后配置里不再有的上游，连接池就此丢掉：正在用它的
    /// 查询拿着连接池，做完才释放；之后它的连接随之关闭。
    /// Keeps only the pools of the upstreams `keep` accepts. After a reload, the pool of an
    /// upstream the configuration no longer names is dropped: queries using it hold on to
    /// it until they finish, and its connections close after that.
    fn retain(&self, keep: impl Fn(&str) -> bool) {
        self.pools.retain(|upstream, _| keep(upstream));
    }

    /// `upstream` 的连接池，还没有就用 `clients` 建一个 / The pool for `upstream`, built from
    /// `clients` if there is none
    fn get_or_create(
        &self,
        upstream: &str,
        clients: impl FnOnce(&Arc<str>) -> Vec<Arc<C>>,
    ) -> Arc<ConnectionPool<C>> {
        let upstream_key: Arc<str> = Arc::from(upstream);
        self.pools
            .entry(upstream_key.clone())
            .or_insert_with(|| Arc::new(ConnectionPool::new(clients(&upstream_key))))
            .clone()
    }

    #[cfg(test)]
    fn get(&self, upstream: &str) -> Option<Arc<ConnectionPool<C>>> {
        self.pools.get(upstream).map(|pool| Arc::clone(&pool))
    }
}

/// TCP 或 DoT 的连接复用器：每个上游一个连接池 / The TCP or DoT connection multiplexer:
/// one connection pool per upstream
pub struct StreamMultiplexer<T: StreamTransport> {
    pools: UpstreamPools<StreamMuxClient<T>>,
    /// 每个池几个客户端，至少一个 / How many clients a pool has, at least one
    pool_size: usize,
    /// 建连用的共享部分 / What connects share
    shared: T::Shared,
    /// 健康检查配置 / Health check configuration
    health_error_threshold: usize,
    max_age_secs: u64,
    idle_timeout_secs: u64,
}

/// TCP 连接复用器 / TCP connection multiplexer
pub type TcpMultiplexer = StreamMultiplexer<Tcp>;

/// DoT (DNS over TLS) 多路复用器，参考 RFC 7858 实现
/// DoT (DNS over TLS) multiplexer, implementing RFC 7858
pub type DotMultiplexer = StreamMultiplexer<Dot>;

pub type StreamConnectionPool<T> = ConnectionPool<StreamMuxClient<T>>;
pub type TcpConnectionPool = StreamConnectionPool<Tcp>;
pub type DotConnectionPool = StreamConnectionPool<Dot>;

impl<T: StreamTransport> StreamMultiplexer<T> {
    fn with_shared(
        shared: T::Shared,
        pool_size: usize,
        health_error_threshold: usize,
        max_age_secs: u64,
        idle_timeout_secs: u64,
    ) -> Self {
        Self {
            pools: UpstreamPools::new(),
            pool_size: pool_size.max(1),
            shared,
            health_error_threshold,
            max_age_secs,
            idle_timeout_secs,
        }
    }

    /// 只留下 `keep` 认可的上游的连接池。重载后配置里不再有的上游，连接池就此丢掉：正在用它的
    /// 查询拿着连接池，做完才释放；之后它的连接随之关闭。
    /// Keeps only the pools of the upstreams `keep` accepts. After a reload, the pool of an
    /// upstream the configuration no longer names is dropped: queries using it hold on to
    /// it until they finish, and its connections close after that.
    pub(crate) fn retain_upstreams(&self, keep: impl Fn(&str) -> bool) {
        self.pools.retain(keep);
    }

    /// `upstream` 的连接池：`pool_size` 个客户端，每个客户端最多一条连接；还没有就建一个。预热和
    /// 发送都用它，两边建的池才一样大
    /// The pool for `upstream`: `pool_size` clients, each holding at most one connection,
    /// built if there is none. Warm-up and send both use it, so their pools are alike
    fn pool(&self, upstream: &str) -> Arc<StreamConnectionPool<T>> {
        self.pools.get_or_create(upstream, |upstream| {
            (0..self.pool_size)
                .map(|_| {
                    Arc::new(StreamMuxClient::with_shared(
                        self.shared.clone(),
                        upstream.clone(),
                        StreamHealth {
                            error_threshold: self.health_error_threshold,
                            max_age_ms: self.max_age_secs * 1000,
                            idle_timeout_ms: self.idle_timeout_secs * 1000,
                        },
                    ))
                })
                .collect()
        })
    }

    /// Test-only helper to initialize or get a pool without network operations
    /// This mirrors the production pool initialization logic used in send().
    #[cfg(test)]
    pub fn get_or_init_pool_for_test(&self, upstream: &str) -> Arc<StreamConnectionPool<T>> {
        self.pool(upstream)
    }

    #[inline]
    pub async fn send(
        &self,
        packet: &[u8],
        upstream: &str,
        timeout_dur: Duration,
    ) -> anyhow::Result<Bytes> {
        let pool = self.pool(upstream);
        pool.pick().send(packet, timeout_dur).await
    }
}

impl TcpMultiplexer {
    pub fn new(
        pool_size: usize,
        health_error_threshold: usize,
        max_age_secs: u64,
        idle_timeout_secs: u64,
    ) -> Self {
        Self::with_shared(
            (),
            pool_size,
            health_error_threshold,
            max_age_secs,
            idle_timeout_secs,
        )
    }

    /// 为配置里的 TCP 上游建好连接池，和发送时现建的一样大（`pool_size`），首个查询就不用再建。
    /// 只建客户端，连接要等查询用到时才建立。
    /// Build the pools of the configuration's TCP upstreams, as large as one built on
    /// first send (`pool_size`), so the first query need not build it. Only the clients
    /// are built; each connects when a query first needs it.
    pub fn warm_up_pools(&self, upstreams: &rustc_hash::FxHashSet<String>) {
        if upstreams.is_empty() {
            info!("No TCP upstreams to warm up");
            return;
        }

        info!(
            count = upstreams.len(),
            "Warming up TCP connection pools..."
        );

        for upstream in upstreams {
            self.pool(upstream);
        }

        info!(
            count = upstreams.len(),
            "TCP connection pools warmed up successfully"
        );
    }
}

impl DotMultiplexer {
    pub fn new(
        pool_size: usize,
        health_error_threshold: usize,
        max_age_secs: u64,
        idle_timeout_secs: u64,
    ) -> anyhow::Result<Self> {
        let tls_config = build_tls_client_config()?;
        Ok(Self::with_shared(
            Arc::new(tls_config),
            pool_size,
            health_error_threshold,
            max_age_secs,
            idle_timeout_secs,
        ))
    }
}

/// 一个上游的一条多路复用连接（TCP 或 DoT）/ One multiplexed connection to an upstream (TCP or DoT)
pub struct StreamMuxClient<T: StreamTransport> {
    pub upstream: Arc<str>,
    /// 建连用的共享部分 / What connects share
    shared: T::Shared,
    /// Write half protected by Mutex - serves as both connection storage and write serialization
    conn: Arc<Mutex<Option<T::Write>>>,
    /// 上一次写入被取消，下次使用前需要完整 reset
    /// A write was cancelled; the connection needs a full reset before reuse
    write_cancelled: AtomicBool,
    pending: Arc<dashmap::DashMap<u16, Pending, FxBuildHasher>>,
    next_id: AtomicU16,
    /// Generation counter to detect stale readers
    /// 代数计数器，用于检测过期的 reader (Wrapped in Arc for sharing with spawned tasks)
    generation: Arc<AtomicU64>,
    /// 健康检查：连续错误计数 / Health check: consecutive error count
    consecutive_errors: AtomicUsize,
    /// 健康检查的设置 / Health check settings
    health: StreamHealth,
    /// 连接老化：创建时间戳（毫秒）/ Connection aging: creation timestamp (ms)
    conn_create_time: AtomicU64,
    /// 空闲超时：最后请求时间（毫秒）/ Idle timeout: last request time (ms)
    last_request_time: AtomicU64,
    /// 性能优化：上次健康检查时间（毫秒）/ Performance: last health check time (ms)
    last_health_check_time: AtomicU64,
    /// Reader 取消令牌 / Reader cancellation token
    read_cancel: Mutex<CancellationToken>,
    /// 这条客户端的 reader 读到的应答帧总数。查询超时时拿它判断连接是不是还活着：
    /// 本查询写出之后数字涨过，说明连接照常在回答，慢的只是这一个
    /// Answer frames this client's readers have read. A timed-out query uses it to
    /// tell whether the connection is still alive: if it grew after the query was
    /// written, the connection kept answering and only this one answer is slow
    answers_read: Arc<AtomicU64>,
}

/// 一条 TCP/DoT 连接的健康检查设置，建客户端时给定，之后不变
/// A TCP/DoT connection's health check settings, given when the client is built and fixed after
#[derive(Debug, Clone, Copy)]
struct StreamHealth {
    /// 连续错误达到这个数就复位；0 不按次数复位 / Reset after this many errors in a row; 0 never by count
    error_threshold: usize,
    /// 连接最长存活多久（毫秒），0 不限 / How long a connection may live (ms), 0 for no limit
    max_age_ms: u64,
    /// 空闲多久（毫秒）就复位，0 不限 / How long it may sit idle (ms) before a reset, 0 for no limit
    idle_timeout_ms: u64,
}

impl Default for StreamHealth {
    /// 3 次错误、5 分钟、1 分钟 / 3 errors, 5 minutes, 1 minute
    fn default() -> Self {
        Self {
            error_threshold: 3,
            max_age_ms: 300_000,
            idle_timeout_ms: 60_000,
        }
    }
}

pub type TcpMuxClient = StreamMuxClient<Tcp>;
pub type DotMuxClient = StreamMuxClient<Dot>;

struct Pending {
    original_id: u16,
    /// 写出去的帧（长度前缀加查询），回答到了用来比对问题
    /// The frame that was written (length prefix plus query), for checking the answer's question
    frame: Bytes,
    tx: oneshot::Sender<anyhow::Result<Bytes>>,
}

/// RAII Guard for TCP and DoT pending requests to ensure cleanup on cancellation
/// 写入期间被取消时丢弃这条连接
/// Drops the connection if the write is cancelled part way through
///
/// 与 [`RemoveOnDrop`] 是同一个取消点：`send_attempt` 可以在任意 await 处
/// 被丢弃——外层请求超时先到（`validate_timeouts` 只要求 request >= upstream，
/// 取等时就会），或者双发路径上 UDP 先返回导致 `tcp_task.abort()`。待处理表
/// 那一侧已经由 `RemoveOnDrop` 兜住，写入这一侧此前没有：`write_all` 只写
/// 进去一部分就被丢弃时，连接仍然留在池里，下一个请求把自己的帧接在半条帧
/// 后面，对端按长度前缀读就会错位，而且不计错误也不重置，只能等下一次失败
/// 才自愈。
///
/// 这里把连接置空即可，下一次 `ensure_connection` 会重建。代价是热路径上多
/// 一次栈上构造和一次布尔写。
///
/// The same cancellation point as [`RemoveOnDrop`]: `send_attempt` can be
/// dropped at any await, either because the outer request timeout fires first
/// (`validate_timeouts` only requires request >= upstream, so equality allows
/// it) or because UDP answered first on the dual-send path and aborted the TCP
/// task. The pending-map side was already covered by `RemoveOnDrop`; the
/// write side was not. A `write_all` dropped after a partial write leaves the
/// connection in the pool, the next request appends its frame to half a frame,
/// and a peer reading by length prefix desynchronises, with nothing counting an
/// error or resetting it until a later request fails. Clearing the slot is
/// enough, since the next `ensure_connection` rebuilds it. The hot path pays
/// one stack construction and one boolean store.
///
/// DoT 的写半边换成 TLS 流，用的是同一个 guard。
/// DoT, whose write half is a TLS stream, uses the same guard.
struct TcpWriteGuard<'a, W> {
    slot: &'a mut Option<W>,
    /// 取消时置位，交给下一次 `ensure_connection` 做完整 reset
    /// Set on cancellation so the next `ensure_connection` does a full reset
    needs_reset: &'a AtomicBool,
    armed: bool,
}

impl<W> Drop for TcpWriteGuard<'_, W> {
    fn drop(&mut self) {
        if self.armed {
            // 立刻丢掉写半边，半条帧不会再被别人续写；`reset()` 还要取消 reader
            // 的 token、让还在等这条连接的查询失败，那两件事不能在 Drop 里 await，所以
            // 置位让下一次 `ensure_connection` 顺着既有的 `errors > 0` 那条路
            // 一起收口。
            // Drop the write half at once so nothing can append to half a frame.
            // A full `reset()` also cancels the reader's token and fails the queries
            // still waiting on the connection, neither of which can await inside
            // Drop, so this flags the next `ensure_connection` to take the existing
            // `errors > 0` path and finish the job in one place.
            *self.slot = None;
            self.needs_reset.store(true, Ordering::Release);
        }
    }
}

/// 客户端被丢掉（它的上游在重载后不在配置里了）时，让读取任务结束：读取任务拿着写半边的共享引用，
/// 不结束的话连接会一直开着。
/// When the client is dropped (its upstream left the configuration on a reload), its
/// reader task is ended: the reader holds a share of the write half, and the connection
/// would stay open while it runs.
impl<T: StreamTransport> Drop for StreamMuxClient<T> {
    fn drop(&mut self) {
        self.read_cancel.get_mut().cancel();
    }
}

#[cfg(test)]
impl TcpMuxClient {
    fn new(upstream: Arc<str>) -> Self {
        Self::with_shared((), upstream, StreamHealth::default())
    }
}

#[cfg(test)]
impl DotMuxClient {
    fn new(upstream: Arc<str>, tls_config: Arc<ClientConfig>) -> Self {
        Self::with_shared(tls_config, upstream, StreamHealth::default())
    }
}

impl<T: StreamTransport> StreamMuxClient<T> {
    fn with_shared(shared: T::Shared, upstream: Arc<str>, health: StreamHealth) -> Self {
        Self {
            upstream,
            shared,
            conn: Arc::new(Mutex::new(None)),
            write_cancelled: AtomicBool::new(false),
            pending: Arc::new(dashmap::DashMap::with_hasher(FxBuildHasher)),
            next_id: AtomicU16::new(1),
            generation: Arc::new(AtomicU64::new(0)),
            consecutive_errors: AtomicUsize::new(0),
            health,
            conn_create_time: AtomicU64::new(0),
            last_request_time: AtomicU64::new(0),
            last_health_check_time: AtomicU64::new(0),
            read_cancel: Mutex::new(CancellationToken::new()),
            answers_read: Arc::new(AtomicU64::new(0)),
        }
    }

    fn spawn_reader(
        &self,
        mut reader: T::Read,
        cancel_token: CancellationToken,
        my_generation: u64,
    ) {
        let global_generation = Arc::clone(&self.generation);
        let pending = Arc::clone(&self.pending);
        let upstream = self.upstream.clone();
        let conn = Arc::clone(&self.conn);
        let answers_read = Arc::clone(&self.answers_read);

        tokio::spawn(async move {
            // Pre-allocate a reusable buffer for reads
            // DNS TCP max is 65535 bytes, but typical responses are much smaller
            let mut reusable_buf = BytesMut::with_capacity(4096);
            loop {
                // Check if this reader is still valid (Zombie Check)
                // 检查此 reader 是否仍然有效（僵尸检测）
                if global_generation.load(Ordering::Relaxed) != my_generation {
                    debug!(target = T::LOG_TARGET, upstream = %upstream, gen = my_generation, "{} reader detected older generation, exiting silently", T::NAME);
                    return;
                }

                let mut len_buf = [0u8; 2];
                // Cancellation: select! interrupts blocked read_exact on reset
                // 取消机制：select! 在 reset 时中断阻塞的 read_exact
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        debug!(target = T::LOG_TARGET, upstream = %upstream, gen = my_generation, "{} reader cancelled by reset, exiting", T::NAME);
                        return;
                    }
                    result = reader.read_exact(&mut len_buf) => {
                        if let Err(err) = result {
                            // Check generation again before resetting anything
                            if global_generation.load(Ordering::Relaxed) == my_generation {
                                debug!(target = T::LOG_TARGET, upstream = %upstream, error = %err, "{} read len failed", T::LABEL);
                                Self::fail_all_async(
                                    &pending,
                                    anyhow::anyhow!("{} read len failed", T::LABEL),
                                    &conn,
                                )
                                .await;
                            } else {
                                debug!(target = T::LOG_TARGET, upstream = %upstream, gen = my_generation, "{} reader failed but generation changed, ignoring", T::NAME);
                            }
                            break;
                        }
                    }
                }
                let resp_len = u16::from_be_bytes(len_buf) as usize;

                // Resize buffer if needed, reusing allocation (and ensure capacity)
                // resize() handles both truncation and extension, no need for clear()
                if reusable_buf.capacity() < resp_len {
                    reusable_buf.reserve(resp_len.max(4096));
                }
                reusable_buf.resize(resp_len, 0);

                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        debug!(target = T::LOG_TARGET, upstream = %upstream, gen = my_generation, "{} reader cancelled by reset during body read, exiting", T::NAME);
                        return;
                    }
                    result = reader.read_exact(&mut reusable_buf[..resp_len]) => {
                        if let Err(err) = result {
                            // Check generation again
                            if global_generation.load(Ordering::Relaxed) == my_generation {
                                debug!(target = T::LOG_TARGET, upstream = %upstream, error = %err, "{} read body failed", T::LABEL);
                                Self::fail_all_async(
                                    &pending,
                                    anyhow::anyhow!("{} read body failed", T::LABEL),
                                    &conn,
                                )
                                .await;
                            }
                            break;
                        }
                    }
                }

                // 读满一整帧就算这条连接在回答，不管它对不对得上号
                // A whole frame read counts as the connection answering, matched or not
                answers_read.fetch_add(1, Ordering::Release);
                if resp_len < 2 {
                    continue;
                }
                let resp_id = u16::from_be_bytes([reusable_buf[0], reusable_buf[1]]);
                // RFC 5452 §9.1, as on UDP: a matching ID is not enough, the
                // question has to match too. An answer to another question under
                // this ID (a late answer to an earlier query that had the same ID,
                // say) is dropped, and the query keeps waiting for its own.
                // RFC 5452 §9.1，和 UDP 一样：ID 相符还不够，问题也要一致。这个 ID 下回答别的问题的
                // （比如之前用过同一个 ID 的查询迟到的回答）丢掉，查询接着等自己的回答。
                let matched = match pending.entry(resp_id) {
                    entry::Entry::Occupied(e)
                        if crate::proto_utils::answers_query(
                            &e.get().frame[2..],
                            &reusable_buf[..resp_len],
                        ) =>
                    {
                        Some(e.remove())
                    }
                    entry::Entry::Occupied(_) => {
                        warn!(target = T::LOG_TARGET, upstream = %upstream, resp_id, "{} response does not answer the query, dropped", T::NAME);
                        None
                    }
                    entry::Entry::Vacant(_) => {
                        debug!(target = T::LOG_TARGET, upstream = %upstream, resp_id, "response with unknown id");
                        None
                    }
                };
                if let Some(p) = matched {
                    let orig = p.original_id;
                    reusable_buf[0..2].copy_from_slice(&p.original_id.to_be_bytes());
                    // Copy it out and keep the buffer, as the UDP reader does
                    // 拷出一份、缓冲区留着，和 UDP 的读取一样
                    let response = Bytes::copy_from_slice(&reusable_buf[..resp_len]);
                    match p.tx.send(Ok(response)) {
                        Ok(()) => {
                            tracing::trace!(
                                target = T::LOG_TARGET,
                                upstream = %upstream,
                                resp_id,
                                original_id = orig,
                                response_len = resp_len,
                                "{} mux response sent successfully",
                                T::NAME
                            );
                        }
                        Err(_) => {
                            tracing::debug!(
                                target = T::LOG_TARGET,
                                upstream = %upstream,
                                resp_id,
                                original_id = orig,
                                "{} mux response send failed, channel already closed",
                                T::NAME
                            );
                        }
                    }
                }
            }
        });
    }

    // ========== Health check methods / 健康检查方法 ==========

    /// Record error and check if connection reset is needed
    /// 记录错误并检查是否需要重置连接
    ///
    /// When the error threshold is exceeded, the connection is reset and the error
    /// counter is cleared to avoid immediate re-triggering on the next error.
    ///
    /// 当错误阈值超过时，连接会被重置，错误计数器会被清零以避免下次错误时立即重新触发。
    async fn record_error(&self) -> bool {
        let errors = self.consecutive_errors.fetch_add(1, Ordering::Release) + 1;
        // 阈值 0 表示禁用健康检查（README 与 config.rs 如此描述），
        // 而不是"每次错误都重置连接"。
        // A threshold of 0 disables the health check, as README and config.rs
        // describe, rather than resetting the connection on every error.
        let threshold = self.health.error_threshold;

        debug!(
            upstream = %self.upstream,
            consecutive_errors = errors,
            threshold = threshold,
            "{} connection error recorded",
            T::NAME
        );

        // Check if threshold exceeded / 检查是否超过阈值
        if threshold > 0 && errors >= threshold {
            warn!(
                upstream = %self.upstream,
                consecutive_errors = errors,
                threshold = threshold,
                "{} connection error threshold exceeded, resetting connection",
                T::NAME
            );
            self.reset().await;
            // Clear error counter to avoid immediate re-triggering on next error
            // 清零错误计数器，避免下次错误时立即重新触发
            self.consecutive_errors.store(0, Ordering::Release);
            true // Connection was reset / 连接已重置
        } else {
            false // Connection was not reset / 连接未重置
        }
    }

    /// Record success and clear error counter
    /// 记录成功并清零错误计数
    fn record_success(&self) {
        self.consecutive_errors.store(0, Ordering::Release);
        let now = unix_time_millis();
        self.last_request_time.store(now, Ordering::Release);
    }

    /// Check if connection needs reset due to aging or idle timeout
    /// 检查连接是否需要重置（老化或空闲超时）
    ///
    /// Returns true if connection was reset, false otherwise.
    /// 如果连接被重置返回 true，否则返回 false。
    async fn check_connection_health(&self) -> bool {
        let now = unix_time_millis();

        // Check connection aging / 检查连接老化
        let create_time = self.conn_create_time.load(Ordering::Acquire);
        let max_age = self.health.max_age_ms;
        if create_time > 0 && max_age > 0 {
            let age_ms = now.saturating_sub(create_time);
            if age_ms > max_age {
                info!(
                    upstream = %self.upstream,
                    age_ms = age_ms,
                    max_age_ms = max_age,
                    "{} connection too old, resetting",
                    T::NAME
                );
                self.reset().await;
                // Clear error counter since we're starting fresh
                // 清零错误计数器，因为我们重新开始
                self.consecutive_errors.store(0, Ordering::Release);
                return true;
            }
        }

        // Check idle timeout / 检查空闲超时
        let last_req = self.last_request_time.load(Ordering::Acquire);
        let idle_timeout = self.health.idle_timeout_ms;
        if last_req > 0 && idle_timeout > 0 {
            let idle_ms = now.saturating_sub(last_req);
            if idle_ms > idle_timeout {
                info!(
                    upstream = %self.upstream,
                    idle_ms = idle_ms,
                    idle_timeout_ms = idle_timeout,
                    "{} connection idle timeout, resetting",
                    T::NAME
                );
                self.reset().await;
                // Clear error counter since we're starting fresh
                // 清零错误计数器，因为我们重新开始
                self.consecutive_errors.store(0, Ordering::Release);
                return true;
            }
        }

        false
    }

    async fn send(&self, packet: &[u8], timeout_dur: Duration) -> anyhow::Result<Bytes> {
        let start = tokio::time::Instant::now();
        if packet.len() < 2 {
            anyhow::bail!("dns packet too short for {}", T::LABEL);
        }

        // Check if we are reusing an existing connection (for potential retry strategy)
        // 检查我们是否在重用现有连接（用于潜在的重试策略）
        // 不等连接锁：这一步在预算之外，以前前面有查询占着锁时会一直等。锁正被拿着，多半是有查询
        // 在用这条连接，就当复用
        // Without waiting for the connection lock: this step lies outside the budget
        // and used to wait as long as the lock was held ahead of it. A held lock most
        // likely means a query is using the connection, so it counts as reused
        let is_reused = match self.conn.try_lock() {
            Ok(guard) => guard.is_some(),
            Err(_) => true,
        };

        match self.send_attempt(packet, timeout_dur).await {
            Ok(res) => Ok(res),
            Err(err) => {
                // TRANSPARENT RETRY: If connection was reused and failed with transport error,
                // retry once with a fresh connection, within what is left of the budget
                // 透明重试：如果连接是复用的并且因传输错误失败，则在剩余预算内用新连接重试一次
                if is_reused {
                    let remaining = timeout_dur.saturating_sub(start.elapsed());
                    if remaining < MIN_RETRY_BUDGET {
                        return Err(err);
                    }

                    debug!(
                        upstream = %self.upstream,
                        error = %err,
                        retry_timeout_ms = remaining.as_millis() as u64,
                        "Connection reuse failed, performing transparent retry with fresh connection"
                    );

                    // Connection should have been reset by send_attempt already upon error
                    // send_attempt 出错时连接应该已经被重置
                    return self.send_attempt(packet, remaining).await;
                }
                Err(err)
            }
        }
    }

    async fn send_attempt(&self, packet: &[u8], timeout_dur: Duration) -> anyhow::Result<Bytes> {
        let start = tokio::time::Instant::now();

        // 性能优化：仅在距离上次检查超过 30 秒时才执行健康检查
        // Performance: Only check connection health if 30 seconds have passed since last check
        const HEALTH_CHECK_INTERVAL_MS: u64 = 30_000; // 30 秒
        let now = unix_time_millis();
        let last_check = self.last_health_check_time.load(Ordering::Relaxed);
        if last_check == 0 || now.saturating_sub(last_check) >= HEALTH_CHECK_INTERVAL_MS {
            self.check_connection_health().await;
            self.last_health_check_time.store(now, Ordering::Relaxed);
        }

        // 1. Ensure the connection exists (connecting if needed), within what is left
        //    of the budget
        // 确保连接存在（没有就建连），受剩余预算约束
        self.ensure_connection(timeout_dur.saturating_sub(start.elapsed()))
            .await?;

        let elapsed = start.elapsed();
        if elapsed >= timeout_dur {
            anyhow::bail!("{} timeout before processing", T::LABEL);
        }
        let remaining = timeout_dur - elapsed;

        let original_id = u16::from_be_bytes([packet[0], packet[1]]);

        // 生成通道
        let (tx, rx) = oneshot::channel();

        // 原子操作：分配 ID 并注册到 pending map，避免竞态条件
        // 注册要等连接锁，也受剩余预算约束：以前排在一长串注册后面的查询，会远远超出自己的时限
        // Registration waits for the connection lock, so it is bounded by what is left
        // of the budget too: a query queued behind a long run of registrations used to
        // run far past its own deadline
        let Ok(registered) =
            timeout(remaining, self.register_pending(packet, original_id, tx)).await
        else {
            anyhow::bail!(
                "{name} timeout waiting to register for upstream {upstream}",
                name = T::NAME,
                upstream = self.upstream
            );
        };
        let (new_packet, new_id) = registered?;
        let remaining = timeout_dur.saturating_sub(start.elapsed());

        // RAII Guard: ensures entry is removed from map when guard is dropped
        // RAII Guard：确保在 guard 丢弃时（超时、取消、提前返回）移除条目
        let _guard = RemoveOnDrop {
            map: self.pending.clone(),
            id: new_id,
        };

        // 2. Write request with remaining timeout (connection already ensured)
        // 2. 写入请求（连接已确保）
        let write_res = timeout(remaining, async {
            // Frame already contains length prefix + payload — write directly, no second copy.
            // 帧已包含长度前缀 + 负载——直接写入，无二次拷贝。
            let mut guard = self.conn.lock().await;

            // Connection must exist (ensure_connection was called earlier)
            // 连接必须存在（ensure_connection 已在之前调用）
            // Pre-flight check: if writer is closed or broken, fail fast
            if guard.is_none() {
                anyhow::bail!("{} write half missing", T::LABEL);
            }

            // Note: OwnedWriteHalf doesn't support peek/checking error directly easily without shared socket access.
            // But if the previous read failed, guard should be None (reset).
            // The fact we are here means 'guard' is Some, so we think connection is alive.
            // Writing to a closed socket usually triggers error immediately on Linux/BSD.

            // 写入期间被取消时丢弃连接，避免半条帧留在池里 / Drop the connection
            // if the write is cancelled, so half a frame cannot stay pooled
            let mut write_guard = TcpWriteGuard {
                slot: &mut guard,
                needs_reset: &self.write_cancelled,
                armed: true,
            };
            let writer = write_guard
                .slot
                .as_mut()
                .expect("connection presence checked above");
            // TLS 流在 socket 写满时会先收下明文、返回"已写入"，加密后的记录留在缓冲
            // 里，要等下一次写或 flush 才发出去；不 flush 的话，流量少时这个查询可能
            // 一直等到超时。TCP 的 flush 什么也不做。
            // When the socket is full a TLS stream accepts the plaintext and
            // reports it written while the encrypted records stay buffered until
            // the next write or flush; without the flush, on a quiet connection
            // the query could wait out its whole timeout. A TCP flush does nothing.
            let mut result = writer.write_all(&new_packet).await;
            if result.is_ok() {
                result = writer.flush().await;
            }
            // 走到这里说明写入已经结束：成功则帧是完整的，失败则下面会 reset。
            // Reaching here means the write finished: complete on success, and
            // the caller resets on failure.
            write_guard.armed = false;

            if let Err(e) = result {
                return Err(anyhow::anyhow!(e).context(format!("{} write failed", T::LABEL)));
            }
            Ok::<(), anyhow::Error>(())
        })
        .await;

        match write_res {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                // Guard will remove pending entry automatically
                // Guard 会自动移除 pending 条目

                // The socket is likely dead: record the error and reset the connection, failing
                // the queries still waiting on it (see `reset`)
                // socket 多半已经死了：记一次错误并复位连接，还在等这条连接的查询一起失败（见 `reset`）
                self.record_error().await;
                self.reset().await;
                self.consecutive_errors.store(0, Ordering::Release);

                return Err(err).context(format!(
                    "{name} write/connect failed for upstream {upstream}",
                    name = T::NAME,
                    upstream = self.upstream
                ));
            }
            Err(_) => {
                // Guard will remove pending entry automatically

                // The write timed out: reset the connection, or have the next connect reset
                // it when the lock is busy (see `reset_after_deadline`)
                // 写入超时：复位连接，锁被占着时交给下一次建连去复位（见 `reset_after_deadline`）
                self.reset_after_deadline().await;

                return Err(anyhow::anyhow!(
                    "{name} write/connect timeout for upstream {upstream} (timeout: {timeout_ms}ms)",
                    name = T::NAME,
                    upstream = self.upstream,
                    timeout_ms = remaining.as_millis()
                ));
            }
        }

        let answers_at_write = self.answers_read.load(Ordering::Acquire);

        // 3. Wait for response
        // 3. 等待响应
        let elapsed_after_write = start.elapsed();
        if elapsed_after_write >= timeout_dur {
            // Guard will remove pending entry automatically

            // The deadline passed before waiting began: reset the connection, or have the
            // next connect reset it when the lock is busy (see `reset_after_deadline`)
            // 还没开始等就到了时限：复位连接，锁被占着时交给下一次建连去复位（见 `reset_after_deadline`）
            self.reset_after_deadline().await;

            return Err(anyhow::anyhow!(
                "{name} timeout before waiting for response from upstream {upstream} (elapsed: {elapsed_ms}ms, timeout: {timeout_ms}ms)",
                name = T::NAME,
                upstream = self.upstream,
                elapsed_ms = elapsed_after_write.as_millis(),
                timeout_ms = timeout_dur.as_millis()
            ));
        }
        let final_remaining = timeout_dur - elapsed_after_write;

        let resp = match timeout(final_remaining, rx).await {
            Ok(Ok(Ok(response))) => {
                // Record success and clear error count
                // 记录成功并清零错误计数
                self.record_success();
                response
            }
            Ok(Ok(Err(err))) => {
                // 连接在等待期间断开或被重置，所有等待的查询都被告知了；这不是成功，
                // 是否换新连接重发由 send() 决定
                // The connection broke or was reset while this query waited, and
                // every waiter was told. That is no success; send() decides on a
                // retry over a fresh connection
                return Err(err);
            }
            Ok(Err(_canceled)) => {
                // Guard will remove pending entry automatically

                // Record error but DO NOT reset - Mux handles ignored responses
                // 记录错误但不重置 - Mux 会处理被忽略的响应
                self.record_error().await;
                return Err(anyhow::anyhow!(
                    "{name} response canceled for upstream {upstream}",
                    name = T::NAME,
                    upstream = self.upstream
                ));
            }
            Err(_elapsed) => {
                // Guard will remove pending entry automatically

                // 写出之后这条连接还在回答别的查询：连接是活的，只是这一个回答慢。重建
                // 连接只会让同一条连接上其他查询的回答跟着丢掉，也不算连接出错
                // The connection kept answering other queries after this one was
                // written: it is alive and only this answer is slow. Rebuilding it
                // would only lose the other answers on it, and it is no connection error
                if self.answers_read.load(Ordering::Acquire) > answers_at_write {
                    return Err(anyhow::anyhow!(
                        "{name} response timeout from upstream {upstream} (remaining: {timeout_ms}ms); the connection is still answering",
                        name = T::NAME,
                        upstream = self.upstream,
                        timeout_ms = final_remaining.as_millis()
                    ));
                }

                // No answer in time and the connection has gone quiet (likely dead or
                // stalled): reset it, or have the next connect reset it when the lock is busy
                // (see `reset_after_deadline`)
                // 时限内没有回答，连接也没了动静（多半已死或卡住）：复位它，锁被占着时交给下一次建连去
                // 复位（见 `reset_after_deadline`）
                self.reset_after_deadline().await;

                return Err(anyhow::anyhow!(
                    "{name} response timeout from upstream {upstream} (remaining: {timeout_ms}ms)",
                    name = T::NAME,
                    upstream = self.upstream,
                    timeout_ms = final_remaining.as_millis()
                ));
            }
        };
        Ok(resp)
    }

    /// Ensure the connection exists, connecting if needed. One connection carries
    /// any number of queries at once (multiplexing).
    /// 确保连接存在，没有就建连。一条连接上可以同时跑任意多个查询（多路复用）。
    ///
    /// `budget` bounds the connect (DoT's TLS handshake included); on failure
    /// the lock is released immediately.
    /// `budget` 约束建连（包括 DoT 的 TLS 握手）；失败时立即释放锁。
    async fn ensure_connection(&self, budget: Duration) -> anyhow::Result<()> {
        let started = tokio::time::Instant::now();
        // First, check if we need to reconnect based on error state
        // 首先，根据错误状态检查是否需要重连
        let errors = self.consecutive_errors.load(Ordering::Acquire);
        // 写入被取消过：写半边已经在 Drop 里丢掉了，这里补上取消 reader token、
        // 让还在等的查询失败，让清理和普通错误路径完全对称。
        // A cancelled write already dropped the write half in Drop; this cancels
        // the reader token and fails the queries still waiting, so the cleanup
        // matches the ordinary error path exactly.
        let write_cancelled = self.write_cancelled.swap(false, Ordering::AcqRel);
        let needs_reset = errors > 0 || write_cancelled;

        if needs_reset {
            debug!(
                upstream = %self.upstream,
                consecutive_errors = errors,
                write_cancelled,
                "{} connection needs a reset before ensure",
                T::NAME
            );
            // 欠着的复位也守预算：前面的写入占着锁时不能等过时限；没做完下次再做
            // An owed reset keeps to the budget too: with writes holding the lock
            // ahead of it, it must not wait past the deadline; if unfinished, the next
            // connect does it
            if timeout(budget, self.reset()).await.is_err() {
                if write_cancelled {
                    self.write_cancelled.store(true, Ordering::Release);
                }
                anyhow::bail!(
                    "{} timeout resetting the connection after {}ms",
                    T::LABEL,
                    budget.as_millis()
                );
            }
        }

        // 等连接锁也算在预算里：前面有查询占着锁时，不能等过自己的时限
        // Waiting for the connection lock counts against the budget too: with the lock
        // held ahead of it, a query must not wait past its own deadline
        let Ok(mut guard) =
            timeout(budget.saturating_sub(started.elapsed()), self.conn.lock()).await
        else {
            anyhow::bail!(
                "{} timeout waiting for the connection after {}ms",
                T::LABEL,
                budget.as_millis()
            );
        };
        let budget = budget.saturating_sub(started.elapsed());

        if guard.is_none() {
            let (read_half, write_half) = T::connect(&self.shared, &self.upstream, budget).await?;

            *guard = Some(write_half);

            // Increment generation for new connection
            // 为新连接增加代数
            let new_gen = self.generation.fetch_add(1, Ordering::Relaxed) + 1;

            // Create fresh cancellation token for this connection lifecycle
            // 为此连接生命周期创建新的取消令牌
            let new_token = CancellationToken::new();

            // Spawn reader while holding the lock to prevent races
            // 持有锁时启动 reader 以防止竞争
            self.spawn_reader(read_half, new_token.clone(), new_gen);

            // Store token AFTER spawn so reset() can only cancel a live reader
            // 在 spawn 之后存储 token，确保 reset() 只能取消已启动的 reader
            {
                let mut token_guard = self.read_cancel.lock().await;
                *token_guard = new_token;
            }

            // 设置连接创建时间
            // Set connection creation time
            let now = unix_time_millis();
            self.conn_create_time.store(now, Ordering::Release);
            self.last_request_time.store(now, Ordering::Release);

            // Clear error count for new connection
            // 清除新连接的错误计数
            self.consecutive_errors.store(0, Ordering::Release);

            info!(upstream = %self.upstream, "{} connection established", T::NAME);
        }

        Ok(())
    }

    /// Rewrite DNS transaction ID and register in pending map atomically, returning the frame to write
    /// 原子操作：重写 DNS 事务 ID 并注册到 pending map，返回要写出的帧
    async fn register_pending(
        &self,
        packet: &[u8],
        original_id: u16,
        tx: oneshot::Sender<anyhow::Result<Bytes>>,
    ) -> anyhow::Result<(Bytes, u16)> {
        // Build complete TCP/DoT wire frame (2-byte length prefix + DNS message). Caller writes
        // it directly without further copying, and the same buffer stays in the pending
        // entry for the answer's question check, as on UDP.
        // 构建完整 TCP/DoT wire frame（2 字节长度前缀 + DNS 消息）。调用方直接写入、无需二次拷贝；
        // 同一份缓冲还留在 pending 条目里供应答比对问题，和 UDP 一样。
        let mut frame = BytesMut::with_capacity(2 + packet.len());
        frame.extend_from_slice(&(packet.len() as u16).to_be_bytes());
        frame.extend_from_slice(packet);

        // Serialize registration with connection teardown so a failed reader cannot miss a waiter.
        // 将 pending 注册与连接清理串行化，避免失败的 reader 遗漏 waiter。
        let conn_guard = self.conn.lock().await;
        if conn_guard.is_none() {
            anyhow::bail!("connection closed before registration");
        }

        let mut tries = 0;
        let (frame, new_id) = loop {
            let cand = self.next_id.fetch_add(1, Ordering::Relaxed);
            tries += 1;

            // Use Entry API to check vacancy and insert atomically
            // 使用 Entry API 检查空位并原子插入
            if let entry::Entry::Vacant(e) = self.pending.entry(cand) {
                // TXID at offset 2 (after length prefix) / 偏移 2 处（长度前缀之后）
                frame[2..4].copy_from_slice(&cand.to_be_bytes());
                let frame = frame.freeze();
                e.insert(Pending {
                    original_id,
                    frame: frame.clone(),
                    tx,
                });
                break (frame, cand);
            }

            // 头一个 ID 就被占着时看看是不是全被占了：65536 个 ID 都被等着的查询占着时立刻说没有，
            // 不在连接锁下把每个 ID 都试一遍。以前一大批这样的查询排着队各试一遍，后面的都远远超出
            // 时限。数一遍要锁每个分片，所以平常拿到空 ID 时不数
            // The first ID taken, see whether all are: with all 65536 held by waiting
            // queries, say so at once rather than try every ID under the connection
            // lock. A crowd of such queries used to take turns trying them all, the later
            // ones running far past their deadlines. Counting locks every shard, so it
            // is skipped while the first ID is free
            if tries == 1 && self.pending.len() > u16::MAX as usize {
                anyhow::bail!("no available dns ids for {} mux", T::LABEL);
            }
            if tries > u16::MAX as usize {
                anyhow::bail!("no available dns ids for {} mux", T::LABEL);
            }
        };
        drop(conn_guard);
        Ok((frame, new_id))
    }

    async fn fail_all_async(
        pending: &Arc<dashmap::DashMap<u16, Pending, FxBuildHasher>>,
        err: anyhow::Error,
        conn: &Arc<Mutex<Option<T::Write>>>,
    ) {
        // Hold the connection lock while resetting and draining. register_pending uses the same
        // lock, so it either registers before this drain or observes the closed connection.
        let mut conn_guard = conn.lock().await;
        Self::fail_all_locked(pending, err, &mut conn_guard);
    }

    /// [`fail_all_async`](Self::fail_all_async)，连接锁已经拿在手里 / [`fail_all_async`](Self::fail_all_async) with the connection lock already held
    fn fail_all_locked(
        pending: &Arc<dashmap::DashMap<u16, Pending, FxBuildHasher>>,
        err: anyhow::Error,
        conn_guard: &mut Option<T::Write>,
    ) {
        let err_msg = err.to_string();
        *conn_guard = None;
        let keys: Vec<u16> = pending.iter().map(|item| *item.key()).collect();
        for key in keys {
            if let Some((_, p)) = pending.remove(&key) {
                let _ = p.tx.send(Err(anyhow::anyhow!(err_msg.clone())));
            }
        }
    }

    /// Reset connection: cancel reader task, then drop write half and fail every
    /// waiting query
    /// 重置连接：取消 reader 任务，然后丢弃写半部、让所有等待中的查询失败
    ///
    /// The cancellation token interrupts the reader's blocked read so it
    /// exits immediately instead of leaking the connection. With the reader
    /// gone nothing can answer the queries still waiting on this connection, so
    /// they are failed at once: each can then retry over a fresh connection
    /// instead of sitting out its whole deadline and resetting the next
    /// connection in turn.
    /// 取消令牌中断 reader 阻塞的读取操作，使其立即退出而非泄漏连接。reader 没了，
    /// 这条连接上还在等的查询再也等不到回答，所以立刻让它们失败：各自可以换新连接重发，
    /// 而不是干等到截止时间、再轮流把下一条连接也重置掉。
    async fn reset(&self) {
        self.read_cancel.lock().await.cancel();
        Self::fail_all_async(
            &self.pending,
            anyhow::anyhow!("{} connection reset", T::NAME),
            &self.conn,
        )
        .await;
    }

    /// 时限已经到了的查询复位连接。连接锁空着就马上复位；被别人拿着时（多半是排着队的写入）不等，
    /// 记一次错误，下一次建连会先复位（见 `ensure_connection`）。以前这里一直等锁，排在长队后面的
    /// 查询要远远超出时限才返回。
    /// Reset the connection for a query whose deadline has passed. With the
    /// connection lock free it resets at once; held by someone else (most likely a
    /// queue of writes) it does not wait but records an error, and the next connect
    /// resets first (see `ensure_connection`). It used to wait for the lock, so a
    /// query at the back of a long queue returned far past its deadline.
    async fn reset_after_deadline(&self) {
        let Ok(mut conn) = self.conn.try_lock() else {
            self.consecutive_errors.fetch_add(1, Ordering::Release);
            return;
        };
        self.read_cancel.lock().await.cancel();
        Self::fail_all_locked(
            &self.pending,
            anyhow::anyhow!("{} connection reset", T::NAME),
            &mut conn,
        );
        self.consecutive_errors.store(0, Ordering::Release);
    }
}

// ===================== DoH (DNS over HTTPS) =====================

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
    /// 最近一次使用的时刻，用于清理热重载换掉的旧上游
    /// When the entry was last used, so upstreams dropped by a reload can be pruned
    last_used_millis: AtomicU64,
    /// 回了 429 以后暂停到什么时候，从 `DohClient::epoch` 起算的毫秒数；没暂停过是 0
    /// Until when a 429 paused it, in milliseconds from `DohClient::epoch`; 0 if it never was
    paused_until: AtomicU64,
}

pub struct DohClient {
    /// Per-upstream state, created the first time an upstream is used.
    /// 按上游划分的状态，首次使用该上游时创建。
    upstreams: DashMap<Arc<str>, Arc<DohUpstream>, FxBuildHasher>,
    pool_max_idle_per_host: usize,
    /// Threshold of consecutive transport errors that triggers a pool rebuild.
    /// 触发连接池重建的连续传输错误阈值
    health_error_threshold: usize,
    /// 上次清理空闲上游的时刻 / When idle upstreams were last pruned
    last_prune_millis: AtomicU64,
    /// 暂停时刻的起点。用单调时钟，调系统时间不会让暂停变长或变短
    /// The origin of pause deadlines. A monotonic clock, so setting the system time makes
    /// no pause longer or shorter
    epoch: std::time::Instant,
    /// 所有上游里最晚的暂停结束时刻（同样从 `epoch` 起算），过了就清回 0。合并转发先看它：
    /// 没有上游在暂停时，判断只花这一次读取
    /// The latest pause end over all upstreams (from `epoch` too), cleared back to 0 once
    /// past. A merged forward looks at it first: with no upstream paused, the check costs
    /// this one load
    latest_pause_end: AtomicU64,
    /// 测试里改走明文 http：引擎把 DoH 上游一律当 https，本机的假 DoH 上游只会说 http
    /// Plain http in tests: the engine takes every DoH upstream as https, and the local fake
    /// DoH upstream speaks http only
    #[cfg(test)]
    plain_http: AtomicBool,
}

impl DohClient {
    pub fn new(
        pool_max_idle_per_host: usize,
        health_error_threshold: usize,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            upstreams: DashMap::with_hasher(FxBuildHasher),
            pool_max_idle_per_host,
            health_error_threshold,
            last_prune_millis: AtomicU64::new(unix_time_millis()),
            epoch: std::time::Instant::now(),
            latest_pause_end: AtomicU64::new(0),
            #[cfg(test)]
            plain_http: AtomicBool::new(false),
        })
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

    /// Build a fresh reqwest client. Used for both initial construction and pool
    /// rebuilds (the latter evicts dead/half-open connections).
    /// 构建新的 reqwest 客户端，用于初始构造和连接池重建（后者驱逐死/半开连接）
    fn build_client(pool_max_idle_per_host: usize) -> anyhow::Result<DohHttpClient> {
        DohHttpClient::builder()
            // A DoH server has no reason to redirect, and following one could send
            // the query elsewhere, plain HTTP included; a 3xx fails like any other
            // non-success status
            // DoH 服务器没有理由跳转，跟着跳可能把查询发到别处，包括明文 HTTP；3xx 和别的非成功状态一样算失败
            .redirect(reqwest::redirect::Policy::none())
            .http2_adaptive_window(true)
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(pool_max_idle_per_host.max(1))
            .build()
            .context("build doh http client")
    }

    /// State for `upstream`, built on first sight. One map read per query on
    /// the hot path; the key is allocated once per upstream.
    /// `upstream` 的状态，首次遇到时创建。热路径每查询一次 map 读取；key 每个上游只分配一次。
    fn upstream(&self, upstream: &str) -> anyhow::Result<Arc<DohUpstream>> {
        let now = unix_time_millis();
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
                let state = Arc::new(DohUpstream {
                    client: ArcSwap::from_pointee(Self::build_client(self.pool_max_idle_per_host)?),
                    consecutive_errors: AtomicUsize::new(0),
                    last_used_millis: AtomicU64::new(now),
                    paused_until: AtomicU64::new(0),
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
        // 先占下这一轮：CAS 成功的调用者负责扫描，其它调用者立刻返回。时间戳在
        // 扫描之前就推后，所以无论这轮删没删掉东西，热路径都要再等一个间隔才会
        // 走到这里——之前的数量门槛放在 CAS 之前，不满足时直接 return 而不推后
        // 时间戳，于是每一次查询都要付一次 DashMap::len()（逐分片取读锁）。
        // Claim the round first: the caller that wins the CAS does the scan and
        // the others return. The timestamp moves before the scan, so whether or
        // not this round drops anything the hot path waits another interval to
        // get here. The entry-count gate used to sit before the CAS and return
        // without moving the timestamp, so every lookup paid a DashMap::len(),
        // which takes a read lock on every shard.
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
        let (url, host_override) = build_doh_url(upstream)?;
        #[cfg(test)]
        let url = self.scheme_for_tests(url);
        let host = host_override.as_deref();
        let state = self.upstream(upstream)?;

        let start = tokio::time::Instant::now();
        let result = match Self::send_once(&state, packet, &url, host, timeout_dur).await {
            Ok(bytes) => {
                state.consecutive_errors.store(0, Ordering::Release);
                return Ok(restore_query_id(packet, bytes));
            }
            Err(err) if is_transport_error(&err) => {
                // TRANSPARENT RETRY: DNS queries are semantically idempotent, so a
                // single retry is safe. record_error() may rebuild the pool first;
                // the retry then loads the fresh client (new connections).
                // 透明重试：DNS 查询语义幂等，单次重试安全。
                // record_error() 可能先重建连接池，重试时加载新客户端（新连接）。
                let rebuilt = self.record_error(upstream, &state);
                let remaining = timeout_dur.saturating_sub(start.elapsed());
                if remaining < MIN_RETRY_BUDGET {
                    return Err(err);
                }
                debug!(
                    upstream = upstream,
                    error = %err,
                    pool_rebuilt = rebuilt,
                    retry_timeout_ms = remaining.as_millis() as u64,
                    "DoH transport error, performing transparent retry"
                );
                Self::send_once(&state, packet, &url, host, remaining).await
            }
            Err(e) => Err(e),
        };
        // 429，不管是第一次还是重试时回的：这个上游暂停一会儿
        // A 429, whether to the first send or to the retry: the upstream pauses for a while
        if let Err(err) = &result
            && let Some(throttle) = throttle_of(err)
        {
            self.pause(upstream, &state, throttle);
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

    /// Single attempt: send the request and read the body within a timeout.
    /// 单次尝试：在超时内发送请求并读取响应体
    async fn send_once(
        state: &DohUpstream,
        packet: &[u8],
        url: &Url,
        host_override: Option<&str>,
        timeout_dur: Duration,
    ) -> anyhow::Result<Bytes> {
        // load_full() returns an owned Arc<Client>, keeping the Future Send across
        // await points (an ArcSwap Guard would not). The Arc is cheap to hold.
        // load_full() 返回 owned Arc<Client>，保持 Future 跨 await 点 Send
        // （ArcSwap 的 Guard 不满足）。持有 Arc 很廉价。
        let client = state.client.load_full();

        let mut req = client
            .post(url.clone())
            .header(ACCEPT, DOH_MEDIA_TYPE)
            .header(CONTENT_TYPE, DOH_MEDIA_TYPE)
            .body(packet.to_vec());

        if let Some(host) = host_override {
            req = req.header(HOST, host);
        }

        // Wrap entire operation (send + read body) in a single timeout to prevent
        // hanging if the server sends headers but delays the body.
        // 将整个操作（发送 + 读取响应体）包裹在单个超时中，
        // 防止服务器发送头信息但延迟响应体时挂起。
        let result = timeout(timeout_dur, async {
            let resp = req.send().await.context("doh request send failed")?;

            let status = resp.status();
            if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
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

            let body = read_doh_body(resp).await?;
            // RFC 5452 §9.1, as on the other transports: the answer has to be for
            // this question
            // RFC 5452 §9.1，和别的传输一样：回答必须是这个问题的
            if !crate::proto_utils::answers_query(packet, &body) {
                return Err(doh_answer_error(
                    "doh reply does not answer the query".to_string(),
                ));
            }
            Ok(body)
        })
        .await;

        // 超时算传输层错误，可以重试；内层的错误照原样交出：发送、IO、正文出错可以重试，
        // DohAnswerError 不行（见 `is_transport_error`）
        // A timeout is a transport error and can be retried; inner errors go out as they
        // are: send, IO and body errors can be retried, a DohAnswerError cannot (see
        // `is_transport_error`)
        result.map_err(|_elapsed| anyhow::anyhow!("doh request timeout"))?
    }

    /// Record a consecutive transport error for the upstream. When the count
    /// reaches the threshold, rebuild that upstream's reqwest client (evicting
    /// its dead connection pool) and reset the counter. Returns true if rebuilt.
    /// 记录 upstream 的连续传输错误。计数达阈值时重建该上游的 reqwest 客户端
    /// （驱逐其死连接池）并清零计数。重建返回 true。
    fn record_error(&self, upstream: &str, state: &DohUpstream) -> bool {
        let count = state.consecutive_errors.fetch_add(1, Ordering::AcqRel) + 1;
        if self.health_error_threshold > 0 && count >= self.health_error_threshold {
            match Self::build_client(self.pool_max_idle_per_host) {
                Ok(new_client) => {
                    // Swap in a fresh client; the old pool is released once in-flight
                    // requests holding a cloned Arc finish.
                    // 替换为新客户端；旧池在持有 Arc 副本的在途请求结束后释放
                    state.client.store(Arc::new(new_client));
                    warn!(
                        upstream = upstream,
                        consecutive_errors = count,
                        threshold = self.health_error_threshold,
                        "DoH error threshold exceeded, rebuilding connection pool"
                    );
                    state.consecutive_errors.store(0, Ordering::Release);
                    true
                }
                Err(e) => {
                    warn!(
                        upstream = upstream,
                        error = %e,
                        "failed to rebuild DoH client, keeping old pool"
                    );
                    false
                }
            }
        } else {
            debug!(
                upstream = upstream,
                consecutive_errors = count,
                threshold = self.health_error_threshold,
                "DoH transport error recorded"
            );
            false
        }
    }

    /// [`Self::record_error`] for `upstream` by its name / 按名字找到 `upstream` 再 [`Self::record_error`]
    #[cfg(test)]
    fn record_error_of(&self, upstream: &str) -> bool {
        let state = self.upstream(upstream).expect("doh upstream state");
        self.record_error(upstream, &state)
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

/// Read a DoH answer body, at most one DNS message long. A server sending without
/// end used to have every byte kept until the request timed out, gigabytes for a
/// single answer.
/// 读 DoH 回答的正文，最多一条 DNS 消息那么长。以前一个不停往回发的服务器发多少就收多少，直到请求超时，
/// 一个回答就能占掉几个 GB。
async fn read_doh_body(mut resp: reqwest::Response) -> anyhow::Result<Bytes> {
    let Some(first) = resp.chunk().await.context("read doh response body")? else {
        return Ok(Bytes::new());
    };
    // An answer usually arrives in one piece, handed on as it is
    // 回答一般一块就到齐，那时原样交出
    let mut length = first.len();
    let mut joined: Option<BytesMut> = None;
    loop {
        if length > MAX_DNS_MESSAGE_SIZE {
            return Err(doh_answer_error(format!(
                "doh answer longer than {MAX_DNS_MESSAGE_SIZE} bytes"
            )));
        }
        let Some(chunk) = resp.chunk().await.context("read doh response body")? else {
            return Ok(joined.map_or(first, BytesMut::freeze));
        };
        length += chunk.len();
        joined
            .get_or_insert_with(|| BytesMut::from(first.as_ref()))
            .extend_from_slice(&chunk);
    }
}

/// A transport-level error is anything that is NOT an unusable answer (see
/// [`DohAnswerError`]): timeouts, connection failures, and IO errors all indicate a
/// possibly dead connection and are safe to retry once (DoH queries are
/// semantically idempotent).
/// 传输层错误 = 不是用不了的回答（见 [`DohAnswerError`]）：超时、连接失败、IO 错误都指示连接可能已死，
/// 单次重试安全（DoH 查询语义幂等）
fn is_transport_error(err: &anyhow::Error) -> bool {
    err.downcast_ref::<DohAnswerError>().is_none()
}

fn build_doh_url(upstream: &str) -> anyhow::Result<(Url, Option<String>)> {
    let url_str = if upstream.starts_with("http://") || upstream.starts_with("https://") {
        upstream.to_string()
    } else if let Some(stripped) = upstream.strip_prefix("doh://") {
        format!("https://{}", stripped)
    } else {
        format!("https://{}", upstream)
    };

    let mut url = Url::parse(&url_str).context("invalid doh url")?;

    // Default path for DoH if not provided
    if url.path().is_empty() || url.path() == "/" {
        url.set_path("/dns-query");
    }

    let mut host_override: Option<String> = None;
    if url.query().is_some() {
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        for (k, v) in url.query_pairs() {
            if k.eq_ignore_ascii_case("host") {
                if !v.is_empty() {
                    host_override = Some(v.to_string());
                }
            } else {
                serializer.append_pair(&k, &v);
            }
        }
        let new_query = serializer.finish();
        if new_query.is_empty() {
            url.set_query(None);
        } else {
            url.set_query(Some(&new_query));
        }
    }

    Ok((url, host_override))
}

// ===================== DoT (DNS over TLS) =====================

type DotTlsStream = tokio_rustls::client::TlsStream<TcpStream>;

#[derive(Clone)]
struct DotTarget {
    connect_addr: Arc<str>,
    sni: Arc<str>,
}

/// DNS over TLS（RFC 7858），多路复用见 [`StreamMultiplexer`]
/// DNS over TLS (RFC 7858), multiplexed by [`StreamMultiplexer`]
pub struct Dot;

impl StreamTransport for Dot {
    type Read = tokio::io::ReadHalf<DotTlsStream>;
    type Write = tokio::io::WriteHalf<DotTlsStream>;
    type Shared = Arc<ClientConfig>;
    const LABEL: &'static str = "dot";
    const NAME: &'static str = "DoT";
    const LOG_TARGET: &'static str = "dot_mux";

    async fn connect(
        tls_config: &Arc<ClientConfig>,
        upstream: &str,
        budget: Duration,
    ) -> anyhow::Result<(Self::Read, Self::Write)> {
        let target = parse_dot_target(upstream)?;

        // Connect and complete the TLS handshake within the budget: an
        // upstream that accepts and stays silent would otherwise hold the
        // lock, and every request queued behind it, indefinitely.
        // 在预算内建连并完成 TLS 握手：accept 后沉默的上游否则会无限期占住锁，
        // 排在后面的请求一起被钉死。
        let tls_connector = TlsConnector::from(tls_config.clone());
        let server_name = build_server_name(&target.sni)?;
        let connect = async {
            let stream = TcpStream::connect(&*target.connect_addr)
                .await
                .map_err(|e| anyhow::anyhow!("dot connect failed: {}", e))?;
            tune_stream_socket(&stream, upstream);
            tls_connector
                .connect(server_name, stream)
                .await
                .context("dot tls handshake failed")
        };
        let tls_stream = match timeout(budget, connect).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => return Err(e),
            Err(_) => anyhow::bail!(
                "dot connect/handshake timeout after {}ms",
                budget.as_millis()
            ),
        };
        Ok(tokio::io::split(tls_stream))
    }
}

fn build_tls_client_config() -> anyhow::Result<ClientConfig> {
    let mut root_store = RootCertStore::empty();
    root_store.extend(TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Ok(config)
}

fn build_server_name(name: &str) -> anyhow::Result<ServerName<'static>> {
    if let Ok(ip) = name.parse::<std::net::IpAddr>() {
        let ip = rustls::pki_types::IpAddr::from(ip);
        Ok(ServerName::IpAddress(ip))
    } else {
        ServerName::try_from(name.to_string()).context("invalid tls server name")
    }
}

/// URL 里的主机，IPv6 地址不带方括号。`Url::host_str` 会把方括号原样带上，拼地址时
/// 就成了 `[[…]]:853`，拿去当证书名或判断是不是 IP 也都对不上。
/// The URL's host, an IPv6 address without its brackets. `Url::host_str` keeps
/// the brackets, which turned into `[[…]]:853` once joined with the port and
/// matched neither a certificate name nor an IP check.
fn url_host(url: &Url) -> Option<String> {
    Some(match url.host()? {
        url::Host::Domain(domain) => domain.to_string(),
        url::Host::Ipv4(addr) => addr.to_string(),
        url::Host::Ipv6(addr) => addr.to_string(),
    })
}

/// `主机:端口`，IPv6 地址加上方括号 / `host:port`, with brackets around an IPv6 address
fn host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// 一个上游地址（不带前缀）用 `transport` 读不读得懂，读法和各个客户端连接时一样
/// Whether `transport` can read one upstream address (prefix removed), read the
/// way each client reads it when it connects
pub(crate) fn check_upstream_address(
    address: &str,
    transport: crate::config::Transport,
) -> anyhow::Result<()> {
    use crate::config::Transport;

    // UDP 只认 IP 和端口（见 UdpClient::send）；TCP 交给 TcpStream::connect，也认域名
    // UDP takes an IP and a port only (see UdpClient::send); TCP goes to
    // TcpStream::connect, which takes a name too
    let socket_address = |address: &str| -> anyhow::Result<()> {
        let parsed: SocketAddr = address
            .parse()
            .context("expected an IP address and a port")?;
        anyhow::ensure!(parsed.port() != 0, "port 0");
        Ok(())
    };
    match transport {
        Transport::Udp | Transport::TcpUdp => socket_address(address),
        Transport::Tcp => {
            if socket_address(address).is_ok() {
                return Ok(());
            }
            let (host, port) = address
                .rsplit_once(':')
                .context("expected a host and a port")?;
            let port: u16 = port.parse().context("invalid port")?;
            anyhow::ensure!(port != 0, "port 0");
            anyhow::ensure!(
                !host.is_empty()
                    && host
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.'),
                "invalid host \"{host}\""
            );
            Ok(())
        }
        Transport::Doh => build_doh_url(address).map(drop),
        // 建连时拿 SNI 做 TLS 服务器名，做不成的名字（`%20`、`.`）每次建连都会失败
        // A connect makes the TLS server name from the SNI, so a name that makes none
        // (`%20`, `.`) would fail every connect
        Transport::Dot => build_server_name(&parse_dot_target(address)?.sni).map(drop),
        Transport::Doq => build_server_name(&parse_doq_target(address)?.sni).map(drop),
    }
}

/// DoT、DoQ 上游地址共有的部分：没写协议时补上 `scheme`，主机，端口（默认 853），不许带路径，
/// `sni`/`servername` 参数（空的不算，多个时取最后一个）。错误文字里的协议名就是 `scheme`
/// What DoT and DoQ upstream addresses share: `scheme` added when none is written, the
/// host, the port (853 by default), no path, and the `sni`/`servername` parameter (an
/// empty one does not count, the last of several wins). The errors name `scheme`
fn parse_tls_upstream(
    upstream: &str,
    scheme: &str,
) -> anyhow::Result<(Url, String, u16, Option<String>)> {
    let url = if upstream.contains("://") {
        Url::parse(upstream)
    } else {
        Url::parse(&format!("{scheme}://{upstream}"))
    }
    .with_context(|| format!("invalid {scheme} upstream url"))?;

    let host = url_host(&url).with_context(|| format!("{scheme} upstream missing host"))?;
    let port = url.port().unwrap_or(853);

    if !url.path().is_empty() && url.path() != "/" {
        anyhow::bail!("{scheme} upstream should not contain path");
    }

    let sni = url
        .query_pairs()
        .filter(|(k, v)| {
            (k.eq_ignore_ascii_case("sni") || k.eq_ignore_ascii_case("servername")) && !v.is_empty()
        })
        .last()
        .map(|(_, v)| v.to_string());
    Ok((url, host, port, sni))
}

fn parse_dot_target(upstream: &str) -> anyhow::Result<DotTarget> {
    let (_, host, port, sni) = parse_tls_upstream(upstream, "dot")?;

    let connect_addr = host_port(&host, port);
    let sni_value = sni.unwrap_or(host);

    Ok(DotTarget {
        connect_addr: Arc::from(connect_addr.as_str()),
        sni: Arc::from(sni_value.as_str()),
    })
}

// ===================== DoQ (DNS over QUIC) =====================

const MAX_DNS_MESSAGE_SIZE: usize = 65_535;

#[derive(Clone)]
struct DoqTarget {
    host: Arc<str>,
    port: u16,
    sni: Arc<str>,
    /// Enable 0-RTT for this specific upstream (overrides global setting)
    /// 为此特定上游启用 0-RTT（覆盖全局设置）
    /// None = use global setting, Some(true) = force enable, Some(false) = force disable
    /// None = 使用全局设置，Some(true) = 强制启用，Some(false) = 强制禁用
    enable_0rtt: Option<bool>,
}

struct DoqRuntime {
    endpoint_v4: QuicEndpoint,
    endpoint_v6: QuicEndpoint,
    enable_0rtt: bool,
    /// 0-RTT 的安全提示只在真正用上 0-RTT 时打印一次
    /// Prints the 0-RTT security notice once, and only if 0-RTT is really used
    zero_rtt_notice: std::sync::Once,
}

struct DoqConnectionInfo {
    conn: QuicConnection,
    used_0rtt: bool,
    /// 连接取自连接池，而不是为这次查询新建的
    /// The connection came from the pool rather than being made for this query
    reused: bool,
}

/// DoQ (DNS over QUIC) 连接池
/// DoQ (DNS over QUIC) connection pool
///
/// 参考 RFC 9250 (DNS over Dedicated QUIC Connections) 实现
/// Implements RFC 9250 (DNS over Dedicated QUIC Connections)
pub type DoqConnectionPool = ConnectionPool<DoqMuxClient>;

/// DoQ 一次尝试的失败原因，按类型保留 quinn 的原始错误
/// Why one DoQ attempt failed, keeping quinn's own error by type
///
/// 此前内层每一步都被 `.context()` 包过，而 `anyhow::Error::to_string()` 只
/// 输出最外层那一句，所以判定 0-RTT 是否被拒绝时拿到的永远只是那几个固定
/// 短语，quinn 说的话根本到不了。把原始错误原样带出来，判定就能落在类型上。
/// Every step used to be wrapped in `.context()`, and
/// `anyhow::Error::to_string()` renders only the outermost one, so the check
/// for a rejected 0-RTT attempt never saw anything but a handful of fixed
/// phrases and never quinn's own words. Carrying the error out untouched lets
/// the decision rest on types.
#[derive(Debug)]
enum DoqFailure {
    /// `open_bi` 失败：连接已经不可用 / the connection is already unusable
    OpenStream(quinn::ConnectionError),
    /// 写查询失败 / writing the query failed
    Write(quinn::WriteError),
    /// 读应答失败 / reading the answer failed
    Read(quinn::ReadToEndError),
    /// 应答本身不合协议，与 0-RTT 无关 / the answer itself is malformed
    Protocol(String),
}

impl std::fmt::Display for DoqFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OpenStream(err) => write!(f, "doq open stream failed: {err}"),
            Self::Write(err) => write!(f, "doq send query failed: {err}"),
            Self::Read(err) => write!(f, "doq read response failed: {err}"),
            Self::Protocol(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for DoqFailure {
    /// 保住 quinn 的 source 链：类型化到这里就被拍平成字符串的话，日志里就只
    /// 剩 Display 那一行了。
    /// Keeps quinn's source chain: flattening to a string at this boundary
    /// would leave the log with nothing but the Display line.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::OpenStream(err) => Some(err),
            Self::Write(err) => Some(err),
            Self::Read(err) => Some(err),
            Self::Protocol(_) => None,
        }
    }
}

/// DoQ (DNS over QUIC) 客户端，管理多个上游的 QUIC 连接池
/// DoQ (DNS over QUIC) client, managing QUIC connection pools for multiple upstreams
///
/// 参考 RFC 9250 (DNS over Dedicated QUIC Connections) 实现
/// Implements RFC 9250 (DNS over Dedicated QUIC Connections)
pub struct DoqClient {
    pools: UpstreamPools<DoqMuxClient>,
    /// 每个池几个客户端，至少一个 / How many clients a pool has, at least one
    pool_size: usize,
    runtime: Arc<DoqRuntime>,
}

/// DoQ (DNS over QUIC) 多路复用客户端，管理单个上游的 QUIC 连接
/// DoQ (DNS over QUIC) multiplexing client, managing QUIC connection for a single upstream
///
/// 参考 RFC 9250 (DNS over Dedicated QUIC Connections) 实现
/// Implements RFC 9250 (DNS over Dedicated QUIC Connections)
pub struct DoqMuxClient {
    upstream: Arc<str>,
    target: Mutex<Option<DoqTarget>>,
    connection: Mutex<Option<QuicConnection>>,
    runtime: Arc<DoqRuntime>,
    /// Track whether 0-RTT has been rejected by the server for auto-fallback
    /// 跟踪服务器是否拒绝了 0-RTT，用于自动回退
    /// Once rejected, 0-RTT will be skipped for subsequent connections
    /// 一旦被拒绝，后续连接将跳过 0-RTT
    ///
    /// 同一个上游连接池里的所有连接共用这个标记：一条连接学到的事，其余连接不必再各
    /// 失败一次、各等满一次超时
    /// Shared by every connection in the upstream's pool: what one connection
    /// learned, the others need not each fail and sit out a timeout to learn again
    zero_rtt_rejected: Arc<AtomicBool>,
    /// 连接老化：创建时间戳（毫秒）/ Connection aging: creation timestamp (ms)
    conn_create_time: AtomicU64,
    /// 空闲超时：最后请求时间（毫秒）/ Idle timeout: last request time (ms)
    last_request_time: AtomicU64,
    /// 性能优化：上次健康检查时间（毫秒）/ Performance: last health check time (ms)
    last_health_check_time: AtomicU64,
}

/// DoQ 连接最长用多久（毫秒）：30 分钟 / How long a DoQ connection may live (ms): 30 minutes
const DOQ_MAX_AGE_MS: u64 = 30 * 60 * 1000;
/// DoQ 连接空闲多久（毫秒）就换新的：5 分钟 / How long a DoQ connection may sit idle (ms) before a new one: 5 minutes
const DOQ_IDLE_TIMEOUT_MS: u64 = 5 * 60 * 1000;

impl DoqClient {
    /// 只留下 `keep` 认可的上游的连接池。重载后配置里不再有的上游，连接池就此丢掉：正在用它的
    /// 查询拿着连接池，做完才释放；之后它的连接随之关闭。
    /// Keeps only the pools of the upstreams `keep` accepts. After a reload, the pool of an
    /// upstream the configuration no longer names is dropped: queries using it hold on to
    /// it until they finish, and its connections close after that.
    pub(crate) fn retain_upstreams(&self, keep: impl Fn(&str) -> bool) {
        self.pools.retain(keep);
    }

    pub fn new(
        pool_size: usize,
        idle_timeout_secs: u64,
        keepalive_interval_ms: u64,
        enable_0rtt: bool,
    ) -> anyhow::Result<Self> {
        let mut tls = build_tls_client_config()?;
        tls.alpn_protocols = vec![b"doq".to_vec()];
        tls.enable_early_data = enable_0rtt;

        let quic_crypto = QuicClientConfig::try_from(tls).context("build quic client config")?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));

        let mut transport_config = QuicTransportConfig::default();

        // Set initial RTT to 100ms (idoq best practice)
        // This helps QUIC estimate initial round-trip time for better congestion control
        // 设置初始 RTT 为 100ms（idoq 最佳实践）
        // 这有助于 QUIC 估算初始往返时间，以实现更好的拥塞控制
        transport_config.initial_rtt(Duration::from_millis(100));

        // Set max concurrent streams (idoq best practice)
        // 设置最大并发流数（idoq 最佳实践）
        transport_config.max_concurrent_bidi_streams(100u32.into());
        transport_config.max_concurrent_uni_streams(100u32.into());

        if keepalive_interval_ms > 0 {
            transport_config
                .keep_alive_interval(Some(Duration::from_millis(keepalive_interval_ms)));
        }
        if idle_timeout_secs > 0 {
            let idle_timeout = Duration::from_secs(idle_timeout_secs)
                .try_into()
                .context("invalid doq idle timeout")?;
            transport_config.max_idle_timeout(Some(idle_timeout));
        }
        client_config.transport_config(Arc::new(transport_config));

        let mut endpoint_v4 = QuicEndpoint::client("0.0.0.0:0".parse()?)?;
        endpoint_v4.set_default_client_config(client_config.clone());

        let endpoint_v6 = match QuicEndpoint::client("[::]:0".parse()?) {
            Ok(mut ep) => {
                ep.set_default_client_config(client_config);
                ep
            }
            Err(e) => {
                warn!(error = %e, "Failed to bind IPv6 QUIC endpoint, falling back to IPv4 only");
                endpoint_v4.clone()
            }
        };

        let runtime = Arc::new(DoqRuntime {
            endpoint_v4,
            endpoint_v6,
            enable_0rtt,
            zero_rtt_notice: std::sync::Once::new(),
        });

        Ok(Self {
            pools: UpstreamPools::new(),
            pool_size: pool_size.max(1),
            runtime,
        })
    }

    pub async fn send(
        &self,
        packet: &[u8],
        upstream: &str,
        timeout_dur: Duration,
    ) -> anyhow::Result<Bytes> {
        let pool = self.pools.get_or_create(upstream, |upstream| {
            // 一个池的连接共用对 0-RTT 的了解 / A pool's connections share what they learn about 0-RTT
            let zero_rtt_rejected = Arc::new(AtomicBool::new(false));
            (0..self.pool_size)
                .map(|_| {
                    Arc::new(DoqMuxClient::new(
                        upstream.clone(),
                        Arc::clone(&self.runtime),
                        Arc::clone(&zero_rtt_rejected),
                    ))
                })
                .collect()
        });
        pool.pick().send(packet, timeout_dur).await
    }
}

impl DoqMuxClient {
    fn new(
        upstream: Arc<str>,
        runtime: Arc<DoqRuntime>,
        zero_rtt_rejected: Arc<AtomicBool>,
    ) -> Self {
        Self {
            upstream,
            target: Mutex::new(None),
            connection: Mutex::new(None),
            runtime,
            zero_rtt_rejected,
            conn_create_time: AtomicU64::new(0),
            last_request_time: AtomicU64::new(0),
            last_health_check_time: AtomicU64::new(0),
        }
    }

    /// Record a success / 记一次成功
    fn record_success(&self) {
        let now = unix_time_millis();
        self.last_request_time.store(now, Ordering::Release);
    }

    /// Check if connection needs reset due to aging or idle timeout
    /// 检查连接是否需要重置（老化或空闲超时）
    async fn check_connection_health(&self) -> bool {
        let now = unix_time_millis();

        // Throttle health checks: only check once per second
        let last_check = self.last_health_check_time.load(Ordering::Acquire);
        if now.saturating_sub(last_check) < 1000 {
            return false;
        }
        self.last_health_check_time.store(now, Ordering::Release);

        // Check connection aging
        let create_time = self.conn_create_time.load(Ordering::Acquire);
        let max_age = DOQ_MAX_AGE_MS;
        if create_time > 0 {
            let age_ms = now.saturating_sub(create_time);
            if age_ms > max_age {
                info!(
                    upstream = %self.upstream,
                    age_ms = age_ms,
                    max_age_ms = max_age,
                    "DoQ connection too old, resetting"
                );
                self.reset_connection().await;
                return true;
            }
        }

        // Check idle timeout
        let last_req = self.last_request_time.load(Ordering::Acquire);
        let idle_timeout = DOQ_IDLE_TIMEOUT_MS;
        if last_req > 0 {
            let idle_ms = now.saturating_sub(last_req);
            if idle_ms > idle_timeout {
                info!(
                    upstream = %self.upstream,
                    idle_ms = idle_ms,
                    idle_timeout_ms = idle_timeout,
                    "DoQ connection idle too long, resetting"
                );
                self.reset_connection().await;
                return true;
            }
        }

        false
    }

    pub async fn send(&self, packet: &[u8], timeout_dur: Duration) -> anyhow::Result<Bytes> {
        let target = {
            let mut guard = self.target.lock().await;
            if guard.is_none() {
                *guard = Some(parse_doq_target(&self.upstream)?);
            }
            guard
                .as_ref()
                .context("doq target missing after initialization")?
                .clone()
        };

        if target.host.is_empty() {
            anyhow::bail!("invalid doq upstream: {}", self.upstream);
        }

        self.send_with_retry(&target, packet, timeout_dur).await
    }

    async fn send_with_retry(
        &self,
        target: &DoqTarget,
        packet: &[u8],
        timeout_dur: Duration,
    ) -> anyhow::Result<Bytes> {
        // RFC 9250 §4.2.1: DNS Message ID over DoQ MUST be set to 0.
        // We preserve original ID for local correlation and restore it in the final response.
        // RFC 9250 §4.2.1：DoQ 上的 DNS Message ID 必须为 0。
        // 我们保留原始 ID 用于本地关联，并在最终响应中恢复。
        if packet.len() < 2 {
            anyhow::bail!("dns packet too short for doq");
        }
        let original_id = u16::from_be_bytes([packet[0], packet[1]]);

        // 一次查询最多重试一次 / A query is retried at most once
        let mut allow_retry = true;
        let mut timeout_dur = timeout_dur;

        loop {
            // Check connection health (aging, idle timeout) before each attempt
            // 每次尝试前检查连接健康状态（老化、空闲超时）
            self.check_connection_health().await;

            let start = tokio::time::Instant::now();
            // 解析上游名字、等连接锁、握手和等回答共用这一份预算。此前握手和回答各拿
            // 一整份超时，一个请求最多能跑到配置值的两倍，系统解析上游名字则完全不受限
            // Resolving the upstream name, waiting for the connection lock, the
            // handshake and the answer share this one budget. The handshake and
            // the answer used to get a full timeout each, so a request could run
            // to twice the configured value, and resolving the name had no bound
            let DoqConnectionInfo {
                conn,
                used_0rtt,
                reused,
            } = match timeout(timeout_dur, self.get_or_connect(target, timeout_dur)).await {
                Ok(info) => info?,
                Err(_) => anyhow::bail!("doq connect timeout after {}ms", timeout_dur.as_millis()),
            };
            let query_budget = timeout_dur.saturating_sub(start.elapsed());
            if query_budget.is_zero() {
                anyhow::bail!("doq timeout before sending the query");
            }

            let resp = timeout(query_budget, async {
                // 内层返回带类型的失败，而不是 anyhow：每一步都被 context 包过
                // 之后，anyhow 的 to_string 只剩最外层那一句，quinn 的原始错误
                // 到不了判定处。
                // The inner block yields a typed failure rather than anyhow:
                // once every step is wrapped in context, anyhow's to_string
                // leaves only the outermost sentence and quinn's own error never
                // reaches the decision.
                let (mut send, mut recv) = conn.open_bi().await.map_err(DoqFailure::OpenStream)?;

                // RFC 9250 §4.2: DNS messages sent over QUIC streams MUST be prefixed
                // with a 2-octet length field, followed by the DNS message content.
                // Each query uses a separate bidirectional stream; the message boundary
                // is signalled by FIN.
                // RFC 9250 §4.2: QUIC 流上的 DNS 消息必须使用 2 字节长度前缀，
                // 后跟 DNS 消息内容。每个查询使用单独的双向流；消息边界由 FIN 信号标识。
                //
                // RFC 9250 §4.2.1: DNS Message ID MUST be 0 over DoQ.
                // Build complete wire frame in one allocation, no intermediate copy.
                // RFC 9250 §4.2.1: DoQ 上 DNS Message ID 必须为 0。
                // 单次分配构建完整 wire frame，无中间拷贝。
                let mut frame = Vec::with_capacity(2 + packet.len());
                frame.extend_from_slice(&(packet.len() as u16).to_be_bytes());
                frame.extend_from_slice(packet);
                frame[2] = 0; // Message ID = 0 (RFC 9250 §4.2.1) / 消息 ID = 0
                frame[3] = 0;

                send.write_all(&frame).await.map_err(DoqFailure::Write)?;
                let _ = send.finish();

                // Read response: 2-byte length prefix followed by DNS message
                // 读取响应：2 字节长度前缀，后跟 DNS 消息
                // Note: The server sends the response and closes the stream with FIN
                // We need to read all data until FIN, then parse the length prefix
                // 注意：服务器发送响应后用 FIN 关闭流
                // 我们需要读取所有数据直到 FIN，然后解析长度前缀
                // 连接被对端关掉的判断此前靠字符串，而且那个判断把所有原因都
                // 折叠成同一句话；现在原样把 quinn 的错误带出去，由
                // zero_rtt_likely_rejected 按类型判定。
                // Detecting a peer-closed connection used to go through strings,
                // and that check folded every cause into one sentence. The quinn
                // error is now carried out as it is and
                // zero_rtt_likely_rejected decides by type.
                let mut all_data = recv
                    .read_to_end(MAX_DNS_MESSAGE_SIZE + 2)
                    .await
                    .map_err(DoqFailure::Read)?;

                if all_data.is_empty() {
                    return Err(DoqFailure::Protocol(
                        "doq received empty response (server closed stream without sending data)"
                            .to_string(),
                    ));
                }

                if all_data.len() < 2 {
                    return Err(DoqFailure::Protocol(format!(
                        "doq response too short: {} bytes",
                        all_data.len()
                    )));
                }

                let msg_len = u16::from_be_bytes([all_data[0], all_data[1]]) as usize;

                // idoq-style length validation: response length must match length prefix
                // idoq 风格的长度验证：响应长度必须匹配长度前缀
                if all_data.len() != 2 + msg_len {
                    return Err(DoqFailure::Protocol(format!(
                        "doq length mismatch: expected {} bytes (2 + {}), got {} bytes. \
                        This may indicate data corruption or server protocol violation.",
                        2 + msg_len,
                        msg_len,
                        all_data.len()
                    )));
                }

                let buf = &all_data[2..2 + msg_len];
                if buf.len() < 2 {
                    // DNS message must be at least 2 bytes for TXID restoration.
                    // Also prevents all_data[2..4] index out of bounds when msg_len < 2.
                    // DNS 消息必须至少 2 字节才能恢复 TXID。
                    // 同时防止 msg_len < 2 时 all_data[2..4] 越界。
                    return Err(DoqFailure::Protocol(format!(
                        "doq DNS message too short: {msg_len} bytes"
                    )));
                }
                // RFC 5452 §9.1, as on the other transports: the answer has to be
                // for this question
                // RFC 5452 §9.1，和别的传输一样：回答必须是这个问题的
                if !crate::proto_utils::answers_query(packet, buf) {
                    return Err(DoqFailure::Protocol(
                        "doq reply does not answer the query".to_string(),
                    ));
                }
                // Restore original DNS Message ID in-place (Vec<u8> is mutable).
                // Bytes::from(Vec) takes ownership of the heap allocation (zero-copy).
                // slice(2..) returns a view past the length prefix (zero-copy, shares allocation).
                // 原地恢复原始 DNS Message ID（Vec<u8> 可变）。
                // Bytes::from(Vec) 接管堆分配（零拷贝）。
                // slice(2..) 返回跳过长度前缀的视图（零拷贝，共享分配）。
                all_data[2..4].copy_from_slice(&original_id.to_be_bytes());
                Ok::<Bytes, DoqFailure>(Bytes::from(all_data).slice(2..))
            })
            .await;

            match resp {
                Ok(Ok(bytes)) => {
                    self.record_success();
                    return Ok(bytes);
                }
                Ok(Err(failure)) => {
                    // 每次失败都复位连接 / Every failure resets the connection
                    self.reset_connection().await;
                    let retry = if !allow_retry {
                        false
                    } else if used_0rtt
                        && self.zero_rtt_retry_allowed(target)
                        && Self::zero_rtt_likely_rejected(&failure)
                    {
                        self.disable_zero_rtt();
                        warn!(
                            upstream = %self.upstream,
                            error = %failure,
                            "DoQ 0-RTT likely rejected, retrying without 0-RTT"
                        );
                        true
                    } else if reused && Self::connection_gone(&failure) {
                        // 池里的连接在两次查询之间断了（服务器的空闲超时可能比保活间隔还短），
                        // 这次查询本身没问题：换一条新连接再发一次
                        // The pooled connection died between two queries (a server's
                        // idle timeout can be shorter than our keep-alive interval);
                        // the query itself is fine, so send it again on a fresh one
                        debug!(
                            upstream = %self.upstream,
                            error = %failure,
                            "DoQ pooled connection is gone, retrying on a fresh connection"
                        );
                        true
                    } else {
                        false
                    };
                    let remaining = timeout_dur.saturating_sub(start.elapsed());
                    if retry && !remaining.is_zero() {
                        allow_retry = false;
                        timeout_dur = remaining;
                        continue;
                    }
                    return Err(anyhow::Error::new(failure));
                }
                Err(_) => {
                    // 只有用了 0-RTT 的连接超时才算 0-RTT 的嫌疑；普通连接上的超时
                    // 只是这次回答慢，不能因此把 0-RTT 永久关掉
                    // Only a timeout on a connection that used 0-RTT puts 0-RTT
                    // under suspicion; on a normal connection it just means a slow
                    // answer and must not switch 0-RTT off for good
                    if used_0rtt {
                        self.disable_zero_rtt();
                        if allow_retry {
                            let remaining = timeout_dur.saturating_sub(start.elapsed());
                            self.reset_connection().await;
                            if remaining.is_zero() {
                                return Err(anyhow::anyhow!("doq timeout"));
                            }
                            warn!(
                                upstream = %self.upstream,
                                "DoQ 0-RTT timeout detected, retrying without 0-RTT"
                            );
                            allow_retry = false;
                            timeout_dur = remaining;
                            continue;
                        }
                    }
                    self.reset_connection().await;
                    return Err(anyhow::anyhow!("doq timeout"));
                }
            }
        }
    }

    /// 这次失败是否像 0-RTT 被拒绝，值得关掉 0-RTT 再试一次
    /// Whether this failure looks like a rejected 0-RTT attempt and is worth one
    /// retry with 0-RTT off
    ///
    /// 两类算数：quinn 明确报告 `ZeroRttRejected`；或者连接被对端关闭、重置、
    /// 丢失——服务器拒绝 0-RTT 数据时常常直接关连接，而不是报那个专门的错误。
    /// 本地关闭、超时、协议层面的问题都不算，它们和 0-RTT 无关。
    ///
    /// 纯函数，不吃 `&self`，所以测试可以直接拿 quinn 的错误值驱动它。
    /// Two things count: quinn saying `ZeroRttRejected` outright, and the
    /// connection being closed, reset or lost by the peer, since a server that
    /// refuses 0-RTT data often just closes instead of raising that specific
    /// error. A local close, a timeout and any protocol-level problem do not,
    /// having nothing to do with 0-RTT. It takes no `&self`, so a test can drive
    /// it with real quinn error values.
    fn zero_rtt_likely_rejected(failure: &DoqFailure) -> bool {
        fn peer_ended_it(err: &quinn::ConnectionError) -> bool {
            matches!(
                err,
                quinn::ConnectionError::ApplicationClosed(_)
                    | quinn::ConnectionError::ConnectionClosed(_)
                    | quinn::ConnectionError::Reset
            )
        }

        match failure {
            DoqFailure::OpenStream(err) => peer_ended_it(err),
            DoqFailure::Write(quinn::WriteError::ZeroRttRejected) => true,
            DoqFailure::Write(quinn::WriteError::ConnectionLost(err)) => peer_ended_it(err),
            DoqFailure::Read(quinn::ReadToEndError::Read(err)) => match err {
                quinn::ReadError::ZeroRttRejected => true,
                quinn::ReadError::ConnectionLost(err) => peer_ended_it(err),
                _ => false,
            },
            _ => false,
        }
    }

    /// 这次失败是否说明连接本身已经没了（而不是这一次查询出了问题）
    /// Whether this failure means the connection itself is gone, rather than
    /// something being wrong with this one query
    ///
    /// 开流失败、写或读的时候连接丢了，都算；流被对端重置、应答不合协议都不算，
    /// 换连接重发也不会更好。
    /// A failed stream open and a connection lost during the write or the read
    /// count. A stream reset by the peer or a malformed answer do not, as
    /// sending again on another connection would not help.
    fn connection_gone(failure: &DoqFailure) -> bool {
        matches!(
            failure,
            DoqFailure::OpenStream(_)
                | DoqFailure::Write(quinn::WriteError::ConnectionLost(_))
                | DoqFailure::Read(quinn::ReadToEndError::Read(
                    quinn::ReadError::ConnectionLost(_)
                ))
        )
    }

    /// 在这条连接上是否还允许关掉 0-RTT 重试：配置开着、且还没被标记过拒绝
    /// Whether a 0-RTT retry is still allowed here: enabled by configuration and
    /// not already marked as rejected
    fn zero_rtt_retry_allowed(&self, target: &DoqTarget) -> bool {
        target.enable_0rtt.unwrap_or(self.runtime.enable_0rtt)
            && !self.zero_rtt_rejected.load(Ordering::Relaxed)
    }

    /// 给这个上游关掉 0-RTT；查和改是同一步，同时来的几个里只有一个记 warn
    /// Switch 0-RTT off for this upstream; checking and setting is one step, so of
    /// several arriving at once only one logs the warn
    fn disable_zero_rtt(&self) {
        if !self.zero_rtt_rejected.swap(true, Ordering::Relaxed) {
            warn!(
                upstream = %self.upstream,
                "DoQ 0-RTT rejected or unstable, disabling 0-RTT for this upstream until restart"
            );
        }
    }
    async fn get_or_connect(
        &self,
        target: &DoqTarget,
        timeout_dur: Duration,
    ) -> anyhow::Result<DoqConnectionInfo> {
        // Single-lock pattern: acquire lock once, check + create in one critical section.
        // This prevents the TOCTOU race where two coroutines both pass the first check,
        // then both create connections, wasting one.
        // 单锁模式：一次获取锁，检查+创建在一个临界区内完成。
        // 防止两个协程同时通过第一次检查后都创建连接、浪费一个的竞态。
        let mut guard = self.connection.lock().await;
        if let Some(conn) = guard.as_ref() {
            // 对端关掉的、或者空闲超时的连接还留在这里的话，拿去用只会让这次查询失败
            // A connection the peer closed, or one that idled out, would only
            // fail this query if handed out again
            match conn.close_reason() {
                None => {
                    return Ok(DoqConnectionInfo {
                        conn: conn.clone(),
                        used_0rtt: false,
                        reused: true,
                    });
                }
                Some(reason) => {
                    debug!(
                        upstream = %self.upstream,
                        reason = %reason,
                        "DoQ pooled connection already closed, reconnecting"
                    );
                    *guard = None;
                }
            }
        }

        let (conn, used_0rtt) = self.connect_new(target, timeout_dur).await?;
        *guard = Some(conn.clone());

        // Record connection creation time for aging checks
        // 记录连接创建时间用于老化检查
        let now = unix_time_millis();
        self.conn_create_time.store(now, Ordering::Release);
        self.last_request_time.store(now, Ordering::Release);

        Ok(DoqConnectionInfo {
            conn,
            used_0rtt,
            reused: false,
        })
    }

    async fn connect_new(
        &self,
        target: &DoqTarget,
        timeout_dur: Duration,
    ) -> anyhow::Result<(QuicConnection, bool)> {
        let addr_str = host_port(&target.host, target.port);
        let addrs = tokio::net::lookup_host(&addr_str)
            .await
            .context("doq resolve failed")?;

        // 优先使用 IPv4 地址，避免 IPv6 连接问题
        // Prefer IPv4 addresses to avoid IPv6 connection issues
        // 某些网络的 IPv6 连接不稳定或 MTU 限制导致 QUIC Initial 数据包发送失败
        // Some networks have unstable IPv6 or MTU limits causing QUIC Initial packet send failures
        let addrs_vec: Vec<_> = addrs.collect();
        let addr = addrs_vec
            .iter()
            .find(|a| a.is_ipv4())
            .or_else(|| addrs_vec.first())
            .context("doq resolve returned no addresses")?;

        let addr = *addr;

        let endpoint = if addr.is_ipv6() {
            &self.runtime.endpoint_v6
        } else {
            &self.runtime.endpoint_v4
        };
        let connecting = endpoint
            .connect(addr, target.sni.as_ref())
            .context("doq connect failed")?;

        // 0-RTT：上游设置优先于全局设置，之前被拒绝过就跳过（见 `zero_rtt_retry_allowed`）
        // 0-RTT: the upstream's setting before the global one, skipped once it was
        // rejected (see `zero_rtt_retry_allowed`)
        let connecting = if self.zero_rtt_retry_allowed(target) {
            // Security warning: 0-RTT (early data) is vulnerable to replay attacks
            // per RFC 8446 §8 and RFC 9001 §5.4. DNS queries are idempotent, so
            // replay impact is limited to redundant lookups and potential cache
            // timing side-channels. Only enable 0-RTT in trusted network environments.
            // The client is built for every configuration, so the notice waits for
            // the first connection that actually offers early data.
            // 安全警告：0-RTT（早期数据）容易受到重放攻击（RFC 8446 §8, RFC 9001 §5.4）。
            // DNS 查询是幂等的，因此重放影响仅限于冗余查询和潜在的缓存时序侧信道。
            // 仅在可信网络环境中启用 0-RTT。客户端在任何配置下都会构造，因此提示
            // 推迟到第一个真正发送早期数据的连接。
            self.runtime.zero_rtt_notice.call_once(|| {
                tracing::warn!(
                    upstream = %target.host,
                    "DoQ 0-RTT enabled: vulnerable to replay attacks (RFC 8446 §8). \
                     DNS queries are idempotent but an attacker can observe timing patterns. \
                     Disable 0-RTT in untrusted environments."
                );
            });
            match connecting.into_0rtt() {
                Ok((conn, _zero_rtt_accepted)) => {
                    // 0-RTT connection established
                    // Note: Some DoQ servers (e.g., Alibaba DNS) may reject 0-RTT data
                    // If you see timeouts, the system will automatically disable 0-RTT for this upstream
                    // 0-RTT 连接已建立
                    // 注意：某些 DoQ 服务器（如阿里 DNS）可能拒绝 0-RTT 数据
                    // 如果遇到超时，系统将自动为此上游禁用 0-RTT
                    debug!(
                        upstream = %self.upstream,
                        "DoQ 0-RTT connection established"
                    );
                    return Ok((conn, true));
                }
                // 0-RTT not available (no previous session), fall back to normal connect
                // 0-RTT 不可用（无先前会话），回退到正常连接
                Err(connecting) => connecting,
            }
        } else {
            connecting
        };

        let connection = timeout(timeout_dur, connecting)
            .await
            .context("doq connect timeout")??;

        Ok((connection, false))
    }

    async fn reset_connection(&self) {
        let mut guard = self.connection.lock().await;
        *guard = None;
        // Reset connection creation time so aging checks start fresh on reconnect
        self.conn_create_time.store(0, Ordering::Release);
    }
}

fn parse_doq_target(upstream: &str) -> anyhow::Result<DoqTarget> {
    let (url, host, port, sni) = parse_tls_upstream(upstream, "doq")?;

    let mut enable_0rtt: Option<bool> = None;
    for (k, v) in url.query_pairs() {
        if k.eq_ignore_ascii_case("0rtt") || k.eq_ignore_ascii_case("enable_0rtt") {
            // Parse 0rtt parameter: true/false/1/0
            // 解析 0rtt 参数：true/false/1/0
            enable_0rtt = match v.to_lowercase().as_str() {
                "true" | "1" | "yes" | "on" => Some(true),
                "false" | "0" | "no" | "off" => Some(false),
                _ => {
                    warn!("invalid doq 0rtt value: {}, ignoring", v);
                    None
                }
            };
        }
    }

    let is_ip = host.parse::<std::net::IpAddr>().is_ok();
    if sni.is_none() && is_ip {
        anyhow::bail!(
            "doq upstream with IP address requires explicit sni (e.g. doq://223.5.5.5:853?sni=alidns.com)"
        );
    }

    let sni_value = sni.unwrap_or_else(|| host.clone());

    Ok(DoqTarget {
        host: Arc::from(host),
        port,
        sni: Arc::from(sni_value.as_str()),
        enable_0rtt,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::test_support::{DohReply, http_ok, spawn_doh_upstream};

    /// reqwest + rustls 要有进程级的加密实现，明文 http 也一样
    /// reqwest + rustls needs a process-level crypto provider, plain http included
    #[ctor::ctor]
    fn init_crypto() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

    /// 写入中途被取消时，这条池化连接必须被丢弃。取消点与 RemoveOnDrop
    /// 兜的是同一个：外层请求超时先到，或者双发路径上 UDP 先返回导致
    /// tcp_task.abort()。此前只有待处理表那一侧被清理，连接仍然留在池里，
    /// 下一个请求会把自己的帧接在可能只写了一半的帧后面。
    /// A pooled connection has to be dropped when the write is cancelled part
    /// way through. The cancellation point is the one RemoveOnDrop already
    /// covers: the outer request timeout firing first, or the dual-send path
    /// aborting the TCP task once UDP answered. Only the pending-map side used
    /// to be cleaned up, leaving the connection pooled for the next request to
    /// append its frame to a possibly half-written one.
    #[tokio::test]
    async fn a_cancelled_write_drops_the_pooled_connection() {
        // 对端只 accept 不读，发送缓冲区会被填满，写入因此停在 await 上
        // The peer accepts and never reads, so the send buffer fills and the
        // write parks on an await
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (held, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(held);
        });

        let client = Arc::new(TcpMuxClient::new(Arc::from(addr.to_string().as_str())));

        // 直接建连，不走查询——查询超时会自己 reset 掉连接
        // Connect directly: a query would time out and reset the connection
        let query = [0u8; 12];
        client
            .ensure_connection(Duration::from_secs(2))
            .await
            .expect("connect to the test peer");
        assert!(
            client.conn.lock().await.is_some(),
            "the connection must be pooled before the test can mean anything"
        );

        // 把发送缓冲区填满，让后续写入必然停在 await 上
        // Fill the send buffer so any later write must park on an await
        {
            let mut guard = client.conn.lock().await;
            let writer = guard.as_mut().unwrap();
            let chunk = vec![0u8; 65536];
            while tokio::time::timeout(Duration::from_millis(300), writer.write_all(&chunk))
                .await
                .is_ok()
            {}
        }

        // 写入停在 await 上时取消这次发送
        // Cancel the send while the write is parked
        let sender = Arc::clone(&client);
        let task = tokio::spawn(async move { sender.send(&query, Duration::from_secs(30)).await });
        tokio::time::sleep(Duration::from_millis(300)).await;
        task.abort();
        let _ = task.await;

        assert!(
            client.conn.lock().await.is_none(),
            "a write cancelled part way through must drop the connection instead of \
             leaving a possibly half-written frame in the pool"
        );
        assert!(
            client.write_cancelled.load(Ordering::Acquire),
            "the next ensure_connection must be told to finish the cleanup that \
             Drop cannot await: the reader token and the queries still waiting"
        );

        // 下一次建连要真的走完整 reset，并把标志清掉
        // The next connect must take the full reset path and clear the flag
        client
            .ensure_connection(Duration::from_secs(2))
            .await
            .expect("reconnect after a cancelled write");
        assert!(
            !client.write_cancelled.load(Ordering::Acquire),
            "the flag must be consumed, not left to reset a healthy connection later"
        );

        peer.abort();
    }

    /// 0-RTT 判定必须按类型走。此前它比对 `anyhow::Error::to_string()`，而内层
    /// 每一步都被 `.context()` 包过，那个字符串永远只是三句固定短语之一或一条
    /// bail 文本，于是 quinn 明说的 `ZeroRttRejected` 从来没有被识别过：判定
    /// 返回 false，0-RTT 不被禁用，下次连接又用 0-RTT，该上游一直失败到重启。
    /// The 0-RTT decision has to go by type. It used to compare
    /// `anyhow::Error::to_string()`, and since every inner step was wrapped in
    /// `.context()` that string was only ever one of three fixed phrases or a
    /// bail text, so quinn saying `ZeroRttRejected` outright was never
    /// recognised: the check returned false, 0-RTT stayed on, the next
    /// connection used it again and the upstream kept failing until a restart.
    #[test]
    fn doq_zero_rtt_rejection_is_classified_by_type() {
        use quinn::{ConnectionError, ReadError, ReadToEndError, WriteError};

        // quinn 明说被拒绝 / quinn says so outright
        assert!(DoqMuxClient::zero_rtt_likely_rejected(&DoqFailure::Write(
            WriteError::ZeroRttRejected
        )));
        assert!(DoqMuxClient::zero_rtt_likely_rejected(&DoqFailure::Read(
            ReadToEndError::Read(ReadError::ZeroRttRejected)
        )));

        // 对端直接关掉连接：拒绝 0-RTT 数据的服务器常常这样做
        // The peer just closes: what a server refusing 0-RTT data often does
        let closed = || {
            ConnectionError::ApplicationClosed(quinn::ApplicationClose {
                error_code: quinn::VarInt::from_u32(0),
                reason: bytes::Bytes::new(),
            })
        };
        assert!(DoqMuxClient::zero_rtt_likely_rejected(
            &DoqFailure::OpenStream(closed())
        ));
        assert!(DoqMuxClient::zero_rtt_likely_rejected(&DoqFailure::Read(
            ReadToEndError::Read(ReadError::ConnectionLost(closed()))
        )));
        assert!(DoqMuxClient::zero_rtt_likely_rejected(&DoqFailure::Write(
            WriteError::ConnectionLost(ConnectionError::Reset)
        )));

        // 与 0-RTT 无关的失败不该触发重试
        // Failures that have nothing to do with 0-RTT must not trigger a retry
        assert!(!DoqMuxClient::zero_rtt_likely_rejected(
            &DoqFailure::OpenStream(ConnectionError::TimedOut)
        ));
        assert!(!DoqMuxClient::zero_rtt_likely_rejected(
            &DoqFailure::OpenStream(ConnectionError::LocallyClosed)
        ));
        assert!(!DoqMuxClient::zero_rtt_likely_rejected(&DoqFailure::Read(
            ReadToEndError::TooLong
        )));
        assert!(!DoqMuxClient::zero_rtt_likely_rejected(&DoqFailure::Read(
            ReadToEndError::Read(ReadError::ClosedStream)
        )));
        assert!(!DoqMuxClient::zero_rtt_likely_rejected(
            &DoqFailure::Protocol("doq response too short: 1 bytes".to_string())
        ));
    }

    use futures::future::join_all;

    /// UDP "upstream" for UdpClient tests: records the (transaction id, source
    /// port) of every query it receives and answers with each datagram of
    /// `reply(query)`, in order.
    /// UdpClient 测试用的 UDP "上游"：记录每个查询的 (TXID, 源端口)，按序发回
    /// reply(query) 给出的每个数据报。
    async fn spawn_udp_upstream(
        reply: impl Fn(&[u8]) -> Vec<Vec<u8>> + Send + 'static,
    ) -> (String, Arc<std::sync::Mutex<Vec<(u16, u16)>>>) {
        spawn_udp_upstream_on("127.0.0.1:0", reply)
            .await
            .expect("bind UDP test upstream")
    }

    /// 同 [`spawn_udp_upstream`]，绑在 `bind` 上；该地址族不可用时为 None
    /// As [`spawn_udp_upstream`], bound to `bind`; `None` when that address family is
    /// unavailable on this host
    async fn spawn_udp_upstream_on(
        bind: &str,
        reply: impl Fn(&[u8]) -> Vec<Vec<u8>> + Send + 'static,
    ) -> Option<(String, Arc<std::sync::Mutex<Vec<(u16, u16)>>>)> {
        let socket = tokio::net::UdpSocket::bind(bind).await.ok()?;
        let addr = socket.local_addr().expect("read UDP test address");
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorder = Arc::clone(&seen);
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, src)) = socket.recv_from(&mut buf).await {
                let query = &buf[..n];
                let id = u16::from_be_bytes([query[0], query[1]]);
                recorder.lock().unwrap().push((id, src.port()));
                for datagram in reply(query) {
                    let _ = socket.send_to(&datagram, src).await;
                }
            }
        });
        Some((addr.to_string(), seen))
    }

    /// A query for `name` (A, IN) with a fixed transaction id.
    fn udp_test_query(name: &str) -> Vec<u8> {
        use hickory_proto::op::{Message, MessageType, OpCode, Query};
        use hickory_proto::rr::{Name, RecordType};
        let mut msg = Message::new(0x1234, MessageType::Query, OpCode::Query);
        msg.add_query(Query::query(
            Name::from_ascii(name).expect("parse test name"),
            RecordType::A,
        ));
        msg.to_vec().expect("encode test query")
    }

    /// 标上 QR 的查询本身，当作它的回答 / The query itself with QR set, as its answer
    fn echo_answer(query: &[u8]) -> Vec<u8> {
        let mut answer = query.to_vec();
        answer[2] |= 0x80;
        answer
    }

    /// Response to `query` whose question section names `name` instead.
    fn udp_response_with_question(query: &[u8], name: &str) -> Vec<u8> {
        use hickory_proto::op::{Message, MessageType, OpCode, Query};
        use hickory_proto::rr::{Name, RecordType};
        let id = u16::from_be_bytes([query[0], query[1]]);
        let mut msg = Message::new(id, MessageType::Response, OpCode::Query);
        msg.add_query(Query::query(
            Name::from_ascii(name).expect("parse test name"),
            RecordType::A,
        ));
        msg.to_vec().expect("encode test response")
    }

    #[tokio::test]
    async fn udp_send_randomizes_transaction_id_and_source_port() {
        // RFC 5452 §4.3 / §9.2: neither the ID nor the source port may be
        // predictable. Before this, every socket numbered its IDs 0, 1, 2, …
        // and sockets were picked round-robin, so the sequence of (ID, port)
        // pairs was fully predictable.
        // RFC 5452 §4.3/§9.2：TXID 和源端口都不能可预测。此前每个 socket 的 ID 从
        // 0 顺序递增、socket 轮询选择，(ID, 端口) 序列完全可预测。
        let (upstream, seen) = spawn_udp_upstream(|query| vec![echo_answer(query)]).await;
        let client = UdpClient::new(4).expect("create UDP client");
        let sends = 16;
        for _ in 0..sends {
            client
                .send(
                    &udp_test_query("id.example."),
                    &upstream,
                    Duration::from_secs(2),
                )
                .await
                .expect("query answered");
        }
        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen.len(), sends);

        // Sequential numbering keeps every ID below the number of sends per
        // socket; random IDs spread over the whole 16-bit space.
        let ids: Vec<u16> = seen.iter().map(|(id, _)| *id).collect();
        assert!(
            ids.iter().any(|&id| id as usize >= sends),
            "transaction IDs look sequential: {ids:?}"
        );

        // Round-robin socket choice repeats the same port every pool_size sends.
        let ports: Vec<u16> = seen.iter().map(|(_, port)| *port).collect();
        assert!(
            ports
                .iter()
                .enumerate()
                .any(|(i, port)| *port != ports[i % 4]),
            "source ports cycle round-robin: {ports:?}"
        );
    }

    #[tokio::test]
    async fn udp_send_ignores_answer_whose_question_differs() {
        // RFC 5452 §9.1: an answer is only accepted when its question section
        // matches the query; a matching ID and source address are not enough.
        // RFC 5452 §9.1：question 段不匹配的应答必须忽略，ID 和源地址相符不够。
        let (upstream, _seen) =
            spawn_udp_upstream(|query| vec![udp_response_with_question(query, "evil.example.")])
                .await;
        let client = UdpClient::new(1).expect("create UDP client");
        let err = client
            .send(
                &udp_test_query("id.example."),
                &upstream,
                Duration::from_millis(300),
            )
            .await
            .expect_err("an answer for a different question must not be delivered");
        assert!(
            err.to_string().contains("timeout"),
            "expected the query to time out, got: {err:#}"
        );
    }

    #[tokio::test]
    async fn udp_send_accepts_case_randomized_question() {
        // DNS 0x20 upstreams answer with the query name's case scrambled; the
        // match must ignore ASCII case.
        // 0x20 大小写随机化的应答要能匹配：比较忽略 ASCII 大小写。
        let (upstream, _seen) =
            spawn_udp_upstream(|query| vec![udp_response_with_question(query, "Id.ExAmPlE.")])
                .await;
        let client = UdpClient::new(1).expect("create UDP client");
        let response = client
            .send(
                &udp_test_query("id.example."),
                &upstream,
                Duration::from_secs(2),
            )
            .await
            .expect("case-scrambled answer must be accepted");
        assert_eq!(&response[0..2], &[0x12, 0x34], "original ID restored");
    }

    /// EDNS 允许把 UDP 应答协商到 65535 字节。接收缓冲区此前只有 4096 字节，更大的应答被
    /// 系统截掉尾部，解析失败，客户端拿到 SERVFAIL；公共 DNS 一般封顶 1232 字节，自建的、
    /// 缓冲开得大的上游才会发这么大的应答。
    /// EDNS lets a UDP answer be negotiated up to 65535 bytes. The receive buffer
    /// used to hold 4096, so a larger answer lost its tail, failed to parse and
    /// the client got SERVFAIL; public resolvers usually stop at 1232, but a
    /// self-hosted upstream with a larger buffer sends answers this big.
    #[tokio::test]
    async fn udp_send_receives_an_answer_larger_than_4096_bytes() {
        let (upstream, _) = spawn_udp_upstream(|query| {
            let mut answer = echo_answer(query);
            answer.resize(5_000, 0);
            vec![answer]
        })
        .await;
        let client = UdpClient::new(1).expect("build UDP client");
        let answer = client
            .send(
                &udp_test_query("big.example"),
                &upstream,
                Duration::from_secs(2),
            )
            .await
            .expect("the upstream answers");
        assert_eq!(answer.len(), 5_000, "the whole datagram must arrive");
    }

    #[tokio::test]
    async fn udp_send_accepts_record_less_error_without_question() {
        // Some upstreams answer FORMERR/NOTIMP with QDCOUNT = 0. Such a reply
        // carries nothing cacheable, so it is delivered as the fast failure it
        // is instead of being treated as forged and waited out.
        // 有些上游对 FORMERR/NOTIMP 回 QDCOUNT=0：没有可缓存内容，按快速失败投递，
        // 而不是当作伪造等到超时。
        let (upstream, _seen) = spawn_udp_upstream(|query| {
            let mut header_only = query[..12].to_vec();
            header_only[2] |= 0x80;
            header_only[3] = 0x01; // FORMERR
            header_only[5] = 0; // QDCOUNT = 0
            vec![header_only]
        })
        .await;
        let client = UdpClient::new(1).expect("create UDP client");
        let response = client
            .send(
                &udp_test_query("id.example."),
                &upstream,
                Duration::from_secs(2),
            )
            .await
            .expect("record-less FORMERR must be delivered");
        assert_eq!(response.len(), 12);
        assert_eq!(response[3] & 0x0F, 0x01, "RCODE = FORMERR");
    }

    #[tokio::test]
    async fn udp_send_keeps_waiting_after_mismatched_answer() {
        // A mismatched answer must not consume the in-flight entry: the genuine
        // answer arriving right after it is still delivered.
        // 不匹配的应答不能消耗在途条目：紧随其后的真应答仍被投递。
        let (upstream, _seen) = spawn_udp_upstream(|query| {
            vec![
                udp_response_with_question(query, "evil.example."),
                echo_answer(query),
            ]
        })
        .await;
        let client = UdpClient::new(1).expect("create UDP client");
        let query = udp_test_query("id.example.");
        let response = client
            .send(&query, &upstream, Duration::from_secs(2))
            .await
            .expect("genuine answer after a bogus one must be delivered");
        assert_eq!(
            &response[12..],
            &query[12..],
            "delivered answer is the genuine one"
        );
    }

    /// Listener whose accept queue is full and never drained: the kernel drops
    /// further SYNs, so a connect() to it hangs until the SYN retransmits give
    /// up (minutes) unless the caller bounds it.
    /// accept 队列已满且从不 accept 的监听器：内核丢弃后续 SYN，connect() 会挂到
    /// SYN 重传耗尽（分钟级），除非调用方自己设限。
    struct BlackholedListener {
        addr: SocketAddr,
        _listener: Socket,
        _queued: Vec<std::net::TcpStream>,
    }

    async fn blackholed_tcp_listener() -> BlackholedListener {
        let listener = Socket::new(Domain::IPV4, Type::STREAM, None).expect("create listener");
        listener
            .bind(&"127.0.0.1:0".parse::<SocketAddr>().unwrap().into())
            .expect("bind listener");
        listener.listen(1).expect("listen with backlog 1");
        let addr = listener.local_addr().unwrap().as_socket().unwrap();
        let queued = tokio::task::spawn_blocking(move || {
            let mut held = Vec::new();
            for _ in 0..8 {
                if let Ok(stream) =
                    std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(200))
                {
                    held.push(stream);
                }
            }
            held
        })
        .await
        .expect("fill accept queue");
        BlackholedListener {
            addr,
            _listener: listener,
            _queued: queued,
        }
    }

    /// Listener that accepts and then never sends a byte, so a TLS handshake
    /// against it never completes.
    /// accept 后一个字节都不发的监听器：TLS 握手永远完不成。
    async fn silent_tcp_listener() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind silent listener");
        let addr = listener.local_addr().expect("read silent listener address");
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        addr
    }

    #[tokio::test]
    async fn tcp_connect_is_bounded_by_the_request_budget() {
        // ensure_connection used to call TcpStream::connect with no timeout while
        // holding the connection lock: a blackholed upstream pinned the request
        // (and every request queued behind the lock) for the kernel's SYN
        // timeout, regardless of the configured upstream timeout.
        // ensure_connection 曾在持有连接锁时无超时地 connect：上游黑洞时请求（以及排在
        // 锁后的所有请求）会等满内核 SYN 超时，配置的 upstream 超时形同虚设。
        let blackhole = blackholed_tcp_listener().await;
        let client = TcpMuxClient::new(Arc::from(blackhole.addr.to_string()));
        let started = tokio::time::Instant::now();
        let result = timeout(
            Duration::from_secs(3),
            client.send(&[0u8; 12], Duration::from_millis(300)),
        )
        .await
        .expect("send must give up within its budget, not wait for the kernel SYN timeout");
        assert!(result.is_err(), "a blackholed upstream cannot succeed");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "gave up after {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn dot_connect_and_handshake_are_bounded_by_the_request_budget() {
        // Same for DoT, where the TLS handshake is the part that can stall: an
        // upstream that accepts and stays silent must not pin the request.
        // DoT 同理，卡住的是 TLS 握手：accept 后沉默的上游不能钉死请求。
        let addr = silent_tcp_listener().await;
        let client = DotMuxClient::new(
            Arc::from(format!("dot://{addr}?sni=localhost")),
            Arc::new(build_tls_client_config().expect("tls config")),
        );
        let started = tokio::time::Instant::now();
        let result = timeout(
            Duration::from_secs(3),
            client.send(&[0u8; 12], Duration::from_millis(300)),
        )
        .await
        .expect("send must give up within its budget, not wait for a handshake that never comes");
        assert!(result.is_err(), "a silent upstream cannot succeed");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "gave up after {:?}",
            started.elapsed()
        );
    }

    /// TCP upstream that answers the very first query it ever receives
    /// (echoing the frame with QR set) and then swallows everything, on that
    /// connection and on any later one.
    /// 只应答收到的第一个查询（回显帧并置 QR 位），之后无论旧连接还是新连接一律吞掉的
    /// TCP 上游。
    async fn answer_once_then_stall_tcp_upstream() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind stalling upstream");
        let addr = listener
            .local_addr()
            .expect("read stalling upstream address");
        let answered = Arc::new(std::sync::atomic::AtomicBool::new(false));
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let answered = Arc::clone(&answered);
                tokio::spawn(async move {
                    let mut len = [0u8; 2];
                    if stream.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let mut frame = vec![0u8; u16::from_be_bytes(len) as usize];
                    if stream.read_exact(&mut frame).await.is_err() {
                        return;
                    }
                    if !answered.swap(true, Ordering::SeqCst) {
                        frame[2] |= 0x80;
                        let _ = stream.write_all(&len).await;
                        let _ = stream.write_all(&frame).await;
                    }
                    let mut sink = [0u8; 512];
                    while stream.read(&mut sink).await.is_ok_and(|n| n > 0) {}
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn tcp_retry_does_not_exceed_the_request_budget() {
        // The transparent retry over a fresh connection used to be granted a
        // 1.5 s floor even when the caller's budget was already spent, so a
        // 200 ms request took about 1.7 s on a stalled reused connection.
        // 复用连接失败后的透明重试曾无条件给 1.5 s 保底：预算 200 ms 的请求在卡住的
        // 复用连接上要跑约 1.7 s。
        let addr = answer_once_then_stall_tcp_upstream().await;
        let client = TcpMuxClient::new(Arc::from(addr.to_string()));
        let query = [0x12, 0x34, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
        client
            .send(&query, Duration::from_millis(500))
            .await
            .expect("first query on a fresh connection is answered");

        let started = tokio::time::Instant::now();
        let err = client
            .send(&query, Duration::from_millis(200))
            .await
            .expect_err("stalled upstream cannot answer the second query");
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_millis(700),
            "second query took {elapsed:?} on a 200 ms budget: {err:#}"
        );
    }

    /// 绑定在 `bind` 上、把每个查询置 QR 位后原样回显的 UDP 上游；该地址族不可用时为 None。
    /// UDP upstream on `bind` that echoes every query back with QR set, or
    /// `None` when the address family is unavailable on this host.
    async fn spawn_udp_echo_upstream(bind: &str) -> Option<String> {
        let (addr, _) = spawn_udp_upstream_on(bind, |query| vec![echo_answer(query)]).await?;
        Some(addr)
    }

    /// v6 池此前无条件预建：默认 udp_pool_size=64 时，哪怕一个 IPv6 上游都没有
    /// 也要多占 64 个 socket 和 64 个任务。
    /// The v6 pool used to be built unconditionally: with the default
    /// udp_pool_size of 64 a deployment without a single IPv6 upstream still
    /// paid for 64 sockets and 64 tasks.
    #[tokio::test]
    async fn udp_ipv6_pool_is_built_only_when_an_ipv6_upstream_is_used() {
        let client = UdpClient::new(4).expect("create UDP client");
        assert!(
            client.pool_v6.get().is_none(),
            "no IPv6 socket may be created before an IPv6 upstream is used"
        );

        let upstream_v4 = spawn_udp_echo_upstream("127.0.0.1:0")
            .await
            .expect("IPv4 loopback");
        let query = [0x12, 0x34, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
        client
            .send(&query, &upstream_v4, Duration::from_secs(2))
            .await
            .expect("IPv4 upstream reachable");
        assert!(
            client.pool_v6.get().is_none(),
            "IPv4 traffic must not build the IPv6 pool"
        );

        let Some(upstream_v6) = spawn_udp_echo_upstream("[::1]:0").await else {
            eprintln!("IPv6 loopback unavailable, skipping the second half");
            return;
        };
        client
            .send(&query, &upstream_v6, Duration::from_secs(2))
            .await
            .expect("IPv6 upstream reachable");
        assert!(
            client.pool_v6.get().is_some(),
            "the IPv6 pool must appear once an IPv6 upstream is used"
        );
    }

    #[tokio::test]
    async fn udp_send_reaches_an_ipv6_upstream() {
        // The pool only ever created AF_INET sockets, so an IPv6 UDP upstream
        // failed every send with "address family not supported" and the query
        // ended in SERVFAIL while the same host over TCP worked.
        // 连接池只建 AF_INET socket：IPv6 UDP 上游每次发送都失败，查询以 SERVFAIL 告终，
        // 而同一主机走 TCP 正常。
        let Some(upstream) = spawn_udp_echo_upstream("[::1]:0").await else {
            eprintln!("IPv6 loopback unavailable, skipping");
            return;
        };
        let client = UdpClient::new(1).expect("create UDP client");
        let query = [0x12, 0x34, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
        let response = client
            .send(&query, &upstream, Duration::from_secs(2))
            .await
            .expect("IPv6 UDP upstream must be reachable");
        assert_eq!(&response[..2], &query[..2], "original ID restored");

        // IPv4 keeps working through the same client.
        let upstream_v4 = spawn_udp_echo_upstream("127.0.0.1:0")
            .await
            .expect("IPv4 loopback");
        client
            .send(&query, &upstream_v4, Duration::from_secs(2))
            .await
            .expect("IPv4 UDP upstream still reachable");
    }

    async fn connected_tcp_write_half() -> (OwnedWriteHalf, TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind TCP test listener");
        let addr = listener.local_addr().expect("read TCP test address");
        let (client, server) = tokio::join!(TcpStream::connect(addr), listener.accept());
        let client = client.expect("connect TCP test client");
        let (server, _) = server.expect("accept TCP test client");
        let (_, write_half) = client.into_split();
        (write_half, server)
    }

    /// 0-RTT 的安全提示曾在构造 DoQ 客户端时打印，而客户端在任何配置下都会构造，
    /// 于是没有任何 DoQ 上游的部署每次启动也会看到它。
    /// The 0-RTT security notice used to be printed when the DoQ client was
    /// built, and the client is built for every configuration, so deployments
    /// without a single DoQ upstream saw it at every start.
    #[tokio::test]
    async fn doq_client_holds_the_0rtt_notice_until_early_data_is_offered() {
        let client = DoqClient::new(1, 60, 15_000, true).expect("build DoQ client");
        assert!(
            !client.runtime.zero_rtt_notice.is_completed(),
            "building the client must not emit the 0-RTT notice"
        );
    }

    #[test]
    fn doq_query_message_id_must_be_zero() {
        // Verify RFC 9250 §4.2.1: DoQ DNS Message ID MUST be set to 0.
        // The inline frame construction logic (from send_with_retry) zeroes bytes [2..4].
        // 验证 RFC 9250 §4.2.1: DoQ DNS Message ID 必须为 0。
        // 内联帧构建逻辑（来自 send_with_retry）将字节 [2..4] 置零。
        let packet = [0x12, 0x34, 0x01, 0x00, 0xaa, 0xbb];
        let mut frame = Vec::with_capacity(2 + packet.len());
        frame.extend_from_slice(&(packet.len() as u16).to_be_bytes());
        frame.extend_from_slice(&packet);
        frame[2] = 0;
        frame[3] = 0;

        assert_eq!(frame.len(), 2 + packet.len());
        assert_eq!(&frame[0..2], &(packet.len() as u16).to_be_bytes());
        assert_eq!(&frame[2..4], &[0x00, 0x00]);
        assert_eq!(&frame[4..], &packet[2..]);
    }

    #[test]
    fn doq_response_restores_original_message_id() {
        // Verify zero-copy response ID restoration (from send_with_retry):
        // all_data layout: [2 bytes length prefix][DNS message with ID=0]
        // After restoration: ID at offset 2 is replaced with original_id, then slice(2..).
        // 验证零拷贝响应 ID 恢复（来自 send_with_retry）：
        // all_data 布局: [2 字节长度前缀][ID=0 的 DNS 消息]
        // 恢复后: 偏移 2 处的 ID 替换为 original_id，然后 slice(2..)。
        let mut all_data: Vec<u8> = vec![0x00, 0x04, 0x00, 0x00, 0x81, 0x80]; // [len=4][ID=0][flags]
        let original_id: u16 = 0x1234;
        all_data[2..4].copy_from_slice(&original_id.to_be_bytes());
        let restored = bytes::Bytes::from(all_data).slice(2..);

        assert_eq!(&restored[0..2], &[0x12, 0x34]);
        assert_eq!(&restored[2..], &[0x81, 0x80]);
    }

    #[test]
    fn doq_response_short_message_does_not_panic() {
        // Regression test: msg_len < 2 must bail! instead of panicking on all_data[2..4].
        // 回归测试: msg_len < 2 时必须 bail! 而非 all_data[2..4] 越界 panic。
        // all_data layout: [len=1][0xAB] — total 3 bytes, msg_len=1
        let all_data: Vec<u8> = vec![0x00, 0x01, 0xAB];
        let msg_len = u16::from_be_bytes([all_data[0], all_data[1]]) as usize;
        let buf = &all_data[2..2 + msg_len];
        // This is the guard added to prevent panic:
        // 这是为防止 panic 而添加的保护：
        assert!(
            buf.len() < 2,
            "msg_len < 2 should trigger bail, not proceed to copy_from_slice"
        );
    }

    #[test]
    fn doq_target_requires_sni_for_ip() {
        assert!(parse_doq_target("doq://223.5.5.5:853").is_err());
        assert!(parse_doq_target("doq://223.5.5.5:853?sni=alidns.com").is_ok());
        assert!(parse_doq_target("doq://dns.alidns.com:853").is_ok());
    }

    /// README 与 config.rs 都写明阈值 0 表示禁用健康检查，而 `count >= threshold`
    /// 会让 0 变成"每次错误都重建连接池"，正好相反。
    /// README and config.rs both state that a threshold of 0 disables the health
    /// check, while `count >= threshold` turns 0 into a rebuild on every single
    /// error, the exact opposite.
    #[test]
    fn doh_record_error_treats_a_zero_threshold_as_disabled() {
        let client = DohClient::new(8, 0).expect("build doh client");
        let upstream = "doh:8.8.8.8";
        let ptr_before =
            Arc::as_ptr(&client.upstream(upstream).unwrap().client.load_full()) as usize;

        for attempt in 1..=5 {
            assert!(
                !client.record_error_of(upstream),
                "a disabled health check must never rebuild (error {attempt})"
            );
        }
        assert_eq!(
            Arc::as_ptr(&client.upstream(upstream).unwrap().client.load_full()) as usize,
            ptr_before,
            "the connection pool must survive a disabled health check"
        );
    }

    /// 热重载换掉的上游此前会一直留着自己的连接池；现在长期不用的条目会被清掉。
    /// Upstreams a reload replaced used to keep their connection pools forever;
    /// entries nothing has used are now dropped.
    #[test]
    fn doh_prunes_upstreams_nothing_has_used() {
        let client = DohClient::new(8, 3).expect("build doh client");
        for idx in 0..4 {
            client
                .upstream(&format!("https://{idx}.example/dns-query"))
                .expect("create upstream");
        }
        let live = "https://live.example/dns-query";
        client.upstream(live).expect("create live upstream");
        age_out_idle_upstreams(&client, live);

        client
            .upstream("https://new.example/dns-query")
            .expect("create upstream");

        assert!(
            client.upstreams.len() <= 2,
            "idle upstreams must be pruned, {} left",
            client.upstreams.len()
        );
        assert!(
            client.upstreams.contains_key(live),
            "an upstream in use must never be pruned"
        );
    }

    /// 热重载换掉整批上游之后可能再没有新上游出现，此前清理只挂在新键插入上，
    /// 旧条目会留到进程结束；现在查一次已有上游也会触发清理。
    /// A reload can swap the whole upstream set and no new upstream ever follows;
    /// pruning used to hang off new-key inserts alone, so the old entries lived
    /// until the process exited. A lookup of an existing upstream now prunes too.
    #[test]
    fn doh_prunes_idle_upstreams_without_new_keys() {
        let client = DohClient::new(8, 3).expect("build doh client");
        for idx in 0..4 {
            client
                .upstream(&format!("https://{idx}.example/dns-query"))
                .expect("create upstream");
        }
        let live = "https://live.example/dns-query";
        client.upstream(live).expect("create live upstream");
        age_out_idle_upstreams(&client, live);

        // 只重复查询已有上游，不插入任何新键
        // Only look the existing upstream up again; no new key is inserted
        client.upstream(live).expect("look up live upstream");

        assert!(
            client.upstreams.len() <= 2,
            "idle upstreams must be pruned without a new key, {} left",
            client.upstreams.len()
        );
        assert!(
            client.upstreams.contains_key(live),
            "an upstream in use must never be pruned"
        );
    }

    /// 节流窗口过期、但这一轮没有任何条目可清时，时间戳同样要推后；否则每一次
    /// 查询都会重新走到扫描前的检查上——正常配置的上游数很少，这条路径原先永远
    /// 命中，等于每个 DoH 查询白付一次全分片的 DashMap::len()。
    /// When the interval has lapsed but the round drops nothing, the timestamp
    /// must still move. Otherwise every later lookup walks back into the check
    /// before the scan, and since a normal deployment has only a handful of
    /// upstreams that used to happen on every single DoH query.
    #[test]
    fn doh_prune_round_is_claimed_even_when_nothing_expires() {
        let client = DohClient::new(8, 3).expect("build doh client");
        let live = "https://live.example/dns-query";
        client.upstream(live).expect("create upstream");

        // 窗口过期，但条目都是刚用过的 / interval lapsed, every entry just used
        let lapsed =
            unix_time_millis().saturating_sub(DOH_UPSTREAM_PRUNE_EVERY.as_millis() as u64 * 2);
        client.last_prune_millis.store(lapsed, Ordering::Relaxed);

        client.upstream(live).expect("look up upstream");

        assert!(
            client.last_prune_millis.load(Ordering::Relaxed) > lapsed,
            "a lapsed interval must be claimed even when nothing is dropped"
        );
        assert!(
            client.upstreams.contains_key(live),
            "an upstream in use must never be pruned"
        );
    }

    /// 把除 `live` 之外的条目标记为长期未使用，并让节流窗口过期
    /// Age every entry except `live`, and let the prune interval lapse
    fn age_out_idle_upstreams(client: &DohClient, live: &str) {
        let now = unix_time_millis();
        let stale = now.saturating_sub(DOH_UPSTREAM_IDLE.as_millis() as u64 * 2);
        for entry in client.upstreams.iter() {
            if entry.key().as_ref() != live {
                entry
                    .value()
                    .last_used_millis
                    .store(stale, Ordering::Relaxed);
            }
        }
        client.last_prune_millis.store(
            now.saturating_sub(DOH_UPSTREAM_PRUNE_EVERY.as_millis() as u64 * 2),
            Ordering::Relaxed,
        );
    }

    #[test]
    fn doh_record_error_rebuilds_pool_at_threshold() {
        // Verify the core self-healing contract: consecutive transport errors below
        // the threshold accumulate without rebuilding; reaching it rebuilds the pool
        // (a fresh reqwest::Client is the only way to evict dead/half-open connections
        // that reqwest cannot detect on its own).
        // 验证核心自愈契约：连续传输错误在阈值前累积不重建；
        // 达阈值时重建连接池（新 reqwest::Client 是清除 reqwest 自身无法检测的
        // 死/半开连接的唯一手段）。
        let client = DohClient::new(8, 3).expect("build doh client");
        let upstream = "doh:8.8.8.8";

        let ptr_before =
            Arc::as_ptr(&client.upstream(upstream).unwrap().client.load_full()) as usize;
        // Two errors stay below the threshold (3): no rebuild.
        assert!(
            !client.record_error_of(upstream),
            "no rebuild before threshold (1/3)"
        );
        assert!(
            !client.record_error_of(upstream),
            "no rebuild before threshold (2/3)"
        );
        assert_eq!(
            Arc::as_ptr(&client.upstream(upstream).unwrap().client.load_full()) as usize,
            ptr_before,
            "client pointer must be unchanged below threshold"
        );
        // Third error reaches the threshold: pool rebuilt.
        assert!(
            client.record_error_of(upstream),
            "rebuild at threshold (3/3)"
        );
        assert_ne!(
            Arc::as_ptr(&client.upstream(upstream).unwrap().client.load_full()) as usize,
            ptr_before,
            "client pointer must change after rebuild"
        );
    }

    #[test]
    fn doh_rebuild_is_scoped_to_the_failing_upstream() {
        // A single reqwest client used to be shared by every DoH upstream, so
        // reaching the error threshold on one upstream replaced the pool of all
        // of them: the healthy upstream lost its keep-alive connections and had
        // to handshake again. Each upstream now owns its client.
        // 以前所有 DoH 上游共用一个 reqwest 客户端，一个上游达到错误阈值会把所有
        // 上游的连接池一起换掉，健康上游丢失 keep-alive 连接、被迫重新握手。
        // 现在每个上游各持一个客户端。
        let client = DohClient::new(8, 3).expect("build doh client");
        let healthy = "doh:1.1.1.1";
        let failing = "doh:bad.example";
        let healthy_before =
            Arc::as_ptr(&client.upstream(healthy).unwrap().client.load_full()) as usize;
        let failing_before =
            Arc::as_ptr(&client.upstream(failing).unwrap().client.load_full()) as usize;

        for _ in 0..2 {
            assert!(!client.record_error_of(failing));
        }
        assert!(client.record_error_of(failing), "third error rebuilds");

        assert_ne!(
            Arc::as_ptr(&client.upstream(failing).unwrap().client.load_full()) as usize,
            failing_before,
            "the failing upstream's pool is rebuilt"
        );
        assert_eq!(
            Arc::as_ptr(&client.upstream(healthy).unwrap().client.load_full()) as usize,
            healthy_before,
            "the healthy upstream keeps its pool"
        );
    }

    #[test]
    fn doh_record_success_resets_counter() {
        // record_success clears the per-upstream counter so a transient blip does
        // not accumulate toward a rebuild across an intervening healthy request.
        // record_success 清零 per-upstream 计数，避免偶发错误跨健康请求累积到重建。
        let client = DohClient::new(8, 3).expect("build doh client");
        let upstream = "doh:1.1.1.1";

        client.record_error_of(upstream);
        client.record_error_of(upstream);
        client.record_success(upstream); // reset to 0
        // Counter restarted: need 3 more to rebuild, not just 1.
        assert!(
            !client.record_error_of(upstream),
            "counter reset: 1/3 after success"
        );
        assert!(
            !client.record_error_of(upstream),
            "counter reset: 2/3 after success"
        );
        assert!(
            client.record_error_of(upstream),
            "counter reset: rebuild at 3/3"
        );
    }

    #[test]
    fn doh_error_counts_are_isolated_per_upstream() {
        // Mirrors mux clients' per-upstream consecutive_errors isolation: errors on
        // one upstream must not inflate another upstream's count.
        // 对齐 mux 的 per-upstream consecutive_errors 隔离：
        // 一个 upstream 的错误不得累加到另一个 upstream。
        let client = DohClient::new(8, 3).expect("build doh client");

        client.record_error_of("doh:8.8.8.8");
        client.record_error_of("doh:8.8.8.8");
        // A success on a *different* upstream must not touch 8.8.8.8's count.
        client.record_success("doh:1.1.1.1");
        // 8.8.8.8 still at 2 — the 3rd error rebuilds.
        assert!(
            client.record_error_of("doh:8.8.8.8"),
            "isolated counter reaches threshold independently"
        );
    }

    #[test]
    fn doh_is_transport_error_classifies_correctly() {
        // Only unusable answers are non-transport (connection is healthy, retry is
        // useless). Everything else (timeout / connect / IO) indicates a possibly
        // dead connection and is safe to retry once (DoH queries are idempotent).
        // 只有用不了的回答是非传输的（连接健康，重试无益）。
        // 其余（超时/连接/IO）都指示连接可能已死，单次重试安全（DoH 查询语义幂等）。
        let timeout_err = anyhow::anyhow!("doh request timeout");
        assert!(
            is_transport_error(&timeout_err),
            "timeout is transport-level"
        );

        // A reqwest-style error wrapped via .context() must still classify as
        // transport (downcast finds no DohAnswerError at the top of the chain).
        // 经 .context() 包装的 reqwest 风格错误仍须归类为传输错误
        // （downcast 在链顶找不到 DohAnswerError）。
        let send_err = anyhow::anyhow!("doh request send failed").context("wrapped");
        assert!(
            is_transport_error(&send_err),
            "wrapped send error is transport-level"
        );

        let status_err = doh_answer_error("doh http status 503 Server Error".to_string());
        assert!(
            !is_transport_error(&status_err),
            "HTTP status is NOT transport-level"
        );
    }

    #[tokio::test]
    async fn reqwest_client_drop_closes_pooled_connections() {
        // Empirical foundation of DohClient's pool-rebuild healing: dropping a
        // reqwest::Client closes the keep-alive connections held in its pool. If
        // this did not hold, rebuilding the client (store a fresh Arc<Client>)
        // could NOT evict dead/half-open connections and issue #41 would persist.
        // DohClient 连接池重建自愈的实证基础：drop reqwest::Client 会关闭其连接池中
        // 的 keep-alive 连接。若不成立，重建客户端（store 新 Arc<Client>）无法驱逐
        // 死/半开连接，issue #41 将无法解决。
        // Minimal HTTP/1.1 keep-alive server: serve one request, then block reading
        // until the peer closes the connection.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("read test addr");

        let server_task = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 1024];
            let _ = sock.read(&mut buf).await; // read request
            let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok";
            sock.write_all(resp).await.expect("write response");
            // Block until peer closes; Ok(0) = clean EOF (connection closed by client).
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) => return true,
                    Ok(_) => continue,
                    Err(_) => return false,
                }
            }
        });

        let url = format!("http://{addr}/");
        {
            // Long idle timeout so only an explicit Client drop can close the
            // connection within the test window (not the idle reaper).
            // 长 idle 超时，确保测试窗口内只有显式 drop Client 能关闭连接（而非 idle 回收）。
            let client = DohHttpClient::builder()
                .pool_idle_timeout(Duration::from_secs(60))
                .build()
                .expect("build client");
            let resp = client.get(&url).send().await.expect("send");
            assert!(resp.status().is_success());
            drop(resp.bytes().await.expect("read body")); // drain → connection returns to pool
            // client dropped at end of this block → pool torn down
        }

        // pool_idle_timeout is 60s; if the drop did not close the connection the
        // server would only observe EOF after ~60s. A 5s window therefore proves
        // the closure was caused by the drop.
        // pool_idle_timeout 为 60s；若 drop 未关闭连接，server 要等约 60s 才观察到 EOF。
        // 5s 窗口因此证明关闭由 drop 引起。
        let joined = tokio::time::timeout(Duration::from_secs(5), server_task)
            .await
            .expect("server did not observe close within 5s of drop; pool_idle_timeout=60s means only the drop could close it");
        let clean_eof = joined.expect("server task join");
        assert!(
            clean_eof,
            "server saw an error instead of clean EOF on Client drop"
        );
    }

    #[tokio::test]
    async fn tcp_mux_rewrite_id_no_deadlock_under_contention() {
        // Arrange: Prepare a TCP client with many pending IDs to force contention
        let client = Arc::new(TcpMuxClient::new(Arc::from("127.0.0.1:0")));
        let (write_half, _server) = connected_tcp_write_half().await;
        *client.conn.lock().await = Some(write_half);
        for id in 1u16..200u16 {
            client.pending.insert(
                id,
                Pending {
                    original_id: id,
                    frame: Bytes::new(),
                    tx: oneshot::channel().0,
                },
            );
        }

        // Act: Spawn many concurrent register_pending calls to test contention handling
        let tasks = (0..64)
            .map(|_| {
                let client = Arc::clone(&client);
                async move {
                    let dummy = vec![0u8; 4];
                    let (tx, _) = oneshot::channel();
                    client
                        .register_pending(&dummy, 0, tx)
                        .await
                        .map(|(_, id)| id)
                }
            })
            .collect::<Vec<_>>();

        let results = timeout(Duration::from_millis(500), join_all(tasks))
            .await
            .expect("register_pending stalled under contention");

        // Assert: Verify all IDs are unique (no duplicates under contention)
        let mut ids = rustc_hash::FxHashSet::default();
        for r in results {
            let id = r.expect("register_pending failed");
            assert!(ids.insert(id), "duplicate id allocated under contention");
        }
    }

    #[tokio::test]
    async fn tcp_fail_all_cannot_miss_a_concurrent_registration() {
        let client = Arc::new(TcpMuxClient::new(Arc::from("127.0.0.1:0")));
        let (write_half, _server) = connected_tcp_write_half().await;
        *client.conn.lock().await = Some(write_half);

        // Hold the connection lock so registration queues before fail_all. The old implementation
        // took its pending snapshot before this lock, then allowed the queued registration to land
        // after the snapshot. The waiter was never notified.
        let conn_guard = client.conn.lock().await;
        let register_client = Arc::clone(&client);
        let register = tokio::spawn(async move {
            let packet = [0u8; 4];
            let (tx, rx) = oneshot::channel();
            let result = register_client.register_pending(&packet, 0, tx).await;
            (result, rx)
        });
        tokio::task::yield_now().await;

        let pending = Arc::clone(&client.pending);
        let conn = Arc::clone(&client.conn);
        let fail_all = tokio::spawn(async move {
            TcpMuxClient::fail_all_async(&pending, anyhow::anyhow!("reader failed"), &conn).await;
        });
        tokio::task::yield_now().await;
        drop(conn_guard);

        let (registration, receiver) = register.await.expect("join registration task");
        registration.expect("registration should complete before teardown");
        fail_all.await.expect("join fail_all task");

        assert!(client.pending.is_empty());
        let result = timeout(Duration::from_millis(100), receiver)
            .await
            .expect("pending waiter was not notified")
            .expect("pending sender was dropped without a result");
        assert!(result.is_err(), "reader failure should reach the waiter");
    }

    /// DoT、DoQ 的上游必须有建连时用得上的主机名：空的不行，做不成 TLS 服务器名的（`%20`、`.`）
    /// 也不行，建连时都必然失败
    /// A DoT or DoQ upstream needs a host its connect can use: not an empty one, nor one that
    /// makes no TLS server name (`%20`, `.`), which would fail every connect
    #[test]
    fn a_dot_or_doq_upstream_without_a_usable_host_is_refused() {
        use crate::config::Transport;
        for address in [
            "",
            ":853",
            "?sni=dns.example",
            "%20",
            ".",
            ".:853",
            "dns.example?sni=%20",
        ] {
            assert!(
                check_upstream_address(address, Transport::Dot).is_err(),
                "dot {address:?}"
            );
        }
        for address in [
            "",
            ":853",
            "?sni=dns.example",
            "%20",
            ".",
            ".:853",
            "dns.example?sni=%20",
        ] {
            assert!(
                check_upstream_address(address, Transport::Doq).is_err(),
                "doq {address:?}"
            );
        }
        assert!(check_upstream_address("dns.example:853", Transport::Dot).is_ok());
        assert!(check_upstream_address("dns.example:853", Transport::Doq).is_ok());
    }

    /// 接收报 ConnectionReset（Windows 上 ICMP 端口不可达）时马上接着收，别的错误照旧歇 100 ms
    /// ConnectionReset from a receive (an ICMP port unreachable on Windows) reads on at once;
    /// any other error still pauses 100 ms
    #[test]
    fn a_connection_reset_on_receive_reads_on_at_once() {
        use std::io::{Error, ErrorKind};
        assert_eq!(
            recv_error_pause(&Error::from(ErrorKind::ConnectionReset)),
            None
        );
        for kind in [
            ErrorKind::Other,
            ErrorKind::ConnectionRefused,
            ErrorKind::OutOfMemory,
        ] {
            assert_eq!(
                recv_error_pause(&Error::from(kind)),
                Some(Duration::from_millis(100)),
                "{kind:?}"
            );
        }
    }

    /// 预热建的连接池和发送时现建的一样大，每个客户端各有自己的连接位
    /// A warmed-up pool is as large as one built on first send, each client with a
    /// connection slot of its own
    #[test]
    fn a_warmed_up_pool_has_every_client() {
        let mux = TcpMultiplexer::new(3, 3, 0, 0);
        mux.warm_up_pools(&["127.0.0.1:53".to_string()].into_iter().collect());
        let pool = mux
            .pools
            .get("127.0.0.1:53")
            .expect("the upstream is warmed up")
            .clone();
        assert_eq!(pool.clients.len(), 3);
        assert!(!Arc::ptr_eq(&pool.clients[0].conn, &pool.clients[1].conn));
    }

    /// 同一个池的客户端各用各的连接，不同上游各有各的池：经池里两个客户端各发一个查询，上游收到两条
    /// 连接
    /// The clients of one pool each keep a connection of their own, and each upstream has
    /// a pool of its own: a query sent through each of a pool's two clients reaches the
    /// upstream over two connections
    #[tokio::test]
    async fn the_clients_of_one_pool_each_keep_a_connection_of_their_own() {
        use std::sync::atomic::AtomicUsize;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let accepted = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&accepted);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                counted.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    loop {
                        let mut len = [0u8; 2];
                        if stream.read_exact(&mut len).await.is_err() {
                            return;
                        }
                        let mut frame = vec![0u8; u16::from_be_bytes(len) as usize];
                        if stream.read_exact(&mut frame).await.is_err() {
                            return;
                        }
                        frame[2] |= 0x80;
                        if stream.write_all(&len).await.is_err()
                            || stream.write_all(&frame).await.is_err()
                        {
                            return;
                        }
                    }
                });
            }
        });
        let mux = TcpMultiplexer::new(2, 3, 0, 0);
        let pool = mux.get_or_init_pool_for_test(&addr);
        assert_eq!(pool.clients.len(), 2);
        for client in &pool.clients {
            client
                .send(&udp_test_query("a.example"), Duration::from_secs(2))
                .await
                .expect("the upstream answers");
        }
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            2,
            "one connection per client"
        );
        let other = mux.get_or_init_pool_for_test("192.0.2.53:53");
        assert!(
            !Arc::ptr_eq(&pool, &other),
            "each upstream has its own pool"
        );
    }

    /// 查询超时以后，它在 UDP socket 的 inflight 表、TCP 连接的 pending 表里的那一条都已经删掉
    /// Once a query times out, its entry is gone from the UDP socket's inflight map and
    /// from the TCP connection's pending map
    #[tokio::test]
    async fn a_timed_out_query_leaves_no_entry_behind() {
        // 收下查询、从不回答的本机上游 / Local upstreams that take queries and never answer
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_addr = udp.local_addr().unwrap().to_string();
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = tcp.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let mut held = Vec::new();
            let mut buf = [0u8; 512];
            loop {
                tokio::select! {
                    Ok((stream, _)) = tcp.accept() => held.push(stream),
                    _ = udp.recv_from(&mut buf) => {}
                }
            }
        });

        let client = UdpClient::new(2).expect("udp client");
        let result = client
            .send(
                &udp_test_query("a.example"),
                &udp_addr,
                Duration::from_millis(100),
            )
            .await;
        assert!(result.is_err(), "the upstream never answers");
        assert!(client.pool.iter().all(|socket| socket.inflight.is_empty()));

        let tcp_client = TcpMuxClient::new(Arc::from(tcp_addr.as_str()));
        let result = tcp_client
            .send(&udp_test_query("a.example"), Duration::from_millis(100))
            .await;
        assert!(result.is_err(), "the upstream never answers");
        assert!(tcp_client.pending.is_empty());
    }

    /// 连接池大小写成 0 时按 1 算：TCP（DoT 用同一套）和 DoQ 的池里都有一个客户端
    /// A pool size of 0 counts as 1: TCP pools (DoT shares their code) and DoQ pools both
    /// get one client
    #[tokio::test]
    async fn a_pool_size_of_zero_gives_one_client() {
        let tcp = TcpMultiplexer::new(0, 3, 0, 0);
        assert_eq!(
            tcp.get_or_init_pool_for_test("192.0.2.1:53").clients.len(),
            1
        );

        let doq = DoqClient::new(0, 60, 15_000, false).expect("build DoQ client");
        // 发一个连不上的查询，只为建出这个上游的连接池
        // A query nothing answers, only to build this upstream's pool
        let upstream = "127.0.0.1:9?sni=localhost";
        let _ = doq
            .send(
                &udp_test_query("pool.example"),
                upstream,
                Duration::from_millis(50),
            )
            .await;
        let pool = doq
            .pools
            .get(upstream)
            .expect("the first query builds the pool");
        assert_eq!(pool.clients.len(), 1);
    }

    /// 上游拒绝过 0-RTT 以后，新连接不再发早期数据：同一张会话票据，没标记时恢复出的连接用 0-RTT，
    /// 标记以后就不用
    /// Once an upstream rejected 0-RTT, new connections send no early data: with the same
    /// session ticket, a resumed connection uses 0-RTT before the mark and not after it
    #[tokio::test]
    async fn doq_skips_0rtt_once_it_was_rejected() {
        let (mut server, mut client_tls) = localhost_tls(&[b"doq"]);
        server.max_early_data_size = u32::MAX;
        client_tls.enable_early_data = true;
        let addr = spawn_doq_upstream(server, Duration::ZERO, |_, _| {
            DoqReply::Answer(Duration::ZERO)
        })
        .await;
        let client = doq_test_client(format!("doq://{addr}?sni=localhost"), client_tls, true);
        let target = parse_doq_target(&client.upstream).expect("doq target");
        // 第一条连接完整握手，拿到会话票据 / The first connection shakes hands in full and gets a ticket
        client
            .send(&udp_test_query("first.example"), Duration::from_secs(2))
            .await
            .expect("the upstream answers");
        tokio::time::sleep(Duration::from_millis(100)).await;

        client.reset_connection().await;
        let resumed = client
            .get_or_connect(&target, Duration::from_secs(2))
            .await
            .expect("connect");
        assert!(resumed.used_0rtt, "a resumed connection offers early data");

        client.reset_connection().await;
        client.disable_zero_rtt();
        let after = client
            .get_or_connect(&target, Duration::from_secs(2))
            .await
            .expect("connect");
        assert!(!after.used_0rtt, "no early data once 0-RTT was rejected");
    }

    /// DoQ 连接用了超过 30 分钟，或者空闲超过 5 分钟，健康检查就把它换掉；没到时不动
    /// A DoQ connection over 30 minutes old, or idle for over 5 minutes, is replaced by the
    /// health check; short of that it stays
    #[tokio::test]
    async fn a_doq_connection_is_replaced_when_too_old_or_idle_too_long() {
        let (_, client_tls) = localhost_tls(&[b"doq"]);
        let client = doq_test_client(
            "doq://127.0.0.1:853?sni=localhost".into(),
            client_tls,
            false,
        );
        let minute = 60 * 1000;
        let check = |born: u64, last_request: u64| {
            let client = &client;
            async move {
                let now = unix_time_millis();
                client.last_health_check_time.store(0, Ordering::Release);
                client.conn_create_time.store(now - born, Ordering::Release);
                client
                    .last_request_time
                    .store(now - last_request, Ordering::Release);
                client.check_connection_health().await
            }
        };
        assert!(
            !check(29 * minute, 4 * minute).await,
            "young and busy enough"
        );
        assert!(check(31 * minute, 0).await, "too old");
        assert!(check(minute, 6 * minute).await, "idle too long");
    }

    /// DoT 和 DoQ 的上游地址：`sni`/`servername` 取最后一个非空的；出错时错误文字带着协议名
    /// DoT and DoQ upstream addresses: the last non-empty `sni`/`servername` counts, and the
    /// errors name the protocol
    #[test]
    fn dot_and_doq_addresses_take_the_last_sni_and_name_their_protocol_in_errors() {
        for (upstream, sni) in [
            ("1.1.1.1:853?sni=a.example&sni=b.example", "b.example"),
            ("1.1.1.1:853?sni=a.example&sni=", "a.example"),
            ("1.1.1.1:853?servername=c.example", "c.example"),
        ] {
            assert_eq!(parse_dot_target(upstream).expect("dot").sni.as_ref(), sni);
            assert_eq!(parse_doq_target(upstream).expect("doq").sni.as_ref(), sni);
        }
        let dot_error = |upstream: &str| format!("{:#}", parse_dot_target(upstream).err().unwrap());
        let doq_error = |upstream: &str| format!("{:#}", parse_doq_target(upstream).err().unwrap());
        assert_eq!(
            dot_error("dns.example/path"),
            "dot upstream should not contain path"
        );
        assert_eq!(
            doq_error("dns.example/path?sni=dns.example"),
            "doq upstream should not contain path"
        );
        assert!(dot_error("dot://[::1").starts_with("invalid dot upstream url"));
        assert!(doq_error("doq://[::1").starts_with("invalid doq upstream url"));
    }

    /// 上游 DoH 回 ID 0 时，DoH 客户端交回去的仍是查询自己的 ID，和其他传输一样。直接
    /// 转发、回答后跳转再转发、后台刷新都经过这里；以前这里把 0 原样交出，客户端把响应
    /// 当成别人的丢掉，等到超时重试才从缓存拿到答案。
    /// When a DoH upstream answers with ID 0 the DoH client still hands back the query's
    /// own ID, like every other transport. Direct forwards, forwards after a response jump
    /// and background refreshes all go through here; it used to pass the 0 on, and the
    /// client discarded the reply as someone else's until a retry was answered from cache.
    #[tokio::test]
    async fn doh_upstream_answering_with_id_zero_keeps_the_query_id() {
        for drop_first in [false, true] {
            // 不管收到什么 ID 都回 0 的上游（RFC 8484 允许这样做）：把查询原样回过去，ID 写成 0、
            // 标上 QR。`drop_first` 时第一个请求读完就断开、不回答，让客户端走重试那条路。
            // An upstream answering with ID 0 whatever it receives (RFC 8484 allows it): it
            // echoes the query with the ID set to 0 and QR set. With `drop_first` the first
            // request is read and its connection closed without an answer, which sends the
            // client down its retry.
            let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
            let record = Arc::clone(&seen);
            let dropped = AtomicBool::new(!drop_first);
            let (addr, _) = spawn_doh_upstream(move |_, query| {
                if !dropped.swap(true, Ordering::SeqCst) {
                    return DohReply::Close;
                }
                record
                    .lock()
                    .unwrap()
                    .push(u16::from_be_bytes([query[0], query[1]]));
                let mut answer = echo_answer(query);
                answer[..2].copy_from_slice(&[0, 0]);
                DohReply::Raw(http_ok(Some(DOH_MEDIA_TYPE), &answer))
            })
            .await;
            let upstream = format!("http://{addr}/dns-query");
            let client = DohClient::new(8, 0).expect("build doh client");
            for id in [0xBEEF_u16, 0xCAFE] {
                let mut query = vec![0u8; 12];
                query[..2].copy_from_slice(&id.to_be_bytes());
                query[2] = 0x01; // RD
                query[5] = 1; // QDCOUNT
                query.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
                let response = timeout(
                    Duration::from_secs(10),
                    client.send(&query, &upstream, Duration::from_secs(5)),
                )
                .await
                .expect("no hang")
                .expect("doh answer");

                assert_eq!(
                    &response[..2],
                    &id.to_be_bytes(),
                    "the query's own ID comes back"
                );
                assert_eq!(response[2] & 0x80, 0x80, "the rest is the server's reply");
                assert_eq!(&response[12..], &query[12..], "the question is untouched");
            }
            // 第一个请求被断开时，重试那一次也是带着自己的 ID 出去、换回来的
            // When the first request was cut off, the retry also left with its own ID and got it back
            assert_eq!(
                *seen.lock().unwrap(),
                vec![0xBEEF, 0xCAFE],
                "queries leave with their own IDs (drop_first = {drop_first})"
            );
        }
    }

    /// 问 `label.test` 的 A 记录 / An A query for `label.test`
    fn doh_test_query(label: &str) -> Vec<u8> {
        let mut query = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
        query.extend_from_slice(b"\x04test\x00\x00\x01\x00\x01");
        query
    }

    /// 一个回答最多一条 DNS 消息那么长。此前正文有多长就收多长：服务器不停往回发时，一个查询几秒内
    /// 就能占掉几个 GB，一直到超时。
    /// An answer is at most one DNS message long. The body used to be taken whole:
    /// with a server sending without end, one query took gigabytes within seconds,
    /// until it timed out.
    #[tokio::test]
    async fn doh_refuses_an_answer_longer_than_a_dns_message() {
        let (addr, _) = spawn_doh_upstream(|_, query| {
            let mut answer = echo_answer(query);
            match &query[13..17] {
                b"full" => answer.resize(MAX_DNS_MESSAGE_SIZE, 0),
                b"over" => answer.resize(MAX_DNS_MESSAGE_SIZE + 1, 0),
                _ => return DohReply::Endless,
            }
            DohReply::Raw(http_ok(Some(DOH_MEDIA_TYPE), &answer))
        })
        .await;
        let upstream = format!("http://{addr}/dns-query");
        let client = DohClient::new(8, 0).expect("build doh client");

        // 正好一条最长的 DNS 消息：照收，分几块到也拼得回来
        // Exactly one longest DNS message: taken, put back together from its pieces
        let query = doh_test_query("full");
        let answer = client
            .send(&query, &upstream, Duration::from_secs(5))
            .await
            .expect("a 65535-byte answer is an answer");
        assert_eq!(answer.len(), MAX_DNS_MESSAGE_SIZE);
        assert_eq!(&answer[..query.len()], &echo_answer(&query)[..]);

        for label in ["over", "more"] {
            let start = tokio::time::Instant::now();
            let err = client
                .send(&doh_test_query(label), &upstream, Duration::from_secs(5))
                .await
                .expect_err("longer than a DNS message");
            assert!(
                start.elapsed() < Duration::from_secs(1),
                "{label}: refused as soon as it is too long, not at the timeout"
            );
            assert!(
                !is_transport_error(&err),
                "{label}: the server answered, a retry would get the same: {err:#}"
            );
        }
    }

    /// 回答必须是 DNS 消息的媒体类型。此前强制门户或出错的代理回的网页也被当成回答交出去。
    /// An answer has to carry the DNS message media type. A web page from a captive
    /// portal or a broken proxy used to be handed on as an answer.
    #[tokio::test]
    async fn doh_refuses_an_answer_of_another_media_type() {
        let (addr, _) = spawn_doh_upstream(|_, query| {
            let media_type = match &query[13..17] {
                b"html" => Some("text/html"),
                b"none" => None,
                b"case" => Some("Application/DNS-Message"),
                _ => Some("application/dns-message; charset=binary"),
            };
            DohReply::Raw(http_ok(media_type, &echo_answer(query)))
        })
        .await;
        let upstream = format!("http://{addr}/dns-query");
        let client = DohClient::new(8, 0).expect("build doh client");
        for label in ["html", "none"] {
            let err = client
                .send(&doh_test_query(label), &upstream, Duration::from_secs(5))
                .await
                .expect_err("not a DNS message");
            assert!(!is_transport_error(&err), "{label}: no retry: {err:#}");
        }
        // 媒体类型不分大小写，参数不管 / Media types ignore case, and parameters do not matter
        for label in ["case", "parm"] {
            client
                .send(&doh_test_query(label), &upstream, Duration::from_secs(5))
                .await
                .unwrap_or_else(|err| panic!("{label}: a DNS message: {err:#}"));
        }
    }

    /// DoH 客户端不跟随跳转：服务器没有理由跳转，跟着跳可能把查询发到别处，包括明文 HTTP。
    /// The DoH client follows no redirect: a server has no reason to send one, and
    /// following it could take the query elsewhere, plain HTTP included.
    #[tokio::test]
    async fn doh_does_not_follow_redirects() {
        let (addr, paths) = spawn_doh_upstream(|path, query| {
            if path == "/dns-query" {
                DohReply::Raw(
                    b"HTTP/1.1 307 Temporary Redirect\r\nlocation: /elsewhere\r\ncontent-length: 0\r\n\r\n"
                        .to_vec(),
                )
            } else {
                DohReply::Raw(http_ok(Some(DOH_MEDIA_TYPE), &echo_answer(query)))
            }
        })
        .await;
        let client = DohClient::new(8, 0).expect("build doh client");
        let err = client
            .send(
                &doh_test_query("move"),
                &format!("http://{addr}/dns-query"),
                Duration::from_secs(5),
            )
            .await
            .expect_err("a redirect is not an answer");
        assert!(!is_transport_error(&err), "no retry: {err:#}");
        assert_eq!(*paths.lock().unwrap(), vec!["/dns-query".to_string()]);
    }

    /// DoH 上一个查询只有一个回答：答的是别的问题就算失败，不交出去，也不重试。
    /// Over DoH a query gets a single answer: one to another question fails the
    /// query instead of being handed on, with no retry.
    #[tokio::test]
    async fn a_doh_answer_to_another_question_fails_the_query() {
        let (addr, paths) = spawn_doh_upstream(|_, query| {
            DohReply::Raw(http_ok(
                Some(DOH_MEDIA_TYPE),
                &udp_response_with_question(query, "other.example"),
            ))
        })
        .await;
        let client = DohClient::new(8, 0).expect("build doh client");
        let err = client
            .send(
                &udp_test_query("swap.example"),
                &format!("http://{addr}/dns-query"),
                Duration::from_secs(2),
            )
            .await
            .expect_err("an answer to another question");
        assert!(!is_transport_error(&err), "no retry: {err:#}");
        assert_eq!(paths.lock().unwrap().len(), 1);
    }

    /// Retry-After 按秒数读，收进 1 到 60 秒：0 算 1 秒，超过 60 的、大得装不下的都算 60 秒；没写、
    /// 写的是 HTTP 日期或读不懂时 1 秒，也不算照 Retry-After 定的
    /// Retry-After is read as seconds and brought into 1 to 60: 0 counts as 1, anything
    /// above 60 or too large to hold as 60; without one, or with an HTTP date or anything
    /// unreadable, 1 second, not counted as set by Retry-After
    #[test]
    fn a_429_pauses_for_retry_after_seconds_within_one_to_sixty() {
        let pause = |value: Option<&'static str>| {
            let throttle = throttle_after(value.map(HeaderValue::from_static).as_ref());
            (throttle.pause, throttle.from_retry_after)
        };
        let seconds = Duration::from_secs;
        assert_eq!(pause(None), (seconds(1), false));
        assert_eq!(pause(Some("30")), (seconds(30), true));
        assert_eq!(pause(Some("1")), (seconds(1), true));
        assert_eq!(pause(Some("60")), (seconds(60), true));
        assert_eq!(pause(Some("0")), (seconds(1), true));
        assert_eq!(pause(Some("61")), (seconds(60), true));
        assert_eq!(pause(Some("120")), (seconds(60), true));
        assert_eq!(pause(Some("99999999999999999999999")), (seconds(60), true));
        for unreadable in [
            "Wed, 21 Oct 2026 07:28:00 GMT",
            "soon",
            "-5",
            "2.5",
            "1e3",
            "",
        ] {
            assert_eq!(
                pause(Some(unreadable)),
                (seconds(1), false),
                "{unreadable:?}"
            );
        }
    }

    /// 429 不重试，也不算一次传输错误，连接池不重建；这个上游从现在起照 Retry-After 暂停。错误原文和
    /// 别的错误状态一样
    /// A 429 is not retried and is no transport error, so the pool is not rebuilt; the
    /// upstream pauses from now for what Retry-After says. The error text is as for any
    /// other error status
    #[tokio::test]
    async fn a_429_is_not_retried_and_pauses_its_upstream() {
        let (addr, paths) = spawn_doh_upstream(|_, _| {
            DohReply::Raw(
                b"HTTP/1.1 429 Too Many Requests\r\ncontent-type: text/html\r\nretry-after: 120\r\ncontent-length: 0\r\n\r\n"
                    .to_vec(),
            )
        })
        .await;
        let upstream = format!("http://{addr}/dns-query");
        // 阈值 1：记一次传输错误就会重建 / Threshold 1: a single transport error would rebuild
        let client = DohClient::new(8, 1).expect("build doh client");
        assert!(!client.any_paused());
        let state = client.upstream(&upstream).expect("doh upstream state");
        let pool = Arc::as_ptr(&state.client.load_full());

        let err = client
            .send(&doh_test_query("slow"), &upstream, Duration::from_secs(5))
            .await
            .expect_err("a 429 is no answer");
        assert_eq!(format!("{err:#}"), "doh http status 429 Too Many Requests");
        assert!(!is_transport_error(&err), "no retry: {err:#}");
        assert_eq!(paths.lock().unwrap().len(), 1, "sent once");
        assert_eq!(state.consecutive_errors.load(Ordering::Acquire), 0);
        assert_eq!(
            Arc::as_ptr(&state.client.load_full()),
            pool,
            "the pool is kept"
        );

        assert_eq!(
            throttle_of(&err).map(|throttle| throttle.pause),
            Some(Duration::from_secs(60)),
            "Retry-After 120 brought down to 60"
        );
        assert!(client.any_paused());
        assert!(client.is_paused(&upstream));
        assert!(!client.is_paused("other.example/dns-query"));
        let left = state
            .paused_until
            .load(Ordering::Relaxed)
            .saturating_sub(client.millis_since_epoch());
        assert!((59_000..=60_000).contains(&left), "{left} ms left");
    }

    /// 几个 429 同时回来：暂停只往后推，不往前拉；只有暂停开始那一次记 warn，带上游、秒数和是不是照
    /// Retry-After
    /// Several 429s at once: a pause only moves later, never earlier; only its start logs a
    /// warn, with the upstream, the seconds and whether Retry-After set them
    #[test]
    fn concurrent_429s_only_move_a_pause_later_and_warn_once() {
        let client = DohClient::new(8, 0).expect("build doh client");
        let upstream = "doh.example/dns-query";
        let state = client.upstream(upstream).expect("doh upstream state");
        let throttle = |seconds, from_retry_after| Throttle {
            pause: Duration::from_secs(seconds),
            from_retry_after,
        };
        let (warnings, guard) = crate::engine::test_support::Warnings::capture();
        client.pause(upstream, &state, throttle(5, true));
        let until = state.paused_until.load(Ordering::Relaxed);
        client.pause(upstream, &state, throttle(1, false));
        assert_eq!(
            state.paused_until.load(Ordering::Relaxed),
            until,
            "a shorter pause does not cut it short"
        );
        client.pause(upstream, &state, throttle(10, true));
        assert!(state.paused_until.load(Ordering::Relaxed) > until);
        drop(guard);

        let lines = warnings.lines();
        assert_eq!(lines.len(), 1, "{lines:#?}");
        for field in [
            "upstream=\"doh.example/dns-query\"",
            "pause_secs=5",
            "retry_after=true",
        ] {
            assert!(lines[0].contains(field), "{field} in {}", lines[0]);
        }
    }

    /// 暂停到期以后上游又能问了，`any_paused` 也清回 0，之后的检查连时钟都不读
    /// Once a pause ends the upstream can be asked again, and `any_paused` clears back to 0,
    /// so later checks read no clock
    #[test]
    fn a_pause_ends_on_time_and_the_shared_gate_clears() {
        let client = DohClient::new(8, 0).expect("build doh client");
        let upstream = "doh.example/dns-query";
        let state = client.upstream(upstream).expect("doh upstream state");
        client.pause(
            upstream,
            &state,
            Throttle {
                pause: Duration::from_secs(1),
                from_retry_after: false,
            },
        );
        assert!(client.any_paused());
        assert!(client.is_paused(upstream));
        std::thread::sleep(Duration::from_millis(1_100));
        assert!(!client.is_paused(upstream));
        assert!(!client.any_paused());
        assert_eq!(client.latest_pause_end.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn doh_response_gets_the_query_id_back() {
        let query = [0x12, 0x34, 0x01, 0x00];
        // 服务端回 0：换回查询的 ID，其余字节不动 / The server answered 0: the query's ID goes back, the rest is untouched
        let restored =
            restore_query_id(&query, Bytes::from_static(&[0x00, 0x00, 0x81, 0x80, 0x00]));
        assert_eq!(restored.as_ref(), &[0x12, 0x34, 0x81, 0x80, 0x00]);
        // 已经一致：原样返回，不复制 / Already matching: returned as is, not copied
        let echoed = Bytes::from_static(&[0x12, 0x34, 0x81, 0x80]);
        let pointer = echoed.as_ptr();
        assert_eq!(restore_query_id(&query, echoed).as_ptr(), pointer);
        // 太短的包没有 ID 可换 / A packet too short to carry an ID is left alone
        assert_eq!(
            restore_query_id(&query, Bytes::from_static(&[0x00])).as_ref(),
            &[0x00]
        );
        assert_eq!(
            restore_query_id(&[0x12], Bytes::from_static(&[0x00, 0x00])).as_ref(),
            &[0x00, 0x00]
        );
    }

    /// `localhost` 的自签证书，以及只信任它的客户端配置；`alpn` 两边都用
    /// A self-signed certificate for `localhost` and a client config trusting
    /// only it, both sides offering `alpn`
    fn localhost_tls(alpn: &[&[u8]]) -> (rustls::ServerConfig, ClientConfig) {
        self_signed_tls(&["localhost"], alpn)
    }

    /// 给 `names` 签的自签证书（IP 地址成为 IP 类型的名字）和只信任它的客户端配置
    /// A self-signed certificate for `names` (an IP address becomes an IP name)
    /// and a client config trusting only it
    fn self_signed_tls(names: &[&str], alpn: &[&[u8]]) -> (rustls::ServerConfig, ClientConfig) {
        use rcgen::{CertificateParams, KeyPair};
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

        let key_pair = KeyPair::generate().expect("generate key pair");
        let names: Vec<String> = names.iter().map(|name| name.to_string()).collect();
        let cert = CertificateParams::new(names)
            .expect("certificate params")
            .self_signed(&key_pair)
            .expect("self-signed certificate");
        let cert_der: CertificateDer<'static> = cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
        let mut server = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .expect("server config");
        server.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();

        let mut roots = RootCertStore::empty();
        roots.add(cert_der).expect("trust the test certificate");
        let mut client = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        (server, client)
    }

    /// DNS 消息里问题名的第一个标签 / First label of the question name in a DNS message
    fn first_label(message: &[u8]) -> String {
        let len = message[12] as usize;
        String::from_utf8_lossy(&message[13..13 + len]).into_owned()
    }

    /// 本机 DoQ 测试上游怎么对待一个查询 / How the local DoQ test upstream treats one query
    #[derive(Clone, Copy)]
    enum DoqReply {
        /// 隔这么久照常回答 / Answer after this long
        Answer(Duration),
        /// 回答，100 ms 后关掉整条连接 / Answer, then close the whole connection 100 ms later
        AnswerThenClose,
        /// 读完查询就关掉整条连接，不回答 / Read the query and close the connection unanswered
        Close,
        /// 一直不回答 / Never answer
        Silence,
        /// 回答别的问题 / Answer another question
        AnotherQuestion,
    }

    /// 本机 DoQ 上游：握手先压住 `accept_delay`；每条连接上第 n 个查询（从 0 数）按
    /// `reply(n, 问题名第一个标签)` 处理，应答是置了 QR 位的原查询。
    /// Local DoQ upstream: the handshake is held back for `accept_delay`; the
    /// n-th query on each connection (counting from 0) is treated as
    /// `reply(n, first label of the question)`, the answer being the query
    /// with QR set.
    async fn spawn_doq_upstream(
        server: rustls::ServerConfig,
        accept_delay: Duration,
        reply: fn(usize, &str) -> DoqReply,
    ) -> SocketAddr {
        spawn_doq_upstream_on(
            "127.0.0.1:0".parse().unwrap(),
            server,
            accept_delay,
            reply,
            None,
        )
        .expect("bind the DoQ test upstream")
    }

    /// 同 [`spawn_doq_upstream`]，绑在 `bind` 上；该地址族不可用时为 None。给了 `closed`，每条连接
    /// 结束时往里发一个信号
    /// As [`spawn_doq_upstream`], bound to `bind`; `None` when that address
    /// family is unavailable on this host. With `closed`, a signal goes there
    /// whenever a connection ends
    fn spawn_doq_upstream_on(
        bind: SocketAddr,
        server: rustls::ServerConfig,
        accept_delay: Duration,
        reply: fn(usize, &str) -> DoqReply,
        closed: Option<tokio::sync::mpsc::UnboundedSender<()>>,
    ) -> Option<SocketAddr> {
        let crypto =
            quinn::crypto::rustls::QuicServerConfig::try_from(server).expect("quic server crypto");
        let endpoint =
            QuicEndpoint::server(quinn::ServerConfig::with_crypto(Arc::new(crypto)), bind).ok()?;
        let addr = endpoint.local_addr().expect("read the DoQ test address");
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let closed = closed.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(accept_delay).await;
                    let Ok(conn) = incoming.await else { return };
                    let mut index = 0;
                    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                        let n = index;
                        index += 1;
                        let conn = conn.clone();
                        tokio::spawn(async move {
                            let Ok(mut frame) = recv.read_to_end(MAX_DNS_MESSAGE_SIZE + 2).await
                            else {
                                return;
                            };
                            let close = || conn.close(quinn::VarInt::from_u32(0), b"closing");
                            let action = reply(n, &first_label(&frame[2..]));
                            let delay = match action {
                                DoqReply::Silence => {
                                    // 拿着发送端不放：一放手流就结束了，客户端会读到空应答
                                    // Hold on to the send side: dropping it ends
                                    // the stream and the client reads an empty answer
                                    tokio::time::sleep(Duration::from_secs(30)).await;
                                    drop(send);
                                    return;
                                }
                                DoqReply::Close => {
                                    close();
                                    return;
                                }
                                DoqReply::AnotherQuestion => {
                                    let other =
                                        udp_response_with_question(&frame[2..], "other.example");
                                    let _ =
                                        send.write_all(&(other.len() as u16).to_be_bytes()).await;
                                    let _ = send.write_all(&other).await;
                                    let _ = send.finish();
                                    let _ = send.stopped().await;
                                    return;
                                }
                                DoqReply::Answer(delay) => delay,
                                DoqReply::AnswerThenClose => Duration::ZERO,
                            };
                            tokio::time::sleep(delay).await;
                            // 长度前缀之后第 3 个字节是 QR 所在的标志位
                            // The flags byte carrying QR sits third after the length prefix
                            frame[4] |= 0x80;
                            let _ = send.write_all(&frame).await;
                            let _ = send.finish();
                            if matches!(action, DoqReply::AnswerThenClose) {
                                tokio::time::sleep(Duration::from_millis(100)).await;
                                close();
                            }
                        });
                    }
                    if let Some(closed) = closed {
                        let _ = closed.send(());
                    }
                });
            }
        });
        Some(addr)
    }

    /// 只信任 `client_tls` 里那张证书的 DoQ 客户端 / A DoQ client trusting only the certificate in `client_tls`
    fn doq_test_client(
        upstream: String,
        client_tls: ClientConfig,
        enable_0rtt: bool,
    ) -> DoqMuxClient {
        DoqMuxClient::new(
            Arc::from(upstream),
            doq_test_runtime(client_tls, enable_0rtt),
            Arc::new(AtomicBool::new(false)),
        )
    }

    /// 只信任 `client_tls` 里那张证书的 DoQ 端点 / DoQ endpoints trusting only the certificate in `client_tls`
    fn doq_test_runtime(client_tls: ClientConfig, enable_0rtt: bool) -> Arc<DoqRuntime> {
        let crypto = QuicClientConfig::try_from(client_tls).expect("quic client crypto");
        let config = quinn::ClientConfig::new(Arc::new(crypto));
        let mut endpoint_v4 =
            QuicEndpoint::client("127.0.0.1:0".parse().unwrap()).expect("bind the DoQ client");
        endpoint_v4.set_default_client_config(config.clone());
        let endpoint_v6 = match QuicEndpoint::client("[::1]:0".parse().unwrap()) {
            Ok(mut endpoint) => {
                endpoint.set_default_client_config(config);
                endpoint
            }
            Err(_) => endpoint_v4.clone(),
        };
        Arc::new(DoqRuntime {
            endpoint_v4,
            endpoint_v6,
            enable_0rtt,
            zero_rtt_notice: std::sync::Once::new(),
        })
    }

    /// DoQ 上一个查询只有一个回答：答的是别的问题就算失败，不交出去。
    /// Over DoQ a query gets a single answer: one to another question fails the
    /// query instead of being handed on.
    #[tokio::test]
    async fn a_doq_answer_to_another_question_fails_the_query() {
        let (server, client_tls) = localhost_tls(&[b"doq"]);
        let addr =
            spawn_doq_upstream(server, Duration::ZERO, |_, _| DoqReply::AnotherQuestion).await;
        let client = doq_test_client(format!("doq://{addr}?sni=localhost"), client_tls, false);
        let err = client
            .send(&udp_test_query("swap.example"), Duration::from_secs(2))
            .await
            .expect_err("an answer to another question");
        assert!(
            format!("{err:#}").contains("does not answer the query"),
            "{err:#}"
        );
    }

    /// 阿里的 DoQ 服务器大约 10 秒就关掉空闲连接，比 15 秒一次的保活还短。池里那条已经
    /// 关掉的连接曾被原样拿去用，这次查询直接失败；每个上游有 16 条连接轮流用，空闲之后
    /// 头 16 个查询就一个接一个失败。
    /// Alibaba's DoQ servers drop an idle connection after about 10 s, sooner
    /// than the 15 s keep-alive. The closed connection used to be handed out as
    /// it was and the query failed outright; with 16 pooled connections per
    /// upstream used in turn, the first 16 queries after a quiet spell failed
    /// one after another.
    #[tokio::test]
    async fn doq_replaces_a_pooled_connection_the_server_already_closed() {
        let (server, client_tls) = localhost_tls(&[b"doq"]);
        let addr =
            spawn_doq_upstream(server, Duration::ZERO, |_, _| DoqReply::AnswerThenClose).await;
        let client = doq_test_client(format!("doq://{addr}?sni=localhost"), client_tls, false);
        client
            .send(&udp_test_query("first.example"), Duration::from_secs(2))
            .await
            .expect("a fresh connection answers");

        // 服务器在应答 100 ms 后关掉连接 / The server closes the connection 100 ms after answering
        tokio::time::sleep(Duration::from_millis(400)).await;
        let second = client
            .send(&udp_test_query("second.example"), Duration::from_secs(2))
            .await;
        assert!(
            second.is_ok(),
            "a connection the server already closed must be replaced, not used: {:?}",
            second.err()
        );
    }

    /// 连接在检查之后、查询途中才断时，靠的是换一条新连接再发一次
    /// When the connection only dies after the check, during the query, the one
    /// retry on a fresh connection is what saves the query
    #[tokio::test]
    async fn doq_retries_once_when_the_pooled_connection_dies_under_the_query() {
        let (server, client_tls) = localhost_tls(&[b"doq"]);
        let addr = spawn_doq_upstream(server, Duration::ZERO, |n, _| {
            if n == 0 {
                DoqReply::Answer(Duration::ZERO)
            } else {
                DoqReply::Close
            }
        })
        .await;
        let client = doq_test_client(format!("doq://{addr}?sni=localhost"), client_tls, false);
        client
            .send(&udp_test_query("first.example"), Duration::from_secs(2))
            .await
            .expect("a fresh connection answers");

        let second = client
            .send(&udp_test_query("second.example"), Duration::from_secs(2))
            .await;
        assert!(
            second.is_ok(),
            "a pooled connection closed under the query must be retried on a fresh one: {:?}",
            second.err()
        );
    }

    /// 没用 0-RTT 的连接上一次回答慢，曾被当成 0-RTT 被拒，把这个上游的 0-RTT 关到
    /// 重启为止；而断连之后要重连，0-RTT 正好省下一个往返。
    /// One slow answer on a connection that did not use 0-RTT used to count as
    /// 0-RTT being rejected and switched it off for the upstream until a
    /// restart, while 0-RTT is exactly what saves a round trip on every
    /// reconnect after a dropped connection.
    #[tokio::test]
    async fn a_doq_timeout_without_0rtt_leaves_0rtt_on() {
        let (server, client_tls) = localhost_tls(&[b"doq"]);
        let addr = spawn_doq_upstream(server, Duration::ZERO, |_, label| {
            if label == "slow" {
                DoqReply::Silence
            } else {
                DoqReply::Answer(Duration::ZERO)
            }
        })
        .await;
        let client = doq_test_client(format!("doq://{addr}?sni=localhost"), client_tls, true);
        let result = client
            .send(&udp_test_query("slow.example"), Duration::from_millis(300))
            .await;
        assert!(result.is_err(), "the upstream never answers `slow`");
        assert!(
            !client.zero_rtt_rejected.load(Ordering::Relaxed),
            "a timeout on a connection that did not use 0-RTT says nothing about 0-RTT"
        );
    }

    /// 一次查询失败（回答的不是这个问题，或者超时）以后连接被复位，下一个查询走新连接
    /// After a failed query (an answer to another question, or a timeout) the
    /// connection is reset and the next query goes over a fresh one
    #[tokio::test]
    async fn a_failed_doq_query_resets_the_connection() {
        for (failing, budget) in [
            ("wrong", Duration::from_secs(2)),
            ("slow", Duration::from_millis(300)),
        ] {
            let (server, client_tls) = localhost_tls(&[b"doq"]);
            // 只有一条连接上的第一个查询照常回答：还在旧连接上问，就等不到回答
            // Only the first query on a connection is answered as asked: asking again
            // on the old connection gets no answer
            let addr = spawn_doq_upstream(server, Duration::ZERO, |n, label| match label {
                "wrong" => DoqReply::AnotherQuestion,
                "slow" => DoqReply::Silence,
                _ if n == 0 => DoqReply::Answer(Duration::ZERO),
                _ => DoqReply::Silence,
            })
            .await;
            let client = doq_test_client(format!("doq://{addr}?sni=localhost"), client_tls, false);
            let result = client
                .send(&udp_test_query(&format!("{failing}.example")), budget)
                .await;
            assert!(result.is_err(), "`{failing}` gets no usable answer");
            client
                .send(&udp_test_query("after.example"), Duration::from_secs(2))
                .await
                .unwrap_or_else(|err| panic!("after `{failing}`, the next query got {err:#}"));
        }
    }

    /// 本机 TCP 测试上游；`tls` 给了就是 DoT。问题名第一个标签是 `slow` 的永不回答，
    /// `late` 的 400 ms 后回答，`mid` 的 100 ms 后回答，其余立刻回答；同一条连接上的
    /// 查询各自独立回答，先到先回。
    /// Local TCP test upstream, DoT when `tls` is given. A question whose first
    /// label is `slow` is never answered, `late` after 400 ms, `mid` after
    /// 100 ms, anything else at once; queries on one connection are answered
    /// independently, whichever is ready first.
    async fn spawn_stream_upstream(tls: Option<rustls::ServerConfig>) -> SocketAddr {
        spawn_stream_upstream_on("127.0.0.1:0", tls, None)
            .await
            .expect("bind the stream test upstream")
    }

    /// 同 [`spawn_stream_upstream`]，绑在 `bind` 上；该地址族不可用时为 None。给了 `closed`，每条
    /// 连接结束时往里发一个信号
    /// As [`spawn_stream_upstream`], bound to `bind`; `None` when that address
    /// family is unavailable on this host. With `closed`, a signal goes there
    /// whenever a connection ends
    async fn spawn_stream_upstream_on(
        bind: &str,
        tls: Option<rustls::ServerConfig>,
        closed: Option<tokio::sync::mpsc::UnboundedSender<()>>,
    ) -> Option<SocketAddr> {
        async fn serve<S>(stream: S)
        where
            S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + 'static,
        {
            let (mut reader, writer) = tokio::io::split(stream);
            let writer = Arc::new(Mutex::new(writer));
            loop {
                let mut len = [0u8; 2];
                if reader.read_exact(&mut len).await.is_err() {
                    return;
                }
                let mut frame = vec![0u8; u16::from_be_bytes(len) as usize];
                if reader.read_exact(&mut frame).await.is_err() {
                    return;
                }
                let writer = Arc::clone(&writer);
                tokio::spawn(async move {
                    let label = first_label(&frame);
                    let delay = match label.as_str() {
                        "slow" => return,
                        "late" => Duration::from_millis(400),
                        "mid" => Duration::from_millis(100),
                        _ => Duration::ZERO,
                    };
                    if label == "swap" {
                        // 先在同一个 ID 下回一个别的问题的回答，过一会儿再回真正的
                        // First an answer to another question under the same ID, the real one a moment later
                        let other = udp_response_with_question(&frame, "other.example");
                        let mut writer = writer.lock().await;
                        let _ = writer.write_all(&(other.len() as u16).to_be_bytes()).await;
                        let _ = writer.write_all(&other).await;
                        let _ = writer.flush().await;
                        drop(writer);
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                    tokio::time::sleep(delay).await;
                    frame[2] |= 0x80;
                    let mut writer = writer.lock().await;
                    let _ = writer.write_all(&len).await;
                    let _ = writer.write_all(&frame).await;
                });
            }
        }

        let listener = tokio::net::TcpListener::bind(bind).await.ok()?;
        let addr = listener.local_addr().expect("read the stream test address");
        let acceptor = tls.map(|config| tokio_rustls::TlsAcceptor::from(Arc::new(config)));
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (acceptor, closed) = (acceptor.clone(), closed.clone());
                tokio::spawn(async move {
                    match acceptor {
                        Some(acceptor) => {
                            if let Ok(tls) = acceptor.accept(stream).await {
                                serve(tls).await;
                            }
                        }
                        None => serve(stream).await,
                    }
                    if let Some(closed) = closed {
                        let _ = closed.send(());
                    }
                });
            }
        });
        Some(addr)
    }

    /// TCP 和 DoT 的多路复用客户端是同一套写法，下面几条测试对两者一视同仁
    /// The TCP and DoT multiplexing clients share one design, so the tests
    /// below hold both to the same behaviour
    trait StreamMux {
        async fn query(&self, packet: &[u8], timeout_dur: Duration) -> anyhow::Result<Bytes>;
        fn connection_generation(&self) -> u64;
        async fn drop_connection(&self);
        fn pending(&self) -> &DashMap<u16, Pending, FxBuildHasher>;
        /// 拿着连接锁 `hold` 这么久 / Hold the connection lock for `hold`
        async fn hold_connection(&self, hold: Duration);
    }

    impl<T: StreamTransport> StreamMux for StreamMuxClient<T> {
        async fn query(&self, packet: &[u8], timeout_dur: Duration) -> anyhow::Result<Bytes> {
            self.send(packet, timeout_dur).await
        }
        fn connection_generation(&self) -> u64 {
            self.generation.load(Ordering::Acquire)
        }
        async fn drop_connection(&self) {
            self.reset().await;
        }
        fn pending(&self) -> &DashMap<u16, Pending, FxBuildHasher> {
            &self.pending
        }
        async fn hold_connection(&self, hold: Duration) {
            let _held = self.conn.lock().await;
            tokio::time::sleep(hold).await;
        }
    }

    async fn tcp_test_client() -> TcpMuxClient {
        let addr = spawn_stream_upstream(None).await;
        TcpMuxClient::new(Arc::from(addr.to_string()))
    }

    async fn dot_test_client() -> DotMuxClient {
        let (server, client_tls) = localhost_tls(&[]);
        let addr = spawn_stream_upstream(Some(server)).await;
        DotMuxClient::new(
            Arc::from(format!("dot://{addr}?sni=localhost")),
            Arc::new(client_tls),
        )
    }

    /// 一条连接上 65536 个 ID 全被等着的查询占着时，新查询立刻失败，连接照常用。此前每个新查询
    /// 都要在连接锁下把 65536 个 ID 挨个试一遍，一大批这样的查询排着队，后面的远远超出时限。
    /// With all 65536 IDs on a connection held by waiting queries, a new query fails
    /// at once and the connection stays in use. Each new query used to try all 65536
    /// IDs one by one under the connection lock, and a crowd of them queued up, the
    /// later ones running far past their deadlines.
    async fn a_full_id_space_fails_queries_at_once(client: &impl StreamMux) {
        client
            .query(&udp_test_query("warm.example"), Duration::from_secs(2))
            .await
            .expect("a fresh connection answers");
        let generation = client.connection_generation();
        for id in 0..=u16::MAX {
            client.pending().insert(
                id,
                Pending {
                    original_id: id,
                    frame: Bytes::new(),
                    tx: oneshot::channel().0,
                },
            );
        }

        let started = tokio::time::Instant::now();
        let query = udp_test_query("full.example");
        let results = futures::future::join_all(
            (0..2000).map(|_| client.query(&query, Duration::from_secs(1))),
        )
        .await;
        assert!(results.iter().all(Result::is_err), "no ID is free");
        assert!(
            started.elapsed() < Duration::from_millis(900),
            "2000 queries took {:?} to fail",
            started.elapsed()
        );
        assert_eq!(client.connection_generation(), generation);

        client.pending().clear();
        client
            .query(&udp_test_query("again.example"), Duration::from_secs(2))
            .await
            .expect("the same connection answers once IDs are free");
        assert_eq!(client.connection_generation(), generation);
    }

    #[tokio::test]
    async fn a_full_tcp_id_space_fails_queries_at_once() {
        a_full_id_space_fails_queries_at_once(&tcp_test_client().await).await;
    }

    #[tokio::test]
    async fn a_full_dot_id_space_fails_queries_at_once() {
        a_full_id_space_fails_queries_at_once(&dot_test_client().await).await;
    }

    /// 连接锁被别人拿着时，查询等锁也守自己的时限，时限到了只有它失败，连接照常用。此前看连接
    /// 是不是复用的、建连、登记都要等这把锁，要等多久就等多久：排在长队后面的查询远远超出时限，
    /// 最后还把连接重建了。
    /// With the connection lock held by someone else, a query waiting for it keeps to
    /// its own deadline, and when that passes only the query fails while the
    /// connection stays in use. Checking for a reused connection, connecting and
    /// registering all waited for this lock as long as it took: a query at the back
    /// of a long queue ran far past its deadline and then rebuilt the connection.
    async fn waiting_for_the_connection_keeps_to_the_deadline(client: &impl StreamMux) {
        client
            .query(&udp_test_query("warm.example"), Duration::from_secs(2))
            .await
            .expect("a fresh connection answers");
        let generation = client.connection_generation();

        let query = udp_test_query("queued.example");
        let (_, (result, took)) =
            tokio::join!(client.hold_connection(Duration::from_millis(800)), async {
                // 等锁先被拿住 / Let the lock be taken first
                tokio::time::sleep(Duration::from_millis(50)).await;
                let started = tokio::time::Instant::now();
                let result = client.query(&query, Duration::from_millis(200)).await;
                (result, started.elapsed())
            });
        assert!(result.is_err(), "the lock is held past the deadline");
        assert!(
            took < Duration::from_millis(450),
            "the query failed after {took:?}"
        );
        assert_eq!(
            client.connection_generation(),
            generation,
            "nothing was wrong with the connection"
        );
        client
            .query(&udp_test_query("after.example"), Duration::from_secs(2))
            .await
            .expect("the same connection answers");
        assert_eq!(client.connection_generation(), generation);
    }

    #[tokio::test]
    async fn waiting_for_a_tcp_connection_keeps_to_the_deadline() {
        waiting_for_the_connection_keeps_to_the_deadline(&tcp_test_client().await).await;
    }

    #[tokio::test]
    async fn waiting_for_a_dot_connection_keeps_to_the_deadline() {
        waiting_for_the_connection_keeps_to_the_deadline(&dot_test_client().await).await;
    }

    /// 时限到了的查询要复位连接、锁却被别人拿着时，它不等，按时返回；复位留给下一次建连。此前它
    /// 要等到锁放开，排在长队后面的查询远远超出时限才返回。
    /// A query past its deadline that has to reset the connection while someone else
    /// holds the lock does not wait but returns on time, leaving the reset to the
    /// next connect. It used to wait for the lock, so a query at the back of a long
    /// queue returned far past its deadline.
    async fn a_reset_past_the_deadline_does_not_wait_for_the_lock(client: &impl StreamMux) {
        client
            .query(&udp_test_query("warm.example"), Duration::from_secs(2))
            .await
            .expect("a fresh connection answers");
        let generation = client.connection_generation();

        let query = udp_test_query("slow.example");
        let next = udp_test_query("next.example");
        let ((result, took, next_took), _) = tokio::join!(
            async {
                let started = tokio::time::Instant::now();
                let result = client.query(&query, Duration::from_millis(300)).await;
                let took = started.elapsed();
                // 锁还被拿着：下一个查询做欠着的复位时也守自己的时限
                // The lock is still held: the next query keeps to its own deadline
                // while doing the owed reset
                let started = tokio::time::Instant::now();
                let next = client.query(&next, Duration::from_millis(200)).await;
                assert!(next.is_err(), "the lock is still held");
                (result, took, started.elapsed())
            },
            async {
                // 查询的时限到之前把锁拿住 / Take the lock before the query's deadline
                tokio::time::sleep(Duration::from_millis(250)).await;
                client.hold_connection(Duration::from_millis(800)).await;
            }
        );
        assert!(result.is_err(), "the upstream never answers `slow`");
        assert!(took < Duration::from_millis(500), "returned after {took:?}");
        assert!(
            next_took < Duration::from_millis(450),
            "the next query returned after {next_took:?}"
        );

        // 下一次建连先把欠着的复位做完，再换新连接回答
        // The next connect first does the owed reset, then answers over a new connection
        client
            .query(&udp_test_query("after.example"), Duration::from_secs(2))
            .await
            .expect("a new connection answers");
        assert_eq!(client.connection_generation(), generation + 1);
    }

    #[tokio::test]
    async fn a_tcp_reset_past_the_deadline_does_not_wait_for_the_lock() {
        a_reset_past_the_deadline_does_not_wait_for_the_lock(&tcp_test_client().await).await;
    }

    #[tokio::test]
    async fn a_dot_reset_past_the_deadline_does_not_wait_for_the_lock() {
        a_reset_past_the_deadline_does_not_wait_for_the_lock(&dot_test_client().await).await;
    }

    /// 同一个 ID 下回答别的问题的不收，查询接着等自己的回答，和 UDP 一样。此前只按 ID 对号：
    /// 连接上 ID 转了一圈以后，之前用过这个 ID 的查询迟到的回答会被交给现在的查询，还会进缓存。
    /// An answer to another question under the same ID is dropped and the query
    /// keeps waiting for its own, as on UDP. Answers used to be matched by ID only:
    /// once the IDs on a connection had come round, a late answer to an earlier
    /// query with that ID was handed to the current one, and cached.
    async fn an_answer_to_another_question_is_dropped(client: &impl StreamMux) {
        let query = udp_test_query("swap.example");
        let answer = client
            .query(&query, Duration::from_secs(2))
            .await
            .expect("the real answer follows");
        assert_eq!(answer.as_ref(), echo_answer(&query).as_slice());
    }

    #[tokio::test]
    async fn a_tcp_answer_to_another_question_is_dropped() {
        an_answer_to_another_question_is_dropped(&tcp_test_client().await).await;
    }

    #[tokio::test]
    async fn a_dot_answer_to_another_question_is_dropped() {
        an_answer_to_another_question_is_dropped(&dot_test_client().await).await;
    }

    /// 一个查询超时、这条连接上又再没有回答时，连接会被重建。此前同一条连接上还在等
    /// 的查询被晾着：reader 已经取消，它们的回答再也到不了，只能等满自己的截止时间，
    /// 然后各自再重置一次连接，把新连接上的查询也连累进去。
    /// When a query times out and nothing else answered on the connection, the
    /// connection is rebuilt. The other queries waiting on it used to be left
    /// hanging: with the reader cancelled their answers could never arrive, so
    /// each sat out its full deadline and then reset the connection again,
    /// dragging in the queries on the new one.
    async fn a_slow_answer_does_not_cost_its_neighbours_theirs(client: &impl StreamMux) {
        client
            .query(&udp_test_query("warm.example"), Duration::from_secs(2))
            .await
            .expect("a fresh connection answers");

        let started = tokio::time::Instant::now();
        let slow_query = udp_test_query("slow.example");
        let late_query = udp_test_query("late.example");
        let (slow, late) = tokio::join!(
            client.query(&slow_query, Duration::from_millis(300)),
            client.query(&late_query, Duration::from_secs(2)),
        );
        assert!(slow.is_err(), "the upstream never answers `slow`");
        assert!(
            late.is_ok(),
            "`late` is answered after 400 ms, but got {:?} after {:?}",
            late.err(),
            started.elapsed()
        );
        assert!(
            started.elapsed() < Duration::from_millis(1500),
            "`late` waited {:?} instead of retrying over a fresh connection",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn a_slow_tcp_answer_does_not_cost_its_neighbours_theirs() {
        a_slow_answer_does_not_cost_its_neighbours_theirs(&tcp_test_client().await).await;
    }

    #[tokio::test]
    async fn a_slow_dot_answer_does_not_cost_its_neighbours_theirs() {
        a_slow_answer_does_not_cost_its_neighbours_theirs(&dot_test_client().await).await;
    }

    /// 这条连接在慢查询写出之后还回答了别的查询：连接是活的，不能因为一个回答慢就重建
    /// The connection answered another query after the slow one was written: it
    /// is alive and must not be rebuilt over one slow answer
    async fn a_slow_answer_keeps_a_live_connection(client: &impl StreamMux) {
        client
            .query(&udp_test_query("warm.example"), Duration::from_secs(2))
            .await
            .expect("a fresh connection answers");
        let generation = client.connection_generation();

        let slow_query = udp_test_query("slow.example");
        let mid_query = udp_test_query("mid.example");
        let (slow, mid) = tokio::join!(
            client.query(&slow_query, Duration::from_millis(300)),
            client.query(&mid_query, Duration::from_secs(2)),
        );
        assert!(slow.is_err(), "the upstream never answers `slow`");
        assert!(
            mid.is_ok(),
            "`mid` is answered after 100 ms: {:?}",
            mid.err()
        );
        client
            .query(&udp_test_query("after.example"), Duration::from_secs(2))
            .await
            .expect("the connection still answers");
        assert_eq!(
            client.connection_generation(),
            generation,
            "one slow answer on a connection that keeps answering must not rebuild it"
        );
    }

    #[tokio::test]
    async fn a_slow_tcp_answer_keeps_a_live_connection() {
        a_slow_answer_keeps_a_live_connection(&tcp_test_client().await).await;
    }

    #[tokio::test]
    async fn a_slow_dot_answer_keeps_a_live_connection() {
        a_slow_answer_keeps_a_live_connection(&dot_test_client().await).await;
    }

    /// reset 之后连接上再也不会有回答，等着的查询要立刻得到失败，而不是等满截止时间。
    /// 连接老化（默认 5 分钟）、连续出错达到阈值都会走这里。
    /// After a reset no answer can arrive on the connection, so a waiting query
    /// must fail at once rather than at its deadline. Connection ageing (5
    /// minutes by default) and the error threshold both come through here.
    async fn a_reset_fails_waiting_queries_at_once(client: &impl StreamMux) {
        let started = tokio::time::Instant::now();
        let slow_query = udp_test_query("slow.example");
        let (result, ()) = tokio::join!(client.query(&slow_query, Duration::from_secs(3)), async {
            tokio::time::sleep(Duration::from_millis(200)).await;
            client.drop_connection().await;
        });
        assert!(result.is_err(), "the upstream never answers `slow`");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "the waiting query was only released after {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn a_tcp_reset_fails_waiting_queries_at_once() {
        a_reset_fails_waiting_queries_at_once(&tcp_test_client().await).await;
    }

    #[tokio::test]
    async fn a_dot_reset_fails_waiting_queries_at_once() {
        a_reset_fails_waiting_queries_at_once(&dot_test_client().await).await;
    }

    /// 握手被压住 250 ms、回答再等 250 ms：300 ms 预算的请求曾跑满 560 ms 才成功
    /// A handshake held back 250 ms and an answer after another 250 ms: a request
    /// with a 300 ms budget used to run the full 560 ms and succeed
    #[tokio::test]
    async fn doq_handshake_and_answer_share_one_budget() {
        let (server, client_tls) = localhost_tls(&[b"doq"]);
        let addr = spawn_doq_upstream(server, Duration::from_millis(250), |_, _| {
            DoqReply::Answer(Duration::from_millis(250))
        })
        .await;
        let client = doq_test_client(format!("doq://{addr}?sni=localhost"), client_tls, false);
        let started = tokio::time::Instant::now();
        let result = client
            .send(
                &udp_test_query("budget.example"),
                Duration::from_millis(300),
            )
            .await;
        let elapsed = started.elapsed();
        assert!(result.is_err(), "the answer cannot arrive within 300 ms");
        assert!(
            elapsed < Duration::from_millis(420),
            "a 300 ms request ran for {elapsed:?}"
        );
    }

    #[test]
    fn dot_target_accepts_an_ipv6_literal() {
        let target = parse_dot_target("[2400:3200::1]:853").expect("parse an IPv6 DoT upstream");
        assert_eq!(&*target.connect_addr, "[2400:3200::1]:853");
        assert_eq!(&*target.sni, "2400:3200::1");
        assert!(
            matches!(build_server_name(&target.sni), Ok(ServerName::IpAddress(_))),
            "the server name for an IP literal must be the address itself"
        );
    }

    #[test]
    fn doq_target_with_an_ipv6_literal_requires_sni() {
        assert!(
            parse_doq_target("[2400:3200::1]:853").is_err(),
            "an IPv6 literal without sni must be refused like an IPv4 one"
        );
        let target = parse_doq_target("[2400:3200::1]:853?sni=dns.alidns.com")
            .expect("an IPv6 literal with sni is fine");
        assert_eq!(host_port(&target.host, target.port), "[2400:3200::1]:853");
    }

    /// `tls://[…]` 写法的上游此前根本连不上：地址被拼成 `[[…]]:853`
    /// An upstream written `tls://[…]` could not connect at all: the address came
    /// out as `[[…]]:853`
    #[tokio::test]
    async fn dot_reaches_an_ipv6_literal_upstream() {
        let (server, client_tls) = self_signed_tls(&["::1"], &[]);
        let Some(addr) = spawn_stream_upstream_on("[::1]:0", Some(server), None).await else {
            eprintln!("skipped: IPv6 loopback unavailable on this host");
            return;
        };
        let client = DotMuxClient::new(
            Arc::from(format!("dot://[::1]:{}", addr.port())),
            Arc::new(client_tls),
        );
        client
            .send(&udp_test_query("v6.example"), Duration::from_secs(2))
            .await
            .expect("an IPv6 literal DoT upstream answers");
    }

    #[tokio::test]
    async fn doq_reaches_an_ipv6_literal_upstream() {
        let (server, client_tls) = localhost_tls(&[b"doq"]);
        let answer = |_: usize, _: &str| DoqReply::Answer(Duration::ZERO);
        let Some(addr) = spawn_doq_upstream_on(
            "[::1]:0".parse().unwrap(),
            server,
            Duration::ZERO,
            answer,
            None,
        ) else {
            eprintln!("skipped: IPv6 loopback unavailable on this host");
            return;
        };
        let client = doq_test_client(
            format!("doq://[::1]:{}?sni=localhost", addr.port()),
            client_tls,
            false,
        );
        client
            .send(&udp_test_query("v6.example"), Duration::from_secs(2))
            .await
            .expect("an IPv6 literal DoQ upstream answers");
    }

    /// TCP 早有的保护 DoT 此前没有：写到一半被取消（多上游竞速时输掉的请求会被
    /// abort），半条帧留在 TLS 流里，下一个请求接着往后写，对端按长度前缀读就会错位
    /// The guard TCP already had, which DoT lacked: a write cancelled part way
    /// (the losers of a multi-upstream race are aborted) left half a frame in the
    /// TLS stream for the next request to append to, desynchronising a peer
    /// that reads by length prefix
    #[tokio::test]
    async fn a_cancelled_dot_write_drops_the_pooled_connection() {
        // 对端握手之后一个字节也不读，发送缓冲区会被填满
        // The peer completes the handshake and never reads, so the send buffer fills
        let (server, client_tls) = localhost_tls(&[]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
        let peer = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let held = acceptor.accept(stream).await.expect("TLS handshake");
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(held);
        });

        let client = Arc::new(DotMuxClient::new(
            Arc::from(format!("dot://{addr}?sni=localhost")),
            Arc::new(client_tls),
        ));
        client
            .ensure_connection(Duration::from_secs(2))
            .await
            .expect("connect to the test peer");

        // 把发送缓冲区填满，让后续写入必然停在 await 上
        // Fill the send buffer so any later write must park on an await
        {
            let mut guard = client.conn.lock().await;
            let writer = guard.as_mut().unwrap();
            let chunk = vec![0u8; 65536];
            while tokio::time::timeout(Duration::from_millis(300), writer.write_all(&chunk))
                .await
                .is_ok_and(|written| written.is_ok())
            {}
        }

        // 写入停在 await 上时取消这次发送 / Cancel the send while the write is parked
        let sender = Arc::clone(&client);
        let query = udp_test_query("cancelled.example");
        let task = tokio::spawn(async move { sender.send(&query, Duration::from_secs(30)).await });
        tokio::time::sleep(Duration::from_millis(300)).await;
        task.abort();
        let _ = task.await;

        assert!(
            client.conn.lock().await.is_none(),
            "a write cancelled part way through must drop the connection instead of \
             leaving a possibly half-written frame in the pool"
        );
        assert!(
            client.write_cancelled.load(Ordering::Acquire),
            "the next ensure_connection must be told to finish the cleanup that \
             Drop cannot await: the reader token and the queries still waiting"
        );
        peer.abort();
    }

    /// 每个 DoQ 上游有一组连接轮流用（默认 16 条）。"0-RTT 不稳定"此前是每条连接各记
    /// 各的：0-RTT 在跨境线路上发不出去时，每条连接都要先失败一次、等满超时（默认 9 秒）
    /// 才不再用它。
    /// Each DoQ upstream has a set of connections used in turn (16 by default).
    /// "0-RTT is unreliable" used to be recorded per connection: where 0-RTT
    /// cannot get through, every connection had to fail once and sit out the
    /// timeout (9 s by default) before it stopped using it.
    #[tokio::test]
    async fn doq_pool_shares_what_one_connection_learned_about_0rtt() {
        let client = DoqClient::new(2, 60, 15_000, true).expect("build DoQ client");
        // 发一个连不上的查询，只为建出这个上游的连接池
        // A query nothing answers, only to build this upstream's pool
        let upstream = "127.0.0.1:9?sni=localhost";
        let _ = client
            .send(
                &udp_test_query("pool.example"),
                upstream,
                Duration::from_millis(50),
            )
            .await;
        let pool = client
            .pools
            .get(upstream)
            .map(|pool| Arc::clone(&pool))
            .expect("the first query builds the pool");
        assert_eq!(pool.clients.len(), 2);

        pool.clients[0].disable_zero_rtt();
        assert!(
            pool.clients[1].zero_rtt_rejected.load(Ordering::Relaxed),
            "what one connection learned about 0-RTT holds for the whole upstream"
        );
    }

    /// 每条连接结束时发一个信号的本机 TCP 上游（见 [`spawn_stream_upstream`]）；`tls` 给了就是 DoT
    /// A local TCP upstream (see [`spawn_stream_upstream`]) signalling whenever a
    /// connection ends; DoT when `tls` is given
    async fn upstream_noting_closes(
        tls: Option<rustls::ServerConfig>,
    ) -> (SocketAddr, tokio::sync::mpsc::UnboundedReceiver<()>) {
        let (closed_tx, closed_rx) = tokio::sync::mpsc::unbounded_channel();
        let addr = spawn_stream_upstream_on("127.0.0.1:0", tls, Some(closed_tx))
            .await
            .expect("bind the stream test upstream");
        (addr, closed_rx)
    }

    /// 连接池被留下时连接不断，被丢掉以后连接关闭
    /// A kept pool keeps its connection; once the pool is dropped the connection closes
    async fn kept_then_dropped(
        closed: &mut tokio::sync::mpsc::UnboundedReceiver<()>,
        retain: impl Fn(bool),
    ) {
        retain(true);
        assert!(
            timeout(Duration::from_millis(300), closed.recv())
                .await
                .is_err(),
            "a kept upstream keeps its connection"
        );
        retain(false);
        timeout(Duration::from_secs(2), closed.recv())
            .await
            .expect("the connection closes once its pool is dropped");
    }

    #[tokio::test]
    async fn dropping_a_tcp_pool_closes_its_connection() {
        let (addr, mut closed) = upstream_noting_closes(None).await;
        let mux = TcpMultiplexer::new(2, 3, 300, 60);
        mux.send(
            &udp_test_query("a.example"),
            &addr.to_string(),
            Duration::from_secs(2),
        )
        .await
        .expect("the upstream answers");
        kept_then_dropped(&mut closed, |keep| mux.retain_upstreams(|_| keep)).await;
    }

    #[tokio::test]
    async fn dropping_a_dot_pool_closes_its_connection() {
        let (server, client_tls) = localhost_tls(&[]);
        let (addr, mut closed) = upstream_noting_closes(Some(server)).await;
        let mux = DotMultiplexer::with_shared(Arc::new(client_tls), 2, 3, 300, 60);
        mux.send(
            &udp_test_query("a.example"),
            &format!("{addr}?sni=localhost"),
            Duration::from_secs(2),
        )
        .await
        .expect("the upstream answers");
        kept_then_dropped(&mut closed, |keep| mux.retain_upstreams(|_| keep)).await;
    }

    /// 连接池里的客户端用的是建多路复用器时给的健康设置：错误阈值、连接最长存活、空闲时长
    /// A pool's clients take the health settings the multiplexer was built with: the error
    /// threshold, the longest a connection may live and how long it may sit idle
    #[tokio::test]
    async fn pool_clients_take_the_configured_health_settings() {
        let mux = TcpMultiplexer::new(1, 2, 0, 0);
        let client = Arc::clone(&mux.get_or_init_pool_for_test("127.0.0.1:9").clients[0]);
        assert!(
            !client.record_error().await,
            "one error is below a threshold of 2"
        );
        assert!(client.record_error().await, "the second error reaches it");

        // 把连接的出生时间或上次请求时间往前拨 2 秒，再让下一次发送做健康检查：设成 1 秒的
        // 那一项会让旧连接被关掉
        // Wind the connection's birth or its last request back 2 seconds and have the next
        // send run the health check: the setting given as 1 second closes the old connection
        let wind_back = |stamp: fn(&TcpMuxClient) -> &AtomicU64| {
            move |client: &TcpMuxClient| {
                stamp(client).store(unix_time_millis() - 2_000, Ordering::Release);
                client.last_health_check_time.store(0, Ordering::Relaxed);
            }
        };
        for (mux, age) in [
            (
                TcpMultiplexer::new(1, 3, 1, 0),
                wind_back(|client| &client.conn_create_time),
            ),
            (
                TcpMultiplexer::new(1, 3, 0, 1),
                wind_back(|client| &client.last_request_time),
            ),
        ] {
            let (addr, mut closed) = upstream_noting_closes(None).await;
            let upstream = addr.to_string();
            let query = udp_test_query("a.example");
            mux.send(&query, &upstream, Duration::from_secs(2))
                .await
                .expect("the upstream answers");
            age(&mux.get_or_init_pool_for_test(&upstream).clients[0]);
            mux.send(&query, &upstream, Duration::from_secs(2))
                .await
                .expect("the upstream answers again");
            timeout(Duration::from_secs(2), closed.recv())
                .await
                .expect("the health check closes the old connection");
        }
    }

    /// DoQ 连接带着保活，不关掉的话会一直给旧上游发包
    /// A DoQ connection carries a keep-alive and would go on pinging the old upstream
    #[tokio::test]
    async fn dropping_a_doq_pool_closes_its_connection() {
        let (server, client_tls) = localhost_tls(&[b"doq"]);
        let (closed_tx, mut closed) = tokio::sync::mpsc::unbounded_channel();
        let addr = spawn_doq_upstream_on(
            "127.0.0.1:0".parse().unwrap(),
            server,
            Duration::ZERO,
            |_, _| DoqReply::Answer(Duration::ZERO),
            Some(closed_tx),
        )
        .expect("bind the DoQ test upstream");
        let client = DoqClient {
            pools: UpstreamPools::new(),
            pool_size: 1,
            runtime: doq_test_runtime(client_tls, false),
        };
        client
            .send(
                &udp_test_query("a.example"),
                &format!("{addr}?sni=localhost"),
                Duration::from_secs(2),
            )
            .await
            .expect("the upstream answers");
        kept_then_dropped(&mut closed, |keep| client.retain_upstreams(|_| keep)).await;
    }

    /// 重载换掉上游以后，旧上游的连接关闭；上游没变的重载不碰它
    /// After a reload replaces the upstream, the old one's connection closes; a reload
    /// that keeps the upstream leaves it alone
    #[tokio::test]
    async fn a_reload_closes_the_connections_of_upstreams_it_drops() {
        let (addr, mut closed) = upstream_noting_closes(None).await;
        let runtime = |upstream: &str| {
            let raw = serde_json::json!({
                "settings": { "default_upstream": "127.0.0.1:9", "upstream_timeout_ms": 2000 },
                "pipelines": [{ "id": "main", "rules": [{
                    "name": "all", "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "forward", "upstream": upstream }]
                }] }]
            });
            let config: crate::config::PipelineConfig =
                serde_json::from_value(raw).expect("parse config");
            crate::matcher::RuntimePipelineConfig::from_config(config)
                .expect("build runtime config")
        };
        let tcp_upstream = format!("tcp://{addr}");
        let engine =
            crate::engine::Engine::new(runtime(&tcp_upstream), "test".to_string()).expect("engine");
        let peer: SocketAddr = "192.0.2.10:53000".parse().unwrap();
        timeout(
            Duration::from_secs(5),
            engine.handle_packet(&udp_test_query("a.example"), peer),
        )
        .await
        .expect("answer in time")
        .expect("answer");

        engine.reload(runtime(&tcp_upstream));
        assert!(
            timeout(Duration::from_millis(300), closed.recv())
                .await
                .is_err(),
            "a reload that keeps the upstream keeps its connection"
        );
        engine.reload(runtime("udp://127.0.0.1:9"));
        timeout(Duration::from_secs(2), closed.recv())
            .await
            .expect("the dropped upstream's connection closes");
    }
}
