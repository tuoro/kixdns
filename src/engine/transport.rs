use anyhow::Context;
use arc_swap::{ArcSwap, ArcSwapOption};
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use dashmap::mapref::entry;
use futures::FutureExt;
use futures::future::{BoxFuture, Shared};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{
    Connection as QuicConnection, Endpoint as QuicEndpoint, TransportConfig as QuicTransportConfig,
};
use reqwest::Client as DohHttpClient;

use super::bootstrap::{Bootstrap, Resolver};
use super::doh_h2::{self, H2Link};
use reqwest::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE, HOST, HeaderValue, RETRY_AFTER};
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
use tokio::sync::oneshot;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use url::Url;
use webpki_roots::TLS_SERVER_ROOTS;

/// Least budget worth spending on a transparent retry over a fresh connection.
/// A retry has to reconnect (SYN, plus a TLS handshake for DoT and DoH) and
/// then wait for an answer; with less than this left it cannot complete on a
/// realistic path and would only add a second failure after the caller's
/// deadline. The caller's deadline itself is never extended.
/// 值得为透明重试花的最小剩余预算。重试要先重连（SYN，DoT/DoH 还有 TLS 握手）再等应答，
/// 剩余不足这个值时现实路径上跑不完，只会在调用方截止后再失败一次。绝不延长调用方的截止。
const MIN_RETRY_BUDGET: Duration = Duration::from_millis(50);

/// 从 `started` 起有 `budget` 的查询还剩多少，够一次透明重试（见 [`MIN_RETRY_BUDGET`]）时给出来；TCP、DoT、DoH 和
/// DoQ 都按它定重不重试
/// What is left of a query's `budget` from `started`, given when it is enough for a transparent
/// retry (see [`MIN_RETRY_BUDGET`]); TCP, DoT, DoH and DoQ all decide on a retry by it
fn retry_budget(budget: Duration, started: tokio::time::Instant) -> Option<Duration> {
    Some(budget.saturating_sub(started.elapsed())).filter(|left| *left >= MIN_RETRY_BUDGET)
}

/// 一个在途的 UDP 查询：客户端的 ID、发给谁、发出去的查询、回答交给谁 / One UDP query in flight: the
/// client's ID, whom it was sent to, the query as sent, and whom the reply goes to
type UdpInflight = (
    u16,
    SocketAddr,
    Arc<[u8]>,
    oneshot::Sender<anyhow::Result<Bytes>>,
);

/// 在途的 UDP 查询，按改写过的 ID（见 [`UdpInflight`]）。条目留着改写过 ID 的查询报文，供读取任务比对应答的问题（RFC
/// 5452 §9.1）/ The UDP queries in flight, by rewritten ID (see [`UdpInflight`]). An entry keeps
/// the query as sent, its ID rewritten, for the reader to match the answer's question against
/// (RFC 5452 §9.1)
type UdpInflightMap = DashMap<u16, UdpInflight, FxBuildHasher>;

/// 等着一个在途条目的回答的那一头：回答从 `rx` 来。放手时（拿到了回答、超时、取消、提前返回、panic）把 `map` 里
/// `id` 下已经没人等的条目删掉：先关掉自己这一头再删，所以自己的条目一定删得掉。回答到了、读取任务把条目拿走以后，
/// 这个 ID 可能已经分给了后来的查询，那一条有人等着，不动：按 ID 不管是谁都删的话，会把它带走，它的回答到了找不到
/// 条目，只能等到超时
/// The end that waits for an in-flight entry's answer, which comes on `rx`. On letting go (with
/// the answer, at a timeout, on cancellation, an early return or a panic) it removes the entry
/// under `id` in `map` if nobody waits on it any more: its own end is closed first, so its own
/// entry always goes. Once an answer has come and the reader has taken the entry, the ID may
/// have gone to a later query, whose entry is waited on and stays: removing by ID whatever is
/// there would take it along, its answer finding no entry and the query waiting out its timeout
struct Waiting<V> {
    rx: oneshot::Receiver<anyhow::Result<Bytes>>,
    map: Arc<DashMap<u16, V, FxBuildHasher>>,
    id: u16,
    /// 这个条目的回答是不是没人等了 / Whether nobody waits for this entry's answer any more
    abandoned: fn(&V) -> bool,
}

impl<V> Drop for Waiting<V> {
    fn drop(&mut self) {
        self.rx.close();
        self.map
            .remove_if(&self.id, |_, entry| (self.abandoned)(entry));
    }
}

/// 池里的一个 socket：它在途的查询，发过多少个（见 [`UDP_SOCKET_QUERIES`]），和收它回答的任务。还在等回答的查询各拿着
/// 一份，所以换下来以后也照样收得到它们的回答；最后一份放下时停掉接收任务，socket 随之关掉
/// One socket of the pool: its queries in flight, how many it has sent (see
/// [`UDP_SOCKET_QUERIES`]), and the task receiving its replies. Every query still waiting for a
/// reply holds it too, so once replaced it still takes their replies; the last let go of stops
/// the receiving task, and the socket closes with it
struct UdpSocketState {
    socket: Arc<tokio::net::UdpSocket>,
    inflight: Arc<UdpInflightMap>,
    sent: std::sync::atomic::AtomicU32,
    reader: tokio::task::AbortHandle,
}

impl Drop for UdpSocketState {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

/// 一个 socket 发出这么多个查询以后，换成系统另挑端口的新 socket（RFC 5452 §9.2）：一个端口要是一直用下去，猜出或者
/// 探出来（像 SAD DNS 那样借 ICMP 的限速去扫）一次就一直有效；一个端口最多用这么多次，查询越多换得越快。也不每个
/// 查询都换：每个新端口在防火墙的连接跟踪里占一条、留一分钟，OpenWrt 上每秒两百来个未命中就能把表占满，满了整台路由器
/// 的新连接都被丢掉；每个查询单开 socket 的未命中还多花四分之一的 CPU
/// After sending this many queries a socket is replaced by a new one, on another port the system
/// picks (RFC 5452 §9.2): a port kept for good stays good for ever once guessed or probed
/// (through the ICMP rate limit, as SAD DNS does), so a port serves this many at most, replaced
/// the faster the more queries come. Nor is it replaced every query: each
/// new port takes an entry in the firewall's connection tracking for a minute, a couple of
/// hundred misses a second fill the table on OpenWrt, and with it full the whole router drops
/// new connections; a socket per query also costs a miss a quarter more CPU
const UDP_SOCKET_QUERIES: u32 = 64;

/// 池里第 `idx` 个 UDP socket 接收出错：记下来，给出歇多久再接着收，None 是马上接着收。
///
/// Windows 上没有连接的 UDP socket 收到 ICMP 端口不可达时，`recv_from` 会报 ConnectionReset（WSAECONNRESET）。这只说明之前
/// 发出的某个查询没人收，socket 本身好好的，那个查询自己会超时、重发：只记 debug，马上接着收，歇着只会耽误这个 socket 上
/// 别的查询的应答。别的错误记 warn（同一处一阵子只记一条），歇 100 ms，免得反复出错时空转
///
/// A receive error on socket `idx` of the pool: it is logged, and how long to pause before reading
/// on is given, None reading on at once.
///
/// On Windows, an unconnected UDP socket that gets an ICMP port unreachable reports
/// ConnectionReset (WSAECONNRESET) from `recv_from`. That only says some earlier query reached
/// nobody; the socket itself is fine and that query times out and is sent again on its own: it
/// is logged at debug and reading goes on at once, a pause only delaying the answers to the other
/// queries on the socket. Any other error logs a warn (one in a while from this place) and pauses
/// 100 ms, so a repeating one does not spin
fn after_recv_error(idx: usize, error: &std::io::Error) -> Option<Duration> {
    if error.kind() == std::io::ErrorKind::ConnectionReset {
        debug!(socket_idx = idx, error = %error, "UDP pool socket told a query reached nobody");
        return None;
    }
    crate::warn_sparse!(socket_idx = idx, error = %error, "UDP pool recv error, pausing");
    Some(Duration::from_millis(100))
}

thread_local! {
    /// 收 UDP 回答的缓冲，每个线程一块，容得下最大的 DNS 报文：EDNS 允许把 UDP 应答协商到 65535 字节，比缓冲区长的数据报
    /// 会被悄悄截掉尾部。不跟着 socket 走：每个 socket 各带一块的话，默认 64 个 socket 常驻内存多约 1 MiB，换 socket
    /// 时还要重新分配
    /// The buffer UDP replies are received into, one per thread, holding the largest DNS message:
    /// EDNS lets a UDP answer be negotiated up to 65535 bytes, and a datagram longer than the
    /// buffer loses its tail without notice. It goes with no socket: one each would keep some 1 MiB
    /// more resident with the default 64 sockets, allocated again whenever a socket is replaced
    static UDP_RECEIVED: std::cell::RefCell<Box<[u8]>> =
        std::cell::RefCell::new(vec![0; MAX_DNS_MESSAGE_SIZE].into_boxed_slice());
}

/// 把从 `src` 收到的数据报 `reply` 交给等着它的查询：ID 对得上在途的条目、来自它问的地址、而且回答的是它的问题（RFC 5452
/// §9.1，见 `answers_query`）时，换回客户端的 ID，拷出一份正好大小的交过去；对不上的留着条目接着等真的回答
/// Hands the datagram `reply` received from `src` to the query waiting for it: when the ID
/// matches an entry in flight, it comes from the address that entry asked, and it answers that
/// question (RFC 5452 §9.1, see `answers_query`), the client's ID is put back and a copy of
/// exactly its size handed over; one that does not match leaves the entry waiting for the real reply
fn hand_over_udp_reply(idx: usize, inflight: &UdpInflightMap, reply: &mut [u8], src: SocketAddr) {
    let Some(id) = reply.get(..2).map(|id| u16::from_be_bytes([id[0], id[1]])) else {
        return;
    };
    let entry::Entry::Occupied(entry) = inflight.entry(id) else {
        return;
    };
    let (_, expected_addr, query, _) = entry.get();
    if src != *expected_addr {
        crate::warn_sparse!(
            socket_idx = idx,
            response_id = id,
            expected_addr = %expected_addr,
            actual_addr = %src,
            "UDP response address mismatch, possible spoofing or routing anomaly"
        );
    } else if !crate::proto_utils::answers_query(query, reply) {
        crate::warn_sparse!(
            socket_idx = idx,
            response_id = id,
            upstream = %src,
            "UDP response does not answer the query, possible spoofing"
        );
    } else {
        let (_, (original_id, _, _, tx)) = entry.remove_entry();
        reply[..2].copy_from_slice(&original_id.to_be_bytes());
        if tx.send(Ok(Bytes::copy_from_slice(reply))).is_err() {
            tracing::debug!(
                socket_idx = idx,
                original_id,
                response_id = id,
                "Failed to send UDP response, channel already closed"
            );
        }
    }
}

/// 池里的 socket 各在一个位置上，用满 [`UDP_SOCKET_QUERIES`] 次换成新的 / The pool's sockets each in a
/// place of their own, replaced once used [`UDP_SOCKET_QUERIES`] times
type UdpPool = Box<[ArcSwap<UdpSocketState>]>;

pub struct UdpClient {
    /// IPv4 sockets, one ephemeral port each. / IPv4 socket，各占一个临时端口。
    pool: UdpPool,
    /// IPv6 sockets (IPV6_V6ONLY), built on the first query to an IPv6 upstream
    /// so a deployment without one pays for nothing.
    /// IPv6 socket（IPV6_V6ONLY），第一次查询 IPv6 上游时才建立，
    /// 没有 IPv6 上游的部署不付出任何代价。
    pool_v6: tokio::sync::OnceCell<UdpPool>,
    pool_size: usize,
}

/// 一个地址族的 socket 怎么建：哪一族，绑在哪 / How a family's sockets are made: which family, bound where
fn udp_family(v6: bool) -> (Domain, SocketAddr) {
    if v6 {
        (
            Domain::IPV6,
            SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0)),
        )
    } else {
        (Domain::IPV4, SocketAddr::from(([0, 0, 0, 0], 0)))
    }
}

impl UdpClient {
    pub fn new(size: usize) -> anyhow::Result<Self> {
        // Prevent port exhaustion by enforcing minimum pool size
        let effective_size = if size == 0 { 1 } else { size };
        Ok(Self {
            pool: Self::build_pool(effective_size, false)?,
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
    fn build_pool(size: usize, v6: bool) -> anyhow::Result<UdpPool> {
        let (domain, bind_addr) = udp_family(v6);
        let mut sockets = Vec::with_capacity(size);
        for _ in 0..size {
            sockets.push(Self::create_socket(domain, bind_addr)?);
        }
        Ok(sockets
            .into_iter()
            .enumerate()
            .map(|(idx, socket)| ArcSwap::from_pointee(Self::spawn_reader(idx, socket)))
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
        let inflight: Arc<UdpInflightMap> = Arc::new(DashMap::with_hasher(FxBuildHasher));
        let (reading, map) = (Arc::clone(&socket), Arc::clone(&inflight));
        let reader = tokio::spawn(async move {
            let (socket, inflight) = (reading, map);
            loop {
                // 等到可读，再同步收进这个线程的缓冲：socket 自己不带缓冲，换下来再建新的也不用每次分配
                // Readable first, then received into this thread's buffer at once: the socket carries no
                // buffer of its own, and replacing it allocates none
                let received = match socket.readable().await {
                    Ok(()) => UDP_RECEIVED.with_borrow_mut(|buf| {
                        let (len, src) = socket.try_recv_from(buf)?;
                        hand_over_udp_reply(idx, &inflight, &mut buf[..len], src);
                        Ok(())
                    }),
                    Err(error) => Err(error),
                };
                match received {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(error) => {
                        if let Some(pause) = after_recv_error(idx, &error) {
                            tokio::time::sleep(pause).await;
                        }
                    }
                }
            }
        })
        .abort_handle();
        UdpSocketState {
            socket,
            inflight,
            sent: std::sync::atomic::AtomicU32::new(0),
            reader,
        }
    }

    /// 发出查询并在 `timeout_dur` 内等它的回答（测试用）/ Sends the query and waits for its reply
    /// within `timeout_dur` (for tests)
    #[cfg(test)]
    pub async fn send(
        &self,
        packet: &[u8],
        upstream: &str,
        timeout_dur: Duration,
    ) -> anyhow::Result<Bytes> {
        let mut exchange = UdpExchange::new(self, packet, upstream);
        exchange.send(()).await?;
        match timeout(timeout_dur, exchange.reply()).await {
            Ok(Some((reply, ()))) => reply,
            Ok(None) => unreachable!("one copy sent and waited for"),
            Err(_) => Err(anyhow::anyhow!("upstream timeout")),
        }
    }

    /// 把查询发给 `upstream` 一次，返回等它回答的那一头（见 [`UdpSent`]）
    /// Sends the query to `upstream` once and gives the end that waits for its reply (see
    /// [`UdpSent`])
    #[inline]
    async fn begin(&self, packet: &[u8], upstream: &str) -> anyhow::Result<UdpSent> {
        let addr: SocketAddr = upstream.parse().context("invalid upstream address")?;
        // 按目标地址族选池：IPv4 路径只多一次判别
        // Pick the pool by address family; the IPv4 path only gains one check.
        let pool = if addr.is_ipv6() {
            self.pool_v6
                .get_or_try_init(|| async { Self::build_pool(self.pool_size, true) })
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
        let state = pool[idx].load_full();

        if packet.len() < 2 {
            return Err(anyhow::anyhow!("packet too short"));
        }
        let original_id = u16::from_be_bytes([packet[0], packet[1]]);

        // Copy the packet once so the ID can be rewritten; the same buffer is
        // sent and kept in the inflight entry for the answer's question check.
        // 只拷贝一次报文用于改写 ID；同一份缓冲既用于发送，也留在在途条目里供应答比对。
        let mut new_packet: Arc<[u8]> = Arc::from(packet);

        // Claim a free ID using the atomic entry API; on a collision with an
        // in-flight query draw a fresh random ID rather than the next one.
        // 使用原子 Entry API 占用空闲 ID；与在途查询冲突时重新随机，而不是取下一个。
        let mut attempts = 0;
        let mut new_id = draw as u16;
        let (tx, rx) = oneshot::channel();

        let new_packet = loop {
            match state.inflight.entry(new_id) {
                entry::Entry::Vacant(e) => {
                    // 放进条目之前只有这一份 / There is only this one until it goes in the entry
                    Arc::get_mut(&mut new_packet).expect("not shared yet")[0..2]
                        .copy_from_slice(&new_id.to_be_bytes());
                    e.insert((original_id, addr, Arc::clone(&new_packet), tx));
                    break new_packet;
                }
                entry::Entry::Occupied(_) => {
                    new_id = rand::random();
                    attempts += 1;
                    if attempts > 100 {
                        crate::warn_sparse!(
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
        let waiting = Waiting {
            rx,
            map: state.inflight.clone(),
            id: new_id,
            abandoned: |entry| entry.3.is_closed(),
        };

        if let Err(e) = state.socket.send_to(&new_packet, addr).await {
            // Guard will remove inflight entry automatically
            return Err(e.into());
        }
        Self::note_sent(&pool[idx], idx, &state, addr.is_ipv6());
        Ok(UdpSent {
            waiting,
            _socket: state,
        })
    }

    /// `state`（从池里第 `idx` 个位置 `slot` 上取的，`v6` 那一族）又发出了一个查询。用满 [`UDP_SOCKET_QUERIES`] 次就在
    /// `slot` 上换一个新的 socket，但只在 `slot` 上还是它时换：从取出它到数到这一次之间，别的查询可能已经把它换下来了，
    /// 这时再换会把刚换上去、还没怎么用的那个也换掉。建不出新的（描述符用光了）就接着用这个，再用满一轮时再换
    /// `state` (taken from `slot`, place `idx` of the pool, of the `v6` family) has sent one more
    /// query. Once used [`UDP_SOCKET_QUERIES`] times it is replaced on `slot` by a new socket, but
    /// only while `slot` still holds it: between taking it and counting this query another query
    /// may have replaced it already, and replacing then would replace the one just put in, hardly
    /// used yet. One that cannot be made (out of descriptors) leaves this one in use, replaced
    /// after another round
    fn note_sent(
        slot: &ArcSwap<UdpSocketState>,
        idx: usize,
        state: &Arc<UdpSocketState>,
        v6: bool,
    ) {
        if !(state.sent.fetch_add(1, Ordering::Relaxed) + 1).is_multiple_of(UDP_SOCKET_QUERIES) {
            return;
        }
        let (domain, bind_addr) = udp_family(v6);
        match Self::create_socket(domain, bind_addr) {
            Ok(socket) => {
                slot.compare_and_swap(state, Arc::new(Self::spawn_reader(idx, socket)));
            }
            Err(error) => {
                crate::warn_sparse!(error = %error, "cannot replace a UDP socket, keeping it in use")
            }
        }
    }
}

/// 发出去、在等回答的一份 UDP 查询（见 [`UdpClient::begin`]）。只要它还在，回答什么时候到都收得到；放手时不再等，
/// 它登记的条目跟着删掉（见 [`Waiting`]）
/// One copy of a UDP query sent and waiting for its reply (see [`UdpClient::begin`]). For as
/// long as it is kept the reply is taken whenever it arrives; let go of, it waits no more and the
/// entry it registered goes with it (see [`Waiting`])
struct UdpSent {
    waiting: Waiting<UdpInflight>,
    /// 发它的 socket：等着回答时不能关，换下来了也一样 / The socket that sent it, which may not close
    /// while the reply is waited for, replaced or not
    _socket: Arc<UdpSocketState>,
}

/// 一个查询和一个上游经 UDP 的一次收发：没等到回答就再发一份，发出去的每一份都一直登记着，谁的回答先到用谁的。后发的
/// 那份不顶替前面的：前一份的回答在重发以后才到也照样收下，回答比重发慢的上游不用多等一个重发的间隔。什么时候重发由调用方
/// 定（见 `upstream::forward_udp_smart` 和 `bootstrap`）；`T` 是调用方给每一份记的东西，比如它是什么时候发的。第一份放在
/// 自己里面，再发的才另外分配
/// One query's exchange with one upstream over UDP: with no reply yet another copy is sent, and
/// every copy sent stays registered, the first reply to come being used. A later copy does not
/// replace the earlier: a reply to an earlier one arriving after the resend is taken all the
/// same, so an upstream slower than the resend costs no resend's interval more. When to send
/// again is the caller's (see `upstream::forward_udp_smart` and `bootstrap`); `T` is what the
/// caller notes with each copy, when it was sent, say. The first copy is held inline, only further
/// ones are allocated
pub(crate) struct UdpExchange<'a, T> {
    udp: &'a UdpClient,
    packet: &'a [u8],
    upstream: &'a str,
    sent: smallvec::SmallVec<[(UdpSent, T); 1]>,
}

impl<'a, T> UdpExchange<'a, T> {
    /// 经 `udp` 把 `packet` 发给 `upstream` 的收发，还一份也没发 / The exchange sending `packet` to
    /// `upstream` through `udp`, no copy sent yet
    pub(crate) fn new(udp: &'a UdpClient, packet: &'a [u8], upstream: &'a str) -> Self {
        Self {
            udp,
            packet,
            upstream,
            sent: smallvec::SmallVec::new(),
        }
    }

    /// 再发一份，记上 `note`；发不出去的什么也不登记 / Sends one more copy noted `note`; one that cannot be
    /// sent registers nothing
    pub(crate) async fn send(&mut self, note: T) -> anyhow::Result<()> {
        let sent = self.udp.begin(self.packet, self.upstream).await?;
        self.sent.push((sent, note));
        Ok(())
    }

    /// 发出去的几份里先到的结果，和那一份记的东西；一份也不在等时是 None。给了结果的那一份不再等，别的接着等。没等到就被
    /// 放下的这次等待不影响下一次：回答到了，下一次照样拿得到
    /// The first outcome among the copies sent, with what that copy was noted with; None with no
    /// copy waited for. The copy that gave it waits no more, the others still do. A wait dropped
    /// before any outcome leaves the next one unaffected: a reply arriving is still there for it
    pub(crate) async fn reply(&mut self) -> Option<(anyhow::Result<Bytes>, T)> {
        if self.sent.is_empty() {
            return None;
        }
        let (at, outcome) = std::future::poll_fn(|cx| {
            self.sent
                .iter_mut()
                .enumerate()
                .find_map(|(at, (sent, _))| {
                    match std::pin::Pin::new(&mut sent.waiting.rx).poll(cx) {
                        std::task::Poll::Ready(outcome) => Some((at, outcome)),
                        std::task::Poll::Pending => None,
                    }
                })
                .map_or(std::task::Poll::Pending, std::task::Poll::Ready)
        })
        .await;
        let (_, note) = self.sent.swap_remove(at);
        // 发送的那一头没给结果就没了（正常不会，除非逻辑出错或者 panic）/ The sending end went without an
        // outcome (not normally, short of a logic error or a panic)
        let reply = outcome.unwrap_or_else(|_| Err(anyhow::anyhow!("channel closed")));
        Some((reply, note))
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

    /// 建好一条到 `upstream` 的连接，时限由 [`Connect`] 管 / Connect to `upstream`, within the
    /// time [`Connect`] allows
    fn connect(
        shared: &Self::Shared,
        upstream: &str,
    ) -> impl Future<Output = anyhow::Result<(Self::Read, Self::Write)>> + Send;
}

/// DNS over TCP（RFC 7766）/ DNS over TCP (RFC 7766)
pub struct Tcp;

impl StreamTransport for Tcp {
    /// 读回答经过缓冲：一次读进好几条回答，长度前缀和正文不用各读一次系统调用。DoT 的 TLS 流自己有缓冲
    /// Answers are read through a buffer: one read takes in several answers, and a length
    /// prefix and its body do not cost a system call each. DoT's TLS stream buffers on its own
    type Read = tokio::io::BufReader<OwnedReadHalf>;
    type Write = OwnedWriteHalf;
    type Shared = Arc<Bootstrap>;
    const LABEL: &'static str = "tcp";
    const NAME: &'static str = "TCP";
    const LOG_TARGET: &'static str = "tcp_mux";

    async fn connect(
        bootstrap: &Arc<Bootstrap>,
        upstream: &str,
    ) -> anyhow::Result<(Self::Read, OwnedWriteHalf)> {
        let stream = connect_tcp(bootstrap, upstream)
            .await
            .map_err(|e| anyhow::anyhow!("tcp connect failed: {e:#}"))?;
        let (read, write) = stream.into_split();
        Ok((tokio::io::BufReader::new(read), write))
    }
}

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
async fn staggered<T, F>(
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
pub(super) async fn connect_tcp(bootstrap: &Bootstrap, address: &str) -> anyhow::Result<TcpStream> {
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
const KEEPALIVE_TIME: Duration = Duration::from_secs(5);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(2);

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

/// 一条连接上同时有这么多查询还没答完就算忙，再来的查询换下一条：TCP、DoT 的连接池和 DoH 的连接位都这样挑
/// （见 [`least_busy`]）。一阵子几十个以内的查询（比如打开一个网页）都留在第一条连接上，用不着的连接不去连，
/// 常用的那条也不会因为隔太久没轮到而被当作空闲关掉、下个查询再重新连；一直有这么多在途时才分到后面的连接，
/// 各条连接的收发落到不同的核上
/// A connection with this many queries unanswered at once counts as busy, and further queries go
/// to the next one: the TCP and DoT pools and the DoH slots all pick this way (see
/// [`least_busy`]). A burst of a few dozen queries at most (a web page opening, say) stays on the
/// first connection, so connections nothing needs are not made, and the one in use is never left
/// unvisited long enough to be closed as idle and made again for the next query; only steadily
/// this many in flight spreads queries over the later connections, whose I/O then lands on
/// different cores
pub(crate) const BUSY_AT: usize = 32;

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
/// 失败、不去连。它放在各传输自己的锁里，那把锁只在看一眼、起一次建连的那一下拿着
/// Making a connection (TCP, DoT, DoQ, DoH over HTTP/2). The connect happens in a task of its
/// own, taking at most [`CONNECT_BUDGET`], and that task puts the connection in place itself
/// (the `make` each transport gives does both): with the query that started it cancelled
/// (another upstream answering first in a race, an outer timeout), the connection is made and put
/// in place all the same, read and watched for closing from the start, for the queries coming
/// next. Queries wanting a connection meanwhile all wait for this one connect, each until its own
/// deadline at most. After a failure it backs off, from [`CONNECT_BACKOFF`] doubling on each
/// failure up to [`CONNECT_BACKOFF_AT_MOST`], counted from the failure, the queries asking
/// meanwhile failing at once without connecting. It sits under each transport's own lock, held
/// only for the moment of a look and of starting a connect
pub(super) struct Connect {
    /// 这一次建连，等它的各拿一份；建完了也留着，下一个来要连接的查询看过结果再丢掉 / This connect, a copy
    /// for each waiting on it; kept once through, until the next query asking for a connection has
    /// looked at what it gave
    attempt: Option<Attempt>,
    /// 退避到什么时候，下一次失败退避多久 / Backing off until when, and for how long after the next failure
    retry_at: Option<std::time::Instant>,
    backoff: Duration,
}

/// 一次建连的结果，等着它的各拿一份 / One connect's outcome, a copy for each waiting on it
pub(super) type Attempt = Shared<BoxFuture<'static, Result<(), ConnectFailed>>>;

/// 一次建连为什么失败、什么时候失败的 / Why a connect failed, and when
#[derive(Clone, Debug)]
pub(super) struct ConnectFailed {
    why: Arc<str>,
    at: std::time::Instant,
}

impl std::fmt::Display for ConnectFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.why)
    }
}

impl std::error::Error for ConnectFailed {}

/// 建一条连接最多花多久（解析名字、TCP 或 QUIC 握手、TLS 握手）/ The most a connect may take
/// (resolving the name, the TCP or QUIC handshake, the TLS one)
const CONNECT_BUDGET: Duration = Duration::from_secs(5);
/// 建连第一次失败以后退避多久 / How long to back off after a first failed connect
const CONNECT_BACKOFF: Duration = Duration::from_millis(250);
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
    pub(super) fn attempt<F>(&mut self, make: impl FnOnce() -> F) -> anyhow::Result<Attempt>
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
            .and_then(|at| at.checked_duration_since(std::time::Instant::now()))
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
                    at: std::time::Instant::now(),
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
    pub(super) async fn get_or_make<L, T, F>(
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
pub(super) struct Aging {
    pub(super) max_age: Option<Duration>,
    pub(super) idle: Option<Duration>,
}

impl Aging {
    /// 活满 `max_age`、空闲满 `idle` 就摘下，0 是不限 / Taken out once it has lived `max_age` or sat
    /// idle for `idle`, 0 being no limit
    pub(super) fn new(max_age: Duration, idle: Duration) -> Self {
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
    pub(super) async fn worn(self, wear: &Wear) -> &'static str {
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
pub(super) struct Wear {
    made: tokio::time::Instant,
    /// 用它的查询里最晚的期限，从 `made` 起的微秒数 / The latest deadline of the queries using it, in
    /// microseconds from `made`
    latest_deadline_us: AtomicU64,
}

impl Wear {
    /// 刚建好的连接，还没有查询用过 / A connection just made, used by no query yet
    pub(super) fn new() -> Self {
        Self {
            made: tokio::time::Instant::now(),
            latest_deadline_us: AtomicU64::new(0),
        }
    }

    /// 一个期限在 `deadline` 的查询用上了它 / A query with its deadline at `deadline` uses it
    pub(super) fn note(&self, deadline: tokio::time::Instant) {
        let us = deadline.saturating_duration_since(self.made).as_micros();
        self.latest_deadline_us
            .fetch_max(u64::try_from(us).unwrap_or(u64::MAX), Ordering::AcqRel);
    }

    /// 用它的查询里最晚的期限；还没有查询用过时是建好的那一刻 / The latest deadline of the queries
    /// using it; the moment it was made while none has
    pub(super) fn latest_deadline(&self) -> tokio::time::Instant {
        self.made + Duration::from_micros(self.latest_deadline_us.load(Ordering::Acquire))
    }

    /// 等到用它的查询都过了各自的期限 / Waits until every query using it is past its deadline
    pub(super) async fn settled(&self) {
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
    clients: Vec<Arc<C>>,
}

impl<C> ConnectionPool<C> {
    fn new(clients: Vec<Arc<C>>) -> Self {
        Self { clients }
    }

    /// 排在最前、还不忙的客户端；都忙时在途最少的那个（见 [`least_busy`]）
    /// The first client not busy; with all busy, the one with the fewest in flight (see
    /// [`least_busy`])
    fn least_busy(&self, in_flight: impl Fn(&C) -> usize) -> &Arc<C> {
        least_busy(&self.clients, |client| in_flight(client))
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

    /// `upstream` 的连接池，还没有就用 `clients` 建一个。平常池已经在，只读一下：不分配键、不拿写锁 / The pool for
    /// `upstream`, built from `clients` if there is none. Normally the pool is there and is only
    /// read: no key allocated and no write lock taken
    fn get_or_create(
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
    /// 连接怎样老化（`tcp_connection_max_age_seconds`、`tcp_connection_idle_timeout_seconds`）/ How
    /// connections age (`tcp_connection_max_age_seconds`, `tcp_connection_idle_timeout_seconds`)
    aging: Aging,
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
        max_age_secs: u64,
        idle_timeout_secs: u64,
    ) -> Self {
        Self {
            pools: UpstreamPools::new(),
            pool_size: pool_size.max(1),
            shared,
            aging: Aging::new(
                Duration::from_secs(max_age_secs),
                Duration::from_secs(idle_timeout_secs),
            ),
        }
    }

    /// 只留下 `keep` 认可的上游的连接池（见 [`UpstreamPools::retain`]）/ Keeps only the pools of the
    /// upstreams `keep` accepts (see [`UpstreamPools::retain`])
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
                        self.aging,
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
        // 平常只用第一条连接，同一轮的查询在它上面一次写出去（见 `WriteQueue`）；忙了才用后面的
        // Normally only the first connection is used, with one round's queries going out on it
        // in one write (see `WriteQueue`); the later ones only once it is busy
        let client = pool.least_busy(|client| client.in_flight.load(Ordering::Relaxed));
        let _in_flight = InFlight::enter(&client.in_flight);
        client.send(packet, timeout_dur).await
    }
}

impl TcpMultiplexer {
    pub fn new(
        pool_size: usize,
        max_age_secs: u64,
        idle_timeout_secs: u64,
        bootstrap: Arc<Bootstrap>,
    ) -> Self {
        Self::with_shared(bootstrap, pool_size, max_age_secs, idle_timeout_secs)
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
        max_age_secs: u64,
        idle_timeout_secs: u64,
        bootstrap: Arc<Bootstrap>,
    ) -> anyhow::Result<Self> {
        let tls_config = build_tls_client_config()?;
        Ok(Self::with_shared(
            (Arc::new(tls_config), bootstrap),
            pool_size,
            max_age_secs,
            idle_timeout_secs,
        ))
    }
}

/// 一条连接：它的写入队列（见 [`WriteQueue`]）、它是第几代、停掉它的读取和写入任务的令牌、它读到过几个回答、它用了多久
/// （见 [`Wear`]）。几样放在一起、在同一把锁下，拆连接时才说得清拆的是哪一条
/// One connection: its write queue (see [`WriteQueue`]), which generation it is, the token that
/// stops its reader and writer, how many answers it has read, and how long it has lived (see
/// [`Wear`]). They sit together under one lock, so a teardown can say which connection it means
struct Live {
    queue: Arc<WriteQueue>,
    generation: u64,
    cancel: CancellationToken,
    /// 它的读取任务读满过几帧，对不对得上号都算。查询超时时看这期间涨没涨：涨了说明连接照常在回答，慢的只是这一个；
    /// 断了时看有没有过：答过的连接是上游关的，没答完的查询换一条重发（见 [`ConnectionGone`]）
    /// Whole frames its reader has read, matched or not. A query timing out looks whether this
    /// grew meanwhile: if so the connection kept answering and only this one is slow; a connection
    /// gone looks whether it ever did: one that answered was closed by the upstream, and the
    /// queries left unanswered are sent again on another (see [`ConnectionGone`])
    answers: Arc<AtomicU64>,
    /// 登记的查询都记上自己的期限，它的写入任务按它老化（见 [`Aging`]）/ Every query registered notes its
    /// deadline here, and the connection's writer ages it by this (see [`Aging`])
    wear: Arc<Wear>,
}

/// 一个客户端的连接槽：现在的连接（没有时是 None），和在建的连接（见 [`Connect`]）/ A client's connection
/// slot: the connection now (None without one), and the connection being made (see [`Connect`])
#[derive(Default)]
struct Slot {
    live: Option<Live>,
    connect: Connect,
}

/// 等着回答的查询，按改写过的 ID / The queries waiting for answers, by their rewritten IDs
type PendingMap = DashMap<u16, Pending, FxBuildHasher>;

/// 一个客户端的连接都要用的那几样，建连、读取和写入的任务各拿一份 / What a client's connections all use, a
/// copy for each connecting, reading and writing task
#[derive(Clone)]
struct Wires {
    upstream: Arc<str>,
    /// 连接槽。锁只在登记查询、装上和拆掉连接的那一下拿着，拿着它时不等任何东西；登记和拆除因此排得出先后：一个查询要么在拆
    /// 之前登记上、被告知失败，要么看到连接已经没了
    /// The connection slot. Its lock is held only for the moment of registering a query, and of
    /// putting a connection in place or tearing one down, never across a wait; registration and
    /// teardown are thereby ordered: a query either registers before the teardown and is told of
    /// the failure, or finds the connection gone
    slot: Arc<parking_lot::Mutex<Slot>>,
    pending: Arc<PendingMap>,
    /// 最近建的那条连接是第几代，从 1 起，装上连接时在槽的锁下加一。拆连接的决定都点名一代（见 `close_locked`）
    /// The generation of the connection made last, from 1, raised under the slot's lock as a
    /// connection is put in place. Every decision to tear one down names a generation (see
    /// `close_locked`)
    generation: Arc<AtomicU64>,
    /// 客户端被丢掉时取消：每条连接的令牌都是它的子令牌 / Cancelled when the client is dropped:
    /// every connection's token is a child of it
    stop: CancellationToken,
    /// 连接怎样老化 / How the connections age
    aging: Aging,
}

/// 一个上游的一条多路复用连接（TCP 或 DoT）/ One multiplexed connection to an upstream (TCP or DoT)
pub struct StreamMuxClient<T: StreamTransport> {
    wires: Wires,
    /// 建连用的共享部分 / What connects share
    shared: T::Shared,
    /// 这个客户端上还没答完的查询数（见 [`BUSY_AT`]）/ Queries on this client not yet answered (see [`BUSY_AT`])
    in_flight: AtomicUsize,
    next_id: AtomicU16,
}

/// 查询等回答时，它登记的那条连接没了：读写失败、被复位、空闲关掉、到期摘下后断了，或者在登记之前就被拆了。带着那条
/// 连接是第几代、回答过没有，`send` 据此判断要不要换新连接重发
/// The connection a query registered on went while it waited: a read or write failed, it was
/// reset or closed as idle, it broke after being taken out at its max age, or it was torn down
/// before the query could register. It carries that connection's generation and whether it had
/// answered anything, by which `send` decides whether to send again on a fresh one
#[derive(Debug)]
struct ConnectionGone {
    generation: u64,
    answered: bool,
    why: String,
}

impl std::fmt::Display for ConnectionGone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.why)
    }
}

impl std::error::Error for ConnectionGone {}

pub type TcpMuxClient = StreamMuxClient<Tcp>;
pub type DotMuxClient = StreamMuxClient<Dot>;

struct Pending {
    original_id: u16,
    /// 登记在第几代连接上：拆一代时只让它自己的查询失败 / Which generation of connection it registered on:
    /// tearing a generation down fails its own queries alone
    generation: u64,
    /// 写出去的帧（长度前缀加查询），回答到了用来比对问题
    /// The frame that was written (length prefix plus query), for checking the answer's question
    frame: Bytes,
    tx: oneshot::Sender<anyhow::Result<Bytes>>,
}

/// 一条连接上排着要写出去的帧，各带着它的查询改写过的 ID。查询登记时把帧放进来，连接的写入任务被叫醒后先让一轮，再把这一轮
/// 里排进来、查询还在等的帧一次写出去（见 [`write_frames`]）。查询自己不写：一个查询一次系统调用、DoT 一个 TLS 记录太贵，
/// 写到一半被取消（外层超时先到、多上游竞速输了被 abort）还会把半条帧留在连接上
/// The frames queued for writing on one connection, each with its query's rewritten ID. A query
/// puts its frame here when it registers; once woken, the connection's writer yields one round
/// and then writes at once the frames queued during that round whose queries still wait (see
/// [`write_frames`]). Queries do not write themselves: a system call per query, and for DoT a TLS
/// record, cost too much, and a write cancelled part way (the outer timeout first, or the loser of
/// a multi-upstream race aborted) would leave half a frame on the connection
#[derive(Default)]
struct WriteQueue {
    queued: parking_lot::Mutex<Vec<(u16, Bytes)>>,
    wake: tokio::sync::Notify,
}

impl WriteQueue {
    /// 排进 ID 为 `id` 的查询的帧 `frame`，叫醒写入任务 / Queues `frame`, the frame of the query whose ID
    /// is `id`, and wakes the writer
    fn push(&self, id: u16, frame: Bytes) {
        self.queued.lock().push((id, frame));
        self.wake.notify_one();
    }

    /// 取走排着的全部帧，换进 `taken` 里那个空的 / Takes every queued frame, leaving the empty one in
    /// `taken` in their place
    fn take(&self, taken: &mut Vec<(u16, Bytes)>) {
        std::mem::swap(taken, &mut *self.queued.lock());
    }
}

/// 让一轮：叫醒自己再让出，tokio 把这样的任务排到队尾，眼下排着的任务都跑过一遍再轮到它。
/// `tokio::task::yield_now` 不一样，要等工作线程手上的活全干完才回来，一直有活时会被拖很久
/// Yields one round: the task wakes itself and steps aside, and tokio puts such a task at the
/// back of its queue, after every task queued now. `tokio::task::yield_now` differs: it comes
/// back only once the worker runs out of work, which under steady load can be long
async fn yield_one_round() {
    let mut yielded = false;
    std::future::poll_fn(|cx| {
        if yielded {
            return std::task::Poll::Ready(());
        }
        yielded = true;
        cx.waker().wake_by_ref();
        std::task::Poll::Pending
    })
    .await;
}

/// 把 `queue` 里排着的帧写到 `writer`，直到写失败，给出那次失败。`waited(ID, 帧)` 说这一帧的查询还等不等：已经放弃了的
/// （时限到了、竞速输了）不写，上游不用白答，写不出去时排着的帧也不会越积越多地全写给它
/// Writes the frames queued on `queue` to `writer` until a write fails, giving that failure.
/// `waited(ID, frame)` says whether the frame's query still waits: one given up already (its
/// deadline past, a race lost) is not written, so the upstream answers nothing for nobody, and a
/// backlog built up while writes were stuck does not all go to it
///
/// 叫醒以后先让一轮再取（见 [`yield_one_round`]）：tokio 让刚被叫醒的任务插到最前面先跑，不让的话，
/// 第一个查询一叫醒写入任务，它就只写这一帧，一个查询写一次
/// Once woken it yields one round before taking the frames (see [`yield_one_round`]): tokio runs
/// a task it was just woken for first, so without the yield the first query to wake the writer
/// would be written alone, one write per query
async fn write_frames<W>(
    mut writer: W,
    queue: &WriteQueue,
    waited: impl Fn(u16, &Bytes) -> bool,
) -> std::io::Error
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let (mut taken, mut batch) = (Vec::new(), BytesMut::new());
    loop {
        queue.wake.notified().await;
        yield_one_round().await;
        queue.take(&mut taken);
        for (id, frame) in taken.drain(..) {
            if waited(id, &frame) {
                batch.extend_from_slice(&frame);
            }
        }
        if batch.is_empty() {
            continue;
        }
        // TLS 流在 socket 写满时会先收下明文、返回"已写入"，加密后的记录留在缓冲里，要等下一次写或 flush
        // 才发出去；不 flush 的话，流量少时这一批可能一直等到超时。TCP 的 flush 什么也不做
        // When the socket is full a TLS stream accepts the plaintext and reports it written
        // while the encrypted records stay buffered until the next write or flush; without the
        // flush, on a quiet connection the batch could wait out the whole timeout. A TCP flush
        // does nothing
        let written = async {
            writer.write_all(&batch).await?;
            writer.flush().await
        };
        if let Err(err) = written.await {
            return err;
        }
        batch.clear();
    }
}

/// 自己关一条连接时（空闲、复位、用到最长时间、客户端被丢掉），最多等多久把 DoT 的 close_notify（RFC 8446 §6.1）和
/// FIN 写出去：上游不读、发送缓冲满着时写不出去，不能为此一直占着连接
/// When closing a connection of our own accord (idle, reset, at its max age, the client dropped),
/// how long writing out DoT's close_notify (RFC 8446 §6.1) and the FIN may take at most: with the
/// upstream not reading and the send buffer full they cannot go, and the connection is not to be
/// held for it
const CLOSE_BUDGET: Duration = Duration::from_secs(1);

/// 客户端被丢掉（它的上游在重载后不在配置里了）时，让读取和写入任务结束：它们拿着连接的两半，不结束的话
/// 连接会一直开着。
/// When the client is dropped (its upstream left the configuration on a reload), its reader
/// and writer tasks are ended: they hold the two halves of the connection, which would stay
/// open while they run.
impl<T: StreamTransport> Drop for StreamMuxClient<T> {
    fn drop(&mut self) {
        self.wires.stop.cancel();
    }
}

#[cfg(test)]
impl Aging {
    /// 测试里的客户端用的老化：5 分钟、1 分钟，和默认配置一样 / The aging of clients in tests: 5 minutes and
    /// 1 minute, as the default configuration has
    fn for_tests() -> Self {
        Self::new(Duration::from_secs(300), Duration::from_secs(60))
    }
}

#[cfg(test)]
impl TcpMuxClient {
    fn new(upstream: Arc<str>) -> Self {
        Self::with_shared(Bootstrap::system(), upstream, Aging::for_tests())
    }
}

#[cfg(test)]
impl DotMuxClient {
    fn new(upstream: Arc<str>, tls_config: Arc<ClientConfig>) -> Self {
        Self::with_shared(
            (tls_config, Bootstrap::system()),
            upstream,
            Aging::for_tests(),
        )
    }
}

#[cfg(test)]
impl<T: StreamTransport> StreamMuxClient<T> {
    /// 测试里连上上游，不发查询 / In tests, connect to the upstream without sending a query
    async fn connect_for_tests(&self) -> anyhow::Result<()> {
        Connect::get_or_make(
            &self.wires.slot,
            |slot| &mut slot.connect,
            |slot| slot.live.as_ref().map(drop),
            || self.connecting(),
        )
        .await?;
        Ok(())
    }

    /// 测试里看槽里有没有连接 / In tests, whether the slot holds a connection
    fn connected(&self) -> bool {
        self.wires.slot.lock().live.is_some()
    }
}

impl<T: StreamTransport> StreamMuxClient<T> {
    fn with_shared(shared: T::Shared, upstream: Arc<str>, aging: Aging) -> Self {
        Self {
            wires: Wires {
                upstream,
                slot: Arc::default(),
                pending: Arc::new(DashMap::with_hasher(FxBuildHasher)),
                generation: Arc::new(AtomicU64::new(0)),
                stop: CancellationToken::new(),
                aging,
            },
            shared,
            in_flight: AtomicUsize::new(0),
            next_id: AtomicU16::new(1),
        }
    }

    /// 建一条到上游的连接并装上（见 [`Connect`]、[`Self::install`]）/ Connects to the upstream and puts the
    /// connection in place (see [`Connect`] and [`Self::install`])
    fn connecting(&self) -> impl Future<Output = anyhow::Result<()>> + Send + 'static {
        let (shared, wires) = (self.shared.clone(), self.wires.clone());
        async move {
            let (read_half, write_half) = T::connect(&shared, &wires.upstream).await?;
            Self::install(&wires, read_half, write_half);
            Ok(())
        }
    }

    /// 把刚建好的连接装进槽里：新的一代，起它的读取和写入任务。槽里原来的那条（没有时是 None）不会还在：只有槽空着时才建连
    /// Puts a connection just made in the slot: a new generation, with its reader and writer
    /// started. The slot holds no other: a connect is only made while it is empty
    fn install(wires: &Wires, read_half: T::Read, write_half: T::Write) {
        let mut slot = wires.slot.lock();
        let generation = wires.generation.fetch_add(1, Ordering::AcqRel) + 1;
        // 这条连接自己的取消令牌；客户端被丢掉时也跟着取消
        // The connection's own cancellation token, cancelled with the client too
        let cancel = wires.stop.child_token();
        let (queue, answers) = (Arc::new(WriteQueue::default()), Arc::new(AtomicU64::new(0)));
        let wear = Arc::new(Wear::new());
        Self::spawn_reader(
            wires,
            read_half,
            cancel.clone(),
            generation,
            Arc::clone(&answers),
        );
        Self::spawn_writer(
            wires,
            write_half,
            Arc::clone(&queue),
            Arc::clone(&wear),
            cancel.clone(),
            generation,
        );
        slot.live = Some(Live {
            queue,
            generation,
            cancel,
            answers,
            wear,
        });
        info!(upstream = %wires.upstream, "{} connection established", T::NAME);
    }

    fn spawn_reader(
        wires: &Wires,
        mut reader: T::Read,
        cancel_token: CancellationToken,
        my_generation: u64,
        answers: Arc<AtomicU64>,
    ) {
        let wires = wires.clone();
        tokio::spawn(async move {
            let (pending, upstream) = (&wires.pending, &wires.upstream);
            // Pre-allocate a reusable buffer for reads
            // DNS TCP max is 65535 bytes, but typical responses are much smaller
            let mut reusable_buf = BytesMut::with_capacity(4096);
            // 一直读到这一代被取消：复位时马上取消，用旧了摘下的等它的查询都到了期限再取消（见 `spawn_writer`）
            // Reading goes on until this generation is cancelled: at once on a reset, and once its
            // queries have all reached their deadlines when taken out as worn (see `spawn_writer`)
            loop {
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
                            // 拆的是这个读取任务自己的那一代；已经换了代就什么都不动
                            // The generation this reader belongs to is what goes; one already
                            // replaced is left alone
                            let why = format!("{} read len failed", T::LABEL);
                            if Self::close(&wires, my_generation, &why) {
                                debug!(target = T::LOG_TARGET, upstream = %upstream, error = %err, "{} read len failed", T::LABEL);
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
                            let why = format!("{} read body failed", T::LABEL);
                            if Self::close(&wires, my_generation, &why) {
                                debug!(target = T::LOG_TARGET, upstream = %upstream, error = %err, "{} read body failed", T::LABEL);
                            }
                            break;
                        }
                    }
                }

                // 读满一整帧就算这条连接在回答，不管它对不对得上号
                // A whole frame read counts as the connection answering, matched or not
                answers.fetch_add(1, Ordering::Release);
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
                        crate::warn_sparse!(target = T::LOG_TARGET, upstream = %upstream, resp_id, "{} response does not answer the query, dropped", T::NAME);
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
            // 读不下去了，写入任务也跟着结束 / Reading has failed, so the writer ends too
            cancel_token.cancel();
        });
    }

    /// 起这条连接的写入任务（见 [`WriteQueue`]），它也照 [`Aging`] 给这条连接老化。写失败时这条连接就废了：让还在等它的
    /// 查询失败，读取任务也跟着结束。用旧了（活满 `tcp_connection_max_age_seconds`，或者空闲满
    /// `tcp_connection_idle_timeout_seconds`，RFC 7766 §6.2.3）就从槽里摘下，排在池后面、平常轮不到的连接也一样；它上面还在
    /// 等的查询照样等到各自的期限，帧照写、回答照收，过了最晚的那个再关。自己关的连接好好地关：DoT 发 close_notify，再发
    /// FIN（见 [`CLOSE_BUDGET`]）。连接已经换了代就不去动槽里的新连接
    /// Starts the connection's writer (see [`WriteQueue`]), which also ages the connection by
    /// [`Aging`]. A failed write ends the connection: the queries still waiting on it fail and the
    /// reader ends too. Worn (it has lived `tcp_connection_max_age_seconds`, or sat idle for
    /// `tcp_connection_idle_timeout_seconds`, RFC 7766 §6.2.3) it is taken out of the slot, one
    /// far down the pool and normally left alone too; the queries still waiting on it go on to
    /// their own deadlines, their frames written and their answers taken, and it closes once the
    /// latest has passed. A connection closed of our own accord is closed properly: DoT sends
    /// close_notify, then the FIN (see [`CLOSE_BUDGET`]). The new connection in the slot of a
    /// newer generation is left alone
    fn spawn_writer(
        wires: &Wires,
        mut writer: impl tokio::io::AsyncWrite + Unpin + Send + 'static,
        queue: Arc<WriteQueue>,
        wear: Arc<Wear>,
        cancel_token: CancellationToken,
        my_generation: u64,
    ) {
        let wires = wires.clone();
        tokio::spawn(async move {
            let failed = async {
                // 帧的查询还登记着、还在等：同一个 ID 后来的查询的帧是另一份 / The frame's query is still
                // registered and waiting: a later query on the same ID has a frame of its own
                let waited = |id, frame: &Bytes| {
                    wires.pending.get(&id).is_some_and(|pending| {
                        pending.frame.as_ptr() == frame.as_ptr() && !pending.tx.is_closed()
                    })
                };
                let mut writing = std::pin::pin!(write_frames(&mut writer, &queue, waited));
                let why = tokio::select! {
                    () = cancel_token.cancelled() => return None,
                    err = &mut writing => return Some(err),
                    why = wires.aging.worn(&wear) => why,
                };
                if Self::retire(&wires, my_generation) {
                    info!(target = T::LOG_TARGET, upstream = %wires.upstream, why, "{} connection worn, closing it once its queries are done", T::NAME);
                }
                tokio::select! {
                    () = cancel_token.cancelled() => None,
                    err = &mut writing => Some(err),
                    () = wear.settled() => None,
                }
            }
            .await;
            cancel_token.cancel();
            // 写不出去的连接没法好好地关 / A connection that cannot be written to cannot be closed
            // properly
            if let Some(err) = failed {
                let why = format!("{} write failed", T::LABEL);
                if Self::close(&wires, my_generation, &why) {
                    debug!(target = T::LOG_TARGET, upstream = %wires.upstream, error = %err, "{why}");
                }
                return;
            }
            let _ = timeout(CLOSE_BUDGET, writer.shutdown()).await;
        });
    }

    async fn send(&self, packet: &[u8], timeout_dur: Duration) -> anyhow::Result<Bytes> {
        let start = tokio::time::Instant::now();
        if packet.len() < 2 {
            anyhow::bail!("dns packet too short for {}", T::LABEL);
        }

        // 发之前最新的那一代：查询登记的连接没了（见 [`ConnectionGone`]），而它不比这一代新（这次之前就有的连接，
        // 多半是空闲久了被上游关掉的），或者它回答过别的查询（上游答了一些就关掉，RFC 7766 §6.2.1.1 要客户端把没答的
        // 重发），就换一条新的在剩下的预算里重发一次。别的失败不重发：建连失败、退避、超时，再来一次也一样；这次自己
        // 新建、一个也没答就断了的连接，再建一条多半还是断
        // The latest generation before sending: when the connection the query registered on is gone
        // (see [`ConnectionGone`]) and was no newer than that (there before this send, most likely
        // closed by the upstream after sitting idle), or had answered other queries (an upstream
        // answering some and closing, whose unanswered queries RFC 7766 §6.2.1.1 has the client
        // send again), the query is sent once more on a fresh one within what is left of the
        // budget. Other failures are not sent again: a failed connect, backing off and timeouts
        // would only come round again, and a connection this send made breaking before answering
        // anything most likely breaks again
        let before = self.wires.generation.load(Ordering::Acquire);
        match self.send_attempt(packet, timeout_dur).await {
            Err(err)
                if err
                    .downcast_ref::<ConnectionGone>()
                    .is_some_and(|gone| gone.generation <= before || gone.answered) =>
            {
                let Some(remaining) = retry_budget(timeout_dur, start) else {
                    return Err(err);
                };
                debug!(
                    upstream = %self.wires.upstream,
                    error = %err,
                    retry_timeout_ms = remaining.as_millis() as u64,
                    "{} connection gone under a query, sending again on a fresh one",
                    T::NAME
                );
                self.send_attempt(packet, remaining).await
            }
            result => result,
        }
    }

    async fn send_attempt(&self, packet: &[u8], timeout_dur: Duration) -> anyhow::Result<Bytes> {
        let deadline = tokio::time::Instant::now() + timeout_dur;
        // 登记在哪一代连接上：之后要拆连接、要记错误，说的都是这一代；它读到过几个回答
        // The generation of the connection it registered on: a later teardown or a recorded
        // error means this one; and how many answers it has read
        let (mut waiting, generation, answers) = self.register(packet, deadline).await?;
        let answers_at_queue = answers.load(Ordering::Acquire);

        // 等待响应；帧由连接的写入任务发出（见 `WriteQueue`）。登记完就到了时限：连接还没机会回答，不怪它，不复位
        // Wait for the response; the connection's writer sends the frame (see `WriteQueue`). The
        // deadline passed as registration finished: the connection had no chance to answer, so it
        // is not blamed and not reset
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!(
                "{name} timeout before waiting for response from upstream {upstream} (timeout: {timeout_ms}ms)",
                name = T::NAME,
                upstream = self.wires.upstream,
                timeout_ms = timeout_dur.as_millis()
            );
        }

        match tokio::time::timeout_at(deadline, &mut waiting.rx).await {
            Ok(Ok(Ok(response))) => Ok(response),
            // 连接在等待期间断开或被重置，所有等待的查询都被告知了；这不是成功，是否换新连接重发由 send() 决定
            // The connection broke or was reset while this query waited, and every waiter was
            // told. That is no success; send() decides on a retry over a fresh connection
            Ok(Ok(Err(err))) => Err(err),
            // 发送的那一头没给结果就没了（正常不会：拿走条目的都先给结果）/ The sending end went
            // without an outcome (not normally: whatever takes an entry gives its outcome first)
            Ok(Err(_canceled)) => Err(anyhow::anyhow!(
                "{name} response canceled for upstream {upstream}",
                name = T::NAME,
                upstream = self.wires.upstream
            )),
            Err(_elapsed) => {
                // 排进去之后这条连接还在回答别的查询：连接是活的，只是这一个回答慢。重建连接只会让同一条连接上其他查询的
                // 回答跟着丢掉，也不算连接出错
                // The connection kept answering other queries after this one was queued: it is
                // alive and only this answer is slow. Rebuilding it would only lose the other
                // answers on it, and it is no connection error
                if answers.load(Ordering::Acquire) > answers_at_queue {
                    return Err(anyhow::anyhow!(
                        "{name} response timeout from upstream {upstream} (timeout: {timeout_ms}ms); the connection is still answering",
                        name = T::NAME,
                        upstream = self.wires.upstream,
                        timeout_ms = timeout_dur.as_millis()
                    ));
                }
                // 时限内没有回答，连接也没了动静（多半已死或卡住）：复位它
                // No answer in time and the connection has gone quiet (likely dead or stalled):
                // reset it
                self.reset(generation);
                Err(anyhow::anyhow!(
                    "{name} response timeout from upstream {upstream} (timeout: {timeout_ms}ms)",
                    name = T::NAME,
                    upstream = self.wires.upstream,
                    timeout_ms = timeout_dur.as_millis()
                ))
            }
        }
    }

    /// 登记一个查询：在现在的连接上登记（见 [`Self::register_on`]）；没有连接就等一条，最多到 `deadline`（见
    /// [`Connect::get_or_make`]）。一条连接上可以同时跑任意多个查询（多路复用）。等来的连接在登记之前就没了时不再等下一条
    /// Registers a query: on the connection now (see [`Self::register_on`]); with none, one is
    /// waited for until `deadline` at most (see [`Connect::get_or_make`]). One connection carries
    /// any number of queries at once (multiplexing). A connection waited for and gone before the
    /// query could register is not followed by a wait for another
    async fn register(
        &self,
        packet: &[u8],
        deadline: tokio::time::Instant,
    ) -> anyhow::Result<(Waiting<Pending>, u64, Arc<AtomicU64>)> {
        let register = |slot: &mut Slot| {
            let live = slot.live.as_ref()?;
            Some(self.register_on(live, packet, deadline))
        };
        // 平常连接在，只拿一下锁就登记上，不起计时器 / Normally the connection is there, and the query
        // registers in one take of the lock, with no timer set
        if let Some(registered) = register(&mut self.wires.slot.lock()) {
            return registered;
        }
        let waited = Connect::get_or_make(
            &self.wires.slot,
            |slot| &mut slot.connect,
            register,
            || self.connecting(),
        );
        match tokio::time::timeout_at(deadline, waited).await {
            Ok(waited) => match waited? {
                Some((registered, _)) => registered,
                None => Err(ConnectionGone {
                    generation: self.wires.generation.load(Ordering::Acquire),
                    answered: false,
                    why: "connection closed before registration".into(),
                }
                .into()),
            },
            Err(_) => anyhow::bail!(
                "{} timeout waiting for the connection to upstream {}",
                T::LABEL,
                self.wires.upstream
            ),
        }
    }

    /// 在连接 `live` 上登记一个期限在 `deadline` 的查询：记上期限（见 [`Wear`]），重写 DNS 事务 ID、登记进 pending、
    /// 把帧排进写入队列，返回等它回答的那一头（见 [`Waiting`]）、连接是第几代和它的回答数（见 [`Live::answers`]）。拿着槽的
    /// 锁调用
    /// Registers a query with its deadline at `deadline` on the connection `live`: the deadline
    /// noted (see [`Wear`]), the DNS transaction ID rewritten, the query registered in pending and
    /// its frame queued for writing, returning the end that waits for its answer (see
    /// [`Waiting`]), the connection's generation and its answer count (see [`Live::answers`]).
    /// Called with the slot's lock held
    fn register_on(
        &self,
        live: &Live,
        packet: &[u8],
        deadline: tokio::time::Instant,
    ) -> anyhow::Result<(Waiting<Pending>, u64, Arc<AtomicU64>)> {
        let original_id = u16::from_be_bytes([packet[0], packet[1]]);
        // Build complete TCP/DoT wire frame (2-byte length prefix + DNS message). The same
        // buffer stays in the pending entry for the answer's question check, as on UDP.
        // 构建完整 TCP/DoT wire frame（2 字节长度前缀 + DNS 消息）。同一份缓冲还留在 pending 条目里
        // 供应答比对问题，和 UDP 一样。
        let mut frame = BytesMut::with_capacity(2 + packet.len());
        frame.extend_from_slice(&(packet.len() as u16).to_be_bytes());
        frame.extend_from_slice(packet);
        let (queue, generation, pending) = (&live.queue, live.generation, &self.wires.pending);
        live.wear.note(deadline);
        let (tx, rx) = oneshot::channel();

        let mut tries = 0;
        let new_id = loop {
            let cand = self.next_id.fetch_add(1, Ordering::Relaxed);
            tries += 1;

            // Use Entry API to check vacancy and insert atomically
            // 使用 Entry API 检查空位并原子插入
            if let entry::Entry::Vacant(e) = pending.entry(cand) {
                // TXID at offset 2 (after length prefix) / 偏移 2 处（长度前缀之后）
                frame[2..4].copy_from_slice(&cand.to_be_bytes());
                let frame = frame.freeze();
                e.insert(Pending {
                    original_id,
                    generation,
                    frame: frame.clone(),
                    tx,
                });
                queue.push(cand, frame);
                break cand;
            }

            // 头一个 ID 就被占着时看看是不是全被占了：65536 个 ID 都被等着的查询占着时立刻说没有，不在槽的锁下把每个 ID
            // 都试一遍。数一遍要锁每个分片，所以平常拿到空 ID 时不数
            // The first ID taken, see whether all are: with all 65536 held by waiting queries,
            // say so at once rather than try every ID under the slot's lock. Counting locks every
            // shard, so it is skipped while the first ID is free
            if (tries == 1 && pending.len() > u16::MAX as usize) || tries > u16::MAX as usize {
                anyhow::bail!("no available dns ids for {} mux", T::LABEL);
            }
        };
        // 从这一刻起放手时就把条目删掉（超时、取消、提前返回）/ From here on the entry goes when this is
        // let go of (a timeout, a cancellation, an early return)
        let waiting = Waiting {
            rx,
            map: Arc::clone(pending),
            id: new_id,
            abandoned: |pending| pending.tx.is_closed(),
        };
        Ok((waiting, generation, Arc::clone(&live.answers)))
    }

    /// 拆掉第 `generation` 代连接，拿槽的锁（见 [`close_locked`](Self::close_locked)）
    /// Tears down the connection of `generation`, taking the slot's lock (see
    /// [`close_locked`](Self::close_locked))
    fn close(wires: &Wires, generation: u64, why: &str) -> bool {
        Self::close_locked(&wires.pending, &mut wires.slot.lock().live, generation, why)
    }

    /// 槽的锁已经拿在手里，拆掉第 `generation` 代连接：停掉它的读取和写入任务，丢掉写入队列，让等在它上面的
    /// 查询都以 `why` 失败。现在的连接不是这一代（已经换成新的，或者已经拆了）就什么都不做，返回 false。
    ///
    /// 拆连接的决定都是对着某一条连接作的：它空闲太久了、它读写失败了、它上面的查询超时了。作出决定到拿到锁
    /// 之间连接可能已经换过，这个决定不能落到替它的那条上：那会让刚建好的连接白建，登记在它上面的查询失败
    ///
    /// With the slot's lock held, tears down the connection of `generation`: its reader and
    /// writer are stopped, its write queue dropped, and the queries waiting on it fail with
    /// `why`. When the connection now is not of that generation (replaced by a new one, or torn
    /// down already) nothing is done and false comes back.
    ///
    /// Every decision to tear a connection down is made about one connection: it sat idle too
    /// long, its read or write failed, a query on it timed out. Between the decision and the
    /// lock the connection may have been replaced, and the decision must not land on the one in
    /// its place, which would waste a connection just made and fail the queries registered on it
    fn close_locked(
        pending: &PendingMap,
        slot: &mut Option<Live>,
        generation: u64,
        why: &str,
    ) -> bool {
        let closed = slot.take_if(|live| live.generation == generation);
        if let Some(live) = &closed {
            live.cancel.cancel();
        }
        // 不在槽里的那一代是用到最长时间摘下的，老连接，它上面的查询照样重发（见 `send`）/ A generation not in
        // the slot is one taken out at its max age, an old connection whose queries are sent again
        // all the same (see `send`)
        let answered = closed
            .as_ref()
            .is_some_and(|live| live.answers.load(Ordering::Acquire) > 0);
        // 这一代上的查询都告诉一声：它在不在槽里都一样，用到最长时间摘下的那一代自己断了时也是
        // Every query on this generation is told, whether or not it is in the slot: a generation
        // taken out at its max age breaking by itself too
        let keys: Vec<u16> = pending
            .iter()
            .filter(|item| item.generation == generation)
            .map(|item| *item.key())
            .collect();
        for key in keys {
            if let Some((_, p)) = pending.remove_if(&key, |_, p| p.generation == generation) {
                let gone = ConnectionGone {
                    generation,
                    answered,
                    why: why.to_owned(),
                };
                let _ = p.tx.send(Err(gone.into()));
            }
        }
        closed.is_some()
    }

    /// 复位第 `generation` 代连接：取消读取和写入任务，丢掉写入队列，让所有等在它上面的查询马上失败，各自可以换新连接
    /// 重发，而不是干等到期限、再轮流把下一条连接也复位掉。现在的连接已经不是它就什么都不做，返回 false（见 `close_locked`）
    /// Resets the connection of `generation`: its reader and writer are cancelled, its write
    /// queue dropped, and every query waiting on it fails at once, free to retry over a fresh
    /// connection instead of sitting out its deadline and resetting the next connection in turn.
    /// When the connection now is another, nothing is done and false comes back (see
    /// `close_locked`)
    fn reset(&self, generation: u64) -> bool {
        let why = format!("{} connection reset", T::NAME);
        Self::close(&self.wires, generation, &why)
    }

    /// 第 `generation` 代连接用旧了（见 [`Aging`]）：从槽里摘下，接着来的查询去建新连接；它上面还在等的查询照样收它的回答
    /// （见 [`Self::spawn_writer`]）。现在的连接已经不是它就什么都不做，返回 false
    /// The connection of `generation` is worn (see [`Aging`]): it is taken out of the slot, and
    /// queries coming next make a new one; those still waiting on it go on taking its answers (see
    /// [`Self::spawn_writer`]). When the connection now is another, nothing is done and false
    /// comes back
    fn retire(wires: &Wires, generation: u64) -> bool {
        wires
            .slot
            .lock()
            .live
            .take_if(|live| live.generation == generation)
            .is_some()
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
    /// 测试里改走明文 http：引擎把 DoH 上游一律当 https，本机的假 DoH 上游只会说 http
    /// Plain http in tests: the engine takes every DoH upstream as https, and the local fake
    /// DoH upstream speaks http only
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
        let resolver = Resolver(bootstrap);
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
        // 握手时选了 h2 的 https 上游直连（见 `doh_h2`）；明文 http、设了代理时照旧经 reqwest
        // An https upstream that picks h2 in the handshake is connected to directly (see
        // `doh_h2`); plain http, or a proxy set, goes through reqwest as before
        let uri = target
            .uri
            .as_ref()
            .filter(|_| self.direct_h2 && url.scheme() == "https");

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
    /// 才是传输错误，可以重试（见 [`is_transport_error`]）；正文迟迟不来也算在这个时限里
    /// Asks once, within `timeout_dur`: an upstream that picked h2 first waits for its direct
    /// connection, then sends the request on it and reads the answer; any other goes through
    /// reqwest. The wait for the connection counts against this one budget, and running out there
    /// is no connection (see [`DohNotConnected`]): a slow handshake says nothing of a connection
    /// made being broken. Once connected, the request itself timing out is a transport error,
    /// open to a retry (see [`is_transport_error`]); a body slow to come counts against the same
    /// limit
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
                        .sender(url, &self.tls_h2, &self.resolver.0, deadline),
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
    type Shared = (Arc<ClientConfig>, Arc<Bootstrap>);
    const LABEL: &'static str = "dot";
    const NAME: &'static str = "DoT";
    const LOG_TARGET: &'static str = "dot_mux";

    async fn connect(
        (tls_config, bootstrap): &(Arc<ClientConfig>, Arc<Bootstrap>),
        upstream: &str,
    ) -> anyhow::Result<(Self::Read, Self::Write)> {
        let target = parse_dot_target(upstream)?;
        let server_name = build_server_name(&target.sni)?;
        let stream = connect_tcp(bootstrap, &target.connect_addr)
            .await
            .map_err(|e| anyhow::anyhow!("dot connect failed: {e:#}"))?;
        let tls_stream = TlsConnector::from(tls_config.clone())
            .connect(server_name, stream)
            .await
            .context("dot tls handshake failed")?;
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

/// 直连 DoH 上游用的 TLS 设置：`base` 再加上握手时报 h2 和 http/1.1，和 reqwest 一样
/// The TLS settings for a direct DoH connection: `base` with h2 and http/1.1 offered in the
/// handshake, as reqwest offers them
fn direct_tls_config(mut base: ClientConfig) -> Arc<ClientConfig> {
    base.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Arc::new(base)
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

    // UDP 只认 IP 和端口（见 UdpClient::send）；TCP 也认主机名，由 Bootstrap 解析
    // UDP takes an IP and a port only (see UdpClient::send); TCP takes a host name too,
    // which Bootstrap resolves
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

/// 用 `transport` 连一个上游地址（不带前缀）之前要解析的主机名，读法和各个客户端连接时一样；写成 IP 的没有，UDP 只认 IP
/// The host name to resolve before `transport` connects to one upstream address (prefix
/// removed), read the way each client reads it when it connects; none for one written as an IP,
/// and UDP takes IPs only
pub(crate) fn host_name(address: &str, transport: crate::config::Transport) -> Option<String> {
    use crate::config::Transport;

    let host = match transport {
        Transport::Udp | Transport::TcpUdp => return None,
        Transport::Tcp if address.parse::<SocketAddr>().is_ok() => return None,
        Transport::Tcp => address.rsplit_once(':')?.0.to_owned(),
        Transport::Dot => parse_tls_upstream(address, "dot").ok()?.1,
        Transport::Doq => parse_tls_upstream(address, "doq").ok()?.1,
        Transport::Doh => url_host(&build_doh_url(address).ok()?.0)?,
    };
    host.parse::<std::net::IpAddr>().is_err().then_some(host)
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
    /// 连接怎样老化：最长 [`DOQ_MAX_AGE`]，空闲 `doq_connection_idle_timeout_seconds` / How connections
    /// age: [`DOQ_MAX_AGE`] at most, idle for `doq_connection_idle_timeout_seconds`
    aging: Aging,
    /// 上游的主机名怎样解析（见 [`Bootstrap`]）/ How upstream host names are resolved (see [`Bootstrap`])
    bootstrap: Arc<Bootstrap>,
    enable_0rtt: bool,
    /// 0-RTT 的安全提示只在真正用上 0-RTT 时打印一次
    /// Prints the 0-RTT security notice once, and only if 0-RTT is really used
    zero_rtt_notice: std::sync::Once,
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
/// 每一步都包进 `.context()` 的话，`anyhow::Error::to_string()` 只给出最外层那一句，判定 0-RTT 是否被拒绝时看不到 quinn
/// 说了什么。原始错误原样带出来，判定就落在类型上
/// With every step wrapped in `.context()`, `anyhow::Error::to_string()` would render only the
/// outermost one, and the check for a rejected 0-RTT attempt would never see quinn's own words.
/// Carried out untouched, the error lets the decision rest on types
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
    /// 解析好的上游地址，第一个查询时算 / The upstream address parsed, worked out at the first query
    target: std::sync::OnceLock<DoqTarget>,
    /// 池里的连接。读它不加锁，建连的任务建好了把连接放进来 / The pooled connection, read without a
    /// lock; the connecting task puts the connection here once made
    pooled: Arc<ArcSwapOption<DoqConn>>,
    /// 在建的连接、建连失败以后的退避（见 [`Connect`]）；等它算在各个查询自己的预算里 / The
    /// connection being made and the backing off after a failed connect (see [`Connect`]); waiting
    /// for it counts against each query's own budget
    connecting: parking_lot::Mutex<Connect>,
    /// 这个客户端上还没答完的查询数（见 [`least_busy`]）/ Queries on this client not yet answered (see [`least_busy`])
    in_flight: AtomicUsize,
    runtime: Arc<DoqRuntime>,
    /// 客户端被丢掉时取消：它的连接马上关掉（见 [`DoqMuxClient::watch`]）/ Cancelled when the client is
    /// dropped: its connection closes at once (see [`DoqMuxClient::watch`])
    stop: CancellationToken,
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
}

/// 新建的一条 DoQ 连接，和它有没有用 0-RTT / A DoQ connection newly made, and whether it used 0-RTT
struct NewDoqConn {
    conn: QuicConnection,
    used_0rtt: bool,
}

/// 发查询用的连接，和它是怎么来的 / The connection to send on, and how it came
struct DoqConnected {
    pooled: Arc<DoqConn>,
    used_0rtt: bool,
    /// 取自池里，而不是为这次查询新建的 / Taken from the pool rather than made for this query
    reused: bool,
}

/// 池里的一条 QUIC 连接 / One pooled QUIC connection
struct DoqConn {
    conn: QuicConnection,
    /// 建它时用了 0-RTT / Made with 0-RTT
    used_0rtt: bool,
    /// 用它的查询都记上自己的期限，它的看守任务按它老化（见 [`DoqMuxClient::watch`]）/ Every query using it
    /// notes its deadline here, and its watching task ages it by this (see [`DoqMuxClient::watch`])
    wear: Wear,
    /// 在它上面读到过几个回答。查询超时时看这期间涨没涨：涨了说明连接照常在回答，慢的只是这一个，不换连接
    /// Answers read on it. A query timing out looks whether this grew meanwhile: if so the
    /// connection kept answering and only this one is slow, so it is not replaced
    answers: AtomicU64,
}

/// DoQ 连接的传输参数。查询都是我们开的流，一个流问一个（RFC 9250 第 4.2 节），所以：
/// - 上游能开给我们的流是 0。quinn 的 `max_concurrent_bidi/uni_streams` 限的是对端开过来的流，我们从不去接，给了的话
///   上游开过来的流和发来的数据会一直缓冲着；
/// - 每个流的接收窗口正好装下最长的回答（65535 字节加两字节长度前缀），连接的窗口和 DoH 的 HTTP/2 连接一样（见
///   `doh_h2::CONNECTION_WINDOW`）。照 quinn 默认的每个流 1.25 MB、连接不设上限，一个恶意上游能让一条连接缓冲上百 MB；
/// - 不收 QUIC datagram，DoQ 用不着。
///
/// 初始 RTT 定 100 ms，好让拥塞控制一开始估得准一些；`keepalive_interval_ms`、`idle_timeout_secs` 为 0 时不设
/// The transport parameters of a DoQ connection. Every query is a stream we open, one query
/// a stream (RFC 9250 section 4.2), so:
/// - the upstream may open no stream to us. quinn's `max_concurrent_bidi/uni_streams` bound the
///   streams the peer opens, which we never accept, so streams an upstream opened and the data
///   it sent on them would stay buffered;
/// - each stream's receive window holds just the longest answer (65535 bytes and its two-byte
///   length prefix), and the connection's is that of an HTTP/2 DoH connection (see
///   `doh_h2::CONNECTION_WINDOW`). quinn's defaults are 1.25 MB a stream and no bound on the
///   connection, which let a malicious upstream have one connection buffer hundreds of MB;
/// - no QUIC datagram is taken, DoQ has no use for them.
///
/// The initial RTT is 100 ms, for congestion control to start from a better estimate;
/// `keepalive_interval_ms` and `idle_timeout_secs` at 0 leave theirs unset
fn doq_transport(
    keepalive_interval_ms: u64,
    idle_timeout_secs: u64,
) -> anyhow::Result<QuicTransportConfig> {
    let mut transport = QuicTransportConfig::default();
    transport
        .initial_rtt(Duration::from_millis(100))
        .max_concurrent_bidi_streams(0u32.into())
        .max_concurrent_uni_streams(0u32.into())
        .stream_receive_window(quinn::VarInt::from_u32(MAX_DNS_MESSAGE_SIZE as u32 + 2))
        .receive_window(doh_h2::CONNECTION_WINDOW.into())
        .datagram_receive_buffer_size(None);
    if keepalive_interval_ms > 0 {
        transport.keep_alive_interval(Some(Duration::from_millis(keepalive_interval_ms)));
    }
    if idle_timeout_secs > 0 {
        let idle_timeout = Duration::from_secs(idle_timeout_secs)
            .try_into()
            .context("invalid doq idle timeout")?;
        transport.max_idle_timeout(Some(idle_timeout));
    }
    Ok(transport)
}

/// DoQ 连接最长用多久：30 分钟 / How long a DoQ connection may live: 30 minutes
const DOQ_MAX_AGE: Duration = Duration::from_secs(30 * 60);

impl DoqClient {
    /// 只留下 `keep` 认可的上游的连接池（见 [`UpstreamPools::retain`]）/ Keeps only the pools of the
    /// upstreams `keep` accepts (see [`UpstreamPools::retain`])
    pub(crate) fn retain_upstreams(&self, keep: impl Fn(&str) -> bool) {
        self.pools.retain(keep);
    }

    pub fn new(
        pool_size: usize,
        idle_timeout_secs: u64,
        keepalive_interval_ms: u64,
        enable_0rtt: bool,
        bootstrap: Arc<Bootstrap>,
    ) -> anyhow::Result<Self> {
        let mut tls = build_tls_client_config()?;
        tls.alpn_protocols = vec![b"doq".to_vec()];
        tls.enable_early_data = enable_0rtt;

        let quic_crypto = QuicClientConfig::try_from(tls).context("build quic client config")?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));
        client_config.transport_config(Arc::new(doq_transport(
            keepalive_interval_ms,
            idle_timeout_secs,
        )?));

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
            aging: Aging::new(DOQ_MAX_AGE, Duration::from_secs(idle_timeout_secs)),
            bootstrap,
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
        pool.least_busy(|client| client.in_flight.load(Ordering::Relaxed))
            .send(packet, timeout_dur)
            .await
    }
}

/// 客户端被丢掉（它的上游在重载后不在配置里了）时，它的连接马上关掉 / When the client is dropped (its
/// upstream left the configuration on a reload), its connection closes at once
impl Drop for DoqMuxClient {
    fn drop(&mut self) {
        self.stop.cancel();
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
            target: std::sync::OnceLock::new(),
            pooled: Arc::default(),
            connecting: parking_lot::Mutex::default(),
            in_flight: AtomicUsize::new(0),
            runtime,
            stop: CancellationToken::new(),
            zero_rtt_rejected,
        }
    }

    /// 解析好的上游地址 / The upstream address, parsed
    fn target(&self) -> anyhow::Result<&DoqTarget> {
        if let Some(target) = self.target.get() {
            return Ok(target);
        }
        let target = parse_doq_target(&self.upstream)?;
        anyhow::ensure!(
            !target.host.is_empty(),
            "invalid doq upstream: {}",
            self.upstream
        );
        Ok(self.target.get_or_init(|| target))
    }

    pub async fn send(&self, packet: &[u8], timeout_dur: Duration) -> anyhow::Result<Bytes> {
        let target = self.target()?;
        let _in_flight = InFlight::enter(&self.in_flight);
        self.send_with_retry(target, packet, timeout_dur).await
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
            let start = tokio::time::Instant::now();
            // 等别的查询连好、解析上游名字、握手和等回答共用这一份预算
            // Waiting for another query's connect, resolving the upstream name, the handshake and
            // the answer share this one budget
            let DoqConnected {
                pooled,
                used_0rtt,
                reused,
            } = match timeout(timeout_dur, self.get_or_connect(target)).await {
                Ok(connected) => connected?,
                Err(_) => {
                    anyhow::bail!("doq connect timeout after {}ms", timeout_dur.as_millis())
                }
            };
            let query_budget = timeout_dur.saturating_sub(start.elapsed());
            if query_budget.is_zero() {
                anyhow::bail!("doq timeout before sending the query");
            }
            pooled.wear.note(start + timeout_dur);
            let answers_before = pooled.answers.load(Ordering::Acquire);

            match timeout(query_budget, Self::ask(&pooled.conn, packet, original_id)).await {
                Ok(Ok(bytes)) => {
                    pooled.answers.fetch_add(1, Ordering::AcqRel);
                    return Ok(bytes);
                }
                Ok(Err(failure)) => {
                    // 连接没了才换；流被重置、回答不合协议是这一个查询的事，连接照用
                    // Only a connection that is gone is replaced; a stream reset or a malformed
                    // answer is this one query's matter, and the connection stays in use
                    let gone = Self::connection_gone(&failure);
                    if gone {
                        forget(&self.pooled, &pooled);
                    }
                    let retry = if !allow_retry {
                        false
                    } else if Self::early_data_refused(&failure)
                        || (used_0rtt
                            && self.zero_rtt_retry_allowed(target)
                            && Self::zero_rtt_likely_rejected(&failure))
                    {
                        self.disable_zero_rtt();
                        warn!(
                            upstream = %self.upstream,
                            error = %failure,
                            "DoQ 0-RTT likely rejected, retrying without 0-RTT"
                        );
                        true
                    } else if reused && gone {
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
                    if retry && let Some(remaining) = retry_budget(timeout_dur, start) {
                        allow_retry = false;
                        timeout_dur = remaining;
                        continue;
                    }
                    return Err(anyhow::Error::new(failure));
                }
                Err(_) => {
                    // 用了 0-RTT 的连接上超时，算 0-RTT 的嫌疑，往后不再用；普通连接上的超时只是这次回答慢。预算已经
                    // 用完，不再重试
                    // A timeout on a connection that used 0-RTT puts 0-RTT under suspicion, and it
                    // is not used from then on; on a normal connection it is just a slow answer.
                    // The budget is spent, so there is no retry
                    if used_0rtt {
                        self.disable_zero_rtt();
                    }
                    // 这期间连接上没读到过别的回答（多半死了或者卡住了）才换 / Replaced only when no
                    // other answer was read on it meanwhile (it is most likely dead or stalled)
                    if pooled.answers.load(Ordering::Acquire) == answers_before {
                        forget(&self.pooled, &pooled);
                    }
                    return Err(anyhow::anyhow!("doq timeout"));
                }
            }
        }
    }

    /// 在 `conn` 上开一个流问一次（RFC 9250 §4.2）。返回带类型的失败而不是 anyhow：每一步都被 context 包过之后，
    /// anyhow 的 to_string 只剩最外层那一句，quinn 的原始错误到不了判定处
    /// Asks once on a stream of its own on `conn` (RFC 9250 §4.2). It gives a typed failure
    /// rather than anyhow: once every step is wrapped in context, anyhow's to_string leaves only
    /// the outermost sentence and quinn's own error never reaches the decision
    async fn ask(
        conn: &QuicConnection,
        packet: &[u8],
        original_id: u16,
    ) -> Result<Bytes, DoqFailure> {
        let (send, recv) = conn.open_bi().await.map_err(DoqFailure::OpenStream)?;
        let mut stream = DoqStream {
            send,
            recv,
            answered: false,
        };
        let DoqStream {
            send,
            recv,
            answered,
        } = &mut stream;

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
        let mut all_data = recv
            .read_to_end(MAX_DNS_MESSAGE_SIZE + 2)
            .await
            .map_err(DoqFailure::Read)?;
        // 上游已经把流结束了：之后不论应答对不对，都不算放弃 / The upstream has ended the stream: whatever
        // the answer, from here on it is no abandoning
        *answered = true;

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
    }

    /// 池里的连接还能用（没被关掉）就给出来；用旧了的看守任务已经把它从池里拿掉了（见 [`Self::watch`]）
    /// The pooled connection when still usable (not closed); one worn out has been taken out of
    /// the pool by its watching task already (see [`Self::watch`])
    fn usable(&self) -> Option<Arc<DoqConn>> {
        let pooled = self.pooled.load_full()?;
        if let Some(reason) = pooled.conn.close_reason() {
            debug!(upstream = %self.upstream, reason = %reason, "DoQ pooled connection already closed, reconnecting");
            return None;
        }
        Some(pooled)
    }

    /// 发查询用的连接：池里的能用就用，不能用就等一条新的（见 [`Connect::get_or_make`]）：建连的任务建好了放进池里，这个
    /// 查询再取用。等来的连接在取用之前就没了时不再等下一条。等来的连接不算取自池里，用没用 0-RTT 照建它时的
    /// The connection to send on: the pooled one when usable, otherwise a new one waited for (see
    /// [`Connect::get_or_make`]): the connecting task pools it once made, and this query takes it
    /// from there. A connection waited for and gone before it could be taken is not followed by a
    /// wait for another. A connection waited for does not count as taken from the pool, and used
    /// 0-RTT as it was made
    async fn get_or_connect(&self, target: &DoqTarget) -> anyhow::Result<DoqConnected> {
        let connected = |pooled: Arc<DoqConn>, waited: bool| DoqConnected {
            used_0rtt: waited && pooled.used_0rtt,
            reused: !waited,
            pooled,
        };
        if let Some(pooled) = self.usable() {
            return Ok(connected(pooled, false));
        }
        let make = || {
            let (pool, upstream) = (Arc::clone(&self.pooled), Arc::clone(&self.upstream));
            let (aging, stop) = (self.runtime.aging, self.stop.clone());
            let made = Self::connect_new(
                Arc::clone(&self.runtime),
                Arc::clone(&self.upstream),
                target.clone(),
                self.zero_rtt_retry_allowed(target),
            );
            async move {
                let NewDoqConn { conn, used_0rtt } = made.await?;
                let pooled = Arc::new(DoqConn {
                    conn,
                    used_0rtt,
                    wear: Wear::new(),
                    answers: AtomicU64::new(0),
                });
                pool.store(Some(Arc::clone(&pooled)));
                tokio::spawn(Self::watch(pooled, pool, aging, stop, upstream));
                Ok(())
            }
        };
        let (pooled, waited) =
            Connect::get_or_make(&self.connecting, |connect| connect, |_| self.usable(), make)
                .await?
                .context("doq connection closed as soon as it was made")?;
        Ok(connected(pooled, waited))
    }

    /// 看着池里的一条连接直到它走：上游关了它就从池里拿掉；用旧了（见 [`Aging`]）也拿掉，接着来的查询另建一条，它上面的查询
    /// 都过了期限再关；客户端被丢掉时马上关。keepalive 让上游看它一直在用，不由这里关的话，没人用的连接会一直开着
    /// Watches a pooled connection until it goes: closed by the upstream, it is taken out of the
    /// pool; worn (see [`Aging`]), it is taken out too, queries coming next make another, and it
    /// closes once the queries on it are past their deadlines; with the client dropped it closes at
    /// once. Its keepalive has the upstream see it in use all along, so a connection nobody uses
    /// would stay open were it not closed here
    async fn watch(
        pooled: Arc<DoqConn>,
        pool: Arc<ArcSwapOption<DoqConn>>,
        aging: Aging,
        stop: CancellationToken,
        upstream: Arc<str>,
    ) {
        let worn = tokio::select! {
            () = stop.cancelled() => None,
            _ = pooled.conn.closed() => None,
            why = aging.worn(&pooled.wear) => Some(why),
        };
        forget(&pool, &pooled);
        if let Some(why) = worn {
            info!(upstream = %upstream, why, "DoQ connection worn, closing it once its queries are done");
            tokio::select! {
                () = stop.cancelled() => {}
                _ = pooled.conn.closed() => {}
                () = pooled.wear.settled() => {}
            }
        }
        pooled.conn.close(DOQ_NO_ERROR, b"");
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

    /// quinn 明说这个查询发出去的是早期数据、被上游拒收了。只有 0-RTT 期间开的流才会报这个，所以不管这条连接是不是
    /// 这个查询自己建的，它都该换一条不带 0-RTT 的连接再发一次，搭在别的查询建的连接上的也一样
    /// quinn says outright that what this query sent was early data the upstream refused. Only
    /// a stream opened during 0-RTT is told so, and whether or not this query made the
    /// connection it is to be sent again on one without 0-RTT, one riding a connection another
    /// query made included
    fn early_data_refused(failure: &DoqFailure) -> bool {
        matches!(
            failure,
            DoqFailure::Write(quinn::WriteError::ZeroRttRejected)
                | DoqFailure::Read(quinn::ReadToEndError::Read(
                    quinn::ReadError::ZeroRttRejected
                ))
        )
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
    /// 建一条到 `target` 的连接，`zero_rtt` 时先试 0-RTT；连接和用没用 0-RTT。几个地址错开着连（见
    /// [`staggered`]），握手失败了马上连下一个 / Connects to `target`, trying 0-RTT first when
    /// `zero_rtt`; the connection and whether 0-RTT was used. Several addresses are connected to
    /// staggered (see [`staggered`]), a failed handshake moving on to the next at once
    async fn connect_new(
        runtime: Arc<DoqRuntime>,
        upstream: Arc<str>,
        target: DoqTarget,
        zero_rtt: bool,
    ) -> anyhow::Result<NewDoqConn> {
        let mut addresses = runtime
            .bootstrap
            .addresses(&target.host, target.port)
            .await
            .context("doq resolve failed")?;

        // 优先使用 IPv4 地址，避免 IPv6 连接问题
        // Prefer IPv4 addresses to avoid IPv6 connection issues
        // 某些网络的 IPv6 连接不稳定或 MTU 限制导致 QUIC Initial 数据包发送失败
        // Some networks have unstable IPv6 or MTU limits causing QUIC Initial packet send failures
        addresses.sort_by_key(SocketAddr::is_ipv6);
        staggered(addresses, |address| {
            Self::connect_to(&runtime, &upstream, &target, address, zero_rtt)
        })
        .await
    }

    /// 在 `address` 上建一条到 `target` 的连接（见 [`Self::connect_new`]）/ Connects to `target` at
    /// `address` (see [`Self::connect_new`])
    async fn connect_to(
        runtime: &DoqRuntime,
        upstream: &str,
        target: &DoqTarget,
        address: SocketAddr,
        zero_rtt: bool,
    ) -> anyhow::Result<NewDoqConn> {
        let endpoint = if address.is_ipv6() {
            &runtime.endpoint_v6
        } else {
            &runtime.endpoint_v4
        };
        let connecting = endpoint
            .connect(address, target.sni.as_ref())
            .context("doq connect failed")?;

        // 0-RTT：上游设置优先于全局设置，之前被拒绝过就跳过（见 `zero_rtt_retry_allowed`）
        // 0-RTT: the upstream's setting before the global one, skipped once it was
        // rejected (see `zero_rtt_retry_allowed`)
        let connecting = if zero_rtt {
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
            runtime.zero_rtt_notice.call_once(|| {
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
                        upstream = %upstream,
                        "DoQ 0-RTT connection established"
                    );
                    return Ok(NewDoqConn {
                        conn,
                        used_0rtt: true,
                    });
                }
                // 0-RTT not available (no previous session), fall back to normal connect
                // 0-RTT 不可用（无先前会话），回退到正常连接
                Err(connecting) => connecting,
            }
        } else {
            connecting
        };

        let connection = connecting.await.context("doq handshake failed")?;

        Ok(NewDoqConn {
            conn: connection,
            used_0rtt: false,
        })
    }
}

/// 把连接 `pooled` 从放它的地方 `pool`（DoQ 客户端的池、DoH 的连接位）拿掉，下一个要连接的新建一条。那里现在的已经不是它
/// （换成了新的，或者已经拿掉了）就什么都不做：几个查询在同一条连接上一起失败时，先失败的那个已经换了新连接，后面的不能把
/// 新连接也拿掉、让每个查询各建一条。不用锁：别人正在建连时也不用等
/// Takes the connection `pooled` out of `pool`, where it is kept (a DoQ client's pool, a DoH
/// slot), so the next to want a connection makes a new one. When what is kept there now is not
/// it (replaced by a new one, or taken out already) nothing is done: with several queries failing
/// together on one connection, the first has had a new one made, and the rest must not take that
/// out too, each making its own. Lock-free: it never waits for another's connect
pub(super) fn forget<T>(pool: &ArcSwapOption<T>, pooled: &Arc<T>) {
    pool.rcu(|current| {
        current
            .clone()
            .filter(|current| !Arc::ptr_eq(current, pooled))
    });
}

/// RFC 9250 第 4.4 节的 DOQ_NO_ERROR：自己关掉连接、没出什么错 / RFC 9250 section 4.4's DOQ_NO_ERROR:
/// the connection closed of our own accord, nothing wrong
const DOQ_NO_ERROR: quinn::VarInt = quinn::VarInt::from_u32(0x0);

/// RFC 9250 第 4.3 节的 DOQ_REQUEST_CANCELLED：客户端不要这个查询的回答了 / RFC 9250 section
/// 4.3's DOQ_REQUEST_CANCELLED: the client no longer wants this query's answer
const DOQ_REQUEST_CANCELLED: quinn::VarInt = quinn::VarInt::from_u32(0x3);

/// 一个 DoQ 查询的那一对流。没等到上游把回答发完就被丢掉（时限到了、几个上游竞速它输了）时，按 RFC 9250
/// 第 4.3.1 节用 [`DOQ_REQUEST_CANCELLED`] 停止接收、重置发送：交给 quinn 丢掉流的话，发出的错误码是 0，
/// 也就是 DOQ_NO_ERROR，上游会当它正常结束
/// The pair of streams of one DoQ query. Dropped before the upstream has finished sending the
/// answer (a deadline that came first, a race between upstreams lost), it stops receiving and
/// resets sending with [`DOQ_REQUEST_CANCELLED`], as RFC 9250 section 4.3.1 asks: streams left
/// for quinn to drop would carry error code 0, DOQ_NO_ERROR, which the upstream takes for a
/// normal end
struct DoqStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    /// 上游已经把回答发完 / The upstream has finished sending the answer
    answered: bool,
}

impl Drop for DoqStream {
    fn drop(&mut self) {
        if !self.answered {
            let _ = self.send.reset(DOQ_REQUEST_CANCELLED);
            let _ = self.recv.stop(DOQ_REQUEST_CANCELLED);
        }
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
    use tokio::sync::Mutex;

    /// 远在任何测试结束之后的期限 / A deadline far past the end of any test
    fn far_off() -> tokio::time::Instant {
        tokio::time::Instant::now() + Duration::from_secs(3600)
    }

    /// reqwest + rustls 要有进程级的加密实现，明文 http 也一样
    /// reqwest + rustls needs a process-level crypto provider, plain http included
    #[ctor::ctor]
    fn init_crypto() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

    /// 填满 `client` 的连接、让写入卡住，再看一个查询到时限以后怎么收尾：连接上没有动静，复位；写入任务
    /// 结束、放掉写半边，对端（收到 `read_now` 后读到连接关闭为止）读得到头
    /// Fills `client`'s connection so the writer is stuck, then follows a query past its
    /// deadline: the connection has gone quiet, so it is reset; the writer ends and lets go of
    /// the write half, and the peer (reading to the close once told by `read_now`) reaches
    /// the end
    async fn assert_a_stuck_write_ends_at_the_deadline<T: StreamTransport>(
        client: &StreamMuxClient<T>,
        read_now: oneshot::Sender<()>,
        peer: tokio::task::JoinHandle<()>,
    ) {
        client
            .connect_for_tests()
            .await
            .expect("connect to the test peer");
        // 排进比两头的缓冲加起来还多的字节，当作一个还在等的查询的帧，写入停在 await 上
        // Queue more bytes than both ends' buffers hold, as the frame of a query still waiting, so
        // the writer parks on an await
        let blob = Bytes::from(vec![0u8; 32 << 20]);
        let (tx, _waiting) = oneshot::channel();
        let queue = {
            let slot = client.wires.slot.lock();
            let live = slot.live.as_ref().expect("connected");
            client.wires.pending.insert(
                0,
                Pending {
                    original_id: 0,
                    generation: live.generation,
                    frame: blob.clone(),
                    tx,
                },
            );
            Arc::clone(&live.queue)
        };
        queue.push(0, blob);
        let err = client
            .send(&udp_test_query("stuck.example"), Duration::from_millis(500))
            .await
            .expect_err("nothing answers");
        assert!(err.to_string().contains("response timeout"), "{err:#}");
        assert!(!client.connected(), "the quiet connection is reset");
        read_now.send(()).expect("the peer waits");
        tokio::time::timeout(Duration::from_secs(10), peer)
            .await
            .expect("the writer lets go of the write half, so the peer reads to the close")
            .expect("join the peer");
    }

    /// 读到连接关闭为止 / Reads until the connection closes
    async fn read_to_close(mut stream: impl tokio::io::AsyncRead + Unpin) {
        let mut sink = vec![0u8; 1 << 16];
        while matches!(stream.read(&mut sink).await, Ok(n) if n > 0) {}
    }

    /// 写不出去的连接（对端一个字节也不读）不会一直占着：查询等到时限、连接上又没有动静时复位，写入任务
    /// 跟着结束。查询不再自己写（见 `WriteQueue`），以前写到一半被取消时会把半条帧留在连接上
    /// A connection that cannot be written to (the peer reads not a byte) is not held on to:
    /// a query waiting out its deadline on a quiet connection resets it and the writer ends.
    /// Queries no longer write themselves (see `WriteQueue`); one cancelled part way through
    /// its write used to leave half a frame on the connection
    #[tokio::test]
    async fn a_stuck_write_ends_at_the_deadline() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (read_now, told) = oneshot::channel();
        let peer = tokio::spawn(async move {
            let (held, _) = listener.accept().await.unwrap();
            let _ = told.await;
            read_to_close(held).await;
        });
        let client = TcpMuxClient::new(Arc::from(addr.to_string().as_str()));
        assert_a_stuck_write_ends_at_the_deadline(&client, read_now, peer).await;
    }

    /// 对端关掉自己往这边写的那一头以后，读取任务读到头、腾出连接，写入任务也跟着结束、放掉写半边，对端
    /// 读得到连接关闭；不然写入任务会一直拿着这条半开的连接
    /// Once the peer closes its sending side, the reader reaches the end and clears the
    /// connection, and the writer ends too and lets go of the write half, so the peer reads to
    /// the close; otherwise the writer would hold on to the half-open connection for good
    #[tokio::test]
    async fn a_closed_peer_ends_the_writer_too() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.shutdown().await.unwrap();
            read_to_close(stream).await;
        });
        let client = TcpMuxClient::new(Arc::from(addr.to_string().as_str()));
        client
            .connect_for_tests()
            .await
            .expect("connect to the test peer");
        tokio::time::timeout(Duration::from_secs(5), peer)
            .await
            .expect("the writer lets go of the write half, so the peer reads to the close")
            .expect("join the peer");
        assert!(!client.connected(), "the connection is cleared");
    }

    /// 同一轮里排进来的帧一次写出去。一个工作线程，排帧的任务都从这个线程上起，和收到一批查询时一样；不先让
    /// 一轮的话，第一个任务一叫醒写入任务，它就只写这一帧
    /// The frames queued in one round go out in one write. One worker thread, with the tasks
    /// queuing them started on it, as when a batch of queries arrives; without yielding a round
    /// first, the first task to wake the writer would have it write that frame alone
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn a_round_of_frames_goes_out_in_one_write() {
        let queue = Arc::new(WriteQueue::default());
        let (client_io, mut server_io) = tokio::io::duplex(1 << 16);
        let writes = Arc::new(AtomicUsize::new(0));
        let writer = crate::engine::test_support::CountedWrites {
            io: client_io,
            writes: Arc::clone(&writes),
        };
        let draining = Arc::clone(&queue);
        tokio::spawn(async move { write_frames(writer, &draining, |_, _| true).await });
        // 先写一帧，写入任务写完转回去等着 / One frame first, after which the writer is back to waiting
        queue.push(9, Bytes::from_static(&[0, 1, 9]));
        server_io.read_exact(&mut [0u8; 3]).await.unwrap();
        let before = writes.load(Ordering::SeqCst);
        // 排完帧的任务接着等，和查询排完帧等回答一样 / The tasks keep waiting once their frames are
        // queued, as queries wait for their answers
        let queuing = Arc::clone(&queue);
        let waiting = tokio::spawn(async move {
            (0..8u8)
                .map(|index| {
                    let queue = Arc::clone(&queuing);
                    tokio::spawn(async move {
                        queue.push(u16::from(index), Bytes::copy_from_slice(&[0, 1, index]));
                        std::future::pending::<()>().await
                    })
                })
                .collect::<Vec<_>>()
        })
        .await
        .unwrap();
        let mut written = [0u8; 24];
        server_io.read_exact(&mut written).await.unwrap();
        waiting.iter().for_each(tokio::task::JoinHandle::abort);
        assert_eq!(writes.load(Ordering::SeqCst) - before, 1);
        assert!(
            (0..8u8).all(|index| written.chunks(3).any(|frame| frame == [0, 1, index])),
            "every frame is written whole: {written:?}"
        );
    }

    /// 帧还没写出去，它的查询就放弃了（时限先到、竞速输了）：这一帧不写，上游不用白答；还在等的照写
    /// A query giving up (its deadline first, a race lost) before its frame is written has the
    /// frame left unwritten, so the upstream answers nothing for nobody; the frames still waited
    /// for are written as ever
    #[tokio::test]
    async fn a_frame_whose_query_gave_up_is_not_written() {
        let client = TcpMuxClient::new(Arc::from("127.0.0.1:9"));
        let queue = Arc::new(WriteQueue::default());
        client.wires.slot.lock().live = Some(planted(Arc::clone(&queue)));
        let (ours, mut theirs) = tokio::io::duplex(1 << 16);
        TcpMuxClient::spawn_writer(
            &client.wires,
            ours,
            queue,
            Arc::new(Wear::new()),
            CancellationToken::new(),
            1,
        );
        // 两个查询在写入任务醒来之前登记好，第一个随即放弃 / Both queries register before the writer
        // wakes, and the first gives up at once
        let given_up = client
            .register(&udp_test_query("given-up.example"), far_off())
            .await
            .expect("registered");
        drop(given_up);
        let _waiting = client
            .register(&udp_test_query("waited.example"), far_off())
            .await
            .expect("registered");
        let written = read_frame(&mut theirs).await.expect("a frame written");
        assert_eq!(first_label(&written), "waited");
        assert!(
            timeout(Duration::from_millis(100), read_frame(&mut theirs))
                .await
                .is_err(),
            "nothing more is written"
        );
    }

    /// 让一轮就是一轮：工作线程一直有活时，写入任务也只排在眼下这些任务后面。`tokio::task::yield_now`
    /// 要等手上的活干完、或者隔上几十个任务才回来，持续有负载时每一批都会晚出去
    /// One round is one round: on a worker that always has work, the writer still waits only
    /// behind the tasks queued now. `tokio::task::yield_now` comes back only once the work runs
    /// out, or after some dozens of tasks, so under steady load every batch would leave late
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn the_writer_waits_one_round_on_a_busy_worker() {
        /// 不真写，只记下写的时候忙任务转到了第几圈 / Writes nothing, noting how many turns the busy task had made when written to
        struct NotingWrites {
            turns: Arc<AtomicUsize>,
            written_at: Arc<AtomicUsize>,
        }
        impl tokio::io::AsyncWrite for NotingWrites {
            fn poll_write(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
                buf: &[u8],
            ) -> std::task::Poll<std::io::Result<usize>> {
                self.written_at
                    .store(self.turns.load(Ordering::SeqCst), Ordering::SeqCst);
                std::task::Poll::Ready(Ok(buf.len()))
            }
            fn poll_flush(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Ready(Ok(()))
            }
            fn poll_shutdown(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Ready(Ok(()))
            }
        }

        let turns = Arc::new(AtomicUsize::new(0));
        let written_at = Arc::new(AtomicUsize::new(usize::MAX));
        let queue = Arc::new(WriteQueue::default());
        let writer = NotingWrites {
            turns: Arc::clone(&turns),
            written_at: Arc::clone(&written_at),
        };
        let draining = Arc::clone(&queue);
        let writing =
            tokio::spawn(async move { write_frames(writer, &draining, |_, _| true).await });
        // 一直有活的任务：每圈记一次数，让一轮再来 / A task that always has work: it counts each turn and yields a round
        let counting = Arc::clone(&turns);
        let busy = tokio::spawn(async move {
            loop {
                counting.fetch_add(1, Ordering::SeqCst);
                yield_one_round().await;
            }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        for _ in 0..5 {
            let (queuing, counted) = (Arc::clone(&queue), Arc::clone(&turns));
            let pushed_at = tokio::spawn(async move {
                let at = counted.load(Ordering::SeqCst);
                queuing.push(2, Bytes::from_static(&[0, 1, 2]));
                at
            })
            .await
            .unwrap();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            while written_at.load(Ordering::SeqCst) == usize::MAX {
                assert!(tokio::time::Instant::now() < deadline, "never written");
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            let waited = written_at.swap(usize::MAX, Ordering::SeqCst) - pushed_at;
            assert!(waited < 8, "written {waited} turns of the busy task late");
        }
        busy.abort();
        writing.abort();
    }

    /// 写失败时这条连接就废了：还在等它的查询马上失败，不用等到超时；连接腾出来，下一个查询重新连
    /// A failed write ends the connection: the queries still waiting on it fail at once rather
    /// than at their timeout, and the slot is cleared for the next query to connect again
    #[tokio::test]
    async fn a_failed_write_fails_the_waiting_queries() {
        struct Broken;
        impl tokio::io::AsyncWrite for Broken {
            fn poll_write(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
                _: &[u8],
            ) -> std::task::Poll<std::io::Result<usize>> {
                std::task::Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
            }
            fn poll_flush(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Ready(Ok(()))
            }
            fn poll_shutdown(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Ready(Ok(()))
            }
        }

        let client = TcpMuxClient::new(Arc::from("127.0.0.1:9"));
        let queue = Arc::new(WriteQueue::default());
        client.wires.slot.lock().live = Some(planted(Arc::clone(&queue)));
        let token = CancellationToken::new();
        // 写入任务属于摆进去的那条连接（第 1 代）/ The writer belongs to the planted connection
        // (generation 1)
        TcpMuxClient::spawn_writer(
            &client.wires,
            Broken,
            queue,
            Arc::new(Wear::new()),
            token.clone(),
            1,
        );
        let (mut waiting, _, _) = client
            .register(&udp_test_query("broken.example"), far_off())
            .await
            .expect("register while connected");
        let answer = tokio::time::timeout(Duration::from_secs(2), &mut waiting.rx)
            .await
            .expect("told at once, not at a timeout")
            .expect("the sender is used, not dropped");
        assert!(
            answer
                .expect_err("the write failed")
                .to_string()
                .contains("write failed")
        );
        assert!(!client.connected(), "the slot is cleared");
        assert!(token.is_cancelled(), "the reader ends too");
    }

    /// 帧排进去以后查询被取消（外层超时先到、多上游竞速输了被 abort），帧照样整条写出去，迟到的回答对不上号
    /// 丢掉，连接还是对齐的：下一个查询在同一条连接上照样答对
    /// A query cancelled once its frame is queued (the outer timeout first, or the loser of a
    /// multi-upstream race aborted) still has its frame written whole; the late answer matches
    /// nothing and is dropped, the connection stays in step, and the next query is answered
    /// right on the same connection
    #[tokio::test]
    async fn a_query_cancelled_after_queuing_leaves_the_connection_in_step() {
        let addr = spawn_stream_upstream(None).await;
        let client = Arc::new(TcpMuxClient::new(Arc::from(addr.to_string())));
        let asking = Arc::clone(&client);
        let task = tokio::spawn(async move {
            asking
                .send(&udp_test_query("cancelled.example"), Duration::from_secs(5))
                .await
        });
        while client.wires.pending.is_empty() {
            tokio::task::yield_now().await;
        }
        task.abort();
        let _ = task.await;
        let generation = client.wires.generation.load(Ordering::Acquire);
        let answer = client
            .send(&udp_test_query("next.example"), Duration::from_secs(5))
            .await
            .expect("answered");
        assert_eq!(first_label(&answer), "next");
        assert_eq!(
            client.wires.generation.load(Ordering::Acquire),
            generation,
            "on the same connection"
        );
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

    /// 一个 socket 发满 [`UDP_SOCKET_QUERIES`] 个查询就换成另一个端口上的新 socket。以前池里的端口用到进程结束
    /// A socket that has sent [`UDP_SOCKET_QUERIES`] queries is replaced by a new one on another
    /// port. The pool's ports used to last the process
    #[tokio::test]
    async fn a_udp_socket_moves_to_another_port_after_its_queries() {
        let (upstream, seen) = spawn_udp_upstream(|query| vec![echo_answer(query)]).await;
        let client = UdpClient::new(1).expect("create UDP client");
        let per_socket = UDP_SOCKET_QUERIES as usize;
        for _ in 0..2 * per_socket + 1 {
            client
                .send(
                    &udp_test_query("turn.example."),
                    &upstream,
                    Duration::from_secs(2),
                )
                .await
                .expect("query answered");
        }
        let ports: Vec<u16> = seen.lock().unwrap().iter().map(|(_, port)| *port).collect();
        let rounds: Vec<&[u16]> = ports.chunks(per_socket).collect();
        for round in &rounds {
            assert!(round.iter().all(|port| *port == round[0]), "{round:?}");
        }
        assert_ne!(rounds[0][0], rounds[1][0]);
        assert_ne!(rounds[1][0], rounds[2][0]);
    }

    /// 换 socket 只换数满的那一个：取了旧 socket 的查询在它换下来以后又把它数满一轮，池里刚换上的新 socket 留着。以前不看
    /// 位置上现在是哪个，照换
    /// A replacement replaces only the socket counted up: a query that took the old socket counting
    /// it up to another round after it was replaced leaves the new one in the pool. Whatever the
    /// place held used to be replaced
    #[tokio::test]
    async fn a_socket_replaced_already_is_not_replaced_again() {
        let client = UdpClient::new(1).expect("create UDP client");
        let old = client.pool[0].load_full();
        old.sent.store(UDP_SOCKET_QUERIES - 1, Ordering::Relaxed);
        UdpClient::note_sent(&client.pool[0], 0, &old, false);
        let new = client.pool[0].load_full();
        assert!(!Arc::ptr_eq(&new, &old), "used up, it is replaced");
        old.sent
            .store(2 * UDP_SOCKET_QUERIES - 1, Ordering::Relaxed);
        UdpClient::note_sent(&client.pool[0], 0, &old, false);
        assert!(
            Arc::ptr_eq(&client.pool[0].load_full(), &new),
            "the new one stays"
        );
    }

    /// 换下来的 socket 还收它在途查询的回答：查询发出去以后它的 socket 被换掉，回答照样到得了；这个查询放手以后旧 socket 关掉
    /// A replaced socket still takes the replies to its queries in flight: a query whose socket
    /// is replaced after it was sent still gets its reply; once that query lets go the old socket
    /// closes
    #[tokio::test]
    async fn a_query_in_flight_is_answered_after_its_socket_is_replaced() {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream = socket.local_addr().unwrap().to_string();
        let per_socket = UDP_SOCKET_QUERIES as usize;
        // 第一个查询的回答压着，等后面的查询把它的 socket 换掉以后再发 / The first query's reply is held
        // back until the queries after it have had its socket replaced
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let mut held = None;
            for seen in 1..=per_socket + 1 {
                let (n, src) = socket.recv_from(&mut buf).await.unwrap();
                let reply = echo_answer(&buf[..n]);
                if seen == 1 {
                    held = Some((reply, src));
                    continue;
                }
                socket.send_to(&reply, src).await.unwrap();
                if seen == per_socket + 1
                    && let Some((reply, src)) = held.take()
                {
                    socket.send_to(&reply, src).await.unwrap();
                }
            }
        });
        let client = UdpClient::new(1).expect("create UDP client");
        let query = udp_test_query("held.example.");
        let mut first = UdpExchange::new(&client, &query, &upstream);
        first.send(()).await.expect("sent");
        for _ in 0..per_socket {
            client
                .send(&query, &upstream, Duration::from_secs(2))
                .await
                .expect("query answered");
        }
        let replaced = client.pool[0].load().socket.local_addr().unwrap();
        let old_socket = Arc::downgrade(&first.sent[0].0._socket.socket);
        assert_ne!(
            old_socket.upgrade().unwrap().local_addr().unwrap(),
            replaced
        );
        let (reply, ()) = timeout(Duration::from_secs(2), first.reply())
            .await
            .expect("answered in time")
            .expect("waited for");
        assert_eq!(
            &reply.expect("answered")[..2],
            &query[..2],
            "original ID restored"
        );

        // 最后一个查询拿到了结果、放了手，接收任务停下，socket 关掉 / Once its last query has its
        // outcome and lets go, the receiving task stops and the socket closes
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            old_socket.upgrade().is_none(),
            "the replaced socket is closed"
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

    #[tokio::test]
    async fn a_dot_handshake_outlives_the_query_that_started_it() {
        // 发起建连的查询在 TLS 握手做完前被取消了（竞速时别的上游先答完），握手照样做完，下一个查询直接用上，不另建
        // The query that started the connect is cancelled before the TLS handshake is through
        // (another upstream answering first in a race); the handshake goes on all the same and
        // the next query uses it, making no other
        let (server, client_tls) = localhost_tls(&[]);
        let upstream = spawn_stream_upstream(Some(server)).await;
        let (addr, accepted) =
            crate::engine::test_support::slow_front(upstream, Duration::from_millis(300)).await;
        let client = DotMuxClient::new(
            Arc::from(format!("dot://{addr}?sni=localhost")),
            Arc::new(client_tls),
        );
        let raced = timeout(
            Duration::from_millis(100),
            client.send(&udp_test_query("first.example"), Duration::from_secs(2)),
        )
        .await;
        assert!(raced.is_err(), "cancelled while the handshake goes on");
        tokio::time::sleep(Duration::from_millis(400)).await;
        client
            .send(
                &udp_test_query("second.example"),
                Duration::from_millis(100),
            )
            .await
            .expect("the connection made meanwhile answers at once");
        assert_eq!(accepted.load(Ordering::SeqCst), 1, "one connection made");
    }

    /// DoT 的前置：第一条连接压 300 ms 再接到 `upstream`，接通 `first_for` 以后关掉（None 是不接通、直接关掉）；之后的
    /// 连接马上接通、一直通着。返回地址和接下了几条连接
    /// A DoT front: the first connection is held 300 ms before it is put through to `upstream`
    /// and closed after `first_for` through (None: closed without being put through); later ones
    /// are put through at once and stay so. Its address, and how many connections it accepted
    async fn front_closing_the_first(
        upstream: SocketAddr,
        first_for: Option<Duration>,
    ) -> (SocketAddr, Arc<AtomicUsize>) {
        let front = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the front");
        let addr = front.local_addr().expect("read the front address");
        let accepted = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&accepted);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = front.accept().await {
                let first = counted.fetch_add(1, Ordering::SeqCst) == 0;
                tokio::spawn(async move {
                    if first {
                        tokio::time::sleep(Duration::from_millis(300)).await;
                    }
                    let through = if first {
                        first_for
                    } else {
                        Some(Duration::MAX)
                    };
                    let Some(through) = through else { return };
                    let mut upstream = tokio::net::TcpStream::connect(upstream)
                        .await
                        .expect("reach the upstream");
                    let _ = timeout(
                        through,
                        tokio::io::copy_bidirectional(&mut stream, &mut upstream),
                    )
                    .await;
                });
            }
        });
        (addr, accepted)
    }

    /// 发起建连的查询在握手做完前被取消了，连接照样建完、装上，从一开始就有人读它：上游随后把它关了，这边跟着关掉，不会
    /// 停在 CLOSE_WAIT 里等下一个查询来取
    /// The query that started the connect is cancelled before the handshake is through; the
    /// connection is made and put in place all the same, read from the start: when the upstream
    /// then closes it, this end closes too rather than sitting in CLOSE_WAIT until another query
    /// comes to take it
    #[tokio::test]
    async fn a_connection_made_for_a_cancelled_query_closes_with_the_upstream() {
        let (server, client_tls) = localhost_tls(&[]);
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (closed_tx, closed_rx) = oneshot::channel();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_millis(300)).await;
            let mut tls = acceptor.accept(tcp).await.unwrap();
            tls.shutdown().await.unwrap();
            read_to_close(tls).await;
            let _ = closed_tx.send(());
        });
        let client = DotMuxClient::new(
            Arc::from(format!("dot://{addr}?sni=localhost")),
            Arc::new(client_tls),
        );
        let raced = timeout(
            Duration::from_millis(100),
            client.send(&udp_test_query("first.example"), Duration::from_secs(2)),
        )
        .await;
        assert!(raced.is_err(), "cancelled while the handshake goes on");
        timeout(Duration::from_secs(2), closed_rx)
            .await
            .expect("this end closes once the upstream has")
            .expect("the upstream noted it");
        assert!(!client.connected(), "the slot is cleared");
    }

    #[tokio::test]
    async fn a_connection_left_waiting_and_closed_meanwhile_is_made_again() {
        // 发起建连的查询被取消了，连接照样建完、装上，上游这期间把它关了：读取任务看到就拆掉它，下一个查询重建一条再答
        // The query that started the connect is cancelled, the connection is made and put in
        // place all the same, and the upstream closes it meanwhile: its reader sees that and
        // tears it down, and the next query makes another and is answered
        let (server, client_tls) = localhost_tls(&[]);
        let upstream = spawn_stream_upstream(Some(server)).await;
        let (addr, accepted) =
            front_closing_the_first(upstream, Some(Duration::from_millis(150))).await;
        let client = DotMuxClient::new(
            Arc::from(format!("dot://{addr}?sni=localhost")),
            Arc::new(client_tls),
        );
        let raced = timeout(
            Duration::from_millis(100),
            client.send(&udp_test_query("first.example"), Duration::from_secs(2)),
        )
        .await;
        assert!(raced.is_err(), "cancelled while the handshake goes on");
        tokio::time::sleep(Duration::from_millis(800)).await;
        client
            .send(&udp_test_query("second.example"), Duration::from_secs(2))
            .await
            .expect("answered on a connection made again");
        assert_eq!(accepted.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_failure_left_waiting_past_its_backoff_does_not_fail_the_next_query() {
        // 发起建连的查询被取消了，建连随后失败；下一个查询来时，从这次失败算起的退避早已过去：重新建连再答
        // The query that started the connect is cancelled and the connect then fails; by the time
        // the next query comes the backing off counted from that failure is long over, so a
        // connect is made again before answering
        let (server, client_tls) = localhost_tls(&[]);
        let upstream = spawn_stream_upstream(Some(server)).await;
        let (addr, accepted) = front_closing_the_first(upstream, None).await;
        let client = DotMuxClient::new(
            Arc::from(format!("dot://{addr}?sni=localhost")),
            Arc::new(client_tls),
        );
        let raced = timeout(
            Duration::from_millis(100),
            client.send(&udp_test_query("first.example"), Duration::from_secs(2)),
        )
        .await;
        assert!(raced.is_err(), "cancelled while the handshake goes on");
        tokio::time::sleep(Duration::from_millis(800)).await;
        client
            .send(&udp_test_query("second.example"), Duration::from_secs(2))
            .await
            .expect("answered after connecting again");
        assert_eq!(accepted.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_failed_connect_backs_off_before_the_next() {
        // 建连失败以后退避：这期间的查询马上失败、不再去连；过了退避再连。以前上游不通时每个查询都去连一次
        // After a failed connect it backs off: the queries meanwhile fail at once without
        // connecting; past the backing off it connects again. Every query used to connect
        // with the upstream unreachable
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the refusing listener");
        let addr = listener
            .local_addr()
            .expect("read the refusing listener address");
        let accepted = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&accepted);
        tokio::spawn(async move {
            // 接下就关，TLS 握手失败 / Accepted and closed at once, failing the TLS handshake
            while listener.accept().await.is_ok() {
                counted.fetch_add(1, Ordering::Relaxed);
            }
        });
        let client = DotMuxClient::new(
            Arc::from(format!("dot://{addr}?sni=localhost")),
            Arc::new(build_tls_client_config().expect("tls config")),
        );
        let query = udp_test_query("refused.example");
        assert!(client.send(&query, Duration::from_secs(1)).await.is_err());
        let backing_off = client
            .send(&query, Duration::from_secs(1))
            .await
            .expect_err("still backing off");
        assert!(
            backing_off.to_string().contains("failed lately"),
            "{backing_off:#}"
        );
        assert_eq!(
            accepted.load(Ordering::Relaxed),
            1,
            "no connect while backing off"
        );
        tokio::time::sleep(CONNECT_BACKOFF + Duration::from_millis(50)).await;
        assert!(client.send(&query, Duration::from_secs(1)).await.is_err());
        assert_eq!(
            accepted.load(Ordering::Relaxed),
            2,
            "connects again past it"
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

    /// TCP 上游：每条连接上的前 `answers` 个查询回显作答，再来一个就关掉这条连接；返回地址和接下了几条连接
    /// A TCP upstream answering the first `answers` queries on each connection with an echo and
    /// closing the connection on the next; its address, and how many connections it accepted
    async fn closing_tcp_upstream(answers: usize) -> (SocketAddr, Arc<AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind closing upstream");
        let addr = listener
            .local_addr()
            .expect("read closing upstream address");
        let accepted = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&accepted);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                counted.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    for answered in 0.. {
                        let mut len = [0u8; 2];
                        if stream.read_exact(&mut len).await.is_err() {
                            return;
                        }
                        let mut frame = vec![0u8; u16::from_be_bytes(len) as usize];
                        if stream.read_exact(&mut frame).await.is_err() || answered == answers {
                            return;
                        }
                        frame[2] |= 0x80;
                        let _ = stream.write_all(&len).await;
                        let _ = stream.write_all(&frame).await;
                    }
                });
            }
        });
        (addr, accepted)
    }

    #[tokio::test]
    async fn a_query_on_a_connection_the_upstream_closed_is_sent_again() {
        // 连接在这次发送之前就有，上游在查询到达时把它关了（空闲久了的连接常这样）：换一条新连接重发，拿到回答
        // The connection was there before this send and the upstream closed it as the query
        // arrived (as idle connections often go): it is sent again on a fresh one and answered
        let (addr, accepted) = closing_tcp_upstream(1).await;
        let client = TcpMuxClient::new(Arc::from(addr.to_string()));
        let query = udp_test_query("again.example");
        client
            .send(&query, Duration::from_secs(1))
            .await
            .expect("answered on the first connection");
        client
            .send(&query, Duration::from_secs(1))
            .await
            .expect("sent again on a fresh connection and answered");
        assert_eq!(accepted.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_send_whose_own_connection_breaks_is_not_sent_again() {
        // 这次发送自己建的连接一收到查询就断了：不重发，再建一条多半还是断
        // The connection this send made itself breaks on receiving the query: it is not sent
        // again, as another would most likely break as well
        let (addr, accepted) = closing_tcp_upstream(0).await;
        let client = TcpMuxClient::new(Arc::from(addr.to_string()));
        let query = udp_test_query("broken.example");
        let sent = client.send(&query, Duration::from_secs(1)).await;
        assert!(sent.is_err(), "the upstream never answers");
        assert_eq!(accepted.load(Ordering::SeqCst), 1, "connected once");
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

    /// 0-RTT 的安全提示曾在构造 DoQ 客户端时打印，而客户端在任何配置下都会构造，
    /// 于是没有任何 DoQ 上游的部署每次启动也会看到它。
    /// The 0-RTT security notice used to be printed when the DoQ client was
    /// built, and the client is built for every configuration, so deployments
    /// without a single DoQ upstream saw it at every start.
    #[tokio::test]
    async fn doq_client_holds_the_0rtt_notice_until_early_data_is_offered() {
        let client =
            DoqClient::new(1, 60, 15_000, true, Bootstrap::system()).expect("build DoQ client");
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
        let client = DohClient::new(8, 0, Bootstrap::system()).expect("build doh client");
        let upstream = "doh://8.8.8.8";
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
        let client = DohClient::new(8, 3, Bootstrap::system()).expect("build doh client");
        for idx in 0..4 {
            client
                .upstream(&format!("https://{idx}.example/dns-query"))
                .expect("create upstream");
        }
        let live = "https://live.example/dns-query";
        client.upstream(live).expect("create live upstream");
        let now = age_out_idle_upstreams(&client, live);

        client
            .upstream_at("https://new.example/dns-query", now)
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
        let client = DohClient::new(8, 3, Bootstrap::system()).expect("build doh client");
        for idx in 0..4 {
            client
                .upstream(&format!("https://{idx}.example/dns-query"))
                .expect("create upstream");
        }
        let live = "https://live.example/dns-query";
        client.upstream(live).expect("create live upstream");
        let now = age_out_idle_upstreams(&client, live);

        // 只重复查询已有上游，不插入任何新键
        // Only look the existing upstream up again; no new key is inserted
        client
            .upstream_at(live, now)
            .expect("look up live upstream");

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
        let client = DohClient::new(8, 3, Bootstrap::system()).expect("build doh client");
        let live = "https://live.example/dns-query";
        client.upstream(live).expect("create upstream");

        // 窗口过期，但条目都是刚用过的 / interval lapsed, every entry just used
        let lapsed = client.millis_since_epoch() + DOH_UPSTREAM_PRUNE_EVERY.as_millis() as u64 * 2;
        client.upstream_at(live, lapsed).expect("look up upstream");

        assert_eq!(
            client.last_prune_millis.load(Ordering::Relaxed),
            lapsed,
            "a lapsed interval must be claimed even when nothing is dropped"
        );
        assert!(
            client.upstreams.contains_key(live),
            "an upstream in use must never be pruned"
        );
    }

    /// 往后看一段：除 `live` 之外的条目都长期未使用，节流窗口也过期了，给出那时的 `now`（见 `DohClient::upstream_at`）
    /// A look ahead: every entry but `live` has long gone unused and the prune interval has lapsed,
    /// giving the `now` of then (see `DohClient::upstream_at`)
    fn age_out_idle_upstreams(client: &DohClient, live: &str) -> u64 {
        let now = client.millis_since_epoch() + DOH_UPSTREAM_IDLE.as_millis() as u64 * 2;
        client
            .upstreams
            .get(live)
            .expect("the live upstream")
            .last_used_millis
            .store(now, Ordering::Relaxed);
        now
    }

    /// 同一代开始的请求一起断掉、一起报错，只重建一次；旧连接上迟到的错误不算，新的一代从头数。以前每数到阈值就重建
    /// 一次，一百个一起报错要重建三十三次
    /// Requests started under one generation, broken together and erring together, rebuild
    /// once; errors arriving late from the old connections do not count, and the new generation
    /// counts from scratch. Every count up to the threshold used to rebuild, thirty-three
    /// rebuilds for a hundred erring together
    #[test]
    fn requests_broken_together_rebuild_once() {
        let client = DohClient::new(8, 3, Bootstrap::system()).expect("build doh client");
        let upstream = "doh://8.8.8.8";
        let state = client.upstream(upstream).unwrap();
        let started = state.generation.load(Ordering::Acquire);
        let before = state.client.load_full();
        let rebuilds = (0..100)
            .filter(|_| client.record_error(upstream, &state, started))
            .count();
        assert_eq!(rebuilds, 1);
        assert!(!Arc::ptr_eq(&before, &state.client.load_full()));
        assert!(!client.record_error_of(upstream));
        assert!(!client.record_error_of(upstream));
        assert!(
            client.record_error_of(upstream),
            "the third error of the new generation"
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
        let client = DohClient::new(8, 3, Bootstrap::system()).expect("build doh client");
        let upstream = "doh://8.8.8.8";

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
        let client = DohClient::new(8, 3, Bootstrap::system()).expect("build doh client");
        let healthy = "doh://1.1.1.1";
        let failing = "doh://bad.example";
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
        let client = DohClient::new(8, 3, Bootstrap::system()).expect("build doh client");
        let upstream = "doh://1.1.1.1";

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
        let client = DohClient::new(8, 3, Bootstrap::system()).expect("build doh client");

        client.record_error_of("doh://8.8.8.8");
        client.record_error_of("doh://8.8.8.8");
        // A success on a *different* upstream must not touch 8.8.8.8's count.
        client.record_success("doh://1.1.1.1");
        // 8.8.8.8 still at 2 — the 3rd error rebuilds.
        assert!(
            client.record_error_of("doh://8.8.8.8"),
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

        // 没连上也不是：没有建好的连接可换 / Nor is no connection: there is none made to replace
        let not_connected = anyhow::anyhow!("doh tls handshake failed").context(DohNotConnected);
        assert!(
            !is_transport_error(&not_connected),
            "no connection is NOT transport-level"
        );
    }

    /// 没连上 DoH 上游（这里是 TLS 握手时连接就被关掉），直连和经 reqwest 都一样：不重发，也不算进重建连接池的门槛，没有
    /// 建好的连接可换。以前都算，门槛是 1 时每个请求都要重建一次连接池，经 reqwest 的还要再连一次
    /// No connection to the DoH upstream (here closed during the TLS handshake), directly or
    /// through reqwest alike: it is not sent again and does not count toward rebuilding the pool,
    /// there being no connection made to replace. Both used to count, so with a threshold of 1
    /// every request rebuilt the pool, and through reqwest connected once more
    #[tokio::test]
    async fn a_failed_doh_connect_is_neither_sent_again_nor_counted() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = format!("https://{}/dns-query", listener.local_addr().unwrap());
        let accepted = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&accepted);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                counted.fetch_add(1, Ordering::Relaxed);
                drop(stream);
            }
        });
        for direct in [true, false] {
            let mut client = DohClient::new(8, 1, Bootstrap::system()).expect("build doh client");
            if !direct {
                client.reqwest_only_for_tests();
            }
            let before = accepted.load(Ordering::Relaxed);
            client
                .send(&doh_test_query("closed"), &upstream, Duration::from_secs(2))
                .await
                .expect_err("no connection");
            assert_eq!(
                accepted.load(Ordering::Relaxed) - before,
                1,
                "connected once (direct = {direct})"
            );
            let state = client.upstreams.get(upstream.as_str()).expect("state");
            assert_eq!(
                state.generation.load(Ordering::Acquire),
                0,
                "the pool is not rebuilt (direct = {direct})"
            );
        }
    }

    /// 经 reqwest 的 DoH 连接和别的 TCP 连接一样保活（见 [`KEEPALIVE_TIME`]）：连上以后到这个进程里找出那条连接的
    /// socket，读它的保活设置
    /// A DoH connection through reqwest keeps alive as every other TCP connection does (see
    /// [`KEEPALIVE_TIME`]): once it is made, its socket is found in this process and its keepalive
    /// read
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn a_reqwest_connection_keeps_alive_as_the_others_do() {
        let (addr, _) = spawn_doh_upstream(|_, query| {
            DohReply::Raw(http_ok(Some(DOH_MEDIA_TYPE), &echo_answer(query)))
        })
        .await;
        let mut client = DohClient::new(8, 3, Bootstrap::system()).expect("build doh client");
        client.reqwest_only_for_tests();
        let upstream = format!("http://{addr}/dns-query");
        client
            .send(&doh_test_query("kept"), &upstream, Duration::from_secs(2))
            .await
            .expect("the upstream answers");
        assert_eq!(
            tcp_keepalive_towards(addr),
            Some((KEEPALIVE_TIME, KEEPALIVE_INTERVAL))
        );
    }

    /// 这个进程里连到 `peer` 的那条 TCP 连接的保活：多久没有收发开始探、隔多久探一次 / The keepalive of
    /// this process's TCP connection to `peer`: how long without traffic before probing, and how far
    /// apart the probes are
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn tcp_keepalive_towards(peer: SocketAddr) -> Option<(Duration, Duration)> {
        use std::os::fd::{AsRawFd, BorrowedFd};
        #[cfg(target_os = "macos")]
        const IDLE: libc::c_int = libc::TCP_KEEPALIVE;
        #[cfg(target_os = "linux")]
        const IDLE: libc::c_int = libc::TCP_KEEPIDLE;
        let seconds = |fd: &BorrowedFd<'_>, option| {
            let (mut value, mut len) = (
                0 as libc::c_int,
                size_of::<libc::c_int>() as libc::socklen_t,
            );
            // SAFETY: 只读一个整数选项，写进这里的 `value`；`fd` 不是 socket 时调用失败 / Reads an
            // integer option into `value` here alone; on an `fd` that is no socket the call fails
            let read = unsafe {
                libc::getsockopt(
                    fd.as_raw_fd(),
                    libc::IPPROTO_TCP,
                    option,
                    (&raw mut value).cast(),
                    &raw mut len,
                )
            };
            (read == 0).then(|| Duration::from_secs(value as u64))
        };
        (0..4096).find_map(|raw| {
            // SAFETY: 只在下面几次调用里借用；没打开的描述符让它们失败 / Borrowed for the calls below
            // only; a descriptor not open makes them fail
            let fd = unsafe { BorrowedFd::borrow_raw(raw) };
            let to = SockRef::from(&fd).peer_addr().ok()?.as_socket()?;
            (to == peer).then(|| Some((seconds(&fd, IDLE)?, seconds(&fd, libc::TCP_KEEPINTVL)?)))?
        })
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
        client.wires.slot.lock().live = Some(planted(Arc::new(WriteQueue::default())));
        for id in 1u16..200u16 {
            client.wires.pending.insert(
                id,
                Pending {
                    original_id: id,
                    generation: 1,
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
                    client.register(&dummy, far_off()).await
                }
            })
            .collect::<Vec<_>>();

        let results = timeout(Duration::from_millis(500), join_all(tasks))
            .await
            .expect("register_pending stalled under contention");

        // Assert: Verify all IDs are unique (no duplicates under contention)
        let mut ids = rustc_hash::FxHashSet::default();
        for r in results {
            let (waiting, _, _) = r.expect("register_pending failed");
            assert!(
                ids.insert(waiting.id),
                "duplicate id allocated under contention"
            );
        }
    }

    /// 回答到了，读取任务把条目拿走，这个 ID 随后分给了后来的查询；先前那个查询这时才放手，不能把后来的条目带走。
    /// 以前放手时按 ID 无条件删：后来的查询的回答到了却找不到条目，只能等到超时
    /// An answer arrives and the reader takes the entry, the ID then goes to a later query, and
    /// only now does the earlier query let go: it must not take the later one's entry with it.
    /// Letting go used to remove by ID whatever was there, so the later query's answer found no
    /// entry and the query waited out its timeout
    #[test]
    fn letting_go_of_an_id_leaves_a_later_query_on_it_alone() {
        let map: Arc<DashMap<u16, Pending, FxBuildHasher>> =
            Arc::new(DashMap::with_hasher(FxBuildHasher));
        let entry = |tx| Pending {
            original_id: 1,
            generation: 1,
            frame: Bytes::new(),
            tx,
        };
        let waiting = |rx| Waiting {
            rx,
            map: Arc::clone(&map),
            id: 7,
            abandoned: |pending: &Pending| pending.tx.is_closed(),
        };
        let (earlier_tx, earlier_rx) = oneshot::channel();
        map.insert(7, entry(earlier_tx));
        let earlier = waiting(earlier_rx);
        // 回答到了：读取任务拿走条目，交出回答 / The answer arrives: the reader takes the entry
        // and hands the answer over
        let (_, taken) = map.remove(&7).expect("the earlier query's entry");
        taken.tx.send(Ok(Bytes::new())).expect("still waited for");
        // 同一个 ID 分给了后来的查询 / The same ID goes to a later query
        let (later_tx, later_rx) = oneshot::channel();
        map.insert(7, entry(later_tx));
        let later = waiting(later_rx);

        drop(earlier);
        assert!(map.contains_key(&7), "the later query's entry stays");
        // 后来的查询自己放手（超时、取消）时，它的条目跟着走 / When the later query lets go itself
        // (a timeout, a cancellation) its entry goes with it
        drop(later);
        assert!(map.is_empty(), "its own entry goes");
    }

    /// 登记和拆除都在槽的锁下做完：拆之前登记上的查询，拆的时候都被告知，条目也不留下
    /// Registration and teardown are each done under the slot's lock: a query registered before
    /// the teardown is told of it, and leaves no entry behind
    #[tokio::test]
    async fn a_teardown_tells_the_queries_registered_before_it() {
        let client = TcpMuxClient::new(Arc::from("127.0.0.1:9"));
        client.wires.slot.lock().live = Some(planted(Arc::new(WriteQueue::default())));
        let (mut waiting, _, _) = client
            .register(&[0u8; 4], far_off())
            .await
            .expect("registered on the planted connection");
        assert!(TcpMuxClient::close(&client.wires, 1, "reader failed"));
        assert!(client.wires.pending.is_empty());
        let result = timeout(Duration::from_millis(100), &mut waiting.rx)
            .await
            .expect("the waiter is told at once")
            .expect("the sender is used, not dropped");
        assert!(result.is_err(), "the teardown reaches the waiter");
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

    /// 接收报 ConnectionReset（Windows 上 ICMP 端口不可达）时马上接着收，不记 warn 以上的日志：每个没人收的查询都有一个，记
    /// 下来就是每个查询一条。别的错误记 warn（`warn_sparse`，单元测试里每条都记），歇 100 ms
    /// ConnectionReset from a receive (an ICMP port unreachable on Windows) reads on at once and
    /// logs nothing at warn or above: every query reaching nobody brings one, which logged would be
    /// a line a query. Any other error logs a warn (`warn_sparse`, every one logged in unit tests)
    /// and pauses 100 ms
    #[test]
    fn a_connection_reset_on_receive_reads_on_at_once_and_quietly() {
        use std::io::{Error, ErrorKind};
        let (warnings, _capturing) = crate::engine::test_support::Warnings::capture();
        for _ in 0..3 {
            assert_eq!(
                after_recv_error(0, &Error::from(ErrorKind::ConnectionReset)),
                None
            );
        }
        assert_eq!(warnings.lines(), Vec::<String>::new());
        for kind in [
            ErrorKind::Other,
            ErrorKind::ConnectionRefused,
            ErrorKind::OutOfMemory,
        ] {
            assert_eq!(
                after_recv_error(0, &Error::from(kind)),
                Some(Duration::from_millis(100)),
                "{kind:?}"
            );
        }
        let lines = warnings.lines();
        assert_eq!(lines.len(), 3, "{lines:?}");
        assert!(lines.iter().all(|line| line.contains("WARN")), "{lines:?}");
    }

    /// 预热建的连接池和发送时现建的一样大，每个客户端各有自己的连接位
    /// A warmed-up pool is as large as one built on first send, each client with a
    /// connection slot of its own
    #[test]
    fn a_warmed_up_pool_has_every_client() {
        let mux = TcpMultiplexer::new(3, 0, 0, Bootstrap::system());
        mux.warm_up_pools(&["127.0.0.1:53".to_string()].into_iter().collect());
        let pool = mux
            .pools
            .get("127.0.0.1:53")
            .expect("the upstream is warmed up")
            .clone();
        assert_eq!(pool.clients.len(), 3);
        assert!(!Arc::ptr_eq(
            &pool.clients[0].wires.slot,
            &pool.clients[1].wires.slot
        ));
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
        let mux = TcpMultiplexer::new(2, 0, 0, Bootstrap::system());
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
        assert!(
            client
                .pool
                .iter()
                .all(|socket| socket.load().inflight.is_empty())
        );

        let tcp_client = TcpMuxClient::new(Arc::from(tcp_addr.as_str()));
        let result = tcp_client
            .send(&udp_test_query("a.example"), Duration::from_millis(100))
            .await;
        assert!(result.is_err(), "the upstream never answers");
        assert!(tcp_client.wires.pending.is_empty());
    }

    /// 连接池大小写成 0 时按 1 算：TCP（DoT 用同一套）和 DoQ 的池里都有一个客户端
    /// A pool size of 0 counts as 1: TCP pools (DoT shares their code) and DoQ pools both
    /// get one client
    #[tokio::test]
    async fn a_pool_size_of_zero_gives_one_client() {
        let tcp = TcpMultiplexer::new(0, 0, 0, Bootstrap::system());
        assert_eq!(
            tcp.get_or_init_pool_for_test("192.0.2.1:53").clients.len(),
            1
        );

        let doq =
            DoqClient::new(0, 60, 15_000, false, Bootstrap::system()).expect("build DoQ client");
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

        client.pooled.store(None);
        let resumed = client.get_or_connect(&target).await.expect("connect");
        assert!(resumed.used_0rtt, "a resumed connection offers early data");

        client.pooled.store(None);
        client.disable_zero_rtt();
        let after = client.get_or_connect(&target).await.expect("connect");
        assert!(!after.used_0rtt, "no early data once 0-RTT was rejected");
    }

    /// 上游拒绝了 0-RTT 时，不光建这条连接的查询换一条不带 0-RTT 的连接再发一次，同时搭在这条连接上的查询也
    /// 一样。以前只有建连接的那个查询重发，搭车的查询直接失败
    /// When an upstream rejects 0-RTT, the query that made the connection is sent again on one
    /// without 0-RTT, and so are the queries riding that connection at the time. Only the query
    /// that made the connection used to be sent again, and those riding it failed
    #[tokio::test]
    async fn queries_riding_a_connection_whose_0rtt_is_rejected_are_sent_again() {
        let (mut accepting, mut client_tls) = localhost_tls(&[b"doq"]);
        accepting.max_early_data_size = u32::MAX;
        client_tls.enable_early_data = true;
        // 同一张证书的另一台上游：不认别人发的票据，早期数据也不收
        // Another upstream with the same certificate: it knows no ticket another gave, and
        // takes no early data
        let mut rejecting = accepting.clone();
        rejecting.max_early_data_size = 0;
        rejecting.session_storage = rustls::server::ServerSessionMemoryCache::new(32);
        let answer: fn(usize, &str) -> DoqReply = |_, _| DoqReply::Answer(Duration::ZERO);
        let first = spawn_doq_upstream(accepting, Duration::ZERO, answer).await;
        let second = spawn_doq_upstream(rejecting, Duration::ZERO, answer).await;

        // 先从第一台拿到允许早期数据的票据（票据按服务器名存，两台同名）
        // A ticket allowing early data comes from the first (tickets are kept by server name,
        // which the two share)
        let ticket = doq_test_client(
            format!("doq://{first}?sni=localhost"),
            client_tls.clone(),
            true,
        );
        ticket
            .send(&udp_test_query("first.example"), Duration::from_secs(2))
            .await
            .expect("the first upstream answers");
        tokio::time::sleep(Duration::from_millis(100)).await;

        let client = doq_test_client(format!("doq://{second}?sni=localhost"), client_tls, true);
        let (a, b) = (udp_test_query("a.example"), udp_test_query("b.example"));
        let (made_it, rode_it) = tokio::join!(
            client.send(&a, Duration::from_secs(2)),
            client.send(&b, Duration::from_secs(2)),
        );
        made_it.expect("the query that made the connection is sent again");
        rode_it.expect("so is the one riding it");
        assert!(
            client.zero_rtt_rejected.load(Ordering::Relaxed),
            "0-RTT is off for this upstream from then on"
        );
        // 两个查询的重发都在池里这一条连接上答完：没有各建一条 / Both resends were answered on
        // the one pooled connection: they did not make one each
        let pooled = client.pooled.load_full().expect("a pooled connection");
        assert_eq!(pooled.answers.load(Ordering::Acquire), 2);
    }

    /// 连接活满最长时间、或者最晚的期限过后空闲满时限就用旧了，看哪个先到；中途来的查询把空闲往后推，用旧的时刻按单调时钟
    /// 算；都不限时一直不会用旧
    /// A connection is worn once it has lived its max age, or sat idle its limit past the latest
    /// deadline, whichever comes first; a query coming meanwhile puts idleness later, and the
    /// moment counts on the monotonic clock; with neither limited it never wears out
    #[tokio::test(start_paused = true)]
    async fn a_connection_wears_out_by_age_or_idleness_whichever_comes_first() {
        let second = Duration::from_secs(1);
        let started = tokio::time::Instant::now();
        let (wear, aging) = (Wear::new(), Aging::new(1800 * second, 60 * second));
        wear.note(started + 2 * second);
        let (why, ()) = tokio::join!(aging.worn(&wear), async {
            tokio::time::sleep(30 * second).await;
            wear.note(tokio::time::Instant::now() + 2 * second);
        });
        assert_eq!((why, started.elapsed()), ("idle", 92 * second));

        let (started, wear) = (tokio::time::Instant::now(), Wear::new());
        let why = Aging::new(10 * second, 60 * second).worn(&wear).await;
        assert_eq!((why, started.elapsed()), ("too old", 10 * second));

        let never = Aging::new(Duration::ZERO, Duration::ZERO);
        assert!(timeout(3600 * second, never.worn(&wear)).await.is_err());
    }

    /// 配置写了极大的时限（比如 u64::MAX 秒，想表示永不）：那个时限不限，另一个照样起作用。时钟表示不了那么远，
    /// 照直加上去会 panic，每条 TCP、DoT 连接的写入任务一起来就死掉
    /// A huge limit configured (u64::MAX seconds, say, meant as never) is no limit, while the
    /// other still applies. The clock cannot hold a moment that far off, and adding it as it is
    /// would panic, killing every TCP and DoT connection's writer as it starts
    #[tokio::test(start_paused = true)]
    async fn a_limit_too_far_off_for_the_clock_is_no_limit() {
        let (second, huge) = (Duration::from_secs(1), Duration::from_secs(u64::MAX));
        let (started, wear) = (tokio::time::Instant::now(), Wear::new());
        let why = Aging::new(huge, 60 * second).worn(&wear).await;
        assert_eq!((why, started.elapsed()), ("idle", 60 * second));

        let (started, wear) = (tokio::time::Instant::now(), Wear::new());
        let why = Aging::new(10 * second, huge).worn(&wear).await;
        assert_eq!((why, started.elapsed()), ("too old", 10 * second));

        let never = Aging::new(huge, huge);
        assert!(timeout(3600 * second, never.worn(&wear)).await.is_err());
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
            let client = DohClient::new(8, 0, Bootstrap::system()).expect("build doh client");
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
        let client = DohClient::new(8, 0, Bootstrap::system()).expect("build doh client");

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
        let client = DohClient::new(8, 0, Bootstrap::system()).expect("build doh client");
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
        let client = DohClient::new(8, 0, Bootstrap::system()).expect("build doh client");
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
        let client = DohClient::new(8, 0, Bootstrap::system()).expect("build doh client");
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
        let client = DohClient::new(8, 1, Bootstrap::system()).expect("build doh client");
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
        let client = DohClient::new(8, 0, Bootstrap::system()).expect("build doh client");
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
        let client = DohClient::new(8, 0, Bootstrap::system()).expect("build doh client");
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
        /// 读完查询，隔这么久关掉整条连接，不回答 / Read the query and close the connection after this
        /// long, unanswered
        Close(Duration),
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
                                DoqReply::Close(delay) => {
                                    tokio::time::sleep(delay).await;
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
        doq_test_runtime_through(client_tls, enable_0rtt, Bootstrap::system())
    }

    /// 同 [`doq_test_runtime`]，主机名交给 `bootstrap` 解析 / As [`doq_test_runtime`], host names
    /// resolved by `bootstrap`
    fn doq_test_runtime_through(
        client_tls: ClientConfig,
        enable_0rtt: bool,
        bootstrap: Arc<Bootstrap>,
    ) -> Arc<DoqRuntime> {
        doq_runtime_aging(
            client_tls,
            enable_0rtt,
            bootstrap,
            0,
            Aging::new(DOQ_MAX_AGE, Duration::from_secs(60)),
        )
    }

    /// 同 [`doq_test_runtime_through`]，QUIC 每 `keepalive_ms` 毫秒保活一次（0 不保活），连接照 `aging` 老化 / As
    /// [`doq_test_runtime_through`], QUIC keeping alive every `keepalive_ms` (0 for never) and
    /// connections aging by `aging`
    fn doq_runtime_aging(
        client_tls: ClientConfig,
        enable_0rtt: bool,
        bootstrap: Arc<Bootstrap>,
        keepalive_ms: u64,
        aging: Aging,
    ) -> Arc<DoqRuntime> {
        let crypto = QuicClientConfig::try_from(client_tls).expect("quic client crypto");
        let mut config = quinn::ClientConfig::new(Arc::new(crypto));
        config.transport_config(Arc::new(doq_transport(keepalive_ms, 0).expect("transport")));
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
            aging,
            bootstrap,
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

    /// 上游开不出流给我们：查询都是我们开的流，上游开过来的流不会有人接，以前各能开 100 个，开过来的流和上面的数据
    /// 就一直缓冲着。它照样回答我们开的流
    /// An upstream can open no stream to us: every query is a stream we open, and nobody would
    /// accept one it opened; it used to be allowed 100 of each, those streams and their data
    /// staying buffered. It still answers the streams we open
    #[tokio::test]
    async fn a_doq_upstream_cannot_open_streams_to_us() {
        let (server, client_tls) = localhost_tls(&[b"doq"]);
        let crypto =
            quinn::crypto::rustls::QuicServerConfig::try_from(server).expect("quic server crypto");
        let endpoint = QuicEndpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(crypto)),
            "127.0.0.1:0".parse().unwrap(),
        )
        .expect("bind the DoQ test upstream");
        let addr = endpoint.local_addr().unwrap();
        let opened = tokio::spawn(async move {
            let conn = endpoint
                .accept()
                .await
                .expect("incoming")
                .await
                .expect("connected");
            let (mut send, mut recv) = conn.accept_bi().await.expect("the query's stream");
            let mut frame = recv.read_to_end(MAX_DNS_MESSAGE_SIZE + 2).await.unwrap();
            let wait = Duration::from_millis(300);
            let uni = tokio::time::timeout(wait, conn.open_uni()).await.is_ok();
            let bi = tokio::time::timeout(wait, conn.open_bi()).await.is_ok();
            frame[4] |= 0x80;
            send.write_all(&frame).await.unwrap();
            send.finish().unwrap();
            let _ = send.stopped().await;
            (uni, bi)
        });
        let client = doq_test_client(format!("doq://{addr}?sni=localhost"), client_tls, false);
        client
            .send(&udp_test_query("streams.example"), Duration::from_secs(3))
            .await
            .expect("the stream we opened is answered");
        assert_eq!(opened.await.unwrap(), (false, false), "(uni, bi) opened");
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

    /// 放弃一个查询时（竞速时别的上游先答了），上游收到的停止接收带着 DOQ_REQUEST_CANCELLED（RFC 9250 第 4.3.1 节）。
    /// 以前是 0，也就是 DOQ_NO_ERROR。时限用完、连接上也没读到过别的回答时，整条连接换掉，用不着这个码
    /// Abandoning a query (another upstream answering first in a race), the upstream is told to
    /// stop sending with DOQ_REQUEST_CANCELLED (RFC 9250 section 4.3.1). It used to be 0,
    /// DOQ_NO_ERROR. A deadline running out with no other answer read on the connection has the
    /// whole connection replaced, where the code does not come into it
    #[tokio::test]
    async fn an_abandoned_doq_query_is_cancelled_with_request_cancelled() {
        let (server, client_tls) = localhost_tls(&[b"doq"]);
        let crypto =
            quinn::crypto::rustls::QuicServerConfig::try_from(server).expect("quic server crypto");
        let endpoint = QuicEndpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(crypto)),
            "127.0.0.1:0".parse().unwrap(),
        )
        .expect("bind the DoQ test server");
        let addr = endpoint.local_addr().expect("read the DoQ test address");
        let (told, stopped) = oneshot::channel();
        tokio::spawn(async move {
            let conn = endpoint
                .accept()
                .await
                .expect("a connection")
                .await
                .expect("handshake");
            let (send, mut recv) = conn.accept_bi().await.expect("a query stream");
            recv.read_to_end(MAX_DNS_MESSAGE_SIZE + 2)
                .await
                .expect("the query");
            let _ = told.send(send.stopped().await);
            // 连接要留到读完错误码 / The connection stays until the error code is read
            let _ = (endpoint, conn);
        });
        let client = doq_test_client(format!("doq://{addr}?sni=localhost"), client_tls, false);
        // 外层先放弃（竞速时别的上游先答了），连接还在用 / Given up from outside (another upstream
        // answering first in a race), with the connection still in use
        let raced = timeout(
            Duration::from_millis(100),
            client.send(&udp_test_query("abandoned.example"), Duration::from_secs(2)),
        )
        .await;
        assert!(raced.is_err(), "the server never answers");
        let code = timeout(Duration::from_secs(2), stopped)
            .await
            .expect("the server is told")
            .expect("the server reports");
        assert_eq!(
            code.as_ref().ok(),
            Some(&Some(DOQ_REQUEST_CANCELLED)),
            "{code:?}"
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
                DoqReply::Close(Duration::ZERO)
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

    /// 池里的连接在查询途中断了，剩下的预算却不到 [`MIN_RETRY_BUDGET`]：不换连接重发，和别的传输一样。以前还剩 1 毫秒
    /// 也重发
    /// A pooled connection dying under a query with less than [`MIN_RETRY_BUDGET`] of its budget
    /// left: the query is not sent again on a fresh one, as on the other transports. It used to
    /// be sent again with a millisecond left
    #[tokio::test]
    async fn doq_does_not_retry_without_the_budget_for_it() {
        /// 上游收到了几次 `second` / How many times the upstream received `second`
        static SECOND: AtomicUsize = AtomicUsize::new(0);
        let (server, client_tls) = localhost_tls(&[b"doq"]);
        // 预算 400 毫秒，连接在 355 毫秒时断：剩下的一定不到 MIN_RETRY_BUDGET，换一条新连接重发却来得及
        // A budget of 400 ms and the connection gone at 355 ms: what is left is always short of
        // MIN_RETRY_BUDGET, yet enough to send again on a fresh connection
        let addr = spawn_doq_upstream(server, Duration::ZERO, |n, label| {
            if label != "second" {
                return DoqReply::Answer(Duration::ZERO);
            }
            if SECOND.fetch_add(1, Ordering::Relaxed) == 0 && n > 0 {
                DoqReply::Close(Duration::from_millis(355))
            } else {
                DoqReply::Answer(Duration::ZERO)
            }
        })
        .await;
        let client = doq_test_client(format!("doq://{addr}?sni=localhost"), client_tls, false);
        client
            .send(&udp_test_query("first.example"), Duration::from_secs(2))
            .await
            .expect("a fresh connection answers");

        let second = client
            .send(
                &udp_test_query("second.example"),
                Duration::from_millis(400),
            )
            .await;
        assert!(second.is_err(), "not sent again: {second:?}");
        assert_eq!(SECOND.load(Ordering::Relaxed), 1, "sent once");
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

    /// 连接没了、或者超时而这期间连接上没读到别的回答，才换连接；回答的不是这个问题是这一个查询的事，超时而连接照常
    /// 在回答别的查询是这一个回答慢，连接都照用。以前每次失败都换，接着的查询又要重新握手
    /// The connection is replaced only once it is gone, or a query timed out with no other answer
    /// read on it meanwhile; an answer to another question is this one query's matter, and a
    /// timeout while the connection kept answering others is this one answer being slow, the
    /// connection staying in use either way. Every failure used to replace it, the next query
    /// shaking hands again
    #[tokio::test]
    async fn a_doq_connection_is_replaced_only_when_it_failed() {
        for (failing, budget, alongside, replaced) in [
            ("wrong", Duration::from_secs(2), false, false),
            ("slow", Duration::from_millis(300), false, true),
            ("slow", Duration::from_millis(300), true, false),
        ] {
            let (server, client_tls) = localhost_tls(&[b"doq"]);
            let addr = spawn_doq_upstream(server, Duration::ZERO, |_, label| match label {
                "wrong" => DoqReply::AnotherQuestion,
                "slow" => DoqReply::Silence,
                "late" => DoqReply::Answer(Duration::from_millis(100)),
                _ => DoqReply::Answer(Duration::ZERO),
            })
            .await;
            let client = doq_test_client(format!("doq://{addr}?sni=localhost"), client_tls, false);
            client
                .send(&udp_test_query("warm.example"), Duration::from_secs(2))
                .await
                .expect("a fresh connection answers");
            let before = client.pooled.load_full().expect("a pooled connection");
            let query = udp_test_query(&format!("{failing}.example"));
            let (failed, ()) = tokio::join!(client.send(&query, budget), async {
                if alongside {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    client
                        .send(&udp_test_query("late.example"), Duration::from_secs(2))
                        .await
                        .expect("answered alongside");
                }
            });
            assert!(failed.is_err(), "`{failing}` gets no usable answer");
            let kept = client
                .pooled
                .load_full()
                .is_some_and(|after| Arc::ptr_eq(&after, &before));
            assert_eq!(
                !kept, replaced,
                "`{failing}`, answered alongside: {alongside}"
            );
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
    /// 测试直接摆进客户端的一条连接：第 1 代，写入队列是 `queue`
    /// A connection a test plants in a client: generation 1, with `queue` as its write queue
    fn planted(queue: Arc<WriteQueue>) -> Live {
        Live {
            queue,
            generation: 1,
            cancel: CancellationToken::new(),
            answers: Arc::default(),
            wear: Arc::new(Wear::new()),
        }
    }

    trait StreamMux {
        async fn query(&self, packet: &[u8], timeout_dur: Duration) -> anyhow::Result<Bytes>;
        fn connection_generation(&self) -> u64;
        async fn drop_connection(&self);
        fn pending(&self) -> &DashMap<u16, Pending, FxBuildHasher>;
    }

    impl<T: StreamTransport> StreamMux for StreamMuxClient<T> {
        async fn query(&self, packet: &[u8], timeout_dur: Duration) -> anyhow::Result<Bytes> {
            self.send(packet, timeout_dur).await
        }
        fn connection_generation(&self) -> u64 {
            self.wires.generation.load(Ordering::Acquire)
        }
        async fn drop_connection(&self) {
            self.reset(self.wires.generation.load(Ordering::Acquire));
        }
        fn pending(&self) -> &DashMap<u16, Pending, FxBuildHasher> {
            &self.wires.pending
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
                    generation: 1,
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

    /// 连接用旧了以后同时来几个查询（一次解析的 A 和 AAAA 就是这样）：旧连接只由它自己的写入任务摘下一次，新连接建一条，
    /// 查询都等这同一次建连、都答上
    /// With a connection worn and several queries arriving together (the A and AAAA of one lookup
    /// do), the old connection is taken out once, by its own writer, one new one is made, and every
    /// query waits for that one connect and is answered
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_expired_connection_is_replaced_once_for_queries_arriving_together() {
        let addr = spawn_stream_upstream(None).await;
        let client = Arc::new(TcpMuxClient::with_shared(
            Bootstrap::system(),
            Arc::from(addr.to_string()),
            Aging {
                max_age: Some(Duration::from_millis(100)),
                ..Aging::for_tests()
            },
        ));
        client
            .send(&udp_test_query("warm.example"), Duration::from_millis(50))
            .await
            .expect("a fresh connection answers");
        for round in 0..5 {
            // 用到了最长时间，期限也都过了：摘下了 / Past its max age and its deadlines: taken out
            tokio::time::sleep(Duration::from_millis(150)).await;
            assert!(!client.connected(), "round {round}: worn and taken out");
            let before = client.wires.generation.load(Ordering::Acquire);
            let queries = (0..4).map(|n| {
                let client = Arc::clone(&client);
                tokio::spawn(async move {
                    let query = udp_test_query(&format!("r{round}q{n}.example"));
                    client.send(&query, Duration::from_millis(50)).await
                })
            });
            for answered in futures::future::join_all(queries).await {
                answered
                    .expect("the query task ran")
                    .unwrap_or_else(|err| panic!("round {round}: {err:#}"));
            }
            assert_eq!(
                client.wires.generation.load(Ordering::Acquire),
                before + 1,
                "round {round}: the expired connection is replaced once"
            );
        }
    }

    /// 连接用到了最长时间：它上面还在等的查询照样在它上面拿到回答，接着的查询走新连接；最晚的期限过了以后旧连接关掉
    /// A connection reaching its max age: a query still waiting on it gets its answer there, and
    /// the next query goes over a new one; past the latest deadline the old connection closes
    #[tokio::test]
    async fn a_query_in_flight_outlives_its_connection_reaching_max_age() {
        let (addr, mut closed) = upstream_noting_closes(None).await;
        let client = TcpMuxClient::with_shared(
            Bootstrap::system(),
            Arc::from(addr.to_string()),
            Aging {
                max_age: Some(Duration::from_millis(50)),
                ..Aging::for_tests()
            },
        );
        let mid = udp_test_query("mid.example");
        let (waited, ()) = tokio::join!(
            client.send_attempt(&mid, Duration::from_millis(500)),
            async {
                // 上游 100 毫秒后才答 `mid`，连接 50 毫秒就用到了最长时间 / The upstream answers `mid`
                // after 100 ms, and the connection reaches its max age at 50 ms
                tokio::time::sleep(Duration::from_millis(70)).await;
                let old = client.wires.generation.load(Ordering::Acquire);
                assert!(!client.connected(), "taken out at its max age");
                client
                    .send_attempt(&udp_test_query("next.example"), Duration::from_secs(2))
                    .await
                    .expect("a new connection answers");
                assert_eq!(client.wires.generation.load(Ordering::Acquire), old + 1);
            }
        );
        waited.expect("the query on the aged connection is answered on it");
        tokio::time::timeout(Duration::from_secs(2), closed.recv())
            .await
            .expect("the aged connection closes once its last deadline has passed")
            .expect("a close noted");
    }

    /// 连接活了多久按单调时钟算，系统时间被往回调也照样到最长时间就摘下：这里 tokio 的钟走了 20 秒，墙上的钟几乎没动
    /// How long a connection has lived counts on the monotonic clock, so it is taken out at its max
    /// age however the system time is set back: here tokio's clock moves 20 seconds on while the
    /// wall clock hardly moves at all
    #[tokio::test]
    async fn a_connection_ages_on_the_monotonic_clock() {
        let addr = spawn_stream_upstream(None).await;
        let client = TcpMuxClient::with_shared(
            Bootstrap::system(),
            Arc::from(addr.to_string()),
            Aging {
                max_age: Some(Duration::from_secs(10)),
                ..Aging::for_tests()
            },
        );
        client
            .send(&udp_test_query("warm.example"), Duration::from_secs(2))
            .await
            .expect("a fresh connection answers");
        let old = client.wires.generation.load(Ordering::Acquire);
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(20)).await;
        // 让写入任务跑一跑，到了时候它就把连接摘下 / Let the writer run: when the time has come it takes
        // the connection out
        for _ in 0..100 {
            if !client.connected() {
                break;
            }
            tokio::task::yield_now().await;
        }
        tokio::time::resume();
        client
            .send(&udp_test_query("next.example"), Duration::from_secs(2))
            .await
            .expect("a new connection answers");
        assert_eq!(client.wires.generation.load(Ordering::Acquire), old + 1);
    }

    /// 拆连接的决定点名一代：点的那一代已经换成新连接时，什么都不动。新连接照常用，等在它上面的查询不受影响，
    /// 也没有多建一条。拆除的每条路都这样：复位、读写失败时的拆除
    /// A decision to tear a connection down names a generation, and does nothing once that
    /// generation has been replaced: the new connection goes on being used, a query waiting on
    /// it is untouched, and no further connection is made. So for every way of tearing down: a
    /// reset, the teardown after a failed read or write
    #[tokio::test]
    async fn a_teardown_naming_a_replaced_connection_leaves_the_new_one_alone() {
        let client = tcp_test_client().await;
        let ask =
            |name: &'static str| client.send(udp_test_query(name).leak(), Duration::from_secs(2));
        ask("warm.example")
            .await
            .expect("a fresh connection answers");
        let old = client.wires.generation.load(Ordering::Acquire);
        assert!(client.reset(old), "the connection it names is torn down");
        assert!(!client.reset(old), "torn down already");
        ask("again.example")
            .await
            .expect("a new connection answers");
        let new = client.wires.generation.load(Ordering::Acquire);
        assert_eq!(new, old + 1);

        // 新连接上有一个查询在等（上游 100 毫秒后才答）/ A query waits on the new connection (the
        // upstream answers after 100 ms)
        let (waiting, ()) = tokio::join!(ask("mid.example"), async {
            tokio::time::sleep(Duration::from_millis(30)).await;
            assert!(!client.reset(old));
            assert!(!TcpMuxClient::close(&client.wires, old, "stale"));
            ask("next.example")
                .await
                .expect("the same connection answers");
        });
        waiting.expect("the query on the new connection is answered");
        assert_eq!(client.wires.generation.load(Ordering::Acquire), new);
    }

    /// 握手被压住 250 ms、回答再等 250 ms：300 ms 预算的请求不跑满 500 ms，到时限就失败
    /// A handshake held back 250 ms and an answer after another 250 ms: a request with a 300 ms
    /// budget does not run the full 500 ms but fails at its limit
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

    /// 两族交替排开，第一个地址那一族在前，同一族里照原来的先后 / The families alternate, the first
    /// address's family first, each family in its own order
    #[test]
    fn addresses_alternate_by_family() {
        let parse = |addresses: &[&str]| -> Vec<SocketAddr> {
            addresses
                .iter()
                .map(|address| address.parse().unwrap())
                .collect()
        };
        let (a, b, c) = ("192.0.2.1:53", "192.0.2.2:53", "192.0.2.3:53");
        let (x, y) = ("[2001:db8::1]:53", "[2001:db8::2]:53");
        assert_eq!(
            interleaved(parse(&[a, b, c, x, y])),
            parse(&[a, x, b, y, c])
        );
        assert_eq!(interleaved(parse(&[x, a, y, b])), parse(&[x, a, y, b]));
        assert_eq!(interleaved(parse(&[x, y, a])), parse(&[x, a, y]));
        assert!(interleaved(Vec::new()).is_empty());
    }

    /// 本机的 bootstrap 服务器，`upstream.test` 解析成 127.0.0.1 和 ::1，IPv4 在前 / A local bootstrap
    /// server, `upstream.test` resolving to 127.0.0.1 and ::1, IPv4 first
    async fn loopback_names() -> (crate::engine::test_support::Upstream, Arc<Bootstrap>) {
        let server = crate::engine::test_support::loopback_bootstrap(300).await;
        let bootstrap = Bootstrap::new(
            &server.address,
            Arc::new(UdpClient::new(1).expect("UDP client")),
        );
        (server, bootstrap)
    }

    /// 错开着连（RFC 8305）：第一个尝试不回应，过了 [`ATTEMPT_DELAY`] 才起第二个，用先连上的那个；一个失败了马上起下一个，
    /// 不等；都失败时报最后那个失败。TCP、DoT、直连的 DoH 都经这里连（见 [`connect_tcp`]），DoQ 也是。以前 TCP、DoT 一个个
    /// 依次连，第一个不回应就等到建连的时限
    /// Connecting staggered (RFC 8305): with the first attempt not answering, the second starts
    /// only after [`ATTEMPT_DELAY`] and the first to connect is used; a failed attempt has the next
    /// one started at once, with no wait; with all failed the last failure is reported. TCP, DoT
    /// and direct DoH all connect through here (see [`connect_tcp`]), DoQ too. TCP and DoT used to
    /// try one after another, waiting out the connect's time limit on a first one not answering
    #[tokio::test(start_paused = true)]
    async fn attempts_are_staggered_and_a_failure_moves_on_at_once() {
        let (a, b): (SocketAddr, SocketAddr) = (
            "192.0.2.1:53".parse().unwrap(),
            "[2001:db8::1]:53".parse().unwrap(),
        );
        let started = tokio::time::Instant::now();
        let connected = staggered(vec![a, b], |address| async move {
            if address == a {
                std::future::pending::<anyhow::Result<SocketAddr>>().await
            } else {
                Ok(address)
            }
        })
        .await
        .expect("the second connects");
        assert_eq!((connected, started.elapsed()), (b, ATTEMPT_DELAY));

        let started = tokio::time::Instant::now();
        let connected = staggered(vec![a, b], |address| async move {
            anyhow::ensure!(address != a, "{address} refused");
            Ok(address)
        })
        .await
        .expect("the second connects");
        assert_eq!((connected, started.elapsed()), (b, Duration::ZERO));

        let failed = staggered(vec![a, b], |address| async move {
            Err::<SocketAddr, _>(anyhow::anyhow!("{address} refused"))
        })
        .await
        .expect_err("none connects");
        assert_eq!(failed.to_string(), format!("{b} refused"));
    }

    /// DoQ 也一样：127.0.0.1 上同一个端口的 UDP 从不回应，过 [`ATTEMPT_DELAY`] 就在 ::1 上握手。以前只连 IPv4 的那一个
    /// DoQ alike: with UDP on the same port of 127.0.0.1 never answering, the handshake goes to ::1
    /// after [`ATTEMPT_DELAY`]. The IPv4 address used to be the only one tried
    #[tokio::test]
    async fn a_doq_connect_moves_on_from_an_address_that_does_not_answer() {
        let (_server, bootstrap) = loopback_names().await;
        let answer = |_: usize, _: &str| DoqReply::Answer(Duration::ZERO);
        let mut tries = 0;
        let (port, client_tls, _silent) = loop {
            tries += 1;
            assert!(tries <= 20, "no port free on both loopbacks in 20 tries");
            let (server, client_tls) = localhost_tls(&[b"doq"]);
            let Some(v6) = spawn_doq_upstream_on(
                "[::1]:0".parse().unwrap(),
                server,
                Duration::ZERO,
                answer,
                None,
            ) else {
                eprintln!("skipped: IPv6 loopback unavailable on this host");
                return;
            };
            // 收下发来的握手却从不读 / Takes the handshakes sent to it but never reads them
            if let Ok(silent) = std::net::UdpSocket::bind(("127.0.0.1", v6.port())) {
                break (v6.port(), client_tls, silent);
            }
        };
        let client = DoqMuxClient::new(
            Arc::from(format!("doq://upstream.test:{port}?sni=localhost")),
            doq_test_runtime_through(client_tls, false, bootstrap),
            Arc::new(AtomicBool::new(false)),
        );
        client
            .send(&udp_test_query("named.example"), Duration::from_secs(2))
            .await
            .expect("the second address answers");
    }

    /// 写成主机名的 TCP、DoT、DoQ 上游经 Bootstrap 解析：`upstream.test` 只有本机的 bootstrap 服务器认得，
    /// 三种上游都由它解析出 127.0.0.1 连上
    /// TCP, DoT and DoQ upstreams written with a host name are resolved through Bootstrap:
    /// `upstream.test` is known to the local bootstrap server only, and all three connect to the
    /// 127.0.0.1 it resolves
    #[tokio::test]
    async fn named_tcp_dot_and_doq_upstreams_are_resolved_through_bootstrap() {
        let server = crate::engine::test_support::loopback_bootstrap(300).await;
        let bootstrap = Bootstrap::new(
            &server.address,
            Arc::new(UdpClient::new(1).expect("UDP client")),
        );
        let query = udp_test_query("named.example");
        let budget = Duration::from_secs(2);

        let tcp = spawn_stream_upstream(None).await;
        TcpMultiplexer::new(1, 0, 0, Arc::clone(&bootstrap))
            .send(&query, &format!("upstream.test:{}", tcp.port()), budget)
            .await
            .expect("the named TCP upstream answers");

        let (dot_server, dot_client) = self_signed_tls(&["upstream.test"], &[]);
        let dot = spawn_stream_upstream(Some(dot_server)).await;
        DotMultiplexer::with_shared((Arc::new(dot_client), Arc::clone(&bootstrap)), 1, 0, 0)
            .send(&query, &format!("upstream.test:{}", dot.port()), budget)
            .await
            .expect("the named DoT upstream answers");

        let (doq_server, doq_client) = self_signed_tls(&["upstream.test"], &[b"doq"]);
        let answer = |_: usize, _: &str| DoqReply::Answer(Duration::ZERO);
        let doq = spawn_doq_upstream(doq_server, Duration::ZERO, answer).await;
        let runtime = Arc::into_inner(doq_test_runtime(doq_client, false)).expect("one owner");
        DoqMuxClient::new(
            Arc::from(format!("doq://upstream.test:{}", doq.port())),
            Arc::new(DoqRuntime {
                bootstrap,
                ..runtime
            }),
            Arc::new(AtomicBool::new(false)),
        )
        .send(&query, budget)
        .await
        .expect("the named DoQ upstream answers");

        assert_eq!(
            server.queries(),
            2,
            "A and AAAA asked once, then kept for their TTL"
        );
    }

    /// DoT 的写入卡住时也一样收尾（见 `a_stuck_write_ends_at_the_deadline`）：TLS 流写满时会先收下明文，
    /// 写入任务停在 flush 上
    /// A stuck DoT write ends the same way (see `a_stuck_write_ends_at_the_deadline`): a full
    /// TLS stream accepts the plaintext first and the writer parks on the flush
    #[tokio::test]
    async fn a_stuck_dot_write_ends_at_the_deadline() {
        let (server, client_tls) = localhost_tls(&[]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
        let (read_now, told) = oneshot::channel();
        let peer = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let held = acceptor.accept(stream).await.expect("TLS handshake");
            let _ = told.await;
            read_to_close(held).await;
        });
        let client = DotMuxClient::new(
            Arc::from(format!("dot://{addr}?sni=localhost")),
            Arc::new(client_tls),
        );
        assert_a_stuck_write_ends_at_the_deadline(&client, read_now, peer).await;
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
        let client =
            DoqClient::new(2, 60, 15_000, true, Bootstrap::system()).expect("build DoQ client");
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

    /// 从 `stream` 读一个带长度前缀的查询 / Reads one length-prefixed query from `stream`
    async fn read_frame(
        stream: &mut (impl tokio::io::AsyncRead + Unpin),
    ) -> std::io::Result<Vec<u8>> {
        let mut len = [0u8; 2];
        stream.read_exact(&mut len).await?;
        let mut query = vec![0u8; usize::from(u16::from_be_bytes(len))];
        stream.read_exact(&mut query).await?;
        Ok(query)
    }

    /// 往 `stream` 写 `query` 的回答（见 [`echo_answer`]），带长度前缀 / Writes the answer to `query`
    /// (see [`echo_answer`]) to `stream`, length-prefixed
    async fn write_answer(
        stream: &mut (impl tokio::io::AsyncWrite + Unpin),
        query: &[u8],
    ) -> std::io::Result<()> {
        let answer = echo_answer(query);
        stream
            .write_all(&(answer.len() as u16).to_be_bytes())
            .await?;
        stream.write_all(&answer).await?;
        stream.flush().await
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
        let mux = TcpMultiplexer::new(2, 300, 60, Bootstrap::system());
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
        let mux =
            DotMultiplexer::with_shared((Arc::new(client_tls), Bootstrap::system()), 2, 300, 60);
        mux.send(
            &udp_test_query("a.example"),
            &format!("{addr}?sni=localhost"),
            Duration::from_secs(2),
        )
        .await
        .expect("the upstream answers");
        kept_then_dropped(&mut closed, |keep| mux.retain_upstreams(|_| keep)).await;
    }

    /// 连接池里的客户端用的是建多路复用器时给的老化设置：连接最长存活（设成 1 秒的连接到时候自己摘下、关掉，不等下一个
    /// 查询来看）、空闲时长（设成 1 秒的连接不再有查询时自己关掉）
    /// A pool's clients take the aging the multiplexer was built with: the longest a connection
    /// may live (given 1 second, it takes itself out and closes when the time comes, with no next
    /// query to look) and how long it may sit idle (given 1 second, it closes by itself once no
    /// query comes)
    #[tokio::test]
    async fn pool_clients_take_the_configured_health_settings() {
        let query = udp_test_query("a.example");
        let mux = TcpMultiplexer::new(1, 1, 0, Bootstrap::system());
        let (addr, mut closed) = upstream_noting_closes(None).await;
        let upstream = addr.to_string();
        // 期限短一些：摘下的旧连接要等登记在它上面最晚的那个期限 / A short deadline: the old connection
        // taken out waits for the latest deadline registered on it
        mux.send(&query, &upstream, Duration::from_millis(300))
            .await
            .expect("the upstream answers");
        timeout(Duration::from_secs(3), closed.recv())
            .await
            .expect("past its max age and its deadline, it closes with no query coming");

        let mux = TcpMultiplexer::new(1, 0, 1, Bootstrap::system());
        let (addr, mut closed) = upstream_noting_closes(None).await;
        mux.send(&query, &addr.to_string(), Duration::from_millis(300))
            .await
            .expect("the upstream answers");
        timeout(Duration::from_secs(3), closed.recv())
            .await
            .expect("idle for a second past the deadline, it closes");
    }

    /// 连接空闲了 `tcp_connection_idle_timeout_seconds` 就自己关掉，不等哪个查询来查（RFC 7766 §6.2.3）；DoT 关的时候先发
    /// close_notify（RFC 8446 §6.1）。以前要等下一个用到这个客户端的查询来查，池里排在后面、平常轮不到的连接靠 keepalive
    /// 一直开着；关的时候也只断 TCP
    /// A connection idle for `tcp_connection_idle_timeout_seconds` closes by itself, without
    /// waiting for a query to look (RFC 7766 §6.2.3), DoT sending close_notify first (RFC 8446
    /// §6.1). It used to wait for the next query using its client, so the connections far down a
    /// pool, normally left alone, stayed open on their keepalive; and closing only cut the TCP
    /// connection
    #[tokio::test]
    async fn an_idle_dot_connection_closes_by_itself_with_close_notify() {
        let (server, client_tls) = localhost_tls(&[]);
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // 答一个查询，再说一声连接结束得干不干净：读到 close_notify 是 Ok(0)，没有它就断了是错误
        // Answers one query, then says how the connection ended: close_notify reads as Ok(0), a
        // close without it as an error
        let (ended, mut how) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(stream).await.unwrap();
            let query = read_frame(&mut tls).await.unwrap();
            write_answer(&mut tls, &query).await.unwrap();
            let clean = matches!(tls.read(&mut [0u8; 1]).await, Ok(0));
            ended.send(clean).unwrap();
        });
        let client = DotMuxClient::with_shared(
            (Arc::new(client_tls), Bootstrap::system()),
            Arc::from(format!("dot://{addr}?sni=localhost")),
            Aging {
                idle: Some(Duration::from_millis(100)),
                ..Aging::for_tests()
            },
        );
        client
            .send(&udp_test_query("a.example"), Duration::from_millis(200))
            .await
            .expect("the upstream answers");
        let clean = timeout(Duration::from_secs(2), how.recv())
            .await
            .expect("the idle connection closes with no query coming")
            .expect("the upstream says how");
        assert!(clean, "closed with close_notify");
        assert!(!client.connected(), "the slot is cleared");
    }

    /// 新建的连接答了一些查询就被上游关掉，没答的查询换一条新连接重发（RFC 7766 §6.2.1.1）。以前只看连接是不是这次之前
    /// 就有：这次新建的连接断了一律不重发，没答的查询跟着失败
    /// A connection newly made that the upstream closes once it has answered some queries has the
    /// ones left unanswered sent again on a fresh one (RFC 7766 §6.2.1.1). Whether the connection
    /// was there before this send used to be all that counted: a new one breaking was never sent
    /// again on, and the queries left unanswered failed with it
    #[tokio::test]
    async fn queries_a_closed_connection_left_unanswered_are_sent_again() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // 每条连接：200 毫秒里读到两个查询就只答第一个，然后关掉；只来了一个就照常答下去
        // On each connection: with two queries read within 200 ms only the first is answered and
        // the connection closed; with one alone it is answered and the connection goes on
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let Ok(first) = read_frame(&mut stream).await else {
                        return;
                    };
                    let second = timeout(Duration::from_millis(200), read_frame(&mut stream)).await;
                    let _ = write_answer(&mut stream, &first).await;
                    if second.is_ok() {
                        return;
                    }
                    while let Ok(query) = read_frame(&mut stream).await {
                        let _ = write_answer(&mut stream, &query).await;
                    }
                });
            }
        });
        let client = TcpMuxClient::new(Arc::from(addr.to_string()));
        let (first, second) = (
            udp_test_query("first.example"),
            udp_test_query("second.example"),
        );
        let (first, second) = tokio::join!(
            client.send(&first, Duration::from_secs(2)),
            client.send(&second, Duration::from_secs(2)),
        );
        first.expect("answered before the close");
        second.expect("sent again on a fresh connection and answered there");
    }

    /// DoQ 连接带着保活，不关掉的话会一直给旧上游发包
    /// A DoQ connection carries a keep-alive and would go on pinging the old upstream
    /// DoQ 连接池先用排在前面、还不忙的那个客户端：一个个来的查询都走第一条连接，别的客户端不建连接。以前轮流用，
    /// 每个上游最后都开着 16 条连接、各自保活
    /// A DoQ pool takes the first client not busy: queries coming one by one all go over the
    /// first connection, and the other clients make none. They used to be taken in turn, every
    /// upstream ending up with 16 connections open, each kept alive
    #[tokio::test]
    async fn a_doq_pool_uses_one_connection_until_it_is_busy() {
        let (server, client_tls) = localhost_tls(&[b"doq"]);
        let addr = spawn_doq_upstream(server, Duration::ZERO, |_, _| {
            DoqReply::Answer(Duration::ZERO)
        })
        .await;
        let client = DoqClient {
            pools: UpstreamPools::new(),
            pool_size: 4,
            runtime: doq_test_runtime(client_tls, false),
        };
        let upstream = format!("{addr}?sni=localhost");
        for n in 0..8 {
            client
                .send(
                    &udp_test_query(&format!("q{n}.example")),
                    &upstream,
                    Duration::from_secs(2),
                )
                .await
                .expect("the upstream answers");
        }
        let pool = client
            .pools
            .get_or_create(&upstream, |_| unreachable!("built already"));
        let connected: Vec<bool> = pool
            .clients
            .iter()
            .map(|client| client.pooled.load().is_some())
            .collect();
        assert_eq!(connected, [true, false, false, false]);
    }

    /// QUIC 的保活让上游看这条连接一直在用；没人用了它照样关：最后一个查询的期限过后空闲满时限，从池里拿掉、关掉，不等下一个
    /// 查询来看
    /// QUIC's keepalive has the upstream see this connection in use all along; once nobody uses it
    /// it closes all the same: idle its limit past the last query's deadline, it is taken out of
    /// the pool and closed, with no next query to look
    #[tokio::test]
    async fn an_unused_doq_connection_closes_once_idle_despite_its_keepalive() {
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
        let aging = Aging {
            idle: Some(Duration::from_millis(200)),
            ..Aging::for_tests()
        };
        let client = DoqMuxClient::new(
            Arc::from(format!("{addr}?sni=localhost")),
            doq_runtime_aging(client_tls, false, Bootstrap::system(), 50, aging),
            Arc::new(AtomicBool::new(false)),
        );
        client
            .send(&udp_test_query("a.example"), Duration::from_millis(100))
            .await
            .expect("the upstream answers");
        timeout(Duration::from_secs(2), closed.recv())
            .await
            .expect("idle past the last deadline, it closes with no query coming")
            .expect("a close noted");
        assert!(client.pooled.load().is_none(), "taken out of the pool");
    }

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
