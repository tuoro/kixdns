//! 经 UDP 问上游：一池 socket，各占一个临时端口，用满 [`UDP_SOCKET_QUERIES`] 次换一个（RFC 5452），回答按改写过的 ID
//! 交给等它的查询；一次收发可以发几份（见 [`UdpExchange`]）
//! Asking upstreams over UDP: a pool of sockets, each on an ephemeral port of its own and
//! replaced once used [`UDP_SOCKET_QUERIES`] times (RFC 5452), a reply handed by its rewritten ID
//! to the query waiting for it; one exchange may send several copies (see [`UdpExchange`])

use super::{MAX_DNS_MESSAGE_SIZE, Waiting};
use anyhow::Context;
use arc_swap::ArcSwap;
use bytes::Bytes;
use dashmap::DashMap;
use dashmap::mapref::entry;
use rustc_hash::FxBuildHasher;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::sync::oneshot;
#[cfg(test)]
use tokio::time::timeout;
use tracing::debug;

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
    crate::warn_sparse!(
        event = "udp_recv_error",
        socket_idx = idx,
        error = %error,
        "UDP pool recv error, pausing"
    );
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
            event = "reply_from_wrong_address",
            socket_idx = idx,
            response_id = id,
            expected_addr = %expected_addr,
            actual_addr = %src,
            "UDP response address mismatch, possible spoofing or routing anomaly"
        );
    } else if !crate::proto_utils::answers_query(query, reply) {
        // 按上游分开算：这里 `src` 就是问的那个上游，键不会比上游多 / Counted per upstream: `src` is
        // the upstream asked here, so there are no more keys than upstreams
        crate::warn_sparse!(
            per src;
            event = "reply_not_for_query",
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
        crate::socket_utils::set_udp_buffers(&socket);
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

    /// 测试里占住 IPv4 池里每个 socket 的每个 ID：这期间查询都发不出去（见 [`Self::begin`]），直到
    /// [`Self::free_ids_for_tests`] / In tests, takes every ID of every socket of the IPv4 pool: no
    /// query can be sent meanwhile (see [`Self::begin`]), until [`Self::free_ids_for_tests`]
    #[cfg(test)]
    pub(crate) fn hold_every_id_for_tests(&self) {
        for slot in self.pool.iter() {
            let state = slot.load();
            for id in 0..=u16::MAX {
                let (tx, _) = oneshot::channel();
                let nowhere = SocketAddr::from(([0, 0, 0, 0], 0));
                state.inflight.insert(id, (id, nowhere, Arc::from([]), tx));
            }
        }
    }

    /// 放开 [`Self::hold_every_id_for_tests`] 占住的 ID / Lets go of the IDs
    /// [`Self::hold_every_id_for_tests`] took
    #[cfg(test)]
    pub(crate) fn free_ids_for_tests(&self) {
        for slot in self.pool.iter() {
            slot.load().inflight.clear();
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
                            event = "udp_ids_exhausted",
                            socket_idx = idx,
                            inflight_count = state.inflight.len(),
                            "udp pool exhausted"
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
                crate::warn_sparse!(
                    event = "udp_socket_not_replaced",
                    error = %error,
                    "cannot replace a UDP socket, keeping it in use"
                )
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

#[cfg(test)]
#[path = "udp_tests.rs"]
mod tests;
