//! UDP 和 TCP 监听器：绑定监听地址，收查询、当场作答或交给完整路径，按自适应流控收发。以前都写在二进制的 main.rs 里，
//! 库里的测试和别的入口用不上
//! The UDP and TCP listeners: binding the listening addresses, taking queries, answering on the
//! spot or handing them to the full path, receiving and sending under adaptive flow control. They
//! used to live in the binary's main.rs, out of reach of the library's tests and other entry points

use crate::config::ListenerConfig;
use crate::doh_server::{DohCertificate, run_doh};
use crate::engine::concurrency::QUEUE_TARGET;
use crate::engine::fair_queue::{Device, FairQueue};
use crate::engine::{Engine, OnTheSpot, PreParsedData};
use crate::observe::ClientTransport;
use crate::proto_utils::{servfail_reply, truncate_udp_response};
#[cfg(target_os = "linux")]
use crate::socket_utils::udp_batch;
#[cfg(unix)]
use crate::socket_utils::udp_local;
use anyhow::Context;
use bytes::{Bytes, BytesMut};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, UdpSocket};
use tracing::{debug, error, info};

/// 绑定好、还没开始答的 UDP socket，每个 worker 一个 / UDP sockets bound and not answering yet, one per worker
struct BoundUdp {
    addr: SocketAddr,
    family: &'static str,
    sockets: Vec<Arc<UdpSocket>>,
}

/// 绑定好、还没开始答的监听口 / Listeners bound and not answering yet
pub struct BoundListeners {
    udp: Vec<BoundUdp>,
    tcp: Vec<TcpListener>,
    doh: Option<BoundDoh>,
    /// 配了的入站 DoH 为什么没起来 / Why the inbound DoH configured did not start
    doh_error: Option<String>,
}

/// 绑定好、证书也读好了的入站 DoH：`[::]` 时 IPv4、IPv6 各一个监听口（见 [`bind_tcp_listeners`]），共用一份证书
/// Inbound DoH, bound and with its certificate read: for `[::]` one listener for IPv4 and one
/// for IPv6 (see [`bind_tcp_listeners`]), sharing one certificate
struct BoundDoh {
    listeners: Vec<TcpListener>,
    certificate: Arc<DohCertificate>,
    path: Arc<str>,
}

impl BoundListeners {
    pub fn bind(listeners: ListenerConfig, udp_workers: usize) -> anyhow::Result<Self> {
        let ListenerConfig {
            udp: bind_addr,
            tcp: bind_tcp,
            doh,
        } = listeners;
        // `[::]` 拆成两个时 worker 两边平分 / With `[::]` split in two the workers are shared between them
        let addrs: Vec<_> = listen_addrs(bind_addr).collect();
        let workers = udp_workers.div_ceil(addrs.len());
        let udp = addrs
            .into_iter()
            .map(|(addr, family)| bind_udp_workers(addr, family, workers))
            .collect::<anyhow::Result<_>>()?;

        let tcp = bind_tcp_listeners(bind_tcp)?;

        // 入站 DoH 只在配置了 bind_doh 时开：绑不上、证书读不了只记错误、留下原因（见 [`Self::doh_error`]），DNS 照常答
        // Inbound DoH only with bind_doh configured: failing to bind or to read the certificate
        // is only logged, the reason kept (see [`Self::doh_error`]), and DNS answers as usual
        let mut doh_error = None;
        let doh = doh.and_then(|doh| {
            let bound = bind_tcp_listeners(doh.bind).and_then(|listeners| {
                Ok(BoundDoh {
                    listeners,
                    certificate: DohCertificate::load(&doh.tls_cert, &doh.tls_key)?,
                    path: Arc::from(doh.path),
                })
            });
            bound
                .inspect(
                    |bound| info!(addr = %doh.bind, doh_path = %bound.path, "DoH server listening"),
                )
                .map_err(|err| {
                    let error = format!("{err:#}");
                    error!(addr = %doh.bind, %error, "DoH server cannot start");
                    doh_error = Some(error);
                })
                .ok()
        });

        Ok(Self {
            udp,
            tcp,
            doh,
            doh_error,
        })
    }

    /// 配了的入站 DoH 为什么没起来，带着原因链；起来了或没配时为 None / Why the inbound DoH
    /// configured did not start, with the cause chain; None when it started or none is configured
    pub fn doh_error(&self) -> Option<&str> {
        self.doh_error.as_deref()
    }

    /// 开始答 / Starts answering
    pub fn serve(self, engine: &Engine, all_handles: &mut Vec<tokio::task::JoinHandle<()>>) {
        for BoundUdp {
            addr,
            family,
            sockets,
        } in self.udp
        {
            info!(bind_addr = %addr, workers = sockets.len(), "Starting {family} UDP workers");
            for (worker_id, socket) in sockets.into_iter().enumerate() {
                let engine = engine.clone();
                all_handles.push(tokio::spawn(async move {
                    run_udp_worker(worker_id, socket, engine).await
                }));
            }
        }

        for listener in self.tcp {
            let engine = engine.clone();
            all_handles.push(tokio::spawn(async move { run_tcp(listener, engine).await }));
        }

        if let Some(doh) = self.doh {
            for listener in doh.listeners {
                let (certificate, engine) = (Arc::clone(&doh.certificate), engine.clone());
                let path = Arc::clone(&doh.path);
                all_handles.push(tokio::spawn(async move {
                    run_doh(listener, certificate, engine, path).await
                }));
            }
        }
    }
}

/// 在 `addr` 上开 TCP 监听口，TCP 和入站 DoH 都用它，和 UDP 一样按 [`listen_addrs`] 拆开。以前入站 DoH 直接绑
/// `[::]`，在 BSD 上 IPv4 客户端连不上，也没有哪种写法能让它两边都收
/// Opens the TCP listeners on `addr`, for TCP and inbound DoH alike, split as for UDP by
/// [`listen_addrs`]. Inbound DoH used to bind `[::]` alone, leaving IPv4 clients out on the
/// BSDs with no way to write it that took both
fn bind_tcp_listeners(addr: SocketAddr) -> anyhow::Result<Vec<TcpListener>> {
    listen_addrs(addr)
        .map(|(addr, family)| {
            tcp_listener(addr).with_context(|| format!("bind {family} TCP listener {addr}"))
        })
        .collect()
}

/// 一个 TCP 监听口，两个地址族一样开：IPv6 的只收 IPv6（IPv4 有自己的，见 [`bind_tcp_listeners`]）；排队等接受的连接最多
/// 1024 个，SO_REUSEADDR 只在 Windows 以外设，都和 tokio 的 `TcpListener::bind` 一样。Windows 上的 SO_REUSEADDR 让别的
/// 程序能绑上同一个端口，抢走连接。以前 IPv6 的另有一套写法，只排 128 个，Windows 上也设 SO_REUSEADDR
/// One TCP listener, opened alike for both families: an IPv6 one takes IPv6 alone (IPv4 has
/// its own, see [`bind_tcp_listeners`]); at most 1024 connections wait to be accepted, and
/// SO_REUSEADDR is set outside Windows only, both as tokio's `TcpListener::bind` does. On
/// Windows SO_REUSEADDR lets another program bind the same port and take the connections. The
/// IPv6 one used to be written apart, with a queue of 128, setting SO_REUSEADDR on Windows too
fn tcp_listener(addr: SocketAddr) -> std::io::Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    #[cfg(not(windows))]
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    TcpListener::from_std(socket.into())
}

/// 监听 `addr` 要绑的地址和各自的地址族，UDP、TCP 和入站 DoH 都这样绑：IPv4 地址本身；IPv6 地址本身，`[::]` 之前还有
/// 它的同伴 `0.0.0.0`（端口相同），`[::]` 只收 IPv6。IPv6 socket 收不收 IPv4 各系统默认不同（Linux、macOS 收，FreeBSD 等
/// BSD 不收，OpenBSD 怎么都不收），IPv4 另绑，在哪里都一样
/// The addresses to bind for listening on `addr`, with their families, as UDP, TCP and inbound
/// DoH all bind: an IPv4 address itself; an IPv6 address itself, `[::]` preceded by its twin
/// `0.0.0.0` on the same port, `[::]` taking IPv6 alone. Whether an IPv6 socket takes IPv4
/// differs by system (Linux and macOS do by default, FreeBSD and the other BSDs do not, OpenBSD
/// never does), and IPv4 bound apart is the same everywhere
fn listen_addrs(addr: SocketAddr) -> impl Iterator<Item = (SocketAddr, &'static str)> {
    let ipv4 = match addr {
        SocketAddr::V4(_) => Some(addr),
        SocketAddr::V6(v6) if v6.ip().is_unspecified() => Some(SocketAddr::new(
            std::net::Ipv4Addr::UNSPECIFIED.into(),
            addr.port(),
        )),
        SocketAddr::V6(_) => None,
    };
    let ipv6 = addr.is_ipv6().then_some((addr, "IPv6"));
    ipv4.map(|ipv4| (ipv4, "IPv4")).into_iter().chain(ipv6)
}

/// 为一个地址绑定 UDP worker 的 socket。内核会把报文分给同一个端口上几个 socket 的系统上（见
/// `socket_utils::SPREADS_DATAGRAMS`）每个 worker 一个，各收各的；别的系统上 worker 共用一个，那里各绑一个只有一个
/// 收得到报文
/// Binds the UDP workers' sockets for one address. Where the kernel spreads the datagrams over
/// the sockets on one port (see `socket_utils::SPREADS_DATAGRAMS`) each worker gets its own and
/// receives on it alone; elsewhere the workers share one, as only one of several would receive
/// anything
fn bind_udp_workers(
    addr: SocketAddr,
    family: &'static str,
    worker_count: usize,
) -> anyhow::Result<BoundUdp> {
    let bind = || {
        bind_udp_socket(addr)
            .map(Arc::new)
            .with_context(|| format!("bind {family} UDP socket {addr}"))
    };
    let sockets = if crate::socket_utils::SPREADS_DATAGRAMS {
        (0..worker_count)
            .map(|_| bind())
            .collect::<anyhow::Result<_>>()?
    } else {
        vec![bind()?; worker_count]
    };
    Ok(BoundUdp {
        addr,
        family,
        sockets,
    })
}

/// 一个监听用的 UDP socket。IPv6 的只收 IPv6（IPv4 有自己的，见 `listen_addrs`）。不设 SO_REUSEADDR：端口被别的
/// 程序占着时绑不上、启动失败，说得清楚；设了的话，macOS 等 BSD 和 Linux 上会悄悄和占着它的程序共用这个端口（比如
/// 5353 上的 mDNSResponder、avahi），查询进了别人那里，一个都答不上。SO_REUSEPORT 也只在内核会分报文时设（见
/// `socket_utils::spread_datagrams`），只是为了每个 worker 一个 socket
/// One UDP socket to listen on. An IPv6 one takes IPv6 alone (IPv4 has its own, see
/// `listen_addrs`). No SO_REUSEADDR: with the port taken by another program binding fails
/// and so does starting, saying why; with it, macOS and the other BSDs and Linux quietly share
/// the port with the program holding it (mDNSResponder or avahi on 5353, say), the queries
/// going to it and none getting an answer. SO_REUSEPORT too is set only where the kernel
/// spreads datagrams (see `socket_utils::spread_datagrams`), just to give each worker a socket
fn bind_udp_socket(addr: SocketAddr) -> anyhow::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    crate::socket_utils::spread_datagrams(&socket)?;
    set_udp_buffers(&socket);

    // 监听在通配地址上时，回答要从查询发到的那个地址发出（见 `UdpAnswering::local_addresses`）。在绑定之前就开：绑定
    // 以后、开之前排进来的报文，内核没给它们记下本机地址
    // Listening on the wildcard address, a reply has to leave from the address the query was
    // sent to (see `UdpAnswering::local_addresses`). Turned on before binding: for datagrams
    // queued after the bind and before this, the kernel has noted no local address
    #[cfg(unix)]
    if addr.ip().is_unspecified() {
        use std::os::fd::AsRawFd;
        if let Err(error) = udp_local::receive_local_addresses(socket.as_raw_fd(), addr.is_ipv6()) {
            tracing::warn!(%error, "cannot learn which address UDP queries are sent to; replies leave from the address the system picks");
        }
    }

    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    Ok(UdpSocket::from_std(socket.into())?)
}

/// UDP 收发缓冲平时的大小 / The usual size of the UDP send and receive buffers
const UDP_BUFFER_SIZE: usize = 4 * 1024 * 1024;

/// 设置 UDP 收发缓冲区，免得负载高时丢包：先试 4 MiB，设不上再退到 1 MiB
/// Set the UDP buffer sizes to prevent packet loss under load: 4 MiB first, falling back
/// to 1 MiB if that fails
fn set_udp_buffers(socket: &socket2::Socket) {
    let desired_size = UDP_BUFFER_SIZE;
    let fallback_size = 1024 * 1024;

    if let Err(e) = socket.set_recv_buffer_size(desired_size) {
        debug!(
            "failed to set udp recv buffer to {} bytes: {}, trying {}",
            desired_size, e, fallback_size
        );
        let _ = socket.set_recv_buffer_size(fallback_size);
    }
    if let Err(e) = socket.set_send_buffer_size(desired_size) {
        debug!(
            "failed to set udp send buffer to {} bytes: {}, trying {}",
            desired_size, e, fallback_size
        );
        let _ = socket.set_send_buffer_size(fallback_size);
    }
}

/// 一个 UDP 回答发给谁，从哪个本机地址发出。监听在通配地址上时，`local` 是查询发到的那个地址（见
/// `socket_utils::LocalAddr`）；监听在具体地址上、或在 Windows 上没有，由内核挑
/// Whom a UDP reply goes to and which local address it leaves from. Listening on the wildcard
/// address, `local` is the address the query was sent to (see `socket_utils::LocalAddr`);
/// listening on one address, or on Windows, there is none and the kernel picks
#[derive(Clone, Copy)]
struct ReplyTo {
    peer: SocketAddr,
    #[cfg_attr(not(unix), allow(dead_code))]
    // Windows 上读不到、用不上 / Windows neither reads nor uses it
    local: Option<crate::socket_utils::LocalAddr>,
}

impl From<SocketAddr> for ReplyTo {
    fn from(peer: SocketAddr) -> Self {
        Self { peer, local: None }
    }
}

#[cfg(target_os = "linux")]
impl From<udp_batch::Peer> for ReplyTo {
    fn from(peer: udp_batch::Peer) -> Self {
        Self {
            peer: peer.addr(),
            local: peer.local(),
        }
    }
}

impl ReplyTo {
    /// 不等待地发一次；发送缓冲满时是 `WouldBlock` / Sends once without waiting; `WouldBlock`
    /// when the send buffer is full
    fn try_send(self, socket: &UdpSocket, data: &[u8]) -> std::io::Result<usize> {
        #[cfg(unix)]
        if let Some(local) = self.local {
            use std::os::fd::AsRawFd;
            return socket.try_io(tokio::io::Interest::WRITABLE, || {
                udp_local::send(socket.as_raw_fd(), data, self.peer, local)
            });
        }
        socket.try_send_to(data, self.peer)
    }
}

/// 发送 UDP 数据报：try_send_to 优先（避免 reactor 开销），WouldBlock 回退异步
/// Send UDP datagram: try non-blocking first, async fallback on WouldBlock
async fn send_udp_datagram(
    socket: &UdpSocket,
    data: &[u8],
    to: impl Into<ReplyTo>,
) -> std::io::Result<usize> {
    let to = to.into();
    loop {
        match to.try_send(socket, data) {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                socket.writable().await?;
            }
            sent => return sent,
        }
    }
}

/// UDP 回答：超过客户端声明的上限就截断（RFC 6891）/ A UDP reply, cut to the client's advertised
/// limit when over it (RFC 6891)
fn udp_reply(request: &[u8], response: Bytes) -> Bytes {
    truncate_udp_response(request, &response).unwrap_or(response)
}

/// 转发回来、等着和下一批一起发出去的回答。接收循环忙着的时候（它很快会回来收发下一批），转发完的任务把
/// 回答放在这里，接收循环把它们和当场答出的回答拼进同一批，一次 sendmmsg 发出；接收循环在等新报文时，回答
/// 直接发，不为一个回答把它叫醒。只有 Linux 的批量循环会说自己在忙，其他平台的回答都直接发。
/// Replies back from a forward, waiting to go out with the next batch. While the receive loop is busy
/// (it will soon be back to receive and send the next batch), a task done forwarding leaves its reply
/// here, and the loop puts it in the same batch as the replies it gave on the spot, one sendmmsg for
/// all; while the loop waits for datagrams the reply goes directly, without waking the loop for it.
/// Only Linux's batched loop ever says it is busy; on other platforms every reply goes directly.
struct PendingReplies {
    queue: parking_lot::Mutex<Vec<(Bytes, ReplyTo)>>,
    /// 接收循环在等新报文 / The receive loop is waiting for datagrams
    idle: std::sync::atomic::AtomicBool,
    /// 接收循环在等新报文时有回答放了进来 / A reply came in while the receive loop waited for datagrams
    wake: tokio::sync::Notify,
}

impl Default for PendingReplies {
    fn default() -> Self {
        Self {
            queue: parking_lot::Mutex::new(Vec::new()),
            idle: std::sync::atomic::AtomicBool::new(true),
            wake: tokio::sync::Notify::new(),
        }
    }
}

impl PendingReplies {
    /// 接收循环忙着时收下这个回答；它在等新报文时不收，返回 false，由调用方直接发
    /// Takes the reply while the receive loop is busy; while it waits for datagrams the reply is
    /// not taken and false comes back, for the caller to send it directly
    fn try_queue(&self, reply: &Bytes, to: impl Into<ReplyTo>) -> bool {
        use std::sync::atomic::Ordering::SeqCst;
        if self.idle.load(SeqCst) {
            return false;
        }
        self.queue_and_wake(reply, to);
        true
    }

    /// 放进队列。放进来的时候循环正好转去等待、可能没看到它，就叫醒它（见 `begin_wait`）
    /// Queues the reply, and wakes the loop should it have turned to waiting just as the reply
    /// came in, possibly without seeing it (see `begin_wait`)
    fn queue_and_wake(&self, reply: &Bytes, to: impl Into<ReplyTo>) {
        use std::sync::atomic::Ordering::SeqCst;
        self.queue.lock().push((reply.clone(), to.into()));
        if self.idle.load(SeqCst) {
            self.wake.notify_one();
        }
    }

    /// 排着的回答按先后挪进 `replies`，直到这一批放满 / Moves queued replies into `replies` in order
    /// until the batch is full
    #[cfg(target_os = "linux")]
    fn fill(&self, replies: &mut crate::socket_utils::udp_batch::Replies) {
        use crate::socket_utils::udp_batch::Peer;
        let mut queue = self.queue.lock();
        let room = queue
            .len()
            .min(crate::socket_utils::udp_batch::BATCH - replies.len());
        for (reply, to) in queue.drain(..room) {
            let buf = replies.next_buf();
            buf.clear();
            buf.extend_from_slice(&reply);
            replies.push(Peer::of(to.peer).from_local(to.local));
        }
    }

    /// 接收循环没有报文可收了：先把排着的回答发掉，再等新报文或者放进来的回答
    /// The receive loop has nothing to receive: it sends the queued replies, then waits for a
    /// datagram or a queued reply
    #[cfg(target_os = "linux")]
    async fn wait(
        &self,
        socket: &UdpSocket,
        replies: &mut crate::socket_utils::udp_batch::Replies,
    ) {
        send_pending(socket, self, replies).await;
        if self.begin_wait() {
            tokio::select! {
                _ = socket.readable() => {}
                _ = self.wake.notified() => {}
            }
        }
        self.idle.store(false, std::sync::atomic::Ordering::SeqCst);
    }

    /// 说自己在等，再看一眼队列：在这之前放进来的回答 `queue_and_wake` 不会叫醒循环。队列空着才可以睡
    /// Says the loop waits, then looks at the queue once more: `queue_and_wake` wakes the loop for
    /// nothing queued before this. The loop may sleep only when the queue is empty
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))] // 只有 Linux 的批量循环会等 / Only Linux's batched loop waits
    fn begin_wait(&self) -> bool {
        self.idle.store(true, std::sync::atomic::Ordering::SeqCst);
        self.queue.lock().is_empty()
    }
}

/// 高性能 UDP worker：直接在接收循环中处理请求，避免 spawn 开销 / High-performance UDP worker: process requests directly in receive loop, avoiding spawn overhead
async fn run_udp_worker(worker_id: usize, socket: Arc<UdpSocket>, engine: Engine) -> ! {
    // 共享不复制：要等上游的查询各自起一个任务，每个只加一次引用计数，不复制整个 Engine（二十多个 Arc）
    // Shared, not copied: each query that waits on an upstream gets its own task, which takes one
    // reference count instead of a copy of the whole Engine (twenty-odd Arcs)
    let engine = Arc::new(engine.with_client_transport(ClientTransport::Udp));
    info!(worker_id, "UDP worker started");
    #[cfg(target_os = "linux")]
    receive_in_batches(&socket, &engine).await;
    #[cfg(not(target_os = "linux"))]
    receive_one_by_one(&socket, &engine).await;
}

/// 一个 worker 的接收循环里，快速路径要用的几样东西 / What the fast path needs in one worker's receive loop
struct UdpAnswering<'a> {
    socket: &'a Arc<UdpSocket>,
    engine: &'a Arc<Engine>,
    pending: &'a Arc<PendingReplies>,
    /// 监听在通配地址上：回答要从查询发到的那个地址发出，内核连同每个报文交上这个地址（`bind_udp_socket` 绑定之前就让它
    /// 这样做了）。监听在具体地址上时回答只会从那个地址发出，用不着
    /// Listening on the wildcard address: a reply has to leave from the address the query was
    /// sent to, which the kernel hands over with each datagram (as `bind_udp_socket` had it do
    /// before binding). Listening on one address, replies can only leave from it, and none of
    /// this is needed
    #[cfg(unix)]
    local_addresses: bool,
    /// 自适应流控：每 100 个请求检查一次是否需要调整 permits / Adaptive flow control: check if adjustment needed every 100 requests
    request_count: u32,
    /// socket 上次收空的时刻，流控靠它判断内核忙不忙 / When the socket last ran empty, by which flow control tells whether the kernel is busy
    emptied_at: Instant,
    /// 上次收空以后看过几次接收缓冲 / How many times the receive buffer was looked at since the socket last ran empty
    checks_since_empty: u32,
    /// 接收缓冲现在是不是收小的 / Whether the receive buffer is shrunk right now
    buffer_shrunk: bool,
    /// 这一段积压里上次读到的丢包数 / The drop count last read during this backlog
    drops_seen: Option<u32>,
    /// 读不读丢包数。读不到的系统（见 `socket_utils::udp_receive_drops`）怎么都是 None；测试可以关掉，在 Linux 上走那些系统的路
    /// Whether the drops are read. On systems that cannot read them (see
    /// `socket_utils::udp_receive_drops`) they are None anyway; a test may turn this off to take
    /// those systems' way on Linux
    reads_drops: bool,
    /// 上次读丢包数的时刻，到下一次之间处理了多少查询是定数，这就量出了处理速度
    /// When the drops were last read; a set number of queries is handled until the next read, which gives the speed
    looked_at: Instant,
    /// 上次见到跟不上的时刻：丢包或者拒绝 / When falling behind was last seen: drops or refusals
    behind_at: Instant,
    /// 这一段跟不上从什么时候开始。只有还从没跟不上过时它晚于 `behind_at`（见 `UdpAnswering::new`）
    /// When this spell of falling behind began. It is later than `behind_at` only while nothing
    /// has fallen behind yet (see `UdpAnswering::new`)
    behind_since: Instant,
    /// 上次看过以后，这个 worker 读到的查询有没有被流控拒绝。只算自己的：别的 worker、TCP 和 DoH 被拒，
    /// 轮流时排不下丢的，都不是这个 socket 跟不上
    /// Whether flow control refused a query this worker read since the last look. Only its own
    /// count: refusals in another worker or over TCP and DoH, and what taking turns drops for not
    /// fitting, are not this socket falling behind
    refused: bool,
    /// 正在按设备轮流：要等上游的查询只看内存，交给内核多少看有多少查询有活等着它干（见
    /// `concurrency::WAITING_TO_RUN_AT_MOST`）
    /// Devices are taking turns: a query that waits on an upstream goes by memory alone, and how
    /// many are handed to the kernel goes by how many queries have work waiting for it (see
    /// `concurrency::WAITING_TO_RUN_AT_MOST`)
    taking_turns: bool,
    /// 这台机器 `QUEUE_TARGET` 内处理得完多少查询，上次读丢包数时量的 / How many queries this machine handles
    /// within `QUEUE_TARGET`, measured when the drops were last read
    queries_within_target: usize,
    /// 这会儿在丢包或者拒绝 / Dropping or refusing just now
    behind: bool,
    /// 丢包持续了够久，就按设备轮流 / Drops have lasted long enough, so devices take turns
    overloaded: bool,
}

/// 每 100 个查询看一次接收缓冲，看到这么多次的整数倍、socket 还没收空就读一次丢包数，平时不多这一次系统调用
/// The receive buffer is looked at every 100 queries, and at every multiple of this many looks without the socket
/// running empty the drops are read, sparing the usual path that system call
const BEHIND_AFTER_CHECKS: u32 = 10;

/// 一个小查询在接收缓冲里算多少字节：内核给每个小报文记 960 字节，再把 `SO_RCVBUF` 的值翻倍当上限。网卡收进来的报文记得
/// 更多，放得下的少，排队只会更短
/// What a small query counts for in the receive buffer: the kernel charges a small datagram 960 bytes and doubles
/// the `SO_RCVBUF` value for its limit. A datagram from a network card is charged more, so fewer fit and the wait
/// only gets shorter
const RECV_BUFFER_PER_QUERY: usize = 480;

/// 大接收缓冲放得下多少个小查询，读不到实际大小时按这个算 / How many small queries the large receive
/// buffer holds, taken when the actual size cannot be read
#[cfg(target_os = "linux")]
const QUERIES_IN_RECV_BUFFER: usize = UDP_BUFFER_SIZE / RECV_BUFFER_PER_QUERY;

/// 这个 socket 的接收缓冲放得下多少个小查询，开始轮流时先这么算。`net.core.rmem_max` 比 4 MiB 小时，设下去的
/// 大小会被内核截短；内核报的是翻过倍的大小，一个小查询按 `2 * RECV_BUFFER_PER_QUERY` 算。网卡收的包内核记得更多，
/// 读的时候再量（见 `TakingTurns::read`）
/// How many small queries this socket's receive buffer holds, as reckoned when turns begin. With
/// `net.core.rmem_max` below 4 MiB the kernel cuts the size that was set; it reports the doubled
/// size, a small query reckoned at `2 * RECV_BUFFER_PER_QUERY`. The kernel charges datagrams from
/// a network card more, so reading measures it again (see `TakingTurns::read`)
#[cfg(target_os = "linux")]
fn queries_in_recv_buffer(socket: &UdpSocket) -> usize {
    socket2::SockRef::from(socket)
        .recv_buffer_size()
        .map_or(QUERIES_IN_RECV_BUFFER, |size| {
            size / (2 * RECV_BUFFER_PER_QUERY)
        })
        .max(MIN_QUERIES_IN_RECV_BUFFER)
}

/// 接收缓冲至少放得下这么多查询（两批）/ The receive buffer holds at least this many queries (two batches)
const MIN_QUERIES_IN_RECV_BUFFER: usize = 64;

/// 丢包停了这么久才算跟上。缓冲收小以后只排 `QUEUE_TARGET` 那么多，到达有一小段空档就会收空；这时放回大缓冲，下一波要排
/// 满它才会再收小，这段时间答的都要排很久
/// Drops have to stop for this long to count as having caught up. Once shrunk the buffer holds
/// only `QUEUE_TARGET`, so a short gap in arrivals runs it empty; putting the large buffer back
/// then means the next wave has to fill it before it shrinks again, and what gets answered
/// meanwhile waits long
const CAUGHT_UP_AFTER: Duration = Duration::from_secs(1);

/// 跟不上（丢包或者拒绝）持续这么久才按设备轮流。一阵突发很快就处理完，不该有人因此被丢
/// Falling behind (drops or refusals) has to last this long before devices take turns. A burst
/// is soon handled, and nobody should lose queries over it
const BEHIND_BEFORE_TURNS: Duration = Duration::from_secs(1);

/// 跟上以后这么久之内又跟不上，算同一阵过载的继续：一阵开头已经过了 `BEHIND_BEFORE_TURNS`，马上轮流。一阵阵、每阵不到一秒的
/// 洪泛中间停一两秒，每次都从头计时的话，一阵还没够一秒就停了，轮流一次都不会开始，每阵里别的设备都答不上
/// Falling behind again within this long of catching up continues the same spell of overload: the
/// spell began `BEHIND_BEFORE_TURNS` ago or more, so turns begin at once. A flood coming in waves
/// of under a second with a second or two between them would otherwise start over each time, each
/// wave ending before it lasted a second, so turns would never begin and other devices would go
/// unanswered through every wave
const QUIET_BEFORE_A_NEW_SPELL: Duration = Duration::from_secs(60);

/// 这台机器 `QUEUE_TARGET` 内处理得完多少查询，`took` 是处理 `BEHIND_AFTER_CHECKS` 次看缓冲之间那些查询用的时间
/// How many queries this machine handles within `QUEUE_TARGET`, `took` being how long the queries
/// between `BEHIND_AFTER_CHECKS` looks took
fn queries_within_target(took: Duration) -> usize {
    let handled = u128::from(BEHIND_AFTER_CHECKS) * 100;
    let queries = handled * QUEUE_TARGET.as_nanos() / took.as_nanos().max(1);
    usize::try_from(queries)
        .unwrap_or(usize::MAX)
        .max(MIN_QUERIES_IN_RECV_BUFFER)
}

/// 缓冲满到丢包时收到多小：正好放得下这台机器 `QUEUE_TARGET` 内处理得完的查询。处理不完的查询反正要丢，缓冲越大，答得上
/// 的那些排得越久
/// How small the receive buffer gets once full enough to drop: just what this machine handles
/// within `QUEUE_TARGET`. What cannot be handled gets dropped anyway, and the larger the buffer
/// the longer the queries that do get answered wait in line
fn recv_buffer_when_behind(queries: usize) -> usize {
    queries
        .saturating_mul(RECV_BUFFER_PER_QUERY)
        .min(UDP_BUFFER_SIZE)
}

impl<'a> UdpAnswering<'a> {
    fn new(
        socket: &'a Arc<UdpSocket>,
        engine: &'a Arc<Engine>,
        pending: &'a Arc<PendingReplies>,
    ) -> Self {
        Self {
            socket,
            engine,
            pending,
            #[cfg(unix)]
            local_addresses: socket
                .local_addr()
                .is_ok_and(|bound| bound.ip().is_unspecified()),
            request_count: 0,
            emptied_at: Instant::now(),
            checks_since_empty: 0,
            buffer_shrunk: false,
            drops_seen: None,
            reads_drops: true,
            looked_at: Instant::now(),
            behind_at: Instant::now() - CAUGHT_UP_AFTER,
            behind_since: Instant::now(),
            refused: false,
            taking_turns: false,
            queries_within_target: MIN_QUERIES_IN_RECV_BUFFER,
            behind: false,
            overloaded: false,
        }
    }

    /// 量处理速度，记下在不在丢包、过没过载。没开流控时一丢包就把接收缓冲收小，压住排队延迟；只看积压
    /// 不够，贴着处理能力时大缓冲一个包都不丢，收小才是白丢
    /// Measures the handling speed and notes whether it is dropping and overloaded. Without flow
    /// control a drop shrinks the receive buffer, holding down the wait in line; a backlog alone is
    /// not enough, as right at capacity the large buffer drops nothing and shrinking would throw
    /// queries away for nothing
    fn shrink_buffer_if_overflowing(&mut self) {
        self.checks_since_empty += 1;
        if !self.checks_since_empty.is_multiple_of(BEHIND_AFTER_CHECKS) {
            return;
        }
        let now = Instant::now();
        let took = now.duration_since(std::mem::replace(&mut self.looked_at, now));
        let dropping = match self.drops() {
            Some(drops) => self
                .drops_seen
                .replace(drops)
                .is_some_and(|seen| seen != drops),
            // 读不到丢包数（FreeBSD、Windows 等）：不在轮流时，socket 连续 `BUSY_AFTER` 没收空就算在丢——过了处理能力积压
            // 才会一直在，接收缓冲早晚满出来。轮流时读得比处理快，socket 总收得空，看的是轮流自己算的积压（见 `Turns::would_overflow`）
            // The drops cannot be read (FreeBSD, Windows and so on): not taking turns, a socket
            // going `BUSY_AFTER` without running empty counts as dropping, as only past capacity
            // does a backlog stay, and the receive buffer overflows sooner or later. Taking turns
            // reads faster than it handles, so the socket keeps running empty, and the backlog
            // the turns work out themselves is what tells (see `Turns::would_overflow`)
            None => {
                !self.taking_turns
                    && self
                        .engine
                        .flow_control_state
                        .as_ref()
                        .is_some_and(|flow| flow.busy(self.emptied_at))
            }
        };
        let refusing = std::mem::take(&mut self.refused);
        // 这一段积压第一次看：到上一次之间可能空闲过，量不出速度 / The first look of this backlog: it may
        // have been idle since the last, so this measures no speed
        if self.checks_since_empty == BEHIND_AFTER_CHECKS {
            return;
        }
        self.queries_within_target = queries_within_target(took);
        if dropping || refusing {
            // 还从没跟不上过，或者已经安静了够久：新的一段 / Never behind yet, or quiet long enough: a new spell
            if self.behind_since > self.behind_at
                || now.duration_since(self.behind_at) >= QUIET_BEFORE_A_NEW_SPELL
            {
                self.behind_since = now;
            }
            self.behind_at = now;
        }
        self.behind = now.duration_since(self.behind_at) < CAUGHT_UP_AFTER;
        self.overloaded = self.engine.flow_control_state.is_some()
            && now.duration_since(self.behind_since) >= BEHIND_BEFORE_TURNS
            && self.behind;
        // 开了流控不收小：过载了就按设备轮流，排队压在各设备自己的队列里。缓冲收小了，发得少的那台的包在被读到
        // 之前就在内核里和洪泛一起丢了，接收循环见不到它，它也就轮不上
        // With flow control it is never shrunk: overload means taking turns, with the wait held down in
        // each device's own queue. A shrunk buffer would lose a device sending little in the kernel
        // along with the flood, before it is ever read, so it would never get a turn
        if dropping && self.engine.flow_control_state.is_none() {
            self.set_recv_buffer(recv_buffer_when_behind(self.queries_within_target));
            self.buffer_shrunk = true;
        }
    }

    /// 开始按设备轮流。接收缓冲一直是大的：排队在各设备自己的队列里，缓冲小了只会在读不及时满出来，不分来源地丢
    /// Devices begin to take turns. The receive buffer stays large: the wait in line is in each
    /// device's own queue, and a small buffer would only overflow when a read comes late, dropping
    /// whatever comes from anyone
    #[cfg(target_os = "linux")]
    fn begin_turns(&mut self) -> Box<TakingTurns> {
        self.taking_turns = true;
        self.engine.permit_manager.note_turns_begun();
        Box::new(TakingTurns::new(
            self.queries_within_target,
            queries_in_recv_buffer(self.socket),
        ))
    }

    /// 轮流时有活等着内核干的查询已经够多，先不再交（见 `concurrency::WAITING_TO_RUN_AT_MOST`）/ Whether
    /// enough queries have work waiting for the kernel while taking turns, so that no more are
    /// handed over for now (see `concurrency::WAITING_TO_RUN_AT_MOST`)
    fn kernel_has_enough(&self) -> bool {
        self.engine
            .flow_control_state
            .as_ref()
            .is_some_and(|flow| flow.waiting_to_run.is_enough())
    }

    /// 这个 socket 丢过多少报文；读不到或不读时是 None / How many datagrams this socket has dropped;
    /// None when that cannot be read or is not read
    fn drops(&self) -> Option<u32> {
        self.reads_drops
            .then(|| crate::socket_utils::udp_receive_drops(self.socket))
            .flatten()
    }

    /// 逐个收：不等待地收一个报文，和它的回答发给谁、从哪个地址发出。要本机地址时才用 recvmsg 连同它一起收，别的
    /// 时候只收对端；没有报文时是 `WouldBlock`
    /// Receiving one by one: takes a datagram without waiting, along with whom its reply goes to
    /// and the address it leaves from. Only with local addresses wanted does recvmsg take one
    /// along, otherwise just the peer is taken; `WouldBlock` when there is none
    fn try_recv(&self, buf: &mut [u8]) -> std::io::Result<(usize, ReplyTo)> {
        #[cfg(unix)]
        if self.local_addresses {
            use std::os::fd::AsRawFd;
            let (len, peer, local) = self.socket.try_io(tokio::io::Interest::READABLE, || {
                udp_local::recv(self.socket.as_raw_fd(), buf)
            })?;
            return Ok((len, ReplyTo { peer, local }));
        }
        let (len, peer) = self.socket.try_recv_from(buf)?;
        Ok((len, peer.into()))
    }

    /// 逐个收的循环开始按设备轮流（见 `Turns::read_available`）/ The loop receiving one by one begins taking
    /// devices in turn (see `Turns::read_available`)
    #[cfg_attr(target_os = "linux", allow(dead_code))] // Linux 上只有测试用 / On Linux only the tests use it
    fn begin_turns_one_by_one(&mut self) -> Turns<ReplyTo> {
        self.taking_turns = true;
        self.engine.permit_manager.note_turns_begun();
        Turns::new(self.queries_within_target, recv_buffer_holds(self.socket))
    }

    fn set_recv_buffer(&self, size: usize) {
        if let Err(error) = socket2::SockRef::from(self.socket.as_ref()).set_recv_buffer_size(size)
        {
            debug!(%error, size, "failed to resize udp recv buffer");
        }
    }

    /// socket 读空了，就要开始等：到这一刻的丢包算在等之前。等完再读的话，等了再久都会当成刚丢过，跟上了也算没跟上
    /// The socket was read empty and the wait is about to begin: the drops so far come before the
    /// wait. Read after it, they would seem just dropped however long the wait, and being caught
    /// up would not count
    fn note_drops_before_waiting(&mut self) {
        if self.buffer_shrunk || self.taking_turns {
            let drops = self.drops();
            if drops != self.drops_seen {
                self.drops_seen = drops;
                self.behind_at = Instant::now();
            }
        } else {
            self.drops_seen = None;
        }
    }

    /// socket 收空了，刚等到新东西：等的这段时间不算没收空，否则空闲之后的第一个查询就算内核忙。丢包停得够久，接收缓冲
    /// 也放回去接突发
    /// The socket ran empty and the wait just ended: the wait does not count as not running empty, or the first
    /// query after a quiet spell would find the kernel busy. With the drops stopped long enough, the receive buffer
    /// goes back to catching bursts
    #[inline]
    fn socket_ran_empty(&mut self) {
        if self.engine.flow_control_state.is_some() {
            self.emptied_at = Instant::now();
        }
        self.checks_since_empty = 0;
        if (self.buffer_shrunk || self.overloaded || self.taking_turns)
            && self.behind_at.elapsed() >= CAUGHT_UP_AFTER
        {
            if self.buffer_shrunk {
                self.set_recv_buffer(UDP_BUFFER_SIZE);
                self.buffer_shrunk = false;
            }
            self.drops_seen = None;
            self.behind = false;
            self.overloaded = false;
            self.taking_turns = false;
        }
    }

    /// 处理收到的一个报文。快速路径当场答得上的（见 `Engine::on_the_spot`）写进 `reply` 并返回 true，超过客户端上限的已经
    /// 截断；要等上游的交给单独的任务，应答和太短的报文丢掉，都返回 false。
    /// Handles one received datagram. What the fast path answers on the spot (see
    /// `Engine::on_the_spot`) is written to `reply`, already cut to the client's limit, and gives
    /// true; a query that waits on an upstream goes to its own task and a response or a message
    /// too short is dropped, both giving false.
    fn answer(&mut self, packet: &[u8], to: impl Into<ReplyTo>, reply: &mut BytesMut) -> bool {
        let to = to.into();
        let peer = to.peer;
        self.request_count += 1;
        if self.request_count >= 100 {
            self.request_count = 0;
            self.shrink_buffer_if_overflowing();
        }
        match self.engine.on_the_spot(packet, peer, reply) {
            OnTheSpot::Reply => {}
            // 要等上游的放进它自己的任务，带着快速路径解析出的内容 / One that waits on an upstream goes to
            // its own task, with what the fast path parsed
            OnTheSpot::Forward(pre_parsed) => {
                let packet = Bytes::copy_from_slice(packet);
                self.refused |= !spawn_udp_answer(self, packet, to, pre_parsed);
                return false;
            }
            OnTheSpot::Drop => return false,
        }
        // 截断超限响应，避免 UDP 报文超过客户端声明上限 / Truncate to the client's advertised UDP limit
        if let Some(truncated) = truncate_udp_response(packet, reply) {
            reply.clear();
            reply.extend_from_slice(&truncated);
        }
        true
    }
}

/// 接收循环连着收到这么多个报文、socket 一直没空过，就让出一次线程。socket 里有包时非阻塞接收一直成功，
/// 循环从不 await；不让出的话，同一线程上要等上游的查询和上游回答的接收就轮不到，过载时转发全停
/// After this many datagrams in a row without the socket running empty, a receive loop yields its
/// thread once. While the socket holds datagrams the non-blocking receive keeps succeeding and the loop
/// never awaits; without the yield the queries waiting on an upstream and the readers of upstream
/// answers on the same thread never run, and under overload forwarding stops altogether
const RECEIVED_BEFORE_YIELD: usize = 32;

/// Linux：一次系统调用收一批、回一批（recvmmsg / sendmmsg）。满负荷时省下每个报文各自进出内核的那一趟；
/// 空闲时一批只有一个，和单收单发一样。没有报文时让出 tokio，worker 不空转。
/// Linux: one system call takes a batch and one sends the replies (recvmmsg / sendmmsg). Under full load
/// this saves each datagram its own trip into the kernel; when idle a batch holds one, the same as single
/// receives and sends. With nothing to read the worker yields to tokio and does not spin.
#[cfg(target_os = "linux")]
async fn receive_in_batches(socket: &Arc<UdpSocket>, engine: &Arc<Engine>) -> ! {
    use std::os::fd::AsRawFd;
    use tokio::io::Interest;
    use udp_batch::{Received, Replies};

    let fd = socket.as_raw_fd();
    let mut replies = Replies::default();
    let pending = Arc::new(PendingReplies::default());
    pending
        .idle
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let mut answering = UdpAnswering::new(socket, engine, &pending);
    let mut received = Received::default();
    if answering.local_addresses {
        received = received.with_local_addresses();
    }
    let mut received_in_row = 0;
    let mut turns: Option<Box<TakingTurns>> = None;
    loop {
        let read = match &mut turns {
            Some(taking) => taking.read(socket, &mut received),
            None => socket.try_io(Interest::READABLE, || received.recv(fd)),
        };
        let got = match read {
            Ok(got) => got,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if turns.as_ref().is_none_or(|turns| turns.queue.is_empty()) {
                    // 当前无包可读：先把排着的回答发掉，再等新报文或新回答 / Nothing to receive right now:
                    // send the queued replies, then wait for a datagram or a queued reply
                    received_in_row = 0;
                    answering.note_drops_before_waiting();
                    pending.wait(socket, &mut replies).await;
                    answering.socket_ran_empty();
                    if !answering.taking_turns {
                        turns = None;
                    }
                    continue;
                }
                0
            }
            Err(_) => continue,
        };
        if let Some(taking) = &mut turns {
            taking.queue_received(&received, got, &mut answering);
            if got == udp_batch::BATCH && taking.may_read_more() {
                continue;
            }
            taking.answer_in_turn(&mut answering, &mut replies);
            received_in_row = RECEIVED_BEFORE_YIELD;
        } else {
            for k in 0..got {
                let Some((packet, peer)) = received.get(k) else {
                    continue;
                };
                if answering.answer(packet, peer, replies.next_buf()) {
                    replies.push(peer);
                }
            }
            received_in_row += got;
            if answering.overloaded {
                turns = Some(answering.begin_turns());
            }
        }
        // 转发回来的回答搭上这一批，放不下的随后成批发 / Replies back from forwards ride along with this
        // batch; what does not fit goes in batches right after
        pending.fill(&mut replies);
        send_replies(socket, &replies).await;
        replies.clear();
        send_pending(socket, &pending, &mut replies).await;
        if received_in_row >= RECEIVED_BEFORE_YIELD {
            received_in_row = 0;
            tokio::task::yield_now().await;
        }
    }
}

/// 过载时按设备轮流：能读多少先读多少，排不下的不解析就丢，所以读得比处理得快得多，socket 不再因为满了而不分来源地丢包；
/// 然后轮流答一批，有活等着内核干的查询够多时先不交（见 `concurrency::WAITING_TO_RUN_AT_MOST`）。只有一台设备在刷也这样：别的设备隔多久
/// 才问一次都读得到、轮得上。不轮流也不会丢包了就是跟上了：读到的按量到的速度消得掉，大接收缓冲放得下。成批收的循环用
/// `TakingTurns`，逐个收的循环直接用它（见 `Turns::read_available`）
/// Devices taking turns under overload: as much as there is gets read first and what does not fit
/// is dropped unparsed, so reading is far faster than handling and the socket no longer drops
/// whatever comes for being full; then a batch is answered in turn, none being handed to the
/// kernel while enough queries have work waiting for it (see
/// `concurrency::WAITING_TO_RUN_AT_MOST`). A single device flooding gets
/// the same, so another asking however rarely is read and gets its turn. It has caught up once
/// there would be no drops without turns either: what is read is worked off at the measured speed
/// and the large receive buffer holds it. The loop receiving in batches uses `TakingTurns`, the
/// one receiving one by one this directly (see `Turns::read_available`)
struct Turns<P, R = ()> {
    queue: FairQueue<P>,
    /// 不轮流的话接收缓冲里会积着多少查询：读到的加上，按量到的速度消掉。轮流时读得比处理快，缓冲满不了，排不下
    /// 的也只是这台设备超出了自己那一份，所以看这个数：超过缓冲放得下的，不轮流也会丢包，才算还跟不上
    /// How many queries the receive buffer would hold without turns: what is read adds to it and the
    /// measured speed works it off. Taking turns reads faster than it handles, so the buffer does not
    /// fill, and what does not fit only means a device went past its share; this tells instead: past
    /// what the buffer holds there would be drops without turns, and only that is still falling behind
    backlog: usize,
    /// `backlog` 上次算到的时刻 / When `backlog` was last worked out
    counted_at: Instant,
    /// 接收缓冲放得下多少个查询 / How many queries the receive buffer holds
    holds: usize,
    /// 这种收法自己要记的；逐个收的没有，是 () / What this way of receiving keeps for itself; receiving
    /// one by one keeps nothing, and it is ()
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    reading: R,
}

impl<P, R: Default> Turns<P, R> {
    fn new(room: usize, holds: usize) -> Self {
        Self {
            queue: FairQueue::new(room),
            backlog: 0,
            counted_at: Instant::now(),
            holds,
            reading: R::default(),
        }
    }
}

impl<P, R> Turns<P, R> {
    /// 读到的一个排进它那台设备的队列，排不下的丢掉、算它被拒一次。丢掉的不算跟不上：一台设备一次发得比自己那一份多、平均却没到
    /// 处理能力，不轮流的话大缓冲照样接得住；不轮流也会丢包时才算（见 [`Self::note_read`]）
    /// Queues one that was read in its device's queue, dropping it when it does not fit and counting
    /// the device refused. What is dropped is not falling behind: a device sending more than its
    /// share at once but below capacity on average would be caught by the large buffer without
    /// turns; only drops that would happen without turns count (see [`Self::note_read`])
    fn offer(&mut self, packet: &[u8], client: IpAddr, peer: P, answering: &UdpAnswering<'_>) {
        if !self.queue.offer(packet, Device::of(client), peer) {
            let manager = &answering.engine.permit_manager;
            manager.count_refused(crate::engine::concurrency::Defence::Queue);
            manager.note_refused(client);
        }
    }

    /// 这一回读到了 `got` 个：不轮流的话接收缓冲这会儿放不下了，就是还跟不上 / `got` were read this time:
    /// with the receive buffer by now overflowing without turns, it is still falling behind
    fn note_read(&mut self, got: usize, answering: &mut UdpAnswering<'_>) {
        let now = Instant::now();
        if self.would_overflow(got, answering.queries_within_target, now) {
            answering.behind_at = now;
        }
    }

    /// 记下又读到 `got` 个，`within_target` 是 `QUEUE_TARGET` 内处理得完多少：积压从上次算到的起，这段时间按量到的速度消掉，再加上
    /// 读到的；不轮流的话接收缓冲这会儿放不下了，返回 true。放不下的那些内核会丢掉，所以积压到缓冲放得下的为止
    /// Notes `got` more read, `within_target` being how many are handled within `QUEUE_TARGET`: the
    /// backlog since it was last worked out is worked off at the measured speed, and what was read
    /// is added; gives true when the receive buffer would by now overflow without turns. The kernel
    /// would drop what does not fit, so the backlog stops at what the buffer holds
    fn would_overflow(&mut self, got: usize, within_target: usize, now: Instant) -> bool {
        let took = now.saturating_duration_since(std::mem::replace(&mut self.counted_at, now));
        let handled = within_target as u128 * took.as_nanos() / QUEUE_TARGET.as_nanos();
        let backlog = self
            .backlog
            .saturating_sub(usize::try_from(handled).unwrap_or(usize::MAX))
            .saturating_add(got);
        self.backlog = backlog.min(self.holds);
        backlog > self.holds
    }

    /// 开始答一批 / Begins answering a batch
    fn begin_batch(&mut self, answering: &UdpAnswering<'_>) {
        self.queue
            .begin_batch(answering.queries_within_target, Instant::now());
    }

    /// 轮到的下一个。有活等着内核干的查询够多了就先停，排着的留到下一轮（见 `concurrency::WAITING_TO_RUN_AT_MOST`）；当场答得上的
    /// 也一起留着：取出来才知道它答不答得上，答不上的就得交出去
    /// The next in turn. With enough queries having work waiting for the kernel it stops for now,
    /// what is queued waiting for the next turn (see `concurrency::WAITING_TO_RUN_AT_MOST`), those
    /// answerable on the spot along with the rest: only taking one tells whether it is, and one
    /// that is not would have to be handed over
    fn next(&mut self, answering: &UdpAnswering<'_>) -> Option<(Box<[u8]>, P)> {
        if answering.kernel_has_enough() {
            return None;
        }
        self.queue.next_in_turn()
    }
}

/// 成批收的循环按设备轮流（见 `Turns`），每轮读的批数有上限，开始轮流后头几批还量一下每个查询在接收缓冲里实际记多少
/// The loop receiving in batches taking devices in turn (see `Turns`): the batches read per turn
/// are bounded, and the first few after turns begin measure what a query is actually charged in
/// the receive buffer
#[cfg(target_os = "linux")]
type TakingTurns = Turns<udp_batch::Peer, BatchReading>;

/// 成批收时自己要记的 / What receiving in batches keeps for itself
#[cfg(target_os = "linux")]
struct BatchReading {
    /// 答一批之前已经读了几批 / How many batches were read before answering one
    reads: usize,
    /// 还要量几批每个查询实际记多少 / How many more batches measure what a query is charged
    samples_left: usize,
}

#[cfg(target_os = "linux")]
impl Default for BatchReading {
    fn default() -> Self {
        Self {
            reads: 0,
            samples_left: CHARGE_SAMPLES,
        }
    }
}

/// 开始轮流后头这么多批读的时候量一下每个查询在接收缓冲里实际记多少字节 / For this many batches after
/// turns begin, reading measures how many bytes a query is charged in the receive buffer
#[cfg(target_os = "linux")]
const CHARGE_SAMPLES: usize = 8;

/// 答一批之前最多读这么多批，再多的洪泛也要留时间处理 / At most this many batches are read before one is
/// answered, leaving time for handling under any flood
const READS_PER_TURN: usize = 64;

#[cfg(target_os = "linux")]
impl TakingTurns {
    /// 读一批。开始轮流后的头 `CHARGE_SAMPLES` 批，读前读后各看一次接收缓冲记着多少字节，差除以读到的个数就是每个
    /// 查询实际记多少（见 `note_charge`）。读的同时又来了包，量出来只会偏小
    /// Reads a batch. For the first `CHARGE_SAMPLES` batches after turns begin the bytes the
    /// receive buffer is charged with are read before and after, and the difference over how many
    /// were read is what a query is actually charged (see `note_charge`). Datagrams arriving
    /// meanwhile only make it come out smaller
    fn read(
        &mut self,
        socket: &UdpSocket,
        received: &mut udp_batch::Received,
    ) -> std::io::Result<usize> {
        use std::os::fd::AsRawFd;
        use tokio::io::Interest;

        let before = (self.reading.samples_left > 0)
            .then(|| crate::socket_utils::udp_receive_queue(socket))
            .flatten();
        let fd = socket.as_raw_fd();
        let got = socket.try_io(Interest::READABLE, || received.recv(fd))?;
        if let Some((queued, _)) = before
            && got > 0
            && let Some((left, buffer)) = crate::socket_utils::udp_receive_queue(socket)
        {
            self.reading.samples_left -= 1;
            self.note_charge(queued.saturating_sub(left) as usize / got, buffer as usize);
        }
        Ok(got)
    }

    /// 量到一个查询实际记 `charge` 字节，缓冲最多记 `buffer` 字节。放得下的比原先算的少才改：原先按每个查询
    /// `2 * RECV_BUFFER_PER_QUERY` 算，回环上已经偏少，网卡收的包记得更多、放得下的更少；量偏小时算出来的偏多，不改
    /// A query measured at `charge` bytes, the buffer charged with at most `buffer`. It changes only
    /// when fewer fit than reckoned: the reckoning at `2 * RECV_BUFFER_PER_QUERY` a query already
    /// comes out low on loopback, while datagrams from a network card are charged more and fewer
    /// fit; a measurement that came out small gives more, and changes nothing
    fn note_charge(&mut self, charge: usize, buffer: usize) {
        if let Some(fits) = buffer.checked_div(charge) {
            self.holds = self.holds.min(fits.max(MIN_QUERIES_IN_RECV_BUFFER));
        }
    }

    /// 收到的排进队列，排不下的丢掉（见 `Turns::offer`）/ Queues what was received, dropping what does not
    /// fit (see `Turns::offer`)
    fn queue_received(
        &mut self,
        received: &udp_batch::Received,
        got: usize,
        answering: &mut UdpAnswering<'_>,
    ) {
        for (packet, peer) in (0..got).filter_map(|k| received.get(k)) {
            self.offer(packet, peer.addr().ip(), peer, answering);
        }
        self.note_read(got, answering);
    }

    fn may_read_more(&mut self) -> bool {
        self.reading.reads += 1;
        self.reading.reads < READS_PER_TURN
    }

    /// 轮流答一批（见 `Turns::next`）/ Answers a batch in turn (see `Turns::next`)
    fn answer_in_turn(
        &mut self,
        answering: &mut UdpAnswering<'_>,
        replies: &mut udp_batch::Replies,
    ) {
        self.reading.reads = 0;
        self.begin_batch(answering);
        for _ in 0..udp_batch::BATCH {
            let Some((packet, peer)) = self.next(answering) else {
                return;
            };
            if answering.answer(&packet, peer, replies.next_buf()) {
                replies.push(peer);
            }
        }
    }
}

/// 这个 socket 的接收缓冲放得下多少个小查询。Linux 报的是翻过倍的大小（见 `queries_in_recv_buffer`），别的系统报的就是设下的
/// 大小；读不到时按平常的大小算
/// How many small queries this socket's receive buffer holds. Linux reports the doubled size
/// (see `queries_in_recv_buffer`) and other systems the size that was set; when it cannot be
/// read the usual size is reckoned
#[cfg_attr(target_os = "linux", allow(dead_code))] // Linux 上只有测试用 / On Linux only the tests use it
fn recv_buffer_holds(socket: &UdpSocket) -> usize {
    let reported_per_query = if cfg!(target_os = "linux") {
        2 * RECV_BUFFER_PER_QUERY
    } else {
        RECV_BUFFER_PER_QUERY
    };
    socket2::SockRef::from(socket)
        .recv_buffer_size()
        .unwrap_or(UDP_BUFFER_SIZE)
        .checked_div(reported_per_query)
        .unwrap_or(0)
        .max(MIN_QUERIES_IN_RECV_BUFFER)
}

/// 逐个收的循环一轮答多少个 / How many the loop receiving one by one answers per turn
const ONE_BY_ONE_TURN: usize = 32;

/// 逐个收的循环过载时按设备轮流，给没有 recvmmsg 的系统用：读是一个一个的非阻塞接收
/// Devices taking turns under overload in the loop receiving one by one, for systems without
/// recvmmsg: reading takes one non-blocking receive at a time
#[cfg_attr(target_os = "linux", allow(dead_code))] // Linux 上只有测试用 / On Linux only the tests use it
impl Turns<ReplyTo> {
    /// 把 socket 里现有的读出来排进队列，最多 `READS_PER_TURN` 轮那么多；读空了返回 true / Reads what the
    /// socket holds into the queue, at most `READS_PER_TURN` turns' worth; gives true once it is read
    /// empty
    fn read_available(&mut self, buf: &mut [u8], answering: &mut UdpAnswering<'_>) -> bool {
        let (mut got, mut drained) = (0, false);
        for _ in 0..READS_PER_TURN * ONE_BY_ONE_TURN {
            match answering.try_recv(buf) {
                Ok((len, to)) => {
                    got += 1;
                    self.offer(&buf[..len], to.peer.ip(), to, answering);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    drained = true;
                    break;
                }
                Err(_) => {}
            }
        }
        self.note_read(got, answering);
        drained
    }

    /// 轮流答一批（见 `Turns::next`）/ Answers a batch in turn (see `Turns::next`)
    async fn answer_in_turn(&mut self, answering: &mut UdpAnswering<'_>, reply: &mut BytesMut) {
        self.begin_batch(answering);
        for _ in 0..ONE_BY_ONE_TURN {
            let Some((packet, to)) = self.next(answering) else {
                return;
            };
            if answering.answer(&packet, to, reply)
                && let Err(error) = send_udp_datagram(answering.socket, reply, to).await
            {
                debug!(peer = %to.peer, %error, response_len = reply.len(), "failed to send UDP response");
            }
        }
    }
}

/// 排着的回答成批发完 / Sends every queued reply, in batches
#[cfg(target_os = "linux")]
async fn send_pending(
    socket: &UdpSocket,
    pending: &PendingReplies,
    replies: &mut crate::socket_utils::udp_batch::Replies,
) {
    loop {
        pending.fill(replies);
        if replies.is_empty() {
            return;
        }
        send_replies(socket, replies).await;
        replies.clear();
    }
}

/// 一批回答发出去：发送缓冲满时等到能写再接着发，和单发时一样；发不出去的那个记下来跳过
/// Sends a batch of replies: when the send buffer is full it waits until writable and goes on, as single
/// sends do; a reply that cannot be sent is logged and skipped
#[cfg(target_os = "linux")]
async fn send_replies(socket: &UdpSocket, replies: &crate::socket_utils::udp_batch::Replies) {
    use std::os::fd::AsRawFd;
    use tokio::io::Interest;

    let fd = socket.as_raw_fd();
    let mut next = 0;
    while next < replies.len() {
        match socket.try_io(Interest::WRITABLE, || replies.send(fd, next)) {
            // sendmmsg 要么至少发出一个，要么报错；0 只当发不出去 / sendmmsg sends at least one or
            // fails; a 0 is taken as nothing more can be sent
            Ok(0) => return,
            Ok(sent) => next += sent,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if socket.writable().await.is_err() {
                    return;
                }
            }
            Err(error) => {
                if let Some((response, peer)) = replies.get(next) {
                    debug!(%peer, %error, response_len = response.len(), "failed to send UDP response");
                }
                next += 1;
            }
        }
    }
}

/// 其他平台：一个一个收、一个一个回。先尝试非阻塞，EAGAIN 时回退到异步：高负载时消除每包的 tokio reactor
/// 开销（epoll_wait + 任务唤醒/调度循环），空闲时让出 CPU 不浪费。
/// Other platforms: one datagram received and answered at a time. A non-blocking receive comes first and
/// falls back to async on EAGAIN: under load this eliminates the per-packet tokio reactor overhead (epoll_wait
/// plus the task wake/schedule cycle), and when idle the worker yields and does not waste CPU.
#[cfg_attr(target_os = "linux", allow(dead_code))] // Linux 上只有测试用 / On Linux only the tests use it
async fn receive_one_by_one(socket: &Arc<UdpSocket>, engine: &Arc<Engine>) -> ! {
    receive_one_by_one_reading_drops(socket, engine, true).await
}

/// 同 [`receive_one_by_one`]，`reads_drops` 为 false 时不读丢包数，在 Linux 上走读不到丢包数的系统的路（测试用）
/// The same as [`receive_one_by_one`]; with `reads_drops` false the drops are not read, taking
/// the way of systems that cannot read them on Linux (for tests)
#[cfg_attr(target_os = "linux", allow(dead_code))] // Linux 上只有测试用 / On Linux only the tests use it
async fn receive_one_by_one_reading_drops(
    socket: &Arc<UdpSocket>,
    engine: &Arc<Engine>,
    reads_drops: bool,
) -> ! {
    let mut buf = vec![0; crate::proto_utils::MAX_QUERY_LEN];
    // 复用发送缓冲区：缓存命中时在这里改 TTL 和 TXID，避免每包堆分配 / Reuse send buffer to patch TTLs and the TXID on cache hits, avoiding per-packet heap allocation
    let mut reply = BytesMut::with_capacity(512);
    // 这个循环从不说自己在忙，转发回来的回答都直接发 / This loop never says it is busy, so replies
    // back from forwards all go directly
    let pending = Arc::new(PendingReplies::default());
    let mut answering = UdpAnswering::new(socket, engine, &pending);
    answering.reads_drops = reads_drops;
    let mut received_in_row = 0;
    let mut turns: Option<Turns<ReplyTo>> = None;
    loop {
        if let Some(taking) = &mut turns {
            let drained = taking.read_available(&mut buf, &mut answering);
            if taking.queue.is_empty() {
                if drained {
                    // 读空了也答完了：等新报文，不在这里收，下一轮照样先读 / Read empty and all answered:
                    // wait for a datagram without taking it here, so the next round reads first as before
                    answering.note_drops_before_waiting();
                    let _ = socket.readable().await;
                    answering.socket_ran_empty();
                    if !answering.taking_turns {
                        turns = None;
                    }
                }
                continue;
            }
            taking.answer_in_turn(&mut answering, &mut reply).await;
            tokio::task::yield_now().await;
            continue;
        }
        let (len, to) = match answering.try_recv(&mut buf) {
            Ok(result) => result,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // 当前无包可读 — 让出 tokio，等到有了再收 / No packet available right now — yield to
                // tokio until one comes, then receive it
                received_in_row = 0;
                answering.note_drops_before_waiting();
                let _ = socket.readable().await;
                answering.socket_ran_empty();
                continue;
            }
            Err(_) => continue,
        };
        if answering.answer(&buf[..len], to, &mut reply)
            && let Err(error) = send_udp_datagram(socket, &reply, to).await
        {
            debug!(peer = %to.peer, %error, response_len = reply.len(), "failed to send UDP response");
        }
        if answering.overloaded {
            turns = Some(answering.begin_turns_one_by_one());
        }
        received_in_row += 1;
        if received_in_row >= RECEIVED_BEFORE_YIELD {
            received_in_row = 0;
            tokio::task::yield_now().await;
        }
    }
}

/// 要等上游的查询交给单独的任务，在请求时限内回答（见 `Engine::answer_after_fast_path`）。流控拒绝时（过载）立刻回
/// SERVFAIL，照线上格式拼、不解析查询（见 `proto_utils::servfail_reply`），非阻塞发送，发送缓冲满就丢掉（背压）。流控
/// 拒绝时返回 false。
/// A query that waits on an upstream goes to its own task, answered within the request timeout
/// (see `Engine::answer_after_fast_path`). When flow control refuses it (overload) it gets
/// SERVFAIL at once, put together on the wire with no parse of the query (see
/// `proto_utils::servfail_reply`), sent without blocking and dropped when the send buffer is
/// full (backpressure). Gives false when flow control refused it.
fn spawn_udp_answer(
    answering: &UdpAnswering<'_>,
    packet: bytes::Bytes,
    to: impl Into<ReplyTo>,
    pre_parsed: Option<PreParsedData>,
) -> bool {
    let to = to.into();
    let peer = to.peer;
    // 轮流时排不下的已经丢过了，轮到这里的只看内存 / Taking turns, what did not fit has been dropped
    // already, and what gets here goes by memory alone
    let emptied_at = (!answering.taking_turns).then_some(answering.emptied_at);
    let permit = answering.engine.query_permit(emptied_at, peer.ip());
    let Some(permit) = permit else {
        // 只有报文头、问题和 OPT，不超过 512 字节，不必截断 / Only the header, the question and an OPT,
        // within 512 bytes, so nothing to cut
        let servfail = servfail_reply(&packet);
        if let Err(error) = to.try_send(answering.socket, &servfail)
            && error.kind() != std::io::ErrorKind::WouldBlock
        {
            debug!(%peer, %error, "failed to send UDP response");
        }
        return false;
    };
    let engine = Arc::clone(answering.engine);
    let socket = Arc::clone(answering.socket);
    let pending = Arc::clone(answering.pending);
    // 从排进去到开始跑等了多久：等上游不算在内，算的是内核自己跟不跟得上。开了流控时拿 permit 的那一刻就是排进去的时候
    // How long it waits from being queued until it runs: waiting on an upstream is not in
    // this, so it tells whether the kernel itself keeps up. With flow control on, taking the
    // permit is when it was queued
    let queued_at = permit.held_since();
    let answer = async move {
        let _permit = permit; // 自动释放 / Auto-release on drop
        if let (Some(queued_at), Some(flow)) = (queued_at, &engine.flow_control_state) {
            flow.note_queue_delay(queued_at.elapsed());
        }
        let response = udp_reply(
            &packet,
            engine
                .answer_after_fast_path(&packet, peer, pre_parsed)
                .await,
        );
        if !pending.try_queue(&response, to)
            && let Err(error) = send_udp_datagram(&socket, &response, to).await
        {
            debug!(%peer, %error, response_len = response.len(), "failed to send UDP response");
        }
    };
    // 轮流时记着这个查询什么时候有活等着内核干（见 `concurrency::WAITING_TO_RUN_AT_MOST`）；不轮流时接收循环不看这个数，
    // 查询也就不必为它多花什么
    // Taking turns, when this query has work waiting for the kernel is kept count of (see
    // `concurrency::WAITING_TO_RUN_AT_MOST`); without turns the receive loops do not go by the
    // count, so a query pays nothing for it
    match &answering.engine.flow_control_state {
        Some(flow) if answering.taking_turns => {
            let waiting = Arc::clone(&flow.waiting_to_run);
            tokio::spawn(crate::engine::concurrency::WaitingToRun::counting(
                waiting, answer,
            ));
        }
        _ => {
            tokio::spawn(answer);
        }
    }
    true
}

mod tcp;
use tcp::run_tcp;

#[cfg(test)]
mod tests;
