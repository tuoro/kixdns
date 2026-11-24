//! TCP（RFC 7766）和 DoT（RFC 7858）：两字节长度前缀的流式传输，共用一套多路复用器、连接池和客户端，只在怎样建连上
//! 不同（见 [`StreamTransport`]）
//! TCP (RFC 7766) and DoT (RFC 7858): the stream transports behind a two-byte length prefix,
//! sharing one multiplexer, pool and client and differing only in how they connect (see
//! [`StreamTransport`])

use super::address::{build_server_name, parse_dot_target};
use super::connect::{
    Aging, Connect, ConnectionPool, InFlight, UpstreamPools, Wear, build_tls_client_config,
    connect_tcp,
};
use super::{Waiting, retry_budget};
use crate::engine::bootstrap::Bootstrap;
use anyhow::Context;
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use dashmap::mapref::entry;
use rustc_hash::FxBuildHasher;
use rustls::ClientConfig;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicU64, AtomicUsize, Ordering};
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
use tracing::{debug, info};

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

    /// 建好一条到 `upstream` 的连接，最晚到 [`Connect`] 给的期限 `deadline` / Connect to `upstream`, by
    /// the `deadline` [`Connect`] gives
    fn connect(
        shared: &Self::Shared,
        upstream: &str,
        deadline: tokio::time::Instant,
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
        deadline: tokio::time::Instant,
    ) -> anyhow::Result<(Self::Read, OwnedWriteHalf)> {
        let stream = connect_tcp(bootstrap, upstream, deadline)
            .await
            .map_err(|e| anyhow::anyhow!("tcp connect failed: {e:#}"))?;
        let (read, write) = stream.into_split();
        Ok((tokio::io::BufReader::new(read), write))
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
    pub(super) fn with_shared(
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
            |deadline| self.connecting(deadline),
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
    fn connecting(
        &self,
        deadline: tokio::time::Instant,
    ) -> impl Future<Output = anyhow::Result<()>> + Send + 'static {
        let (shared, wires) = (self.shared.clone(), self.wires.clone());
        async move {
            let (read_half, write_half) = T::connect(&shared, &wires.upstream, deadline).await?;
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
            // 一直读到这一代被取消：还在槽里时一拆就取消，用旧了摘下的等它的查询都到了期限再取消（见 `spawn_writer`）
            // Reading goes on until this generation is cancelled: at once when it is torn down
            // while in the slot, and once its queries have all reached their deadlines when taken
            // out as worn (see `spawn_writer`)
            loop {
                let mut len_buf = [0u8; 2];
                // 取消时 select! 打断卡着的 read_exact / On cancellation select! interrupts a blocked read_exact
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        debug!(target = T::LOG_TARGET, upstream = %upstream, gen = my_generation, "{} reader cancelled, exiting", T::NAME);
                        return;
                    }
                    result = reader.read_exact(&mut len_buf) => {
                        if let Err(err) = result {
                            // 拆的是这个读取任务自己的那一代（见 `close_locked`）：它的查询都被告知，槽里换上的新连接不动
                            // What goes is this reader's own generation (see `close_locked`): its
                            // queries are all told, and a newer connection in the slot is left alone
                            let why = format!("{} read len failed", T::LABEL);
                            let in_slot = Self::close(&wires, my_generation, &why);
                            debug!(target = T::LOG_TARGET, upstream = %upstream, gen = my_generation, in_slot, error = %err, "{why}");
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
                        debug!(target = T::LOG_TARGET, upstream = %upstream, gen = my_generation, "{} reader cancelled during body read, exiting", T::NAME);
                        return;
                    }
                    result = reader.read_exact(&mut reusable_buf[..resp_len]) => {
                        if let Err(err) = result {
                            let why = format!("{} read body failed", T::LABEL);
                            let in_slot = Self::close(&wires, my_generation, &why);
                            debug!(target = T::LOG_TARGET, upstream = %upstream, gen = my_generation, in_slot, error = %err, "{why}");
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
                        crate::warn_sparse!(per upstream; target = T::LOG_TARGET, event = "reply_not_for_query", upstream = %upstream, resp_id, "{} response does not answer the query, dropped", T::NAME);
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
                let in_slot = Self::close(&wires, my_generation, &why);
                debug!(target = T::LOG_TARGET, upstream = %wires.upstream, gen = my_generation, in_slot, error = %err, "{why}");
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
            |deadline| self.connecting(deadline),
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

    /// 槽的锁已经拿在手里，拆掉第 `generation` 代连接：等在它上面的查询都以 `why` 失败；它还在槽里的话从槽里拿掉，停掉它的
    /// 读取和写入任务，丢掉写入队列，返回 true。不在槽里的（用旧了摘下的；已经拆了、换上了新的）只让它的查询失败，返回
    /// false：槽里的连接不动，用旧了摘下的那一代的读写任务照旧到它最晚的期限过了才结束（见 [`Self::spawn_writer`]），自己
    /// 读写失败时更早。
    ///
    /// 拆连接的决定都是对着某一条连接作的：它空闲太久了、它读写失败了、它上面的查询超时了。作出决定到拿到锁
    /// 之间连接可能已经换过，这个决定不能落到替它的那条上：那会让刚建好的连接白建，登记在它上面的查询失败
    ///
    /// With the slot's lock held, tears down the connection of `generation`: the queries waiting
    /// on it fail with `why`, and while it is in the slot it is taken out, its reader and writer
    /// stopped and its write queue dropped, true coming back. One not in the slot (taken out as
    /// worn; torn down already and replaced) only has its queries failed, and false comes back:
    /// the connection in the slot is left alone, and the reader and writer of one taken out as
    /// worn still end once its latest deadline has passed (see [`Self::spawn_writer`]), or
    /// earlier on a read or write of their own failing.
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

    /// 复位第 `generation` 代连接（见 [`Self::close_locked`]）：等在它上面的查询马上失败，各自可以换新连接重发，而不是干等到
    /// 期限、再轮流把下一条连接也复位掉。它还在槽里时读写任务跟着停掉，返回 true；用旧了摘下的那一代不在槽里，读写任务到它
    /// 最晚的期限过了才结束，返回 false
    /// Resets the connection of `generation` (see [`Self::close_locked`]): every query waiting
    /// on it fails at once, free to retry over a fresh connection instead of sitting out its
    /// deadline and resetting the next connection in turn. While it is in the slot its reader and
    /// writer stop with it and true comes back; one taken out as worn is not in the slot, its
    /// reader and writer ending once its latest deadline has passed, and false comes back
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

type DotTlsStream = tokio_rustls::client::TlsStream<TcpStream>;

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
        deadline: tokio::time::Instant,
    ) -> anyhow::Result<(Self::Read, Self::Write)> {
        let target = parse_dot_target(upstream)?;
        let server_name = build_server_name(&target.sni)?;
        let stream = connect_tcp(bootstrap, &target.connect_addr, deadline)
            .await
            .map_err(|e| anyhow::anyhow!("dot connect failed: {e:#}"))?;
        let tls_stream = TlsConnector::from(tls_config.clone())
            .connect(server_name, stream)
            .await
            .context("dot tls handshake failed")?;
        Ok(tokio::io::split(tls_stream))
    }
}

#[cfg(test)]
#[path = "stream_tests.rs"]
mod tests;
