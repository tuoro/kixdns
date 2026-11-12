//! 面板查询日志在内核里的一半：把引擎事件拼成一条条查询记录，放进有界的交接区，面板按序号游标取走、写到磁盘。
//! 只在面板来取的时候记：两分钟没人来取就不再记，热路径上只多一次原子读。
//!
//! The kernel half of the panel's query log: engine events are assembled into one record per query
//! and kept in a bounded hand-off ring, from which the panel takes them by sequence cursor and writes
//! them to disk. Recording runs only while the panel collects: after two minutes without a collection
//! nothing is recorded, and the hot path pays a single atomic load.
//!
//! 记录只写事实（走了哪些 Pipeline、哪条规则、缓存、问了哪些上游、回了什么），不做面板那边的解释：
//! 「拦截」还是「自定义回答」、规则在配置页上叫什么，由面板按配置去认。
//! A record states facts only (the pipelines, rules, cache and upstreams it went through and what came
//! back) and leaves the panel's interpretation to the panel: whether a static answer is a block or a
//! custom answer, and what a rule is called on the config page, are read from the config there.

use std::borrow::{Borrow, Cow};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Range;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder};
use parking_lot::Mutex;
use rustc_hash::FxHashSet;
use smallvec::SmallVec;

use crate::config::Transport;
use crate::observe::{
    CacheHit, CacheHitKind, ClientTransport, DecisionDetail, DecisionKind, DecisionMade,
    RequestContext, RequestOutcome, RequestStatus, RuleAnswer, RuleEvaluated, RuleMatched,
    RulePhase, UpstreamOutcome, UpstreamResult, UpstreamSkipReason, UpstreamSkipped,
};
use crate::panel::{outcome_label, phase_label, skip_reason_label, transport_label};

/// 交接区最多留多少条，只是给索引一个上限，先到的是字节上限（[`RING_BYTES`]）。面板说存好了（下次来取时的 `after`）的
/// 就删掉，平时交接区几乎是空的；面板重启、跟不上时才攒起来，攒满了就丢最旧的，面板从序号的空缺看出漏了几条
/// How many records the hand-off ring keeps, which only bounds its index: the byte limit
/// ([`RING_BYTES`]) comes first. What the panel says it has stored (the `after` of its next take) is
/// deleted, so the ring is nearly empty most of the time; it fills only while the panel restarts or
/// falls behind, and when full the oldest goes, the panel seeing from the gap in sequence numbers how
/// many it missed
pub(crate) const CAPACITY: usize = 131_072;
/// 一次最多取走多少条 / At most this many records per collection
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) const MAX_PAGE: usize = 2_000;
/// 同时在跟的请求上限：超过的不记，只计个数（`untracked`），面板据此说漏记了几条。每秒几万个查询、上游
/// 慢到一百多毫秒时，同时在途的就上了四千
/// At most this many requests tracked at once: beyond it requests are only counted (`untracked`), so
/// the panel can still say how many it missed. Tens of thousands of queries a second with an upstream
/// slowing past a hundred milliseconds put over four thousand in flight at once
const MAX_PENDING: usize = 16_384;
/// 交接区最多占多少字节。一条命中的记录一百来字节，放得下七万多条：每秒七十万条时是一百来毫秒，每秒一千条时面板停半分钟
/// 也留得住（要上游的记录长些）。面板跟得上时交接区几乎是空的，只占用过的那一点。一条记录长过它的四分之一（配置里的名字
/// 长得离谱时）就不记，算进没记下的
/// The most bytes the ring takes. A hit's record is about a hundred bytes, so it holds over seventy
/// thousand: a hundred milliseconds or so at seven hundred thousand a second, and at a thousand a second
/// the panel can be away half a minute (records with upstream steps are longer). With the panel keeping
/// up the ring is nearly empty and takes only what it has used. A record longer than a quarter of it
/// (with absurdly long names in the config) is not recorded, and counts as unrecorded
const RING_BYTES: usize = 8 << 20;
/// 在跟的请求按编号直接定位的槽位数，2 的幂；同时在跟的多过它时，多出来的记在共享表里
/// Slots the tracked requests are placed in by number, a power of two; requests beyond them at once go
/// to a shared map
const PENDING_SLOTS: usize = 1_024;
/// 每个线程记住的名字上限：一份配置里的 Pipeline、规则和上游地址通常不过几十个，多过这个数就从头记
/// The most names a thread remembers: a config's pipelines, rules and upstream addresses usually number a
/// few dozen, and past this the thread starts over
const KNOWN_NAMES: usize = 512;
const MAX_STEPS: usize = 64;
const MAX_ANSWERS: usize = 8;
const MAX_TEXT: usize = 256;
/// 面板多久没来取就停记 / How long without a collection before recording stops
const IDLE_AFTER: Duration = Duration::from_secs(120);
/// 面板等着取时最多等多久 / The longest a panel waiting to collect is kept waiting
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) const MAX_WAIT: Duration = Duration::from_secs(5);

/// 这么多条命中的规则放得进一条记录：一步 Pipeline、一步缓存、每条规则一步、可能还有一步决定，都不超过步数上限
/// So many matched rules fit one record: a step for the pipeline, one for the cache, one per rule and
/// perhaps one for the decision, all within the limit on steps
pub(crate) fn fits_a_record(rules: usize) -> bool {
    rules + 3 <= MAX_STEPS
}

/// 配置里的名字：Pipeline、规则、上游地址。来来回回就那几个，每个线程记住见过的，同一个名字一份内存，
/// 记一步只加一次引用计数，不再每一步复制一份字符串
/// A name from the config: a pipeline, rule or upstream address. The same few come again and again, so
/// each thread remembers the ones it has seen and a name is held once; recording a step bumps a
/// reference count instead of copying a string each time
#[derive(Clone, PartialEq, Eq, Hash)]
struct ConfigName(Arc<str>);

thread_local! {
    static KNOWN: RefCell<FxHashSet<ConfigName>> = RefCell::new(FxHashSet::default());
}

impl ConfigName {
    fn of(text: &str) -> Self {
        KNOWN.with_borrow_mut(|known| {
            if let Some(name) = known.get(text) {
                return name.clone();
            }
            if known.len() >= KNOWN_NAMES {
                known.clear();
            }
            let name = Self(Arc::from(text));
            known.insert(name.clone());
            name
        })
    }
}

impl Borrow<str> for ConfigName {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl std::ops::Deref for ConfigName {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

/// 一个槽位：空着，或放着一个在跟的请求（编号和它写到一半的记录）。记录在别处，槽位里只是一个指针，
/// 一千多个槽位放得进缓存
/// One slot: empty, or holding a tracked request (its number and its half-written record). The record
/// lives elsewhere and the slot holds a pointer, so a thousand slots fit in the cache
type Slot = Mutex<Option<(u64, Box<Pending>)>>;

thread_local! {
    /// 这个线程上一个请求用完的记录，下一个请求接着用：每个请求不再分配一份，域名和步骤也留着用过的容量
    /// The record the last request on this thread finished with, taken up by the next one: no request
    /// allocates its own, and the domain and steps keep the capacity they had
    static SPARE: RefCell<Option<Box<Pending>>> = const { RefCell::new(None) };
    /// 编一条记录用的缓冲，编好再复制成交接区里那一份 / The buffer a record is encoded into before it is
    /// copied into the ring
    static ENCODING: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// 独占自己缓存行的一项（硬件预取成对抓两行，所以按两行对齐）：被写得很勤的东西和只读的放在一行上，读也要抢
/// An item on cache lines of its own (hardware prefetching fetches lines in pairs, so it aligns to two):
/// something written often and something only read on one line would have the reads fighting too
#[derive(Default)]
#[repr(align(128))]
pub(crate) struct OwnLines<T>(T);

impl<T> std::ops::Deref for OwnLines<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

pub(crate) struct QueryLog {
    epoch: Instant,
    /// 这次内核进程的身份：面板发现它变了就知道序号从头算了 / This kernel run's identity: when it
    /// changes, the panel knows the sequence restarted
    instance: u64,
    capacity: usize,
    max_pending: usize,
    /// 上一次被取走的时刻（相对 `epoch` 的毫秒数加一），0 表示没在记：没在记时请求进来只读这一个数，不读时钟。
    /// 内核一启动就算取过一次：开机时内核比面板先起来，那几秒的查询也要记下
    /// The last collection (milliseconds since `epoch`, plus one), or 0 when not recording: while not
    /// recording, an arriving request reads this one number and never the clock. Start-up counts as a
    /// collection: at boot the kernel comes up before the panel, and the queries of those seconds are
    /// recorded too
    collected: AtomicU64,
    /// 等着取的面板各自盼到的序号：面板可以同时取好几段，每段一个 / The numbers the waiting takes look for: the
    /// panel may take several ranges at once, one number each
    waiting: Mutex<Vec<u64>>,
    /// 其中最小的：最新一条到了它就叫醒等着的；没人等时是 `u64::MAX` / The smallest of them: the newest record
    /// reaching it wakes the waiting takes; `u64::MAX` with no one waiting
    wake_at: AtomicU64,
    arrived: tokio::sync::Notify,
    /// 没能记下的请求数（自内核启动起累计）：同时在途的超过上限，或者一条记录长得放不进交接区 / Requests left
    /// unrecorded (cumulative since the kernel started): more were in flight than the limit, or a record too
    /// long for the ring
    untracked: AtomicU64,
    /// 在跟的请求，按编号直接定位槽位：不算哈希、不碰共享表的锁。槽位被另一个还没结束的请求占着时
    /// （同时在跟的多过槽位数），这个请求记在 `overflow` 里
    /// Tracked requests, placed in a slot by number: no hashing and no shared map lock. When another
    /// request still running holds the slot (more are tracked at once than there are slots), the request
    /// goes to `overflow`
    slots: Box<[Slot]>,
    overflow: DashMap<u64, Box<Pending>>,
    /// `overflow` 里有几条：为 0 时不碰共享表 / How many requests `overflow` holds: at 0 the map is not
    /// touched
    overflow_len: AtomicUsize,
    /// 在跟的请求数：为 0 时别的事件一次原子读就返回 / How many requests are tracked: at 0 every other
    /// event returns after one atomic load
    pending_count: AtomicUsize,
    ring: OwnLines<Mutex<Ring>>,
    wall: WallClock,
}

/// 交接区：编好的记录首尾相接放在一块内存里，序号连续（只从头上丢），最后一条是 `newest`。放一条只是复制这几十上百
/// 字节；删掉、挤掉只是从目录头上去掉，不逐条分配和释放。面板来取时复制一段连续的内存，锁占得很短
/// The hand-off ring: encoded records laid end to end in one block of memory, numbered contiguously (it
/// only drops from the front), the last being `newest`. Putting one in copies its few dozen or hundred
/// bytes; deleting or pushing out only drops them from the head of the directory, with nothing allocated
/// or freed per record. A collection copies a stretch of contiguous memory, holding the lock briefly
struct Ring {
    bytes: Vec<u8>,
    /// 每条记录在 `bytes` 里的位置，按序号排 / Where each record sits in `bytes`, by number
    index: VecDeque<Range<usize>>,
    /// 下一条从哪里放 / Where the next record goes
    tail: usize,
    max_bytes: usize,
    /// 最近一条的序号；第一条是 1 / The newest record's sequence number; the first is 1
    newest: u64,
}

impl Ring {
    fn new(max_bytes: usize) -> Self {
        Self {
            bytes: Vec::new(),
            index: VecDeque::new(),
            tail: 0,
            max_bytes,
            newest: 0,
        }
    }

    fn len(&self) -> usize {
        self.index.len()
    }

    /// 最早那条的序号；空着时为 None / The oldest record's number; None while empty
    fn oldest(&self) -> Option<u64> {
        let len = u64::try_from(self.len()).unwrap_or(u64::MAX);
        (len > 0).then(|| self.newest + 1 - len)
    }

    /// 从头数第几条 / The record at this position from the oldest
    fn record(&self, at: usize) -> &[u8] {
        &self.bytes[self.index[at].clone()]
    }

    fn pop_front(&mut self) {
        self.index.pop_front();
    }

    /// 放进一条，序号是 `newest` 的下一个；交回放没放下。条数到了 `capacity` 先挤掉最早一条。末尾放不下就从头放：
    /// 末尾剩的那截不用，还在那截里的是最早的几条，先挤掉——从头那一带放的比它们新，不能先挪到头上再看。要占的地方
    /// 上还有最早的几条，也挤掉
    /// Puts a record in, numbered after `newest`; returns whether it was kept. At `capacity` records the
    /// oldest is pushed out first. When the end has no room it goes to the start: the rest of the end goes
    /// unused, and the records still there, the oldest ones, are pushed out first (those near the start are
    /// newer, so moving to the start before looking would be wrong). The oldest records on the space it
    /// takes are pushed out as well
    fn push(&mut self, record: &[u8], capacity: usize) -> bool {
        let len = record.len();
        if len > self.max_bytes / 4 {
            return false;
        }
        if self.index.len() >= capacity {
            self.index.pop_front();
        }
        if self.index.is_empty() {
            self.tail = 0;
        }
        let mut at = self.tail;
        if at + len > self.max_bytes {
            while self.index.front().is_some_and(|front| front.start >= at) {
                self.index.pop_front();
            }
            at = 0;
        }
        let taken = at..at + len;
        while self
            .index
            .front()
            .is_some_and(|front| front.start < taken.end && taken.start < front.end)
        {
            self.index.pop_front();
        }
        if self.bytes.len() < taken.end {
            self.bytes.resize(taken.end, 0);
        }
        self.bytes[taken.clone()].copy_from_slice(record);
        self.tail = taken.end;
        self.index.push_back(taken);
        self.newest += 1;
        true
    }

    /// 全清掉，内存还回去；序号照旧往下数 / Empties everything and gives the memory back; numbering carries
    /// on
    fn clear(&mut self) {
        self.bytes = Vec::new();
        self.index = VecDeque::new();
        self.tail = 0;
    }
}

struct Step<N = ConfigName> {
    /// 从请求进来算起的微秒数 / Microseconds since the request arrived
    at_us: u64,
    what: StepKind<N>,
}

/// 处理过程的一步，写出来是 `{"at_us":…,"kind":"…",…}`：`kind` 是下面的名字（小写、下划线连接），空着的项不写。
/// 阶段、决定、结果这些存成原来的枚举，一个字节，写的时候才变成文字
/// A step of the handling, written as `{"at_us":…,"kind":"…",…}`: `kind` is the name below (lower case,
/// joined by underscores), and empty items are left out. Phases, decisions and results are kept as their
/// enums, a byte each, and turned into text only when written
enum StepKind<N = ConfigName> {
    /// 进入一个 Pipeline：选中入口时一次，之后每跳一次一次 / Entered a pipeline: once at selection,
    /// once more after every jump
    Pipeline { pipeline: N },
    /// 一条规则命中（请求阶段），或回答后检查的结果（`phase` 为 `response`，`matched` 是检查的结论）；
    /// `decision` 和 `target` 由随后的决定补上：跳去的 Pipeline，或转发用的上游（沿用上游回答时是回答的那个）
    /// A rule matched (request phase), or an answer check's result (`phase` is `response`, `matched` its
    /// verdict); `decision` and `target` come from the decision that follows: the pipeline it jumps to,
    /// or the upstreams it forwards to (the upstream that answered, when an answer is kept)
    Rule {
        pipeline: N,
        rule: N,
        phase: RulePhase,
        matched: Option<bool>,
        decision: Option<DecisionKind>,
        target: Option<N>,
    },
    /// 前面没有对应规则那一步的决定：没有规则命中时 Pipeline 的默认决定，或没写回答检查条件的规则的回答阶段动作
    /// A decision with no rule step before it: a pipeline's default decision when no rule matched, or the
    /// response actions of a rule that has no response matchers
    Decision {
        pipeline: N,
        rule: Option<N>,
        phase: RulePhase,
        decision: DecisionKind,
        target: Option<N>,
    },
    /// 响应缓存：`fresh`、`stale`、`stale_timeout`、`stale_failure` 或 `miss`；命中时 `source` 是当初回答的上游
    /// The response cache: `fresh`, `stale`, `stale_timeout`, `stale_failure` or `miss`; on a hit `source`
    /// is the upstream that answered originally
    Cache {
        /// 没命中时为 None / None on a miss
        result: Option<CacheHitKind>,
        source: Option<N>,
    },
    /// 同一时刻已有相同的查询在问上游，这次用了它的答案 / An identical query was already asking
    /// upstream, and this request took its answer
    Joined,
    /// 一次上游尝试：`success`、`rejected`（回了失败应答被丢掉，见 `is_failure_reply`）、`error`、`aborted`
    /// （别的上游先回了，这个被取消）或 `throttled`（DoH 上游回了 HTTP 429）
    /// One upstream attempt: `success`, `rejected` (a failure reply was dropped, see
    /// `is_failure_reply`), `error`, `aborted` (another upstream answered first and this one
    /// was cancelled) or `throttled` (the DoH upstream answered HTTP 429)
    Upstream {
        upstream: N,
        transport: Transport,
        via: Transport,
        result: UpstreamOutcome,
        latency_us: u64,
        rcode: Option<ResponseCode>,
        error: Option<Box<str>>,
    },
    /// 一组上游里这个这次没问，不算一次尝试；`reason` 只有 `throttled`（刚回过 429，正在暂停）。用单独的
    /// kind：旧面板不认得的 kind 整步不显示，`upstream` 带着不认得的结果却会显示成出错
    /// An upstream of a set that was not asked this time, which is no attempt; `reason` is only
    /// `throttled` (it answered 429 a moment ago and is paused). A kind of its own: an older
    /// panel leaves out a kind it does not know, but shows an `upstream` step with a result it
    /// does not know as an error
    UpstreamSkipped {
        upstream: N,
        transport: Transport,
        reason: UpstreamSkipReason,
    },
}

/// 一个在跟的请求写到一半的记录：每一步原地写进来。请求结束时连同结果编成一段字节（见 [`Pending::encode`]），
/// 交接区里放的是那段字节，这份结构留给这个线程的下一个请求接着用。字节在答它的那颗核上就编好，面板来取的线程
/// 读的是连在一起的一小段，不必把散在几处的结构从别的核上搬过来
/// A tracked request's half-written record: each step is written into it in place. When the request
/// ends it is encoded together with the result into bytes (see [`Pending::encode`]); the ring holds
/// those bytes, and this structure is taken up by the next request on the thread. The bytes are made on
/// the core that answered, so the thread the panel collects on reads one small contiguous piece instead
/// of pulling a structure spread over several places from another core
struct Pending {
    started: Instant,
    /// 这个请求答完才一次性上报（见 [`RequestContext::reported_at_once`]）：几步的时刻说明不了什么，不为它们读钟
    /// The request is reported at once after answering (see [`RequestContext::reported_at_once`]): the steps' times
    /// say nothing, and the clock is not read for them
    at_once: bool,
    time_unix_ms: u64,
    client: IpAddr,
    transport: Option<ClientTransport>,
    qname: String,
    qtype: RecordType,
    /// 多数请求不过四步，放得下就不另外分配 / Most requests take four steps or fewer, which need no
    /// allocation of their own
    steps: SmallVec<[Step; 4]>,
    steps_truncated: bool,
    /// 命中的是哪种缓存 / Which kind of cache hit answered
    cache: Option<CacheHitKind>,
    /// 缓存的答案当初是哪个上游回答的 / Which upstream originally answered a cached answer
    cache_source: Option<ConfigName>,
    joined: bool,
    /// 最后进入的 Pipeline：请求在哪里结束（缓存在规则之前就回了的，也有它）
    /// The pipeline entered last: where the request ended (a cache answer given before any rule ran has
    /// one too)
    pipeline: Option<ConfigName>,
    /// 最后一次决定：哪条规则（没有规则命中时是 None）、决定了什么；回答后检查的决定也算。那个 Pipeline
    /// 只负责转发时，规则可能在更早的 Pipeline 里
    /// The last decision: which rule (None when no rule matched) and what it decided; an answer check's
    /// decision counts too. When the final pipeline only forwards, the rule may sit in an earlier one
    decision: Option<(Option<ConfigName>, DecisionKind)>,
    /// 最后一个回了可用答案的上游 / The last upstream that returned a usable answer
    answered_by: Option<ConfigName>,
}

/// 请求怎么结束的 / How the request ended
#[derive(Clone, Copy, PartialEq, Eq)]
enum Status {
    Completed,
    /// 引擎出错，客户端收到 SERVFAIL / The engine erred and the client got SERVFAIL
    Failed,
    Cancelled,
}

impl Status {
    fn label(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

/// 答案从哪来（见 [`Pending::outcome`]）/ Where the answer came from (see [`Pending::outcome`])
#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Forwarded,
    Cached,
    Stale,
    Joined,
    Static,
    Failed,
    Cancelled,
}

impl Outcome {
    fn label(self) -> &'static str {
        match self {
            Self::Forwarded => "forwarded",
            Self::Cached => "cached",
            Self::Stale => "stale",
            Self::Joined => "joined",
            Self::Static => "static",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

/// 一条回答。地址留着原样，写的时候直接写数字，不先格式化成一个字符串；别的类型是读出来的文字
/// One answer. An address is kept as it is and written digit by digit, without being formatted into a
/// string first; any other type is the text read
#[derive(Clone, Debug, PartialEq, Eq)]
enum Answer {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
    Text(String),
}

/// 一条记录的回答，最多 [`MAX_ANSWERS`] 条，不另外分配 / A record's answers, at most [`MAX_ANSWERS`], with no
/// allocation of their own
type Answers = SmallVec<[Answer; MAX_ANSWERS]>;

/// 枚举在编好的记录里写成一个字节。同一张表生成两个方向；写的那边是完整的 match，加了新的值不给编号就编译不过
/// An enum written as one byte in an encoded record. One table makes both directions; the writing side is
/// a full match, so a new value without a number does not compile
macro_rules! byte_codes {
    ($code:ident, $of:ident, $ty:ident { $($variant:ident = $byte:literal),+ $(,)? }) => {
        fn $code(value: $ty) -> u8 {
            match value {
                $($ty::$variant => $byte,)+
            }
        }

        fn $of(byte: u8) -> Option<$ty> {
            match byte {
                $($byte => Some($ty::$variant),)+
                _ => None,
            }
        }
    };
}

byte_codes!(client_transport_code, client_transport_of, ClientTransport { Udp = 0, Tcp = 1, Doh = 2 });
byte_codes!(status_code, status_of, Status { Completed = 0, Failed = 1, Cancelled = 2 });
byte_codes!(outcome_code, outcome_of, Outcome {
    Forwarded = 0,
    Cached = 1,
    Stale = 2,
    Joined = 3,
    Static = 4,
    Failed = 5,
    Cancelled = 6,
});
byte_codes!(phase_code, phase_of, RulePhase { Request = 0, Response = 1 });
byte_codes!(decision_code, decision_of, DecisionKind { Static = 0, Forward = 1, Jump = 2, Continue = 3 });
byte_codes!(cache_code, cache_of, CacheHitKind {
    Fresh = 0,
    Stale = 1,
    StaleClientTimeout = 2,
    StaleUpstreamFailure = 3,
});
byte_codes!(transport_code, transport_of, Transport { Udp = 0, Tcp = 1, TcpUdp = 2, Doh = 3, Dot = 4, Doq = 5 });
byte_codes!(upstream_outcome_code, upstream_outcome_of, UpstreamOutcome {
    Success = 0,
    Rejected = 1,
    Error = 2,
    Aborted = 3,
    Throttled = 4,
});
byte_codes!(skip_reason_code, skip_reason_of, UpstreamSkipReason { Throttled = 0 });

/// 步骤的种类在编好的记录里的编号 / The numbers of the step kinds in an encoded record
const STEP_PIPELINE: u8 = 0;
const STEP_RULE: u8 = 1;
const STEP_DECISION: u8 = 2;
const STEP_CACHE: u8 = 3;
const STEP_JOINED: u8 = 4;
const STEP_UPSTREAM: u8 = 5;
const STEP_UPSTREAM_SKIPPED: u8 = 6;
/// 回答的种类：IPv4、IPv6 地址照原样，别的是文字 / The kinds of answer: IPv4 and IPv6 addresses as they
/// are, anything else as text
const ANSWER_TEXT: u8 = 0;
const ANSWER_V4: u8 = 4;
const ANSWER_V6: u8 = 6;

/// 编一条记录：数字是变长整数（每个字节七位，高位说后面还有），文字是长度加原文；可有可无的项，文字和枚举前面
/// 一个 0 表示没有，数字加一、0 表示没有
/// Encodes a record: numbers are variable-length integers (seven bits a byte, the high bit saying more
/// follow), text is its length and then itself; for optional items, text and enums are preceded by 0 when
/// absent, and numbers are stored plus one with 0 for none
struct Encoder<'a>(&'a mut Vec<u8>);

impl Encoder<'_> {
    fn byte(&mut self, byte: u8) {
        self.0.push(byte);
    }

    fn number(&mut self, mut value: u64) {
        while value >= 0x80 {
            self.0.push(value.to_le_bytes()[0] | 0x80);
            value >>= 7;
        }
        self.0.push(value.to_le_bytes()[0]);
    }

    fn text(&mut self, text: &str) {
        self.number(u64::try_from(text.len()).unwrap_or(u64::MAX));
        self.0.extend_from_slice(text.as_bytes());
    }

    fn optional_text(&mut self, text: Option<&str>) {
        match text {
            None => self.byte(0),
            Some(text) => {
                self.byte(1);
                self.text(text);
            }
        }
    }

    fn optional_number(&mut self, value: Option<u64>) {
        self.number(value.map_or(0, |value| value + 1));
    }

    fn address(&mut self, address: IpAddr) {
        match address {
            IpAddr::V4(address) => {
                self.byte(ANSWER_V4);
                self.0.extend_from_slice(&address.octets());
            }
            IpAddr::V6(address) => {
                self.byte(ANSWER_V6);
                self.0.extend_from_slice(&address.octets());
            }
        }
    }
}

/// 读编好的记录（见 [`Encoder`]）；读不通时交回 None / Reads an encoded record (see [`Encoder`]); None
/// when it does not read
struct Decoder<'a>(&'a [u8]);

impl<'a> Decoder<'a> {
    fn byte(&mut self) -> Option<u8> {
        let (&byte, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(byte)
    }

    fn number(&mut self) -> Option<u64> {
        let mut value = 0;
        for shift in (0..64).step_by(7) {
            let byte = self.byte()?;
            value |= u64::from(byte & 0x7F) << shift;
            if byte & 0x80 == 0 {
                return Some(value);
            }
        }
        None
    }

    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let (taken, rest) = self.0.split_at_checked(len)?;
        self.0 = rest;
        Some(taken)
    }

    fn text(&mut self) -> Option<&'a str> {
        let len = usize::try_from(self.number()?).ok()?;
        std::str::from_utf8(self.take(len)?).ok()
    }

    fn optional_text(&mut self) -> Option<Option<&'a str>> {
        match self.byte()? {
            0 => Some(None),
            1 => self.text().map(Some),
            _ => None,
        }
    }

    fn optional_number(&mut self) -> Option<Option<u64>> {
        Some(self.number()?.checked_sub(1))
    }

    /// 前面一个 0 表示没有，否则是编号加一 / 0 for none, otherwise the code plus one
    fn optional_code<T>(&mut self, of: fn(u8) -> Option<T>) -> Option<Option<T>> {
        match self.byte()? {
            0 => Some(None),
            code => of(code - 1).map(Some),
        }
    }

    fn octets<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }

    fn address(&mut self) -> Option<IpAddr> {
        match self.byte()? {
            ANSWER_V4 => Some(IpAddr::V4(Ipv4Addr::from(self.octets::<4>()?))),
            ANSWER_V6 => Some(IpAddr::V6(Ipv6Addr::from(self.octets::<16>()?))),
            _ => None,
        }
    }

    fn rcode(&mut self) -> Option<Option<u16>> {
        match self.optional_number()? {
            None => Some(None),
            Some(rcode) => u16::try_from(rcode).ok().map(Some),
        }
    }
}

impl Pending {
    /// 这个请求的记录：接着用这个线程上一个请求用完的那份，没有才分配 / This request's record: the one the
    /// last request on this thread finished with, or a new one when there is none
    fn start(ctx: &RequestContext<'_>, time_unix_ms: u64) -> Box<Self> {
        let client = ctx.client.ip().to_canonical();
        let Some(mut pending) = SPARE.with_borrow_mut(Option::take) else {
            return Box::new(Self {
                started: ctx.started,
                at_once: ctx.reported_at_once,
                time_unix_ms,
                client,
                transport: ctx.transport,
                qname: ctx.qname.to_owned(),
                qtype: ctx.qtype,
                steps: SmallVec::new(),
                steps_truncated: false,
                cache: None,
                cache_source: None,
                joined: false,
                pipeline: None,
                decision: None,
                answered_by: None,
            });
        };
        pending.started = ctx.started;
        pending.at_once = ctx.reported_at_once;
        pending.time_unix_ms = time_unix_ms;
        pending.client = client;
        pending.transport = ctx.transport;
        pending.qname.clear();
        pending.qname.push_str(ctx.qname);
        pending.qtype = ctx.qtype;
        pending.steps.clear();
        pending.steps_truncated = false;
        pending.cache = None;
        pending.cache_source = None;
        pending.joined = false;
        pending.pipeline = None;
        pending.decision = None;
        pending.answered_by = None;
        pending
    }

    /// 用完了，留给这个线程的下一个请求 / Done with, kept for the next request on this thread
    fn release(self: Box<Self>) {
        SPARE.with_borrow_mut(|spare| {
            if spare.is_none() {
                *spare = Some(self);
            }
        });
    }

    /// 最后一次决定是规则直接回应 / Whether the last decision was a rule's own answer
    fn decided_static(&self) -> bool {
        matches!(self.decision, Some((_, DecisionKind::Static)))
    }

    /// 答案从哪来：`forwarded`、`cached`、`stale`、`joined`、`static`（规则直接回应，包括回答后检查拦截或改写）、
    /// `failed`（引擎出错，或客户端收到的不是缓存里的 SERVFAIL）或 `cancelled`。缓存里拿到的 SERVFAIL 还算缓存
    /// （照实说答案从哪来）；别的 SERVFAIL 都是没解析出来
    /// Where the answer came from: `forwarded`, `cached`, `stale`, `joined`, `static` (a rule answered,
    /// an answer check's block or rewrite included), `failed` (the engine erred, or the client got a
    /// SERVFAIL that did not come from the cache) or `cancelled`. A SERVFAIL taken from the cache still
    /// counts as cached (it says where the answer came from); any other SERVFAIL means the name was not
    /// resolved
    fn outcome(&self, status: Status, rcode: Option<ResponseCode>) -> Outcome {
        match status {
            Status::Completed if self.cache.is_some() => cached_outcome(status, self.cache),
            Status::Completed if rcode == Some(ResponseCode::ServFail) => Outcome::Failed,
            Status::Completed if self.joined => Outcome::Joined,
            Status::Completed if self.decided_static() => Outcome::Static,
            Status::Completed => Outcome::Forwarded,
            Status::Failed => Outcome::Failed,
            Status::Cancelled => Outcome::Cancelled,
        }
    }

    /// 请求结束：连同用了多久、怎么结束的和客户端收到的应答编成一段字节，顺序就是写成 JSON 的顺序（见
    /// [`write_record`]）。应答这时就读出来，不再留一份原文
    /// The request ended: the record is encoded with how long it took, how it ended and the response the
    /// client got, in the order its JSON is written (see [`write_record`]). The response is read now, and
    /// no copy of it is kept
    fn encode(&self, outcome: &RequestOutcome<'_>, out: &mut Vec<u8>) {
        encode_record(
            &RecordHead {
                time_unix_ms: self.time_unix_ms,
                client: self.client,
                transport: self.transport,
                qname: &self.qname,
                qtype: self.qtype,
                pipeline: self.pipeline.as_deref(),
                rule: match &self.decision {
                    Some((Some(rule), _)) => Some(rule),
                    _ => None,
                },
            },
            outcome,
            |status, rcode| {
                let result = self.outcome(status, rcode);
                // 答案来自哪个上游：转发的是回答的那个，缓存的是当初回答的那个；规则直接回应、合并和失败的没有
                // Which upstream the answer came from: for a forward the one that answered, for a
                // cached answer the one that answered originally; none for a rule's own answer, a
                // joined query or a failure
                let upstream = match result {
                    Outcome::Cached | Outcome::Stale => self.cache_source.as_deref(),
                    Outcome::Forwarded => self.answered_by.as_deref(),
                    _ => None,
                };
                (result, upstream)
            },
            &self.steps,
            self.steps_truncated,
            out,
        );
    }
}

/// 一条记录里步骤和结果以外的部分 / The parts of a record other than its steps and how it ended
struct RecordHead<'a> {
    time_unix_ms: u64,
    client: IpAddr,
    transport: Option<ClientTransport>,
    qname: &'a str,
    qtype: RecordType,
    pipeline: Option<&'a str>,
    rule: Option<&'a str>,
}

/// 缓存答的请求算哪种结果 / What a request the cache answered counts as
fn cached_outcome(status: Status, cache: Option<CacheHitKind>) -> Outcome {
    match status {
        Status::Completed if cache == Some(CacheHitKind::Fresh) => Outcome::Cached,
        Status::Completed => Outcome::Stale,
        Status::Failed => Outcome::Failed,
        Status::Cancelled => Outcome::Cancelled,
    }
}

/// 规则直接答的请求算哪种结果：SERVFAIL 算没解析出来（见 [`Pending::outcome`]）
/// What a request a rule answered counts as: a SERVFAIL means it was not resolved (see
/// [`Pending::outcome`])
fn rule_outcome(status: Status, rcode: Option<ResponseCode>) -> Outcome {
    match status {
        Status::Completed if rcode == Some(ResponseCode::ServFail) => Outcome::Failed,
        Status::Completed => Outcome::Static,
        Status::Failed => Outcome::Failed,
        Status::Cancelled => Outcome::Cancelled,
    }
}

/// 编一条记录，顺序就是写成 JSON 的顺序（见 [`write_record`]）。`decide` 由结束状态和响应码定出结果和答案来自哪个上游
/// Encodes a record, in the order its JSON is written (see [`write_record`]). `decide` gives how it
/// ended and which upstream the answer came from, from the status and the response code
fn encode_record<'a, N: std::ops::Deref<Target = str>>(
    head: &RecordHead<'_>,
    outcome: &RequestOutcome<'_>,
    decide: impl FnOnce(Status, Option<ResponseCode>) -> (Outcome, Option<&'a str>),
    steps: &[Step<N>],
    steps_truncated: bool,
    out: &mut Vec<u8>,
) {
    let status = match outcome.status {
        RequestStatus::Completed => Status::Completed,
        RequestStatus::Failed => Status::Failed,
        RequestStatus::Cancelled => Status::Cancelled,
    };
    let (rcode, answers) = outcome
        .response
        .map_or_else(|| (None, Answers::new()), read_response);
    let (result, upstream) = decide(status, rcode);
    let mut out = Encoder(out);
    out.number(head.time_unix_ms);
    out.address(head.client);
    out.byte(
        head.transport
            .map_or(0, |transport| client_transport_code(transport) + 1),
    );
    out.text(head.qname);
    out.text(type_name(head.qtype, &mut [0; 9]));
    out.number(u64::try_from(outcome.latency.as_micros()).unwrap_or(u64::MAX));
    out.byte(status_code(status));
    out.byte(outcome_code(result));
    out.optional_number(rcode.map(|rcode| u64::from(u16::from(rcode))));
    out.number(u64::try_from(answers.len()).unwrap_or(u64::MAX));
    for answer in &answers {
        match answer {
            Answer::V4(address) => out.address(IpAddr::V4(*address)),
            Answer::V6(address) => out.address(IpAddr::V6(*address)),
            Answer::Text(text) => {
                out.byte(ANSWER_TEXT);
                out.text(text);
            }
        }
    }
    out.optional_text(outcome.error.map(clip).as_deref());
    out.optional_text(head.pipeline);
    out.optional_text(head.rule);
    out.optional_text(upstream);
    out.number(u64::try_from(steps.len()).unwrap_or(u64::MAX));
    for step in steps {
        step.encode(&mut out);
    }
    out.byte(u8::from(steps_truncated));
}

impl<N: std::ops::Deref<Target = str>> Step<N> {
    fn encode(&self, out: &mut Encoder<'_>) {
        out.number(self.at_us);
        match &self.what {
            StepKind::Pipeline { pipeline } => {
                out.byte(STEP_PIPELINE);
                out.text(pipeline);
            }
            StepKind::Rule {
                pipeline,
                rule,
                phase,
                matched,
                decision,
                target,
            } => {
                out.byte(STEP_RULE);
                out.text(pipeline);
                out.text(rule);
                out.byte(phase_code(*phase));
                out.byte(matched.map_or(0, |matched| u8::from(matched) + 1));
                out.byte(decision.map_or(0, |decision| decision_code(decision) + 1));
                out.optional_text(target.as_deref());
            }
            StepKind::Decision {
                pipeline,
                rule,
                phase,
                decision,
                target,
            } => {
                out.byte(STEP_DECISION);
                out.text(pipeline);
                out.optional_text(rule.as_deref());
                out.byte(phase_code(*phase));
                out.byte(decision_code(*decision));
                out.optional_text(target.as_deref());
            }
            StepKind::Cache { result, source } => {
                out.byte(STEP_CACHE);
                out.byte(result.map_or(0, |result| cache_code(result) + 1));
                out.optional_text(source.as_deref());
            }
            StepKind::Joined => out.byte(STEP_JOINED),
            StepKind::Upstream {
                upstream,
                transport,
                via,
                result,
                latency_us,
                rcode,
                error,
            } => {
                out.byte(STEP_UPSTREAM);
                out.text(upstream);
                out.byte(transport_code(*transport));
                out.byte(transport_code(*via));
                out.byte(upstream_outcome_code(*result));
                out.number(*latency_us);
                out.optional_number(rcode.map(|rcode| u64::from(u16::from(rcode))));
                out.optional_text(error.as_deref());
            }
            StepKind::UpstreamSkipped {
                upstream,
                transport,
                reason,
            } => {
                out.byte(STEP_UPSTREAM_SKIPPED);
                out.text(upstream);
                out.byte(transport_code(*transport));
                out.byte(skip_reason_code(*reason));
            }
        }
    }
}

/// 编好的一条记录写成一行 JSON：字段的顺序固定，空着的不写；`steps_truncated` 只在截断时写。字节是这个进程自己
/// 编的，读不通只会是程序写错了，交回 None
/// Writes an encoded record as one line of JSON: the fields come in a fixed order and empty ones are left
/// out; `steps_truncated` appears only when the steps were cut. The bytes were encoded by this process, so
/// failing to read them can only be a bug, and gives None
fn write_record(seq: u64, record: &[u8], json: &mut Json) -> Option<()> {
    let mut input = Decoder(record);
    json.raw("{\"seq\":");
    json.number(seq);
    json.key("time_unix_ms");
    json.number(input.number()?);
    json.key("client");
    json.address(input.address()?);
    if let Some(transport) = input.optional_code(client_transport_of)? {
        json.key("transport");
        json.label(client_transport_label(transport));
    }
    json.key("qname");
    json.text(input.text()?);
    json.key("qtype");
    json.text(input.text()?);
    json.key("latency_us");
    json.number(input.number()?);
    json.key("status");
    json.label(status_of(input.byte()?)?.label());
    json.key("outcome");
    json.label(outcome_of(input.byte()?)?.label());
    if let Some(rcode) = input.rcode()? {
        json.key("rcode");
        json.label(&rcode_name(rcode));
    }
    json.key("answers");
    json.raw("[");
    for index in 0..input.number()? {
        if index > 0 {
            json.raw(",");
        }
        match input.byte()? {
            ANSWER_V4 => json.ipv4(Ipv4Addr::from(input.octets::<4>()?)),
            ANSWER_V6 => json.address(IpAddr::V6(Ipv6Addr::from(input.octets::<16>()?))),
            ANSWER_TEXT => json.text(input.text()?),
            _ => return None,
        }
    }
    json.raw("]");
    for key in ["error", "pipeline", "rule", "upstream"] {
        if let Some(text) = input.optional_text()? {
            json.key(key);
            json.text(text);
        }
    }
    json.key("steps");
    json.raw("[");
    for index in 0..input.number()? {
        if index > 0 {
            json.raw(",");
        }
        write_step(&mut input, json)?;
    }
    json.raw("]");
    if input.byte()? != 0 {
        json.key("steps_truncated");
        json.raw("true");
    }
    json.raw("}");
    input.0.is_empty().then_some(())
}

/// 编好的一步写成 JSON / Writes one encoded step as JSON
fn write_step(input: &mut Decoder<'_>, json: &mut Json) -> Option<()> {
    json.raw("{\"at_us\":");
    json.number(input.number()?);
    json.key("kind");
    match input.byte()? {
        STEP_PIPELINE => {
            json.label("pipeline");
            json.key("pipeline");
            json.text(input.text()?);
        }
        STEP_RULE => {
            json.label("rule");
            json.key("pipeline");
            json.text(input.text()?);
            json.key("rule");
            json.text(input.text()?);
            json.key("phase");
            json.label(phase_label(phase_of(input.byte()?)?));
            match input.byte()? {
                0 => {}
                1 => {
                    json.key("matched");
                    json.raw("false");
                }
                2 => {
                    json.key("matched");
                    json.raw("true");
                }
                _ => return None,
            }
            if let Some(decision) = input.optional_code(decision_of)? {
                json.key("decision");
                json.label(decision_label(decision));
            }
            if let Some(target) = input.optional_text()? {
                json.key("target");
                json.text(target);
            }
        }
        STEP_DECISION => {
            json.label("decision");
            json.key("pipeline");
            json.text(input.text()?);
            if let Some(rule) = input.optional_text()? {
                json.key("rule");
                json.text(rule);
            }
            json.key("phase");
            json.label(phase_label(phase_of(input.byte()?)?));
            json.key("decision");
            json.label(decision_label(decision_of(input.byte()?)?));
            if let Some(target) = input.optional_text()? {
                json.key("target");
                json.text(target);
            }
        }
        STEP_CACHE => {
            json.label("cache");
            json.key("result");
            json.label(input.optional_code(cache_of)?.map_or("miss", cache_label));
            if let Some(source) = input.optional_text()? {
                json.key("source");
                json.text(source);
            }
        }
        STEP_JOINED => json.label("joined"),
        STEP_UPSTREAM => {
            json.label("upstream");
            json.key("upstream");
            json.text(input.text()?);
            json.key("transport");
            json.label(transport_label(transport_of(input.byte()?)?));
            json.key("via");
            json.label(transport_label(transport_of(input.byte()?)?));
            json.key("result");
            json.label(outcome_label(upstream_outcome_of(input.byte()?)?));
            json.key("latency_us");
            json.number(input.number()?);
            if let Some(rcode) = input.rcode()? {
                json.key("rcode");
                json.label(&rcode_name(rcode));
            }
            if let Some(error) = input.optional_text()? {
                json.key("error");
                json.text(error);
            }
        }
        STEP_UPSTREAM_SKIPPED => {
            json.label("upstream_skipped");
            json.key("upstream");
            json.text(input.text()?);
            json.key("transport");
            json.label(transport_label(transport_of(input.byte()?)?));
            json.key("reason");
            json.label(skip_reason_label(skip_reason_of(input.byte()?)?));
        }
        _ => return None,
    }
    json.raw("}");
    Some(())
}

/// 拼一页 JSON。键名和内核自己的标签（`udp`、`forward`、`success`……）原样写；外来的文字（域名、配置里的名字、
/// 错误、回答）照 serde_json 的规矩转义，数字也由它写。不先建 JSON 树，也不走通用的序列化
/// Builds a page of JSON. Keys and the kernel's own labels (`udp`, `forward`, `success`, …) go in as
/// they are; outside text (domain names, names from the config, errors, answers) is escaped by
/// serde_json's rules, and numbers are written by it too. No JSON tree is built, and no generic
/// serialization is gone through
struct Json(Vec<u8>);

impl Json {
    fn raw(&mut self, text: &str) {
        self.0.extend_from_slice(text.as_bytes());
    }

    /// 下一个字段的键：前面总有别的字段，所以先写逗号 / The next field's key: another field always comes
    /// before, so a comma goes first
    fn key(&mut self, key: &str) {
        self.raw(",\"");
        self.raw(key);
        self.raw("\":");
    }

    /// 内核自己的标签：只有小写字母、数字和下划线，不用转义 / A label of the kernel's own: lower-case
    /// letters, digits and underscores only, which need no escaping
    fn label(&mut self, label: &str) {
        self.raw("\"");
        self.raw(label);
        self.raw("\"");
    }

    fn text(&mut self, text: &str) {
        // 写进 Vec 不会失败 / Writing into a Vec cannot fail
        let _ =
            serde::Serializer::serialize_str(&mut serde_json::Serializer::new(&mut self.0), text);
    }

    fn number(&mut self, number: u64) {
        let _ =
            serde::Serializer::serialize_u64(&mut serde_json::Serializer::new(&mut self.0), number);
    }

    /// 地址的写法和 `Display` 一样，只有数字、字母、点和冒号 / An address as `Display` writes it: digits,
    /// letters, dots and colons only
    fn address(&mut self, address: IpAddr) {
        use std::io::Write as _;
        match address {
            IpAddr::V4(address) => self.ipv4(address),
            IpAddr::V6(address) => {
                let _ = write!(self.0, "\"{address}\"");
            }
        }
    }

    /// IPv4 地址一位位写出来，和 `Display` 一样，不经格式化那一套 / An IPv4 address written digit by digit, as
    /// `Display` writes it, without the formatting machinery
    fn ipv4(&mut self, address: Ipv4Addr) {
        self.0.push(b'"');
        for (index, octet) in address.octets().into_iter().enumerate() {
            if index > 0 {
                self.0.push(b'.');
            }
            if octet >= 100 {
                self.0.push(b'0' + octet / 100);
            }
            if octet >= 10 {
                self.0.push(b'0' + octet / 10 % 10);
            }
            self.0.push(b'0' + octet % 10);
        }
        self.0.push(b'"');
    }
}

/// 一段在等着取；放下时不再算它，`wake_at` 换成还在等的里最小的
/// A take waiting for its range; dropping it stops counting it, and `wake_at` becomes the smallest number still waited
/// for
struct Waiting<'a> {
    log: &'a QueryLog,
    target: u64,
}

impl<'a> Waiting<'a> {
    fn new(log: &'a QueryLog, target: u64) -> Self {
        let mut waiting = log.waiting.lock();
        waiting.push(target);
        log.wake_at.fetch_min(target, Ordering::Relaxed);
        Self { log, target }
    }
}

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        let mut waiting = self.log.waiting.lock();
        if let Some(at) = waiting.iter().position(|target| *target == self.target) {
            waiting.swap_remove(at);
        }
        let smallest = waiting.iter().copied().min().unwrap_or(u64::MAX);
        self.log.wake_at.store(smallest, Ordering::Relaxed);
    }
}

impl Pending {
    fn push(&mut self, what: StepKind) {
        if self.steps.len() >= MAX_STEPS {
            self.steps_truncated = true;
            return;
        }
        let at_us = if self.at_once {
            0
        } else {
            u64::try_from(self.started.elapsed().as_micros()).unwrap_or(u64::MAX)
        };
        self.steps.push(Step { at_us, what });
    }
}

impl Default for QueryLog {
    fn default() -> Self {
        Self::with_capacity(CAPACITY)
    }
}

/// 一份日志的标识：随机取的 1 到 2^53−1（写进 JSON 是个整数，谁读都装得下）。面板拿它认出内核重启过、手里的位置
/// 作废。以前用的是启动时刻的毫秒数：没有时钟电池的设备每次开机时钟从同一个时刻走起，两次启动撞上同一毫秒时面板
/// 认不出重启，它手里那个超前的位置会让内核把交接区里的记录当成已经存好的删掉
/// A log's identity: a random number from 1 to 2^53−1 (a whole number in JSON that any reader
/// holds). The panel knows by it that the kernel restarted and the position it holds is void. It
/// used to be the start time in milliseconds: on a device without a clock battery the clock
/// starts from the same moment at every boot, and with two starts on the same millisecond the
/// panel saw no restart, and the position it held, ahead of the new log, had the kernel delete
/// the records in the ring as already stored
fn new_instance() -> u64 {
    (rand::random::<u64>() >> 11).max(1)
}

/// 记录类型写成什么：有名字的照 hickory `Display` 的写法，不分配字符串；没有名字的写成 `TYPE` 加类型号（RFC 3597
/// 第 5 节），写进 `buf`。以前没有名字的一律写成 `Unknown`，看不出问的是哪一种
/// How a record type is written: one with a name as hickory's `Display` writes it, with no
/// string allocated; one without as `TYPE` and its number (RFC 3597 section 5), written into
/// `buf`. One without a name used to be written `Unknown`, whichever type was asked
fn type_name(qtype: RecordType, buf: &mut [u8; 9]) -> &str {
    use std::io::Write;
    let RecordType::Unknown(number) = qtype else {
        return <&'static str>::from(qtype);
    };
    let mut rest = &mut buf[..];
    // `TYPE65535` 正好 9 个字节，写得下 / `TYPE65535` is exactly 9 bytes and fits
    let _ = write!(rest, "TYPE{number}");
    let left = rest.len();
    let written = buf.len() - left;
    std::str::from_utf8(&buf[..written]).unwrap_or("TYPE")
}

impl QueryLog {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            epoch: Instant::now(),
            instance: new_instance(),
            capacity,
            max_pending: MAX_PENDING,
            collected: AtomicU64::new(1),
            waiting: Mutex::new(Vec::new()),
            wake_at: AtomicU64::new(u64::MAX),
            arrived: tokio::sync::Notify::new(),
            untracked: AtomicU64::new(0),
            slots: (0..PENDING_SLOTS).map(|_| Mutex::new(None)).collect(),
            overflow: DashMap::new(),
            overflow_len: AtomicUsize::new(0),
            pending_count: AtomicUsize::new(0),
            ring: OwnLines(Mutex::new(Ring::new(RING_BYTES))),
            wall: WallClock::default(),
        }
    }

    fn since_epoch_ms(&self) -> u64 {
        self.ms_since_epoch(Instant::now())
    }

    fn ms_since_epoch(&self, now: Instant) -> u64 {
        u64::try_from(now.saturating_duration_since(self.epoch).as_millis()).unwrap_or(u64::MAX)
    }

    #[cfg(test)]
    fn recording(&self) -> bool {
        self.recording_after(self.collected.load(Ordering::Acquire), Instant::now())
    }

    /// 面板最近两分钟来取过（内核刚启动也算一次）。超过两分钟就停下并清空交接区（序号照旧往后数，面板回来时从空缺
    /// 看出漏了几条）。停下用比较交换：同时来取的面板赢。`collected` 是刚读到的那个数，`now` 是这个请求的时刻
    /// The panel collected within the last two minutes (start-up counting as one). Past two minutes
    /// recording stops and the ring is emptied (numbering carries on, so a returning panel sees from the
    /// gap how many it missed). Stopping uses compare-and-exchange, so a collection arriving at the same
    /// moment wins. `collected` is the value just read and `now` the request's moment
    fn recording_after(&self, collected: u64, now: Instant) -> bool {
        if collected == 0 {
            return false;
        }
        let idle = self.ms_since_epoch(now).saturating_sub(collected - 1);
        if idle < u64::try_from(IDLE_AFTER.as_millis()).unwrap_or(u64::MAX) {
            return true;
        }
        // 交换失败：要么面板刚来取过（接着记），要么别的请求已经停下了（不记）
        // The exchange failed: either the panel just collected (keep recording) or another request
        // already stopped it (do not record)
        if let Err(current) =
            self.collected
                .compare_exchange(collected, 0, Ordering::AcqRel, Ordering::Acquire)
        {
            return current != 0;
        }
        self.ring.lock().clear();
        false
    }

    #[inline]
    fn slot(&self, request_id: u64) -> &Slot {
        &self.slots[request_id as usize & (self.slots.len() - 1)]
    }

    /// 往在跟的请求的记录里写 / Writes into a tracked request's record
    fn with_pending(&self, ctx: &RequestContext<'_>, update: impl FnOnce(&mut Pending)) {
        if self.pending_count.load(Ordering::Relaxed) == 0 {
            return;
        }
        if let Some((id, pending)) = &mut *self.slot(ctx.request_id).lock()
            && *id == ctx.request_id
        {
            update(pending);
            return;
        }
        if self.overflow_len.load(Ordering::Relaxed) > 0
            && let Some(mut pending) = self.overflow.get_mut(&ctx.request_id)
        {
            update(&mut pending);
        }
    }

    /// 后台刷新和诊断查询不记：前者不是客户端的查询，后者是测试用的域名和指定的客户端 IP
    /// Background refreshes and diagnostic queries are not recorded: the former are not client
    /// queries, the latter carry test domains and an assigned client IP
    pub(crate) fn request_started(&self, ctx: &RequestContext<'_>, diagnostic: bool) {
        if ctx.background_refresh || diagnostic {
            return;
        }
        if !self.recording_after(self.collected.load(Ordering::Acquire), ctx.started) {
            return;
        }
        if self.pending_count.load(Ordering::Relaxed) >= self.max_pending {
            self.untracked.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let pending = Pending::start(ctx, self.wall.unix_ms_at(ctx.started));
        // 同一个请求号又开始一次时替换掉原来那条，不多算一条（和原先用共享表时一样）
        // The same request number starting again replaces its record without counting another (as
        // when a shared map held them all)
        let mut slot = self.slot(ctx.request_id).lock();
        match &*slot {
            None => {
                *slot = Some((ctx.request_id, pending));
                self.pending_count.fetch_add(1, Ordering::Relaxed);
            }
            Some((held, _)) if *held == ctx.request_id => {
                if let Some((_, replaced)) = slot.replace((ctx.request_id, pending)) {
                    replaced.release();
                }
            }
            Some(_) => {
                drop(slot);
                if self.overflow.insert(ctx.request_id, pending).is_none() {
                    self.overflow_len.fetch_add(1, Ordering::Relaxed);
                    self.pending_count.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    pub(crate) fn pipeline_selected(&self, ctx: &RequestContext<'_>, pipeline: &str) {
        self.with_pending(ctx, |pending| {
            let pipeline = ConfigName::of(pipeline);
            pending.pipeline = Some(pipeline.clone());
            pending.push(StepKind::Pipeline { pipeline });
        });
    }

    /// 回答后检查（响应阶段）的每条规则都记下，命中没命中都算：「没发现问题」也是处理过程的一步
    /// Every answer-check (response phase) rule is recorded, matched or not: 「nothing wrong」 is a
    /// step of the handling too
    pub(crate) fn rule_evaluated(&self, ctx: &RequestContext<'_>, event: &RuleEvaluated<'_>) {
        if event.phase != RulePhase::Response {
            return;
        }
        self.with_pending(ctx, |pending| {
            pending.push(StepKind::Rule {
                pipeline: ConfigName::of(event.pipeline),
                rule: ConfigName::of(event.rule),
                phase: RulePhase::Response,
                matched: Some(event.matched),
                decision: None,
                target: None,
            });
        });
    }

    /// 请求阶段命中的规则是一步。回答后检查的命中已经在评估时记了一步，这里先写上它要做什么
    /// （「继续往下」只有这一处说），实际的决定随后补上
    /// A request-phase match is a step. An answer check's match got its step when evaluated; this
    /// writes what it is set to do (the only place 「continue」 is told), and the actual decision follows
    pub(crate) fn rule_matched(&self, ctx: &RequestContext<'_>, event: &RuleMatched<'_>) {
        self.with_pending(ctx, |pending| {
            if event.phase != RulePhase::Request {
                if let Some(StepKind::Rule { decision, .. }) =
                    pending.steps.iter_mut().rev().map(|step| &mut step.what).find(|what| {
                        matches!(what, StepKind::Rule { pipeline, rule, phase: RulePhase::Response, decision: None, .. }
                            if **pipeline == *event.pipeline && **rule == *event.rule)
                    })
                {
                    *decision = Some(event.decision);
                }
                return;
            }
            pending.push(StepKind::Rule {
                pipeline: ConfigName::of(event.pipeline),
                rule: ConfigName::of(event.rule),
                phase: RulePhase::Request,
                matched: None,
                decision: Some(event.decision),
                target: None,
            });
        });
    }

    /// 决定补到定下它的那一步上（同一阶段、同一 Pipeline 的同一条规则，还没有去处的那一步）：跳去哪、
    /// 转发给谁、沿用了谁的回答；找不到那一步就单记一步
    /// A decision is added to the step that made it (the same phase, pipeline and rule, not yet given a
    /// target): where it jumps, whom it forwards to, whose answer it keeps; with no such step it becomes
    /// a step of its own
    pub(crate) fn decision_made(&self, ctx: &RequestContext<'_>, event: &DecisionMade<'_>) {
        self.with_pending(ctx, |pending| {
            let (kind, target): (DecisionKind, Option<ConfigName>) = match event.detail {
                DecisionDetail::Static { .. } => (DecisionKind::Static, None),
                DecisionDetail::Forward { upstream, .. } => {
                    (DecisionKind::Forward, Some(ConfigName::of(upstream)))
                }
                DecisionDetail::Jump { pipeline } => {
                    (DecisionKind::Jump, Some(ConfigName::of(pipeline)))
                }
            };
            pending.decision = Some((event.rule.map(ConfigName::of), kind));
            let phase = event.phase;
            // 只看这条规则最近的那一步：它是同一阶段、还没有去处时才补上。再往前的是更早的一轮
            // （比如跳回同一个列表之前），不能把这次的决定挂到那里
            // Only the rule's latest step is considered: the decision is added when that step is of the
            // same phase and has no target yet. Anything older belongs to an earlier pass (before a jump
            // back into the same list, say) and must not take this decision
            let step = event.rule.and_then(|decided| {
                pending
                    .steps
                    .iter_mut()
                    .rev()
                    .find_map(|step| match &mut step.what {
                        StepKind::Rule {
                            pipeline,
                            rule,
                            phase: step_phase,
                            decision,
                            target: slot,
                            ..
                        } if **pipeline == *event.pipeline && **rule == *decided => Some(
                            (*step_phase == phase && slot.is_none()).then_some((decision, slot)),
                        ),
                        _ => None,
                    })
                    .flatten()
            });
            match step {
                Some((decision, slot)) => {
                    *decision = Some(kind);
                    *slot = target;
                }
                None => pending.push(StepKind::Decision {
                    pipeline: ConfigName::of(event.pipeline),
                    rule: event.rule.map(ConfigName::of),
                    phase,
                    decision: kind,
                    target,
                }),
            }
        });
    }

    pub(crate) fn cache_hit(&self, ctx: &RequestContext<'_>, event: &CacheHit<'_>) {
        self.with_pending(ctx, |pending| {
            let source = event.source.map(ConfigName::of);
            pending.cache = Some(event.kind);
            pending.cache_source.clone_from(&source);
            pending.push(StepKind::Cache {
                result: Some(event.kind),
                source,
            });
        });
    }

    pub(crate) fn cache_miss(&self, ctx: &RequestContext<'_>) {
        self.with_pending(ctx, |pending| {
            pending.push(StepKind::Cache {
                result: None,
                source: None,
            });
        });
    }

    pub(crate) fn inflight_joined(&self, ctx: &RequestContext<'_>) {
        self.with_pending(ctx, |pending| {
            pending.joined = true;
            pending.push(StepKind::Joined);
        });
    }

    pub(crate) fn upstream_result(&self, ctx: &RequestContext<'_>, event: &UpstreamResult<'_>) {
        self.with_pending(ctx, |pending| {
            let upstream = ConfigName::of(event.upstream);
            if event.outcome == UpstreamOutcome::Success {
                pending.answered_by = Some(upstream.clone());
            }
            pending.push(StepKind::Upstream {
                upstream,
                transport: event.transport,
                via: event.via,
                result: event.outcome,
                latency_us: u64::try_from(event.latency.as_micros()).unwrap_or(u64::MAX),
                rcode: event.rcode,
                error: event.error.map(|error| clip(&format!("{error:#}")).into()),
            });
        });
    }

    pub(crate) fn upstream_skipped(&self, ctx: &RequestContext<'_>, event: &UpstreamSkipped<'_>) {
        self.with_pending(ctx, |pending| {
            pending.push(StepKind::UpstreamSkipped {
                upstream: ConfigName::of(event.upstream),
                transport: event.transport,
                reason: event.reason,
            });
        });
    }

    pub(crate) fn request_finished(&self, ctx: &RequestContext<'_>, outcome: &RequestOutcome<'_>) {
        if self.pending_count.load(Ordering::Relaxed) == 0 {
            return;
        }
        let pending = {
            let mut slot = self.slot(ctx.request_id).lock();
            match &*slot {
                Some((id, _)) if *id == ctx.request_id => slot.take().map(|(_, pending)| pending),
                _ => None,
            }
        };
        let pending = pending.or_else(|| {
            if self.overflow_len.load(Ordering::Relaxed) == 0 {
                return None;
            }
            let (_, pending) = self.overflow.remove(&ctx.request_id)?;
            self.overflow_len.fetch_sub(1, Ordering::Relaxed);
            Some(pending)
        });
        let Some(pending) = pending else {
            return;
        };
        self.pending_count.fetch_sub(1, Ordering::Relaxed);
        ENCODING.with_borrow_mut(|encoding| {
            encoding.clear();
            pending.encode(outcome, encoding);
            self.push(encoding);
        });
        pending.release();
    }

    /// 快速路径用缓存答的请求，一次记完（见 [`crate::observe::EngineObserver::answered_from_cache`]）。这之前没有
    /// 在跟它，也就用不着槽位、记录结构和配置名那张表，名字直接从引擎借来编进去。两步都没等过什么，时刻记 0
    /// A request the fast path answered from the cache, recorded in one go (see
    /// [`crate::observe::EngineObserver::answered_from_cache`]). It was never tracked, so it needs no slot, record
    /// structure or table of config names, and the names are borrowed from the engine and encoded directly.
    /// Neither step waited for anything, and both have 0 for their time
    pub(crate) fn answered_from_cache(
        &self,
        ctx: &RequestContext<'_>,
        pipeline: &str,
        hit: &CacheHit<'_>,
        outcome: &RequestOutcome<'_>,
    ) {
        if !self.recording_after(self.collected.load(Ordering::Acquire), ctx.started) {
            return;
        }
        let steps = [
            Step {
                at_us: 0,
                what: StepKind::Pipeline { pipeline },
            },
            Step {
                at_us: 0,
                what: StepKind::Cache {
                    result: Some(hit.kind),
                    source: hit.source,
                },
            },
        ];
        ENCODING.with_borrow_mut(|encoding| {
            encoding.clear();
            encode_record(
                &RecordHead {
                    time_unix_ms: self.wall.unix_ms_at(ctx.started),
                    client: ctx.client.ip().to_canonical(),
                    transport: ctx.transport,
                    qname: ctx.qname,
                    qtype: ctx.qtype,
                    pipeline: Some(pipeline),
                    rule: None,
                },
                outcome,
                |status, _| {
                    let result = cached_outcome(status, Some(hit.kind));
                    let cached = matches!(result, Outcome::Cached | Outcome::Stale);
                    (result, hit.source.filter(|_| cached))
                },
                &steps,
                false,
                encoding,
            );
            self.push(encoding);
        });
    }

    /// 快速路径上规则直接答的请求，一次记完，道理同 [`Self::answered_from_cache`]。命中的规则各记一步，定下回答的
    /// 那条是静态决定，别的是接着往下；没有规则定下时是 Pipeline 默认的决定，单记一步
    /// A request a rule answered on the fast path, recorded in one go for the reasons of
    /// [`Self::answered_from_cache`]. Each matched rule has a step: the one that decided has the static
    /// decision and the others carry on; with no rule deciding, the pipeline's default is a step of its own
    pub(crate) fn answered_by_rule(
        &self,
        ctx: &RequestContext<'_>,
        pipeline: &str,
        answer: &RuleAnswer<'_>,
        outcome: &RequestOutcome<'_>,
    ) {
        if !self.recording_after(self.collected.load(Ordering::Acquire), ctx.started) {
            return;
        }
        let step = |what| Step { at_us: 0, what };
        let mut steps: SmallVec<[Step<&str>; 6]> = SmallVec::new();
        steps.push(step(StepKind::Pipeline { pipeline }));
        steps.push(step(StepKind::Cache {
            result: None,
            source: None,
        }));
        for (at, rule) in answer.rules.iter().enumerate() {
            steps.push(step(StepKind::Rule {
                pipeline,
                rule,
                phase: RulePhase::Request,
                matched: None,
                decision: Some(if answer.decided_by_rule && at + 1 == answer.rules.len() {
                    DecisionKind::Static
                } else {
                    DecisionKind::Continue
                }),
                target: None,
            }));
        }
        if !answer.decided_by_rule {
            steps.push(step(StepKind::Decision {
                pipeline,
                rule: None,
                phase: RulePhase::Request,
                decision: DecisionKind::Static,
                target: None,
            }));
        }
        ENCODING.with_borrow_mut(|encoding| {
            encoding.clear();
            encode_record(
                &RecordHead {
                    time_unix_ms: self.wall.unix_ms_at(ctx.started),
                    client: ctx.client.ip().to_canonical(),
                    transport: ctx.transport,
                    qname: ctx.qname,
                    qtype: ctx.qtype,
                    pipeline: Some(pipeline),
                    rule: answer
                        .decided_by_rule
                        .then(|| answer.rules.last().copied())
                        .flatten(),
                },
                outcome,
                |status, rcode| (rule_outcome(status, rcode), None),
                &steps,
                false,
                encoding,
            );
            self.push(encoding);
        });
    }

    /// 编好的记录放进交接区，序号是它的位置 / Puts an encoded record into the ring; its number is its
    /// place
    fn push(&self, record: &[u8]) {
        let pushed = {
            let mut ring = self.ring.lock();
            ring.push(record, self.capacity).then_some(ring.newest)
        };
        let Some(newest) = pushed else {
            self.untracked.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if newest >= self.wake_at.load(Ordering::Relaxed) {
            self.arrived.notify_waiters();
        }
    }

    /// 续上「面板在取」：没在记的话从现在起接着记 / Renews 「the panel is collecting」: recording resumes now if it had stopped
    fn renew(&self) {
        self.collected
            .store(self.since_epoch_ms().saturating_add(1), Ordering::Release);
    }

    /// 等到 `after` 之后攒满 `limit` 条（给了 `until` 时，到它为止的都有了也算满），或者过了 `wait`：面板这样等着取，
    /// 流量一来就取走，交接区不会满；空闲时也只隔 `wait` 来一次。游标是别的内核进程的就不等，马上回，面板好早点发现
    /// 内核换了
    /// Waits until `limit` records follow `after` (or, given `until`, every record up to it is there), or
    /// `wait` has passed: a panel waiting like this takes records as soon as traffic brings them, before the
    /// ring can fill, and comes only once per `wait` while things are quiet. A cursor of another kernel
    /// process gets no wait but an answer at once, so the panel soon finds out the kernel has changed
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(crate) async fn wait_for_page(
        &self,
        after: u64,
        limit: usize,
        until: Option<u64>,
        instance: Option<u64>,
        wait: Duration,
    ) {
        if instance.is_some_and(|instance| instance != self.instance) {
            return;
        }
        self.renew();
        let target = after
            .saturating_add(u64::try_from(limit).unwrap_or(u64::MAX))
            .min(until.unwrap_or(u64::MAX));
        let deadline = tokio::time::Instant::now() + wait;
        // 等完、或者面板中途断开（这个 future 被丢掉）都不再等这一段 / Done waiting, or the panel gone
        // midway (this future dropped), this range is no longer waited for
        let _waiting = Waiting::new(self, target);
        loop {
            // 先登记要等，再看够不够：看完之后到的那一条也叫得醒它
            // Register to wait before checking: a record arriving right after the check still wakes it
            let arrived = self.arrived.notified();
            tokio::pin!(arrived);
            arrived.as_mut().enable();
            if self.ring.lock().newest >= target
                || tokio::time::timeout_at(deadline, arrived).await.is_err()
            {
                break;
            }
        }
    }

    /// 取走 `after` 之后的记录（最多 `limit` 条；给了 `until` 时只到它为止，`querylog_until_v1`），同时续上「面板在取」，
    /// 交回这一页的页头和记录编好的字节，按面板要的写出来（见 [`TakenPage`]）。面板同时取着相邻的几段时，每段各管各的：前面被挤掉了一截，这一段
    /// 也不会越界交出下一段的记录，`missed` 只算这一段里不在了的。
    /// `instance` 是游标所属的内核进程：是这个进程的，面板存好了的就删掉。存好到哪由 `stored` 说
    /// （`querylog_stored_v1`：面板同时取着好几段，取到哪和存到哪不是一回事），没给 `stored` 时就是 `after`
    /// （游标在写好以后才往前挪）；`stored` 超过 `after` 时也只删到 `after`，还没取走的不删。没说是哪个进程的（面板
    /// 在探是哪个进程，或者面板不认 `querylog_wait_v1`）、或是别的进程的游标，一条不删
    /// Takes the records after `after` (at most `limit`, and with `until` none past it,
    /// `querylog_until_v1`), renews 「the panel is collecting」, and returns the page's head and its records'
    /// encoded bytes, written the way the panel asks for (see [`TakenPage`]). With a panel taking neighbouring ranges at once, each range keeps
    /// to itself: with a stretch before it pushed out, it never hands over the next range's records, and
    /// `missed` counts only what is gone from this one. `instance` is the kernel process
    /// the cursor belongs to: if it is this one, what the panel has stored is deleted. How far that goes is
    /// `stored` (`querylog_stored_v1`: a panel taking several ranges at once has taken further than it has
    /// stored), and `after` without it (the cursor moves only once a page is written); a `stored` past
    /// `after` still deletes only up to `after`, never what was not taken yet. A cursor of no stated
    /// process (the panel probing which process this is, or one that does not know `querylog_wait_v1`) or
    /// of another one deletes nothing
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(crate) fn take(
        &self,
        after: u64,
        limit: usize,
        until: Option<u64>,
        instance: Option<u64>,
        stored: Option<u64>,
        protocol_version: u8,
    ) -> TakenPage {
        self.renew();
        let stored_up_to = (instance == Some(self.instance))
            .then(|| stored.map_or(after, |stored| stored.min(after)));
        // 锁里只复制这一页的字节，写出来在锁外 / Only the page's bytes are copied under the lock; they are
        // written out outside it
        let mut records = Vec::with_capacity(limit.min(MAX_PAGE) * 128);
        let mut ends = Vec::with_capacity(limit.min(MAX_PAGE));
        let (first, oldest, newest) = {
            let mut ring = self.ring.lock();
            while let Some(up_to) = stored_up_to
                && ring.oldest().is_some_and(|oldest| oldest <= up_to)
            {
                ring.pop_front();
            }
            let oldest = ring.oldest();
            // 交接区里的序号是连续的（只从头上丢），所以 `after` 之后的第一条就在 `after - oldest + 1`
            // The ring's numbers are contiguous (it only drops from the front), so the first record
            // after `after` sits at `after - oldest + 1`
            let start = oldest.map_or(0, |oldest| after.saturating_add(1).saturating_sub(oldest));
            let first = oldest.map_or(0, |oldest| oldest + start);
            let positions = usize::try_from(start).unwrap_or(usize::MAX)..ring.len();
            for (at, _) in positions
                .zip(first..)
                .take_while(|(_, seq)| until.is_none_or(|until| *seq <= until))
                .take(limit)
            {
                records.extend_from_slice(ring.record(at));
                ends.push(records.len());
            }
            (first, oldest, ring.newest)
        };
        // 交接区空了（清空过，或从没记过）时，游标之后、到最新序号为止的都已不在
        // With the ring empty (emptied, or never written), everything after the cursor up to the newest
        // number is gone
        let first_kept = oldest.unwrap_or(newest.saturating_add(1));
        let missed = first_kept
            .saturating_sub(after.saturating_add(1))
            .min(until.map_or(u64::MAX, |until| until.saturating_sub(after)));
        // 交出的记录是连着的，接在不在了的那些后面：这一页管到哪儿，最新的还在它后面就是还有
        // The records handed over are contiguous and follow those that are gone: more remain when the newest
        // lies past where this page reaches
        let reached = after
            .saturating_add(missed)
            .saturating_add(u64::try_from(ends.len()).unwrap_or(u64::MAX));
        TakenPage {
            protocol_version,
            instance: self.instance,
            capacity: u64::try_from(self.capacity).unwrap_or(u64::MAX),
            newest,
            missed,
            untracked: self.untracked.load(Ordering::Relaxed),
            more: reached < newest,
            first,
            records,
            ends,
        }
    }
}

#[cfg(test)]
impl QueryLog {
    /// 取走一页写成 JSON，测试里用 / Takes a page as JSON, for the tests
    pub(crate) fn collect(
        &self,
        after: u64,
        limit: usize,
        until: Option<u64>,
        instance: Option<u64>,
        stored: Option<u64>,
        protocol_version: u8,
    ) -> String {
        self.take(after, limit, until, instance, stored, protocol_version)
            .json()
    }
}

/// 编好的记录交给面板时，二进制那种写法开头的几个字节：名字和版本 / The leading bytes of the binary way of
/// handing encoded records to the panel: a name and the version
const RECORDS_MAGIC: &[u8; 5] = b"KXQL\x01";

/// 取走的一页：页头那几项，和这一页记录编好的字节（`ends` 是每条的结尾）/ A page taken: its head items and its
/// records' encoded bytes (`ends` holds where each ends)
pub(crate) struct TakenPage {
    protocol_version: u8,
    instance: u64,
    capacity: u64,
    newest: u64,
    /// 序号在游标之后（给了 `until` 时到它为止）、已经被挤出交接区的条数 / Records numbered after the cursor
    /// (up to `until`, when given) that were already pushed out of the ring
    missed: u64,
    /// 没能记下的请求，自内核启动起累计 / Requests left unrecorded, cumulative since the kernel started
    untracked: u64,
    more: bool,
    /// 这一页第一条的序号 / The number of the page's first record
    first: u64,
    records: Vec<u8>,
    ends: Vec<usize>,
}

impl TakenPage {
    /// 这一页的记录：(序号, 编好的字节) / The page's records: (number, encoded bytes)
    fn each(&self) -> impl Iterator<Item = (u64, &[u8])> {
        let starts = std::iter::once(0).chain(self.ends.iter().copied());
        (self.first..)
            .zip(starts.zip(&self.ends))
            .map(|(seq, (start, &end))| (seq, &self.records[start..end]))
    }

    /// 写成 JSON（`querylog_v1`）：不先建中间的 JSON 树 / Written as JSON (`querylog_v1`), without building an
    /// intermediate JSON tree first
    pub(crate) fn json(&self) -> String {
        // 一条大约六七百字节，一次给够，免得边写边挪 / A record takes six or seven hundred bytes, so the room is
        // given at once instead of moving as it grows
        let mut json = Json(Vec::with_capacity(256 + self.ends.len() * 768));
        json.raw("{\"protocol_version\":");
        json.number(u64::from(self.protocol_version));
        json.key("instance");
        json.number(self.instance);
        json.key("capacity");
        json.number(self.capacity);
        json.key("newest_seq");
        json.number(self.newest);
        json.key("missed");
        json.number(self.missed);
        json.key("untracked");
        json.number(self.untracked);
        json.key("more");
        json.raw(if self.more { "true" } else { "false" });
        json.key("entries");
        json.raw("[");
        for (seq, record) in self.each() {
            if seq > self.first {
                json.raw(",");
            }
            let at = json.0.len();
            if write_record(seq, record, &mut json).is_none() {
                // 编好的记录读不回来只会是程序写错了：这一条只留序号，整页照样能读
                // An encoded record that does not read back can only be a bug: it keeps just its number,
                // and the page still reads
                tracing::error!(seq, "查询日志里有一条编好的记录读不回来");
                json.0.truncate(at);
                json.raw("{\"seq\":");
                json.number(seq);
                json.raw("}");
            }
        }
        json.raw("]}");
        // 写进去的都是完整的 UTF-8 / Everything written is whole UTF-8
        String::from_utf8(json.0).unwrap_or_default()
    }

    /// 写成二进制（`querylog_records_v1`）：[`RECORDS_MAGIC`]，页头那几项（变长整数，`more` 一个字节），第一条的
    /// 序号和条数，再是每条的长度和编好的字节。记录怎么编见 [`Pending::encode`]；交接区里的字节原样交出去，内核
    /// 不必再写成文字
    /// Written as binary (`querylog_records_v1`): [`RECORDS_MAGIC`], the head items (variable-length
    /// integers, `more` one byte), the first record's number and the count, then each record's length and
    /// encoded bytes. How a record is encoded is told at [`Pending::encode`]; the ring's bytes go out as
    /// they are, and the kernel no longer writes them as text
    pub(crate) fn records(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.records.len() + self.ends.len() * 2);
        out.extend_from_slice(RECORDS_MAGIC);
        let mut encoder = Encoder(&mut out);
        encoder.number(u64::from(self.protocol_version));
        encoder.number(self.instance);
        encoder.number(self.capacity);
        encoder.number(self.newest);
        encoder.number(self.missed);
        encoder.number(self.untracked);
        encoder.byte(u8::from(self.more));
        encoder.number(self.first);
        encoder.number(u64::try_from(self.ends.len()).unwrap_or(u64::MAX));
        for (_, record) in self.each() {
            encoder.number(u64::try_from(record.len()).unwrap_or(u64::MAX));
            encoder.0.extend_from_slice(record);
        }
        out
    }
}

/// 响应码和回答记录（只取记录的数据部分，最多 8 条）；解析不了就只读包头的响应码。
/// 结构过得了 [`crate::proto_utils::well_formed_reply`]（缓存靠的也是它）、前 8 条回答都是地址或名字的应答自己读：
/// 地址直接写出来，名字交给 hickory 的 `Name` 读，写出来和 hickory 整份解析的一字不差，省下整份解析；
/// 别的照旧整份解析
/// The response code and the answer records (data only, at most eight); when the message cannot be
/// parsed, only the header's response code is read. A reply whose structure passes
/// [`crate::proto_utils::well_formed_reply`] (which the cache relies on too) and whose first eight answers
/// are addresses or names is read here: addresses are written directly and names read by hickory's
/// `Name`, word for word what hickory's whole parse writes, without that parse; anything else is still
/// parsed whole
fn read_response(bytes: &[u8]) -> (Option<ResponseCode>, Answers) {
    if crate::proto_utils::well_formed_reply(bytes)
        && let Some(read) = read_plain_response(bytes)
    {
        return read;
    }
    read_whole_response(bytes)
}

fn read_whole_response(bytes: &[u8]) -> (Option<ResponseCode>, Answers) {
    match Message::from_vec(bytes) {
        Ok(message) => (
            Some(message.metadata.response_code),
            message
                .answers
                .iter()
                .take(MAX_ANSWERS)
                .map(|record| match &record.data {
                    RData::A(address) => Answer::V4(address.0),
                    RData::AAAA(address) => Answer::V6(address.0),
                    data => Answer::Text(clip_owned(data.to_string())),
                })
                .collect(),
        ),
        Err(_) => (crate::observe::header_rcode(bytes), Answers::new()),
    }
}

/// 结构已经检查过的应答：响应码（加上 EDNS 里的高位，和 hickory 一样）和前 8 条回答。回答里有地址、名字以外的
/// 类型时为 None，交给 hickory
/// A reply whose structure is already checked: the response code (with the high bits from EDNS, as hickory
/// merges them) and the first eight answers. None when an answer is of a type other than an address or a
/// name, which is left to hickory
fn read_plain_response(packet: &[u8]) -> Option<(Option<ResponseCode>, Answers)> {
    let count = |at: usize| {
        packet
            .get(at..at + 2)
            .map(|n| usize::from(u16::from_be_bytes([n[0], n[1]])))
    };
    let answers = count(6)?;
    let additional_from = answers + count(8)?;
    let records = additional_from + count(10)?;
    let mut pos = 12;
    for _ in 0..count(4)? {
        pos = name_end(packet, pos)?.checked_add(4)?;
    }
    let mut texts = Answers::new();
    let mut high = 0;
    for index in 0..records {
        pos = name_end(packet, pos)?;
        let header = packet.get(pos..pos.checked_add(10)?)?;
        let rr_type = u16::from_be_bytes([header[0], header[1]]);
        let rdata = pos + 10;
        let end = rdata.checked_add(usize::from(u16::from_be_bytes([header[8], header[9]])))?;
        let data = packet.get(rdata..end)?;
        if index < answers.min(MAX_ANSWERS) {
            let answer = match RecordType::from(rr_type) {
                RecordType::A => Answer::V4(Ipv4Addr::from(<[u8; 4]>::try_from(data).ok()?)),
                RecordType::AAAA => Answer::V6(Ipv6Addr::from(<[u8; 16]>::try_from(data).ok()?)),
                RecordType::CNAME | RecordType::NS | RecordType::PTR => {
                    let mut decoder = BinDecoder::new(packet).clone(u16::try_from(rdata).ok()?);
                    Answer::Text(clip_owned(Name::read(&mut decoder).ok()?.to_string()))
                }
                _ => return None,
            };
            texts.push(answer);
        } else if index >= additional_from && rr_type == u16::from(RecordType::OPT) {
            // OPT 的 TTL 第一个字节是扩展响应码的高位 / The first byte of OPT's TTL is the extended
            // response code's high bits
            high = header[4];
        }
        pos = end;
    }
    Some((Some(ResponseCode::from(high, packet[3] & 0x0F)), texts))
}

/// 一个名字在报文里结束的位置（压缩指针占两个字节，之后不再往下读） / Where a name ends in the message (a
/// compression pointer takes two bytes and ends it)
fn name_end(packet: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *packet.get(pos)?;
        match len {
            0 => return Some(pos + 1),
            _ if len & 0xC0 == 0xC0 => return Some(pos + 2),
            _ => pos += 1 + usize::from(len),
        }
    }
}

/// 响应码的助记名（NOERROR、NXDOMAIN……），和配置里写的一样 / The response code mnemonic
/// (NOERROR, NXDOMAIN, …), as written in the config
fn rcode_name(code: u16) -> Cow<'static, str> {
    match code {
        0 => Cow::Borrowed("NOERROR"),
        1 => Cow::Borrowed("FORMERR"),
        2 => Cow::Borrowed("SERVFAIL"),
        3 => Cow::Borrowed("NXDOMAIN"),
        4 => Cow::Borrowed("NOTIMP"),
        5 => Cow::Borrowed("REFUSED"),
        6 => Cow::Borrowed("YXDOMAIN"),
        7 => Cow::Borrowed("YXRRSET"),
        8 => Cow::Borrowed("NXRRSET"),
        9 => Cow::Borrowed("NOTAUTH"),
        10 => Cow::Borrowed("NOTZONE"),
        other => Cow::Owned(format!("RCODE{other}")),
    }
}

fn decision_label(kind: DecisionKind) -> &'static str {
    match kind {
        DecisionKind::Static => "static",
        DecisionKind::Forward => "forward",
        DecisionKind::Jump => "jump",
        DecisionKind::Continue => "continue",
    }
}

fn cache_label(kind: CacheHitKind) -> &'static str {
    match kind {
        CacheHitKind::Fresh => "fresh",
        CacheHitKind::Stale => "stale",
        CacheHitKind::StaleClientTimeout => "stale_timeout",
        CacheHitKind::StaleUpstreamFailure => "stale_failure",
    }
}

fn client_transport_label(transport: ClientTransport) -> &'static str {
    match transport {
        ClientTransport::Udp => "udp",
        ClientTransport::Tcp => "tcp",
        ClientTransport::Doh => "doh",
    }
}

/// 截到 256 个字符（按字符，不切坏 UTF-8） / Cut to 256 characters (by character, never splitting UTF-8)
fn clip(text: &str) -> String {
    match text.char_indices().nth(MAX_TEXT) {
        Some((end, _)) => format!("{}…", &text[..end]),
        None => text.to_owned(),
    }
}

/// 同 [`clip`]，短的原样交回，不再复制一份 / As [`clip`], handing a short text back as it is without
/// copying it
fn clip_owned(text: String) -> String {
    match text.char_indices().nth(MAX_TEXT) {
        Some((end, _)) => format!("{}…", &text[..end]),
        None => text,
    }
}

/// 墙上时钟，由请求手里的单调时刻推算：每个请求都读一次墙上时钟太贵。每秒和系统对一次，系统时间被调过时最多错一秒
/// The wall clock worked out from the monotonic moment a request already holds: reading it for every
/// request costs too much. It is checked against the system once a second, so a change of the system time
/// is wrong for at most a second
pub(crate) struct WallClock {
    epoch: Instant,
    /// `epoch` 那一刻的墙上时间 / The wall time at `epoch`
    at_epoch_ms: AtomicU64,
    /// 下回对时的时刻，自 `epoch` 起的毫秒数 / When to check next, in milliseconds since `epoch`
    check_at_ms: AtomicU64,
}

impl Default for WallClock {
    fn default() -> Self {
        Self {
            epoch: Instant::now(),
            at_epoch_ms: AtomicU64::new(0),
            check_at_ms: AtomicU64::new(0),
        }
    }
}

impl WallClock {
    #[inline]
    pub(crate) fn unix_ms_at(&self, now: Instant) -> u64 {
        let since = u64::try_from(now.saturating_duration_since(self.epoch).as_millis())
            .unwrap_or(u64::MAX);
        if since >= self.check_at_ms.load(Ordering::Relaxed) {
            self.check();
        }
        self.at_epoch_ms
            .load(Ordering::Relaxed)
            .saturating_add(since)
    }

    #[cold]
    fn check(&self) {
        let since = u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.at_epoch_ms
            .store(unix_ms().saturating_sub(since), Ordering::Relaxed);
        self.check_at_ms
            .store(since.saturating_add(1_000), Ordering::Relaxed);
    }
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::str::FromStr;
    use std::sync::atomic::Ordering::Relaxed;
    use std::time::{Duration, Instant};

    use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
    use serde_json::{Value, json};

    use super::{
        CAPACITY, ConfigName, IDLE_AFTER, KNOWN_NAMES, MAX_ANSWERS, MAX_PAGE, MAX_STEPS, MAX_TEXT,
        PENDING_SLOTS, QueryLog, RING_BYTES, WallClock, clip, read_response, read_whole_response,
        unix_ms,
    };
    use crate::config::Transport;
    use crate::observe::{
        CacheHit, CacheHitKind, ClientTransport, DecisionDetail, DecisionKind, DecisionMade,
        RequestContext, RequestOutcome, RequestStatus, RuleAnswer, RuleEvaluated, RuleMatched,
        RulePhase, UpstreamOutcome, UpstreamResult,
    };

    fn ctx(request_id: u64) -> RequestContext<'static> {
        RequestContext {
            request_id,
            listener_label: "default",
            client: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), 53_000),
            transport: Some(ClientTransport::Udp),
            qname: "www.example.com",
            qtype: RecordType::A,
            qclass: DNSClass::IN,
            background_refresh: false,
            started: Instant::now(),
            reported_at_once: false,
        }
    }

    fn response(rcode: ResponseCode, addresses: &[[u8; 4]]) -> Vec<u8> {
        let mut message = Message::new(1, MessageType::Response, OpCode::Query);
        message.metadata.response_code = rcode;
        let name = Name::from_str("www.example.com.").unwrap();
        for [a, b, c, d] in addresses {
            message.answers.push(Record::from_rdata(
                name.clone(),
                300,
                RData::A(A::new(*a, *b, *c, *d)),
            ));
        }
        message.to_vec().unwrap()
    }

    fn finish(
        log: &QueryLog,
        request: &RequestContext<'_>,
        status: RequestStatus,
        bytes: Option<&[u8]>,
    ) {
        log.request_finished(
            request,
            &RequestOutcome {
                latency: Duration::from_millis(21),
                status,
                response: bytes,
                error: (status == RequestStatus::Failed).then_some("engine failed"),
            },
        );
    }

    fn upstream(
        log: &QueryLog,
        request: &RequestContext<'_>,
        address: &str,
        outcome: UpstreamOutcome,
    ) {
        log.upstream_result(
            request,
            &UpstreamResult {
                upstream: address,
                transport: Transport::Udp,
                via: Transport::Udp,
                outcome,
                latency: Duration::from_millis(20),
                rcode: (outcome == UpstreamOutcome::Success).then_some(ResponseCode::NoError),
                truncated: None,
                error: None,
            },
        );
    }

    fn matched(log: &QueryLog, request: &RequestContext<'_>, rule: &str, decision: DecisionKind) {
        log.rule_matched(
            request,
            &RuleMatched {
                pipeline: "main",
                rule,
                phase: RulePhase::Request,
                decision,
                fast_path: false,
            },
        );
    }

    /// 回答检查照引擎的发法（`report_response_rule`）：先记判断，命中时再记它的动作要作的决定
    /// An answer check reported the way the engine does (`report_response_rule`): the verdict,
    /// then on a match the decision its actions lead to
    fn checked(
        log: &QueryLog,
        request: &RequestContext<'_>,
        rule: &str,
        on_match: Option<DecisionKind>,
    ) {
        log.rule_evaluated(
            request,
            &RuleEvaluated {
                pipeline: "main",
                rule,
                phase: RulePhase::Response,
                matched: on_match.is_some(),
                matchers: 1,
            },
        );
        if let Some(decision) = on_match {
            log.rule_matched(
                request,
                &RuleMatched {
                    pipeline: "main",
                    rule,
                    phase: RulePhase::Response,
                    decision,
                    fast_path: false,
                },
            );
        }
    }

    fn decide(
        log: &QueryLog,
        request: &RequestContext<'_>,
        rule: Option<&str>,
        phase: RulePhase,
        detail: DecisionDetail<'_>,
    ) {
        log.decision_made(
            request,
            &DecisionMade {
                pipeline: "main",
                rule,
                phase,
                detail,
            },
        );
    }

    const STATIC: DecisionDetail<'static> = DecisionDetail::Static {
        rcode: ResponseCode::NoError,
        answers: 1,
    };
    const FORWARD: DecisionDetail<'static> = DecisionDetail::Forward {
        upstream: "192.0.2.53:53",
        transport: Some(Transport::Udp),
    };

    /// 时钟起点在三分钟前的日志：「上次取」记的是起点之后的毫秒数，记成 1 就是三分钟前取过
    /// A log whose clock starts three minutes back: the last collection is stored as
    /// milliseconds after that start, so 1 means it was three minutes ago
    fn started_three_minutes_ago() -> QueryLog {
        QueryLog {
            epoch: Instant::now()
                .checked_sub(Duration::from_secs(180))
                .expect("the monotonic clock goes back three minutes"),
            ..QueryLog::default()
        }
    }

    fn page(log: &QueryLog, after: u64, limit: usize) -> Value {
        serde_json::from_str(&log.collect(after, limit, None, None, None, 1))
            .expect("a page is JSON")
    }

    /// 给的时刻往后几秒，算出来的墙上时间也往后几秒，不用读系统时间
    /// A moment some seconds on gives a wall time the same seconds on, with no read of the system time
    #[test]
    fn the_wall_clock_is_worked_out_from_the_moment_given() {
        let clock = WallClock::default();
        let now = Instant::now();
        let at = clock.unix_ms_at(now);
        assert!(unix_ms().abs_diff(at) < 2_000, "{at}");
        clock.check_at_ms.store(u64::MAX, Relaxed);
        clock.at_epoch_ms.fetch_add(7, Relaxed);
        assert_eq!(clock.unix_ms_at(now + Duration::from_secs(10)), at + 10_007);
    }

    /// 起点早就过了也一样，算出来的还是现在 / An epoch long past changes nothing: what comes out is still now
    #[test]
    fn the_wall_clock_holds_for_an_epoch_long_past() {
        let clock = WallClock {
            epoch: Instant::now() - Duration::from_secs(60),
            ..WallClock::default()
        };
        let at = clock.unix_ms_at(Instant::now());
        assert!(unix_ms().abs_diff(at) < 2_000, "{at}");
    }

    /// 系统时间被调过：一秒之内不再对时，过了一秒就对上了
    /// The system time changed: it is not checked again within the second, and it matches after that
    #[test]
    fn the_wall_clock_catches_a_changed_system_time_after_a_second() {
        const DAY_MS: u64 = 86_400_000;
        let clock = WallClock::default();
        let now = Instant::now();
        clock.unix_ms_at(now);
        clock.at_epoch_ms.fetch_sub(DAY_MS, Relaxed);
        assert!(unix_ms().abs_diff(clock.unix_ms_at(now)) > DAY_MS / 2);
        let later = clock.unix_ms_at(now + Duration::from_secs(2));
        assert!(unix_ms().abs_diff(later) < 10_000, "{later}");
    }

    /// 记录的时刻来自引擎读到的那一刻，不再读一次钟
    /// A record's time comes from the moment the engine read, with no other read of the clock
    #[test]
    fn a_record_is_timed_from_the_moment_the_engine_read() {
        let log = QueryLog::default();
        let request = RequestContext {
            started: Instant::now() + Duration::from_secs(60),
            ..ctx(1)
        };
        log.request_started(&request, false);
        finish(&log, &request, RequestStatus::Completed, None);
        let time = entries(&log)[0]["time_unix_ms"].as_u64().unwrap();
        assert!((unix_ms() + 60_000).abs_diff(time) < 10_000, "{time}");
    }

    /// 是否还在记也按引擎读到的那一刻算 / Whether recording goes on is judged by that moment too
    #[test]
    fn whether_to_record_is_judged_by_the_moment_the_engine_read() {
        let log = QueryLog::default();
        let request = RequestContext {
            started: Instant::now() + IDLE_AFTER + Duration::from_secs(60),
            ..ctx(1)
        };
        log.request_started(&request, false);
        finish(&log, &request, RequestStatus::Completed, None);
        assert!(entries(&log).is_empty());
    }

    /// 答完才一次性上报的请求，几步的时刻都记 0，不为它们读钟；边走边报的照旧记真实的时刻。两种请求在同一个线程上
    /// 接着用同一份记录，上一个的这两项不能留下
    /// A request reported at once has 0 for each step's time, with no clock read for them; a request
    /// reported as it goes keeps the real times. Both reuse one record on this thread, and the last request's
    /// two items must not stay
    #[test]
    fn only_a_request_reported_at_once_goes_without_the_steps_times() {
        let log = QueryLog::default();
        let at_once = RequestContext {
            started: Instant::now(),
            reported_at_once: true,
            ..ctx(1)
        };
        let as_it_goes = RequestContext {
            started: Instant::now() - Duration::from_millis(50),
            reported_at_once: false,
            ..ctx(2)
        };
        for request in [&at_once, &as_it_goes, &at_once] {
            log.request_started(request, false);
            log.pipeline_selected(request, "main");
            finish(&log, request, RequestStatus::Completed, None);
        }
        let at_us: Vec<u64> = entries(&log)
            .iter()
            .map(|entry| entry["steps"][0]["at_us"].as_u64().unwrap())
            .collect();
        assert_eq!(at_us[0], 0);
        assert!(at_us[1] >= 50_000, "{at_us:?}");
        assert_eq!(at_us[2], 0);
    }

    /// 一次记完的记录和分开的事件记下的逐字节一样：各种客户端、传输、来源、缓存种类和结束方式
    /// A record made in one go is byte for byte what the separate events make, for every kind of
    /// client, transport, source, cache hit and ending
    #[test]
    fn a_cache_hit_recorded_whole_is_what_the_separate_events_record() {
        let log = QueryLog::default();
        // 两种写法的墙上时间要一样：对过一次就不再对 / Both ways must see one wall time: checked once and no more
        log.wall.unix_ms_at(Instant::now());
        log.wall.check_at_ms.store(u64::MAX, Relaxed);
        let ok = response(ResponseCode::NoError, &[[192, 0, 2, 1], [198, 51, 100, 23]]);
        let servfail = response(ResponseCode::ServFail, &[]);
        let completed = |bytes| (RequestStatus::Completed, Some(bytes), None);
        let endings = [
            completed(ok.as_slice()),
            completed(servfail.as_slice()),
            (RequestStatus::Failed, None, Some("engine failed")),
        ];
        let port = 53_000;
        let clients = [
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), port),
            SocketAddr::new(
                IpAddr::V6(Ipv4Addr::new(192, 0, 2, 7).to_ipv6_mapped()),
                port,
            ),
            SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), port),
        ];
        let mut compared = 0;
        for client in clients {
            for transport in [Some(ClientTransport::Udp), Some(ClientTransport::Doh), None] {
                for source in [Some("udp://192.0.2.53:53"), None] {
                    for kind in [CacheHitKind::Fresh, CacheHitKind::Stale] {
                        for (status, bytes, error) in endings {
                            let request = RequestContext {
                                client,
                                transport,
                                reported_at_once: true,
                                ..ctx(compared + 1)
                            };
                            let hit = CacheHit {
                                kind,
                                remaining_ttl: None,
                                original_ttl: None,
                                source,
                            };
                            let finished = RequestOutcome {
                                latency: Duration::from_micros(900),
                                status,
                                response: bytes,
                                error,
                            };
                            log.request_started(&request, false);
                            log.pipeline_selected(&request, "main");
                            log.cache_hit(&request, &hit);
                            log.request_finished(&request, &finished);
                            log.answered_from_cache(&request, "main", &hit, &finished);
                            let ring = log.ring.lock();
                            let last = ring.len() - 1;
                            assert_eq!(
                                ring.record(last - 1),
                                ring.record(last),
                                "{client} {source:?}"
                            );
                            compared += 1;
                        }
                    }
                }
            }
        }
        assert_eq!(compared, 108);
    }

    /// 规则直接答的请求一次记完，和引擎一个个发事件记下的逐字节一样：一条规则定的、规则缓存里几条规则命中、都没定而是
    /// Pipeline 默认的，各种响应码和结束方式
    /// A request a rule answered recorded in one go is byte for byte what the engine's separate events make:
    /// one rule deciding, several matched from the rule cache, none deciding and the pipeline's default, with
    /// every response code and ending
    #[test]
    fn a_rule_answer_recorded_whole_is_what_the_separate_events_record() {
        let log = QueryLog::default();
        log.wall.unix_ms_at(Instant::now());
        log.wall.check_at_ms.store(u64::MAX, Relaxed);
        let ok = response(ResponseCode::NoError, &[[192, 0, 2, 1]]);
        let nxdomain = response(ResponseCode::NXDomain, &[]);
        let servfail = response(ResponseCode::ServFail, &[]);
        let completed = |bytes| (RequestStatus::Completed, Some(bytes), None);
        let endings = [
            completed(ok.as_slice()),
            completed(nxdomain.as_slice()),
            completed(servfail.as_slice()),
            (RequestStatus::Failed, None, Some("engine failed")),
        ];
        let shapes: [(&[&str], bool); 6] = [
            (&["block"], true),
            (&["first", "second", "block"], true),
            (&["block", "block"], true),
            (&["first", "second"], false),
            (&["first"], false),
            (&[], false),
        ];
        let mut compared = 0;
        for (rules, decided_by_rule) in shapes {
            for (status, bytes, error) in endings {
                let request = RequestContext {
                    reported_at_once: true,
                    ..ctx(compared + 1)
                };
                let finished = RequestOutcome {
                    latency: Duration::from_micros(900),
                    status,
                    response: bytes,
                    error,
                };
                let rcode = ResponseCode::NXDomain;
                log.request_started(&request, false);
                log.pipeline_selected(&request, "main");
                log.cache_miss(&request);
                for (at, rule) in rules.iter().enumerate() {
                    log.rule_matched(
                        &request,
                        &RuleMatched {
                            pipeline: "main",
                            rule,
                            phase: RulePhase::Request,
                            decision: if decided_by_rule && at + 1 == rules.len() {
                                DecisionKind::Static
                            } else {
                                DecisionKind::Continue
                            },
                            fast_path: true,
                        },
                    );
                }
                log.decision_made(
                    &request,
                    &DecisionMade {
                        pipeline: "main",
                        rule: decided_by_rule.then(|| rules[rules.len() - 1]),
                        phase: RulePhase::Request,
                        detail: DecisionDetail::Static { rcode, answers: 0 },
                    },
                );
                log.request_finished(&request, &finished);
                log.answered_by_rule(
                    &request,
                    "main",
                    &RuleAnswer {
                        rules,
                        decided_by_rule,
                        rcode,
                        answers: 0,
                    },
                    &finished,
                );
                let ring = log.ring.lock();
                let last = ring.len() - 1;
                assert_eq!(
                    ring.record(last - 1),
                    ring.record(last),
                    "{rules:?} {status:?}"
                );
                compared += 1;
            }
        }
        assert_eq!(compared, 24);
    }

    /// 没人来取以后，规则回答这条路也不再记 / Once nobody collects, the way of recording a rule's answer stops too
    #[test]
    fn a_rule_answer_is_not_recorded_once_recording_has_stopped() {
        let log = started_three_minutes_ago();
        let finished = RequestOutcome {
            latency: Duration::from_micros(900),
            status: RequestStatus::Completed,
            response: None,
            error: None,
        };
        let answer = RuleAnswer {
            rules: &["block"],
            decided_by_rule: true,
            rcode: ResponseCode::NXDomain,
            answers: 0,
        };
        log.answered_by_rule(&ctx(1), "main", &answer, &finished);
        assert_eq!(log.ring.lock().newest, 0);
    }

    /// 没人来取以后，一次记完的这条路也不再记 / Once nobody collects, the way of recording in one go stops too
    #[test]
    fn a_cache_hit_is_not_recorded_once_recording_has_stopped() {
        let log = started_three_minutes_ago();
        let hit = CacheHit {
            kind: CacheHitKind::Fresh,
            remaining_ttl: None,
            original_ttl: None,
            source: None,
        };
        let finished = RequestOutcome {
            latency: Duration::from_micros(900),
            status: RequestStatus::Completed,
            response: None,
            error: None,
        };
        log.answered_from_cache(&ctx(1), "main", &hit, &finished);
        assert_eq!(log.ring.lock().newest, 0);
    }

    /// 一条命中的记录一百来字节时，先到的是字节上限，放得下的都留着：面板慢一下，每秒七十万条时也有一百来毫秒的余地
    /// With records of a hit's hundred or so bytes the byte limit comes first and all that fit are kept:
    /// should the panel slow down, there are a hundred milliseconds or so to spare even at seven hundred
    /// thousand records a second
    #[test]
    fn the_ring_is_limited_by_its_bytes_before_its_count() {
        let log = QueryLog::default();
        let record = [0u8; 110];
        let fit = RING_BYTES / record.len();
        assert!(fit < CAPACITY);
        for _ in 0..fit {
            log.push(&record);
        }
        assert_eq!(log.ring.lock().len(), fit);
        log.push(&record);
        assert_eq!(log.ring.lock().newest, u64::try_from(fit).unwrap() + 1);
        assert!(log.ring.lock().len() <= fit, "the oldest goes when full");
    }

    /// 带着这个内核进程的游标来取的一页 / A page taken with a cursor of this kernel process
    fn page_of_this_run(log: &QueryLog, after: u64, limit: usize) -> Value {
        serde_json::from_str(&log.collect(after, limit, None, Some(log.instance), None, 1))
            .expect("a page is JSON")
    }

    /// 面板来取一次（开始记），返回取到的记录 / The panel collects once (which starts recording) and
    /// gets the records
    fn entries(log: &QueryLog) -> Vec<Value> {
        page(log, 0, MAX_PAGE)["entries"]
            .as_array()
            .cloned()
            .unwrap_or_default()
    }

    /// 上游那一步写成面板认得的短名：六种传输（记下的和实际走的）、五种结果都是。读不出的应答，响应码
    /// 取报文头的低四位，不列答案
    /// An upstream step is written in the short names the panel reads: all six transports
    /// (the one recorded and the one actually used) and all five outcomes. For a response
    /// that cannot be read, the response code is the header's low four bits and no answer
    /// is listed
    #[test]
    fn every_transport_and_outcome_gets_its_short_name() {
        let transports = [
            (Transport::Udp, "udp"),
            (Transport::Tcp, "tcp"),
            (Transport::TcpUdp, "tcp_udp"),
            (Transport::Doh, "doh"),
            (Transport::Dot, "dot"),
            (Transport::Doq, "doq"),
        ];
        let outcomes = [
            (UpstreamOutcome::Success, "success"),
            (UpstreamOutcome::Rejected, "rejected"),
            (UpstreamOutcome::Error, "error"),
            (UpstreamOutcome::Aborted, "aborted"),
            (UpstreamOutcome::Throttled, "throttled"),
        ];
        let log = QueryLog::default();
        let _ = page(&log, 0, 1);
        let request = ctx(1);
        log.request_started(&request, false);
        log.pipeline_selected(&request, "main");
        for (index, (transport, _)) in transports.iter().enumerate() {
            log.upstream_result(
                &request,
                &UpstreamResult {
                    upstream: "192.0.2.53:53",
                    transport: *transport,
                    via: transports[(index + 1) % transports.len()].0,
                    outcome: outcomes[index % outcomes.len()].0,
                    latency: Duration::from_millis(20),
                    rcode: None,
                    truncated: None,
                    error: None,
                },
            );
        }
        // 只有六个字节，读不出；报文头说 NXDOMAIN / Six bytes only, unreadable; the header says NXDOMAIN
        finish(
            &log,
            &request,
            RequestStatus::Completed,
            Some(&[0x12, 0x34, 0x81, 0x83, 0x00, 0x01]),
        );

        let entry = entries(&log).pop().expect("one record");
        let steps: Vec<&Value> = entry["steps"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|step| step["kind"] == "upstream")
            .collect();
        assert_eq!(steps.len(), transports.len(), "{entry}");
        for (index, step) in steps.iter().enumerate() {
            assert_eq!(step["transport"], transports[index].1, "{step}");
            assert_eq!(
                step["via"],
                transports[(index + 1) % transports.len()].1,
                "{step}"
            );
            assert_eq!(step["result"], outcomes[index % outcomes.len()].1, "{step}");
        }
        assert_eq!(entry["rcode"], "NXDOMAIN", "{entry}");
        assert!(
            entry["answers"].as_array().is_none_or(Vec::is_empty),
            "{entry}"
        );
    }

    /// 客户端的三种传输也写成短名：udp、tcp、doh
    /// The client's three transports are written in short names too: udp, tcp, doh
    #[test]
    fn every_client_transport_gets_its_short_name() {
        let log = QueryLog::default();
        let _ = page(&log, 0, 1);
        let transports = [
            (ClientTransport::Udp, "udp"),
            (ClientTransport::Tcp, "tcp"),
            (ClientTransport::Doh, "doh"),
        ];
        for (index, (transport, _)) in transports.iter().enumerate() {
            let request = RequestContext {
                transport: Some(*transport),
                ..ctx(index as u64 + 1)
            };
            log.request_started(&request, false);
            finish(&log, &request, RequestStatus::Completed, None);
        }
        let written: Vec<Value> = entries(&log)
            .iter()
            .map(|entry| entry["transport"].clone())
            .collect();
        assert_eq!(
            written,
            transports
                .iter()
                .map(|(_, name)| Value::from(*name))
                .collect::<Vec<_>>()
        );
    }

    /// 请求结束时就读出应答，交接区里不存应答原文：短的照样读出全部回答，长的只留前 8 条
    /// The response is read when the request ends and the ring keeps no copy of it: a short one gives all its
    /// answers, a long one only the first eight
    #[test]
    fn responses_are_read_when_the_request_ends() {
        let log = QueryLog::default();
        let _ = page(&log, 0, 1);
        let short = response(ResponseCode::NoError, &[[192, 0, 2, 1], [192, 0, 2, 2]]);
        let many: Vec<[u8; 4]> = (0..200u8).map(|i| [198, 51, 100, i]).collect();
        let long = response(ResponseCode::NoError, &many);
        for (id, bytes) in [(1, &short), (2, &long)] {
            let request = ctx(id);
            log.request_started(&request, false);
            finish(&log, &request, RequestStatus::Completed, Some(bytes));
        }
        {
            let ring = log.ring.lock();
            assert!(
                (0..ring.len()).all(|at| ring.record(at).len() < 200),
                "the ring holds the encoded records, not the {}-byte response",
                long.len()
            );
        }
        let got = entries(&log);
        assert_eq!(
            got[0]["answers"],
            serde_json::json!(["192.0.2.1", "192.0.2.2"])
        );
        let long_answers = got[1]["answers"].as_array().expect("answers");
        assert_eq!(long_answers.len(), MAX_ANSWERS);
        assert_eq!(long_answers[0], "198.51.100.0");
        for entry in &got {
            assert_eq!(entry["rcode"], "NOERROR");
            assert_eq!(entry["outcome"], "forwarded");
        }
    }

    fn kinds(entry: &Value) -> Vec<String> {
        entry["steps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|step| step["kind"].as_str().unwrap().to_owned())
            .collect()
    }

    fn seqs(page: &Value) -> Vec<u64> {
        page["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["seq"].as_u64().unwrap())
            .collect()
    }

    fn cancelled(log: &QueryLog, ids: std::ops::RangeInclusive<u64>) {
        for id in ids {
            let request = ctx(id);
            log.request_started(&request, false);
            finish(log, &request, RequestStatus::Cancelled, None);
        }
    }

    /// 内核一启动就记：开机时内核比面板先起来，面板头一次来取时那几秒的查询都在
    /// Recording starts with the kernel: at boot the kernel comes up before the panel, and the
    /// queries of those seconds are there when the panel first collects
    #[test]
    fn recording_starts_with_the_kernel() {
        let log = QueryLog::default();
        assert!(log.recording(), "before any collection");
        let ok = response(ResponseCode::NoError, &[]);
        for id in 1..=2 {
            let request = ctx(id);
            log.request_started(&request, false);
            finish(&log, &request, RequestStatus::Completed, Some(&ok));
        }
        assert_eq!(entries(&log).len(), 2);
    }

    /// 内核启动两分钟里面板一直没来：照样停记，和面板走了以后一样
    /// No panel within two minutes of start-up: recording stops, as after a panel has gone
    #[test]
    fn without_a_panel_recording_stops_two_minutes_after_start_up() {
        let log = started_three_minutes_ago();
        assert!(!log.recording());
        assert_eq!(log.collected.load(Relaxed), 0);
    }

    fn quick_answers(log: &QueryLog, ids: std::ops::RangeInclusive<u64>) {
        let ok = response(ResponseCode::NoError, &[]);
        for id in ids {
            let request = ctx(id);
            log.request_started(&request, false);
            finish(log, &request, RequestStatus::Completed, Some(&ok));
        }
    }

    /// 等着取：交接区里已经够一页就不等 / Waiting to collect: with a page already in the ring there is no wait
    #[tokio::test]
    async fn a_full_page_is_taken_without_waiting() {
        let log = QueryLog::default();
        quick_answers(&log, 1..=5);
        let started = tokio::time::Instant::now();
        log.wait_for_page(0, 5, None, None, Duration::from_secs(5))
            .await;
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(log.wake_at.load(Relaxed), u64::MAX, "no one waits any more");
    }

    /// 攒不满一页时等着，攒满的那一刻就回，不等到时限
    /// Short of a page it waits, and returns the moment the page fills rather than at the deadline
    #[tokio::test]
    async fn a_waiting_panel_is_woken_when_the_page_fills() {
        let log = std::sync::Arc::new(QueryLog::default());
        quick_answers(&log, 1..=2);
        let filling = std::sync::Arc::clone(&log);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            quick_answers(&filling, 3..=4);
        });
        let started = tokio::time::Instant::now();
        log.wait_for_page(0, 4, None, Some(log.instance), Duration::from_secs(5))
            .await;
        let waited = started.elapsed();
        assert!(waited >= Duration::from_millis(100), "{waited:?}");
        assert!(waited < Duration::from_secs(2), "{waited:?}");
        assert_eq!(seqs(&page(&log, 0, 4)), [1, 2, 3, 4]);
    }

    /// 面板等到一半断开了：也算没人等了，之后的记录不再去叫它 / The panel gone midway through a wait no
    /// longer counts as waiting, and later records do not try to wake it
    #[tokio::test]
    async fn a_wait_given_up_midway_is_no_longer_waiting() {
        let log = QueryLog::default();
        let given_up = tokio::time::timeout(
            Duration::from_millis(50),
            log.wait_for_page(0, 5, None, None, Duration::from_secs(5)),
        )
        .await;
        assert!(given_up.is_err());
        assert_eq!(log.wake_at.load(Relaxed), u64::MAX);
    }

    /// 游标是别的内核进程的：不等，马上回 / A cursor of another kernel process: no wait, an answer at once
    #[tokio::test]
    async fn a_cursor_of_another_run_is_answered_at_once() {
        let log = QueryLog::default();
        let started = tokio::time::Instant::now();
        log.wait_for_page(0, 5, None, Some(log.instance + 1), Duration::from_secs(5))
            .await;
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    /// 一直攒不满就到时限回，交来手上有的；只差几条的到来不会把它提前叫醒
    /// Never filling, it returns at the deadline with what there is; records short of the page do not
    /// wake it early
    #[tokio::test]
    async fn a_waiting_panel_returns_at_the_deadline() {
        let log = std::sync::Arc::new(QueryLog::default());
        let trickle = std::sync::Arc::clone(&log);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            quick_answers(&trickle, 1..=1);
        });
        let started = tokio::time::Instant::now();
        log.wait_for_page(0, 100, None, None, Duration::from_millis(400))
            .await;
        let waited = started.elapsed();
        assert!(waited >= Duration::from_millis(400), "{waited:?}");
        assert_eq!(seqs(&page(&log, 0, 100)), [1]);
    }

    /// 面板带着这个内核进程的游标来取：`after` 说明之前的都存好了，删掉，交接区平时几乎是空的。还没取的照留
    /// The panel takes with a cursor of this kernel process: its `after` says everything before is
    /// stored, which is deleted, so the ring is nearly empty most of the time. What has not been taken
    /// stays
    #[test]
    fn what_the_panel_has_stored_is_deleted() {
        let log = QueryLog::default();
        cancelled(&log, 1..=5);
        assert_eq!(seqs(&page_of_this_run(&log, 0, 10)), [1, 2, 3, 4, 5]);
        assert_eq!(log.ring.lock().len(), 5, "taking deletes nothing yet");
        let next = page_of_this_run(&log, 3, 10);
        assert_eq!(seqs(&next), [4, 5]);
        assert_eq!(next["missed"], 0, "deleted after storing is no gap");
        assert_eq!(log.ring.lock().len(), 2);
        assert!(seqs(&page_of_this_run(&log, 5, 10)).is_empty());
        assert_eq!(log.ring.lock().len(), 0);
    }

    /// 没说游标是哪个进程的（面板在探，或者面板是旧的），或者游标是别的进程的（内核重启了，面板还拿着上一个进程的
    /// 游标）：都不是存好了什么，一条不删
    /// A cursor of no stated process (the panel probing, or an older panel) or of another one (the kernel
    /// restarted and the panel still holds the last process's cursor) says nothing was stored: nothing
    /// 面板同时取着好几段时，存好到哪由 `stored` 说：只删到它为止，取走了还没存好的照留；`stored` 超过 `after`
    /// 也只删到 `after`；不是这个进程的游标照样一条不删
    /// With the panel taking several ranges at once, `stored` says how far it has stored: deletion stops there, and
    /// what was taken but not stored stays; a `stored` past `after` still deletes only up to `after`; a cursor of
    /// another process still deletes nothing
    #[test]
    fn what_is_stored_is_said_apart_from_what_is_taken() {
        let log = QueryLog::default();
        cancelled(&log, 1..=8);
        let page_after = |after, stored, instance| -> Value {
            serde_json::from_str(&log.collect(after, 10, None, instance, stored, 1)).unwrap()
        };
        assert_eq!(
            seqs(&page_after(4, Some(2), Some(log.instance))),
            [5, 6, 7, 8]
        );
        assert_eq!(
            seqs(&page(&log, 0, 10)),
            [3, 4, 5, 6, 7, 8],
            "3 and 4 were taken, not stored"
        );
        let _ = page_after(5, Some(7), Some(log.instance));
        assert_eq!(
            seqs(&page(&log, 0, 10)),
            [6, 7, 8],
            "never past what was taken"
        );
        let _ = page_after(8, Some(8), Some(log.instance + 1));
        assert_eq!(seqs(&page(&log, 0, 10)), [6, 7, 8]);
    }

    /// 面板同时取相邻的几段时，每段只交到 `until`：前面被挤掉了一截，这一段也不越界交出下一段的记录，`missed` 只算
    /// 这一段里不在了的；整段都不在了，后面还有的照样说还有。不给 `until` 的照旧
    /// With the panel taking neighbouring ranges at once, each hands over records up to `until` only: with a stretch
    /// before it pushed out, it never hands over the next range's records, and `missed` counts only what is gone from
    /// this one; with the whole range gone, it still says more remain when they do. Without `until` nothing changes
    #[test]
    fn a_range_keeps_to_itself() {
        let log = QueryLog::with_capacity(4);
        let _ = page(&log, 0, 1);
        cancelled(&log, 1..=10);
        let range = |after, until| -> Value {
            serde_json::from_str(&log.collect(after, 10, Some(until), None, None, 1)).unwrap()
        };
        let summary = |page: &Value| (seqs(page), page["missed"].clone(), page["more"].clone());
        assert_eq!(summary(&range(6, 8)), (vec![7, 8], json!(0), json!(true)));
        assert_eq!(
            summary(&range(4, 8)),
            (vec![7, 8], json!(2), json!(true)),
            "5 and 6 were pushed out"
        );
        assert_eq!(
            summary(&range(2, 4)),
            (vec![], json!(2), json!(true)),
            "the whole range is gone, and 7 to 10 remain"
        );
        assert_eq!(
            summary(&range(8, 10)),
            (vec![9, 10], json!(0), json!(false))
        );
        assert_eq!(summary(&range(8, 8)), (vec![], json!(0), json!(true)));
        assert_eq!(
            summary(&page(&log, 2, 10)),
            (vec![7, 8, 9, 10], json!(4), json!(false))
        );
        assert_eq!(
            summary(&page(&log, 2, 2)),
            (vec![7, 8], json!(4), json!(true))
        );
    }

    /// 等着取的一段到 `until` 为止的都到了就回，不等攒满 `limit` 条 / A range waiting to be taken returns once
    /// everything up to `until` is there, without waiting for `limit` records
    #[tokio::test]
    async fn a_waiting_range_returns_once_it_is_complete() {
        let log = std::sync::Arc::new(QueryLog::default());
        let waiting = {
            let log = std::sync::Arc::clone(&log);
            tokio::spawn(async move {
                let started = tokio::time::Instant::now();
                log.wait_for_page(0, 500, Some(2), None, Duration::from_secs(5))
                    .await;
                started.elapsed()
            })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        quick_answers(&log, 1..=2);
        let waited = waiting.await.unwrap();
        assert!(waited < Duration::from_secs(2), "{waited:?}");
    }

    /// 好几段同时在等：先等到的那段走了，后面那段照样一到就叫醒，不白等到时限
    /// Several ranges waiting at once: once the first has what it waited for and leaves, the next is still woken the
    /// moment its records arrive, without sitting out its deadline
    #[tokio::test]
    async fn several_waiting_takes_are_each_woken() {
        let log = std::sync::Arc::new(QueryLog::default());
        let first = {
            let log = std::sync::Arc::clone(&log);
            tokio::spawn(async move {
                log.wait_for_page(0, 2, None, None, Duration::from_secs(5))
                    .await
            })
        };
        let second = {
            let log = std::sync::Arc::clone(&log);
            tokio::spawn(async move {
                let started = tokio::time::Instant::now();
                log.wait_for_page(2, 2, None, None, Duration::from_secs(5))
                    .await;
                started.elapsed()
            })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        quick_answers(&log, 1..=2);
        first.await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        quick_answers(&log, 3..=4);
        let waited = second.await.unwrap();
        assert!(waited < Duration::from_secs(2), "{waited:?}");
        assert_eq!(log.wake_at.load(Relaxed), u64::MAX, "no one waits any more");
        assert!(log.waiting.lock().is_empty());
    }

    /// is deleted
    #[test]
    fn only_a_cursor_of_this_run_deletes() {
        let log = QueryLog::default();
        cancelled(&log, 1..=3);
        let _ = page(&log, 3, 10);
        let _ = page(&log, u64::MAX / 2, 1);
        let _ = log.collect(3, 10, None, Some(log.instance + 1), None, 1);
        assert_eq!(seqs(&page(&log, 0, 10)), [1, 2, 3]);
    }

    /// 一页 JSON 逐字节固定：每种步骤、空着不写的项、要转义的文字、IPv6 客户端、各种结果。面板照原文存下记录，
    /// 字段的顺序和写法变了，存下来的就跟着变
    /// A page of JSON fixed byte for byte: every kind of step, items left out when empty, text that needs
    /// escaping, an IPv6 client and the various outcomes. The panel stores records as written, so a change
    /// in field order or spelling changes what it stores
    /// 编好的记录读回来写成的 JSON，和原来直接从记录写的一字不差。原来的写法照搬下来当标准答案（只把字段换成在跟的
    /// 记录和请求结束时的结果），随机的记录比两万条：每种步骤、要转义的文字、截断的报错、IPv6 客户端、各种应答
    /// The JSON written from an encoded record equals what was written straight from the record. The old
    /// way of writing is kept as the reference (its fields taken from the tracked record and the request's
    /// end), compared over twenty thousand random records: every kind of step, text that needs escaping,
    /// clipped errors, IPv6 clients and all sorts of responses
    mod encoded_records {
        use super::super::*;
        use hickory_proto::op::{MessageType, OpCode};
        use hickory_proto::rr::Record;
        use hickory_proto::rr::rdata::{A, AAAA, CNAME, TXT};
        use std::str::FromStr;

        fn reference_json(pending: &Pending, seq: u64, finished: &RequestOutcome<'_>) -> String {
            let status = match finished.status {
                RequestStatus::Completed => Status::Completed,
                RequestStatus::Failed => Status::Failed,
                RequestStatus::Cancelled => Status::Cancelled,
            };
            let latency_us = u64::try_from(finished.latency.as_micros()).unwrap_or(u64::MAX);
            let error = finished.error.map(clip);
            let reference_outcome = |rcode: Option<ResponseCode>| -> &'static str {
                match status {
                    Status::Completed if pending.cache == Some(CacheHitKind::Fresh) => "cached",
                    Status::Completed if pending.cache.is_some() => "stale",
                    Status::Completed if rcode == Some(ResponseCode::ServFail) => "failed",
                    Status::Completed if pending.joined => "joined",
                    Status::Completed
                        if matches!(pending.decision, Some((_, DecisionKind::Static))) =>
                    {
                        "static"
                    }
                    Status::Completed => "forwarded",
                    Status::Failed => "failed",
                    Status::Cancelled => "cancelled",
                }
            };
            let mut json = Json(Vec::new());
            let (rcode, answers) = finished
                .response
                .map_or_else(|| (None, Answers::new()), read_response);
            let outcome = reference_outcome(rcode);
            // 答案来自哪个上游：转发的是回答的那个，缓存的是当初回答的那个；规则直接回应、合并和失败的没有
            // Which upstream the answer came from: for a forward the one that answered, for a cache hit the one
            // that answered originally; none for a rule's own answer, a joined query or a failure
            let upstream = match outcome {
                "cached" | "stale" => pending.cache_source.as_deref(),
                "forwarded" => pending.answered_by.as_deref(),
                _ => None,
            };
            json.raw("{\"seq\":");
            json.number(seq);
            json.key("time_unix_ms");
            json.number(pending.time_unix_ms);
            json.key("client");
            json.address(pending.client);
            if let Some(transport) = pending.transport {
                json.key("transport");
                json.label(client_transport_label(transport));
            }
            json.key("qname");
            json.text(&pending.qname);
            json.key("qtype");
            json.text(type_name(pending.qtype, &mut [0; 9]));
            json.key("latency_us");
            json.number(latency_us);
            json.key("status");
            json.label(status.label());
            json.key("outcome");
            json.label(outcome);
            if let Some(rcode) = rcode {
                json.key("rcode");
                json.label(&rcode_name(u16::from(rcode)));
            }
            json.key("answers");
            json.raw("[");
            for (index, answer) in answers.iter().enumerate() {
                if index > 0 {
                    json.raw(",");
                }
                match answer {
                    Answer::V4(address) => json.ipv4(*address),
                    Answer::V6(address) => json.address(IpAddr::V6(*address)),
                    Answer::Text(text) => json.text(text),
                }
            }
            json.raw("]");
            if let Some(error) = &error {
                json.key("error");
                json.text(error);
            }
            if let Some(pipeline) = &pending.pipeline {
                json.key("pipeline");
                json.text(pipeline);
            }
            if let Some((Some(rule), _)) = &pending.decision {
                json.key("rule");
                json.text(rule);
            }
            if let Some(upstream) = upstream {
                json.key("upstream");
                json.text(upstream);
            }
            json.key("steps");
            json.raw("[");
            for (index, step) in pending.steps.iter().enumerate() {
                if index > 0 {
                    json.raw(",");
                }
                reference_step(step, &mut json);
            }
            json.raw("]");
            if pending.steps_truncated {
                json.key("steps_truncated");
                json.raw("true");
            }
            json.raw("}");
            String::from_utf8(json.0).unwrap()
        }

        fn reference_step(step: &Step, json: &mut Json) {
            json.raw("{\"at_us\":");
            json.number(step.at_us);
            json.key("kind");
            match &step.what {
                StepKind::Pipeline { pipeline } => {
                    json.label("pipeline");
                    json.key("pipeline");
                    json.text(pipeline);
                }
                StepKind::Rule {
                    pipeline,
                    rule,
                    phase,
                    matched,
                    decision,
                    target,
                } => {
                    json.label("rule");
                    json.key("pipeline");
                    json.text(pipeline);
                    json.key("rule");
                    json.text(rule);
                    json.key("phase");
                    json.label(phase_label(*phase));
                    if let Some(matched) = matched {
                        json.key("matched");
                        json.raw(if *matched { "true" } else { "false" });
                    }
                    if let Some(decision) = decision {
                        json.key("decision");
                        json.label(decision_label(*decision));
                    }
                    if let Some(target) = target {
                        json.key("target");
                        json.text(target);
                    }
                }
                StepKind::Decision {
                    pipeline,
                    rule,
                    phase,
                    decision,
                    target,
                } => {
                    json.label("decision");
                    json.key("pipeline");
                    json.text(pipeline);
                    if let Some(rule) = rule {
                        json.key("rule");
                        json.text(rule);
                    }
                    json.key("phase");
                    json.label(phase_label(*phase));
                    json.key("decision");
                    json.label(decision_label(*decision));
                    if let Some(target) = target {
                        json.key("target");
                        json.text(target);
                    }
                }
                StepKind::Cache { result, source } => {
                    json.label("cache");
                    json.key("result");
                    json.label(result.map_or("miss", cache_label));
                    if let Some(source) = source {
                        json.key("source");
                        json.text(source);
                    }
                }
                StepKind::Joined => json.label("joined"),
                StepKind::Upstream {
                    upstream,
                    transport,
                    via,
                    result,
                    latency_us,
                    rcode,
                    error,
                } => {
                    json.label("upstream");
                    json.key("upstream");
                    json.text(upstream);
                    json.key("transport");
                    json.label(transport_label(*transport));
                    json.key("via");
                    json.label(transport_label(*via));
                    json.key("result");
                    json.label(outcome_label(*result));
                    json.key("latency_us");
                    json.number(*latency_us);
                    if let Some(rcode) = rcode {
                        json.key("rcode");
                        json.label(&rcode_name(u16::from(*rcode)));
                    }
                    if let Some(error) = error {
                        json.key("error");
                        json.text(error);
                    }
                }
                StepKind::UpstreamSkipped {
                    upstream,
                    transport,
                    reason,
                } => {
                    json.label("upstream_skipped");
                    json.key("upstream");
                    json.text(upstream);
                    json.key("transport");
                    json.label(transport_label(*transport));
                    json.key("reason");
                    json.label(skip_reason_label(*reason));
                }
            }
            json.raw("}");
        }

        /// 小的伪随机数，测试每次都一样 / A small pseudo-random generator, the same on every run
        struct Rng(u64);

        impl Rng {
            fn below(&mut self, bound: usize) -> usize {
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 7;
                self.0 ^= self.0 << 17;
                usize::try_from(self.0 % u64::try_from(bound).unwrap()).unwrap()
            }

            fn pick<T: Clone>(&mut self, items: &[T]) -> T {
                items[self.below(items.len())].clone()
            }

            fn maybe<T>(&mut self, value: impl FnOnce(&mut Self) -> T) -> Option<T> {
                (self.below(2) == 0).then(|| value(self))
            }

            fn number(&mut self) -> u64 {
                self.below(usize::MAX) as u64 >> self.below(60)
            }
        }

        const NAMES: [&str; 8] = [
            "main",
            "abroad",
            "q\"uote",
            "back\\slash",
            "tab\tname",
            "名字",
            "udp://192.0.2.53:53",
            "https://doh.example/dns-query",
        ];

        fn name(rng: &mut Rng) -> ConfigName {
            ConfigName::of(rng.pick(&NAMES))
        }

        fn step(rng: &mut Rng) -> Step {
            let phases = [RulePhase::Request, RulePhase::Response];
            let decisions = [
                DecisionKind::Static,
                DecisionKind::Forward,
                DecisionKind::Jump,
                DecisionKind::Continue,
            ];
            let caches = [
                CacheHitKind::Fresh,
                CacheHitKind::Stale,
                CacheHitKind::StaleClientTimeout,
                CacheHitKind::StaleUpstreamFailure,
            ];
            let transports = [
                Transport::Udp,
                Transport::Tcp,
                Transport::TcpUdp,
                Transport::Doh,
                Transport::Dot,
                Transport::Doq,
            ];
            let results = [
                UpstreamOutcome::Success,
                UpstreamOutcome::Rejected,
                UpstreamOutcome::Error,
                UpstreamOutcome::Aborted,
                UpstreamOutcome::Throttled,
            ];
            let what = match rng.below(7) {
                0 => StepKind::Pipeline {
                    pipeline: name(rng),
                },
                1 => StepKind::Rule {
                    pipeline: name(rng),
                    rule: name(rng),
                    phase: rng.pick(&phases),
                    matched: rng.maybe(|rng| rng.below(2) == 0),
                    decision: rng.maybe(|rng| rng.pick(&decisions)),
                    target: rng.maybe(name),
                },
                2 => StepKind::Decision {
                    pipeline: name(rng),
                    rule: rng.maybe(name),
                    phase: rng.pick(&phases),
                    decision: rng.pick(&decisions),
                    target: rng.maybe(name),
                },
                3 => StepKind::Cache {
                    result: rng.maybe(|rng| rng.pick(&caches)),
                    source: rng.maybe(name),
                },
                4 => StepKind::Joined,
                5 => StepKind::Upstream {
                    upstream: name(rng),
                    transport: rng.pick(&transports),
                    via: rng.pick(&transports),
                    result: rng.pick(&results),
                    latency_us: rng.number(),
                    rcode: rng.maybe(rcode),
                    error: rng.maybe(|rng| rng.pick(&NAMES).into()),
                },
                _ => StepKind::UpstreamSkipped {
                    upstream: name(rng),
                    transport: rng.pick(&transports),
                    reason: UpstreamSkipReason::Throttled,
                },
            };
            Step {
                at_us: rng.number(),
                what,
            }
        }

        fn rcode(rng: &mut Rng) -> ResponseCode {
            let code: u16 = rng.pick(&[0, 2, 3, 5, 16, 23, 3_841]);
            ResponseCode::from((code >> 4).to_le_bytes()[0], (code & 0x0F).to_le_bytes()[0])
        }

        /// 一份应答：地址、名字和别的类型的回答，有时坏掉 / A response with address, name and other answers,
        /// sometimes damaged
        fn reply(rng: &mut Rng) -> Vec<u8> {
            let mut message = Message::new(7, MessageType::Response, OpCode::Query);
            message.metadata.response_code = rcode(rng);
            let owner = Name::from_str("www.example.com.").unwrap();
            for index in 0..rng.below(12) {
                let data = match rng.below(4) {
                    0 => RData::A(A::new(192, 0, 2, u8::try_from(index).unwrap())),
                    1 => RData::AAAA(AAAA::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                    2 => RData::CNAME(CNAME(Name::from_str("alias.example.net.").unwrap())),
                    _ => RData::TXT(TXT::new(vec!["v=1".to_owned()])),
                };
                message
                    .answers
                    .push(Record::from_rdata(owner.clone(), 300, data));
            }
            let mut bytes = message.to_vec().unwrap();
            if rng.below(5) == 0 {
                bytes.truncate(rng.below(bytes.len()));
            }
            bytes
        }

        /// 编好的记录多出字节、或者短了一截都读不通，不会写出半条或者错开的 JSON / An encoded record with bytes
        /// left over, or cut short, does not read, so no half or shifted JSON is written
        #[test]
        fn an_encoded_record_reads_only_whole() {
            let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
            let pending = Pending::start(&super::ctx(1), 1_792_065_600_123);
            let response = reply(&mut rng);
            let finished = RequestOutcome {
                latency: Duration::from_micros(900),
                status: RequestStatus::Completed,
                response: Some(&response),
                error: None,
            };
            let mut encoded = Vec::new();
            pending.encode(&finished, &mut encoded);
            let reads = |bytes: &[u8]| write_record(1, bytes, &mut Json(Vec::new())).is_some();
            assert!(reads(&encoded));
            let mut longer = encoded.clone();
            longer.push(0);
            assert!(!reads(&longer));
            for cut in 0..encoded.len() {
                assert!(!reads(&encoded[..cut]), "cut at {cut}");
            }
        }

        /// 一条随机的记录和它结束时的样子，交给 `check` / A random record and how it ended, handed to `check`
        fn random_case<T>(
            rng: &mut Rng,
            check: impl FnOnce(&Pending, &RequestOutcome<'_>) -> T,
        ) -> T {
            let long = "很长的报错".repeat(80);
            let errors = ["engine failed", "q\"\\\n", long.as_str()];
            let qnames = [
                "www.example.com",
                "a\"b.example",
                "中文.example",
                "x.example",
            ];
            let qtypes = [
                RecordType::A,
                RecordType::AAAA,
                RecordType::HTTPS,
                RecordType::CNAME,
                RecordType::Unknown(65_280),
            ];
            let statuses = [
                RequestStatus::Completed,
                RequestStatus::Failed,
                RequestStatus::Cancelled,
            ];
            let caches = [
                CacheHitKind::Fresh,
                CacheHitKind::Stale,
                CacheHitKind::StaleClientTimeout,
                CacheHitKind::StaleUpstreamFailure,
            ];
            let decisions = [
                DecisionKind::Static,
                DecisionKind::Forward,
                DecisionKind::Jump,
                DecisionKind::Continue,
            ];
            let transports = [
                ClientTransport::Udp,
                ClientTransport::Tcp,
                ClientTransport::Doh,
            ];
            let client = if rng.below(2) == 0 {
                IpAddr::V4(Ipv4Addr::from(u32::try_from(rng.number() >> 32).unwrap()))
            } else {
                IpAddr::V6(Ipv6Addr::from(
                    u128::from(rng.number()) << 64 | u128::from(rng.number()),
                ))
            };
            let mut pending = Pending {
                started: Instant::now(),
                at_once: false,
                time_unix_ms: rng.number(),
                client,
                transport: rng.maybe(|rng| rng.pick(&transports)),
                qname: rng.pick(&qnames).to_owned(),
                qtype: rng.pick(&qtypes),
                steps: SmallVec::new(),
                steps_truncated: rng.below(4) == 0,
                cache: rng.maybe(|rng| rng.pick(&caches)),
                cache_source: rng.maybe(name),
                joined: rng.below(4) == 0,
                pipeline: rng.maybe(name),
                decision: rng.maybe(|rng| (rng.maybe(name), rng.pick(&decisions))),
                answered_by: rng.maybe(name),
            };
            for _ in 0..rng.below(9) {
                pending.steps.push(step(rng));
            }
            let response = rng.maybe(reply);
            let finished = RequestOutcome {
                latency: Duration::from_micros(rng.number()),
                status: rng.pick(&statuses),
                response: response.as_deref(),
                error: rng.maybe(|rng| rng.pick(&errors)),
            };
            check(&pending, &finished)
        }

        #[test]
        fn encoded_records_read_back_as_written_directly() {
            let mut rng = Rng(0x2545_F491_4F6C_DD1D);
            for round in 0..20_000 {
                let seq = rng.number();
                random_case(&mut rng, |pending, finished| {
                    let mut encoded = Vec::new();
                    pending.encode(finished, &mut encoded);
                    let mut json = Json(Vec::new());
                    write_record(seq, &encoded, &mut json).expect("an encoded record reads back");
                    assert_eq!(
                        String::from_utf8(json.0).unwrap(),
                        reference_json(pending, seq, finished),
                        "round {round}"
                    );
                });
            }
        }

        /// 一页随机的记录 / A page of random records
        fn random_page(rng: &mut Rng, count: usize) -> TakenPage {
            let mut records = Vec::new();
            let mut ends = Vec::new();
            for _ in 0..count {
                random_case(rng, |pending, finished| {
                    pending.encode(finished, &mut records)
                });
                ends.push(records.len());
            }
            TakenPage {
                protocol_version: 1,
                instance: rng.number(),
                capacity: 16_384,
                newest: rng.number() | 1 << 40,
                missed: rng.number(),
                untracked: rng.number(),
                more: rng.below(2) == 0,
                first: rng.number() >> 30,
                records,
                ends,
            }
        }

        /// 二进制的一页拆回来；读不通时为 None / A binary page taken apart; None when it does not read
        fn page_from_records(bytes: &[u8]) -> Option<TakenPage> {
            let mut input = Decoder(bytes.strip_prefix(RECORDS_MAGIC)?);
            let protocol_version = u8::try_from(input.number()?).ok()?;
            let (instance, capacity, newest, missed, untracked) = (
                input.number()?,
                input.number()?,
                input.number()?,
                input.number()?,
                input.number()?,
            );
            let more = match input.byte()? {
                0 => false,
                1 => true,
                _ => return None,
            };
            let first = input.number()?;
            let mut records = Vec::new();
            let mut ends = Vec::new();
            for _ in 0..input.number()? {
                let len = usize::try_from(input.number()?).ok()?;
                records.extend_from_slice(input.take(len)?);
                ends.push(records.len());
            }
            input.0.is_empty().then_some(TakenPage {
                protocol_version,
                instance,
                capacity,
                newest,
                missed,
                untracked,
                more,
                first,
                records,
                ends,
            })
        }

        /// 二进制交出的一页拆回来，写成的 JSON 和直接写 JSON 的一字不差 / A page handed over as binary, taken
        /// apart again, gives JSON exactly as writing JSON directly does
        #[test]
        fn the_two_ways_of_handing_a_page_over_carry_the_same() {
            let mut rng = Rng(0x0DDB_1A5E_5BAD_5EED);
            for count in [0, 1, 300] {
                let page = random_page(&mut rng, count);
                let back = page_from_records(&page.records()).expect("the binary page reads back");
                assert_eq!(back.json(), page.json(), "{count} records");
            }
        }

        /// 交给面板的二进制逐字节固定：改了记录或页的编法，这里就红，要换版本号（`querylog_records_v2`、
        /// `KXQL\x02`）并告诉面板
        /// The binary handed to the panel is fixed byte for byte: changing how records or pages are encoded
        /// turns this red, and calls for a new version (`querylog_records_v2`, `KXQL\x02`) and the panel told
        #[test]
        fn the_binary_page_is_fixed_byte_for_byte() {
            let hit = Pending {
                started: Instant::now(),
                at_once: false,
                time_unix_ms: 1_792_065_600_123,
                client: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
                transport: Some(ClientTransport::Udp),
                qname: "www.example.com".to_owned(),
                qtype: RecordType::A,
                steps: [
                    Step {
                        at_us: 3,
                        what: StepKind::Pipeline {
                            pipeline: ConfigName::of("main"),
                        },
                    },
                    Step {
                        at_us: 9,
                        what: StepKind::Cache {
                            result: Some(CacheHitKind::Fresh),
                            source: Some(ConfigName::of("udp://192.0.2.53")),
                        },
                    },
                ]
                .into_iter()
                .collect(),
                steps_truncated: false,
                cache: Some(CacheHitKind::Fresh),
                cache_source: Some(ConfigName::of("udp://192.0.2.53")),
                joined: false,
                pipeline: Some(ConfigName::of("main")),
                decision: None,
                answered_by: None,
            };
            let answer = super::response(ResponseCode::NoError, &[[192, 0, 2, 1]]);
            let mut records = Vec::new();
            hit.encode(
                &RequestOutcome {
                    latency: Duration::from_micros(150),
                    status: RequestStatus::Completed,
                    response: Some(&answer),
                    error: None,
                },
                &mut records,
            );
            let ends = vec![records.len()];
            let page = TakenPage {
                protocol_version: 1,
                instance: 1_792_065_000_000,
                capacity: 16_384,
                newest: 42,
                missed: 0,
                untracked: 0,
                more: false,
                first: 42,
                records,
                ends,
            };
            let hex: String = page
                .records()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            assert_eq!(
                hex,
                concat!(
                    // 名字和版本、页头：协议版本、内核进程、容量、最新、漏掉、没记下、还有没有、第一条、条数
                    // Name and version, the head: protocol version, process, capacity, newest, missed,
                    // unrecorded, more, first, count
                    "4b58514c01",
                    "01c0a497fb93348080012a0000002a01",
                    // 一条 97 字节：时刻、客户端、UDP、域名、类型、耗时、完成、命中、NOERROR、一条回答
                    // One record of 97 bytes: time, client, UDP, name, type, latency, completed, cached,
                    // NOERROR, one answer
                    "61fbf4bbfb933404c0000207010f7777772e6578616d706c652e636f6d014196010001010104c0000201",
                    // 没有报错、Pipeline、没有规则、上游、两步、没截断
                    // No error, the pipeline, no rule, the upstream, two steps, not cut
                    "0001046d61696e0001107564703a2f2f3139322e302e322e3533",
                    "020300046d61696e09030101107564703a2f2f3139322e302e322e353300",
                )
            );
        }

        /// 给面板用的样本：一页随机的记录，二进制和 JSON 各一份。`KX_RECORDS_SAMPLE=目录` 时写出来
        /// A sample for the panel: a page of random records, as binary and as JSON. Written with
        /// `KX_RECORDS_SAMPLE=directory`
        #[test]
        #[ignore = "writes the sample the panel's tests read"]
        fn write_the_records_sample_for_the_panel() {
            let directory = std::path::PathBuf::from(
                std::env::var("KX_RECORDS_SAMPLE").expect("KX_RECORDS_SAMPLE names a directory"),
            );
            // 页头前后一致，面板的测试可以拿它当内核的回答 / A consistent head, so the panel's tests can use it as
            // the kernel's answer
            let page = TakenPage {
                instance: 1_792_065_000_000,
                newest: 150,
                missed: 0,
                untracked: 0,
                more: false,
                first: 1,
                ..random_page(&mut Rng(0x5A3F_1E2D_9C8B_7A61), 150)
            };
            std::fs::write(directory.join("querylog-records1.bin"), page.records()).unwrap();
            std::fs::write(directory.join("querylog-records1.json"), page.json()).unwrap();
        }
    }

    #[test]
    fn a_page_is_written_byte_for_byte() {
        let log = QueryLog::default();
        let ok = response(ResponseCode::NoError, &[[192, 0, 2, 1], [192, 0, 2, 2]]);
        let cached = ctx(1);
        log.request_started(&cached, false);
        log.pipeline_selected(&cached, "main");
        log.cache_hit(
            &cached,
            &CacheHit {
                kind: CacheHitKind::Fresh,
                remaining_ttl: None,
                original_ttl: None,
                source: Some("udp://192.0.2.53"),
            },
        );
        finish(&log, &cached, RequestStatus::Completed, Some(&ok));
        let forwarded = RequestContext {
            client: SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 53_000),
            transport: Some(ClientTransport::Tcp),
            ..ctx(2)
        };
        log.request_started(&forwarded, false);
        log.pipeline_selected(&forwarded, "main");
        log.cache_miss(&forwarded);
        matched(&log, &forwarded, "all", DecisionKind::Forward);
        log.decision_made(
            &forwarded,
            &DecisionMade {
                pipeline: "main",
                rule: Some("all"),
                phase: RulePhase::Request,
                detail: DecisionDetail::Forward {
                    upstream: "udp://192.0.2.53",
                    transport: None,
                },
            },
        );
        upstream(&log, &forwarded, "192.0.2.53:53", UpstreamOutcome::Success);
        finish(&log, &forwarded, RequestStatus::Completed, Some(&ok));
        let checked = RequestContext {
            qname: "q\"uote\\back\u{1}.example",
            transport: None,
            ..ctx(3)
        };
        log.request_started(&checked, false);
        log.pipeline_selected(&checked, "p\"1");
        log.inflight_joined(&checked);
        log.rule_evaluated(
            &checked,
            &RuleEvaluated {
                pipeline: "p\"1",
                rule: "check",
                phase: RulePhase::Response,
                matched: false,
                matchers: 1,
            },
        );
        log.decision_made(
            &checked,
            &DecisionMade {
                pipeline: "p\"1",
                rule: Some("check"),
                phase: RulePhase::Request,
                detail: DecisionDetail::Jump { pipeline: "other" },
            },
        );
        log.upstream_skipped(
            &checked,
            &crate::observe::UpstreamSkipped {
                upstream: "https://dns.example/dns-query",
                transport: Transport::Doh,
                reason: crate::observe::UpstreamSkipReason::Throttled,
            },
        );
        let refused = anyhow::anyhow!("refused \"x\"\nagain");
        log.upstream_result(
            &checked,
            &UpstreamResult {
                upstream: "192.0.2.54:53",
                transport: Transport::Udp,
                via: Transport::Tcp,
                outcome: UpstreamOutcome::Error,
                latency: Duration::from_millis(3),
                rcode: None,
                truncated: None,
                error: Some(&refused),
            },
        );
        finish(&log, &checked, RequestStatus::Completed, Some(&ok));
        let blocked = ctx(4);
        log.request_started(&blocked, false);
        matched(&log, &blocked, "ads", DecisionKind::Static);
        log.decision_made(
            &blocked,
            &DecisionMade {
                pipeline: "main",
                rule: Some("ads"),
                phase: RulePhase::Request,
                detail: DecisionDetail::Static {
                    rcode: ResponseCode::NXDomain,
                    answers: 0,
                },
            },
        );
        finish(
            &log,
            &blocked,
            RequestStatus::Completed,
            Some(&response(ResponseCode::NXDomain, &[])),
        );
        let failed = ctx(5);
        log.request_started(&failed, false);
        log.request_finished(
            &failed,
            &RequestOutcome {
                latency: Duration::from_millis(21),
                status: RequestStatus::Failed,
                response: None,
                error: Some("engine \"failed\"\n"),
            },
        );
        let page = log.collect(0, 10, None, None, None, 1);
        let page = regex::Regex::new(r#""(time_unix_ms|at_us|instance)":\d+"#)
            .unwrap()
            .replace_all(&page, r#""$1":0"#);
        assert_eq!(page, EXPECTED_PAGE);
    }

    const EXPECTED_PAGE: &str = concat!(
        r#"{"protocol_version":1,"instance":0,"capacity":131072,"newest_seq":5,"missed":0,"untracked":0,"more":false,"entries":[{"seq":1,"time_unix_ms":0,"client":"192.0.2.7","transport":"udp","qname":"www.example.com","qtype":"A","latency_us":21000,"status":"completed","outcome":"cached","rcode":"NOERROR","answers":["192.0.2.1","192.0.2.2"],"pipeline":"main","upstream":"udp://192.0.2.53","steps":[{"at_us":0,"kind":"pipeline","pipeline":"main"},{"at_us":0,"kind":"cache","result":"fresh","source":"udp://192.0.2.53"}]}"#,
        r#",{"seq":2,"time_unix_ms":0,"client":"::1","transport":"tcp","qname":"www.example.com","qtype":"A","latency_us":21000,"status":"completed","outcome":"forwarded","rcode":"NOERROR","answers":["192.0.2.1","192.0.2.2"],"pipeline":"main","rule":"all","upstream":"192.0.2.53:53","steps":[{"at_us":0,"kind":"pipeline","pipeline":"main"},{"at_us":0,"kind":"cache","result":"miss"},{"at_us":0,"kind":"rule","pipeline":"main","rule":"all","phase":"request","decision":"forward","target":"udp://192.0.2.53"},{"at_us":0,"kind":"upstream","upstream":"192.0.2.53:53","transport":"udp","via":"udp","result":"success","latency_us":20000,"rcode":"NOERROR"}]}"#,
        r#",{"seq":3,"time_unix_ms":0,"client":"192.0.2.7","qname":"q\"uote\\back\u0001.example","qtype":"A","latency_us":21000,"status":"completed","outcome":"joined","rcode":"NOERROR","answers":["192.0.2.1","192.0.2.2"],"pipeline":"p\"1","rule":"check","steps":[{"at_us":0,"kind":"pipeline","pipeline":"p\"1"},{"at_us":0,"kind":"joined"},{"at_us":0,"kind":"rule","pipeline":"p\"1","rule":"check","phase":"response","matched":false},{"at_us":0,"kind":"decision","pipeline":"p\"1","rule":"check","phase":"request","decision":"jump","target":"other"},{"at_us":0,"kind":"upstream_skipped","upstream":"https://dns.example/dns-query","transport":"doh","reason":"throttled"},{"at_us":0,"kind":"upstream","upstream":"192.0.2.54:53","transport":"udp","via":"tcp","result":"error","latency_us":3000,"error":"refused \"x\"\nagain"}]}"#,
        r#",{"seq":4,"time_unix_ms":0,"client":"192.0.2.7","transport":"udp","qname":"www.example.com","qtype":"A","latency_us":21000,"status":"completed","outcome":"static","rcode":"NXDOMAIN","answers":[],"rule":"ads","steps":[{"at_us":0,"kind":"rule","pipeline":"main","rule":"ads","phase":"request","decision":"static"}]}"#,
        r#",{"seq":5,"time_unix_ms":0,"client":"192.0.2.7","transport":"udp","qname":"www.example.com","qtype":"A","latency_us":21000,"status":"failed","outcome":"failed","answers":[],"error":"engine \"failed\"\n","steps":[]}]}"#,
    );

    #[test]
    fn recording_stops_two_minutes_after_the_last_collection() {
        let log = started_three_minutes_ago();
        assert!(!log.recording(), "never collected");
        let _ = page(&log, 0, 1);
        assert!(log.recording());
        // 不到两分钟前取过 / Collected just under two minutes ago
        log.collected.store(61_001, Relaxed);
        assert!(log.recording());
        // 三分钟前取过：停下，之后不再读时钟 / Collected three minutes ago: recording stops and the clock
        // is no longer read
        log.collected.store(1, Relaxed);
        assert!(!log.recording());
        assert_eq!(log.collected.load(Relaxed), 0);
        assert!(!log.recording(), "stays off until the panel collects again");
        let _ = page(&log, 0, 1);
        assert!(log.recording());
    }

    #[test]
    fn stopping_empties_the_ring_and_the_gap_is_reported() {
        let log = started_three_minutes_ago();
        let _ = page(&log, 0, 1);
        cancelled(&log, 1..=3);
        // 面板取到 1 以后再没来 / The panel took 1 and then stayed away
        let _ = page(&log, 0, 1);
        log.collected.store(1, Relaxed);
        assert!(!log.recording());
        assert_eq!(log.ring.lock().len(), 0);
        // 回来时：2、3 已经清掉，算漏记 / On return: 2 and 3 were emptied and count as missed
        let back = page(&log, 1, 10);
        assert_eq!(back["missed"], 2);
        assert_eq!(back["newest_seq"], 3);
        assert!(seqs(&back).is_empty());
        // 接着记的从 4 开始 / What is recorded next starts at 4
        cancelled(&log, 4..=4);
        assert_eq!(seqs(&page(&log, 3, 10)), [4]);
    }

    /// 没有名字的记录类型写成 `TYPE` 加类型号（RFC 3597 的写法），看得出问的是哪一种。以前一律写成 `Unknown`
    /// A record type without a name is written `TYPE` and its number (as RFC 3597 writes it), so
    /// it shows which type was asked. It used to be written `Unknown` whatever the number
    #[test]
    fn a_type_without_a_name_is_written_with_its_number() {
        let log = QueryLog::default();
        let _ = entries(&log);
        for (id, qtype, written) in [
            (7, RecordType::Unknown(65280), "TYPE65280"),
            (8, RecordType::Unknown(999), "TYPE999"),
            (9, RecordType::HTTPS, "HTTPS"),
        ] {
            let mut request = ctx(id);
            request.qtype = qtype;
            log.request_started(&request, false);
            finish(&log, &request, RequestStatus::Completed, None);
            let entry = entries(&log).pop().expect("one record");
            assert_eq!(entry["qtype"], written);
        }
    }

    /// 每次启动的日志有自己的标识：面板靠它认出内核重启过、手里的位置作废。以前标识就是启动时刻的毫秒数，同一
    /// 毫秒里建的两份日志标识相同；没有时钟电池的设备每次开机时钟从同一个时刻走起，两次启动可能撞上
    /// Each start's log has an identity of its own, by which the panel knows the kernel restarted
    /// and the position it holds is void. The identity used to be the start time in milliseconds,
    /// the same for two logs made within one millisecond; on a device without a clock battery
    /// the clock starts from the same moment at every boot, so two starts could coincide
    #[test]
    fn every_log_has_an_identity_of_its_own() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            let instance = QueryLog::default().instance;
            assert!(instance > 0, "0 is no identity");
            assert!(instance < 1 << 53, "a whole number any JSON reader takes");
            assert!(
                seen.insert(instance),
                "two logs share the identity {instance}"
            );
        }
    }

    #[test]
    fn a_forwarded_query_keeps_its_route_its_upstreams_and_its_answers() {
        let log = QueryLog::default();
        let _ = entries(&log);
        let request = ctx(7);
        log.request_started(&request, false);
        log.pipeline_selected(&request, "main");
        matched(&log, &request, "domestic", DecisionKind::Jump);
        decide(
            &log,
            &request,
            Some("domestic"),
            RulePhase::Request,
            DecisionDetail::Jump {
                pipeline: "upstream-cn",
            },
        );
        log.pipeline_selected(&request, "upstream-cn");
        log.cache_miss(&request);
        upstream(&log, &request, "192.0.2.53:53", UpstreamOutcome::Success);
        upstream(
            &log,
            &request,
            "dns.example/dns-query",
            UpstreamOutcome::Aborted,
        );
        finish(
            &log,
            &request,
            RequestStatus::Completed,
            Some(&response(
                ResponseCode::NoError,
                &[[198, 51, 100, 1], [198, 51, 100, 2]],
            )),
        );

        let entry = entries(&log).pop().expect("one record");
        assert_eq!(entry["seq"], 1);
        assert_eq!(entry["client"], "192.0.2.7");
        assert_eq!(entry["transport"], "udp");
        assert_eq!(entry["qname"], "www.example.com");
        assert_eq!(entry["qtype"], "A");
        assert_eq!(entry["latency_us"], 21_000);
        assert_eq!(entry["status"], "completed");
        assert_eq!(entry["outcome"], "forwarded");
        assert_eq!(entry["rcode"], "NOERROR");
        assert_eq!(
            entry["answers"],
            serde_json::json!(["198.51.100.1", "198.51.100.2"])
        );
        assert_eq!(entry["upstream"], "192.0.2.53:53");
        assert_eq!(entry["pipeline"], "upstream-cn", "where the request ended");
        assert_eq!(entry["rule"], "domestic");
        assert_eq!(
            kinds(&entry),
            [
                "pipeline", "rule", "pipeline", "cache", "upstream", "upstream"
            ]
        );
        let steps = entry["steps"].as_array().unwrap();
        assert_eq!(steps[1]["phase"], "request");
        assert_eq!(steps[1]["decision"], "jump");
        assert_eq!(steps[1]["target"], "upstream-cn");
        assert_eq!(steps[3]["result"], "miss");
        assert_eq!(steps[4]["result"], "success");
        assert_eq!(steps[4]["rcode"], "NOERROR");
        assert_eq!(steps[5]["result"], "aborted");
        assert!(steps[5].get("rcode").is_none());
    }

    /// 回答后检查命中时先写上它要做什么：实际的决定还没补上请求就结束了，那一步上留着的就是它
    /// A matched answer check first writes what it is set to do: with the request over before the actual
    /// decision is added, that is what its step keeps
    #[test]
    fn a_matched_answer_check_keeps_what_it_was_set_to_do() {
        let log = QueryLog::default();
        let _ = entries(&log);
        let request = ctx(1);
        log.request_started(&request, false);
        checked(&log, &request, "polluted", Some(DecisionKind::Static));
        finish(&log, &request, RequestStatus::Cancelled, None);
        let records = entries(&log);
        let step = &records[0]["steps"][0];
        assert_eq!(step["phase"], "response", "{step}");
        assert_eq!(step["matched"], true, "{step}");
        assert_eq!(step["decision"], "static", "{step}");
    }

    /// 回答后检查：结论和它实际做了什么都写在检查那一步上；拦截或改写算规则直接回应，不再写上游
    /// Answer checks: the verdict and what it actually did sit on the check's step; a block or rewrite
    /// counts as a rule's own answer and names no upstream
    #[test]
    fn answer_checks_record_their_verdict_and_what_they_did() {
        let log = QueryLog::default();
        let _ = entries(&log);
        let ok = response(ResponseCode::NoError, &[[198, 51, 100, 9]]);
        let forwarded = |request: &RequestContext<'_>, rule: &str| {
            log.request_started(request, false);
            matched(&log, request, rule, DecisionKind::Forward);
            decide(&log, request, Some(rule), RulePhase::Request, FORWARD);
            upstream(&log, request, "192.0.2.53:53", UpstreamOutcome::Success);
        };

        // 污染了，拦下 / Polluted: denied
        let denied = ctx(1);
        forwarded(&denied, "polluted");
        checked(&log, &denied, "polluted", Some(DecisionKind::Static));
        decide(
            &log,
            &denied,
            Some("polluted"),
            RulePhase::Response,
            DecisionDetail::Static {
                rcode: ResponseCode::Refused,
                answers: 0,
            },
        );
        finish(
            &log,
            &denied,
            RequestStatus::Completed,
            Some(&response(ResponseCode::Refused, &[])),
        );

        // 没问题，照用上游的回答 / Nothing wrong: the upstream's answer is kept
        let kept = ctx(2);
        forwarded(&kept, "checked");
        checked(&log, &kept, "checked", None);
        decide(&log, &kept, Some("checked"), RulePhase::Response, FORWARD);
        finish(&log, &kept, RequestStatus::Completed, Some(&ok));

        // 「继续往下」不作决定，只在检查那一步写上 / 「continue」 decides nothing and is told on the
        // check's step only
        let passed = ctx(3);
        forwarded(&passed, "pass");
        checked(&log, &passed, "pass", Some(DecisionKind::Continue));
        finish(&log, &passed, RequestStatus::Completed, Some(&ok));

        // 没写检查条件的规则：回答阶段的动作单独记一步 / A rule without response matchers: its
        // response actions are a step of their own
        let rescued = ctx(4);
        log.request_started(&rescued, false);
        matched(&log, &rescued, "rescue", DecisionKind::Forward);
        decide(&log, &rescued, Some("rescue"), RulePhase::Request, FORWARD);
        upstream(&log, &rescued, "192.0.2.53:53", UpstreamOutcome::Error);
        decide(&log, &rescued, Some("rescue"), RulePhase::Response, STATIC);
        finish(&log, &rescued, RequestStatus::Completed, Some(&ok));

        let records = entries(&log);
        let steps = |index: usize| records[index]["steps"].as_array().unwrap().clone();

        assert_eq!(records[0]["outcome"], "static");
        assert!(
            records[0].get("upstream").is_none(),
            "a block names no upstream"
        );
        assert_eq!(records[0]["rule"], "polluted");
        let check = &steps(0)[2];
        assert_eq!(check["phase"], "response");
        assert_eq!(check["matched"], true);
        assert_eq!(check["decision"], "static");
        assert!(check.get("target").is_none());
        // 请求阶段那一步的去处不被回答阶段的决定盖掉 / The request-phase step's target is not
        // overwritten by the response-phase decision
        assert_eq!(steps(0)[0]["target"], "192.0.2.53:53");

        assert_eq!(records[1]["outcome"], "forwarded");
        assert_eq!(records[1]["upstream"], "192.0.2.53:53");
        let check = &steps(1)[2];
        assert_eq!(check["matched"], false);
        assert_eq!(check["decision"], "forward");
        assert_eq!(check["target"], "192.0.2.53:53");

        assert_eq!(records[2]["outcome"], "forwarded");
        assert_eq!(steps(2)[2]["decision"], "continue");

        assert_eq!(records[3]["outcome"], "static");
        assert_eq!(kinds(&records[3]), ["rule", "upstream", "decision"]);
        let own = &steps(3)[2];
        assert_eq!(own["phase"], "response");
        assert_eq!(own["rule"], "rescue");
        assert_eq!(own["decision"], "static");
    }

    /// 决定只落在同一阶段的那一步上：回答检查那一步不会被请求阶段的决定填上
    /// A decision lands only on a step of its own phase: an answer check's step is never filled by a
    /// request-phase decision
    #[test]
    fn a_decision_lands_only_on_a_step_of_its_own_phase() {
        let log = QueryLog::default();
        let _ = entries(&log);
        let request = ctx(5);
        log.request_started(&request, false);
        checked(&log, &request, "again", None);
        decide(&log, &request, Some("again"), RulePhase::Request, FORWARD);
        finish(&log, &request, RequestStatus::Cancelled, None);
        let entry = entries(&log).pop().unwrap();
        assert_eq!(kinds(&entry), ["rule", "decision"]);
        assert!(entry["steps"][0].get("decision").is_none());
        assert_eq!(entry["steps"][1]["phase"], "request");
    }

    /// 跳回同一个列表的第二轮：这一轮的回答阶段决定不挂到上一轮「继续往下」的检查上
    /// A second pass after a jump back into the same list: this pass's response decision does not land
    /// on the previous pass's 「continue」 check
    #[test]
    fn a_decision_does_not_reach_back_to_an_earlier_pass() {
        let log = QueryLog::default();
        let _ = entries(&log);
        let request = ctx(6);
        log.request_started(&request, false);
        matched(&log, &request, "r1", DecisionKind::Forward);
        decide(&log, &request, Some("r1"), RulePhase::Request, FORWARD);
        checked(&log, &request, "r1", Some(DecisionKind::Continue));
        // 第二轮：同一条规则又转发，上游失败，由「否则」直接回答 / Second pass: the same rule
        // forwards again, the upstream fails, and the miss actions answer
        matched(&log, &request, "r1", DecisionKind::Forward);
        decide(&log, &request, Some("r1"), RulePhase::Request, FORWARD);
        upstream(&log, &request, "192.0.2.53:53", UpstreamOutcome::Error);
        decide(&log, &request, Some("r1"), RulePhase::Response, STATIC);
        finish(&log, &request, RequestStatus::Cancelled, None);
        let entry = entries(&log).pop().unwrap();
        assert_eq!(
            kinds(&entry),
            ["rule", "rule", "rule", "upstream", "decision"]
        );
        assert_eq!(entry["steps"][1]["decision"], "continue", "{entry}");
        assert_eq!(entry["steps"][4]["phase"], "response");
        assert_eq!(entry["steps"][4]["decision"], "static");
    }

    #[test]
    fn a_request_that_finds_recording_already_stopped_does_not_record() {
        let log = started_three_minutes_ago();
        // 读到的还是三分钟前那次，另一个请求已经把它停了 / What it read is the collection three
        // minutes ago, and another request has already stopped recording
        assert!(!log.recording_after(1, Instant::now()));
    }

    #[test]
    fn a_default_decision_without_a_rule_is_a_step_of_its_own() {
        let log = QueryLog::default();
        let _ = entries(&log);
        let request = ctx(4);
        log.request_started(&request, false);
        decide(&log, &request, None, RulePhase::Request, FORWARD);
        finish(
            &log,
            &request,
            RequestStatus::Completed,
            Some(&response(ResponseCode::NoError, &[])),
        );
        let entry = entries(&log).pop().unwrap();
        assert_eq!(kinds(&entry), ["decision"]);
        let step = &entry["steps"][0];
        assert_eq!(step["phase"], "request");
        assert_eq!(step["decision"], "forward");
        assert_eq!(step["target"], "192.0.2.53:53");
        assert!(step.get("rule").is_none());
        assert!(entry.get("rule").is_none());
    }

    #[test]
    fn outcomes_are_told_apart() {
        let log = QueryLog::default();
        let _ = entries(&log);
        let hit = |kind, source| CacheHit {
            kind,
            remaining_ttl: None,
            original_ttl: None,
            source,
        };
        let ok = response(ResponseCode::NoError, &[[198, 51, 100, 9]]);
        let servfail = response(ResponseCode::ServFail, &[]);
        let start = |id: u64| {
            let request = ctx(id);
            log.request_started(&request, false);
            request
        };

        let cached = start(10);
        log.cache_hit(&cached, &hit(CacheHitKind::Fresh, Some("192.0.2.53:53")));
        finish(&log, &cached, RequestStatus::Completed, Some(&ok));

        // 上游全失败、回了过期的旧结果：是「过期缓存」，不是失败 / Every upstream failed and the stale
        // entry answered: stale, not failed
        let stale = start(11);
        log.cache_miss(&stale);
        upstream(&log, &stale, "192.0.2.53:53", UpstreamOutcome::Error);
        log.cache_hit(
            &stale,
            &hit(CacheHitKind::StaleUpstreamFailure, Some("192.0.2.53:53")),
        );
        finish(&log, &stale, RequestStatus::Completed, Some(&ok));

        let joined = start(12);
        log.inflight_joined(&joined);
        finish(&log, &joined, RequestStatus::Completed, Some(&ok));

        // 先问过上游、最后由规则直接回应：不写上游 / Asked an upstream, then a rule answered: no
        // upstream named
        let answered = start(13);
        upstream(&log, &answered, "192.0.2.53:53", UpstreamOutcome::Success);
        decide(
            &log,
            &answered,
            Some("ads"),
            RulePhase::Request,
            DecisionDetail::Static {
                rcode: ResponseCode::NXDomain,
                answers: 0,
            },
        );
        finish(
            &log,
            &answered,
            RequestStatus::Completed,
            Some(&response(ResponseCode::NXDomain, &[])),
        );

        // 引擎自己合成的 SERVFAIL 算失败 / A SERVFAIL the engine made up counts as failed
        let servfailed = start(14);
        upstream(&log, &servfailed, "192.0.2.53:53", UpstreamOutcome::Error);
        finish(&log, &servfailed, RequestStatus::Completed, Some(&servfail));

        let failed = start(15);
        finish(&log, &failed, RequestStatus::Failed, None);

        let cancelled = start(16);
        finish(&log, &cancelled, RequestStatus::Cancelled, None);

        // 缓存里的 SERVFAIL 照实说是缓存 / A SERVFAIL from the cache is said to come from the cache
        let cached_failure = start(17);
        log.cache_hit(
            &cached_failure,
            &hit(CacheHitKind::Fresh, Some("192.0.2.53:53")),
        );
        finish(
            &log,
            &cached_failure,
            RequestStatus::Completed,
            Some(&servfail),
        );

        // 回答阶段的动作也没拿到应答（比如转发次数到了上限）：失败，不算规则回应
        // The response actions found no answer either (a forward limit reached, say): failed, not a
        // rule's answer
        let gave_up = start(18);
        decide(
            &log,
            &gave_up,
            Some("retry"),
            RulePhase::Response,
            DecisionDetail::Static {
                rcode: ResponseCode::ServFail,
                answers: 0,
            },
        );
        finish(&log, &gave_up, RequestStatus::Completed, Some(&servfail));

        let records = entries(&log);
        let outcome = |index: usize| records[index]["outcome"].as_str().unwrap().to_owned();
        assert_eq!(
            (0..9).map(outcome).collect::<Vec<_>>(),
            [
                "cached",
                "stale",
                "joined",
                "static",
                "failed",
                "failed",
                "cancelled",
                "cached",
                "failed"
            ]
        );
        assert_eq!(
            records[0]["upstream"], "192.0.2.53:53",
            "a hit names its source"
        );
        assert_eq!(records[1]["upstream"], "192.0.2.53:53");
        assert_eq!(records[1]["steps"][2]["result"], "stale_failure");
        for index in [2, 3, 4, 5, 6, 8] {
            assert!(
                records[index].get("upstream").is_none(),
                "{}",
                records[index]
            );
        }
        assert_eq!(records[3]["rcode"], "NXDOMAIN");
        assert_eq!(records[4]["rcode"], "SERVFAIL");
        assert_eq!(records[5]["status"], "failed");
        assert_eq!(records[5]["error"], "engine failed");
        assert!(records[5].get("rcode").is_none());
        assert_eq!(records[6]["status"], "cancelled");
        assert_eq!(records[7]["rcode"], "SERVFAIL");
    }

    #[test]
    fn background_refreshes_and_diagnostic_queries_stay_out() {
        let log = QueryLog::default();
        let _ = entries(&log);
        let mut refresh = ctx(20);
        refresh.background_refresh = true;
        log.request_started(&refresh, false);
        finish(&log, &refresh, RequestStatus::Completed, None);
        let diagnostic = ctx(21);
        log.request_started(&diagnostic, true);
        finish(&log, &diagnostic, RequestStatus::Completed, None);
        assert!(entries(&log).is_empty());
        assert_eq!(log.pending_count.load(Relaxed), 0);
    }

    #[test]
    fn requests_beyond_the_in_flight_limit_are_counted() {
        let log = QueryLog {
            max_pending: 1,
            ..QueryLog::default()
        };
        let _ = entries(&log);
        let (first, second) = (ctx(1), ctx(2));
        log.request_started(&first, false);
        log.request_started(&second, false);
        finish(&log, &second, RequestStatus::Cancelled, None);
        finish(&log, &first, RequestStatus::Cancelled, None);
        let page = page(&log, 0, 10);
        assert_eq!(seqs(&page), [1]);
        assert_eq!(page["untracked"], 1);
    }

    /// 两个同时在跟的请求落在同一个槽位：后来的那个记在共享表里，两条记录各是各的，都完整，结束以后两边都空了
    /// Two requests tracked at once that fall in the same slot: the later one goes to the shared map, the
    /// two records stay apart and whole, and both places are empty afterwards
    /// 自己读的应答和 hickory 整份解析的写出来一字不差：地址、名字、别的类型、名字压缩、EDNS 的扩展响应码、
    /// 超过 8 条的回答；改坏一个字节或截短的也一样（读不了的照旧只有包头的响应码）
    /// Replies read here come out word for word as hickory's whole parse writes them: addresses, names,
    /// other types, name compression, EDNS extended response codes and more than eight answers; and so do
    /// ones with one byte changed or cut short (an unreadable one still gives the header's code only)
    #[test]
    fn plain_replies_read_exactly_as_hickory_reads_them() {
        use hickory_proto::op::Edns;
        use hickory_proto::rr::rdata::{AAAA, CNAME, MX, NS, PTR, TXT};

        let mut state = 0x2026_1031_u64;
        let mut next = move |bound: u64| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state % bound
        };
        let suffixes = [
            "example.com.",
            "cdn.example.net.",
            "a.b.example.org.",
            "xn--fiqs8s.cn.",
        ];
        let mut read_here = 0;
        for id in 0..20_000_u16 {
            let mut message = Message::new(id, MessageType::Response, OpCode::Query);
            message.metadata.response_code = [
                ResponseCode::NoError,
                ResponseCode::NXDomain,
                ResponseCode::ServFail,
                ResponseCode::BADVERS,
            ][next(4) as usize];
            let name = |next: &mut dyn FnMut(u64) -> u64| {
                Name::from_str(&format!("h{}.{}", next(50), suffixes[next(4) as usize])).unwrap()
            };
            message.add_query(hickory_proto::op::Query::query(
                name(&mut next),
                RecordType::A,
            ));
            // 前 8 条回答都是地址或名字时，没改坏的应答一定由这里自己读 / With only addresses and names among
            // the first eight answers, an intact reply is always read here
            let mut plain = true;
            for index in 0..next(12) {
                let kind = next(8);
                plain &= index >= MAX_ANSWERS as u64 || kind < 6;
                let data = match kind {
                    0 | 1 => RData::A(A::new(10, 0, next(256) as u8, next(256) as u8)),
                    2 => RData::AAAA(AAAA::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, next(65536) as u16)),
                    3 => RData::CNAME(CNAME(name(&mut next))),
                    4 => RData::NS(NS(name(&mut next))),
                    5 => RData::PTR(PTR(name(&mut next))),
                    6 => RData::MX(MX::new(10, name(&mut next))),
                    _ => RData::TXT(TXT::new(vec![format!("v={}", next(1000))])),
                };
                message
                    .answers
                    .push(Record::from_rdata(name(&mut next), 300, data));
            }
            if next(3) == 0 {
                message.authorities.push(Record::from_rdata(
                    name(&mut next),
                    60,
                    RData::NS(NS(name(&mut next))),
                ));
            }
            if next(2) == 0 {
                message.edns = Some(Edns::new());
            }
            let whole = message.to_vec().unwrap();
            let mut variants = vec![
                whole.clone(),
                whole[..whole.len() - 1 - next(whole.len() as u64 - 1) as usize].to_vec(),
            ];
            let mut changed = whole.clone();
            let at = next(changed.len() as u64) as usize;
            changed[at] ^= 1 << next(8);
            variants.push(changed);
            let quick = |bytes: &[u8]| {
                crate::proto_utils::well_formed_reply(bytes)
                    && super::read_plain_response(bytes).is_some()
            };
            assert_eq!(quick(&whole), plain, "{message:?}");
            read_here += usize::from(plain);
            for bytes in variants {
                assert_eq!(
                    read_response(&bytes),
                    read_whole_response(&bytes),
                    "{bytes:?}"
                );
            }
        }
        assert!(read_here > 5_000, "{read_here} intact replies read here");
    }

    /// IPv4 地址一位位写出来，和 `Display` 写的一字不差 / An IPv4 address written digit by digit reads exactly
    /// as `Display` writes it
    #[test]
    fn an_ipv4_address_is_written_as_display_writes_it() {
        let mut state = 0x9E37_79B9_7F4A_7C15_u64;
        let mut addresses = vec![
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(192, 168, 100, 9),
            Ipv4Addr::new(9, 99, 100, 255),
        ];
        addresses.extend((0..10_000).map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            Ipv4Addr::from(u32::try_from(state >> 32).unwrap())
        }));
        for address in addresses {
            let mut json = super::Json(Vec::new());
            json.ipv4(address);
            assert_eq!(String::from_utf8(json.0).unwrap(), format!("\"{address}\""));
        }
    }

    #[test]
    fn requests_sharing_a_slot_keep_their_own_records() {
        let log = QueryLog::default();
        let _ = entries(&log);
        let first = ctx(5);
        let second = RequestContext {
            qname: "second.example",
            ..ctx(5 + PENDING_SLOTS as u64)
        };
        log.request_started(&first, false);
        log.request_started(&second, false);
        assert_eq!(
            log.overflow_len.load(Relaxed),
            1,
            "the second request takes the shared map"
        );
        // 又开始一次的替换掉原来那条，不多算 / Starting again replaces the record without counting another
        log.request_started(&first, false);
        log.request_started(&second, false);
        assert_eq!(log.pending_count.load(Relaxed), 2);
        assert_eq!(log.overflow_len.load(Relaxed), 1);
        log.pipeline_selected(&second, "abroad");
        log.pipeline_selected(&first, "main");
        upstream(
            &log,
            &second,
            "udp://198.51.100.2:53",
            UpstreamOutcome::Success,
        );
        upstream(
            &log,
            &first,
            "udp://192.0.2.53:53",
            UpstreamOutcome::Success,
        );
        let answer = response(ResponseCode::NoError, &[[203, 0, 113, 9]]);
        // 共享表里那个先结束：这时槽位还被另一个占着，不能拿错 / The one in the shared map finishes first,
        // while the other still holds the slot, which must not be taken by mistake
        finish(&log, &second, RequestStatus::Completed, Some(&answer));
        finish(&log, &first, RequestStatus::Completed, Some(&answer));
        let entries = entries(&log);
        assert_eq!(entries.len(), 2);
        let by_name = |qname: &str| {
            entries
                .iter()
                .find(|entry| entry["qname"] == qname)
                .expect("recorded")
        };
        for (qname, pipeline, upstream) in [
            ("www.example.com", "main", "udp://192.0.2.53:53"),
            ("second.example", "abroad", "udp://198.51.100.2:53"),
        ] {
            let entry = by_name(qname);
            assert_eq!(entry["pipeline"], pipeline, "{entry}");
            assert_eq!(entry["upstream"], upstream, "{entry}");
            assert_eq!(entry["steps"].as_array().map(Vec::len), Some(2), "{entry}");
        }
        assert_eq!(log.pending_count.load(Relaxed), 0);
        assert_eq!(log.overflow_len.load(Relaxed), 0);
        assert!(log.overflow.is_empty());
        assert!(log.slots.iter().all(|slot| slot.lock().is_none()));
    }

    /// 同一个线程里同一个名字共用一份；记过的名字多过上限就从头记，取到的照样是那个名字
    /// On one thread a name is held once; past the limit the remembered names start over, and every
    /// name taken is still the right one
    #[test]
    fn names_are_shared_and_stay_right_past_the_limit() {
        std::thread::spawn(|| {
            let first = ConfigName::of("main");
            assert!(std::sync::Arc::ptr_eq(&first.0, &ConfigName::of("main").0));
            assert!(!std::sync::Arc::ptr_eq(
                &first.0,
                &ConfigName::of("abroad").0
            ));
            for index in 0..KNOWN_NAMES * 2 {
                let text = format!("rule-{index}");
                assert_eq!(&*ConfigName::of(&text), text);
            }
            assert_eq!(&*ConfigName::of("main"), "main");
        })
        .join()
        .expect("the names thread");
    }

    /// 交接区里还在的记录：(序号, 内容) / The records still in the ring: (number, contents)
    fn ring_contents(ring: &super::Ring) -> Vec<(u64, Vec<u8>)> {
        let oldest = ring.oldest().unwrap_or(0);
        (0..ring.len())
            .map(|at| (oldest + at as u64, ring.record(at).to_vec()))
            .collect()
    }

    /// 一条记录：长度为 `len`，每个字节都是它的序号，读错了位置一眼看得出 / A record of `len` bytes, each its
    /// number, so a read from the wrong place shows at once
    fn numbered(seq: u64, len: usize) -> Vec<u8> {
        vec![u8::try_from(seq).unwrap(); len]
    }

    /// 一条记录长得放不进交接区（配置里的名字长得离谱）就不记，算进没记下的；序号不空出来
    /// A record too long for the ring (names in the config of an absurd length) is not kept and counts as
    /// unrecorded; no number is skipped for it
    #[test]
    fn a_record_too_long_for_the_ring_counts_as_unrecorded() {
        let log = QueryLog::default();
        *log.ring.lock() = super::Ring::new(400);
        let _ = page(&log, 0, 1);
        let long = "x".repeat(150);
        let request = RequestContext {
            qname: &long,
            ..ctx(1)
        };
        log.request_started(&request, false);
        finish(&log, &request, RequestStatus::Cancelled, None);
        cancelled(&log, 2..=2);
        let got = page(&log, 0, 10);
        assert_eq!(got["untracked"], 1, "{got}");
        assert_eq!(got["newest_seq"], 1, "{got}");
        assert_eq!(seqs(&got), [1]);
        assert_eq!(got["entries"][0]["qname"], "www.example.com");
    }

    /// 字节环放到末尾放不下就从头放，挤掉要占的地方上最早的几条。交接区绕过一圈、最早一条在末尾、新的又放不下
    /// 末尾时，末尾那条先挤掉，再挤掉从头那一带的最早几条，比它们新的不会被盖掉。长过四分之一的不收；条数到了
    /// 上限挤掉最早一条；清空时内存还回去，序号照旧
    /// A byte ring with no room at the end goes back to the start, pushing out the oldest records on the
    /// space it takes. With the ring wrapped, the oldest record at the end and a new one too long for the
    /// end, that record goes first, then the oldest near the start, and newer ones are never overwritten.
    /// A record longer than a quarter is refused; at the count limit the oldest goes; emptying gives the
    /// memory back and numbering carries on
    #[test]
    fn the_byte_ring_wraps_and_pushes_out_only_the_oldest() {
        let push = |ring: &mut super::Ring, len: usize| {
            let seq = ring.newest + 1;
            assert!(ring.push(&numbered(seq, len), 100), "{seq}");
        };
        let lens = |ring: &super::Ring| -> Vec<(u64, usize)> {
            ring_contents(ring)
                .into_iter()
                .map(|(seq, bytes)| {
                    assert!(bytes.iter().all(|byte| u64::from(*byte) == seq), "{seq}");
                    (seq, bytes.len())
                })
                .collect()
        };
        let mut ring = super::Ring::new(400);
        // 1..=5 放在 0..100、100..200、200..300、300..350、350..390 / 1 to 5 at 0..100, 100..200, 200..300,
        // 300..350 and 350..390
        for len in [100, 100, 100, 50, 40] {
            push(&mut ring, len);
        }
        // 6 放不下末尾，从头放，挤掉 1 / 6 does not fit the end, goes to the start and pushes out 1
        push(&mut ring, 100);
        assert_eq!(
            lens(&ring),
            [(2, 100), (3, 100), (4, 50), (5, 40), (6, 100)]
        );
        // 7、8 挤掉 2、3；9 放在 300..320，挤掉 4。现在最早的 5 在末尾 350..390
        // 7 and 8 push out 2 and 3; 9 at 300..320 pushes out 4. Now the oldest, 5, sits at the end, 350..390
        for len in [100, 100, 20] {
            push(&mut ring, len);
        }
        assert_eq!(
            lens(&ring),
            [(5, 40), (6, 100), (7, 100), (8, 100), (9, 20)]
        );
        // 10 要 90 字节，320 之后放不下：先挤掉末尾的 5，再从头放、挤掉 6；7 以后的都还在
        // 10 needs 90 bytes and does not fit past 320: 5 at the end goes first, then it goes to the start and
        // pushes out 6; 7 onwards stay
        push(&mut ring, 90);
        assert_eq!(lens(&ring), [(7, 100), (8, 100), (9, 20), (10, 90)]);
        assert!(
            !ring.push(&[0; 101], 100),
            "longer than a quarter is not kept"
        );
        assert_eq!(ring.newest, 10);
        // 都删掉以后从头放：面板跟得上时一直用开头那一小段，内存不会越占越多
        // Once all is deleted it starts at the beginning again: with the panel keeping up the same small
        // stretch is used over and over, and memory does not keep growing
        let mut reused = super::Ring::new(400);
        for _ in 0..20 {
            push(&mut reused, 30);
            reused.pop_front();
        }
        assert_eq!(reused.bytes.len(), 30);
        // 条数上限 / The count limit
        let mut counted = super::Ring::new(1 << 20);
        for _ in 0..5 {
            assert!(counted.push(&[1, 2, 3], 3));
        }
        assert_eq!(counted.len(), 3);
        assert_eq!(counted.oldest(), Some(3));
        counted.clear();
        assert_eq!(counted.len(), 0);
        assert_eq!(counted.bytes.capacity(), 0, "the memory is given back");
        assert_eq!(counted.newest, 5);
    }

    #[test]
    fn a_full_ring_drops_the_oldest_and_says_how_many_were_missed() {
        let log = QueryLog::with_capacity(3);
        let _ = page(&log, 0, 1);
        cancelled(&log, 1..=5);
        // 面板上次取到 0：1、2 已经被挤掉 / The panel last took 0: 1 and 2 were pushed out
        let first = page(&log, 0, 10);
        assert_eq!(first["missed"], 2);
        assert_eq!(first["newest_seq"], 5);
        assert_eq!(seqs(&first), [3, 4, 5]);
        // 取到 4 之后只剩 5，不再算漏 / After taking 4 only 5 is left, and nothing is missed
        let next = page(&log, 4, 10);
        assert_eq!(next["missed"], 0);
        assert_eq!(seqs(&next), [5]);
        assert_eq!(next["more"], false);
        assert!(seqs(&page(&log, 5, 10)).is_empty());
        // 游标比最新的还大（内核重启过）：什么也不给，也不算漏 / A cursor beyond the newest (the kernel
        // restarted): nothing, and nothing missed
        let beyond = page(&log, 9, 10);
        assert!(seqs(&beyond).is_empty());
        assert_eq!(beyond["missed"], 0);
    }

    #[test]
    fn pages_follow_the_cursor() {
        let log = QueryLog::default();
        let _ = entries(&log);
        cancelled(&log, 1..=5);
        let first = page(&log, 1, 2);
        assert_eq!(seqs(&first), [2, 3]);
        assert_eq!(first["more"], true);
        assert_eq!(first["capacity"], CAPACITY);
        assert_eq!(first["instance"], log.instance);
        assert_eq!(first["protocol_version"], 1);
        assert_eq!(page(&log, 3, 2)["more"], false);
    }

    #[test]
    fn steps_stop_at_the_cap_and_say_so() {
        let log = QueryLog::default();
        let _ = entries(&log);
        let request = ctx(30);
        log.request_started(&request, false);
        for _ in 0..(MAX_STEPS + 5) {
            log.cache_miss(&request);
        }
        finish(&log, &request, RequestStatus::Cancelled, None);
        let entry = entries(&log).pop().unwrap();
        assert_eq!(entry["steps"].as_array().unwrap().len(), MAX_STEPS);
        assert_eq!(entry["steps_truncated"], true);
    }

    #[test]
    fn long_text_is_cut_by_character() {
        let text = "域".repeat(300);
        let clipped = clip(&text);
        assert_eq!(clipped.chars().count(), MAX_TEXT + 1);
        assert!(clipped.ends_with('…'));
        assert_eq!(clip("short"), "short");
    }
}
