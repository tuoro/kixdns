use std::hash::{BuildHasher, RandomState};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use super::fair_queue::{Device, MAX_QUEUED_DEVICES};
use super::memory_watermark::Room;

/// 查询在内核里排队超过这么久，就算内核跟不上。这是延迟目标，和机器无关：快机器和慢机器都一样
/// Queries waiting longer than this inside the kernel means it cannot keep up. This is a
/// latency goal rather than a property of the machine, the same on a fast one and a slow one
pub const QUEUE_TARGET: Duration = Duration::from_millis(20);

/// socket 连续这么久没收空，才算内核忙。这也是延迟目标、和机器无关：积压持续这么久才是过载，一阵突发很快
/// 就收空了，不算。配置决定不了它，旧配置里写的 `flow_control_latency_threshold_ms` 不起作用
/// A socket going this long without running empty is what counts as the kernel being busy. This too
/// is a latency goal and not a property of the machine: a backlog lasting this long is overload, while
/// a burst soon runs empty and does not count. No configuration sets it, and an old configuration's
/// `flow_control_latency_threshold_ms` has no effect
pub const BUSY_AFTER: Duration = Duration::from_millis(100);

/// 内核忙时，在途的查询平均要等这么久以上才走完，就拒占着自己那一份的设备。平常的上游一秒内都回答了，客户端一秒等不到多半
/// 也已经重发；等得比这还久，等的是不回答或者慢得没用的上游，这些查询占着内存，也都转发给了上游。这也是延迟目标、和机器无关。
/// 比它紧，一台转发器或者 NAT 后面的全部用户在上游稍慢一点时就会被拒
/// While the kernel is busy, queries in flight taking longer than this on average to be done
/// means a device holding its share is refused. Usual upstreams answer within a second, and a
/// client that waited a second has most likely asked again; waiting longer means waiting on
/// upstreams that do not answer or are too slow to be of use, queries that hold memory and were
/// all forwarded upstream too. This too is a latency goal and not a property of the machine. Any
/// tighter, and everyone behind one forwarder or NAT would be refused as soon as an upstream got
/// a little slow
pub const HELD_AT_MOST: Duration = Duration::from_secs(1);

/// 在途的查询不到这么多，不按预算拒：和内存水位开始看内存的在途数一样，这么少占不了多少内存，也压不着上游
/// Under this many queries in flight nothing is refused by the budget: the same number of
/// queries in flight as the memory watermark starts looking at memory from, too few to hold much
/// memory or weigh on an upstream
pub const BUDGET_AT_LEAST: usize = 1000;

/// 内核忙时每台设备在途至少能有这么多个，排队也是（见 `FairQueue::offer`），够 A、AAAA、HTTPS 一起问：来源多到预算平分下来
/// 每台不到一个时，发得少的设备一次问几个，只答得上一个。最多照顾 [`MAX_QUEUED_DEVICES`] 台，在途和排队一共最多各多出它们乘
/// 这么多个；来源再多，每台分到的又和以前一样
/// While the kernel is busy each device may hold at least this many in flight, and queue as many
/// (see `FairQueue::offer`), enough to ask A, AAAA and HTTPS together: with sources so many that
/// the budget shared out gives each less than one, a device sending little asking a few at once
/// would get only one answered. At most [`MAX_QUEUED_DEVICES`] devices are looked after this way,
/// so in flight and queued each hold at most that many times this more in all; with yet more
/// sources each gets what it used to
pub const SHARE_AT_LEAST: usize = 4;

/// 预算看的那一秒分成这么长的一格：每有一个查询在上游超时以前走完，就记进它走完时所在的那一格，看的是现在这一格之前的
/// `HELD_AT_MOST` 那么多格
/// The second the budget looks at is kept in buckets this long: each query done before the
/// upstream timeout is noted in the bucket it was done in, and what is looked at is the
/// `HELD_AT_MOST` worth of buckets before the current one
const BUCKET: Duration = Duration::from_millis(100);

/// 预算看的是现在这一格之前的这么多格 / The budget looks at this many buckets before the current one
const BUCKETS_LOOKED_AT: u64 = (HELD_AT_MOST.as_nanos() / BUCKET.as_nanos()) as u64;

/// 记着的格数：看的那些、正在记的这一格，以及几个核在格子交界处还往上一格记的余地，取 2 的幂
/// How many buckets are kept: those looked at, the one being noted in, and room for cores still
/// noting in the last one around a boundary, as a power of two
const BUCKETS_KEPT: usize = 16;

/// 一格的原子数里，个数占的低位，高位是格号 / In a bucket's atomic, the low bits holding the count,
/// the high bits being the bucket's number
const COUNT_BITS: u32 = 24;
const COUNT_MASK: u64 = (1 << COUNT_BITS) - 1;

/// 一格：这一段时间里有多少查询没等到上游超时就走完、有多少等到了超时，各是一个带格号的原子数。一格单占一条缓存行：
/// 几个核一起往现在这一格记，看预算时读的是别的格，不跟着失效
/// A bucket: how many queries were done short of the upstream timeout over its stretch and how
/// many only at the timeout, each an atomic carrying the bucket's number. A bucket is on a cache
/// line of its own: the cores noting in the current one together leave the others, which the
/// budget reads, valid
#[repr(align(64))]
struct Bucket {
    answered: AtomicU64,
    timed_out: AtomicU64,
}

/// 第 `number` 格的计数加一。这一格上次记的是更早的格号，就从这一个重新数；已经记着更晚的（这个核在交界处慢了一整圈），
/// 这一个不记
/// Adds one to the count of bucket `number`. A count last noted for an earlier number starts
/// again from this one; one already noted for a later number (this core slow by a whole round at
/// a boundary) leaves this one out
fn count_one(counter: &AtomicU64, number: u64) {
    let mut seen = counter.load(Ordering::Relaxed);
    loop {
        let next = match (seen >> COUNT_BITS).cmp(&number) {
            std::cmp::Ordering::Greater => return,
            std::cmp::Ordering::Equal if seen & COUNT_MASK == COUNT_MASK => return,
            std::cmp::Ordering::Equal => seen + 1,
            std::cmp::Ordering::Less => number << COUNT_BITS | 1,
        };
        match counter.compare_exchange_weak(seen, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(now_seen) => seen = now_seen,
        }
    }
}

/// 第 `number` 格记了多少；记着的是别的格号时是 0 / How many bucket `number` holds; 0 when it holds
/// another number
fn count_of(counter: &AtomicU64, number: u64) -> u64 {
    let seen = counter.load(Ordering::Relaxed);
    if seen >> COUNT_BITS == number {
        seen & COUNT_MASK
    } else {
        0
    }
}

/// 一段时间里有多少查询没等到上游超时就走完、有多少等到了超时，按 `bucket` 那么长分格，几个核一起记，见
/// [`PermitManager::budget`] / How many queries were done short of the upstream timeout and how many only
/// at it over a stretch of time, kept in buckets `bucket` long and noted by several cores at once,
/// see [`PermitManager::budget`]
struct Done {
    started: Instant,
    bucket: Duration,
    buckets: [Bucket; BUCKETS_KEPT],
}

impl Done {
    fn new(bucket: Duration) -> Self {
        Self {
            started: Instant::now(),
            bucket,
            buckets: std::array::from_fn(|_| Bucket {
                answered: AtomicU64::new(0),
                timed_out: AtomicU64::new(0),
            }),
        }
    }

    /// `at` 在第几格 / Which bucket `at` falls in
    fn bucket_of(&self, at: Instant) -> u64 {
        (at.saturating_duration_since(self.started).as_nanos() / self.bucket.as_nanos()) as u64
    }

    /// 记下 `at` 这一刻走完了一个，`answered` 是没等到上游超时 / Notes one done at `at`, `answered`
    /// meaning short of the upstream timeout
    fn note(&self, at: Instant, answered: bool) {
        let number = self.bucket_of(at);
        let bucket = &self.buckets[number as usize % BUCKETS_KEPT];
        count_one(
            if answered {
                &bucket.answered
            } else {
                &bucket.timed_out
            },
            number,
        );
    }

    /// `now` 这一格之前的 `N` 格各记了多少，近的在前，`kind` 选是哪一种 / How many were noted in each of the
    /// `N` buckets before the one `now` falls in, the latest first, `kind` choosing which
    fn counts<const N: usize>(&self, now: Instant, kind: fn(&Bucket) -> &AtomicU64) -> [u64; N] {
        let current = self.bucket_of(now);
        std::array::from_fn(|back| match current.checked_sub(back as u64 + 1) {
            Some(number) => count_of(kind(&self.buckets[number as usize % BUCKETS_KEPT]), number),
            None => 0,
        })
    }

    /// 最近一秒有多少没等到上游超时就走完 / How many were done short of the upstream timeout over the
    /// last second
    #[cfg(test)]
    fn last_second(&self, now: Instant) -> u64 {
        self.counts::<{ BUCKETS_LOOKED_AT as usize }>(now, |bucket| &bucket.answered)
            .iter()
            .sum()
    }

    /// 没等到上游超时就走完的，整整一秒有多少，以及最近零点几秒走得更快时跟着那一段折成一秒有多少（最多是整秒的
    /// [`FOLLOWS_FASTER_AT_MOST`] 倍），见 [`PermitManager::budget`] / How many were done short of the upstream
    /// timeout over the whole second, and how many over a second when following the last tenths of
    /// a second that went faster (at most [`FOLLOWS_FASTER_AT_MOST`] times the whole second's), see
    /// [`PermitManager::budget`]
    fn second_and_faster(&self, now: Instant) -> (u64, u64) {
        let answered =
            self.counts::<{ BUCKETS_LOOKED_AT as usize }>(now, |bucket| &bucket.answered);
        let mut second = 0;
        let mut fastest = 0;
        for (k, count) in (1..).zip(answered) {
            second += count;
            fastest = fastest.max(second * BUCKETS_LOOKED_AT / k);
        }
        let faster = second.max(fastest.min(second.saturating_mul(FOLLOWS_FASTER_AT_MOST)));
        (second, faster)
    }

    /// 现在这一格和之前的 `back` 格里，等到上游超时的是不是不到走完的 `1 / TIMED_OUT_ONE_IN`（什么都没走完时算是）。
    /// 现在这一格也算：洪泛一开始超时，下一次问就看得到
    /// Whether those that waited for the upstream timeout were under `1 / TIMED_OUT_ONE_IN` of all
    /// done in the current bucket and the `back` before it (as they are with nothing done). The
    /// current bucket counts too: a flood starting to time out is seen at the next ask
    fn rarely_timed_out(&self, now: Instant, back: u64) -> bool {
        let current = self.bucket_of(now);
        let (mut answered, mut timed_out) = (0u64, 0u64);
        for number in current.saturating_sub(back)..=current {
            let bucket = &self.buckets[number as usize % BUCKETS_KEPT];
            answered += count_of(&bucket.answered, number);
            timed_out += count_of(&bucket.timed_out, number);
        }
        timed_out.saturating_mul(TIMED_OUT_ONE_IN) < answered.saturating_add(timed_out).max(1)
    }
}

/// 最近零点几秒走得比整秒快时，预算最多跟到整秒的这么多倍，见 [`PermitManager::budget`] / How many times the
/// whole second's count the budget follows the last tenths of a second up to, when they went
/// faster, see [`PermitManager::budget`]
const FOLLOWS_FASTER_AT_MOST: u64 = 2;

/// 记等到超时有多少的那些格一格多长，看之前的几格：比默认的上游超时（9 秒）长，洪泛一阵阵地来、每阵之间超时的已经走光了，
/// 也还记着 / How long a bucket noting how many waited for the timeout is, and how many before now are
/// looked at: longer than the default upstream timeout (9 s), so a flood coming in waves is still
/// remembered after one wave's timeouts are all gone
const RECENT_BUCKET: Duration = Duration::from_secs(1);
const RECENT_LOOKED_AT: u64 = 15;

/// 最近 `RECENT_LOOKED_AT` 秒走完的查询里，等到超时的不到这么多分之一，预算才跟着最近零点几秒走，见
/// [`PermitManager::budget`] / The budget follows the last tenths of a second only while fewer than one in
/// this many queries done over the last `RECENT_LOOKED_AT` seconds waited for the timeout, see
/// [`PermitManager::budget`]
const TIMED_OUT_ONE_IN: u64 = 20;

/// 流控的状态。不用填数字，判断都来自运行时测到的：socket 收不收得空、查询排队多久、处理得多快、还剩多少内存
/// The state of flow control. There are no numbers to fill in: it goes by what is measured at
/// run time, namely whether a socket runs empty, how long queries queue, how fast they are
/// handled and how much memory is left
pub struct FlowControlState {
    /// socket 连续这么久没收空就算忙，就是 `BUSY_AFTER`（测试可以换）/ How long a socket goes without
    /// running empty before that counts as busy: `BUSY_AFTER` (a test may change it)
    pub busy_after: Duration,
    pub memory: super::memory_watermark::MemoryWatermark,
    started: Instant,
    /// 跟不上的状态到什么时候（从 `started` 算起的纳秒）/ Until when the kernel counts as behind, in nanoseconds since `started`
    behind_until_ns: AtomicU64,
}

impl FlowControlState {
    pub fn new(memory: super::memory_watermark::MemoryWatermark) -> Self {
        Self {
            busy_after: BUSY_AFTER,
            memory,
            started: Instant::now(),
            behind_until_ns: AtomicU64::new(0),
        }
    }

    /// `device` 的一个要等上游的查询能不能处理，`emptied_at` 是 socket 上次收空的时刻，`budget` 是内核忙时在途的查询一共
    /// 最多多少（见 [`PermitManager::budget`]）。内存不够时拒绝（见 [`Self::memory_refuses`]）。内核忙时，在途到了预算就拒占着自己
    /// 那一份的设备；忙而且查询在内核里排着长队时，拒在途不比各设备平均少的设备，发得少的照常——那时每个查询都要先排同样长
    /// 的队，在途多少就是发得多快，不分设备地拒，发得少的也跟着丢，直到开始按设备轮流。等上游不算排队：上游慢，在途没到预算
    /// 就不拒
    /// Whether a query from `device` that waits on an upstream can go ahead, `emptied_at` being
    /// when the socket last ran empty and `budget` how many queries may be in flight in all while
    /// the kernel is busy (see [`PermitManager::budget`]). Too little memory refuses it (see
    /// [`Self::memory_refuses`]). With the kernel busy, a device holding its share is refused
    /// once the budget is in flight; busy and queueing long inside the kernel, a device holding no
    /// less in flight than the average is refused while those sending little go on. Every query
    /// then waits in the same long line first, so what a device holds in flight is how fast it
    /// sends, and refusing whatever comes would lose the devices sending little too, until devices
    /// take turns. Waiting on an upstream is not queueing: with a slow upstream nothing is refused
    /// until the budget is in flight
    #[inline]
    pub fn permit(
        &self,
        manager: &Arc<PermitManager>,
        emptied_at: Instant,
        device: DeviceSlot,
        budget: usize,
    ) -> Option<PermitGuard> {
        if self.memory_refuses(manager, device)
            || (self.busy(emptied_at)
                && (manager.queries.holds_busy_share_of(device, budget)
                    || (self.behind() && manager.queries.holds_its_share(device))))
        {
            manager.count_refused();
            return None;
        }
        Some(manager.acquire_for(device))
    }

    /// 内存够不够 `device` 再接一个：没了谁都不接；紧张时，在途停在变紧张那一刻的数（见
    /// `MemoryWatermark::tight_budget`），各设备平分，占着自己那一份的不接，发得少的照常——一台或者很多台设备把内存
    /// 占满时先拦住它们，别的设备不受连累
    /// Whether memory refuses one more for `device`: with none left everyone is refused; when it
    /// is tight, what is in flight stays where it was as memory got tight (see
    /// `MemoryWatermark::tight_budget`), shared out among the devices, and one holding its share
    /// is refused while those sending little go on, so one or many devices filling the memory are
    /// stopped first and the others are not held up with them
    #[inline]
    fn memory_refuses(&self, manager: &PermitManager, device: DeviceSlot) -> bool {
        match self.memory.room(manager.inflight()) {
            Room::Plenty => false,
            Room::Tight => manager
                .queries
                .holds_share_of(device, self.memory.tight_budget(manager.queries.total())),
            Room::Full => true,
        }
    }

    /// 一个查询从排进去到开始跑等了 `delay`。超过目标就说明队里积着这么久的活，这段时间不接新查询，让它消化
    /// A query waited `delay` from being queued until it ran. Past the target, that means this
    /// much work is queued, and for that long no new query is taken so it can be worked off
    #[inline]
    pub fn note_queue_delay(&self, delay: Duration) {
        if delay > QUEUE_TARGET {
            let until = self.started.elapsed() + delay;
            self.behind_until_ns
                .store(until.as_nanos() as u64, Ordering::Relaxed);
        }
    }

    #[inline]
    pub fn behind(&self) -> bool {
        (self.started.elapsed().as_nanos() as u64) < self.behind_until_ns.load(Ordering::Relaxed)
    }

    /// 内核忙不忙，`emptied_at` 是 socket 上次收空的时刻。内核跟不上，socket 才会一直收不空；上游慢不算，
    /// 那时查询都在等上游，socket 照样收得空
    /// Whether the kernel is busy, `emptied_at` being when the socket last ran empty. Only a kernel falling
    /// behind leaves a socket never running empty; a slow upstream does not count, as the queries then wait
    /// on it and the socket still runs empty
    #[inline]
    pub fn busy(&self, emptied_at: Instant) -> bool {
        emptied_at.elapsed() >= self.busy_after
    }

    /// 按设备轮流时 `device` 的一个要等上游的查询能不能处理，`budget` 同 [`Self::permit`]：看内存；在途到了预算，占着
    /// 自己那一份的设备也拒绝。轮流挡住的是排队，挡不住在途：对着不
    /// 回答的域名洪泛的设备，只看内存的话在途一直涨到内存水位，这些查询还都转发给了上游。没到预算谁都不拒：只有一台设备、
    /// 发得少的设备一次问好几个，都照常
    /// Whether a query from `device` that waits on an upstream can go ahead while devices take
    /// turns, `budget` as for [`Self::permit`]: by memory, and once the budget is in flight a
    /// device holding its share is refused as well. Taking turns holds the queueing, not what is in flight: a device flooding
    /// names that get no answer would, by memory alone, pile up in flight until the memory
    /// watermark, every one of those queries forwarded upstream too. Under the budget nobody is
    /// refused, a lone device and one sending little asking several at once alike
    #[inline]
    pub fn turn_permit(
        &self,
        manager: &Arc<PermitManager>,
        device: DeviceSlot,
        budget: usize,
    ) -> Option<PermitGuard> {
        if self.memory_refuses(manager, device)
            || manager.queries.holds_busy_share_of(device, budget)
        {
            manager.count_refused();
            return None;
        }
        Some(manager.acquire_for(device))
    }

    /// 只看内存：TCP 和 DoH 没有 socket 收空这个信号，也就不看内核忙不忙
    /// By memory alone: TCP and DoH have no socket running empty to tell by, so whether the
    /// kernel is busy does not come into it
    #[inline]
    pub fn permit_by_memory(
        &self,
        manager: &Arc<PermitManager>,
        device: DeviceSlot,
    ) -> Option<PermitGuard> {
        if self.memory_refuses(manager, device) {
            manager.count_refused();
            None
        } else {
            Some(manager.acquire_for(device))
        }
    }

    /// `device` 的一条 TCP 或 DoH 新连接接不接：和查询一样只看内存，紧张时开着的连接不比各设备平均少，或者占着查询的那一份
    /// （见 [`Self::memory_refuses`]），就不接——占着内存的设备开新连接，连接上的查询反正也要被拒。连接和查询各比各的：
    /// 只开着一条空闲连接不算占了查询的份，开着很多连接的设备（比如 DoH 前面的反向代理）也不把查询的份额压小
    /// Whether a new TCP or DoH connection from `device` is taken: by memory alone, as for a
    /// query, and when tight a device holding no fewer open connections than the average, or
    /// holding its share of queries (see [`Self::memory_refuses`]), gets none: a device holding
    /// the memory would have the queries on a new connection refused anyway. Connections and
    /// queries are each compared with their own kind: one idle connection is no share of queries,
    /// and a device holding many connections (a reverse proxy in front of DoH, say) does not make
    /// the shares of queries smaller
    #[inline]
    pub fn connection_permit(
        &self,
        manager: &Arc<PermitManager>,
        device: DeviceSlot,
    ) -> Option<PermitGuard> {
        let refused = match self.memory.room(manager.inflight()) {
            Room::Plenty => false,
            Room::Tight => {
                manager.connections.holds_its_share(device)
                    || manager
                        .queries
                        .holds_share_of(device, self.memory.tight_budget(manager.queries.total()))
            }
            Room::Full => true,
        };
        if refused {
            manager.count_refused();
            None
        } else {
            Some(manager.acquire_connection_for(device))
        }
    }
}

/// 按设备记在途数的份数：设备按哈希落到其中一份，哈希每次启动都不同，同一份的设备一起算一台。份数多到两千台设备里落在一起
/// 的约 3%；在途的计数是几个核一起改的原子数，按份的数组比按设备的表省得多，两种东西各 256 KiB
/// How many slots the in-flight counts per device are kept in: a device lands in one by a hash
/// that differs at each start, and devices in the same slot count as one. There are enough that
/// about 3% of two thousand devices land together; the counts are atomics several cores change at
/// once, and an array of slots costs far less than a table by device, 256 KiB for each kind
const DEVICE_SLOTS: usize = 65536;

/// 一台设备落在的那一份 / The slot a device lands in
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DeviceSlot(u16);

/// 一种东西按设备记的在途：每一份的个数、有在途的份数、一共多少。份额按同一种东西比
/// What is in flight of one kind, per device: the count in each slot, how many slots hold
/// any, and how many in all. Shares are compared within one kind
struct DeviceCounts {
    per_slot: Box<[AtomicU32]>,
    slots_held: AtomicUsize,
    total: AtomicUsize,
}

impl DeviceCounts {
    fn new() -> Self {
        // 清零的分配：这么大的一块通常由系统按页给零页，碰到的份才真正占内存；没开流控时一份都不碰
        // A zeroed allocation: a block this large usually comes from the system as zero pages, so
        // only the slots touched take memory; without flow control not a slot is touched
        let zeroed: Box<[u32]> = vec![0u32; DEVICE_SLOTS].into_boxed_slice();
        // SAFETY: AtomicU32 和 u32 的大小、对齐、有效位都相同，这块内存按同样的布局分配，也按同样的布局释放
        // SAFETY: AtomicU32 has the same size, alignment and bit validity as u32, so this block is
        // allocated and freed with the same layout
        let per_slot = unsafe { Box::from_raw(Box::into_raw(zeroed) as *mut [AtomicU32]) };
        Self {
            per_slot,
            slots_held: AtomicUsize::new(0),
            total: AtomicUsize::new(0),
        }
    }

    fn add(&self, device: DeviceSlot) {
        self.total.fetch_add(1, Ordering::Relaxed);
        if self.per_slot[usize::from(device.0)].fetch_add(1, Ordering::Relaxed) == 0 {
            self.slots_held.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// 一共多少 / How many in all
    fn total(&self) -> usize {
        self.total.load(Ordering::Relaxed)
    }

    /// 减一，在 0 处饱和 / Takes one off, saturating at zero
    fn remove(&self, device: DeviceSlot) {
        #[allow(deprecated)]
        let _ = self
            .total
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |total| {
                total.checked_sub(1)
            });
        #[allow(deprecated)]
        let was = self.per_slot[usize::from(device.0)].fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |held| held.checked_sub(1),
        );
        if was == Ok(1) {
            #[allow(deprecated)]
            let _ = self
                .slots_held
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |slots| {
                    slots.checked_sub(1)
                });
        }
    }

    /// `device` 在途的是不是不比各设备的平均少：只有一台在途时就是它；自己没有在途的不算，哪台都没有在途时也一样。
    /// 一台在刷的设备被拒以后在途的很快就走光，这时都算的话发得少的也跟着被拒，拒得越管用越分不出是谁在刷。
    /// 就是 [`Self::holds_share_of`] 的预算取现在一共在途的数
    /// Whether `device` holds no less in flight than the average across devices: a lone one in
    /// flight does; one with nothing in flight does not, also with nothing in flight anywhere. A
    /// device flooding has its queries in flight run out soon once refused, and counting everyone
    /// then would refuse those sending little along with it: the better the refusing works, the
    /// less it could tell who floods. It is [`Self::holds_share_of`] with what is in flight now
    /// as the budget
    fn holds_its_share(&self, device: DeviceSlot) -> bool {
        self.holds_share_of(device, self.total())
    }

    /// 在途一共到了 `budget`，`device` 又占着 `budget` 平分给各台有在途的设备的那一份：两样都是才算。没到预算谁都不算，
    /// 自己没有在途的也不算。预算是定数，所以设备再多，一共也只多出每台一个：和平均比的话，有一台偏多，别的就都在平均下面，
    /// 一个个放进去又把平均抬高，一共能涨到设备数乘最多的那台
    /// Whether `budget` is in flight in all and `device` holds its share of `budget` split among
    /// the devices holding any: both, or it does not count. Under the budget nobody does, nor does
    /// a device with nothing in flight. The budget is fixed, so however many devices there are
    /// they hold at most one more each in all; compared with the average instead, one device
    /// holding more leaves all the others under it, each let in raises the average again, and
    /// the total could climb to the devices times the one holding most
    fn holds_share_of(&self, device: DeviceSlot, budget: usize) -> bool {
        let own = self.per_slot[usize::from(device.0)].load(Ordering::Relaxed) as usize;
        let slots = self.slots_held.load(Ordering::Relaxed).max(1);
        own > 0 && self.total() >= budget && own.saturating_mul(slots) >= budget
    }

    /// 内核忙时 `device` 是不是占着 `budget` 的那一份：同 [`Self::holds_share_of`]，只是有在途的设备不超过
    /// [`MAX_QUEUED_DEVICES`] 台时每台至少 [`SHARE_AT_LEAST`] 个。内存紧张时不这样：那时管的是内存
    /// Whether `device` holds its share of `budget` while the kernel is busy: as
    /// [`Self::holds_share_of`], only with at most [`MAX_QUEUED_DEVICES`] devices holding any each
    /// gets at least [`SHARE_AT_LEAST`]. Not so with memory tight: memory is what counts then
    fn holds_busy_share_of(&self, device: DeviceSlot, budget: usize) -> bool {
        let slots = self.slots_held.load(Ordering::Relaxed);
        let at_least = SHARE_AT_LEAST.saturating_mul(slots.min(MAX_QUEUED_DEVICES));
        self.holds_share_of(device, budget.max(at_least))
    }
}

/// 一个 permit 记在哪一种上 / Which kind a permit is counted as
#[derive(Clone, Copy, Debug)]
enum Held {
    Query,
    Connection,
}

/// 记着有多少查询和连接在处理、拒绝了多少 / Counts the queries and connections being handled, and those refused
pub struct PermitManager {
    // Current active permits (acquired) / 当前活跃 permits（已获得）
    pub(crate) active_permits: AtomicUsize,
    // Count of requests refused / 被拒绝的请求计数
    dropped_requests: AtomicU64,
    /// 开了流控时，每一份设备在途的查询 / With flow control on, the queries in flight per slot of devices
    queries: DeviceCounts,
    /// 开了流控时，每一份设备开着的 TCP 和 DoH 连接 / With flow control on, the TCP and DoH
    /// connections open per slot of devices
    connections: DeviceCounts,
    /// 开了流控时，最近一秒有多少查询在上游超时以前走完，见 [`Self::budget`] / With flow control on, how many
    /// queries were done before the upstream timeout over the last second, see [`Self::budget`]
    done: Done,
    /// 开了流控时，最近十几秒有多少查询回答了、有多少等到了超时，见 [`Self::budget`] / With flow control on,
    /// how many queries were answered and how many waited for the timeout over the last dozen
    /// seconds or so, see [`Self::budget`]
    recent: Done,
    /// 记下的预算：高 32 位是算的时候在第几格，低 32 位是预算，见 [`Self::budget`] / The budget kept: the bucket it
    /// was worked out in, in the high 32 bits, and the budget in the low 32, see [`Self::budget`]
    budget_kept: AtomicU64,
    /// 上游超时，毫秒：在途这么久才走完的是等到了超时，见 [`Self::set_upstream_timeout`] / The upstream
    /// timeout in milliseconds: a query done after this long in flight waited for the timeout, see
    /// [`Self::set_upstream_timeout`]
    upstream_timeout_ms: AtomicU64,
    hasher: RandomState,
}

impl Default for PermitManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PermitManager {
    pub fn new() -> Self {
        Self {
            active_permits: AtomicUsize::new(0),
            dropped_requests: AtomicU64::new(0),
            queries: DeviceCounts::new(),
            connections: DeviceCounts::new(),
            done: Done::new(BUCKET),
            recent: Done::new(RECENT_BUCKET),
            budget_kept: AtomicU64::new(u64::MAX),
            upstream_timeout_ms: AtomicU64::new(u64::MAX),
            hasher: RandomState::new(),
        }
    }

    /// 拿一个 permit：这里不拒绝，只记着有多少在处理 / Takes a permit: nothing is refused here, this only counts what is being handled
    pub fn acquire(self: &Arc<Self>) -> PermitGuard {
        self.active_permits.fetch_add(1, Ordering::Release);
        PermitGuard::new(Arc::clone(self), None, None)
    }

    /// 给 `device` 的一个查询拿 permit，也记在它那一份上，记下拿到的时刻（见 [`PermitGuard::held_since`]）/ Takes
    /// a permit for a query of `device`, counted in its slot as well, noting when it was taken (see
    /// [`PermitGuard::held_since`])
    pub fn acquire_for(self: &Arc<Self>, device: DeviceSlot) -> PermitGuard {
        self.active_permits.fetch_add(1, Ordering::Release);
        self.queries.add(device);
        PermitGuard::new(
            Arc::clone(self),
            Some((device, Held::Query)),
            Some(Instant::now()),
        )
    }

    /// 给 `device` 的一条连接拿 permit，也记在它那一份的连接上 / Takes a permit for a connection of
    /// `device`, counted among its slot's connections as well
    pub fn acquire_connection_for(self: &Arc<Self>, device: DeviceSlot) -> PermitGuard {
        self.active_permits.fetch_add(1, Ordering::Release);
        self.connections.add(device);
        PermitGuard::new(Arc::clone(self), Some((device, Held::Connection)), None)
    }

    /// 客户端地址所属的设备落在哪一份 / The slot the device of a client address lands in
    #[inline]
    pub fn slot_of(&self, client: std::net::IpAddr) -> DeviceSlot {
        let hash = self.hasher.hash_one(Device::of(client));
        DeviceSlot((hash % DEVICE_SLOTS as u64) as u16)
    }

    /// 记下一个被拒绝的查询或连接，隔一阵记一条日志 / Counts a refused query or connection, with a log line now and then
    pub fn count_refused(&self) {
        let dropped = self.dropped_requests.fetch_add(1, Ordering::Relaxed);
        if dropped.is_multiple_of(100_000) {
            tracing::warn!(
                inflight = self.inflight(),
                dropped_total = dropped + 1,
                "flow control is refusing queries"
            );
        }
    }

    /// Return one permit. Saturates at zero so the counter can never wrap: a
    /// wrapped counter reads as "full" and refuses every acquire until restart.
    /// 归还一个 permit。在 0 处饱和，计数永不回绕：回绕后的计数看起来是"满的"，
    /// 会拒绝所有 acquire 直到重启。
    /// 记在某台设备上的，那一份也减一，减到 0 时有在途的份数也减一，同样在 0 处饱和
    /// One counted for a device takes one off its slot too, and a slot reaching 0 takes one off
    /// the slots in flight, saturating at zero in the same way
    #[inline]
    fn release_one(&self, device: Option<(DeviceSlot, Held)>, held_since: Option<Instant>) {
        // Rust 1.99 renamed fetch_update to try_update. The crate declares no
        // minimum toolchain, so keep the old name, which every toolchain has,
        // until one is set at 1.99 or later.
        // Rust 1.99 把 fetch_update 改名为 try_update。crate 没有声明最低工具链，
        // 先保留所有版本都有的旧名字，等最低版本定到 1.99 以上再换。
        #[allow(deprecated)]
        let _ = self
            .active_permits
            .fetch_update(Ordering::Release, Ordering::Relaxed, |active| {
                active.checked_sub(1)
            });
        match device {
            Some((device, Held::Query)) => {
                self.queries.remove(device);
                if let Some(held_since) = held_since {
                    self.note_done(held_since, Instant::now());
                }
            }
            Some((device, Held::Connection)) => self.connections.remove(device),
            None => {}
        }
    }

    /// 一个从 `held_since` 起在途的查询在 `now` 走完：记下它有没有等到上游超时，见 [`Self::budget`]
    /// A query in flight since `held_since` is done at `now`: noted with whether it waited for the
    /// upstream timeout, see [`Self::budget`]
    #[inline]
    fn note_done(&self, held_since: Instant, now: Instant) {
        let held = now.saturating_duration_since(held_since).as_millis();
        let answered = held < u128::from(self.upstream_timeout_ms.load(Ordering::Relaxed));
        // 一秒的那些格只看回答了的；等到超时的只记在十几秒的那些格里
        // The buckets of the second look only at those answered; those that waited for the
        // timeout are noted only in the buckets of the dozen seconds
        if answered {
            self.done.note(now, true);
        }
        self.recent.note(now, answered);
    }

    /// 配置里的上游超时（`upstream_timeout_ms`），启动和每次重载时记下：在途这么久才走完的是等到了超时，不算回答了，见
    /// [`Self::budget`]。没记下时都算
    /// The upstream timeout of the configuration (`upstream_timeout_ms`), noted at start and at
    /// each reload: a query done only after this long in flight waited for the timeout and does not
    /// count as answered, see [`Self::budget`]. With none noted every one counts
    pub fn set_upstream_timeout(&self, timeout: Duration) {
        let ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
        self.upstream_timeout_ms.store(ms, Ordering::Relaxed);
    }

    /// 记下的上游超时，见 [`Self::set_upstream_timeout`] / The upstream timeout noted, see
    /// [`Self::set_upstream_timeout`]
    pub fn upstream_timeout(&self) -> Duration {
        Duration::from_millis(self.upstream_timeout_ms.load(Ordering::Relaxed))
    }

    /// Get current inflight permits count / 获取当前进行中的 permits 数
    #[inline]
    pub fn inflight(&self) -> usize {
        self.active_permits.load(Ordering::Acquire)
    }

    /// 内核忙时在途的查询一共最多多少（见 [`FlowControlState::permit`]）：到 `now` 为止的最近一秒里，有多少查询没等到上游超时
    /// 就走完了（回答了、失败了都算，见 [`Self::set_upstream_timeout`]），至少 `BUDGET_AT_LEAST`。在途的数除以每秒走完的数就是
    /// 平均要等多久（利特尔定律），所以在途比它多，就是在途的平均要等 `HELD_AT_MOST` 以上。等到超时才走完的不算：对着不回答的域名
    /// 洪泛，一批一起超时时那一下走完的很多，算进去的话预算跟着跳上去，又放进一批，在途一圈圈往上涨；不算它们，预算就停在别的设备
    /// 答上的那些和底数上。按超时分而不按 `HELD_AT_MOST` 分：上游一次要将近一秒、内核忙时自己又排着几十毫秒，回答了的也过了一秒，
    /// 按一秒分就都不算，预算掉回底数再也起不来；慢的回答照样算进去，在途的平均超过 `HELD_AT_MOST` 时一样会拒。看的是整整一秒：
    /// 只看几毫秒，上游回答得整齐时一批放进去的要过一个延迟才一起走完，没放的那一小段过一个延迟就空着，预算掉回底数，又放不进，
    /// 这个缺口一直留着。最近零点几秒走得更快时跟着那一段，最多到整秒的 [`FOLLOWS_FASTER_AT_MOST`] 倍：放进去的要过一个延迟才
    /// 走完，整秒的数比放进去的落后一个延迟，上游一次要将近一秒时，只看整秒的话负载一下子上来，预算每秒只涨一成多；最多两倍，是不让
    /// 零点一秒里偶尔一下走完很多就把预算抬得太高。只在最近 `RECENT_LOOKED_AT` 秒走完的查询里等到超时的不到
    /// `1 / TIMED_OUT_ONE_IN` 时才这样跟：跟是在赌刚放进去的也会回答，平常超时的极少，这一赌稳赢；一半等到超时的洪泛里，被拒、
    /// 放开、再被拒，每次放开时最近零点几秒都比整秒快，跟的话预算一次次被抬到两倍，在途在一千到两万之间来回晃。要等到超时才知道
    /// 输了，所以记的比上游超时还久，一阵阵的洪泛每阵之间也还记着
    /// How many queries may be in flight in all while the kernel is busy (see
    /// [`FlowControlState::permit`]): how many queries were done short of the upstream timeout over
    /// the last second up to `now` (answered or failed alike, see [`Self::set_upstream_timeout`]),
    /// at least `BUDGET_AT_LEAST`. What is in flight over how many are done per second is how long
    /// they take on average (Little's law), so more in flight than this means they take over
    /// `HELD_AT_MOST` on average. Those done only at the timeout do not count: flooding names that
    /// get no answer, with a batch timing out together many are done at that moment, so counting
    /// them would make the budget jump, let another batch in, and climb round after round; without
    /// them, the budget stays at what other devices get answered and the floor. They are told apart
    /// by the timeout rather than by `HELD_AT_MOST`: with an upstream taking close to a second and
    /// the busy kernel queueing tens of milliseconds of its own, answered queries go past a second
    /// too, so splitting at a second would count none, and the budget would fall to its floor and
    /// never rise again; slow answers count all the same, and in flight averaging over
    /// `HELD_AT_MOST` is refused just as well. A whole second is looked at: looking at a few
    /// milliseconds, with an upstream answering evenly a batch let in is done together one delay
    /// later, a stretch with none let in is empty one delay later, the budget falls back to the
    /// floor and lets none in again, so the gap never closes. When the last tenths of a second went
    /// faster it follows them, up to [`FOLLOWS_FASTER_AT_MOST`] times the whole second's count:
    /// what is let in is done one delay later, so the whole second lags what is let in by a delay,
    /// and with an upstream taking close to a second, load coming on at once would raise a budget
    /// looking at the whole second only a tenth or so a second; at most twice, so that a tenth of a
    /// second now and then with many done does not lift the budget too far. It follows so only while
    /// fewer than `1 / TIMED_OUT_ONE_IN` of the queries done over the last `RECENT_LOOKED_AT`
    /// seconds waited for the timeout: following is a bet that what was just let in will be
    /// answered too, a safe bet with timeouts as rare as they usually are; in a flood half of which
    /// waits for the timeout, refused, let in and refused again, each letting in finds the last
    /// tenths faster than the second, so following would lift the budget to twice over and over,
    /// what is in flight swinging between a thousand and twenty thousand. A lost bet shows only at
    /// the timeout, so this is remembered for longer than the upstream timeout, between the waves
    /// of a flood too
    ///
    /// 一格之内看的格不变，所以每格只算一次，记下来给这一格里的查询用；十几秒那些格里现在这一格的超时，最多晚一格才算进来
    /// The buckets looked at stay the same within a bucket, so it is worked out once a bucket and
    /// kept for the queries in it; timeouts in the current bucket of the dozen seconds come in at
    /// most a bucket late
    #[inline]
    pub fn budget(&self, now: Instant) -> usize {
        let number = self.done.bucket_of(now) & u64::from(u32::MAX);
        let kept = self.budget_kept.load(Ordering::Relaxed);
        if kept >> 32 == number {
            return (kept & u64::from(u32::MAX)) as usize;
        }
        let budget = self.budget_at(now).min(u32::MAX as usize);
        self.budget_kept
            .store(number << 32 | budget as u64, Ordering::Relaxed);
        budget
    }

    /// 按 `now` 现算的预算，见 [`Self::budget`] / The budget worked out afresh at `now`, see [`Self::budget`]
    fn budget_at(&self, now: Instant) -> usize {
        let (second, faster) = self.done.second_and_faster(now);
        let follows = self.recent.rarely_timed_out(now, RECENT_LOOKED_AT);
        usize::try_from(if follows { faster } else { second })
            .unwrap_or(usize::MAX)
            .max(BUDGET_AT_LEAST)
    }

    /// Get total dropped requests count / 获取总丢弃请求数
    #[inline]
    pub fn dropped_requests(&self) -> u64 {
        self.dropped_requests.load(Ordering::Relaxed)
    }
}

/// RAII guard for automatic permit release / RAII 守卫用于自动 permit 释放
///
/// This guard ensures that permits are properly released even in panic scenarios
/// by using defensive programming techniques.
/// 该守卫通过使用防御性编程技术，确保即使在panic场景下也能正确释放permits。
pub struct PermitGuard {
    manager: Arc<PermitManager>,
    /// 记在哪台设备的那一份、哪一种上（开了流控时）/ The device slot and kind it is counted in (with flow control on)
    device: Option<(DeviceSlot, Held)>,
    /// 开了流控时，查询的 permit 是什么时候拿到的 / With flow control on, when a query's permit was taken
    held_since: Option<Instant>,
    released: AtomicBool, // Track if already released to handle double-drop / 跟踪是否已释放以处理双重释放
}

impl PermitGuard {
    fn new(
        manager: Arc<PermitManager>,
        device: Option<(DeviceSlot, Held)>,
        held_since: Option<Instant>,
    ) -> Self {
        Self {
            manager,
            device,
            held_since,
            released: AtomicBool::new(false),
        }
    }

    /// 开了流控时这个查询的 permit 是什么时候拿到的，没开时是 None / When this query's permit was taken
    /// with flow control on, None without
    #[inline]
    pub fn held_since(&self) -> Option<Instant> {
        self.held_since
    }

    /// Manually release the permit early / 提前手动释放permit
    /// This is useful if you want to release the permit before the guard is dropped.
    /// Consumes self to prevent double-release; Drop impl will see released=true and skip.
    /// 如果你想在guard被drop之前释放permit，这很有用。
    /// 消耗 self 防止双重释放；Drop 实现会看到 released=true 并跳过。
    pub fn release(self) {
        // Mark as released and decrement / 标记为已释放并递减
        if self
            .released
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            self.manager.release_one(self.device, self.held_since);
        }
        // self is dropped here; Drop::drop sees released=true → no double free
    }
}

impl Drop for PermitGuard {
    fn drop(&mut self) {
        // Use compare_exchange to handle potential double-drop scenarios
        // 使用compare_exchange处理潜在的双重释放场景
        if self
            .released
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            self.manager.release_one(self.device, self.held_since);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::memory_watermark::{MemoryLeft, MemoryReading, MemoryWatermark};

    fn state(busy_after: Duration) -> FlowControlState {
        let mut state = FlowControlState::new(MemoryWatermark::reading(MemoryReading::default));
        state.busy_after = busy_after;
        state
    }

    const LONG_AGO: Duration = Duration::from_secs(61);
    /// 处理得极快的 worker：预算怎么都用不完，只看别的规则 / A worker handling queries extremely fast: the
    /// budget never runs out, leaving the other rules alone
    const FAST: usize = usize::MAX;
    /// 两台设备，固定落在不同的两份 / Two devices, fixed in two different slots
    const ONE: DeviceSlot = DeviceSlot(0);
    const OTHER: DeviceSlot = DeviceSlot(1);

    /// 忙而且排长队才拒绝：只忙（上游慢、socket 收不空）或只排队（短暂卡顿）都不拒绝
    /// Refused only when busy and queueing long: busy alone (a slow upstream, a socket not
    /// running empty) or queueing alone (a brief stall) refuses nothing
    #[test]
    fn a_query_is_refused_only_when_busy_and_behind() {
        let manager = Arc::new(PermitManager::new());
        let flow = state(Duration::from_secs(60));
        let busy = Instant::now() - LONG_AGO;

        let busy_alone = flow.permit(&manager, busy, ONE, FAST);
        assert!(busy_alone.is_some(), "busy alone");

        flow.note_queue_delay(Duration::from_secs(3600));
        let behind_alone = flow.permit(&manager, Instant::now(), ONE, FAST);
        assert!(behind_alone.is_some(), "behind alone");
        assert_eq!(manager.dropped_requests(), 0);

        assert!(flow.permit(&manager, busy, ONE, FAST).is_none(), "both");
        assert_eq!(manager.dropped_requests(), 1);
        assert_eq!(manager.inflight(), 2, "a refused query holds no permit");
    }

    /// 忙而且排长队时只拒在途不比平均少的设备：一台在刷时拒它，发得少的照常；没有在途的不拒，哪台都没有在途时也
    /// 一样，只有一台时它放进一个以后再拒
    /// Busy and queueing long, only devices holding no less than the average in flight are
    /// refused: the one sending most is, those sending little go on; one with nothing in flight
    /// is not, also with nothing in flight anywhere, so a lone one gets one in and is refused after
    #[test]
    fn busy_and_behind_refuses_only_the_devices_holding_their_share() {
        let manager = Arc::new(PermitManager::new());
        let flow = state(Duration::from_secs(60));
        let busy = Instant::now() - LONG_AGO;
        flow.note_queue_delay(Duration::from_secs(3600));
        let heavy: Vec<_> = (0..100).map(|_| manager.acquire_for(ONE)).collect();
        assert!(
            flow.permit(&manager, busy, ONE, FAST).is_none(),
            "the device sending most"
        );
        let light = flow
            .permit(&manager, busy, OTHER, FAST)
            .expect("one sending little goes on");
        assert!(
            flow.permit(&manager, busy, OTHER, FAST).is_some(),
            "still far below the average"
        );
        assert_eq!(manager.dropped_requests(), 1);
        drop((heavy, light));
        let first = flow
            .permit(&manager, busy, OTHER, FAST)
            .expect("nothing in flight anywhere");
        assert!(
            flow.permit(&manager, busy, OTHER, FAST).is_none(),
            "alone now"
        );
        drop(first);
    }

    /// 预算看的是最近一秒里没等到上游超时就走完的查询，至少是底数：0.5 秒时走完 2000 个，1.2 秒和 1.55 秒时看得到这 2000 个；
    /// 正在记的那一格不算，过了一秒也不算；从拿到 permit 起到了上游超时才走完的不算，慢一点的回答照样算
    /// The budget looks at the queries done short of the upstream timeout over the last second, at
    /// least its floor: 2000 done at 0.5 s are seen at 1.2 s and 1.55 s; the bucket being noted in
    /// does not count, nor does one over a second old; those done only at the upstream timeout
    /// after taking their permit do not count, while slower answers count all the same
    #[test]
    fn the_budget_is_what_was_done_short_of_the_timeout_over_the_last_second() {
        let manager = PermitManager::new();
        manager.set_upstream_timeout(Duration::from_secs(2));
        let at = |ms: u64| manager.done.started + Duration::from_millis(ms);
        for _ in 0..2000 {
            manager.note_done(at(450), at(500));
        }
        assert_eq!(
            manager.budget_at(at(550)),
            BUDGET_AT_LEAST,
            "still being noted in"
        );
        assert_eq!(manager.done.last_second(at(1200)), 2000);
        assert_eq!(
            manager.done.last_second(at(1550)),
            2000,
            "the last of the second"
        );
        assert_eq!(manager.done.last_second(at(1650)), 0);
        assert_eq!(
            manager.budget_at(at(1650)),
            BUDGET_AT_LEAST,
            "over a second old"
        );
        for _ in 0..5000 {
            manager.note_done(at(2000), at(4050));
        }
        manager.note_done(at(2900), at(4050));
        assert_eq!(
            manager.done.last_second(at(4150)),
            1,
            "only the one answered after 1.15 s"
        );
    }

    /// 看的是整整一秒：上游回答得整齐、一段时间没放进去，过一个延迟那一小段没有走完的，预算只少那一小段，不掉回底数；那一小段
    /// 之后又一直走完得一样快，预算跟着最近这一段。以前按几毫秒里走完的速度算，这时掉回底数，又放不进，缺口一直留着
    /// A whole second is looked at: with an upstream answering evenly and a stretch with none let
    /// in, one delay later the stretch has none done and the budget is short of just that stretch,
    /// not back at its floor; with as many done as before ever since, the budget follows that
    /// latest stretch. Worked out from what was done in a few milliseconds it used to fall back
    /// there, let none in, and keep the gap open
    #[test]
    fn a_stretch_with_none_done_leaves_the_rest_of_the_second() {
        let manager = PermitManager::new();
        let at = |ms: u64| manager.done.started + Duration::from_millis(ms);
        for bucket in (0..20).filter(|&bucket| bucket != 15) {
            for _ in 0..5000 {
                manager.note_done(at(bucket * 100), at(bucket * 100 + 30));
            }
        }
        assert_eq!(manager.budget_at(at(1550)), 50_000);
        assert_eq!(manager.budget_at(at(1650)), 45_000, "one stretch short");
        assert_eq!(
            manager.budget_at(at(2050)),
            50_000,
            "as fast for the last 0.4 s"
        );
    }

    /// 最近零点几秒走得比整秒快时预算跟着那一段，最多到整秒的两倍：前九格各 1000、最近一格 1500，预算是 1.5 万；最近两格
    /// 各 5000，整秒 1.85 万，按最近的是 5 万，取两倍 3.7 万
    /// When the last tenths of a second went faster than the whole second the budget follows them,
    /// up to twice the whole second's: nine buckets of 1000 and the latest of 1500 make it 15,000;
    /// the latest two of 5000 each make the second 18,500 and the latest 50,000, so twice, 37,000
    #[test]
    fn the_budget_follows_faster_tenths_up_to_twice_the_second() {
        let manager = PermitManager::new();
        let at = |ms: u64| manager.done.started + Duration::from_millis(ms);
        let fill = |bucket: u64, count: usize| {
            for _ in 0..count {
                manager.note_done(at(bucket * 100), at(bucket * 100 + 10));
            }
        };
        for bucket in 2..11 {
            fill(bucket, 1000);
        }
        fill(11, 1500);
        assert_eq!(manager.budget_at(at(1250)), 15_000);
        fill(12, 5000);
        fill(13, 5000);
        assert_eq!(manager.done.last_second(at(1450)), 18_500);
        assert_eq!(manager.budget_at(at(1450)), 37_000);
    }

    /// 最近十几秒等到超时的有二十分之一，预算就只看整秒、不跟着最近更快的那一段：同样的回答，预算从 15070 变成 10507；超时的
    /// 不到二十分之一时照样跟；那些超时过了十几秒，又跟
    /// With one in twenty of those done over the last dozen seconds or so waiting for the timeout,
    /// the budget goes by the whole second without following the faster latest stretch: the same
    /// answers take it from 15,070 to 10,507; with fewer timeouts than that it follows as before,
    /// and it follows again once those timeouts are over a dozen seconds old
    #[test]
    fn timeouts_stop_the_budget_following_the_faster_tenths() {
        let manager = PermitManager::new();
        manager.set_upstream_timeout(Duration::from_secs(2));
        let at = |ms: u64| manager.done.started + Duration::from_millis(ms);
        let fill = |bucket: u64, count: usize, held_ms: u64| {
            for _ in 0..count {
                manager.note_done(at(bucket * 100 - held_ms), at(bucket * 100));
            }
        };
        for bucket in 32..41 {
            fill(bucket, 1000, 10);
        }
        fill(41, 1507, 10);
        assert_eq!(manager.budget_at(at(4250)), 15_070);
        fill(20, 552, 2000);
        assert_eq!(manager.budget_at(at(4250)), 15_070, "under one in twenty");
        fill(20, 1, 2000);
        assert_eq!(manager.budget_at(at(4250)), 10_507, "one in twenty");
        for bucket in 192..201 {
            fill(bucket, 1000, 10);
        }
        fill(201, 1500, 10);
        assert_eq!(
            manager.budget_at(at(20_250)),
            15_000,
            "over a dozen seconds on"
        );
    }

    /// 每格只算一次：同一格里又记了超时，预算还是这一格开头算的；到了下一格重算
    /// Worked out once a bucket: with timeouts noted again within the same bucket, the budget is
    /// still the one worked out at its start; the next bucket works it out again
    #[test]
    fn the_budget_is_worked_out_once_a_bucket() {
        let manager = PermitManager::new();
        manager.set_upstream_timeout(Duration::from_secs(2));
        let at = |ms: u64| manager.done.started + Duration::from_millis(ms);
        for _ in 0..9000 {
            manager.note_done(at(3500), at(3510));
        }
        for _ in 0..1500 {
            manager.note_done(at(4090), at(4100));
        }
        assert_eq!(manager.budget(at(4210)), 15_000);
        for _ in 0..5000 {
            manager.note_done(at(2210), at(4210));
        }
        assert_eq!(manager.budget(at(4290)), 15_000, "the same bucket");
        assert_eq!(manager.budget(at(4310)), 10_500, "the next");
    }

    /// 一格过了一圈再记，从这一个重新数，不接着上一圈的；这个核在交界处慢了一圈、记的格号比那一格已经记着的早，不记
    /// A bucket noted again a round later counts from this one, not on from the last round; a
    /// core slow by a round at a boundary, noting an earlier number than the bucket already holds,
    /// is left out
    #[test]
    fn a_bucket_starts_again_each_round() {
        let manager = PermitManager::new();
        let at = |ms: u64| manager.done.started + Duration::from_millis(ms);
        let round = BUCKET.as_millis() as u64 * BUCKETS_KEPT as u64;
        for _ in 0..100 {
            manager.done.note(at(50), true);
        }
        manager.done.note(at(round + 50), true);
        manager.done.note(at(50), true);
        assert_eq!(manager.done.last_second(at(round + 150)), 1);
    }

    /// 内核忙时在途一共压到预算：一台设备一直问，放到预算那么多就拒，别的设备照常；不忙时不看预算
    /// Busy, what is in flight is held to the budget: a device asking on and on gets the budget
    /// and is refused after, others going on; not busy, the budget does not come in
    #[test]
    fn busy_holds_what_is_in_flight_to_the_budget() {
        let manager = Arc::new(PermitManager::new());
        let flow = state(Duration::from_secs(60));
        let busy = Instant::now() - LONG_AGO;
        let mut held = Vec::new();
        while let Some(permit) = flow.permit(&manager, busy, ONE, 1000) {
            held.push(permit);
            assert!(held.len() <= 1000, "unbounded");
        }
        assert_eq!(held.len(), 1000);
        let other: Vec<_> = (0..10)
            .map(|_| {
                flow.permit(&manager, busy, OTHER, 1000)
                    .expect("another device goes on")
            })
            .collect();
        assert!(
            flow.permit(&manager, Instant::now(), ONE, 1000).is_some(),
            "not busy, the budget does not come in"
        );
        assert_eq!(manager.dropped_requests(), 1);
        drop((held, other));
    }

    /// 轮流时没到预算谁都不拒：洪泛的设备只剩一个在途，发得少的设备一次问好几个照常；只有一台设备时放到预算那么多才拒。以前
    /// 后面还排着别的、在途又不比平均少就拒，平均被压到 1，发得少的设备并发的中间几个、只有一台时的那台都被拒
    /// While taking turns, under the budget nobody is refused: with a flooding device down to one
    /// in flight, a device sending little asking several at once goes on, and a lone device is
    /// refused only with the budget in flight. Holding no less than the average with more queued
    /// used to be refused, the average pressed down to one, so the middle ones of a few at once and
    /// a lone device were refused
    #[test]
    fn under_the_budget_taking_turns_refuses_nobody() {
        let manager = Arc::new(PermitManager::new());
        let flow = state(Duration::from_secs(60));
        let budget = BUDGET_AT_LEAST;
        let flooder = manager.acquire_for(ONE);
        let light: Vec<_> = (0..8)
            .map(|_| {
                flow.turn_permit(&manager, OTHER, budget)
                    .expect("several at once")
            })
            .collect();
        drop((flooder, light));
        let alone: Vec<_> = (0..budget)
            .map(|_| {
                flow.turn_permit(&manager, ONE, budget)
                    .expect("a lone device under the budget")
            })
            .collect();
        assert!(
            flow.turn_permit(&manager, ONE, budget).is_none(),
            "at the budget"
        );
        assert_eq!(manager.dropped_requests(), 1);
        drop(alone);
        let half: Vec<_> = (0..budget / 2).map(|_| manager.acquire_for(ONE)).collect();
        let other = manager.acquire_for(OTHER);
        assert!(
            flow.turn_permit(&manager, ONE, budget).is_some(),
            "holding most, but the budget is not in flight"
        );
        drop((half, other));
    }

    /// 到了预算，设备再多一共也只多出每台一个：一千台设备轮着问到谁都放不进，在途不超过预算加设备数；什么都没在途的设备照样
    /// 放进去。以前和平均比，设备多到每台只排得进一个时规则不起作用，在途一直涨到内存水位
    /// At the budget, however many devices there are they hold at most one more each: a thousand
    /// devices asking in turn until none gets in hold no more than the budget plus the devices,
    /// and a device with nothing in flight still gets in. Compared with the average, the rule did
    /// nothing once there were enough devices for each to queue only one, and what was in flight
    /// climbed to the memory watermark
    #[test]
    fn at_the_budget_many_devices_hold_at_most_one_more_each() {
        let manager = Arc::new(PermitManager::new());
        let flow = state(Duration::from_secs(60));
        let budget = 3200;
        let mut held = Vec::new();
        loop {
            let before = held.len();
            held.extend(
                (0..1000u16).filter_map(|n| flow.turn_permit(&manager, DeviceSlot(n), budget)),
            );
            assert!(held.len() <= 10 * budget, "unbounded");
            if held.len() == before {
                break;
            }
        }
        assert!(held.len() >= budget, "{} held", held.len());
        assert!(held.len() <= budget + 1000, "{} held", held.len());
        assert!(
            flow.turn_permit(&manager, DeviceSlot(5000), budget)
                .is_some(),
            "one with nothing in flight"
        );
        drop(held);
    }

    /// 内核忙时每台设备在途至少 4 个：一千台各占 4 个、预算在底数，发得少的设备一次问 4 个都放进去，第 5 个才拒，洪泛的那些再来
    /// 也拒；轮流时一样。设备超过 4096 台时不再照顾，每台又和以前一样，占着一个就拒。以前一千台时每台只有一个，并发的第二个起
    /// 回 SERVFAIL
    /// While the kernel is busy each device holds at least 4 in flight: with a thousand holding 4
    /// each and the budget at its floor, a device sending little asking 4 at once gets them all and
    /// only a fifth is refused, as are more from the flooding ones; taking turns alike. Past 4096
    /// devices none is looked after so, each again refused holding one as before. With a thousand,
    /// each used to get one, the second of a few at once getting SERVFAIL
    #[test]
    fn busy_each_device_holds_at_least_a_few() {
        let manager = Arc::new(PermitManager::new());
        let flow = state(Duration::from_secs(60));
        let busy = Instant::now() - LONG_AGO;
        let flooders: Vec<_> = (0..1000u16)
            .flat_map(|n| std::iter::repeat_n(DeviceSlot(n), SHARE_AT_LEAST))
            .map(|slot| manager.acquire_for(slot))
            .collect();
        let light = DeviceSlot(5000);
        let asked: Vec<_> = (0..SHARE_AT_LEAST)
            .map(|_| {
                flow.permit(&manager, busy, light, BUDGET_AT_LEAST)
                    .expect("a few at once")
            })
            .collect();
        assert!(
            flow.permit(&manager, busy, light, BUDGET_AT_LEAST)
                .is_none(),
            "past its share"
        );
        let in_turn: Vec<_> = (0..SHARE_AT_LEAST)
            .map(|_| {
                flow.turn_permit(&manager, DeviceSlot(6000), BUDGET_AT_LEAST)
                    .expect("a few at once, taking turns")
            })
            .collect();
        assert!(
            flow.turn_permit(&manager, DeviceSlot(0), BUDGET_AT_LEAST)
                .is_none(),
            "a flooding one, taking turns"
        );
        assert!(
            flow.permit(&manager, Instant::now(), DeviceSlot(0), BUDGET_AT_LEAST)
                .is_some(),
            "not busy"
        );
        drop((flooders, asked, in_turn));

        let many: Vec<_> = (0..20_000u16)
            .map(|n| manager.acquire_for(DeviceSlot(n)))
            .collect();
        assert!(
            flow.permit(&manager, busy, DeviceSlot(0), BUDGET_AT_LEAST)
                .is_none(),
            "past the devices looked after"
        );
        drop(many);
    }

    /// 排队没超过目标不算跟不上；超过了就按等了多久算，到点自己恢复
    /// Queueing within the target does not count as behind; past it, it counts for as long as
    /// the query waited, and ends by itself
    #[test]
    fn behind_lasts_as_long_as_the_queue_was() {
        let flow = state(Duration::ZERO);
        flow.note_queue_delay(QUEUE_TARGET);
        assert!(!flow.behind(), "the target itself is fine");

        flow.note_queue_delay(QUEUE_TARGET + Duration::from_millis(30));
        assert!(flow.behind());
        std::thread::sleep(QUEUE_TARGET + Duration::from_millis(60));
        assert!(!flow.behind(), "it ends by itself");

        flow.note_queue_delay(Duration::from_secs(3600));
        flow.note_queue_delay(QUEUE_TARGET);
        assert!(flow.behind(), "a short wait does not end it early");
        std::thread::sleep(QUEUE_TARGET + Duration::from_millis(5));
        assert!(flow.behind(), "a long queue lasts longer than the target");
    }

    /// TCP 和 DoH 只看内存：内核忙而且排长队也放行，内存不够时拒绝并记下
    /// TCP and DoH go by memory alone: with the kernel busy and queueing long they go ahead,
    /// and too little memory refuses and counts them
    #[test]
    fn a_stream_query_goes_by_memory_alone() {
        let manager = Arc::new(PermitManager::new());
        let mut flow = state(Duration::ZERO);
        flow.note_queue_delay(Duration::from_secs(3600));
        let plenty = flow.permit_by_memory(&manager, ONE);
        assert!(plenty.is_some());
        assert_eq!(manager.inflight(), 1, "it counts among those in flight");

        flow.memory = MemoryWatermark::reading(|| MemoryReading {
            own: 0,
            limits: vec![MemoryLeft {
                total: 1 << 30,
                available: 0,
            }],
        });
        let in_flight: Vec<_> = (0..1000).map(|_| manager.acquire()).collect();
        assert!(flow.permit_by_memory(&manager, ONE).is_none());
        assert_eq!(manager.dropped_requests(), 1);
        drop(in_flight);
    }

    /// 内存不够时，内核不忙也拒绝并记下；在途查询少时不看内存，照常放行
    /// Too little memory refuses and counts a query even with the kernel not busy; with few
    /// queries in flight memory is not looked at and they go ahead
    #[test]
    fn too_little_memory_refuses_a_query_even_when_not_busy() {
        let manager = Arc::new(PermitManager::new());
        let mut flow = state(Duration::from_secs(3600));
        flow.memory = MemoryWatermark::reading(|| MemoryReading {
            own: 0,
            limits: vec![MemoryLeft {
                total: 1 << 30,
                available: 0,
            }],
        });

        let mut in_flight: Vec<_> = (0..999)
            .map(|_| {
                flow.permit(&manager, Instant::now(), ONE, FAST)
                    .expect("few in flight")
            })
            .collect();
        in_flight.push(
            flow.permit(&manager, Instant::now(), ONE, FAST)
                .expect("the last under the floor"),
        );
        assert_eq!(manager.dropped_requests(), 0);

        assert!(flow.permit(&manager, Instant::now(), ONE, FAST).is_none());
        assert_eq!(manager.dropped_requests(), 1);
        assert_eq!(manager.inflight(), 1000, "a refused query holds no permit");

        in_flight.truncate(999);
        assert!(
            flow.permit(&manager, Instant::now(), ONE, FAST).is_some(),
            "under the floor again"
        );
    }

    /// 从上次收空算起够久了才算忙；阈值是 0 时一直算忙
    /// Busy only once long enough has passed since the socket last ran empty; with a threshold of 0, always
    #[test]
    fn busy_is_judged_from_when_the_socket_last_ran_empty() {
        let state = state(Duration::from_secs(60));
        assert!(!state.busy(Instant::now()));
        assert!(state.busy(Instant::now() - LONG_AGO));

        let always = super::tests::state(Duration::ZERO);
        assert!(always.busy(Instant::now()));
    }

    /// 还回来以后计数归零 / The count returns to zero once permits are given back
    #[test]
    fn permits_are_counted_and_released() {
        let manager = Arc::new(PermitManager::new());
        let first = manager.acquire();
        let second = manager.acquire();
        assert_eq!(manager.inflight(), 2);
        drop(first);
        assert_eq!(manager.inflight(), 1);
        drop(second);
        assert_eq!(manager.inflight(), 0);
    }

    /// 总量 1 GiB、剩下 `available` 字节的流控 / Flow control over 1 GiB with `available` bytes left
    fn with_memory_left(available: u64) -> FlowControlState {
        let mut flow = state(Duration::from_secs(3600));
        flow.memory = MemoryWatermark::reading(move || MemoryReading {
            own: 0,
            limits: vec![MemoryLeft {
                total: 1 << 30,
                available,
            }],
        });
        flow
    }

    /// 内存紧张时只拒在途的不比平均少的设备：一台把内存占着时拒它，没有在途的照常，UDP、TCP 和 DoH 都一样
    /// With memory tight only devices holding no less than the average in flight are refused:
    /// the one holding the memory is, one with nothing in flight goes on, over UDP, TCP and DoH alike
    #[test]
    fn tight_memory_refuses_only_the_devices_holding_their_share() {
        let manager = Arc::new(PermitManager::new());
        // 余量 64 MiB，两倍 128 MiB：剩 100 MiB 算紧张 / A 64 MiB margin, twice that 128 MiB: 100 MiB left is tight
        let flow = with_memory_left(100 << 20);
        let heavy: Vec<_> = (0..1000).map(|_| manager.acquire_for(ONE)).collect();
        assert!(
            flow.permit(&manager, Instant::now(), ONE, FAST).is_none(),
            "the device holding the memory"
        );
        assert!(flow.permit_by_memory(&manager, ONE).is_none());
        let light: Vec<_> = (0..10)
            .map(|_| {
                flow.permit(&manager, Instant::now(), OTHER, FAST)
                    .expect("one sending little goes on")
            })
            .collect();
        assert!(flow.permit_by_memory(&manager, OTHER).is_some());
        assert_eq!(manager.dropped_requests(), 2);
        drop((heavy, light));
    }

    /// 内存紧张时在途停在变紧张那一刻：一台偏多、其余一样多的一百台设备轮着问到谁都放不进，在途不超过那时的数加设备数，
    /// 什么都没在途的照样放进去。以前和平均比，偏多的那台把平均抬高，其余的都在平均下面，一个个放进去又抬高平均，一共涨到
    /// 设备数乘最多的那台
    /// With memory tight what is in flight stays where it was as memory got tight: a hundred
    /// devices, one holding more and the rest alike, asking in turn until none gets in hold no more
    /// than that plus the devices, and one with nothing in flight still gets in. Compared with the
    /// average, the one holding more raised the average, leaving the rest under it, each let in
    /// raised it again, and the total climbed to the devices times the one holding most
    #[test]
    fn tight_memory_holds_what_was_in_flight_as_it_got_tight() {
        let manager = Arc::new(PermitManager::new());
        let flow = with_memory_left(100 << 20);
        let mut held: Vec<_> = (0..20)
            .map(|_| manager.acquire_for(DeviceSlot(0)))
            .collect();
        for n in 1..100u16 {
            held.extend((0..10).map(|_| manager.acquire_for(DeviceSlot(n))));
        }
        let noted = held.len();
        loop {
            let before = held.len();
            held.extend((0..100u16).filter_map(|n| flow.permit_by_memory(&manager, DeviceSlot(n))));
            assert!(held.len() <= 3 * noted, "unbounded");
            if held.len() == before {
                break;
            }
        }
        assert!(held.len() <= noted + 100, "{} held", held.len());
        assert!(
            flow.connection_permit(&manager, DeviceSlot(1)).is_none(),
            "nor a new connection for one at its share"
        );
        assert!(
            flow.permit_by_memory(&manager, DeviceSlot(500)).is_some(),
            "one with nothing in flight"
        );
        drop(held);
    }

    /// 内存紧张时，只开着一条空闲连接的设备照样能问：连接和查询各比各的份额，空闲连接不算查询的在途。以前人人一条连接
    /// 时平均就是一条，这些设备连接上和 UDP 上的未命中查询都被拒
    /// With memory tight a device holding just one idle connection can still ask: connections
    /// and queries are each compared with their own kind, and an idle connection is no query in
    /// flight. With one connection each the average used to be one, refusing those devices'
    /// misses on the connection and over UDP alike
    #[test]
    fn an_idle_connection_is_no_share_of_queries() {
        let manager = Arc::new(PermitManager::new());
        let flow = with_memory_left(100 << 20);
        let connections: Vec<_> = (0..1024u16)
            .map(|n| {
                flow.connection_permit(&manager, DeviceSlot(n))
                    .expect("a device with no connection connects")
            })
            .collect();
        assert!(manager.inflight() >= 1000, "memory is read");
        for n in [0, 1, 500, 1023] {
            assert!(
                flow.permit_by_memory(&manager, DeviceSlot(n)).is_some(),
                "a query on the connection of {n}"
            );
            assert!(
                flow.permit(&manager, Instant::now(), DeviceSlot(n), FAST)
                    .is_some(),
                "a query over UDP from {n}"
            );
        }
        assert_eq!(manager.dropped_requests(), 0);
        drop(connections);
    }

    /// 一台设备开着很多连接，不把查询的平均拉高：内核忙而且排长队时，只有一台在问的设备照样放进一个就拒。以前另一台
    /// 开着 600 条空闲连接时，它能同时在途 600 个
    /// A device holding many connections does not raise the average of queries: busy and
    /// queueing long, a device alone in asking still gets one in and is refused after. With
    /// another holding 600 idle connections it used to hold 600 in flight
    #[test]
    fn many_connections_do_not_raise_the_average_of_queries() {
        let manager = Arc::new(PermitManager::new());
        let flow = state(Duration::from_secs(60));
        let busy = Instant::now() - LONG_AGO;
        let proxy: Vec<_> = (0..600)
            .map(|_| {
                flow.connection_permit(&manager, OTHER)
                    .expect("plenty of memory")
            })
            .collect();
        flow.note_queue_delay(Duration::from_secs(3600));
        let mut flooder = Vec::new();
        while let Some(permit) = flow.permit(&manager, busy, ONE, FAST) {
            flooder.push(permit);
            assert!(flooder.len() <= 600, "unbounded");
        }
        assert_eq!(flooder.len(), 1, "a lone device asking gets one in");
        drop((proxy, flooder));
    }

    /// 连接和连接比：内存紧张时，开着的连接不比平均少的设备不接新连接，没开连接的照常接；它连接上的查询按查询比
    /// Connections are compared with connections: with memory tight a device holding no fewer
    /// connections than the average gets no new one, one holding none still connects, and the
    /// queries on its connections are compared with queries
    #[test]
    fn connections_are_compared_with_connections() {
        let manager = Arc::new(PermitManager::new());
        let flow = with_memory_left(100 << 20);
        let held: Vec<_> = (0..1000)
            .map(|_| manager.acquire_connection_for(ONE))
            .collect();
        assert!(
            flow.connection_permit(&manager, ONE).is_none(),
            "holding them all"
        );
        assert!(
            flow.connection_permit(&manager, OTHER).is_some(),
            "holding none"
        );
        assert!(
            flow.permit_by_memory(&manager, ONE).is_some(),
            "its queries hold no share"
        );
        assert_eq!(manager.dropped_requests(), 1);
        let full = with_memory_left(1 << 20);
        assert!(
            full.connection_permit(&manager, DeviceSlot(2)).is_none(),
            "with no memory left nobody connects"
        );
        drop(held);
    }

    /// 都一样多时都在平均上，都拒；内存没了谁都拒 / Holding as much as each other, all are at the
    /// average and all are refused; with no memory left everyone is
    #[test]
    fn devices_alike_and_no_memory_left_refuse_everyone() {
        let manager = Arc::new(PermitManager::new());
        let tight = with_memory_left(100 << 20);
        let alike: Vec<_> = (0..1000)
            .map(|n| manager.acquire_for(if n % 2 == 0 { ONE } else { OTHER }))
            .collect();
        assert!(tight.permit(&manager, Instant::now(), ONE, FAST).is_none());
        assert!(
            tight
                .permit(&manager, Instant::now(), OTHER, FAST)
                .is_none()
        );

        let full = with_memory_left(1 << 20);
        assert!(
            full.permit(&manager, Instant::now(), DeviceSlot(2), FAST)
                .is_none(),
            "nothing in flight, still refused"
        );
        drop(alike);
    }

    /// 记在设备上的数还回来以后都归零，有在途的设备数也归零 / What is counted per device returns to
    /// zero once given back, and so does the count of devices in flight
    #[test]
    fn device_counts_return_to_zero() {
        let manager = Arc::new(PermitManager::new());
        let first = manager.acquire_for(ONE);
        let second = manager.acquire_for(ONE);
        let other = manager.acquire_for(OTHER);
        let plain = manager.acquire();
        let connection = manager.acquire_connection_for(ONE);
        assert_eq!(manager.queries.slots_held.load(Ordering::Relaxed), 2);
        assert_eq!(manager.queries.per_slot[0].load(Ordering::Relaxed), 2);
        assert_eq!(manager.queries.total.load(Ordering::Relaxed), 3);
        assert_eq!(manager.connections.slots_held.load(Ordering::Relaxed), 1);
        drop(first);
        second.release();
        assert_eq!(manager.queries.slots_held.load(Ordering::Relaxed), 1);
        drop((other, plain, connection));
        for counts in [&manager.queries, &manager.connections] {
            assert_eq!(counts.slots_held.load(Ordering::Relaxed), 0);
            assert_eq!(counts.total.load(Ordering::Relaxed), 0);
            assert!(
                counts
                    .per_slot
                    .iter()
                    .all(|held| held.load(Ordering::Relaxed) == 0)
            );
        }
        assert_eq!(manager.inflight(), 0);
        assert_eq!(
            manager.done.last_second(Instant::now() + BUCKET),
            3,
            "only queries count as done"
        );
    }

    /// 两千台设备几乎都落在各自的份里：份数多到落在一起的很少（约 3%）。以前只有 1024 份，两千台里大半和别的设备落在一起
    /// Two thousand devices land almost all in slots of their own: there are slots enough that
    /// few land together (about 3%). There used to be only 1024, and most of two thousand landed
    /// with another
    #[test]
    fn devices_rarely_share_a_slot() {
        let manager = PermitManager::new();
        let slots: std::collections::HashSet<_> = (0..2000u32)
            .map(|n| manager.slot_of(std::net::Ipv4Addr::from(0x0a00_0000 + n).into()))
            .collect();
        assert!(slots.len() >= 1900, "{} distinct slots", slots.len());
    }

    /// 同一台设备落在同一份，IPv6 同一个 /64 也是 / The same device lands in the same slot, and so does
    /// the same IPv6 /64
    #[test]
    fn a_device_lands_in_one_slot() {
        let manager = PermitManager::new();
        let of = |text: &str| manager.slot_of(text.parse().unwrap());
        assert_eq!(of("192.0.2.1"), of("192.0.2.1"));
        assert_eq!(of("192.0.2.1"), of("::ffff:192.0.2.1"));
        assert_eq!(of("2001:db8:0:1::1"), of("2001:db8:0:1:ffff::2"));
        let slots: std::collections::HashSet<_> =
            (1..=100).map(|n| of(&format!("192.0.2.{n}"))).collect();
        assert!(slots.len() > 1, "devices spread over the slots");
    }
}
