use std::future::Future;
use std::hash::{BuildHasher, RandomState};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;

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

/// 内核跟不上时每台设备至少能排这么多个（见 `FairQueue::offer`），够 A、AAAA、HTTPS 一起问：来源多到平分下来每台不到一个时，
/// 发得少的设备一次问几个，只排得进一个。最多照顾 `fair_queue::MAX_QUEUED_DEVICES` 台
/// While the kernel cannot keep up each device may queue at least this many (see
/// `FairQueue::offer`), enough to ask A, AAAA and HTTPS together: with sources so many that the
/// room shared out gives each less than one, a device sending little asking a few at once would
/// queue only one. At most `fair_queue::MAX_QUEUED_DEVICES` devices are looked after this way
pub const SHARE_AT_LEAST: usize = 4;

/// 按设备轮流时，有活等着内核干的查询最多这么多个（两批），到了接收循环就先不从队列里取（见 [`WaitingToRun`]）。接收循环取一个
/// 查询、起一个任务只要一两微秒，内核把它处理完要十几微秒，转发的还要再处理一次回答：照自己的速度交，交出去的比处理完的多，
/// 调度器里排的任务越来越多，上游的回答到了也轮不到处理，在途只涨不降，最后所有设备一起超时。等着的少了才接着交，多出来的就
/// 不在内核里排队，留在各设备自己的队列里轮着取，排不下的在排进去时丢（见 `FairQueue::offer`）——谁发得多丢谁的，不用判断
/// 谁算「重」。两批够内核在接收循环下次回来之前一直有活干，又远小于调度器一个线程排得下的任务数（tokio 是 256 个，满了就
/// 把一半挪到另一个队列里，那里的任务隔几十个才取一个：回答到了的任务被挪过去，就是等不到处理的那些）
/// While devices take turns, at most this many queries (two batches) have work waiting for the
/// kernel; at that the receive loops take no more from the queues (see [`WaitingToRun`]).
/// Taking a query and starting its task costs a receive loop a microsecond or two, while the
/// kernel needs over ten to handle it and a forward's answer has to be handled as well:
/// handing over at its own speed, more go in than get done, ever more tasks queue in the
/// scheduler, the upstreams' answers arrive and are not got to, what is in flight only grows,
/// and in the end every device times out. Handing over more only once fewer are waiting, the
/// excess does not queue inside the kernel but stays in each device's own queue, taken in
/// turn, and what does not fit is dropped as it is offered (see `FairQueue::offer`): whoever
/// sends most loses most, with no judging who counts as heavy. Two batches keep the kernel in
/// work until a receive loop is back, and are far fewer than the tasks one thread of the
/// scheduler holds (256 in tokio, which at that moves half to another queue where a task is
/// taken only once in dozens: tasks whose answers have arrived, moved there, are the ones
/// that are not got to)
pub const WAITING_TO_RUN_AT_MOST: usize = 64;

/// 卡住的查询（见 [`PermitManager::stuck_after`]）留着等这么多个，各设备平分，再卡住的不等了。和内存水位开始看内存的在途数
/// 一样：这么少占不了多少内存。留着的是每台设备最早卡住的那些：它们等到底，回答真来了，就知道回答比原先以为的慢。每台设备
/// 至少留得下 [`SHARE_AT_LEAST`] 个，留着的设备到 `fair_queue::MAX_QUEUED_DEVICES` 台为止：来源多到平分下来每台不到一个时，
/// 发得少的设备问一个慢名字的 A、AAAA、HTTPS 也都等得到。先留下的不收回，所以设备一台接一台卡住时一共会多出一些：第 k 台
/// 来时留到这个数的 k 分之一和 `SHARE_AT_LEAST` 里大的那个，四千台加起来两万出头
/// How many stuck queries (see [`PermitManager::stuck_after`]) are kept waiting, shared out
/// among the devices, any stuck after that waiting no more. The same number of queries in
/// flight as the memory watermark starts looking at memory from: too few to hold much memory.
/// Those kept are the ones each device had stuck first: they wait to the end, and an answer
/// that does come tells that answers take longer than was thought. Each device keeps at least
/// [`SHARE_AT_LEAST`], up to `fair_queue::MAX_QUEUED_DEVICES` devices keeping any: with
/// sources so many that the share comes to less than one each, a device sending little still
/// gets the A, AAAA and HTTPS of one slow name. Those kept earlier stay, so with devices
/// getting stuck one after another there are some more in all: the k-th to come keeps up to a
/// k-th of this or `SHARE_AT_LEAST`, whichever is more, a little over twenty thousand for four
/// thousand devices together
pub const STUCK_KEPT: usize = 1000;

/// 回答一般要多久，看最近这么多个回答里最慢的 `1 / SLOWEST_ONE_IN`，等过它的 [`WAITS_TIMES_SLOWEST`] 倍还没回答的算卡住
/// How long answers usually take goes by the slowest `1 / SLOWEST_ONE_IN` of the latest
/// answers, and a query waiting [`WAITS_TIMES_SLOWEST`] times that with no answer counts as
/// stuck
const SLOWEST_ONE_IN: u32 = 100;
const WAITS_TIMES_SLOWEST: u32 = 2;

/// 记着的回答到这么多个就都减半：看的是最近四千到八千个回答。按个数不按时间：一阵没有查询，记着的不变——回答要多久是上游的
/// 性质，和有没有负载无关
/// With this many answers noted they are all halved: what is looked at is the latest four to
/// eight thousand answers. By count and not by time: a stretch with no queries leaves what is
/// noted as it was, since how long answers take is a property of the upstream and not of the
/// load
const ANSWERS_REMEMBERED: u32 = 8192;

/// 和上游的收发每这么多次量一次用了多久、一次记这么多个：量一次要读两次时钟，平常每个查询都量的话，光读时钟就比别的加起来
/// 还多。抽着量不偏：慢的回答同样每这么多个里量到一个
/// One exchange with an upstream in this many is timed, and noted as this many: timing one
/// reads the clock twice, and timing every query's would cost more in clock reads than
/// everything else put together. Sampling does not skew it: of slow answers too, one in this
/// many is timed
const ROUND_TRIPS_TIMED_ONE_IN: u32 = 8;

/// 各自记回答要多久的上游最多这么多个，配置里写不了这么多；再多的只记进所有上游合起来的那一份 / The most
/// upstreams whose answer times are kept each on its own, more than a configuration writes; any
/// further are noted only among all upstreams together
const UPSTREAMS_TIMED: usize = 4096;

thread_local! {
    /// 这个线程上还有几次收发没量 / How many exchanges on this thread have gone untimed
    static ROUND_TRIPS_NOT_TIMED: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// 回答的用时按毫秒分档：每翻一倍分 4 档，一共这么多档，最后一档往上都算在里面（一分多钟）
/// Answer times fall in steps by milliseconds: 4 steps to each doubling, this many in all, the
/// last holding everything above it (over a minute)
const TIME_STEPS: usize = 64;

/// `ms` 毫秒落在哪一档 / The step `ms` milliseconds fall in
fn step_of(ms: u64) -> usize {
    let value = ms.saturating_add(1);
    let doublings = 63 - value.leading_zeros() as usize;
    let quarter = if doublings >= 2 {
        (value >> (doublings - 2)) & 3
    } else {
        (value << (2 - doublings)) & 3
    } as usize;
    (doublings * 4 + quarter).min(TIME_STEPS - 1)
}

/// 第 `step` 档里最长的用时再往上一毫秒 / One millisecond past the longest time in step `step`
fn step_ends_ms(step: usize) -> u64 {
    let (doublings, quarter) = (step / 4, (step % 4) as u64);
    // 档里的值是毫秒数加一（见 `step_of`）/ The values in a step are milliseconds plus one (see
    // `step_of`)
    ((5 + quarter) << doublings).div_ceil(4) - 1
}

/// 最近的回答各用了多久，见 [`PermitManager::stuck_after`]：每个上游一份，所有上游合起来还有一份。几个核一起记；减半时只有
/// 一个核在做，别的核这一下记的可能被多减或少减一个，不要紧
/// How long each of the latest answers took, see [`PermitManager::stuck_after`]: one of these
/// for each upstream, and one more for all of them together. Several cores note at once;
/// halving is done by one core at a time, and what another notes meanwhile may be halved one
/// too many or too few, which does not matter
struct AnswerTime {
    steps: [AtomicU32; TIME_STEPS],
    noted: AtomicU32,
    halving: AtomicBool,
    /// 最慢的那些回答用了多少毫秒，`u32::MAX` 是还不知道 / The milliseconds the slowest answers
    /// took, `u32::MAX` while not known yet
    slowest_ms: AtomicU32,
}

impl AnswerTime {
    fn new() -> Self {
        Self {
            steps: std::array::from_fn(|_| AtomicU32::new(0)),
            noted: AtomicU32::new(0),
            halving: AtomicBool::new(false),
            slowest_ms: AtomicU32::new(u32::MAX),
        }
    }

    /// 记下一个用了 `ms` 毫秒的回答 / Notes one answer that took `ms` milliseconds
    #[cfg(test)]
    fn note(&self, ms: u64) {
        self.note_many(ms, 1);
    }

    /// 记下 `count` 个用了 `ms` 毫秒的回答。隔一些个重算一次最慢的那些用了多久；比现在记着的还慢的当场重算，回答变慢了马上
    /// 跟上
    /// Notes `count` answers that took `ms` milliseconds. How long the slowest took is worked out
    /// again every so many; one slower than what is kept has it worked out at once, so answers
    /// getting slower are followed straight away
    fn note_many(&self, ms: u64, count: u32) {
        self.steps[step_of(ms)].fetch_add(count, Ordering::Relaxed);
        let before = self.noted.fetch_add(count, Ordering::Relaxed);
        let noted = before + count;
        if noted >= ANSWERS_REMEMBERED {
            self.halve();
        }
        if before / 64 != noted / 64
            || before == 0
            || ms >= u64::from(self.slowest_ms.load(Ordering::Relaxed))
        {
            self.work_out();
        }
    }

    /// 每一档都减半 / Halves every step
    fn halve(&self) {
        if self
            .halving
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let mut left = 0u32;
        for step in &self.steps {
            let held = step.load(Ordering::Relaxed);
            step.fetch_sub(held - held / 2, Ordering::Relaxed);
            left = left.saturating_add(held / 2);
        }
        self.noted.store(left, Ordering::Relaxed);
        self.halving.store(false, Ordering::Release);
    }

    /// 重算最慢的 `1 / SLOWEST_ONE_IN` 是从哪一档起，记下那一档的上沿 / Works out again which step
    /// the slowest `1 / SLOWEST_ONE_IN` start in, and keeps where that step ends
    fn work_out(&self) {
        let held: [u32; TIME_STEPS] =
            std::array::from_fn(|step| self.steps[step].load(Ordering::Relaxed));
        let all: u64 = held.iter().map(|count| u64::from(*count)).sum();
        if all == 0 {
            return;
        }
        let mut slower = 0u64;
        for (step, count) in held.iter().enumerate().rev() {
            slower += u64::from(*count);
            if slower * u64::from(SLOWEST_ONE_IN) >= all {
                let ms = step_ends_ms(step).min(u64::from(u32::MAX - 1)) as u32;
                self.slowest_ms.store(ms, Ordering::Relaxed);
                return;
            }
        }
    }

    /// 最慢的那些回答用了多久，还不知道时是 None / How long the slowest answers took, None while
    /// not known yet
    fn slowest(&self) -> Option<Duration> {
        match self.slowest_ms.load(Ordering::Relaxed) {
            u32::MAX => None,
            ms => Some(Duration::from_millis(u64::from(ms))),
        }
    }
}

/// 等上游的一个查询卡住了，这台设备留着等的又已经够多：不等了（见 [`Asking::wait`]）/ A query waiting on an
/// upstream was stuck with enough of its device's kept waiting already, and waits no more (see
/// [`Asking::wait`])
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GaveUp;

/// 有活等着内核干的查询有多少：交给任务还没开始跑的，和被叫醒（上游的回答到了、定时器到点了）还没轮到跑的。正在等上游的不算——
/// 那不是内核在排队。几个接收循环、几个核共用这一个数：任务在哪个线程上排着、调度器怎么排，都不用管
/// How many queries have work waiting for the kernel: those handed to a task that has not
/// started running, and those woken (an upstream's answer arrived, a timer fired) whose turn to
/// run has not come. One waiting on an upstream does not count, that not being the kernel
/// queueing. Every receive loop and every core share this one count: on which thread a task
/// queues and how the scheduler orders them does not come into it
#[derive(Default)]
pub struct WaitingToRun(AtomicUsize);

impl WaitingToRun {
    pub fn count(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }

    /// 等着的已经够多，先不再交（见 [`WAITING_TO_RUN_AT_MOST`]）/ Enough are waiting, so no more are
    /// handed over for now (see [`WAITING_TO_RUN_AT_MOST`])
    pub fn is_enough(&self) -> bool {
        self.count() >= WAITING_TO_RUN_AT_MOST
    }

    /// 把 `work` 交给任务去跑，它有活等着内核干的时候都算在里面：从现在到它开始跑，之后每次被叫醒到轮到它跑。算的是交出去的
    /// 这一刻，不是它第一次跑的时候。`work` 没跑完（甚至没跑过）就被丢掉时不再算
    /// Hands `work` to a task, counted in for as long as it has work waiting for the kernel:
    /// from now until it starts running, and from each time it is woken until its turn to run
    /// comes. It counts from this moment of handing over, not from its first run. Dropped
    /// before it is done, or before it ever ran, it counts no more
    pub fn counting<F: Future>(waiting: Arc<Self>, work: F) -> impl Future<Output = F::Output> {
        let handed_over = HandedOver::new(waiting);
        async move {
            let waker = std::task::Waker::from(Arc::clone(&handed_over.0));
            let mut work = std::pin::pin!(work);
            std::future::poll_fn(|cx| {
                handed_over.0.runs(cx.waker());
                work.as_mut()
                    .poll(&mut std::task::Context::from_waker(&waker))
            })
            .await
        }
    }
}

/// 一个交出去的查询这会儿在等什么 / What a query handed over is waiting for right now
const RUNNING_OR_WAITING_ON_OTHERS: u8 = 0;
const WAITING_TO_RUN: u8 = 1;
const DONE: u8 = 2;

/// 一个交出去的查询的任务：记着它是不是有活等着内核干。任务拿到的是包了一层的 waker：谁叫醒它，先记下它在等着跑，再叫醒
/// 任务本身
/// The task of one query handed over, keeping whether it has work waiting for the kernel. What
/// the task is given is a waker wrapped once: whoever wakes it first notes that it waits to
/// run, then wakes the task itself
struct Woken {
    waiting: Arc<WaitingToRun>,
    state: std::sync::atomic::AtomicU8,
    /// 任务本身的 waker / The waker of the task itself
    task: parking_lot::Mutex<Option<std::task::Waker>>,
}

impl Woken {
    /// 轮到它跑了：不再算等着跑；记下任务本身的 waker / Its turn to run has come: it no longer
    /// counts as waiting to run, and the task's own waker is kept
    fn runs(&self, task: &std::task::Waker) {
        if self
            .state
            .compare_exchange(
                WAITING_TO_RUN,
                RUNNING_OR_WAITING_ON_OTHERS,
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_ok()
        {
            self.waiting.0.fetch_sub(1, Ordering::Relaxed);
        }
        let mut kept = self.task.lock();
        if !kept.as_ref().is_some_and(|kept| kept.will_wake(task)) {
            *kept = Some(task.clone());
        }
    }
}

impl std::task::Wake for Woken {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        // 已经在等着跑的不重复算；结束以后才到的叫醒（定时器、别处留着的 waker）不算，没有下一次跑来把它减掉
        // One already waiting to run is not counted again; a wake coming after the end (a timer,
        // a waker kept somewhere) does not count, there being no next run to take it off
        if self
            .state
            .compare_exchange(
                RUNNING_OR_WAITING_ON_OTHERS,
                WAITING_TO_RUN,
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_ok()
        {
            self.waiting.0.fetch_add(1, Ordering::Relaxed);
        }
        let task = self.task.lock().clone();
        if let Some(task) = task {
            task.wake();
        }
    }
}

/// 交出去的一个查询，到它结束或者被丢掉为止 / One query handed over, until it ends or is dropped
struct HandedOver(Arc<Woken>);

impl HandedOver {
    fn new(waiting: Arc<WaitingToRun>) -> Self {
        waiting.0.fetch_add(1, Ordering::Relaxed);
        Self(Arc::new(Woken {
            waiting,
            state: std::sync::atomic::AtomicU8::new(WAITING_TO_RUN),
            task: parking_lot::Mutex::new(None),
        }))
    }
}

impl Drop for HandedOver {
    fn drop(&mut self) {
        if self.0.state.swap(DONE, Ordering::AcqRel) == WAITING_TO_RUN {
            self.0.waiting.0.fetch_sub(1, Ordering::Relaxed);
        }
        *self.0.task.lock() = None;
    }
}

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
    /// 按设备轮流时有活等着内核干的查询（见 [`WaitingToRun`]）/ The queries with work waiting for the
    /// kernel while devices take turns (see [`WaitingToRun`])
    pub waiting_to_run: Arc<WaitingToRun>,
}

impl FlowControlState {
    pub fn new(memory: super::memory_watermark::MemoryWatermark) -> Self {
        Self {
            busy_after: BUSY_AFTER,
            memory,
            started: Instant::now(),
            behind_until_ns: AtomicU64::new(0),
            waiting_to_run: Arc::new(WaitingToRun::default()),
        }
    }

    /// `device` 的一个要等上游的查询能不能处理，`emptied_at` 是 socket 上次收空的时刻。内存不够时拒绝（见
    /// [`Self::memory_refuses`]）。内核忙而且查询在内核里排着长队时，拒在途不比各设备平均少的设备，发得少的照常——那时每个查询
    /// 都要先排同样长的队，在途多少就是发得多快，不分设备地拒，发得少的也跟着丢，直到开始按设备轮流。等上游不算排队：上游慢、
    /// 在途多，都不拒；卡住的查询另有处置（见 [`Asking::wait`]）
    /// Whether a query from `device` that waits on an upstream can go ahead, `emptied_at` being
    /// when the socket last ran empty. Too little memory refuses it (see
    /// [`Self::memory_refuses`]). Busy and queueing long inside the kernel, a device holding no
    /// less in flight than the average is refused while those sending little go on. Every query
    /// then waits in the same long line first, so what a device holds in flight is how fast it
    /// sends, and refusing whatever comes would lose the devices sending little too, until devices
    /// take turns. Waiting on an upstream is not queueing: a slow upstream or many in flight
    /// refuses nothing, and stuck queries are dealt with elsewhere (see [`Asking::wait`])
    #[inline]
    pub fn permit(
        &self,
        manager: &Arc<PermitManager>,
        emptied_at: Instant,
        device: DeviceSlot,
    ) -> Option<PermitGuard> {
        if self.memory_refuses(manager, device)
            || (self.busy(emptied_at) && self.behind() && manager.queries.holds_its_share(device))
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

    /// 按设备轮流时 `device` 的一个要等上游的查询能不能处理：只看内存。轮流挡住的是排队，谁排得多先丢谁的；在途的不在这里拒，
    /// 卡住的另有处置（见 [`Asking::wait`]）
    /// Whether a query from `device` that waits on an upstream can go ahead while devices take
    /// turns: by memory alone. Taking turns holds the queueing, dropping from whoever queues
    /// most; what is in flight is not refused here, and stuck queries are dealt with elsewhere
    /// (see [`Asking::wait`])
    #[inline]
    pub fn turn_permit(
        &self,
        manager: &Arc<PermitManager>,
        device: DeviceSlot,
    ) -> Option<PermitGuard> {
        self.permit_by_memory(manager, device)
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

/// 按设备记在途数的份数：设备按两个不同的哈希各落到一份，两份都记着它的在途，它在途多少看两份里少的那一份；哈希每次启动都
/// 不同。和别的设备落在同一份时，那一份记的是它们加起来的，另一份多半只有它自己的：份数多到两千台设备里一份落在一起的约 3%，
/// 两份都落在一起的不到千分之一。只有一份时，和一个洪泛来源落在一起的设备算成同一台，洪泛期间它问的全被拒，到重启为止。在途的
/// 计数是几个核一起改的原子数，按份的数组比按设备的表省得多：在途的查询、开着的连接、留着等的卡住的查询各两个 256 KiB，
/// 问上游的结果（见 `Asked`）两个 512 KiB，都是清零分配的，碰到的份才真正占内存
/// How many slots the in-flight counts per device are kept in: a device lands in one by each of
/// two different hashes, both count what it holds in flight, and what it holds is the smaller of
/// the two; the hashes differ at each start. Landing in a slot with another device, that slot
/// counts them together while the other most likely counts it alone: there are slots enough that
/// about 3% of two thousand devices share one, and under one in a thousand share both. With one
/// slot only, a device landing with a flooding source counted as the same device, and everything
/// it asked during the flood was refused, until a restart. The counts are atomics several cores
/// change at once, and arrays of slots cost far less than a table by device: two of 256 KiB
/// each for the queries in flight, the open connections and the stuck queries kept waiting, and
/// two of 512 KiB for the outcomes of asking upstreams (see `Asked`), all allocated zeroed, so
/// only the slots touched take memory
const DEVICE_SLOTS: usize = 65536;

/// 一台设备按两个哈希各落在的那一份 / The slot a device lands in by each of the two hashes
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DeviceSlot(u16, u16);

impl DeviceSlot {
    /// 数有在途的设备时它算在哪一份：按第一个哈希，落在同一份的算一台（见 `DeviceCounts`）/ The slot it
    /// counts in when devices holding any are counted: by the first hash, those landing together
    /// counting as one (see `DeviceCounts`)
    pub fn counted_in(self) -> u16 {
        self.0
    }
}

/// 一种东西按设备记的在途：每一份的个数（前 `DEVICE_SLOTS` 份按第一个哈希，后 `DEVICE_SLOTS` 份按第二个）、按第一个哈希有在途的
/// 份数（差不多就是有在途的设备数）、一共多少。份额按同一种东西比
/// What is in flight of one kind, per device: the count in each slot (the first `DEVICE_SLOTS`
/// by the first hash, the next `DEVICE_SLOTS` by the second), how many slots by the first hash
/// hold any (close to how many devices do), and how many in all. Shares are compared within one
/// kind
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
        let zeroed: Box<[u32]> = vec![0u32; 2 * DEVICE_SLOTS].into_boxed_slice();
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
        let [first, second] = Self::slots(device);
        if self.per_slot[first].fetch_add(1, Ordering::Relaxed) == 0 {
            self.slots_held.fetch_add(1, Ordering::Relaxed);
        }
        self.per_slot[second].fetch_add(1, Ordering::Relaxed);
    }

    /// `device` 在 `per_slot` 里的两份 / The two slots of `device` in `per_slot`
    fn slots(device: DeviceSlot) -> [usize; 2] {
        [usize::from(device.0), DEVICE_SLOTS + usize::from(device.1)]
    }

    /// `device` 在途多少：两份里少的那一份，别的设备都落在这两份时才会多算 / How many `device` holds
    /// in flight: the smaller of its two slots, more than its own only with other devices in both
    fn own(&self, device: DeviceSlot) -> usize {
        let [first, second] = Self::slots(device);
        let held = |slot: usize| self.per_slot[slot].load(Ordering::Relaxed) as usize;
        held(first).min(held(second))
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
        let [first, second] = Self::slots(device);
        #[allow(deprecated)]
        let take_one = |slot: usize| {
            self.per_slot[slot].fetch_update(Ordering::Relaxed, Ordering::Relaxed, |held| {
                held.checked_sub(1)
            })
        };
        if take_one(first) == Ok(1) {
            #[allow(deprecated)]
            let _ = self
                .slots_held
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |slots| {
                    slots.checked_sub(1)
                });
        }
        let _ = take_one(second);
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
        let own = self.own(device);
        let slots = self.slots_held.load(Ordering::Relaxed).max(1);
        own > 0 && self.total() >= budget && own.saturating_mul(slots) >= budget
    }

    /// 这一种一共到了 `kept`，`device` 再添一个就到了 `kept` 平分给各台有的设备的那一份：两样都是才算。它自己不到
    /// [`SHARE_AT_LEAST`] 个、有的设备又不到 `MAX_QUEUED_DEVICES` 台时不算——发得少的设备总留得下几个；来源多过这个数，
    /// 就照顾不过来了
    /// Whether `kept` are held in all and one more would bring `device` to its share of `kept`
    /// split among the devices holding any: both, or it does not count. Nor does it while the
    /// device holds under [`SHARE_AT_LEAST`] and fewer than `MAX_QUEUED_DEVICES` devices hold
    /// any, so one sending little always keeps a few; with more sources than that there is no
    /// looking after each
    fn full_for(&self, device: DeviceSlot, kept: usize) -> bool {
        let slots = self.slots_held.load(Ordering::Relaxed).max(1);
        let own = self.own(device);
        if own < SHARE_AT_LEAST && slots < MAX_QUEUED_DEVICES {
            return false;
        }
        self.total() >= kept && (own + 1).saturating_mul(slots) >= kept
    }
}

/// 一台设备问一个上游，最近没等到回答的到了这么多个、又比等到回答的多，就先不替它问这个上游（见 [`PermitManager::ask`]）
/// With this many of a device's latest queries to an upstream unanswered, and more of them
/// than answered, the upstream is not asked for it for now (see [`PermitManager::ask`])
const UNANSWERED_BEFORE_HELD_BACK: u64 = 64;

/// 不替它问的这段时间里，隔这么久放一个去试 / While not asking for it, one goes to try every this
/// long
const TRIES_APART: Duration = Duration::from_secs(1);

/// 回答了的、没回答的，哪一样记到这么多个就两样都减半：看的是最近一两千个。按个数不按时间，隔多久都一样
/// With either of those answered and those unanswered noted this many times both are halved:
/// what is looked at is the latest thousand or two. By count and not by time, however long it
/// takes
const ASKED_REMEMBERED: u64 = 1024;

/// 等到回答的每这么多个记一次、一次记这么多个：平常绝大多数查询都等到回答，逐个记的话每个都要算一次哈希、改两个原子数。没
/// 等到回答的逐个记，一个不漏
/// Answered ones are noted once in this many, as this many at once: nearly every query is
/// answered as a rule, and noting each would cost each a hash and two atomic updates. Those
/// unanswered are noted one by one, none left out
const ANSWERED_NOTED_ONE_IN: u64 = 16;

thread_local! {
    /// 这个线程上等到回答、还没记的有几个 / How many answered on this thread are not noted yet
    static ANSWERED_NOT_NOTED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// 一次转发记成什么 / What a forward is noted as
#[derive(Clone, Copy, PartialEq, Eq)]
enum Noted {
    /// 这么多个等到了回答 / This many were answered
    Answered(u64),
    /// 放去试的那一个等到了回答：从头记，上游又回答它了。拦住以前发出去的查询后来才等到的回答不算——它们是拦住之前那一阵的，
    /// 照常记成回答了的，不够把它放开
    /// The one that went to try got its answer: noted afresh, as the upstream answers it
    /// again. Answers arriving later to queries sent before it was held back do not count so:
    /// they belong to the stretch before, noted as answered like any other, which is not
    /// enough to let it through
    TryAnswered,
    /// 一个没等到回答 / One went unanswered
    Unanswered,
}

/// 按「设备、上游」记的：最近替它问这个上游的查询里回答了多少、没回答多少，以及上次放一个去试的时刻。和在途一样按两个哈希
/// 各记一份，两份都是「没回答的多」才算。每份一个原子数：低 16 位是回答了的，接着 16 位是没回答的，高 32 位是那个时刻
/// （从 `started` 起的毫秒）
/// Kept per device and upstream: how many of the latest queries asked of the upstream for the
/// device were answered and how many not, and when one last went to try. Kept in two slots by
/// two hashes as what is in flight is, and it takes both to read "mostly unanswered". Each
/// slot is one atomic: answered in the low 16 bits, unanswered in the next 16, and that moment
/// (milliseconds since `started`) in the high 32
struct Asked {
    per_slot: Box<[AtomicU64]>,
    started: Instant,
    /// 有几份现在是没回答的多。平常是 0：谁都没被拦，问之前不用算哈希去看。两个核前后脚改同一份时，减的可能比加的先到，
    /// 所以带符号、不在 0 处截住：截住的话那一次减就丢了，之后永远多着一个
    /// How many slots now read mostly unanswered. Zero as a rule: nobody is held back, and asking
    /// needs no hash to look. With two cores changing one slot right after each other the taking
    /// off may land before the adding, so it is signed and not stopped at zero: stopped there
    /// that taking off would be lost, and it would read one too many ever after
    mostly_unanswered: AtomicIsize,
}

impl Asked {
    fn new() -> Self {
        // 清零的分配，同 `DeviceCounts::new` / A zeroed allocation, as in `DeviceCounts::new`
        let zeroed: Box<[u64]> = vec![0u64; 2 * DEVICE_SLOTS].into_boxed_slice();
        // SAFETY: AtomicU64 和 u64 的大小、对齐、有效位都相同，这块内存按同样的布局分配，也按同样的布局释放
        // SAFETY: AtomicU64 has the same size, alignment and bit validity as u64, so this block is
        // allocated and freed with the same layout
        let per_slot = unsafe { Box::from_raw(Box::into_raw(zeroed) as *mut [AtomicU64]) };
        Self {
            per_slot,
            started: Instant::now(),
            mostly_unanswered: AtomicIsize::new(0),
        }
    }

    /// 一份里记的是不是没回答的多 / Whether a slot reads mostly unanswered
    fn is_mostly_unanswered(word: u64) -> bool {
        let (answered, unanswered) = (word & 0xffff, (word >> 16) & 0xffff);
        unanswered >= UNANSWERED_BEFORE_HELD_BACK && unanswered > answered
    }

    fn now_ms(&self) -> u32 {
        self.started.elapsed().as_millis() as u32
    }

    /// 两份都是没回答的多 / Both slots read mostly unanswered
    fn held_back(&self, slots: [usize; 2]) -> bool {
        slots
            .iter()
            .all(|slot| Self::is_mostly_unanswered(self.per_slot[*slot].load(Ordering::Relaxed)))
    }

    /// 两份里记着的回答了的都不是零：这台设备在这个上游上等到过回答（等到回答的每 [`ANSWERED_NOTED_ONE_IN`] 个才记一次，
    /// 头几个回答还没记时也当作没等到过）
    /// Both slots hold some answered: this device has had answers from this upstream (answered
    /// ones are noted once in [`ANSWERED_NOTED_ONE_IN`], so the first few answers, not yet
    /// noted, read as none)
    fn ever_answered(&self, slots: [usize; 2]) -> bool {
        slots
            .iter()
            .all(|slot| self.per_slot[*slot].load(Ordering::Relaxed) & 0xffff != 0)
    }

    /// 现在能不能放一个去试：离上次放（或者离变成「没回答的多」那一刻）到了 [`TRIES_APART`] 就能，并记下这一次
    /// Whether one may go to try now: it may once [`TRIES_APART`] has passed since the last (or
    /// since the slot came to read mostly unanswered), which notes this one
    fn tries_now(&self, slot: usize) -> bool {
        let now = self.now_ms();
        let seen = self.per_slot[slot].load(Ordering::Relaxed);
        if now.wrapping_sub((seen >> 32) as u32) < TRIES_APART.as_millis() as u32 {
            return false;
        }
        let next = (seen & 0xffff_ffff) | u64::from(now) << 32;
        self.per_slot[slot]
            .compare_exchange(seen, next, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    }

    /// 在两份里各记下 `noted` / Notes `noted` in both slots
    fn note(&self, slots: [usize; 2], noted: Noted) {
        for slot in slots {
            let slot = &self.per_slot[slot];
            let mut word = slot.load(Ordering::Relaxed);
            loop {
                let (mut yes, mut no, mut tried_at) =
                    (word & 0xffff, (word >> 16) & 0xffff, word >> 32);
                match noted {
                    Noted::Answered(count) => yes += count,
                    Noted::TryAnswered => (yes, no) = (1, 0),
                    Noted::Unanswered => no += 1,
                }
                if yes >= ASKED_REMEMBERED || no >= ASKED_REMEMBERED {
                    (yes, no) = (yes / 2, no / 2);
                }
                let counts = yes | no << 16;
                let (was, is) = (
                    Self::is_mostly_unanswered(word),
                    Self::is_mostly_unanswered(counts),
                );
                // 刚变成没回答的多：从这一刻起算，过了 `TRIES_APART` 才放第一个去试
                // Just come to read mostly unanswered: counted from now, the first goes to try
                // only after `TRIES_APART`
                if is && !was {
                    tried_at = u64::from(self.now_ms());
                }
                match slot.compare_exchange_weak(
                    word,
                    counts | tried_at << 32,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        if is && !was {
                            self.mostly_unanswered.fetch_add(1, Ordering::Relaxed);
                        } else if was && !is {
                            self.mostly_unanswered.fetch_sub(1, Ordering::Relaxed);
                        }
                        break;
                    }
                    Err(seen) => word = seen,
                }
            }
        }
    }
}

/// 替一台设备等一个上游的一次等待（见 [`PermitManager::ask`]）：自己转发给它（等别的请求正在做的同一个转发只管卡没卡住，
/// 不记，见 [`PermitManager::join`]）。等的时候用 [`Self::wait`]；上游回了应答调 [`Self::replied`]，别的结局——转发出错、上游超时、卡住不等了、请求到了时限、客户端
/// 走了——都是直接放下。记成什么，看的都是事实：
/// - 上游回了用得上的回答：回答了；
/// - 上游回了失败应答（SERVFAIL、REFUSED）：两样都不记。上游是回了的，只是这个名字解析不了；一个程序反复问一个坏掉的
///   名字，不该连累这台设备问别的名字，不管上游回得快还是慢；
/// - 上游什么都没回：等过了算卡住的时间（见 [`PermitManager::stuck_after`]），或者等满了上游的时限，记没回答；没等那么久就
///   结束的（上游一连就断）不记。
///
/// 对着上游要等很久才回失败的名字洪泛（随机子域名打到一个答不上的域），拦住它的是卡住的那一份：超出那一份的不等了，没等到
/// 上游回话，记的就是没回答。内核自己正跟不上时不记没回答，除非这台设备在这个上游上一个回答都没等到过：内核跟不上时回答
/// 读出来得晚，等得久可能只是内核自己慢，说明不了上游；从没等到过回答的，没有理由觉得这一个会不一样。
///
/// One wait on an upstream for a device (see [`PermitManager::ask`]): forwarding to it (a wait
/// on the same forward another request is making sees only to being stuck and notes nothing,
/// see [`PermitManager::join`]). [`Self::wait`] does the waiting; a
/// reply from the upstream calls [`Self::replied`], and every other end (the forward failing,
/// the upstream timing out, stuck and waiting no more, the request timing out, the client gone)
/// is simply dropping it. What is noted goes by facts alone:
/// - the upstream replied with an answer of use: answered;
/// - the upstream replied with a failure (SERVFAIL, REFUSED): noted as neither. The upstream
///   did reply, only this name does not resolve; a program asking one broken name over and over
///   should not drag down the other names its device asks, however quick or slow the upstream
///   is to say so;
/// - the upstream sent nothing: past the time a query counts as stuck after (see
///   [`PermitManager::stuck_after`]), or the whole of the upstream's timeout, it is noted as no
///   answer; one ending sooner than that (the upstream refusing the connection at once) is not
///   noted.
///
/// A flood of names the upstream takes long to fail (random subdomains of a zone that cannot be
/// answered) is held by the share of stuck queries: those past the share wait no more, with no
/// word from the upstream, and that is noted as no answer. While the kernel itself is falling
/// behind no answer is not noted, unless this device never got an answer from this upstream: a
/// kernel falling behind reads answers late, so a long wait may be only the kernel being slow
/// and says nothing of the upstream; with no answer ever, there is no reason to think this one
/// would differ.
pub struct Asking<'a> {
    manager: &'a PermitManager,
    flow: &'a FlowControlState,
    client: std::net::IpAddr,
    upstream: &'a str,
    /// 上游的时限 / The upstream's timeout
    limit: Duration,
    /// 这一次是什么时候开始等的 / When this wait began
    since: Instant,
    /// 上游回了应答：是不是用得上的回答；None 是什么都没回 / The upstream replied: whether with an
    /// answer of use; None when it sent nothing
    replied: Option<bool>,
    /// 等过了算卡住的时间 / It waited past the time a query counts as stuck after
    stuck: bool,
    /// 是拦着的时候放去试的那一个 / It is the one let through to try while held back
    tries: bool,
    /// 是自己问上游的等待，不是等别的请求正在做的转发（见 [`PermitManager::join`]）/ It is a wait that asks
    /// the upstream itself, not one on a forward another request is making (see
    /// [`PermitManager::join`])
    own: bool,
}

impl Asking<'_> {
    /// 上游回了应答，`of_use` 是它是不是用得上的回答（不是 SERVFAIL、REFUSED）/ The upstream replied,
    /// `of_use` being whether with an answer of use (no SERVFAIL or REFUSED)
    pub fn replied(mut self, of_use: bool) {
        self.replied = Some(of_use);
    }

    /// 等到了用得上的回答 / An answer of use came
    #[cfg(test)]
    fn answered(self) {
        self.replied(true);
    }

    /// 等 `work` 走完：`work` 是给这个上游的转发，或者别的请求正在做的同一个转发。等过了算卡住的时间（见
    /// [`PermitManager::stuck_after`]）还没走完：这台设备留着等的卡住的查询还没到它那一份（见 [`STUCK_KEPT`]），就留着等到
    /// `work` 自己结束（上游的时限、请求的时限都还管着它）；到了，这一个不等了，返回 [`GaveUp`]，调用方照上游失败处理。不等的是
    /// 后卡住的、留着的是先卡住的：先卡住的等到底，慢上游的回答总能到，下一批就不再算卡住。新来的查询不因为在途多被拒——放
    /// 进来时没法知道它等不等得到回答，等了很久的那些才看得出来。算卡住的时间一开始就算好，只设一个定时器：先设一个短的、
    /// 到点再算的话，回答比它慢的上游上每个查询都要被白叫醒一次。`work` 由调用方固定在原地再传进来：按值传要拷进这个 future，
    /// 每个等上游的查询就存了两份
    /// Waits for `work` to be done: `work` is the forward to this upstream, or the same forward
    /// another request is making. Past the time a query counts as stuck after (see
    /// [`PermitManager::stuck_after`]) and still not done: with the stuck queries this device
    /// keeps waiting under its share (see [`STUCK_KEPT`]) it stays until `work` ends by itself
    /// (the upstream's timeout and the request's still hold it); at its share, this one waits no
    /// more and returns [`GaveUp`], which the caller treats as the upstream failing. It is the
    /// later ones that wait no more and the earlier ones that are kept: those wait to the end,
    /// so a slow upstream's answers always arrive and the next ones no longer count as stuck. A
    /// new query is not refused over what is in flight: whether it will be answered cannot be
    /// known as it comes in, and shows only in those that have waited long. The time a query
    /// counts as stuck after is worked out as the wait begins and one timer set: with a short
    /// one first and the working out left until it fires, every query on an upstream slower
    /// than that would be woken once for nothing. `work` comes pinned where the caller keeps
    /// it: taken by value it would be copied into this future, and kept twice in every query
    /// waiting on an upstream
    pub async fn wait<F: Future>(
        &mut self,
        mut work: std::pin::Pin<&mut F>,
    ) -> Result<F::Output, GaveUp> {
        // 开始等的那一刻已经读过时钟 / The clock was read as the wait began
        let mut now = self.since;
        loop {
            let stuck_at = self.since + self.manager.stuck_after(self.upstream, self.limit);
            if now >= stuck_at {
                break;
            }
            // 等的这一阵里回答可能变慢了，到点再算一次 / Answers may get slower meanwhile: worked out
            // once more then
            let stuck_at = tokio::time::Instant::from_std(stuck_at);
            if let Ok(done) = tokio::time::timeout_at(stuck_at, &mut work).await {
                return Ok(done);
            }
            now = Instant::now();
        }
        self.stuck = true;
        let device = self.manager.slot_of(self.client);
        let Some(kept) = self.manager.keep_stuck(device) else {
            return Err(GaveUp);
        };
        let done = work.await;
        drop(kept);
        Ok(done)
    }
}

impl Drop for Asking<'_> {
    fn drop(&mut self) {
        if !self.own {
            return;
        }
        let noted = match self.replied {
            Some(false) => return,
            None => {
                if !self.stuck && self.since.elapsed() < self.limit {
                    return;
                }
                let slots = self.manager.asked_slots(self.client, self.upstream);
                if self.flow.behind() && self.manager.asked.ever_answered(slots) {
                    return;
                }
                self.manager.asked.note(slots, Noted::Unanswered);
                return;
            }
            Some(true) if self.tries => Noted::TryAnswered,
            Some(true) => {
                let waiting = ANSWERED_NOT_NOTED.get() + 1;
                if waiting < ANSWERED_NOTED_ONE_IN {
                    ANSWERED_NOT_NOTED.set(waiting);
                    return;
                }
                ANSWERED_NOT_NOTED.set(0);
                Noted::Answered(ANSWERED_NOTED_ONE_IN)
            }
        };
        let slots = self.manager.asked_slots(self.client, self.upstream);
        self.manager.asked.note(slots, noted);
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
    /// 开了流控时，所有上游最近的回答各用了多久，见 [`Self::stuck_after`] / With flow control on, how long
    /// each of the latest answers of all upstreams took, see [`Self::stuck_after`]
    answer_time: AnswerTime,
    /// 开了流控时，每个上游（一个地址）自己最近的回答各用了多久 / With flow control on, how long each of
    /// the latest answers of each upstream (one address) took
    answer_time_of: DashMap<Box<str>, AnswerTime, rustc_hash::FxBuildHasher>,
    /// 开了流控时，每一份设备留着等的卡住的查询，见 [`Asking::wait`] / With flow control on, the stuck
    /// queries kept waiting per slot of devices, see [`Asking::wait`]
    stuck: DeviceCounts,
    /// 开了流控时，替每台设备问每个上游的查询最近回答了多少、没回答多少，见 [`Self::ask`] / With flow control on,
    /// how many of the latest queries asked of each upstream for each device were answered and
    /// how many not, see [`Self::ask`]
    asked: Asked,
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
            answer_time: AnswerTime::new(),
            answer_time_of: DashMap::default(),
            stuck: DeviceCounts::new(),
            asked: Asked::new(),
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

    /// 客户端地址所属的设备按两个哈希各落在哪一份：算一次 64 位的哈希，低 16 位是一个，从第 32 位起的 16 位是另一个
    /// The slots the device of a client address lands in by each of the two hashes: one 64-bit
    /// hash is worked out, its low 16 bits being one and the 16 from bit 32 the other
    #[inline]
    pub fn slot_of(&self, client: std::net::IpAddr) -> DeviceSlot {
        let hash = self.hasher.hash_one(Device::of(client));
        let slot = |bits: u64| (bits % DEVICE_SLOTS as u64) as u16;
        DeviceSlot(slot(hash), slot(hash >> 32))
    }

    /// 记下一个被拒绝的查询或连接，隔一阵记一条日志 / Counts a refused query or connection, with a log line now and then
    pub fn count_refused(&self) {
        let dropped = self.dropped_requests.fetch_add(1, Ordering::Relaxed);
        if dropped.is_multiple_of(100_000) {
            tracing::warn!(
                inflight = self.inflight(),
                stuck = self.stuck(),
                held_back = self.asked.mostly_unanswered.load(Ordering::Relaxed),
                slowest_ms = self.answer_time.slowest_ms.load(Ordering::Relaxed),
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
    fn release_one(&self, device: Option<(DeviceSlot, Held)>) {
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
            Some((device, Held::Query)) => self.queries.remove(device),
            Some((device, Held::Connection)) => self.connections.remove(device),
            None => {}
        }
    }

    /// 这一次和上游的收发要不要量用了多久：每 [`ROUND_TRIPS_TIMED_ONE_IN`] 次量一次，量到的交给 [`Self::note_answer_took`]
    /// Whether this exchange with an upstream is to be timed: one in
    /// [`ROUND_TRIPS_TIMED_ONE_IN`] is, what it took going to [`Self::note_answer_took`]
    #[inline]
    pub fn times_this_round_trip() -> bool {
        let waiting = ROUND_TRIPS_NOT_TIMED.get() + 1;
        if waiting < ROUND_TRIPS_TIMED_ONE_IN {
            ROUND_TRIPS_NOT_TIMED.set(waiting);
            return false;
        }
        ROUND_TRIPS_NOT_TIMED.set(0);
        true
    }

    /// 量到的一次和 `upstream`（一个地址）的收发（见 [`Self::times_this_round_trip`]）等到了用得上的回答，用了 `took`：
    /// 记进这个上游的、也记进所有上游合起来的回答要多久，见 [`Self::stuck_after`]
    /// An exchange with `upstream` (one address) that was timed (see
    /// [`Self::times_this_round_trip`]) got an answer of use and took `took`: noted in how long
    /// this upstream's answers take and in how long those of all upstreams together take, see
    /// [`Self::stuck_after`]
    pub fn note_answer_took(&self, upstream: &str, took: Duration) {
        let ms = took.as_millis() as u64;
        self.answer_time.note_many(ms, ROUND_TRIPS_TIMED_ONE_IN);
        if let Some(own) = self.answer_time_of.get(upstream) {
            own.note_many(ms, ROUND_TRIPS_TIMED_ONE_IN);
        } else if self.answer_time_of.len() < UPSTREAMS_TIMED {
            self.answer_time_of
                .entry(upstream.into())
                .or_insert_with(AnswerTime::new)
                .note_many(ms, ROUND_TRIPS_TIMED_ONE_IN);
        }
    }

    /// 启动以后等到过上游的回答没有（见 [`Self::note_answer_took`]）/ Whether an answer from an upstream
    /// has been seen since the start (see [`Self::note_answer_took`])
    #[inline]
    pub fn has_seen_an_answer(&self) -> bool {
        self.answer_time.slowest().is_some()
    }

    /// Get current inflight permits count / 获取当前进行中的 permits 数
    #[inline]
    pub fn inflight(&self) -> usize {
        self.active_permits.load(Ordering::Acquire)
    }

    /// 等 `upstream`（规则里写的那一串上游）的一个查询等多久算卡住，`limit` 是上游的时限。这个上游最近的回答里最慢的
    /// `1 / SLOWEST_ONE_IN` 用时的 [`WAITS_TIMES_SLOWEST`] 倍，至少 `BUSY_AFTER`。回答要多久是每个上游自己的：国内的上游十毫秒、国外的两百多毫秒，合在一起看的话，
    /// 查询少的那个慢上游永远排不进最慢的那一小部分，它每个回答都算卡住。一串里有几个上游时取最慢的那个；哪个上游还没等到过
    /// 回答，先按所有上游合起来的算——它不通还是慢，等它自己的回答来了才知道；哪个上游都还没等到过回答时（刚启动），按上游
    /// 应当已经回答的时间点（`hedge_timeout`）算，那是配置自己给的、转发该重发的时刻；这之前开始等的查询等到那个点才重算，
    /// 不在第一个回答来的那一下一起叫醒——洪泛时那是几万个查询同时醒来，内核跟着落后一大截。回答用了多久，记的是和上游的一次收发
    /// 从发出到收到用得上的回答（见 [`Self::note_answer_took`]），不是查询一共等了多久：第一次没发到、重发才等到回答的，等的
    /// 那一段不是上游回答要多久；上游回的 SERVFAIL、REFUSED 也不记，上游自己等不到才放弃的那几秒同样不是。看的是回答用了
    /// 多久、不是走完了多少：回答要多久是上游的性质，和有没有负载无关，空了一阵、一阵一阵地来，都不会让它变短；走完了多少跟着
    /// 负载走，拿它定在途的上限，没有负载就成了没有能力。回答比记着的慢了，留着等的那些等到回答（见 [`Asking::wait`]），这个
    /// 时间马上跟着变长；回答变快了，新的回答慢慢把旧的冲掉。内核自己排队的时间不往上加：等待是从转发开始那一刻算的，
    /// 之前在内核里排的队不在里面；内核忙时上游的回答晚读出来，量到的用时里已经带着这一段。加上的话，在途越多排得越久、
    /// 排得越久越没有谁算卡住，在途就一直涨下去。按这个时间看错了的后果：太短，一台设备超出它那一份的慢查询不等了，留着的等到回答以后就改过来；
    /// 太长，不回答的查询多占一阵内存。两样都不会拒掉新来的查询
    /// How long a query waiting on `upstream` (the upstreams as the rule writes them) counts as
    /// stuck after, `limit` being the upstream's timeout. It is [`WAITS_TIMES_SLOWEST`] times
    /// what the slowest `1 / SLOWEST_ONE_IN` of this upstream's latest answers took, at least
    /// `BUSY_AFTER`. How long answers take is each upstream's own: with a
    /// domestic upstream at ten milliseconds and one abroad at over two hundred looked at
    /// together, the slow one with few queries never makes it into the slowest few, and every
    /// answer of its would count as stuck. With several upstreams written, the slowest of them
    /// counts; one with no answer yet goes by all upstreams together for now, as whether it is
    /// down or slow shows only once its own answers come; with no answer from any (a fresh
    /// start) it goes by the point an upstream should have answered by (`hedge_timeout`), which
    /// the configuration itself gives as when a forward sends again; a query that began waiting
    /// before then works it out again at that point, and they are not all woken the moment the
    /// first answer comes, which in a flood is tens of thousands of queries waking at once and
    /// the kernel falling far behind for it. How long an answer took is
    /// one exchange with an upstream, from sending to an answer of use coming back (see
    /// [`Self::note_answer_took`]), not how long the query waited in all: with a first try lost
    /// and the answer won by sending again, the wait in between is not how long the upstream
    /// takes; nor is a SERVFAIL or REFUSED noted, the seconds an upstream took to give up being
    /// no such time either. It goes by how long answers took and not by how many were done: how
    /// long an answer takes is a property of the upstream and not of the load, so a lull or load
    /// in waves cannot shorten it; how many were done follows the load, and a limit on what is
    /// in flight taken from that reads no load as no capacity. With answers slower than noted,
    /// those kept waiting get theirs (see [`Asking::wait`]) and this grows at once; with answers
    /// faster, new ones wash the old out slowly. The kernel's own queueing is not added on top:
    /// a wait counts from when its forward began, the queueing inside the kernel before that
    /// not being in it; and a busy kernel reading an upstream's answers late is already in the
    /// times measured. Added, the more in flight the longer the queueing and the longer the
    /// queueing the less would count as stuck, with what is in flight growing without end. What
    /// a wrong time costs: too short, a device's slow
    /// queries past its share wait no more, put right once those kept get their answers; too
    /// long, queries with no answer hold memory a while longer. Neither refuses a new query
    pub fn stuck_after(&self, upstream: &str, limit: Duration) -> Duration {
        let slowest = self.answer_time.slowest().map(|all| {
            super::upstream::addresses(upstream)
                .map(|address| {
                    self.answer_time_of
                        .get(address)
                        .and_then(|own| own.slowest())
                        .unwrap_or(all)
                })
                .max()
                .unwrap_or(all)
        });
        let after = match slowest {
            Some(slowest) => slowest * WAITS_TIMES_SLOWEST,
            None => super::upstream::hedge_timeout(limit),
        };
        after.max(BUSY_AFTER)
    }

    /// `device` 的一个卡住的查询留不留着等：它留着的没到它那一份就留，返回的守卫放下时不再算；到了就不留，记一次拒绝
    /// Whether a stuck query of `device` is kept waiting: under its share it is, no longer
    /// counted once the guard returned is dropped; at its share it is not, counted as refused
    fn keep_stuck(&self, device: DeviceSlot) -> Option<Stuck<'_>> {
        if self.stuck.full_for(device, STUCK_KEPT) {
            self.count_refused();
            return None;
        }
        self.stuck.add(device);
        Some(Stuck {
            manager: self,
            device,
        })
    }

    /// 替 `client` 等 `upstream`（规则里写的那一串上游）之前调，`limit` 是上游的时限：返回的 [`Asking`] 跟着这一次等待。这台
    /// 设备最近在这个上游上的等待多半没等到回答时返回 None，这一个不等，记一次拒绝，调用方照上游失败处理（规则写了失败时的
    /// 动作就照做，比如改问备用的上游）；每隔 [`TRIES_APART`] 放一个去试，试的那个等到了回答就都放开。新来的查询等不等得到
    /// 回答，放进来时没法知道；这里看的是这台设备在这个上游上已经有的结果，是整个流控里唯一一处按过去的结果拦新查询的地方，
    /// 所以拦得窄：只拦这台设备、只拦这个上游——别的设备、这台设备走别的上游的查询都不受影响；一个上游不通，或者一台设备冲得
    /// 上游不再回答它时，是这里把它拦住，不让它一直往一个不回答的上游发；没回答的要多过回答了的才拦，一成两成名字不回答的
    /// 设备不会被拦。代价：一台设备问同一个上游的名字多半都不回答时，它在这个上游上答得上的那小半也被拦住
    /// Called before waiting on `upstream` (the upstreams as the rule writes them) for `client`,
    /// `limit` being the upstream's timeout: the [`Asking`] returned goes with this wait. With
    /// most of this device's latest waits on this upstream unanswered it returns None, this one
    /// does not wait and counts as refused, and the caller treats it as the upstream failing
    /// (what the rule says to do on a failure is done, asking a fallback upstream say); one goes
    /// to try every [`TRIES_APART`], and an answer to it lets them all through again. Whether a
    /// new query will be answered cannot be known as it comes in; this goes by the outcomes this
    /// device already has on this upstream, the one place in flow control that holds new queries
    /// back on past outcomes, so it holds back narrowly: this device only and this upstream
    /// only, leaving other devices and this device's queries to other upstreams alone. With an
    /// upstream down, or a device pushing an upstream into no longer answering it, this is what
    /// stops it sending on and on to an upstream that does not answer; it takes more unanswered
    /// than answered, so a device with a tenth or a fifth of its names unanswered is not held
    /// back. The price: a device most of whose names on one upstream get no answer has the
    /// answerable rest on that upstream held back too
    pub fn ask<'a>(
        &'a self,
        flow: &'a FlowControlState,
        client: std::net::IpAddr,
        upstream: &'a str,
        limit: Duration,
    ) -> Option<Asking<'a>> {
        // 平常谁都没被拦：不用算哈希 / As a rule nobody is held back: no hash to work out
        let tries = self.asked.mostly_unanswered.load(Ordering::Relaxed) > 0 && {
            let slots = self.asked_slots(client, upstream);
            let held_back = self.asked.held_back(slots);
            if held_back && !self.asked.tries_now(slots[0]) {
                self.count_refused();
                return None;
            }
            held_back
        };
        Some(Asking {
            manager: self,
            flow,
            client,
            upstream,
            limit,
            since: Instant::now(),
            replied: None,
            stuck: false,
            tries,
            own: true,
        })
    }

    /// 替 `client` 等别的请求正在做的、给 `upstream` 的同一个转发之前调：返回的 [`Asking`] 只管这次等待卡没卡住——等过了
    /// 算卡住的时间，这台设备留着等的没到它那一份就留着，到了就不等了（见 [`Asking::wait`]）；不然对着同一个不回答的名字
    /// 洪泛的设备，在途的全都陪着领头的等到上游超时。它不记进「设备、上游」的结果，被拦着的设备也照样等：这个查询自己
    /// 没有问上游，领头的交回来的可能是过期缓存、规则给的应答、备用上游的回答，说明不了这个上游回不回答；领头的那次等待
    /// 已经记在它自己头上。算卡住的时间按这个查询自己这条规则的上游算，领头的那时等的是不是它，这里看不到
    /// Called before waiting for `client` on the same forward to `upstream` that another request
    /// is making: the [`Asking`] returned sees only to whether this wait is stuck. Past the time
    /// a query counts as stuck after, it is kept while what this device keeps waiting is under
    /// its share and waits no more at its share (see [`Asking::wait`]); otherwise a device
    /// flooding one name with no answer would have everything in flight wait out the upstream
    /// timeout with the leader. Nothing of it is noted for the device and upstream, and a device
    /// held back waits like any other: this query asked no upstream itself, and what the leader
    /// hands over may be a stale answer, an answer the rules gave or a fallback upstream's,
    /// which says nothing of whether this upstream answers; the leader's own wait is noted
    /// against the leader. The time it counts as stuck after goes by the upstream of this
    /// query's own rule, whether or not that is what the leader is waiting on then, which
    /// cannot be seen from here
    pub fn join<'a>(
        &'a self,
        flow: &'a FlowControlState,
        client: std::net::IpAddr,
        upstream: &'a str,
        limit: Duration,
    ) -> Asking<'a> {
        Asking {
            manager: self,
            flow,
            client,
            upstream,
            limit,
            since: Instant::now(),
            replied: None,
            stuck: false,
            tries: false,
            own: false,
        }
    }

    /// 「`client` 所属的设备、`upstream`」按两个哈希各落在 `asked` 的哪一份 / The slots of `asked` the device
    /// of `client` and `upstream` land in by each of the two hashes
    fn asked_slots(&self, client: std::net::IpAddr, upstream: &str) -> [usize; 2] {
        let hash = self.hasher.hash_one((Device::of(client), upstream));
        let slot = |bits: u64| (bits % DEVICE_SLOTS as u64) as usize;
        [slot(hash), DEVICE_SLOTS + slot(hash >> 32)]
    }

    /// 测试用：让 `device` 留着等的卡住的查询满到它那一份，返回的放下时都不再算 / For tests: fills what `device`
    /// keeps waiting of stuck queries to its share, none counted any more once what is returned
    /// is dropped
    #[cfg(test)]
    pub(crate) fn keep_all_stuck_for_tests(&self, device: DeviceSlot) -> impl Sized + '_ {
        let mut kept = Vec::new();
        while let Some(one) = self.keep_stuck(device) {
            kept.push(one);
            assert!(kept.len() <= 10 * STUCK_KEPT, "unbounded");
        }
        kept
    }

    /// 留着等的卡住的查询一共多少 / How many stuck queries are kept waiting in all
    pub fn stuck(&self) -> usize {
        self.stuck.total()
    }

    /// Get total dropped requests count / 获取总丢弃请求数
    #[inline]
    pub fn dropped_requests(&self) -> u64 {
        self.dropped_requests.load(Ordering::Relaxed)
    }
}

/// 一个留着等的卡住的查询，放下时不再算 / A stuck query kept waiting, no longer counted once dropped
struct Stuck<'a> {
    manager: &'a PermitManager,
    device: DeviceSlot,
}

impl Drop for Stuck<'_> {
    fn drop(&mut self) {
        self.manager.stuck.remove(self.device);
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
            self.manager.release_one(self.device);
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
            self.manager.release_one(self.device);
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
    /// 两台设备，固定落在不同的两份 / Two devices, fixed in two different slots
    const ONE: DeviceSlot = DeviceSlot(0, 0);
    const OTHER: DeviceSlot = DeviceSlot(1, 1);

    /// 忙而且排长队才拒绝：只忙（上游慢、socket 收不空）或只排队（短暂卡顿）都不拒绝
    /// Refused only when busy and queueing long: busy alone (a slow upstream, a socket not
    /// running empty) or queueing alone (a brief stall) refuses nothing
    #[test]
    fn a_query_is_refused_only_when_busy_and_behind() {
        let manager = Arc::new(PermitManager::new());
        let flow = state(Duration::from_secs(60));
        let busy = Instant::now() - LONG_AGO;

        let busy_alone = flow.permit(&manager, busy, ONE);
        assert!(busy_alone.is_some(), "busy alone");

        flow.note_queue_delay(Duration::from_secs(3600));
        let behind_alone = flow.permit(&manager, Instant::now(), ONE);
        assert!(behind_alone.is_some(), "behind alone");
        assert_eq!(manager.dropped_requests(), 0);

        assert!(flow.permit(&manager, busy, ONE).is_none(), "both");
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
            flow.permit(&manager, busy, ONE).is_none(),
            "the device sending most"
        );
        let light = flow
            .permit(&manager, busy, OTHER)
            .expect("one sending little goes on");
        assert!(
            flow.permit(&manager, busy, OTHER).is_some(),
            "still far below the average"
        );
        assert_eq!(manager.dropped_requests(), 1);
        drop((heavy, light));
        let first = flow
            .permit(&manager, busy, OTHER)
            .expect("nothing in flight anywhere");
        assert!(flow.permit(&manager, busy, OTHER).is_none(), "alone now");
        drop(first);
    }

    /// 轮流时只看内存：在途再多、一台设备占着多少都不拒；内存没了才拒
    /// Taking turns goes by memory alone: however many are in flight and whatever one device
    /// holds, nothing is refused; none left refuses
    #[test]
    fn taking_turns_goes_by_memory_alone() {
        let manager = Arc::new(PermitManager::new());
        let mut flow = state(Duration::ZERO);
        flow.note_queue_delay(Duration::from_secs(3600));
        let held: Vec<_> = (0..5000)
            .map(|_| flow.turn_permit(&manager, ONE).expect("plenty of memory"))
            .collect();
        assert_eq!(manager.dropped_requests(), 0);
        flow.memory = MemoryWatermark::reading(|| MemoryReading {
            own: 0,
            limits: vec![MemoryLeft {
                total: 1 << 30,
                available: 0,
            }],
        });
        assert!(flow.turn_permit(&manager, ONE).is_none(), "none left");
        drop(held);
    }

    /// 用时分的档：越久档越靠后，一档的上沿不比档里的用时短，也长不过五分之一多一点
    /// The steps times fall in: the longer the later, a step ending no sooner than a time in it
    /// and little over a fifth later
    #[test]
    fn a_step_ends_little_after_the_times_in_it() {
        let mut last = 0;
        for ms in (0..2000u64).chain((2000..70_000).step_by(37)) {
            let step = step_of(ms);
            assert!(step >= last, "{ms} ms");
            last = step;
            if step < TIME_STEPS - 1 {
                let ends = step_ends_ms(step);
                assert!(ends > ms, "{ms} ms ends {ends}");
                assert!(ends <= ms + ms / 4 + 2, "{ms} ms ends {ends}");
            }
        }
        assert_eq!(step_of(u64::MAX), TIME_STEPS - 1);
    }

    /// 测试里的上游、它的地址和时限 / The upstream of the tests, its address and its timeout
    const UP: &str = "udp://198.51.100.1:53";
    const UP_ADDRESS: &str = "198.51.100.1:53";
    const LIMIT: Duration = Duration::from_secs(3);

    /// 没在跟不上的流控状态 / A flow-control state not falling behind
    static FLOW: std::sync::LazyLock<FlowControlState> =
        std::sync::LazyLock::new(|| state(Duration::ZERO));

    /// 哪个上游都还没等到过回答时，按上游应当已经回答的时间点算卡住（时限的三分之一），至少 `BUSY_AFTER`；有了第一个回答就
    /// 按回答算，再来更慢的马上跟上
    /// With no answer from any upstream yet, a wait counts as stuck after the point an upstream
    /// should have answered by (a third of its timeout), at least `BUSY_AFTER`; the first answer
    /// is gone by at once, a slower one after it followed straight away
    #[test]
    fn before_any_answer_a_wait_is_stuck_after_the_hedge_point() {
        let manager = PermitManager::new();
        assert_eq!(manager.stuck_after(UP, LIMIT), Duration::from_secs(1));
        assert_eq!(
            manager.stuck_after(UP, Duration::from_millis(150)),
            BUSY_AFTER,
            "never under the floor"
        );
        manager.answer_time.note(20);
        assert_eq!(manager.stuck_after(UP, LIMIT), BUSY_AFTER);
        manager.answer_time.note(300);
        let after = manager.stuck_after(UP, LIMIT);
        assert!(
            after >= Duration::from_millis(600) && after <= Duration::from_millis(760),
            "{after:?}"
        );
    }

    /// 算卡住的时间是最慢的百分之一用时的两倍：一千个 20 毫秒的回答里有 20 个 300 毫秒的，按 300 毫秒算；只有 5 个时按
    /// 20 毫秒算，不到 100 毫秒的按 100 毫秒
    /// The time a query counts as stuck after is twice what the slowest hundredth took: with 20
    /// answers of 300 ms among a thousand of 20 ms it goes by 300 ms; with only 5, by 20 ms,
    /// and under 100 ms it is 100 ms
    #[test]
    fn stuck_is_twice_the_slowest_hundredth_at_least_busy_after() {
        let manager = PermitManager::new();
        for _ in 0..1000 {
            manager.answer_time.note(20);
        }
        for _ in 0..5 {
            manager.answer_time.note(300);
        }
        manager.answer_time.work_out();
        assert_eq!(manager.stuck_after(UP, LIMIT), BUSY_AFTER);
        for _ in 0..15 {
            manager.answer_time.note(300);
        }
        let after = manager.stuck_after(UP, LIMIT);
        assert!(
            after >= Duration::from_millis(600) && after <= Duration::from_millis(760),
            "{after:?}"
        );
    }

    /// 回答变慢了当场跟上，不等隔一些个才重算的那一次：一千个 10 毫秒之后来了 11 个 500 毫秒的，马上按 500 毫秒算
    /// Answers getting slower are followed at once, not at the next working out every so many:
    /// after a thousand of 10 ms come 11 of 500 ms, and it goes by 500 ms straight away
    #[test]
    fn slower_answers_are_followed_at_once() {
        let manager = PermitManager::new();
        for _ in 0..1024 {
            manager.answer_time.note(10);
        }
        assert_eq!(manager.stuck_after(UP, LIMIT), BUSY_AFTER);
        for _ in 0..11 {
            manager.answer_time.note(500);
        }
        let after = manager.stuck_after(UP, LIMIT);
        assert!(after >= Duration::from_secs(1), "{after:?}");
    }

    /// 回答变快了，新的把旧的慢慢冲掉：八千个 500 毫秒之后来两万个 5 毫秒，慢的还占百分之一以上，仍按 500 毫秒算；来到四万个，
    /// 又按 100 毫秒算。只按个数冲，隔多久都一样
    /// Answers getting faster wash the old ones out: after eight thousand of 500 ms come twenty
    /// thousand of 5 ms, the slow ones are still over a hundredth and it goes by 500 ms; with
    /// forty thousand it is 100 ms again. Washed out by count alone, however long it takes
    #[test]
    fn old_answers_are_washed_out_by_new_ones() {
        let manager = PermitManager::new();
        for _ in 0..8000 {
            manager.answer_time.note(500);
        }
        assert!(manager.stuck_after(UP, LIMIT) >= Duration::from_secs(1));
        for _ in 0..20_000 {
            manager.answer_time.note(5);
        }
        assert!(manager.stuck_after(UP, LIMIT) >= Duration::from_secs(1));
        for _ in 0..20_000 {
            manager.answer_time.note(5);
        }
        assert_eq!(manager.stuck_after(UP, LIMIT), BUSY_AFTER);
        assert!(
            manager.answer_time.noted.load(Ordering::Relaxed) < ANSWERS_REMEMBERED,
            "halved along the way"
        );
    }

    /// 回答要多久是每个上游自己的：国内的上游十毫秒、回答占了 99.5%，国外的两百五十毫秒、只占 0.5%，合在一起看，慢的那些
    /// 排不进最慢的百分之一。各看各的：国内的 100 毫秒算卡住，国外的五百毫秒以上才算；一串里两个都写了，按慢的那个；还没
    /// 等到过回答的上游按所有上游合起来的算
    /// How long answers take is each upstream's own: with a domestic upstream at ten
    /// milliseconds giving 99.5% of the answers and one abroad at two hundred and fifty giving
    /// 0.5%, looked at together the slow ones never make the slowest hundredth. Each by its
    /// own: the domestic one counts as stuck after 100 ms, the one abroad only after five
    /// hundred or more; a rule writing both goes by the slower; an upstream with no answer yet
    /// goes by all of them together
    #[test]
    fn each_upstream_goes_by_its_own_answers() {
        let manager = PermitManager::new();
        let (near, far) = ("198.51.100.1:53", "dns.example/dns-query");
        for round in 0..2000 {
            manager.note_answer_took(near, Duration::from_millis(10));
            if round % 200 == 0 {
                manager.note_answer_took(far, Duration::from_millis(250));
            }
        }
        let after = |upstream| manager.stuck_after(upstream, LIMIT);
        assert_eq!(after("udp://198.51.100.1:53"), BUSY_AFTER);
        assert_eq!(after("198.51.100.1:53"), BUSY_AFTER, "with no prefix");
        assert!(
            after("https://dns.example/dns-query") >= Duration::from_millis(500),
            "by its own answers, few as they are"
        );
        assert!(
            after("udp://198.51.100.1:53, https://dns.example/dns-query")
                >= Duration::from_millis(500),
            "the slower of the two"
        );
        assert_eq!(
            after("udp://203.0.113.9:53"),
            BUSY_AFTER,
            "no answer of its own yet: by all together"
        );

        // 上游自己的记录跟着它后来的回答走，不是只记头一个：国内的上游变慢了，它自己的算卡住的时间跟着变长
        // An upstream's own record follows its later answers, not its first alone: the
        // domestic one getting slower, its own time a query counts as stuck after grows
        for _ in 0..100 {
            manager.note_answer_took(near, Duration::from_millis(300));
        }
        assert!(
            after("udp://198.51.100.1:53") >= Duration::from_millis(600),
            "following its own later answers"
        );
    }

    /// 各自记回答要多久的上游有上限，再多的只记进合起来的那一份，表不会一直长
    /// The upstreams whose answer times are kept each on its own are bounded: any further are
    /// noted only among all together, so the table cannot grow for ever
    #[test]
    fn upstreams_past_the_bound_are_noted_only_among_all_together() {
        let manager = PermitManager::new();
        for n in 0..UPSTREAMS_TIMED + 50 {
            manager.note_answer_took(&format!("upstream-{n}:53"), Duration::from_millis(400));
        }
        assert_eq!(manager.answer_time_of.len(), UPSTREAMS_TIMED);
        assert!(
            manager.stuck_after("udp://upstream-4100:53", LIMIT) >= Duration::from_millis(800),
            "by all together"
        );
    }

    /// 卡住的查询留一千个，各设备平分：只有一台时它留满一千个，再卡住的不留，放下一个又能留一个；这时另一台设备照样留得下，
    /// 留到它那一半为止，先留下的不收回。一千台各留一个以后，每台还是留得下 `SHARE_AT_LEAST` 个；留着的设备到了
    /// `MAX_QUEUED_DEVICES` 台，新来的和已经留着的都不再留
    /// A thousand stuck queries are kept, shared among the devices: a lone device keeps the
    /// thousand and no more, and letting one go makes room for one; another device still keeps
    /// its own then, up to its half, those kept earlier staying. With a thousand devices keeping
    /// one each, each still keeps `SHARE_AT_LEAST`; with `MAX_QUEUED_DEVICES` devices keeping
    /// any, neither a new device nor one keeping some already keeps another
    #[test]
    fn stuck_queries_are_kept_up_to_a_share_each() {
        let manager = PermitManager::new();
        let mut kept: Vec<_> = all_it_may_keep(&manager, ONE);
        assert_eq!(kept.len(), STUCK_KEPT);
        assert_eq!(manager.dropped_requests(), 1);
        kept.pop();
        kept.push(manager.keep_stuck(ONE).expect("room for one again"));
        assert!(manager.keep_stuck(ONE).is_none(), "at its share again");

        let other: Vec<_> = all_it_may_keep(&manager, OTHER);
        assert_eq!(other.len(), STUCK_KEPT / 2 - 1, "up to its half");
        assert_eq!(manager.stuck(), STUCK_KEPT + STUCK_KEPT / 2 - 1);
        drop((kept, other));
        assert_eq!(manager.stuck(), 0);

        let mut each: Vec<_> = (0..STUCK_KEPT as u16)
            .map(|n| manager.keep_stuck(DeviceSlot(n, n)).expect("one each"))
            .collect();
        let new = all_it_may_keep(&manager, DeviceSlot(5000, 5000));
        assert_eq!(new.len(), SHARE_AT_LEAST, "a new device keeps a few");
        let more = all_it_may_keep(&manager, DeviceSlot(3, 3));
        assert_eq!(
            more.len(),
            SHARE_AT_LEAST - 1,
            "one keeping one already too"
        );
        drop((new, more));

        each.extend(
            (STUCK_KEPT as u16..MAX_QUEUED_DEVICES as u16)
                .map(|n| manager.keep_stuck(DeviceSlot(n, n)).expect("one each")),
        );
        assert!(
            manager.keep_stuck(DeviceSlot(5000, 5000)).is_none(),
            "too many devices to look after each"
        );
        assert!(manager.keep_stuck(DeviceSlot(3, 3)).is_none(), "a second");
        drop(each);
        assert_eq!(manager.stuck(), 0);
    }

    /// `device` 的卡住的查询一直留到留不下为止。留得下的个数有上限，过了上限还留得下就是没在数，当场失败——不然这个循环会
    /// 一直分配内存，直到把机器吃满
    /// Keeps stuck queries of `device` waiting until no more is kept. What can be kept is
    /// bounded, and keeping past the bound means nothing is being counted, failing at once: left
    /// open, this loop would allocate until the machine ran out of memory
    fn all_it_may_keep(manager: &PermitManager, device: DeviceSlot) -> Vec<Stuck<'_>> {
        let mut kept = Vec::new();
        while let Some(one) = manager.keep_stuck(device) {
            kept.push(one);
            assert!(kept.len() <= 10 * STUCK_KEPT, "unbounded");
        }
        kept
    }

    /// 知道回答只要 1 毫秒的 manager：等了 100 毫秒以上还没回答的算卡住 / A manager knowing answers take
    /// 1 ms, so a query waiting over 100 ms with no answer counts as stuck
    fn knowing() -> PermitManager {
        let manager = PermitManager::new();
        manager.answer_time.note(1);
        assert_eq!(manager.stuck_after(UP, LIMIT), BUSY_AFTER);
        manager
    }

    const CLIENT: &str = "192.0.2.1";

    /// 等 `wait`，最多五秒：代码改坏了、该结束的等待一直不结束时，测试当场失败，不把整套测试挂住
    /// Waits for `wait`, five seconds at most: with the code broken so that a wait that should
    /// end never does, the test fails there and then instead of hanging the whole run
    async fn soon<T>(wait: impl Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(5), wait)
            .await
            .expect("ended within five seconds")
    }

    /// `client` 落在哪一份：留着等的卡住的查询按它数 / The slot `client` lands in, which the stuck
    /// queries kept waiting are counted by
    fn device(manager: &PermitManager, client: &str) -> DeviceSlot {
        manager.slot_of(client.parse().unwrap())
    }

    /// 替 `client` 等 `upstream`，流控没在跟不上 / Waits on `upstream` for `client`, flow control not
    /// falling behind
    fn ask<'a>(manager: &'a PermitManager, client: &str, upstream: &'a str) -> Option<Asking<'a>> {
        manager.ask(&FLOW, client.parse().unwrap(), upstream, LIMIT)
    }

    /// 「`client`、`upstream`」记着的回答了的和没回答的 / What is noted for `client` and `upstream`:
    /// answered and unanswered
    fn noted(manager: &PermitManager, client: &str, upstream: &str) -> (u64, u64) {
        let slots = manager.asked_slots(client.parse().unwrap(), upstream);
        let word = manager.asked.per_slot[slots[0]].load(Ordering::Relaxed);
        (word & 0xffff, (word >> 16) & 0xffff)
    }

    /// 及时走完的照常给出结果，不算卡住，也不记没回答 / One done in time gives its result, is not stuck
    /// and is not noted as unanswered
    #[tokio::test]
    async fn a_wait_done_in_time_gives_its_result() {
        let manager = knowing();
        let mut asking = ask(&manager, CLIENT, UP).expect("asked");
        let done = asking.wait(std::pin::pin!(async { 7 })).await;
        assert_eq!(done, Ok(7));
        assert_eq!(manager.stuck(), 0);
        drop(asking);
        assert_eq!(noted(&manager, CLIENT, UP), (0, 0), "ended quickly");
    }

    /// 卡住了、这台设备留着等的还没到它那一份：留着等到转发自己结束，这期间算在卡住的里面，结束了不再算；没等到回答就
    /// 记一个没回答
    /// Stuck with what this device keeps waiting under its share: it waits until the forward
    /// ends by itself, counted among the stuck meanwhile and no longer after; ending with no
    /// answer, it is noted as one unanswered
    #[tokio::test]
    async fn a_stuck_wait_under_the_share_waits_to_the_end() {
        let manager = knowing();
        let mut asking = ask(&manager, CLIENT, UP).expect("asked");
        let started = Instant::now();
        let forward = std::pin::pin!(async {
            tokio::time::sleep(Duration::from_millis(400)).await;
            "timed out"
        });
        let waiting = asking.wait(forward);
        let watching = async {
            tokio::time::sleep(Duration::from_millis(250)).await;
            manager.stuck()
        };
        let (done, stuck_meanwhile) = tokio::join!(waiting, watching);
        assert_eq!(done, Ok("timed out"));
        assert!(started.elapsed() >= Duration::from_millis(400));
        assert_eq!(stuck_meanwhile, 1);
        assert_eq!(manager.stuck(), 0);
        assert_eq!(manager.dropped_requests(), 0);
        drop(asking);
        assert_eq!(noted(&manager, CLIENT, UP), (0, 1));
    }

    /// 卡住了、这台设备留着等的已经到了它那一份：到算卡住的时候就不等了，不等转发自己结束，记一个没回答；别的设备的照样留着
    /// Stuck with this device keeping its share waiting already: it waits no more when it
    /// counts as stuck, not until the forward ends by itself, and is noted as one unanswered;
    /// another device's is kept all the same
    #[tokio::test]
    async fn a_stuck_wait_past_the_share_gives_up() {
        let manager = knowing();
        let kept: Vec<_> = all_it_may_keep(&manager, device(&manager, CLIENT));
        let refused = manager.dropped_requests();
        let mut asking = ask(&manager, CLIENT, UP).expect("asked");
        let started = Instant::now();
        let done = soon(asking.wait(std::pin::pin!(std::future::pending::<()>()))).await;
        assert_eq!(done, Err(GaveUp));
        let took = started.elapsed();
        assert!(
            took >= BUSY_AFTER && took < Duration::from_secs(2),
            "{took:?}"
        );
        assert_eq!(manager.dropped_requests(), refused + 1);
        assert_eq!(manager.stuck(), STUCK_KEPT);
        drop(asking);
        assert_eq!(noted(&manager, CLIENT, UP), (0, 1));

        let mut other = ask(&manager, "192.0.2.2", UP).expect("asked");
        let done = other
            .wait(std::pin::pin!(async {
                tokio::time::sleep(Duration::from_millis(300)).await;
            }))
            .await;
        assert_eq!(done, Ok(()), "another device's is kept");
        drop(kept);
    }

    /// 哪个上游都还没等到过回答时（刚启动），等过上游应当已经回答的时间点就算卡住：留满了的不等了，不用等到上游超时。
    /// 上游不通时启动，或者刚启动就遇上不回答的洪泛，在途的不会一直涨到超时
    /// With no answer from any upstream yet (a fresh start), a wait past the point an upstream
    /// should have answered by counts as stuck: with all kept it waits no more, not on to the
    /// upstream's timeout. Starting with the upstream unreachable, or into a flood of names
    /// with no answer, what is in flight does not grow all the way to the timeout
    #[tokio::test]
    async fn before_any_answer_a_wait_past_the_hedge_point_gives_up() {
        let manager = PermitManager::new();
        let kept: Vec<_> = all_it_may_keep(&manager, device(&manager, CLIENT));
        let mut asking = manager
            .ask(
                &FLOW,
                CLIENT.parse().unwrap(),
                UP,
                Duration::from_millis(900),
            )
            .expect("asked");
        let started = Instant::now();
        let done = soon(asking.wait(std::pin::pin!(std::future::pending::<()>()))).await;
        assert_eq!(done, Err(GaveUp));
        let took = started.elapsed();
        assert!(
            took >= Duration::from_millis(300) && took < Duration::from_millis(900),
            "{took:?}"
        );
        drop(kept);
    }

    /// 留着等的等到了回答：结果照常给出；转发那一层把这次收发用了多久记下来（见 `PermitManager::note_answer_took`），算卡住
    /// 的时间跟着变长，下一个同样慢的不再算卡住
    /// One kept waiting gets its answer: the result is given as usual; the forward notes how
    /// long the exchange took (see `PermitManager::note_answer_took`), the time a query counts
    /// as stuck after grows with it, and the next one as slow is not stuck
    #[tokio::test]
    async fn a_kept_wait_answered_late_makes_the_wait_longer() {
        let manager = knowing();
        let slow = || async {
            tokio::time::sleep(Duration::from_millis(250)).await;
            manager.note_answer_took(UP_ADDRESS, Duration::from_millis(250));
            9
        };
        let mut asking = ask(&manager, CLIENT, UP).expect("asked");
        let done = asking.wait(std::pin::pin!(slow())).await;
        assert_eq!(done, Ok(9));
        asking.replied(true);
        assert_eq!(manager.stuck(), 0);
        let after = manager.stuck_after(UP, LIMIT);
        assert!(after >= Duration::from_millis(500), "{after:?}");

        // 留满以后，同样慢的下一个没到算卡住的时候就回答了，照常等到
        // With all kept, the next one as slow is answered before it counts as stuck and is
        // waited for as usual
        let kept: Vec<_> = all_it_may_keep(&manager, device(&manager, CLIENT));
        let mut next = ask(&manager, CLIENT, UP).expect("asked");
        let done = next.wait(std::pin::pin!(slow())).await;
        assert_eq!(done, Ok(9));
        drop(kept);
    }

    /// 等的这一阵里回答变慢了，到点重算一次再定：开始等时 100 毫秒算卡住，等到 40 毫秒时这个上游的回答变成了 200 毫秒，
    /// 留满了的设备这个 250 毫秒才回答的查询照常等到，不在 100 毫秒那一刻就不等了
    /// With answers getting slower during the wait, it is worked out once more when the time
    /// comes: counting as stuck after 100 ms as the wait began, with this upstream's answers
    /// turning to 200 ms forty milliseconds in, a query answered at 250 ms of a device keeping
    /// all it may is waited for as usual, not dropped at the 100 ms mark
    #[tokio::test]
    async fn answers_getting_slower_meanwhile_put_off_being_stuck() {
        let manager = knowing();
        let kept: Vec<_> = all_it_may_keep(&manager, device(&manager, CLIENT));
        let mut asking = ask(&manager, CLIENT, UP).expect("asked");
        let slower = async {
            tokio::time::sleep(Duration::from_millis(40)).await;
            for _ in 0..4 {
                manager.note_answer_took(UP_ADDRESS, Duration::from_millis(200));
            }
            tokio::time::sleep(Duration::from_millis(210)).await;
            5
        };
        let done = soon(asking.wait(std::pin::pin!(slower))).await;
        assert_eq!(done, Ok(5));
        drop(kept);
    }

    /// 内核自己在排队时，算卡住的时间不变：排队排了再久，一直不回答的查询照样到点就不等了。把排队的时间加上去的话，在途
    /// 越多排得越久、越没有谁算卡住
    /// With the kernel itself queueing, the time a query counts as stuck after stays as it is:
    /// however long the queueing, a query never answered waits no more when its time comes.
    /// With the queueing added, the more in flight the longer the queueing and the less would
    /// count as stuck
    #[tokio::test]
    async fn the_kernels_own_queueing_does_not_put_off_being_stuck() {
        let manager = knowing();
        let behind = state(Duration::ZERO);
        behind.note_queue_delay(Duration::from_secs(3600));
        let kept: Vec<_> = all_it_may_keep(&manager, device(&manager, CLIENT));
        let mut never = manager
            .ask(&behind, CLIENT.parse().unwrap(), UP, LIMIT)
            .expect("asked");
        let started = Instant::now();
        let done = soon(never.wait(std::pin::pin!(std::future::pending::<()>()))).await;
        assert_eq!(done, Err(GaveUp));
        let took = started.elapsed();
        assert!(
            took >= BUSY_AFTER && took < Duration::from_millis(500),
            "{took:?}"
        );
        drop(kept);
    }

    /// `manager` 记的时间往后拨 `by`，不用真等 / Moves what `manager` reads as now on by `by`, without
    /// waiting
    fn later(manager: &mut PermitManager, by: Duration) {
        manager.asked.started -= by;
    }

    /// 替 `client` 等 `upstream` 的 `count` 次等待都卡住了、没等到回答 / `count` waits on `upstream` for
    /// `client`, each stuck and none answered
    fn unanswered(manager: &PermitManager, client: &str, upstream: &str, count: usize) {
        for _ in 0..count {
            let mut asking = ask(manager, client, upstream).expect("asked");
            asking.stuck = true;
        }
    }

    /// 替 `client` 等 `upstream` 的一次等待等到了回答；被拦着没等的是 false / One wait on `upstream` for
    /// `client` gets its answer; false when held back and not waiting
    fn asks(manager: &PermitManager, client: &str, upstream: &str) -> bool {
        match ask(manager, client, upstream) {
            Some(asking) => {
                asking.answered();
                true
            }
            None => false,
        }
    }

    /// 一台设备等一个上游，没等到回答的到了 64 个、又比等到的多，就不替它等这个上游了，记拒绝；它等别的上游、别的设备等这个
    /// 上游都照常
    /// With 64 of a device's waits on an upstream unanswered, more than were answered, the
    /// upstream is no longer waited on for it, counted as refused; its waits on another
    /// upstream and another device's on this one go on
    #[test]
    fn a_device_is_held_back_from_an_upstream_that_mostly_does_not_answer_it() {
        let manager = knowing();
        unanswered(&manager, CLIENT, UP, 63);
        let last = ask(&manager, CLIENT, UP).map(|mut asking| asking.stuck = true);
        assert!(last.is_some(), "63 unanswered pass");
        assert_eq!(manager.dropped_requests(), 0);
        assert!(
            ask(&manager, CLIENT, UP).is_none(),
            "64 unanswered and none answered"
        );
        assert_eq!(manager.dropped_requests(), 1);
        assert!(
            asks(&manager, CLIENT, "udp://198.51.100.2:53"),
            "another upstream"
        );
        assert!(asks(&manager, "192.0.2.2", UP), "another device");
    }

    /// 没回答的要多过回答了的才拦：五个里一个不回答，等多少都不拦；回答了 160 个之后，没回答的到 160 个还不拦，161 个才拦。
    /// 等到回答的每 16 个记一次、一次记 16 个，所以这里用 16 的整数倍
    /// It takes more unanswered than answered: with one in five unanswered nothing is held back
    /// however many wait; after 160 answered, 160 unanswered still pass and the 161st holds it
    /// back. Answered ones are noted once in 16, as 16 at once, hence the multiples of 16 here
    #[test]
    fn a_device_is_not_held_back_while_more_are_answered() {
        let manager = knowing();
        for n in 0..5000 {
            let mut asking = ask(&manager, CLIENT, UP).expect("one in five unanswered");
            if n % 5 != 0 {
                asking.answered();
            } else {
                asking.stuck = true;
            }
        }
        assert_eq!(manager.dropped_requests(), 0);

        for _ in 0..160 {
            assert!(asks(&manager, "192.0.2.9", UP));
        }
        unanswered(&manager, "192.0.2.9", UP, 160);
        let last = ask(&manager, "192.0.2.9", UP).map(|mut asking| asking.stuck = true);
        assert!(last.is_some(), "as many unanswered as answered");
        assert!(
            ask(&manager, "192.0.2.9", UP).is_none(),
            "one more unanswered than answered"
        );
    }

    /// 记的个数到了 1024 就减半，很久以来都回答的设备不会一直不被拦：回答了一万个以后上游不回答了，再等不到一千个就拦住
    /// （记着的回答了的在 512 到 1024 之间，没回答的多过它就拦）
    /// What is noted is halved at 1024, so a device answered for long is not let through for
    /// ever: after ten thousand answered the upstream stops answering, and under a thousand more
    /// hold it back (those answered are kept between 512 and 1024, and it is held back once
    /// those unanswered outnumber them)
    #[test]
    fn a_long_good_record_does_not_keep_a_device_from_being_held_back() {
        let manager = knowing();
        for _ in 0..10_000 {
            assert!(asks(&manager, CLIENT, UP));
        }
        let mut asked = 0;
        while let Some(mut asking) = ask(&manager, CLIENT, UP) {
            asking.stuck = true;
            asked += 1;
            assert!(asked <= 2000, "never held back");
        }
        assert!(
            (512..=1024).contains(&asked),
            "{asked} asked before held back"
        );
    }

    /// 拦着的时候隔一秒放一个去试，从拦住那一刻算起：刚拦住时不放，过一秒放一个、紧接着的不放；试的那个没等到回答，接着拦，
    /// 再过一秒再放一个；等到了回答，都放开，从头记
    /// While held back one goes to try every second, counted from when it was held back: none
    /// at first, one a second on and not the next; a try going unanswered keeps it held back
    /// with another a second later; a try answered lets them all through, noted afresh
    #[test]
    fn one_goes_to_try_every_second_and_an_answer_lets_all_through() {
        let mut manager = knowing();
        // 内核已经跑了一阵：那一秒是从拦住那一刻算的，不是从启动算的 / The kernel has been up a
        // while: the second counts from when it was held back, not from the start
        later(&mut manager, TRIES_APART * 3);
        unanswered(&manager, CLIENT, UP, 64);
        assert!(ask(&manager, CLIENT, UP).is_none(), "just held back");
        later(&mut manager, TRIES_APART - Duration::from_millis(100));
        assert!(ask(&manager, CLIENT, UP).is_none(), "not a second yet");
        later(&mut manager, Duration::from_millis(100));
        let mut first = ask(&manager, CLIENT, UP).expect("a try a second on");
        assert!(ask(&manager, CLIENT, UP).is_none(), "one try only");
        first.stuck = true;
        drop(first);
        assert!(
            ask(&manager, CLIENT, UP).is_none(),
            "the try went unanswered"
        );
        later(&mut manager, TRIES_APART);
        ask(&manager, CLIENT, UP).expect("another try").answered();
        for _ in 0..10 {
            assert!(asks(&manager, CLIENT, UP), "answered again");
        }
        unanswered(&manager, CLIENT, UP, 63);
        assert!(
            ask(&manager, CLIENT, UP).is_some(),
            "noted afresh: 63 unanswered pass"
        );
    }

    /// 放去试的那一个等到的是失败应答（上游回了 SERVFAIL），不算等到回答，接着拦
    /// The one that went to try getting a failure reply (the upstream replying SERVFAIL) is no
    /// answer, and the device stays held back
    #[test]
    fn a_try_getting_a_failure_reply_does_not_let_it_through() {
        let mut manager = knowing();
        unanswered(&manager, CLIENT, UP, 64);
        later(&mut manager, TRIES_APART);
        ask(&manager, CLIENT, UP).expect("a try").replied(false);
        assert!(ask(&manager, CLIENT, UP).is_none(), "still held back");
        assert_eq!(noted(&manager, CLIENT, UP), (0, 64), "and noted as neither");
    }

    /// 上游回了失败应答，两样都不记，回得再晚也一样：上游是回了的，只是这个名字解析不了。一个程序反复问一个坏掉的名字，
    /// 上游每次都过了算卡住的时间才回 SERVFAIL，问多少次也不拦这台设备
    /// A failure reply from the upstream is noted as neither, however late it comes: the
    /// upstream did reply, only this name does not resolve. A program asking one broken name
    /// over and over, the upstream replying SERVFAIL each time after the time a query counts as
    /// stuck after, does not hold its device back however often
    #[test]
    fn a_failure_reply_is_noted_as_neither_however_late() {
        let manager = knowing();
        for _ in 0..500 {
            let mut asking = ask(&manager, CLIENT, UP).expect("never held back");
            asking.stuck = true;
            asking.since -= LIMIT;
            asking.replied(false);
        }
        assert_eq!(noted(&manager, CLIENT, UP), (0, 0));
        assert_eq!(manager.dropped_requests(), 0);
    }

    /// 拦住以前开始的等待后来才等到回答，不会当场把它放开：这些回答照常记成回答了的，不从头记，要多过没回答的才不拦（见
    /// `enough_late_answers_end_the_holding_back`）。上游不怎么回答时，一阵洪泛里总有一小部分等到回答，这些回答要是一个
    /// 就算数，刚拦住就又放开，等于没拦。放去试的那一个等到回答，才当场放开
    /// Answers arriving later to waits begun before it was held back do not let it through there
    /// and then: they are noted as answered like any other and not afresh, and it takes more of
    /// them than unanswered to end the holding back (see
    /// `enough_late_answers_end_the_holding_back`). With an upstream answering little, a small
    /// part of a flood always gets answered, and were one of those enough it would be let
    /// through as soon as it was held back, as good as never held. The one that went to try
    /// getting its answer is what lets it through at once
    #[test]
    fn answers_to_waits_begun_before_being_held_back_do_not_let_it_through() {
        let mut manager = knowing();
        let begun_before: Vec<_> = (0..20)
            .map(|_| ask(&manager, CLIENT, UP).expect("asked"))
            .collect();
        unanswered(&manager, CLIENT, UP, 64);
        assert!(ask(&manager, CLIENT, UP).is_none(), "held back");
        for late in begun_before {
            late.answered();
        }
        assert!(ask(&manager, CLIENT, UP).is_none(), "still held back");
        later(&mut manager, TRIES_APART);
        ask(&manager, CLIENT, UP).expect("a try").answered();
        assert!(asks(&manager, CLIENT, UP), "let through by the try");
    }

    /// 拦着的时候，之前开始的等待等到的回答多过了没回答的，也就不拦了：上游确实又在回答它
    /// While held back, once the answers to waits begun before outnumber those unanswered it
    /// is no longer held back: the upstream does answer it again
    #[test]
    fn enough_late_answers_end_the_holding_back() {
        let manager = knowing();
        let begun_before: Vec<_> = (0..65)
            .map(|_| ask(&manager, CLIENT, UP).expect("asked"))
            .collect();
        unanswered(&manager, CLIENT, UP, 64);
        assert!(ask(&manager, CLIENT, UP).is_none(), "held back");
        for late in begun_before {
            late.answered();
        }
        assert!(asks(&manager, CLIENT, UP), "more answered than not");
    }

    /// 上游什么都没回的等待，等得久的才记：很快就结束的（上游一连就断）两样都不记；等过了算卡住的时间的，或者等满了上游的
    /// 时限的（上游超时，算卡住的时间比时限还长时也一样），记没回答，到 64 个就拦
    /// Of waits ending with nothing from the upstream only the long ones are noted: one ending
    /// quickly (the upstream refusing the connection) is noted as neither; one past the time a
    /// query counts as stuck after, or lasting the whole of the upstream's timeout (the upstream
    /// timing out, also where that time is longer than the timeout), is noted as no answer, and
    /// 64 hold the device back
    #[test]
    fn only_waits_that_lasted_long_count_as_unanswered() {
        let manager = knowing();
        for _ in 0..500 {
            drop(ask(&manager, CLIENT, UP).expect("ending quickly"));
        }
        assert_eq!(noted(&manager, CLIENT, UP), (0, 0));
        assert_eq!(manager.dropped_requests(), 0);

        unanswered(&manager, CLIENT, UP, 64);
        assert!(ask(&manager, CLIENT, UP).is_none(), "64 past being stuck");

        let other = "192.0.2.2";
        for _ in 0..64 {
            let mut asking = ask(&manager, other, UP).expect("asked");
            asking.since -= LIMIT;
        }
        assert!(
            ask(&manager, other, UP).is_none(),
            "64 lasting the whole timeout"
        );
        let nearly = "192.0.2.3";
        for _ in 0..64 {
            let mut asking = ask(&manager, nearly, UP).expect("asked");
            asking.since -= LIMIT - Duration::from_millis(500);
        }
        assert!(ask(&manager, nearly, UP).is_some(), "short of the timeout");
    }

    /// 内核自己正跟不上时，等得久说明不了上游：不记没回答，除非这台设备在这个上游上一个回答都没等到过
    /// While the kernel itself is falling behind a long wait says nothing of the upstream: it is
    /// not noted as no answer, unless this device never got an answer from this upstream
    #[test]
    fn a_wait_ending_while_the_kernel_falls_behind_is_not_blamed_on_the_upstream() {
        let client: std::net::IpAddr = CLIENT.parse().unwrap();
        let behind = state(Duration::ZERO);
        behind.note_queue_delay(Duration::from_secs(2));
        let stuck = |manager: &PermitManager, client| {
            let mut asking = manager.ask(&behind, client, UP, LIMIT).expect("asked");
            asking.stuck = true;
        };

        let manager = knowing();
        for _ in 0..16 {
            manager
                .ask(&behind, client, UP, LIMIT)
                .expect("asked")
                .answered();
        }
        for _ in 0..200 {
            stuck(&manager, client);
        }
        assert!(
            manager.ask(&behind, client, UP, LIMIT).is_some(),
            "the kernel falling behind, with answers from this upstream before"
        );
        assert_eq!(noted(&manager, CLIENT, UP), (16, 0));

        let other: std::net::IpAddr = "192.0.2.2".parse().unwrap();
        for _ in 0..64 {
            stuck(&manager, other);
        }
        assert!(
            manager.ask(&behind, other, UP, LIMIT).is_none(),
            "never an answer from this upstream"
        );
    }

    /// 等到回答的每 16 个记一次、一次记 16 个：15 个不记，第 16 个记成 16 个；没等到回答的逐个记
    /// Answered ones are noted once in 16, as 16 at once: 15 leave nothing, the 16th notes 16;
    /// unanswered ones are noted one by one
    #[test]
    fn answered_ones_are_noted_sixteen_at_a_time() {
        let manager = knowing();
        for _ in 0..15 {
            assert!(asks(&manager, CLIENT, UP));
        }
        assert_eq!(noted(&manager, CLIENT, UP), (0, 0));
        assert!(asks(&manager, CLIENT, UP));
        assert_eq!(noted(&manager, CLIENT, UP), (16, 0));
        unanswered(&manager, CLIENT, UP, 3);
        assert_eq!(noted(&manager, CLIENT, UP), (16, 3));
    }

    /// 有几份是没回答的多，记着个数：拦住一台是 2，放开以后回到 0——平常是 0，等之前不用算哈希去看
    /// How many slots read mostly unanswered is kept count of: 2 with one device held back and
    /// 0 again once it is let through; zero as a rule, when waiting needs no hash to look
    #[test]
    fn slots_reading_mostly_unanswered_are_counted() {
        let mut manager = knowing();
        let held =
            |manager: &PermitManager| manager.asked.mostly_unanswered.load(Ordering::Relaxed);
        assert_eq!(held(&manager), 0);
        unanswered(&manager, CLIENT, UP, 64);
        assert_eq!(held(&manager), 2);
        unanswered(&manager, "192.0.2.2", UP, 64);
        assert_eq!(held(&manager), 4);
        later(&mut manager, TRIES_APART);
        ask(&manager, CLIENT, UP).expect("a try").answered();
        assert_eq!(held(&manager), 2);
    }

    /// 两个核前后脚改同一份、减的比加的先到时，个数也不会多出来：先减后加，回到 0。以前在 0 处截住，那一次减丢了，之后永远
    /// 多着一个，问之前每次都要白算一次哈希
    /// With two cores changing one slot right after each other and the taking off landing
    /// before the adding, the count does not end up one too many: taken off and then added, it
    /// is zero again. Stopped at zero as it used to be, that taking off was lost and the count
    /// read one too many ever after, every ask then working out a hash for nothing
    #[test]
    fn the_count_of_slots_is_right_whichever_change_lands_first() {
        let asked = Asked::new();
        let slots = [7, DEVICE_SLOTS + 7];
        // 一个核把这一份改成了「没回答的多」，还没来得及加；另一个核紧接着把它改了回去，先减
        // One core has made the slot read mostly unanswered and not yet added; another makes it
        // read otherwise right after, and takes off first
        for slot in slots {
            let unanswered = UNANSWERED_BEFORE_HELD_BACK << 16;
            asked.per_slot[slot].store(unanswered, Ordering::Relaxed);
        }
        asked.note(slots, Noted::TryAnswered);
        assert_eq!(asked.mostly_unanswered.load(Ordering::Relaxed), -2);
        asked.mostly_unanswered.fetch_add(2, Ordering::Relaxed);
        assert_eq!(asked.mostly_unanswered.load(Ordering::Relaxed), 0);
    }

    /// 两份都是没回答的多才拦：只和被拦的设备落在同一份的设备照常，它等到的回答也不会把被拦的那台放开
    /// It takes both slots reading mostly unanswered: a device landing with a held-back one in
    /// one slot only goes on, and the answers it gets do not let the held-back one through
    #[test]
    fn a_device_sharing_one_slot_with_a_held_back_one_goes_on() {
        let asked = Asked::new();
        let (held, sharing) = ([7, DEVICE_SLOTS + 7], [7, DEVICE_SLOTS + 8]);
        for _ in 0..200 {
            asked.note(held, Noted::Unanswered);
        }
        assert!(asked.held_back(held));
        assert!(!asked.held_back(sharing));
        for _ in 0..50 {
            asked.note(sharing, Noted::Answered(1));
        }
        assert!(
            asked.held_back(held),
            "another device's answers do not let it through"
        );
        assert!(!asked.held_back(sharing));
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
                flow.permit(&manager, Instant::now(), ONE)
                    .expect("few in flight")
            })
            .collect();
        in_flight.push(
            flow.permit(&manager, Instant::now(), ONE)
                .expect("the last under the floor"),
        );
        assert_eq!(manager.dropped_requests(), 0);

        assert!(flow.permit(&manager, Instant::now(), ONE).is_none());
        assert_eq!(manager.dropped_requests(), 1);
        assert_eq!(manager.inflight(), 1000, "a refused query holds no permit");

        in_flight.truncate(999);
        assert!(
            flow.permit(&manager, Instant::now(), ONE).is_some(),
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
            flow.permit(&manager, Instant::now(), ONE).is_none(),
            "the device holding the memory"
        );
        assert!(flow.permit_by_memory(&manager, ONE).is_none());
        let light: Vec<_> = (0..10)
            .map(|_| {
                flow.permit(&manager, Instant::now(), OTHER)
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
            .map(|_| manager.acquire_for(DeviceSlot(0, 0)))
            .collect();
        for n in 1..100u16 {
            held.extend((0..10).map(|_| manager.acquire_for(DeviceSlot(n, n))));
        }
        let noted = held.len();
        loop {
            let before = held.len();
            held.extend(
                (0..100u16).filter_map(|n| flow.permit_by_memory(&manager, DeviceSlot(n, n))),
            );
            assert!(held.len() <= 3 * noted, "unbounded");
            if held.len() == before {
                break;
            }
        }
        assert!(held.len() <= noted + 100, "{} held", held.len());
        assert!(
            flow.connection_permit(&manager, DeviceSlot(1, 1)).is_none(),
            "nor a new connection for one at its share"
        );
        assert!(
            flow.permit_by_memory(&manager, DeviceSlot(500, 500))
                .is_some(),
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
                flow.connection_permit(&manager, DeviceSlot(n, n))
                    .expect("a device with no connection connects")
            })
            .collect();
        assert!(manager.inflight() >= 1000, "memory is read");
        for n in [0, 1, 500, 1023] {
            assert!(
                flow.permit_by_memory(&manager, DeviceSlot(n, n)).is_some(),
                "a query on the connection of {n}"
            );
            assert!(
                flow.permit(&manager, Instant::now(), DeviceSlot(n, n))
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
        while let Some(permit) = flow.permit(&manager, busy, ONE) {
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
            full.connection_permit(&manager, DeviceSlot(2, 2)).is_none(),
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
        assert!(tight.permit(&manager, Instant::now(), ONE).is_none());
        assert!(tight.permit(&manager, Instant::now(), OTHER).is_none());

        let full = with_memory_left(1 << 20);
        assert!(
            full.permit(&manager, Instant::now(), DeviceSlot(2, 2))
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
        let stuck = manager.keep_stuck(ONE).expect("under its share");
        assert_eq!(manager.stuck(), 1);
        assert_eq!(manager.queries.slots_held.load(Ordering::Relaxed), 2);
        assert_eq!(manager.queries.per_slot[0].load(Ordering::Relaxed), 2);
        assert_eq!(manager.queries.total.load(Ordering::Relaxed), 3);
        assert_eq!(manager.connections.slots_held.load(Ordering::Relaxed), 1);
        drop(first);
        second.release();
        assert_eq!(manager.queries.slots_held.load(Ordering::Relaxed), 1);
        drop((other, plain, connection, stuck));
        for counts in [&manager.queries, &manager.connections, &manager.stuck] {
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
    }

    /// 两千台设备几乎都各有各的份：按一个哈希落在一起的约 3%，两个哈希不一样，两份都落在一起的几乎没有。以前只有 1024 份，
    /// 两千台里大半和别的设备落在一起
    /// Two thousand devices have slots of their own almost all: by one hash about 3% land
    /// together, the two hashes differ, and hardly any land together in both. There used to be
    /// only 1024 slots, and most of two thousand landed with another
    #[test]
    fn devices_rarely_share_a_slot() {
        let manager = PermitManager::new();
        let slots: Vec<_> = (0..2000u32)
            .map(|n| manager.slot_of(std::net::Ipv4Addr::from(0x0a00_0000 + n).into()))
            .collect();
        let distinct = |pick: fn(&DeviceSlot) -> u16| {
            slots
                .iter()
                .map(pick)
                .collect::<std::collections::HashSet<_>>()
                .len()
        };
        assert!(distinct(|slot| slot.0) >= 1900, "by the first hash");
        assert!(distinct(|slot| slot.1) >= 1900, "by the second hash");
        let both: std::collections::HashSet<_> = slots.iter().collect();
        assert!(both.len() >= 1999, "{} distinct in both", both.len());
        assert!(
            slots.iter().filter(|slot| slot.0 == slot.1).count() < 10,
            "two different hashes"
        );
    }

    /// 发得少的设备和一台洪泛的设备按一个哈希落在同一份时，看的是另一份，它照常；两份都落在一起才算成同一台。以前只有一份，
    /// 落在一起的设备整个洪泛期间问的全被拒
    /// A device sending little landing in one slot with a flooding device goes by its other slot
    /// and goes on; only landing together in both counts as the same device. With one slot only, a
    /// device landing together was refused everything it asked during the whole flood
    #[test]
    fn a_device_sharing_one_slot_with_a_flooding_one_goes_on() {
        let manager = Arc::new(PermitManager::new());
        let flow = state(Duration::from_secs(60));
        let busy = Instant::now() - LONG_AGO;
        flow.note_queue_delay(Duration::from_secs(3600));
        let flooder = DeviceSlot(7, 7);
        let held: Vec<_> = (0..1000).map(|_| manager.acquire_for(flooder)).collect();
        assert!(
            flow.permit(&manager, busy, flooder).is_none(),
            "the flooding one"
        );
        for light in [DeviceSlot(7, 8), DeviceSlot(8, 7)] {
            let asked: Vec<_> = (0..SHARE_AT_LEAST)
                .map(|_| flow.permit(&manager, busy, light).expect("one slot shared"))
                .collect();
            drop(asked);
        }
        assert!(
            flow.permit(&manager, busy, DeviceSlot(7, 7)).is_none(),
            "both slots shared"
        );
        assert_eq!(manager.dropped_requests(), 2);
        drop(held);

        // 卡住的查询也一样：洪泛的那台留满了，只和它落在同一份的设备照样留得下
        // Stuck queries alike: with the flooding one keeping all it may, a device landing with it
        // in one slot still keeps its own
        let kept: Vec<_> = all_it_may_keep(&manager, flooder);
        assert_eq!(kept.len(), STUCK_KEPT);
        for light in [DeviceSlot(7, 8), DeviceSlot(8, 7)] {
            assert!(manager.keep_stuck(light).is_some(), "one slot shared");
        }
        assert!(manager.keep_stuck(flooder).is_none(), "both slots shared");
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

    /// 数自己被叫醒过几次的任务 / A task counting how often it was woken
    struct TaskWoken(AtomicUsize);

    impl std::task::Wake for TaskWoken {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// 一件活：每次跑都把拿到的 waker 留在 `given` 里，`done` 置位以后才结束
    /// A piece of work: each run leaves the waker it was given in `given`, and it ends only once
    /// `done` is set
    fn work_keeping_its_waker(
        given: &Arc<parking_lot::Mutex<Option<std::task::Waker>>>,
        done: &Arc<AtomicBool>,
    ) -> impl Future<Output = u8> + use<> {
        let (given, done) = (Arc::clone(given), Arc::clone(done));
        std::future::poll_fn(move |cx| {
            *given.lock() = Some(cx.waker().clone());
            if done.load(Ordering::Relaxed) {
                std::task::Poll::Ready(7)
            } else {
                std::task::Poll::Pending
            }
        })
    }

    /// 一个查询有活等着内核干的时候才算：交出去到开始跑算，跑过以后在等别的（上游）不算，被叫醒到再轮到它跑又算，叫醒两次只算
    /// 一次；叫醒它的人叫醒的是任务本身。以前只数交出去还没开始跑的：上游的回答到了、任务被叫醒却轮不到跑的那些不算，几个核
    /// 一起处理时在途照样涨到十几万
    /// A query counts only while it has work waiting for the kernel: from being handed over
    /// until it starts running; not once it has run and waits on something else (an upstream);
    /// again from being woken until its turn to run comes, two wakes counting once; and whoever
    /// wakes it wakes the task itself. Only those handed over and not started used to be
    /// counted: those whose answer had arrived, woken with their turn to run not coming, were
    /// not, and with several cores at work what was in flight still grew past a hundred thousand
    #[test]
    fn a_query_counts_while_it_has_work_waiting_for_the_kernel() {
        use std::task::{Context, Poll, Waker};

        let task = Arc::new(TaskWoken(AtomicUsize::new(0)));
        let task_waker = Waker::from(Arc::clone(&task));
        let mut cx = Context::from_waker(&task_waker);
        let woken = || task.0.load(Ordering::Relaxed);
        let waiting = Arc::new(WaitingToRun::default());
        let given = Arc::new(parking_lot::Mutex::new(None));
        let done = Arc::new(AtomicBool::new(false));

        let mut query = Box::pin(WaitingToRun::counting(
            Arc::clone(&waiting),
            work_keeping_its_waker(&given, &done),
        ));
        assert_eq!(waiting.count(), 1, "handed over and not run yet");
        assert!(query.as_mut().poll(&mut cx).is_pending());
        assert_eq!(waiting.count(), 0, "it has run and waits on something else");

        let waker = given.lock().clone().expect("the work was given a waker");
        waker.wake_by_ref();
        assert_eq!(waiting.count(), 1, "woken, its turn to run not come");
        assert_eq!(woken(), 1, "the task itself is woken");
        waker.wake_by_ref();
        assert_eq!(waiting.count(), 1, "woken twice, counted once");
        assert_eq!(woken(), 2);
        assert!(query.as_mut().poll(&mut cx).is_pending());
        assert_eq!(waiting.count(), 0, "it has run again");

        // 跑完了：不再算，之后才到的叫醒也不算，也不再叫醒任务 / Done: it counts no more, nor does a
        // wake coming after, which wakes no task either
        waker.wake_by_ref();
        assert_eq!(waiting.count(), 1);
        done.store(true, Ordering::Relaxed);
        assert_eq!(query.as_mut().poll(&mut cx), Poll::Ready(7));
        assert_eq!(waiting.count(), 0);
        let before = woken();
        waker.wake();
        assert_eq!(waiting.count(), 0, "a wake after the end");
        assert_eq!(woken(), before);
    }

    /// 没跑完就被丢掉的查询不再算：一次都没跑过的，和被叫醒以后还没轮到跑的，都一样
    /// A query dropped before it is done counts no more: one that never ran, and one woken with
    /// its turn to run not come, alike
    #[test]
    fn a_query_dropped_while_waiting_to_run_counts_no_more() {
        use std::task::{Context, Waker};

        let waiting = Arc::new(WaitingToRun::default());
        let never_run = WaitingToRun::counting(Arc::clone(&waiting), std::future::pending::<()>());
        assert_eq!(waiting.count(), 1);
        drop(never_run);
        assert_eq!(waiting.count(), 0, "never run");

        let task_waker = Waker::from(Arc::new(TaskWoken(AtomicUsize::new(0))));
        let mut cx = Context::from_waker(&task_waker);
        let given = Arc::new(parking_lot::Mutex::new(None));
        let done = Arc::new(AtomicBool::new(false));
        let mut query = Box::pin(WaitingToRun::counting(
            Arc::clone(&waiting),
            work_keeping_its_waker(&given, &done),
        ));
        assert!(query.as_mut().poll(&mut cx).is_pending());
        let waker = given.lock().clone().unwrap();
        waker.wake_by_ref();
        assert_eq!(waiting.count(), 1);
        drop(query);
        assert_eq!(waiting.count(), 0, "woken, then dropped");
        waker.wake();
        assert_eq!(waiting.count(), 0, "and a wake after that");
    }

    /// 等着的到了 [`WAITING_TO_RUN_AT_MOST`] 个才算够多 / Enough are waiting only at
    /// [`WAITING_TO_RUN_AT_MOST`]
    #[test]
    fn enough_are_waiting_to_run_at_the_limit() {
        let waiting = Arc::new(WaitingToRun::default());
        let hand_over =
            || WaitingToRun::counting(Arc::clone(&waiting), std::future::pending::<()>());
        let mut handed_over: Vec<_> = (1..WAITING_TO_RUN_AT_MOST).map(|_| hand_over()).collect();
        assert!(!waiting.is_enough(), "one short");
        handed_over.push(hand_over());
        assert!(waiting.is_enough());
    }
}
