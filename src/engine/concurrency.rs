use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// 查询在内核里排队超过这么久，就算内核跟不上。这是延迟目标，和机器无关：快机器和慢机器都一样
/// Queries waiting longer than this inside the kernel means it cannot keep up. This is a
/// latency goal rather than a property of the machine, the same on a fast one and a slow one
const QUEUE_TARGET: Duration = Duration::from_millis(20);

/// 流控的状态。不用填数字，判断都来自运行时测到的：socket 收不收得空、查询排队多久、还剩多少内存
/// The state of flow control. There are no numbers to fill in: it goes by what is measured at
/// run time, namely whether a socket runs empty, how long queries queue and how much memory is left
pub struct FlowControlState {
    /// socket 连续这么久没收空就算忙 / How long a socket goes without running empty before that counts as busy
    pub busy_after: Duration,
    pub memory: super::memory_watermark::MemoryWatermark,
    started: Instant,
    /// 跟不上的状态到什么时候（从 `started` 算起的纳秒）/ Until when the kernel counts as behind, in nanoseconds since `started`
    behind_until_ns: AtomicU64,
}

impl FlowControlState {
    pub fn new(busy_after: Duration, memory: super::memory_watermark::MemoryWatermark) -> Self {
        Self {
            busy_after,
            memory,
            started: Instant::now(),
            behind_until_ns: AtomicU64::new(0),
        }
    }

    /// 一个要等上游的查询能不能处理，`emptied_at` 是 socket 上次收空的时刻。内存不够时拒绝；内核忙而且
    /// 查询在内核里排着长队时也拒绝。等上游不算排队，所以上游再慢，这样的查询也不会被拒绝
    /// Whether a query that waits on an upstream can go ahead, `emptied_at` being when the socket
    /// last ran empty. Too little memory refuses it, and so does the kernel being busy with
    /// queries queueing long inside it. Waiting on an upstream is not queueing, so however slow
    /// the upstream, such queries are not refused
    #[inline]
    pub fn permit(&self, manager: &Arc<PermitManager>, emptied_at: Instant) -> Option<PermitGuard> {
        if !self.memory.has_room(manager.inflight()) {
            manager.count_refused();
            return None;
        }
        if self.busy(emptied_at) && self.behind() {
            manager.count_refused();
            return None;
        }
        Some(manager.acquire())
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
    fn behind(&self) -> bool {
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

    /// 只看内存：TCP 和 DoH 没有 socket 收空这个信号，也就不看内核忙不忙
    /// By memory alone: TCP and DoH have no socket running empty to tell by, so whether the
    /// kernel is busy does not come into it
    #[inline]
    pub fn permit_by_memory(&self, manager: &Arc<PermitManager>) -> Option<PermitGuard> {
        if self.memory.has_room(manager.inflight()) {
            Some(manager.acquire())
        } else {
            manager.count_refused();
            None
        }
    }
}

/// 记着有多少查询和连接在处理、拒绝了多少 / Counts the queries and connections being handled, and those refused
pub struct PermitManager {
    // Current active permits (acquired) / 当前活跃 permits（已获得）
    pub(crate) active_permits: AtomicUsize,
    // Count of requests refused / 被拒绝的请求计数
    dropped_requests: AtomicU64,
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
        }
    }

    /// 拿一个 permit：这里不拒绝，只记着有多少在处理 / Takes a permit: nothing is refused here, this only counts what is being handled
    pub fn acquire(self: &Arc<Self>) -> PermitGuard {
        self.active_permits.fetch_add(1, Ordering::Release);
        PermitGuard::new(Arc::clone(self))
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
    #[inline]
    fn release_one(&self) {
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
    }

    /// Get current inflight permits count / 获取当前进行中的 permits 数
    #[inline]
    pub fn inflight(&self) -> usize {
        self.active_permits.load(Ordering::Acquire)
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
    released: AtomicBool, // Track if already released to handle double-drop / 跟踪是否已释放以处理双重释放
}

impl PermitGuard {
    fn new(manager: Arc<PermitManager>) -> Self {
        Self {
            manager,
            released: AtomicBool::new(false),
        }
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
            self.manager.release_one();
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
            self.manager.release_one();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::memory_watermark::{MemoryLeft, MemoryReading, MemoryWatermark};

    fn state(busy_after: Duration) -> FlowControlState {
        FlowControlState::new(busy_after, MemoryWatermark::reading(MemoryReading::default))
    }

    const LONG_AGO: Duration = Duration::from_secs(61);

    /// 忙而且排长队才拒绝：只忙（上游慢、socket 收不空）或只排队（短暂卡顿）都不拒绝
    /// Refused only when busy and queueing long: busy alone (a slow upstream, a socket not
    /// running empty) or queueing alone (a brief stall) refuses nothing
    #[test]
    fn a_query_is_refused_only_when_busy_and_behind() {
        let manager = Arc::new(PermitManager::new());
        let flow = state(Duration::from_secs(60));
        let busy = Instant::now() - LONG_AGO;

        let busy_alone = flow.permit(&manager, busy);
        assert!(busy_alone.is_some(), "busy alone");

        flow.note_queue_delay(Duration::from_secs(3600));
        let behind_alone = flow.permit(&manager, Instant::now());
        assert!(behind_alone.is_some(), "behind alone");
        assert_eq!(manager.dropped_requests(), 0);

        assert!(flow.permit(&manager, busy).is_none(), "both");
        assert_eq!(manager.dropped_requests(), 1);
        assert_eq!(manager.inflight(), 2, "a refused query holds no permit");
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
        let plenty = flow.permit_by_memory(&manager);
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
        assert!(flow.permit_by_memory(&manager).is_none());
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
                flow.permit(&manager, Instant::now())
                    .expect("few in flight")
            })
            .collect();
        in_flight.push(
            flow.permit(&manager, Instant::now())
                .expect("the last under the floor"),
        );
        assert_eq!(manager.dropped_requests(), 0);

        assert!(flow.permit(&manager, Instant::now()).is_none());
        assert_eq!(manager.dropped_requests(), 1);
        assert_eq!(manager.inflight(), 1000, "a refused query holds no permit");

        in_flight.truncate(999);
        assert!(
            flow.permit(&manager, Instant::now()).is_some(),
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
}
