use std::hash::{BuildHasher, RandomState};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use super::fair_queue::Device;
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

/// 流控的状态。不用填数字，判断都来自运行时测到的：socket 收不收得空、查询排队多久、还剩多少内存
/// The state of flow control. There are no numbers to fill in: it goes by what is measured at
/// run time, namely whether a socket runs empty, how long queries queue and how much memory is left
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

    /// `device` 的一个要等上游的查询能不能处理，`emptied_at` 是 socket 上次收空的时刻。内存不够时拒绝
    /// （见 [`Self::memory_refuses`]）；内核忙而且查询在内核里排着长队时，拒绝在途不比各设备平均少的设备，
    /// 发得少的照常。那时每个查询都要先排同样长的队，在途多少就是发得多快；不分设备地拒，发得少的设备也
    /// 跟着丢，直到开始按设备轮流。等上游不算排队，所以上游再慢，这样的查询也不会被拒绝
    /// Whether a query from `device` that waits on an upstream can go ahead, `emptied_at` being
    /// when the socket last ran empty. Too little memory refuses it (see [`Self::memory_refuses`]),
    /// and with the kernel busy and queries queueing long inside it a device holding no less in
    /// flight than the average is refused while those sending little go on. Every query then
    /// waits in the same long line first, so what a device holds in flight is how fast it sends;
    /// refusing whatever comes would lose the devices sending little too, until devices take
    /// turns. Waiting on an upstream is not queueing, so however slow the upstream, such queries
    /// are not refused
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

    /// 内存够不够 `device` 再接一个：没了谁都不接；紧张时，在途的不比各设备平均少的设备不接，发得少的
    /// 照常——一台设备把内存占满时先拦住它，别的设备不受连累
    /// Whether memory refuses one more for `device`: with none left everyone is refused; when it
    /// is tight, a device holding no less in flight than the average across devices is refused and
    /// those sending little go on, so a device filling the memory is stopped first and the others
    /// are not held up with it
    #[inline]
    fn memory_refuses(&self, manager: &PermitManager, device: DeviceSlot) -> bool {
        match self.memory.room(manager.inflight()) {
            Room::Plenty => false,
            Room::Tight => manager.queries.holds_its_share(device),
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

    /// 按设备轮流时 `device` 的一个要等上游的查询能不能处理：看内存；这台设备后面还排着别的（`more_queued`）、在途又不比
    /// 各设备平均少时也拒绝——和忙而且排长队时同一条规则。轮流挡住的是排队，挡不住在途：对着不回答的域名洪泛的设备，
    /// 只看内存的话在途一直涨到内存水位，这些查询还都转发给了上游
    /// Whether a query from `device` that waits on an upstream can go ahead while devices take
    /// turns: by memory, and a device with more queued behind it (`more_queued`) holding no less
    /// in flight than the average is refused as well, the same rule as when busy and queueing
    /// long. Taking turns holds the queueing, not what is in flight: a device flooding names that
    /// get no answer would, by memory alone, pile up in flight until the memory watermark, every
    /// one of those queries forwarded upstream too
    #[inline]
    pub fn turn_permit(
        &self,
        manager: &Arc<PermitManager>,
        device: DeviceSlot,
        more_queued: bool,
    ) -> Option<PermitGuard> {
        if self.memory_refuses(manager, device)
            || (more_queued && manager.queries.holds_its_share(device))
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

    /// `device` 的一条 TCP 或 DoH 新连接接不接：和查询一样只看内存，紧张时开着的连接或在途的查询有一样不比各设备平均少，
    /// 就不接——占着内存的设备开新连接，连接上的查询反正也要被拒。连接和查询各比各的：只开着一条空闲连接不算占了查询的
    /// 份，开着很多连接的设备（比如 DoH 前面的反向代理）也不把查询的平均拉高
    /// Whether a new TCP or DoH connection from `device` is taken: by memory alone, as for a
    /// query, and when tight a device holding no fewer open connections, or no fewer queries in
    /// flight, than the average gets none: a device holding the memory would have the queries on
    /// a new connection refused anyway. Connections and queries are each compared with their own
    /// kind: one idle connection is no share of queries, and a device holding many connections (a
    /// reverse proxy in front of DoH, say) does not raise the average of queries
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
                    || manager.queries.holds_its_share(device)
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

/// 按设备记在途数的份数：设备按哈希落到其中一份，哈希每次启动都不同，同一份的设备一起算一台
/// How many slots the in-flight counts per device are kept in: a device lands in one by a hash
/// that differs at each start, and devices in the same slot count as one
const DEVICE_SLOTS: usize = 1024;

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
        Self {
            per_slot: (0..DEVICE_SLOTS).map(|_| AtomicU32::new(0)).collect(),
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
    /// 一台在刷的设备被拒以后在途的很快就走光，这时都算的话发得少的也跟着被拒，拒得越管用越分不出是谁在刷
    /// Whether `device` holds no less in flight than the average across devices: a lone one in
    /// flight does; one with nothing in flight does not, also with nothing in flight anywhere. A
    /// device flooding has its queries in flight run out soon once refused, and counting everyone
    /// then would refuse those sending little along with it: the better the refusing works, the
    /// less it could tell who floods
    fn holds_its_share(&self, device: DeviceSlot) -> bool {
        let own = self.per_slot[usize::from(device.0)].load(Ordering::Relaxed) as usize;
        let slots = self.slots_held.load(Ordering::Relaxed).max(1);
        own > 0 && own.saturating_mul(slots) >= self.total.load(Ordering::Relaxed)
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
            hasher: RandomState::new(),
        }
    }

    /// 拿一个 permit：这里不拒绝，只记着有多少在处理 / Takes a permit: nothing is refused here, this only counts what is being handled
    pub fn acquire(self: &Arc<Self>) -> PermitGuard {
        self.active_permits.fetch_add(1, Ordering::Release);
        PermitGuard::new(Arc::clone(self), None)
    }

    /// 给 `device` 的一个查询拿 permit，也记在它那一份上 / Takes a permit for a query of `device`, counted in its slot as well
    pub fn acquire_for(self: &Arc<Self>, device: DeviceSlot) -> PermitGuard {
        self.active_permits.fetch_add(1, Ordering::Release);
        self.queries.add(device);
        PermitGuard::new(Arc::clone(self), Some((device, Held::Query)))
    }

    /// 给 `device` 的一条连接拿 permit，也记在它那一份的连接上 / Takes a permit for a connection of
    /// `device`, counted among its slot's connections as well
    pub fn acquire_connection_for(self: &Arc<Self>, device: DeviceSlot) -> PermitGuard {
        self.active_permits.fetch_add(1, Ordering::Release);
        self.connections.add(device);
        PermitGuard::new(Arc::clone(self), Some((device, Held::Connection)))
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
    /// 记在哪台设备的那一份、哪一种上（开了流控时）/ The device slot and kind it is counted in (with flow control on)
    device: Option<(DeviceSlot, Held)>,
    released: AtomicBool, // Track if already released to handle double-drop / 跟踪是否已释放以处理双重释放
}

impl PermitGuard {
    fn new(manager: Arc<PermitManager>, device: Option<(DeviceSlot, Held)>) -> Self {
        Self {
            manager,
            device,
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
        let connections: Vec<_> = (0..DEVICE_SLOTS as u16)
            .map(|n| {
                flow.connection_permit(&manager, DeviceSlot(n))
                    .expect("a device with no connection connects")
            })
            .collect();
        assert!(manager.inflight() >= 1000, "memory is read");
        for n in [0, 1, 500, DEVICE_SLOTS as u16 - 1] {
            assert!(
                flow.permit_by_memory(&manager, DeviceSlot(n)).is_some(),
                "a query on the connection of {n}"
            );
            assert!(
                flow.permit(&manager, Instant::now(), DeviceSlot(n))
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
        assert!(tight.permit(&manager, Instant::now(), ONE).is_none());
        assert!(tight.permit(&manager, Instant::now(), OTHER).is_none());

        let full = with_memory_left(1 << 20);
        assert!(
            full.permit(&manager, Instant::now(), DeviceSlot(2))
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
