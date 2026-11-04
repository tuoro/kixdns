use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// 动态信号量调整的自适应流控状态 / Adaptive flow control state for dynamic semaphore adjustment
pub struct FlowControlState {
    pub max_permits: AtomicUsize,
    pub min_permits: usize,
    /// 自UNIX_EPOCH以来的最后调整时间戳（毫秒） / Last adjustment timestamp in milliseconds since UNIX_EPOCH
    /// 时钟回滚通过 adjust_flow_control 中的 saturating_sub 处理 / Clock rollback is handled by saturating_sub in adjust_flow_control
    pub last_adjustment_ms: AtomicU64,
    /// socket 连续这么久没收空就算忙 / How long a socket goes without running empty before that counts as busy
    pub busy_after: Duration,
    pub adjustment_interval_ms: u64,
}

impl FlowControlState {
    /// 内核忙不忙，`emptied_at` 是 socket 上次收空的时刻。内核跟不上，socket 才会一直收不空；上游慢不算，
    /// 那时查询都在等上游，socket 照样收得空
    /// Whether the kernel is busy, `emptied_at` being when the socket last ran empty. Only a kernel falling
    /// behind leaves a socket never running empty; a slow upstream does not count, as the queries then wait
    /// on it and the socket still runs empty
    #[inline]
    pub fn busy(&self, emptied_at: Instant) -> bool {
        emptied_at.elapsed() >= self.busy_after
    }

    /// 忙的时候收紧上限，不忙的时候放宽 / Tightens the limit while busy and loosens it otherwise
    pub fn adjust(&self, permit_manager: &PermitManager, busy: bool) {
        // Get current time in milliseconds
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        // Use compare_exchange_weak in a loop for lock-free synchronization
        // saturating_sub handles clock rollback: if now < last, result is 0, we skip
        let mut last_ms = self.last_adjustment_ms.load(Ordering::Acquire);
        loop {
            // Check if adjustment interval has passed
            if now_ms.saturating_sub(last_ms) < self.adjustment_interval_ms {
                return;
            }

            // Try to update timestamp - only one thread will succeed
            match self.last_adjustment_ms.compare_exchange_weak(
                last_ms,
                now_ms,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => break, // Successfully acquired adjustment right
                Err(current) => {
                    // Another thread updated timestamp, reload and recheck
                    last_ms = current;
                    continue;
                }
            }
        }

        let inflight = permit_manager.inflight();
        let current_permits = permit_manager.max_permits();
        let dropped = permit_manager.dropped_requests();

        // Log permit pool health periodically / 定期记录permit pool健康状况
        if dropped > 0 {
            tracing::warn!(
                inflight = inflight,
                max = current_permits,
                dropped_total = dropped,
                "Permit pool health status"
            );
        }

        // Log when the permit pool is full, at most once a minute / permit 池满了就记一条，每分钟最多一次
        permit_manager.check_and_recover();

        if busy && current_permits > self.min_permits {
            let new_permits = (current_permits * 9 / 10).max(self.min_permits);
            permit_manager.set_max_permits(new_permits);
            tracing::info!(
                event = "flow_control_reduce",
                current_permits = current_permits,
                new_permits = new_permits,
                inflight = inflight,
                dropped = dropped,
                "reducing permits while busy"
            );
        } else if !busy && current_permits < self.max_permits.load(Ordering::Relaxed) {
            let new_permits =
                (current_permits * 11 / 10).min(self.max_permits.load(Ordering::Relaxed));
            permit_manager.set_max_permits(new_permits);
            tracing::info!(
                event = "flow_control_increase",
                current_permits = current_permits,
                new_permits = new_permits,
                inflight = inflight,
                dropped = dropped,
                "increasing permits while not busy"
            );
        }
    }
}

/// 动态流控的 Permit 管理器 / Permit manager for dynamic flow control feedback
pub struct PermitManager {
    // Current active permits (acquired) / 当前活跃 permits（已获得）
    pub(crate) active_permits: AtomicUsize,
    // Maximum permits that can be granted / 可授予的最大 permits
    max_permits: AtomicUsize,
    // Last recovery timestamp (ms) / 上次恢复时间戳（毫秒）
    last_recovery_ms: AtomicU64,
    // Count of dropped requests due to pool exhaustion / 因pool耗尽而丢弃的请求计数
    dropped_requests: AtomicU64,
}

impl PermitManager {
    pub fn new(initial_permits: usize) -> Self {
        Self {
            active_permits: AtomicUsize::new(0),
            max_permits: AtomicUsize::new(initial_permits),
            last_recovery_ms: AtomicU64::new(0),
            dropped_requests: AtomicU64::new(0),
        }
    }

    /// 创建一个无限制的PermitManager（用于rustdns风格的无流控模式）
    /// Create an unlimited PermitManager (for rustdns-style no-flow-control mode)
    pub fn new_unlimited() -> Self {
        Self {
            active_permits: AtomicUsize::new(0),
            max_permits: AtomicUsize::new(usize::MAX),
            last_recovery_ms: AtomicU64::new(0),
            dropped_requests: AtomicU64::new(0),
        }
    }

    /// 不看上限拿一个 permit：不忙的时候不拒绝查询，只记着有多少在处理
    /// Takes a permit whatever the limit: while not busy no query is refused, and this only counts how many are
    /// being handled
    pub fn acquire(self: &Arc<Self>) -> PermitGuard {
        self.active_permits.fetch_add(1, Ordering::Release);
        PermitGuard::new(Arc::clone(self))
    }

    /// Try to acquire a permit without blocking / 非阻塞地尝试获取 permit
    /// Returns a guard that holds Arc<PermitManager> to ensure permit is released
    ///
    /// Uses a post-CAS validation to handle the TOCTOU window where max_permits
    /// may shrink between the initial load and the successful CAS.
    /// 使用 CAS 后验证来处理 max_permits 在初始读取和 CAS 成功之间缩小的 TOCTOU 窗口。
    pub fn try_acquire(self: &Arc<Self>) -> Option<PermitGuard> {
        loop {
            let active = self.active_permits.load(Ordering::Acquire);
            let max = self.max_permits.load(Ordering::Acquire);

            if active >= max {
                // Pool exhausted: increment counter and log / Pool耗尽：增加计数器并记录
                let dropped = self.dropped_requests.fetch_add(1, Ordering::Relaxed);

                // Log every 1000 dropped requests to avoid spam / 每1000个丢弃请求记录一次，避免刷屏
                if dropped.is_multiple_of(1000) {
                    tracing::warn!(
                        active = active,
                        max = max,
                        dropped_total = dropped + 1,
                        "UDP permit pool exhausted, requests are being dropped"
                    );

                    // Trigger recovery check if pool is exhausted / 如果pool耗尽，触发恢复检查
                    self.check_and_recover();
                }
                return None;
            }

            match self.active_permits.compare_exchange(
                active,
                active + 1,
                Ordering::Release,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    // Post-CAS validation: max_permits may have shrunk concurrently
                    // via set_max_permits(). If we now exceed the new limit, roll back.
                    // CAS后验证：max_permits 可能已通过 set_max_permits() 缩小，
                    // 如果超出新限制则回滚。
                    let current_max = self.max_permits.load(Ordering::Acquire);
                    if active + 1 > current_max {
                        // Exceeded new limit — return the permit and report exhaustion
                        self.active_permits.fetch_sub(1, Ordering::Release);
                        let dropped = self.dropped_requests.fetch_add(1, Ordering::Relaxed);
                        if dropped.is_multiple_of(1000) {
                            tracing::warn!(
                                active = active,
                                new_max = current_max,
                                dropped_total = dropped + 1,
                                "Permit acquired but max shrunk concurrently, rolling back"
                            );
                        }
                        return None;
                    }
                    return Some(PermitGuard::new(Arc::clone(self)));
                }
                Err(_) => continue, // Retry on CAS failure / CAS 失败时重试
            }
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

    /// Update max permits for dynamic adjustment / 更新最大 permits 用于动态调整
    #[inline]
    pub fn set_max_permits(&self, new_max: usize) {
        self.max_permits.store(new_max, Ordering::Release);
    }

    /// Get current max permits / 获取当前最大 permits
    #[inline]
    pub fn max_permits(&self) -> usize {
        self.max_permits.load(Ordering::Acquire)
    }

    /// Get total dropped requests count / 获取总丢弃请求数
    #[inline]
    pub fn dropped_requests(&self) -> u64 {
        self.dropped_requests.load(Ordering::Relaxed)
    }

    /// Log pool saturation, at most once per minute. Called from the periodic
    /// flow-control adjustment and when an acquire is refused.
    ///
    /// This used to also "recover from leakage" by forcing `active_permits`
    /// down to `max_permits` whenever it exceeded it. That state is not a leak:
    /// the counter only moves through `try_acquire` and `PermitGuard`, which
    /// release exactly once, so a guard that is never dropped keeps `active`
    /// at or below `max`, never above it. `active > max` only arises when
    /// `set_max_permits` lowers the limit under live guards, and clamping the
    /// counter there made their later releases underflow it, after which every
    /// acquire was refused for good.
    /// 记录池饱和，每分钟最多一次。由周期性流控调整和 acquire 被拒时调用。
    ///
    /// 这里原本还会在 active 超过 max 时把 active 强行压到 max 来"恢复泄漏"。那不是
    /// 泄漏：计数只经由 try_acquire 和恰好释放一次的 PermitGuard 变化，永不释放的
    /// guard 只会让 active 停在 ≤ max，不会超过 max。active > max 只在
    /// set_max_permits 于在途 guard 之下调低上限时出现，此时压低计数会让这些 guard
    /// 之后的释放把计数减到下溢，从此所有 acquire 都被拒绝。
    pub fn check_and_recover(&self) {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let last_ms = self.last_recovery_ms.load(Ordering::Relaxed);

        // At most once per minute / 每分钟最多一次
        if now_ms.saturating_sub(last_ms) < 60_000 {
            return;
        }

        // Try to update the timestamp; whoever wins reports / 尝试更新时间戳，赢者上报
        if self
            .last_recovery_ms
            .compare_exchange_weak(last_ms, now_ms, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        let active = self.active_permits.load(Ordering::Acquire);
        let max = self.max_permits.load(Ordering::Acquire);
        if active >= max {
            let dropped = self.dropped_requests.load(Ordering::Relaxed);
            tracing::warn!(
                active = active,
                max = max,
                dropped_total = dropped,
                "Permit pool is at capacity, consider increasing max_permits or checking upstream health"
            );
        }
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

    fn state(min: usize, max: usize, busy_after: Duration) -> FlowControlState {
        FlowControlState {
            max_permits: AtomicUsize::new(max),
            min_permits: min,
            last_adjustment_ms: AtomicU64::new(0),
            busy_after,
            adjustment_interval_ms: 0,
        }
    }

    /// 从上次收空算起够久了才算忙；阈值是 0 时一直算忙
    /// Busy only once long enough has passed since the socket last ran empty; with a threshold of 0, always
    #[test]
    fn busy_is_judged_from_when_the_socket_last_ran_empty() {
        let state = state(1, 1, Duration::from_secs(60));
        assert!(!state.busy(Instant::now()));
        assert!(state.busy(Instant::now() - Duration::from_secs(61)));

        let always = super::tests::state(1, 1, Duration::ZERO);
        assert!(always.busy(Instant::now()));
    }

    /// 忙的时候每次收紧一成，到最少为止；不忙的时候每次放宽一成，到最多为止，有多少在处理都一样
    /// While busy each step tightens by a tenth down to the minimum; while not busy each loosens by a tenth up
    /// to the maximum, however many are being handled
    #[test]
    fn the_limit_tightens_only_while_busy() {
        let state = state(100, 800, Duration::from_millis(100));
        let manager = Arc::new(PermitManager::new(500));
        let step = |busy, expected| {
            state.last_adjustment_ms.store(0, Ordering::Relaxed);
            state.adjust(&manager, busy);
            assert_eq!(manager.max_permits(), expected);
        };
        step(true, 450);
        step(false, 495);

        // 在处理的比上限还多也一样放宽：等上游的查询不算内核忙
        // Loosens even with more being handled than the limit: queries waiting on an upstream are no business
        let waiting: Vec<_> = (0..600).map(|_| manager.acquire()).collect();
        step(false, 544);
        drop(waiting);

        manager.set_max_permits(105);
        step(true, 100);
        step(true, 100);
        manager.set_max_permits(790);
        step(false, 800);
        step(false, 800);
    }

    /// 超过上限拿的 permit 也记着，还回来以后计数归零 / A permit taken past the limit is counted too, and the count returns to zero
    #[test]
    fn a_permit_past_the_limit_is_counted_and_released() {
        let manager = Arc::new(PermitManager::new(1));
        let within = manager.try_acquire().expect("within the limit");
        let past = manager.acquire();
        assert_eq!(manager.inflight(), 2);
        assert!(manager.try_acquire().is_none(), "the limit still stands");
        drop(within);
        assert_eq!(manager.inflight(), 1);
        drop(past);
        assert_eq!(manager.inflight(), 0);
    }

    #[test]
    fn shrinking_max_below_inflight_does_not_corrupt_the_counter() {
        // Flow control lowering max_permits while guards are live is the normal
        // way active can exceed max; it is not a leak. Once those guards drop
        // the pool must be empty and usable again.
        // 流控在有在途 guard 时调低 max_permits 是 active 超过 max 的正常途径，不是
        // 泄漏。这些 guard 释放后，池必须回到空闲且可用。
        let manager = Arc::new(PermitManager::new(100));
        let guards: Vec<_> = (0..60)
            .map(|_| manager.try_acquire().expect("permit within limit"))
            .collect();
        manager.set_max_permits(59);
        // The periodic health hook runs unconditionally from adjust().
        manager.check_and_recover();
        drop(guards);

        assert_eq!(
            manager.inflight(),
            0,
            "every released permit must be counted back"
        );
        manager.set_max_permits(100);
        assert!(
            manager.try_acquire().is_some(),
            "pool must accept requests again after the guards are gone"
        );
    }
}
