//! 隔一阵才记一条的告警。上游坏了、请求超时、收到伪造的回包这种每个查询或每个报文都可能碰上的事，逐个记会把日志刷满：
//! OpenWrt 的日志在内存盘上，上游不通时每秒几十个超时就是每小时十来 MB，伪造的回包则是攻击者想刷多少就刷多少。同一处
//! [`EVERY`] 之内只记第一条，下一条带上这期间没记的次数（`skipped`）：问题照样看得见，次数也不丢。
//! Warnings logged once in a while. An upstream down, a request timing out, a forged reply arriving:
//! things every query or packet may run into fill the log when each is logged. On OpenWrt the log sits on a
//! RAM disk, a few tens of timeouts a second with an upstream unreachable make some ten MB an hour, and forged
//! replies make as much as an attacker cares to send. One place logs only the first within [`EVERY`], and the
//! next carries how many went unlogged meanwhile (`skipped`): the problem still shows, and nothing of the
//! count is lost.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// 同一处两条告警至少隔这么久 / How far apart at least two warnings of one place are
pub const EVERY: Duration = Duration::from_secs(10);

/// 一处告警的节流：下一条什么时候能记，这期间没记的有几次 / The throttle of one place's warnings: when
/// the next may be logged, and how many went unlogged meanwhile
pub struct Sparse {
    /// 下一条能记的时刻，从 [`since_start`] 的起点算的毫秒数 / When the next may be logged, in milliseconds
    /// from the start of [`since_start`]
    next_ms: AtomicU64,
    skipped: AtomicU64,
}

impl Sparse {
    pub const fn new() -> Self {
        Self {
            next_ms: AtomicU64::new(0),
            skipped: AtomicU64::new(0),
        }
    }

    /// 现在该不该记：该记时给出上一条以来没记的次数 / Whether to log now: when so, how many went unlogged
    /// since the last one
    pub fn due(&self) -> Option<u64> {
        // 单元测试各数各的告警：同一进程里别的测试刚在同一处记过一条，不能把这一条挡掉。节流本身见 `due_at` 的测试
        // Unit tests count warnings of their own: another test in the process having just logged
        // at the same place must not keep this one out. The throttling itself is tested by `due_at`
        if cfg!(test) {
            return Some(0);
        }
        self.due_at(since_start())
    }

    fn due_at(&self, now_ms: u64) -> Option<u64> {
        let next = self.next_ms.load(Ordering::Relaxed);
        let every = EVERY.as_millis() as u64;
        if now_ms < next
            || self
                .next_ms
                .compare_exchange(next, now_ms + every, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
        {
            self.skipped.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        Some(self.skipped.swap(0, Ordering::Relaxed))
    }
}

impl Default for Sparse {
    fn default() -> Self {
        Self::new()
    }
}

/// 进程里第一次问起以来的毫秒数 / Milliseconds since this was first asked in the process
fn since_start() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64
}

/// 和 `tracing::warn!` 一样，只是同一处 [`EVERY`] 之内只记一条，带上这期间没记的次数 `skipped`（见 [`Sparse`]）
/// As `tracing::warn!`, except that one place logs once within [`EVERY`], with `skipped`, how many went
/// unlogged meanwhile (see [`Sparse`])
#[macro_export]
macro_rules! warn_sparse {
    ($($arg:tt)+) => {{
        static SPARSE: $crate::sparse_log::Sparse = $crate::sparse_log::Sparse::new();
        if let Some(skipped) = SPARSE.due() {
            ::tracing::warn!(skipped, $($arg)+);
        }
    }};
}

#[cfg(test)]
mod tests {
    use super::{EVERY, Sparse};

    /// 第一条照记；之后 EVERY 之内的都不记，只数着；过了 EVERY 的下一条带上数到的次数，数从头再来
    /// The first is logged; those within EVERY after it are not, only counted; the next one past EVERY
    /// carries the count, which starts over
    #[test]
    fn one_place_logs_once_in_a_while_with_the_count_skipped() {
        let every = EVERY.as_millis() as u64;
        let sparse = Sparse::new();
        assert_eq!(sparse.due_at(5), Some(0));
        assert_eq!(sparse.due_at(6), None);
        assert_eq!(sparse.due_at(5 + every - 1), None);
        assert_eq!(sparse.due_at(5 + every), Some(2));
        assert_eq!(sparse.due_at(5 + every + 1), None);
        assert_eq!(sparse.due_at(5 + 3 * every), Some(1));
    }
}
