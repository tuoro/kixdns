//! 隔一阵才记一条的告警。上游坏了、请求超时、收到伪造的回包这种每个查询或每个报文都可能碰上的事，逐个记会把日志刷满：
//! OpenWrt 的日志在内存盘上，上游不通时每秒几十个超时就是每小时十来 MB，伪造的回包则是攻击者想刷多少就刷多少。同一处
//! [`EVERY`] 之内只记第一条，下一条带上这期间没记的次数（`skipped`）：问题照样看得见，次数也不丢。说的是哪个上游的，
//! 每个上游各算各的（见 [`SparseBy`]），一直坏着的上游挡不住别的上游的失败。
//! Warnings logged once in a while. An upstream down, a request timing out, a forged reply arriving:
//! things every query or packet may run into fill the log when each is logged. On OpenWrt the log sits on a
//! RAM disk, a few tens of timeouts a second with an upstream unreachable make some ten MB an hour, and forged
//! replies make as much as an attacker cares to send. One place logs only the first within [`EVERY`], and the
//! next carries how many went unlogged meanwhile (`skipped`): the problem still shows, and nothing of the
//! count is lost. Where a warning names an upstream, each upstream counts on its own (see [`SparseBy`]), so
//! one that stays down keeps the failures of no other from showing.

use std::hash::{BuildHasher, Hash};
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

/// 一处按键分开的节流最多分几个键 / How many keys one place's throttle keeps apart at most
pub const KEYS: usize = 64;

/// 一处告警按键（比如上游）分开的节流：每个键各有一个 [`Sparse`]，一个键一直在记，别的键照样记得上。键按哈希记在一张
/// [`KEYS`] 格的表里，记下了就不再拿掉；表满了以后新来的键合用这一处自己的那一个，和不分键时一样
/// One place's throttle kept apart by key (an upstream, say): each key has a [`Sparse`] of its own, so
/// one key logging all the time leaves room for the others. Keys go by their hash into a table of
/// [`KEYS`] slots and stay once in; with the table full, keys coming later share the place's own,
/// as without keys
pub struct SparseBy {
    slots: [Slot; KEYS],
    rest: Sparse,
}

/// 表里的一格：键的哈希（0 是空着）和它的节流 / One slot of the table: the key's hash (0 while empty)
/// and its throttle
struct Slot {
    key: AtomicU64,
    sparse: Sparse,
}

impl SparseBy {
    pub const fn new() -> Self {
        Self {
            slots: [const {
                Slot {
                    key: AtomicU64::new(0),
                    sparse: Sparse::new(),
                }
            }; KEYS],
            rest: Sparse::new(),
        }
    }

    /// `key` 的告警现在该不该记，同 [`Sparse::due`] / Whether to log `key`'s warning now, as
    /// [`Sparse::due`]
    pub fn due<K: Hash + ?Sized>(&self, key: &K) -> Option<u64> {
        self.of(key).due()
    }

    #[cfg(test)]
    fn due_at<K: Hash + ?Sized>(&self, key: &K, now_ms: u64) -> Option<u64> {
        self.of(key).due_at(now_ms)
    }

    /// `key` 的节流：表里找它的那一格，没有就占一个空格，表满了是这一处自己的那一个。从哈希定下的格子往后挨个看，
    /// 格子不会空出来，碰到空格就说明表里没有它
    /// `key`'s throttle: its slot in the table, an empty one taken when it has none, or the place's own
    /// with the table full. The slots are looked at in turn from the one the hash picks, and since a
    /// slot never empties again, an empty one means the key is not in the table
    fn of<K: Hash + ?Sized>(&self, key: &K) -> &Sparse {
        let hash = rustc_hash::FxBuildHasher.hash_one(key);
        // 0 留给空格 / 0 is kept for an empty slot
        let tag = hash | 1;
        let first = hash as usize % KEYS;
        for slot in self.slots[first..].iter().chain(&self.slots[..first]) {
            // 先读：只有空格才去占（占上了就是自己的，没占上就是别人刚占的），找到自己那一格的不写各核共用的缓存行
            // Read first: only an empty slot is taken (its own once taken, or someone else's just
            // taken), and finding its own writes no cache line the cores share
            let taken = match slot.key.load(Ordering::Relaxed) {
                0 => slot
                    .key
                    .compare_exchange(0, tag, Ordering::Relaxed, Ordering::Relaxed)
                    .err()
                    .unwrap_or(tag),
                taken => taken,
            };
            if taken == tag {
                return &slot.sparse;
            }
        }
        &self.rest
    }
}

impl Default for SparseBy {
    fn default() -> Self {
        Self::new()
    }
}

/// 进程里第一次问起以来的毫秒数 / Milliseconds since this was first asked in the process
fn since_start() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64
}

/// 和 `tracing::warn!` 一样，只是同一处 [`EVERY`] 之内只记一条，带上这期间没记的次数 `skipped`（见 [`Sparse`]）。
/// 开头写上 `per 键;`（比如 `per upstream;`）就按键分开算（见 [`SparseBy`]）。warn 不记时什么都不做：不读钟，也不碰
/// 各核共用的计数。伪造回包这样由对方定频率的地方每个包都走这里
/// As `tracing::warn!`, except that one place logs once within [`EVERY`], with `skipped`, how many went
/// unlogged meanwhile (see [`Sparse`]). Led by `per key;` (`per upstream;`, say) it counts each key on
/// its own (see [`SparseBy`]). With warnings not logged it does nothing: no clock read, no touch of
/// the count every core shares. Places whose rate the other side sets, forged replies, come here on
/// every packet
#[macro_export]
macro_rules! warn_sparse {
    (per $key:expr; $($arg:tt)+) => {{
        static SPARSE: $crate::sparse_log::SparseBy = $crate::sparse_log::SparseBy::new();
        if ::tracing::enabled!(::tracing::Level::WARN)
            && let Some(skipped) = SPARSE.due(&$key)
        {
            ::tracing::warn!(skipped, $($arg)+);
        }
    }};
    ($($arg:tt)+) => {{
        static SPARSE: $crate::sparse_log::Sparse = $crate::sparse_log::Sparse::new();
        if ::tracing::enabled!(::tracing::Level::WARN)
            && let Some(skipped) = SPARSE.due()
        {
            ::tracing::warn!(skipped, $($arg)+);
        }
    }};
}

#[cfg(test)]
mod tests {
    use super::{EVERY, KEYS, Sparse, SparseBy};

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

    /// 按键分开时各键各算：一个键刚记过，别的键照样记得上；表满以后新来的键合用一个节流
    /// Kept apart by key, each key counts on its own: one having just logged, another still logs;
    /// with the table full, keys coming later share one throttle
    #[test]
    fn each_key_logs_on_its_own_and_keys_past_the_table_share_one() {
        let every = EVERY.as_millis() as u64;
        let sparse = SparseBy::new();
        assert_eq!(sparse.due_at("1.1.1.1:53", 5), Some(0));
        assert_eq!(sparse.due_at("1.1.1.1:53", 6), None);
        assert_eq!(sparse.due_at("8.8.8.8:53", 6), Some(0));
        assert_eq!(sparse.due_at("8.8.8.8:53", 7), None);
        for n in 2..KEYS {
            assert_eq!(sparse.due_at(&format!("upstream {n}"), 7), Some(0), "{n}");
        }
        assert_eq!(sparse.due_at("one more", 8), Some(0));
        assert_eq!(sparse.due_at("and another", 8), None);
        assert_eq!(sparse.due_at("1.1.1.1:53", 5 + every), Some(1));
    }
}
