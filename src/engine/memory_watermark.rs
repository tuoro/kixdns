//! 流控的内存水位：在途查询多到可能撑爆内存时，看这台机器还剩多少内存，不够了就拒绝新的未命中查询，
//! 够了自动恢复。不填数字：每台机器读自己的内存（系统的，以及所在 cgroup 的限制）。
//! 在途查询没到 [`LOOK_FROM_INFLIGHT`] 时不读内存，也不拒绝：日常路径没有开销，其他程序吃内存也不会
//! 牵连日常查询。之后按 [`reads_apart`] 隔一段读一次，两次之间多占的内存和总量成比例，和 CPU 快慢无关。
//!
//! Flow control's memory watermark: once enough queries are in flight to threaten the
//! memory, it looks at how much memory this machine has left, refuses new cache misses
//! when too little remains, and resumes by itself. There is no number to fill in: each
//! machine reads its own memory (the system's and any limit of its cgroups).
//! Under [`LOOK_FROM_INFLIGHT`] queries in flight it neither reads nor refuses: the daily
//! path pays nothing, and other programs using memory do not hold up daily queries. After
//! that it reads every [`reads_apart`], which keeps what is added between two reads in
//! proportion to the total, whatever the CPU's speed.

use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};

/// 在途查询到这么多才开始看内存 / The queries in flight from which memory is looked at
const LOOK_FROM_INFLIGHT: usize = 1000;
/// 还不知道总量时隔多少个读一次 / How many apart reads are while the total is unknown
const READS_APART_UNKNOWN: usize = 10_000;
/// 余量：总量的十六分之一，最多这么多字节。机器再大也不必留更多，否则别的程序占着内存时会误伤
/// The margin: a sixteenth of the total, at most this many bytes. A larger machine needs no
/// more, and leaving more would refuse queries just because other programs hold memory
const MAX_MARGIN: u64 = 256 << 20;

/// 一处内存限制：一共多少、还剩多少字节 / One memory limit: its total and what is left, in bytes
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryLeft {
    pub total: u64,
    pub available: u64,
}

/// 隔多少个未命中或新连接读一次内存：两次之间多占的不超过总量的 1/32。一个按 12 KB 算，这是这个程序
/// 自己的开销，和机器无关；只用来定读的频率，不用来判断够不够。
/// How many misses or new connections apart memory is read: at most a thirty-second of the
/// total is added between two reads. Each counts as 12 KB, a cost of this program and not of
/// the machine, used only to pace the reads and not to judge what is enough.
fn reads_apart(total: u64) -> usize {
    (total / 32 / (12 << 10)).clamp(100, READS_APART_UNKNOWN as u64) as usize
}

impl MemoryLeft {
    /// 这个进程占着 `own` 字节时，这里剩的够不够。不再接新查询之后，在途查询进入超时阶段还会多占
    /// 一成多，所以要留出自身占用的四分之一，再加一点余量
    /// Whether what is left here is too little with this process holding `own` bytes. After new
    /// queries stop, those in flight still grow by over a tenth as they reach their timeouts,
    /// so a quarter of its own use is kept back, plus a margin
    fn is_low(self, own: u64) -> bool {
        self.available < own / 4 + (self.total / 16).min(MAX_MARGIN)
    }
}

/// 读一次内存的结果 / What one reading of the memory gives
#[derive(Debug, Default)]
pub struct MemoryReading {
    /// 这个进程占着多少字节 / The bytes this process holds
    pub own: u64,
    /// 所有内存限制，空的表示读不到 / Every memory limit, empty when they cannot be read
    pub limits: Vec<MemoryLeft>,
}

/// 见模块说明 / See the module's description
pub struct MemoryWatermark {
    read: Box<dyn Fn() -> MemoryReading + Send + Sync>,
    until_read: AtomicIsize,
    low: AtomicBool,
}

impl MemoryWatermark {
    /// 读这台机器的内存；读不到就不起作用，只记一条警告
    /// Reads this machine's memory; when that cannot be read it does nothing but warn once
    pub fn of_this_machine() -> Self {
        let read = system::reader();
        if read().limits.is_empty() {
            tracing::warn!(
                event = "flow_control_memory_unknown",
                "cannot read this machine's memory: flow control will not refuse queries by memory"
            );
        }
        Self::reading(read)
    }

    pub fn reading(read: impl Fn() -> MemoryReading + Send + Sync + 'static) -> Self {
        Self {
            read: Box::new(read),
            until_read: AtomicIsize::new(1),
            low: AtomicBool::new(false),
        }
    }

    /// 在途 `inflight` 个查询时，能不能再接一个未命中 / Whether one more miss can go ahead with `inflight` in flight
    #[inline]
    pub fn has_room(&self, inflight: usize) -> bool {
        inflight < LOOK_FROM_INFLIGHT || self.looked_at()
    }

    fn looked_at(&self) -> bool {
        if self.until_read.fetch_sub(1, Ordering::Relaxed) <= 1 {
            let reading = (self.read)();
            let apart = reading
                .limits
                .iter()
                .map(|limit| reads_apart(limit.total))
                .min();
            self.until_read.store(
                apart.unwrap_or(READS_APART_UNKNOWN) as isize,
                Ordering::Relaxed,
            );
            let low = reading.limits.iter().any(|limit| limit.is_low(reading.own));
            if self.low.swap(low, Ordering::Relaxed) != low {
                tracing::warn!(
                    event = "flow_control_memory",
                    low,
                    ?reading,
                    "memory watermark crossed"
                );
            }
        }
        !self.low.load(Ordering::Relaxed)
    }
}

#[cfg(target_os = "linux")]
mod system {
    use super::{MemoryLeft, MemoryReading};
    use std::path::{Path, PathBuf};

    /// 不把这么大的 cgroup v1 限制当限制：它表示没设 / A cgroup v1 limit this large means none is set
    const NO_V1_LIMIT: u64 = 1 << 62;

    #[derive(Debug, PartialEq, Eq)]
    pub(super) enum Cgroup {
        V2(PathBuf),
        V1(PathBuf),
    }

    pub(super) fn reader() -> Box<dyn Fn() -> MemoryReading + Send + Sync> {
        let cgroups = std::fs::read_to_string("/proc/self/cgroup")
            .map(|text| {
                limited_cgroups(
                    &text,
                    Path::new("/sys/fs/cgroup"),
                    Path::new("/sys/fs/cgroup/memory"),
                )
            })
            .unwrap_or_default();
        Box::new(move || MemoryReading {
            own: std::fs::read_to_string("/proc/self/statm")
                .ok()
                .and_then(|text| resident_bytes(&text))
                .unwrap_or(0),
            limits: std::fs::read_to_string("/proc/meminfo")
                .ok()
                .and_then(|text| parse_meminfo(&text))
                .into_iter()
                .chain(cgroups.iter().filter_map(left_in))
                .collect(),
        })
    }

    /// `/proc/self/statm` 的第二个数是驻留的页数 / The second number of `/proc/self/statm` is the resident pages
    fn resident_bytes(statm: &str) -> Option<u64> {
        let pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
        // SAFETY: sysconf only reads a system setting / sysconf 只读一个系统设置
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        Some(pages.saturating_mul(u64::try_from(page_size).ok()?))
    }

    pub(super) fn parse_meminfo(text: &str) -> Option<MemoryLeft> {
        let kib = |key: &str| -> Option<u64> {
            let rest = text.lines().find_map(|line| line.strip_prefix(key))?;
            rest.trim_start_matches(':')
                .split_whitespace()
                .next()?
                .parse::<u64>()
                .ok()
        };
        Some(MemoryLeft {
            total: kib("MemTotal")?.saturating_mul(1024),
            available: kib("MemAvailable")?.saturating_mul(1024),
        })
    }

    /// 这个进程所在的、设了内存限制的 cgroup，连同各级上级：哪一级的限制都可能先到
    /// The cgroups of this process with a memory limit, its ancestors included, as any level's limit may be reached first
    pub(super) fn limited_cgroups(
        proc_cgroup: &str,
        v2_root: &Path,
        v1_root: &Path,
    ) -> Vec<Cgroup> {
        let mut limited = Vec::new();
        for line in proc_cgroup.lines() {
            let mut fields = line.splitn(3, ':');
            let (Some(_), Some(controllers), Some(path)) =
                (fields.next(), fields.next(), fields.next())
            else {
                continue;
            };
            let relative = path.trim_start_matches('/');
            if controllers.is_empty() {
                walk_up(v2_root, relative, &mut limited, |dir| {
                    read_u64(&dir.join("memory.max")).map(|_| Cgroup::V2(dir.to_path_buf()))
                });
            } else if controllers.split(',').any(|name| name == "memory") {
                walk_up(v1_root, relative, &mut limited, |dir| {
                    read_u64(&dir.join("memory.limit_in_bytes"))
                        .filter(|&limit| limit < NO_V1_LIMIT)
                        .map(|_| Cgroup::V1(dir.to_path_buf()))
                });
            }
        }
        limited
    }

    fn walk_up(
        root: &Path,
        relative: &str,
        limited: &mut Vec<Cgroup>,
        limit_at: impl Fn(&Path) -> Option<Cgroup>,
    ) {
        let start = root.join(relative);
        for dir in start.ancestors() {
            limited.extend(limit_at(dir));
            if dir == root {
                break;
            }
        }
    }

    fn left_in(cgroup: &Cgroup) -> Option<MemoryLeft> {
        let (dir, limit, usage, reclaimable) = match cgroup {
            Cgroup::V2(dir) => (dir, "memory.max", "memory.current", "inactive_file"),
            Cgroup::V1(dir) => (
                dir,
                "memory.limit_in_bytes",
                "memory.usage_in_bytes",
                "total_inactive_file",
            ),
        };
        let total = read_u64(&dir.join(limit))?;
        let used = read_u64(&dir.join(usage))?;
        // 文件缓存不够时会回收，不算占用 / File cache is given back when memory runs short, so it does not count as used
        let cache = std::fs::read_to_string(dir.join("memory.stat"))
            .ok()
            .and_then(|stat| {
                stat.lines().find_map(|line| {
                    let (key, value) = line.split_once(' ')?;
                    (key == reclaimable).then(|| value.parse::<u64>().ok())?
                })
            })
            .unwrap_or(0);
        Some(MemoryLeft {
            total,
            available: total.saturating_sub(used.saturating_sub(cache)),
        })
    }

    /// 文件里的数；`max` 这样不是数的就是没设限制 / The number in a file; `max` and the like mean no limit is set
    fn read_u64(path: &Path) -> Option<u64> {
        std::fs::read_to_string(path).ok()?.trim().parse().ok()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn in_dir(dir: &Path, files: &[(&str, &str)]) {
            std::fs::create_dir_all(dir).unwrap();
            for (name, text) in files {
                std::fs::write(dir.join(name), text).unwrap();
            }
        }

        #[test]
        fn its_own_use_is_the_resident_pages() {
            let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
            assert_eq!(resident_bytes("100 7 3 1 0 2 0\n"), Some(7 * page));
            assert_eq!(resident_bytes("100\n"), None);
        }

        #[test]
        fn the_system_limit_comes_from_meminfo() {
            let text = "MemTotal:       16000 kB\nMemFree:  10 kB\nMemAvailable:    8000 kB\n";
            assert_eq!(
                parse_meminfo(text),
                Some(MemoryLeft {
                    total: 16000 * 1024,
                    available: 8000 * 1024
                })
            );
            assert_eq!(
                parse_meminfo("MemTotal: 16000 kB\n"),
                None,
                "an old kernel without MemAvailable"
            );
        }

        #[test]
        fn cgroup_v2_limits_are_found_at_every_level_and_cache_does_not_count() {
            let root = tempfile::tempdir().unwrap();
            let parent = root.path().join("a");
            let child = parent.join("b");
            in_dir(
                &parent,
                &[
                    ("memory.max", "1000"),
                    ("memory.current", "900"),
                    ("memory.stat", "anon 500\ninactive_file 400\n"),
                ],
            );
            in_dir(&child, &[("memory.max", "max"), ("memory.current", "900")]);

            let found = limited_cgroups("0::/a/b\n", root.path(), Path::new("/nonexistent"));
            assert_eq!(
                found,
                vec![Cgroup::V2(parent.clone())],
                "a limit on the parent counts, and max is none"
            );
            assert_eq!(
                left_in(&found[0]),
                Some(MemoryLeft {
                    total: 1000,
                    available: 500
                })
            );
        }

        #[test]
        fn cgroup_v1_limits_are_read_from_the_memory_controller() {
            let root = tempfile::tempdir().unwrap();
            let dir = root.path().join("docker");
            in_dir(
                &dir,
                &[
                    ("memory.limit_in_bytes", "2000"),
                    ("memory.usage_in_bytes", "1500"),
                    ("memory.stat", "cache 9\ntotal_inactive_file 500\n"),
                ],
            );
            in_dir(
                root.path(),
                &[("memory.limit_in_bytes", "9223372036854771712")],
            );

            let text = "12:cpu,cpuacct:/x\n4:memory:/docker\n";
            let found = limited_cgroups(text, Path::new("/nonexistent"), root.path());
            assert_eq!(
                found,
                vec![Cgroup::V1(dir)],
                "the huge value at the top means no limit"
            );
            assert_eq!(
                left_in(&found[0]),
                Some(MemoryLeft {
                    total: 2000,
                    available: 1000
                })
            );
        }

        #[test]
        fn without_any_limit_only_the_system_counts() {
            let root = tempfile::tempdir().unwrap();
            assert!(limited_cgroups("0::/\n", root.path(), root.path()).is_empty());
            assert!(limited_cgroups("not a cgroup line\n", root.path(), root.path()).is_empty());
        }

        #[test]
        fn this_machine_can_be_read() {
            let reading = reader()();
            assert!(!reading.limits.is_empty());
            assert!(reading.own > 0);
        }
    }
}

// FreeBSD 和 Windows 另行实现，这里先读不到 / FreeBSD and Windows come later; until then memory reads as unknown
#[cfg(not(target_os = "linux"))]
mod system {
    use super::MemoryReading;

    pub(super) fn reader() -> Box<dyn Fn() -> MemoryReading + Send + Sync> {
        Box::new(MemoryReading::default)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, AtomicUsize};

    const MIB: u64 = 1 << 20;
    const GIB: u64 = 1 << 30;
    /// 下面这些测试的总量 1 GiB 对应的间隔 / How far apart reads are with the 1 GiB of the tests below
    const READ_EVERY: usize = 2730;

    /// 剩余内存可以随时改、还记着读了几次的水位，总量 1 GiB
    /// A watermark over 1 GiB whose free memory can change, counting its reads
    fn watermark() -> (MemoryWatermark, Arc<AtomicU64>, Arc<AtomicUsize>) {
        let available = Arc::new(AtomicU64::new(GIB));
        let reads = Arc::new(AtomicUsize::new(0));
        let (left, count) = (Arc::clone(&available), Arc::clone(&reads));
        let watermark = MemoryWatermark::reading(move || {
            count.fetch_add(1, Ordering::Relaxed);
            MemoryReading {
                own: 0,
                limits: vec![MemoryLeft {
                    total: GIB,
                    available: left.load(Ordering::Relaxed),
                }],
            }
        });
        (watermark, available, reads)
    }

    #[test]
    fn what_is_kept_back_grows_with_its_own_use() {
        let low = |total, available, own| MemoryLeft { total, available }.is_low(own);
        assert!(low(256 * MIB, 15 * MIB, 0), "a sixteenth of the total");
        assert!(!low(256 * MIB, 17 * MIB, 0));
        assert!(
            low(256 * MIB, 63 * MIB, 192 * MIB),
            "plus a quarter of its own use"
        );
        assert!(!low(256 * MIB, 65 * MIB, 192 * MIB));
        assert!(low(16 * GIB, 256 * MIB - 1, 0), "the margin stops growing");
        assert!(!low(16 * GIB, 256 * MIB + 1, 0));
        assert!(
            !low(64 * GIB, 3 * GIB, 200 * MIB),
            "other programs holding the memory do not make it low"
        );
    }

    #[test]
    fn reads_are_nearer_together_the_less_memory_there_is() {
        assert_eq!(reads_apart(GIB), READ_EVERY);
        assert_eq!(reads_apart(128 * MIB), 341);
        assert_eq!(reads_apart(16 * MIB), 100, "at least this far apart");
        assert_eq!(
            reads_apart(64 * GIB),
            READS_APART_UNKNOWN,
            "at most this far apart"
        );
    }

    /// 取最小的总量算间隔；读不到时按最大的间隔
    /// The least total sets how far apart reads are; without one it is the widest
    #[test]
    fn the_smallest_limit_paces_the_reads() {
        let reads = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&reads);
        let watermark = MemoryWatermark::reading(move || {
            count.fetch_add(1, Ordering::Relaxed);
            MemoryReading {
                own: 0,
                limits: vec![
                    MemoryLeft {
                        total: 16 * GIB,
                        available: 16 * GIB,
                    },
                    MemoryLeft {
                        total: 128 * MIB,
                        available: 128 * MIB,
                    },
                ],
            }
        });
        for _ in 0..341 * 2 {
            watermark.has_room(LOOK_FROM_INFLIGHT);
        }
        assert_eq!(reads.load(Ordering::Relaxed), 2);

        let reads = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&reads);
        let unknown = MemoryWatermark::reading(move || {
            count.fetch_add(1, Ordering::Relaxed);
            MemoryReading::default()
        });
        for _ in 0..READS_APART_UNKNOWN {
            unknown.has_room(LOOK_FROM_INFLIGHT);
        }
        assert_eq!(reads.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn under_the_floor_memory_is_not_read_and_nothing_is_refused() {
        let (watermark, available, reads) = watermark();
        available.store(0, Ordering::Relaxed);
        for _ in 0..5000 {
            assert!(watermark.has_room(LOOK_FROM_INFLIGHT - 1));
        }
        assert_eq!(reads.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn from_the_floor_memory_is_read_every_so_many_misses() {
        let (watermark, _, reads) = watermark();
        for _ in 0..READ_EVERY * 3 {
            assert!(watermark.has_room(LOOK_FROM_INFLIGHT));
        }
        assert_eq!(reads.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn low_memory_refuses_until_it_comes_back() {
        let (watermark, available, _) = watermark();
        assert!(watermark.has_room(LOOK_FROM_INFLIGHT));

        available.store(GIB / 16 - 1, Ordering::Relaxed);
        for _ in 1..READ_EVERY {
            assert!(watermark.has_room(LOOK_FROM_INFLIGHT), "not read yet");
        }
        assert!(!watermark.has_room(LOOK_FROM_INFLIGHT), "read now");
        assert!(
            watermark.has_room(LOOK_FROM_INFLIGHT - 1),
            "under the floor it is not refused"
        );
        assert!(!watermark.has_room(LOOK_FROM_INFLIGHT), "still low");

        available.store(GIB / 16 + 1, Ordering::Relaxed);
        for _ in 0..READ_EVERY {
            watermark.has_room(LOOK_FROM_INFLIGHT);
        }
        assert!(watermark.has_room(LOOK_FROM_INFLIGHT), "came back");
    }

    #[test]
    fn any_low_limit_counts() {
        let watermark = MemoryWatermark::reading(|| MemoryReading {
            own: 0,
            limits: vec![
                MemoryLeft {
                    total: 16 * GIB,
                    available: 8 * GIB,
                },
                MemoryLeft {
                    total: 256 * MIB,
                    available: MIB,
                },
            ],
        });
        assert!(!watermark.has_room(LOOK_FROM_INFLIGHT));
    }

    #[test]
    fn memory_that_cannot_be_read_refuses_nothing() {
        let watermark = MemoryWatermark::reading(MemoryReading::default);
        for _ in 0..READ_EVERY * 2 {
            assert!(watermark.has_room(LOOK_FROM_INFLIGHT));
        }
    }
}
