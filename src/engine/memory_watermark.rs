//! 流控的内存水位：在途查询多到可能撑爆内存时，看这台机器还剩多少内存。紧张了在途就停在那一刻的数，各设备平分，
//! 只拒占着自己那一份的设备的新未命中，发得少的照常；再少就谁的都拒；够了自动恢复（见 [`Room`]）。不填数字：每台机器读自己的
//! 内存——Linux 读系统的和所在各级 cgroup 的限制，FreeBSD 读系统的，
//! Windows 读系统的和所在作业对象的限制。
//! 在途查询没到 [`LOOK_FROM_INFLIGHT`] 时不读内存，也不拒绝：日常路径没有开销，其他程序吃内存也不会
//! 牵连日常查询。之后按 [`reads_apart`] 隔一段读一次，两次之间多占的内存和总量成比例，和 CPU 快慢无关。
//!
//! Flow control's memory watermark: once enough queries are in flight to threaten the
//! memory, it looks at how much memory this machine has left. When it is tight, what is in
//! flight stays where it was at that moment, shared out among the devices, new cache misses
//! are refused only from devices holding their share, and those sending little go on; with
//! less left, everyone's are refused; with enough it
//! resumes by itself (see [`Room`]). There is no number to fill in: each
//! machine reads its own memory: on Linux the system's and the limits of its cgroups at
//! every level, on FreeBSD the system's, and on Windows the system's and the limits of its job object.
//! Under [`LOOK_FROM_INFLIGHT`] queries in flight it neither reads nor refuses: the daily
//! path pays nothing, and other programs using memory do not hold up daily queries. After
//! that it reads every [`reads_apart`], which keeps what is added between two reads in
//! proportion to the total, whatever the CPU's speed.

use std::sync::atomic::{AtomicIsize, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

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

/// 内存还有多少余地 / How much room memory has left
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Room {
    /// 够 / Enough
    Plenty,
    /// 紧张：在途停在变紧张那一刻的数（见 [`MemoryWatermark::tight_budget`]），只拒占着自己那一份的设备，发得少的照常
    /// Tight: what is in flight stays where it was as memory got tight (see
    /// [`MemoryWatermark::tight_budget`]), only devices holding their share are refused, and
    /// those sending little go on
    Tight,
    /// 没了：谁都拒 / None left: everyone is refused
    Full,
}

impl Room {
    fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Plenty,
            1 => Self::Tight,
            _ => Self::Full,
        }
    }
}

impl MemoryLeft {
    /// 这个进程占着 `own` 字节时这里还有多少余地。不再接新查询之后，在途查询进入超时阶段还会多占
    /// 一成多，所以要留出自身占用的四分之一，再加一点余量，剩的少于这些就谁都拒。少于它的两倍时先只拒
    /// 占得多的设备：两次读之间多占的，一般远少于两条线之间的距离（总量的十六分之一、最多 256 MiB，
    /// 再加自身的四分之一），所以内存只是被这个程序占掉时，总是先读到紧张，一台设备发得多就先拦住它
    /// How much room is left here with this process holding `own` bytes. After new queries stop,
    /// those in flight still grow by over a tenth as they reach their timeouts, so a quarter of its
    /// own use is kept back, plus a margin, and with less left than that everyone is refused. With
    /// less than twice that only the devices holding more are refused first: what is added between
    /// two reads is usually far less than the distance between the two lines (a sixteenth of the
    /// total, at most 256 MiB, plus a quarter of its own use), so while it is this program taking
    /// the memory, tight is read first and a device sending much is stopped there
    fn room_for(self, own: u64) -> Room {
        let margin = own / 4 + (self.total / 16).min(MAX_MARGIN);
        if self.available < margin {
            Room::Full
        } else if self.available < margin.saturating_mul(2) {
            Room::Tight
        } else {
            Room::Plenty
        }
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
    /// 上次读到的 [`Room`] / The [`Room`] last read
    room: AtomicU8,
    started: Instant,
    /// 上次读的时刻，从 `started` 算起的毫秒 / When it was last read, in milliseconds since `started`
    read_at_ms: AtomicU64,
    /// 紧张时在途的查询最多多少，没记下时是 `usize::MAX`，见 [`Self::tight_budget`] / How many queries may be in
    /// flight while tight, `usize::MAX` when none is noted, see [`Self::tight_budget`]
    tight_budget: AtomicUsize,
}

/// 读数放了这么久就重读，不管隔了几次：在途降到底线以下时不读也不计数，再过底线时手上可能是很久以前的读数
/// A reading this old is taken again, however few reads apart: under the floor nothing is read
/// or counted, so crossing the floor again could find a reading from long ago
const READING_KEPT: Duration = Duration::from_secs(1);

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
            room: AtomicU8::new(Room::Plenty as u8),
            started: Instant::now(),
            read_at_ms: AtomicU64::new(0),
            tight_budget: AtomicUsize::new(usize::MAX),
        }
    }

    /// 在途 `inflight` 个查询时，内存还有多少余地 / How much room memory has with `inflight` in flight
    #[inline]
    pub fn room(&self, inflight: usize) -> Room {
        if inflight < LOOK_FROM_INFLIGHT {
            Room::Plenty
        } else {
            self.looked_at()
        }
    }

    /// 紧张时在途的查询一共最多多少，`queries` 是现在在途的查询数（不算连接）：变紧张以后头一次问的时候在途多少，就是多少，
    /// 内存不紧张了（够了，或者没了）就清掉。不随着读数往上调：紧张时放进去的都让内存更紧，到了这个数只再放没占满自己那一份的
    /// 设备，一共最多多出设备数那么多。没了的时候谁都不放，在途只会少，再回到紧张时记下的就更小。内存还给系统以前，在途回到
    /// 这个数用的还是原来那些内存
    /// How many queries may be in flight in all while tight, `queries` being how many are in
    /// flight now (connections not counted): as many as were in flight when first asked after
    /// memory got tight, cleared once it is not tight (enough again, or none left). It does not
    /// follow later readings up: whatever is let in while tight makes memory tighter, so at this
    /// many only devices short of their share get more, the total going past it by at most the
    /// number of devices. With none left nothing is let in and what is in flight only falls, so
    /// coming back to tight notes fewer. Until memory goes back to the system, coming back to this
    /// many uses the memory already held
    #[inline]
    pub fn tight_budget(&self, queries: usize) -> usize {
        match self.tight_budget.compare_exchange(
            usize::MAX,
            queries,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => queries,
            Err(budget) => budget,
        }
    }

    fn looked_at(&self) -> Room {
        let now_ms = self.started.elapsed().as_millis() as u64;
        let stale = now_ms.saturating_sub(self.read_at_ms.load(Ordering::Relaxed))
            > READING_KEPT.as_millis() as u64;
        if self.until_read.fetch_sub(1, Ordering::Relaxed) <= 1 || stale {
            self.read_at_ms.store(now_ms, Ordering::Relaxed);
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
            let room = reading
                .limits
                .iter()
                .map(|limit| limit.room_for(reading.own))
                .max()
                .unwrap_or(Room::Plenty);
            if room != Room::Tight {
                self.tight_budget.store(usize::MAX, Ordering::Relaxed);
            }
            if self.room.swap(room as u8, Ordering::Relaxed) != room as u8 {
                tracing::warn!(
                    event = "flow_control_memory",
                    low = room != Room::Plenty,
                    ?room,
                    ?reading,
                    "memory watermark crossed"
                );
            }
        }
        Room::from_u8(self.room.load(Ordering::Relaxed))
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
    }
}

/// FreeBSD 的系统内存。空闲页加不活跃页随时能用；ZFS 的 ARC 缺内存时会缩到下限，高出下限的那部分也算能用，
/// 不然用 ZFS 的机器 ARC 占着大半内存，总像是不够
/// FreeBSD's system memory. Free and inactive pages can be used at any time; ZFS's ARC shrinks
/// to its minimum when memory runs short, so what it holds above that counts as usable too, or a
/// machine on ZFS, its ARC holding most of the memory, would always seem short
#[cfg(any(target_os = "freebsd", test))]
fn freebsd_left(
    physmem: u64,
    page_size: u64,
    free_pages: u64,
    inactive_pages: u64,
    arc: Option<(u64, u64)>,
) -> MemoryLeft {
    let arc_above_min = arc.map_or(0, |(size, min)| size.saturating_sub(min));
    MemoryLeft {
        total: physmem,
        available: free_pages
            .saturating_add(inactive_pages)
            .saturating_mul(page_size)
            .saturating_add(arc_above_min)
            .min(physmem),
    }
}

/// Windows 作业对象的内存限制，按已提交的内存算。单个进程的上限，用量就是这个进程已提交的；整个作业的上限，
/// 作业里只有这个进程时用量也是它，有别的进程时读不到作业的用量，这一处就不算
/// The memory limits of a Windows job object, counted in committed memory. For the per-process
/// limit the use is what this process has committed; for the whole job's limit it is the same
/// when this process is alone in the job, and with others there the job's use cannot be read,
/// so that limit is left out
#[cfg(any(windows, test))]
fn job_left(
    process_limit: Option<u64>,
    job_limit: Option<u64>,
    alone_in_job: bool,
    committed: u64,
) -> Vec<MemoryLeft> {
    let left = |total: u64| MemoryLeft {
        total,
        available: total.saturating_sub(committed),
    };
    process_limit
        .map(left)
        .into_iter()
        .chain(job_limit.filter(|_| alone_in_job).map(left))
        .collect()
}

#[cfg(target_os = "freebsd")]
mod system {
    use super::{MemoryReading, freebsd_left};
    use std::ffi::CStr;
    use std::mem::{MaybeUninit, size_of};

    pub(super) fn reader() -> Box<dyn Fn() -> MemoryReading + Send + Sync> {
        Box::new(|| MemoryReading {
            own: own_resident().unwrap_or(0),
            limits: system_left().into_iter().collect(),
        })
    }

    fn system_left() -> Option<super::MemoryLeft> {
        let arc =
            sysctl(c"kstat.zfs.misc.arcstats.size").zip(sysctl(c"kstat.zfs.misc.arcstats.c_min"));
        Some(freebsd_left(
            sysctl(c"hw.physmem")?,
            sysctl(c"vm.stats.vm.v_page_size")?,
            sysctl(c"vm.stats.vm.v_free_count")?,
            sysctl(c"vm.stats.vm.v_inactive_count")?,
            arc,
        ))
    }

    /// 读一个整数 sysctl，32 位、64 位的都行；没有这一项（比如没用 ZFS）就是 None
    /// Reads an integer sysctl, 32 or 64 bits wide; None when there is no such entry (no ZFS, say)
    fn sysctl(name: &CStr) -> Option<u64> {
        let mut value = [0u8; 8];
        let mut len = value.len();
        // SAFETY: the buffer holds `len` bytes and the kernel writes no more than that
        // 缓冲区有 `len` 字节，内核写不超过这么多
        let read = unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                value.as_mut_ptr().cast(),
                &mut len,
                std::ptr::null(),
                0,
            )
        };
        if read != 0 {
            return None;
        }
        match len {
            4 => Some(u64::from(u32::from_ne_bytes(value[..4].try_into().ok()?))),
            8 => Some(u64::from_ne_bytes(value)),
            _ => None,
        }
    }

    /// 这个进程驻留的字节：kinfo_proc 里的驻留页数乘页大小。结构体大小和内核报的对不上就不读
    /// The bytes this process holds resident: the resident pages in its kinfo_proc times the page
    /// size. Nothing is read when the structure's size differs from what the kernel reports
    fn own_resident() -> Option<u64> {
        // SAFETY: getpid has no preconditions / getpid 没有前提条件
        let pid = unsafe { libc::getpid() };
        let mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, pid];
        let mut info = MaybeUninit::<libc::kinfo_proc>::zeroed();
        let mut len = size_of::<libc::kinfo_proc>();
        // SAFETY: `info` holds `len` bytes and the kernel writes no more than that
        // `info` 有 `len` 字节，内核写不超过这么多
        let read = unsafe {
            libc::sysctl(
                mib.as_ptr(),
                mib.len() as libc::c_uint,
                info.as_mut_ptr().cast(),
                &mut len,
                std::ptr::null(),
                0,
            )
        };
        if read != 0 || len != size_of::<libc::kinfo_proc>() {
            return None;
        }
        // SAFETY: zeroed and then filled by the kernel, every field is initialised
        // 先清零再由内核填好，每个字段都有值
        let info = unsafe { info.assume_init() };
        if usize::try_from(info.ki_structsize).ok()? != size_of::<libc::kinfo_proc>() {
            return None;
        }
        let pages = u64::try_from(info.ki_rssize).ok()?;
        Some(pages.saturating_mul(sysctl(c"vm.stats.vm.v_page_size")?))
    }
}

#[cfg(windows)]
mod system {
    use super::{MemoryLeft, MemoryReading, job_left};
    use std::mem::{MaybeUninit, size_of};
    use windows_sys::Win32::System::JobObjects::{
        JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOBOBJECTINFOCLASS, JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
        QueryInformationJobObject,
    };
    use windows_sys::Win32::System::ProcessStatus::{
        K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX,
    };
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    pub(super) fn reader() -> Box<dyn Fn() -> MemoryReading + Send + Sync> {
        Box::new(|| {
            let process = process_memory();
            MemoryReading {
                own: process.map_or(0, |counters| counters.WorkingSetSize as u64),
                limits: system_left()
                    .into_iter()
                    .chain(job_limits(
                        process.map_or(0, |counters| counters.PrivateUsage as u64),
                    ))
                    .collect(),
            }
        })
    }

    /// 物理内存总量和可用量，可用的含随时能回收的缓存 / Physical memory in all and available, the
    /// available including cache that can be reclaimed at any time
    fn system_left() -> Option<MemoryLeft> {
        let mut status = MaybeUninit::<MEMORYSTATUSEX>::zeroed();
        // SAFETY: a zeroed MEMORYSTATUSEX is valid, and its length is set before the call
        // 清零的 MEMORYSTATUSEX 合法，调用前先填好长度
        let status = unsafe {
            (*status.as_mut_ptr()).dwLength = size_of::<MEMORYSTATUSEX>() as u32;
            if GlobalMemoryStatusEx(status.as_mut_ptr()) == 0 {
                return None;
            }
            status.assume_init()
        };
        Some(MemoryLeft {
            total: status.ullTotalPhys,
            available: status.ullAvailPhys,
        })
    }

    fn process_memory() -> Option<PROCESS_MEMORY_COUNTERS_EX> {
        let size = size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32;
        let mut counters = MaybeUninit::<PROCESS_MEMORY_COUNTERS_EX>::zeroed();
        // SAFETY: the counters hold `size` bytes, which the call is told, and zeroed they are valid
        // 计数结构有 `size` 字节并告诉了调用，清零也合法
        unsafe {
            (*counters.as_mut_ptr()).cb = size;
            let read = K32GetProcessMemoryInfo(
                GetCurrentProcess(),
                counters.as_mut_ptr().cast::<PROCESS_MEMORY_COUNTERS>(),
                size,
            );
            (read != 0).then(|| counters.assume_init())
        }
    }

    fn job_limits(committed: u64) -> Vec<MemoryLeft> {
        // SAFETY: each class is queried into the structure it fills
        // 每一类信息都查进它对应的结构
        let (limits, accounting) = unsafe {
            (
                query_job::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>(
                    JobObjectExtendedLimitInformation,
                ),
                query_job::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>(
                    JobObjectBasicAccountingInformation,
                ),
            )
        };
        let Some(limits) = limits else {
            return Vec::new();
        };
        let flags = limits.BasicLimitInformation.LimitFlags;
        job_left(
            (flags & JOB_OBJECT_LIMIT_PROCESS_MEMORY != 0)
                .then_some(limits.ProcessMemoryLimit as u64),
            (flags & JOB_OBJECT_LIMIT_JOB_MEMORY != 0).then_some(limits.JobMemoryLimit as u64),
            accounting.is_some_and(|accounting| accounting.ActiveProcesses == 1),
            committed,
        )
    }

    /// 这个进程所在作业的一类信息（作业套作业时是最里面那一层）；不在作业里就没有
    /// One class of information on the job this process is in (the innermost of nested jobs);
    /// None when it is in no job
    ///
    /// # Safety
    /// `T` 必须是 `class` 要填的那个 C 结构，全零是合法值 / `T` must be the C structure `class`
    /// fills, for which all zeros is a valid value
    unsafe fn query_job<T>(class: JOBOBJECTINFOCLASS) -> Option<T> {
        let mut info = MaybeUninit::<T>::zeroed();
        // SAFETY: by this function's contract `info` is what `class` fills, `size_of::<T>()` bytes
        // 按约定 `info` 就是 `class` 要填的，`size_of::<T>()` 字节
        unsafe {
            let read = QueryInformationJobObject(
                std::ptr::null_mut(),
                class,
                info.as_mut_ptr().cast(),
                size_of::<T>() as u32,
                std::ptr::null_mut(),
            );
            (read != 0).then(|| info.assume_init())
        }
    }
}

// 其他系统还读不到内存，不按内存拒绝 / Other systems cannot read memory yet, and nothing is refused by memory
#[cfg(not(any(target_os = "linux", target_os = "freebsd", windows)))]
mod system {
    use super::MemoryReading;

    pub(super) fn reader() -> Box<dyn Fn() -> MemoryReading + Send + Sync> {
        Box::new(MemoryReading::default)
    }
}

/// 读一次这台机器的内存：本进程占的和每一处限制，系统的那处在最前面
/// Reads this machine's memory once: what this process holds and every limit, the system's first
pub fn this_machine() -> MemoryReading {
    system::reader()()
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

    /// 少于余量谁都拒，少于两倍余量算紧张 / Under the margin everyone is refused, under twice it is tight
    #[test]
    fn what_is_kept_back_grows_with_its_own_use() {
        let room = |total, available, own| MemoryLeft { total, available }.room_for(own);
        assert_eq!(
            room(256 * MIB, 15 * MIB, 0),
            Room::Full,
            "a sixteenth of the total"
        );
        assert_eq!(
            room(256 * MIB, 17 * MIB, 0),
            Room::Tight,
            "under twice that"
        );
        assert_eq!(room(256 * MIB, 31 * MIB, 0), Room::Tight);
        assert_eq!(room(256 * MIB, 33 * MIB, 0), Room::Plenty);
        assert_eq!(
            room(256 * MIB, 63 * MIB, 192 * MIB),
            Room::Full,
            "plus a quarter of its own use"
        );
        assert_eq!(room(256 * MIB, 65 * MIB, 192 * MIB), Room::Tight);
        assert_eq!(room(256 * MIB, 129 * MIB, 192 * MIB), Room::Plenty);
        assert_eq!(
            room(16 * GIB, 256 * MIB - 1, 0),
            Room::Full,
            "the margin stops growing"
        );
        assert_eq!(room(16 * GIB, 256 * MIB + 1, 0), Room::Tight);
        assert_eq!(room(16 * GIB, 512 * MIB + 1, 0), Room::Plenty);
        assert_eq!(
            room(64 * GIB, 3 * GIB, 200 * MIB),
            Room::Plenty,
            "other programs holding the memory do not make it tight"
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
            watermark.room(LOOK_FROM_INFLIGHT);
        }
        assert_eq!(reads.load(Ordering::Relaxed), 2);

        let reads = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&reads);
        let unknown = MemoryWatermark::reading(move || {
            count.fetch_add(1, Ordering::Relaxed);
            MemoryReading::default()
        });
        for _ in 0..READS_APART_UNKNOWN {
            unknown.room(LOOK_FROM_INFLIGHT);
        }
        assert_eq!(reads.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn under_the_floor_memory_is_not_read_and_nothing_is_refused() {
        let (watermark, available, reads) = watermark();
        available.store(0, Ordering::Relaxed);
        for _ in 0..5000 {
            assert_eq!(watermark.room(LOOK_FROM_INFLIGHT - 1), Room::Plenty);
        }
        assert_eq!(reads.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn from_the_floor_memory_is_read_every_so_many_misses() {
        let (watermark, _, reads) = watermark();
        for _ in 0..READ_EVERY * 3 {
            assert_eq!(watermark.room(LOOK_FROM_INFLIGHT), Room::Plenty);
        }
        assert_eq!(reads.load(Ordering::Relaxed), 3);
    }

    /// 没了就一直谁都拒，回到线上先是紧张，再多才够 / With none left everyone is refused until it
    /// comes back: just above the line it is tight, and only with more is it plenty
    #[test]
    fn low_memory_refuses_until_it_comes_back() {
        let (watermark, available, _) = watermark();
        assert_eq!(watermark.room(LOOK_FROM_INFLIGHT), Room::Plenty);

        available.store(GIB / 16 - 1, Ordering::Relaxed);
        for _ in 1..READ_EVERY {
            assert_eq!(
                watermark.room(LOOK_FROM_INFLIGHT),
                Room::Plenty,
                "not read yet"
            );
        }
        assert_eq!(watermark.room(LOOK_FROM_INFLIGHT), Room::Full, "read now");
        assert_eq!(
            watermark.room(LOOK_FROM_INFLIGHT - 1),
            Room::Plenty,
            "under the floor it is not refused"
        );
        assert_eq!(watermark.room(LOOK_FROM_INFLIGHT), Room::Full, "still full");

        available.store(GIB / 16 + 1, Ordering::Relaxed);
        for _ in 0..READ_EVERY {
            watermark.room(LOOK_FROM_INFLIGHT);
        }
        assert_eq!(
            watermark.room(LOOK_FROM_INFLIGHT),
            Room::Tight,
            "back above the line"
        );

        available.store(GIB / 8 + 1, Ordering::Relaxed);
        for _ in 0..READ_EVERY {
            watermark.room(LOOK_FROM_INFLIGHT);
        }
        assert_eq!(
            watermark.room(LOOK_FROM_INFLIGHT),
            Room::Plenty,
            "came back"
        );
    }

    /// 读数放了一秒以上就重读：内存不够时读过一次、在途随后降到底线以下，过了一阵再过底线时，按当时的内存判断。以前
    /// 一直沿用旧读数，要等够次数才重读，头一批查询和连接按早已过时的读数被拒
    /// A reading over a second old is taken again: once memory was read as short and in-flight
    /// then fell under the floor, crossing the floor again a while later is judged by the memory
    /// then. The old reading used to stay until enough reads had passed, refusing the first
    /// queries and connections by a reading long out of date
    #[test]
    fn a_reading_over_a_second_old_is_taken_again() {
        let (watermark, available, reads) = watermark();
        available.store(0, Ordering::Relaxed);
        for _ in 0..READ_EVERY {
            watermark.room(LOOK_FROM_INFLIGHT);
        }
        assert_eq!(watermark.room(LOOK_FROM_INFLIGHT), Room::Full);
        let read_so_far = reads.load(Ordering::Relaxed);
        assert_eq!(watermark.room(LOOK_FROM_INFLIGHT - 1), Room::Plenty);

        available.store(GIB, Ordering::Relaxed);
        std::thread::sleep(std::time::Duration::from_millis(1_100));
        assert_eq!(
            watermark.room(LOOK_FROM_INFLIGHT),
            Room::Plenty,
            "read again at once"
        );
        assert_eq!(reads.load(Ordering::Relaxed), read_so_far + 1);
        // 一秒之内照旧按次数 / Within the second it still goes by count
        available.store(0, Ordering::Relaxed);
        assert_eq!(watermark.room(LOOK_FROM_INFLIGHT), Room::Plenty, "not yet");
        assert_eq!(reads.load(Ordering::Relaxed), read_so_far + 1);
    }

    /// 紧张时的在途上限：变紧张以后头一次问时记下，之后不随着问的数往上调；内存没了或者够了就清掉，再变紧张时重新记
    /// The budget while tight is noted as first asked after memory got tight and does not follow
    /// later asks up; it is cleared once memory has none left or enough, and noted afresh as it
    /// gets tight again
    #[test]
    fn the_tight_budget_is_noted_once_and_cleared_when_not_tight() {
        let (watermark, available, _) = watermark();
        let read_as = |left: u64| {
            available.store(left, Ordering::Relaxed);
            for _ in 0..READ_EVERY {
                watermark.room(LOOK_FROM_INFLIGHT);
            }
            watermark.room(LOOK_FROM_INFLIGHT)
        };
        assert_eq!(read_as(GIB / 8 - 1), Room::Tight);
        assert_eq!(watermark.tight_budget(5000), 5000, "noted as first asked");
        assert_eq!(
            watermark.tight_budget(9000),
            5000,
            "not raised by more in flight"
        );
        assert_eq!(read_as(GIB / 8 - 2), Room::Tight);
        assert_eq!(watermark.tight_budget(9000), 5000, "nor by another reading");

        assert_eq!(read_as(0), Room::Full);
        assert_eq!(read_as(GIB / 8 - 1), Room::Tight);
        assert_eq!(
            watermark.tight_budget(3000),
            3000,
            "noted afresh after none left"
        );

        assert_eq!(read_as(GIB), Room::Plenty);
        assert_eq!(read_as(GIB / 8 - 1), Room::Tight);
        assert_eq!(
            watermark.tight_budget(7000),
            7000,
            "noted afresh after enough"
        );
    }

    /// 哪一处限制最紧就按哪一处 / The tightest limit is the one that counts
    #[test]
    fn the_tightest_limit_counts() {
        let reading = |second: MemoryLeft| {
            MemoryWatermark::reading(move || MemoryReading {
                own: 0,
                limits: vec![
                    MemoryLeft {
                        total: 16 * GIB,
                        available: 8 * GIB,
                    },
                    second,
                ],
            })
        };
        let full = reading(MemoryLeft {
            total: 256 * MIB,
            available: MIB,
        });
        assert_eq!(full.room(LOOK_FROM_INFLIGHT), Room::Full);
        let tight = reading(MemoryLeft {
            total: 256 * MIB,
            available: 20 * MIB,
        });
        assert_eq!(tight.room(LOOK_FROM_INFLIGHT), Room::Tight);
    }

    #[test]
    fn memory_that_cannot_be_read_refuses_nothing() {
        let watermark = MemoryWatermark::reading(MemoryReading::default);
        for _ in 0..READ_EVERY * 2 {
            assert_eq!(watermark.room(LOOK_FROM_INFLIGHT), Room::Plenty);
        }
    }

    /// FreeBSD：空闲页加不活跃页能用，ZFS 的 ARC 只算高出下限的那部分；没有 ZFS 就不算它
    /// FreeBSD: free and inactive pages are usable, and of ZFS's ARC only what is above its
    /// minimum; without ZFS it does not count
    #[test]
    fn on_freebsd_free_inactive_and_the_arc_above_its_minimum_are_left() {
        const PAGE: u64 = 4096;
        let with_arc = freebsd_left(16 * GIB, PAGE, 1000, 3000, Some((6 * GIB, GIB)));
        assert_eq!(
            with_arc,
            MemoryLeft {
                total: 16 * GIB,
                available: 4000 * PAGE + 5 * GIB,
            }
        );
        let without_zfs = freebsd_left(16 * GIB, PAGE, 1000, 3000, None);
        assert_eq!(without_zfs.available, 4000 * PAGE);
        let arc_at_its_minimum = freebsd_left(16 * GIB, PAGE, 1000, 3000, Some((GIB, 2 * GIB)));
        assert_eq!(arc_at_its_minimum.available, 4000 * PAGE);
        let counters_past_the_total = freebsd_left(GIB, PAGE, u64::MAX, 1, Some((GIB, 0)));
        assert_eq!(
            counters_past_the_total.available, GIB,
            "never more than the total"
        );
    }

    /// Windows 作业对象：单进程上限按本进程已提交的算；整个作业的上限只在作业里只有本进程时算
    /// A Windows job object: the per-process limit goes by what this process has committed; the
    /// whole job's limit counts only with this process alone in the job
    #[test]
    fn a_windows_job_limit_counts_only_when_its_use_is_known() {
        let process = MemoryLeft {
            total: 2 * GIB,
            available: 2 * GIB - 300 * MIB,
        };
        let job = MemoryLeft {
            total: 4 * GIB,
            available: 4 * GIB - 300 * MIB,
        };
        assert!(job_left(None, None, true, 300 * MIB).is_empty());
        assert_eq!(job_left(Some(2 * GIB), None, false, 300 * MIB), [process]);
        assert_eq!(job_left(None, Some(4 * GIB), true, 300 * MIB), [job]);
        assert!(
            job_left(None, Some(4 * GIB), false, 300 * MIB).is_empty(),
            "others in the job: its use is unknown"
        );
        assert_eq!(
            job_left(Some(2 * GIB), Some(4 * GIB), true, 300 * MIB),
            [process, job]
        );
        assert_eq!(job_left(Some(MIB), None, true, GIB)[0].available, 0);
    }
}
