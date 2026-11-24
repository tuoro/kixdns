use std::any::Any;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use clap::{Parser, Subcommand};

/// 内核进程用 mimalloc 分配内存，不用 glibc 的 malloc。在不断有新名字进出缓存的负载下，glibc 的堆会
/// 碎成许多散块：真正在用的内存只有十几到一百多 MiB，进程占的却能到它的十倍（实测 20 万条应答缓存时
/// 在用约 135 MiB、进程 1.3 GiB），定期 `malloc_trim` 又要锁住分配器几十毫秒。mimalloc 按页归还空闲内存，
/// 同样的负载下进程内存跟着在用的走，查询也更快。只影响这个可执行文件，作为库使用时由调用方自己选分配器。
/// The kernel process allocates with mimalloc rather than glibc's malloc. Under a load that keeps
/// moving new names through the caches, glibc's heap breaks into scattered pieces: the memory in use
/// stays between ten and a hundred-odd MiB while the process holds up to ten times that (measured
/// with 200,000 cached answers: about 135 MiB in use, 1.3 GiB held), and a periodic `malloc_trim`
/// locks the allocator for tens of milliseconds. mimalloc returns free memory page by page, so under
/// the same load the process follows the memory in use, and queries are faster too. This applies to
/// this executable only; as a library the caller picks its own allocator.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// mimalloc 的一个设置，在任何分配之前设好：不预先提交整块内存。预先提交的内存区，mimalloc 会为它申请
/// 透明大页，问题见下面。这个设置只对设好之后才建的内存区生效，所以要赶在第一次分配之前：Linux 和 FreeBSD
/// 上放进 `.init_array`，程序装载时、Rust 运行时分配内存之前就执行；别的平台在 main 一开始设。
///
/// 释放的内存按 mimalloc 默认的延迟（1 秒）归还系统，不改成释放即还。释放即还时，新名字用到的内存页多半
/// 是刚还回去又要回来的，几乎每个查询都多一次缺页，新名字的吞吐少约一成；省下的内存实测只有约 1 MiB
/// （空闲时、GeoSite 规则压测后、20 万条缓存压满后都是）。到期的归还在之后的分配里顺带完成，工作线程闲下来时也整理一次
/// （见 [`allocator_tuning::collect_when_idle`]）。
///
/// 另外在 Linux 上只对本进程关掉透明大页，不改系统设置。用了透明大页，零碎归还过的内存再用到时，系统要把
/// 整块 2 MiB 清零，单核上事件循环会停住（外部压测在 mimalloc 默认设置下测到 p99 上百毫秒）。不预先提交时
/// mimalloc 已经不为内存区申请大页，但透明大页设成 always 的系统不申请也会给，所以直接关掉。
/// One mimalloc setting, applied before any allocation: whole arenas are not committed up front. For
/// an arena committed up front mimalloc asks for transparent huge pages, the trouble with which is
/// described below. The setting applies only to arenas created after it is set, so it has to beat the
/// first allocation: on Linux and FreeBSD it sits in `.init_array` and runs when the program is loaded,
/// before the Rust runtime allocates anything; elsewhere it is set at the start of main.
///
/// Freed memory goes back to the system after mimalloc's default delay (one second) rather than at
/// once. Purging at once makes most pages a new name touches ones that were just handed back and are
/// taken again, so nearly every query costs one more page fault and new names lose about a tenth of
/// their throughput; the memory it saves measured about 1 MiB (idle, after a GeoSite rule load test,
/// and with 200,000 cached answers alike). Purges that fall due are carried out by later allocations,
/// and a worker thread tidies up once more as it goes idle (see [`allocator_tuning::collect_when_idle`]).
///
/// On Linux transparent huge pages are also turned off for this process alone, leaving the system
/// setting as it is. With them, memory that was returned piecemeal and is touched again makes the
/// system zero a whole 2 MiB page, which stalls the event loop on a single core (an external load test
/// measured p99 in the hundreds of milliseconds with mimalloc's defaults). Without committing up front
/// mimalloc no longer asks for huge pages, but a system set to `always` hands them out unasked, so they
/// are turned off outright.
mod allocator_tuning {
    use std::cell::Cell;
    #[cfg(target_os = "linux")]
    use std::ffi::c_ulong;
    use std::ffi::{c_int, c_long};
    use std::time::{Duration, Instant};

    unsafe extern "C" {
        #[cfg(test)]
        fn mi_option_get(option: c_int) -> c_long;
        fn mi_option_set(option: c_int, value: c_long);
        fn mi_collect(force: bool);
    }

    /// 同一个工作线程两次整理之间至少隔多久 / The least time between two tidy-ups on one worker thread
    const COLLECT_EVERY: Duration = Duration::from_secs(1);

    thread_local! {
        /// 这个线程上次整理的时刻 / When this thread last tidied up
        static LAST_COLLECT: Cell<Option<Instant>> = const { Cell::new(None) };
    }

    /// tokio 工作线程没活、要停下来等的时候调用（`on_thread_park`）：离这个线程上次整理过了一秒，就让 mimalloc
    /// 整理一次这个线程的内存，把整页空出来的还给系统。
    ///
    /// mimalloc 的内存页归各线程所有，页空出来、到期归还，都是在这个线程之后的分配里顺带做的。一阵查询过去，
    /// 工作线程闲下来不再分配，这些就一直不做：在 256 MB 内存的 OpenWrt（musl、两个核）上，每秒 8000 个新名字、
    /// 上游 1.5 秒才回，压 15 秒，在用的内存约 40 MiB，进程却占着约 120 MiB，几分钟都不降；把归还延迟设成 0
    /// 也一样（约 110 MiB）。闲下来时整理一次，一秒内就降到在用的那么多。同一台机器上压未命中和命中，每个查询的
    /// CPU（约 51 和 14 微秒）、p99 和 p999 延迟，整理与否测不出差别：忙的时候线程停得少，停的时候正好没活，一秒
    /// 最多一次。不强制整理（`force` 为 false）就够了，强制的结果一样
    ///
    /// Called as a tokio worker thread runs out of work and parks (`on_thread_park`): once a second has
    /// passed since this thread last tidied up, mimalloc tidies up this thread's memory, giving whole
    /// freed pages back to the system.
    ///
    /// mimalloc's pages belong to threads, and freeing an emptied page and carrying out a purge that has
    /// fallen due both happen during that thread's later allocations. After a burst of queries the worker
    /// threads go quiet and stop allocating, so none of it happens: on OpenWrt with 256 MB of memory (musl,
    /// two cores), 15 seconds of 8,000 new names a second against an upstream answering after 1.5 seconds
    /// left about 40 MiB in use while the process held about 120 MiB, for minutes; a purge delay of 0 did
    /// the same (about 110 MiB). Tidying up as the thread goes idle brings it down to what is in use within
    /// a second. On the same machine the CPU per query (about 51 and 14 microseconds for misses and hits)
    /// and the p99 and p999 latencies measured the same with and without it: a busy thread parks seldom, a
    /// parking one has nothing else to do, and it happens at most once a second. A collection that is not
    /// forced (`force` false) is enough; a forced one measured the same
    pub(crate) fn collect_when_idle() {
        let now = Instant::now();
        let due = LAST_COLLECT.with(|last| {
            let due = collect_due(last.get(), now);
            if due {
                last.set(Some(now));
            }
            due
        });
        if due {
            // SAFETY: 只整理调用它的这个线程自己的内存，随时可以调 / Tidies up only the calling thread's own
            // memory, and may be called at any time
            unsafe { mi_collect(false) }
        }
    }

    /// 上次在 `last`，现在是 `now`，该不该整理 / Whether to tidy up at `now`, having last done so at `last`
    fn collect_due(last: Option<Instant>, now: Instant) -> bool {
        last.is_none_or(|last| now.saturating_duration_since(last) >= COLLECT_EVERY)
    }

    // mimalloc v3 `mi_option_e` 里的编号（libmimalloc-sys 自带的常量还是旧版本的）；依赖升级、编号变了时，
    // 下面的测试会报错 / Positions in mimalloc v3's `mi_option_e` (libmimalloc-sys still ships the old
    // constants); the test below fails should a dependency update move them
    /// `mi_option_purge_delay`：释放后多久归还系统，毫秒；保持默认值（见上）/ How long after a free memory
    /// is purged, in ms; left at its default (see above)
    #[cfg(test)]
    const PURGE_DELAY: c_int = 15;
    /// `mi_option_arena_eager_commit`：是否预先提交整块内存 / Whether whole arenas are committed up front
    const ARENA_EAGER_COMMIT: c_int = 4;

    // 测试程序里不装：下面的测试要读到选项的默认值 / Not installed in the test binary: the test below reads
    // the options' defaults
    #[cfg(all(not(test), any(target_os = "linux", target_os = "freebsd")))]
    #[used]
    #[unsafe(link_section = ".init_array")]
    static APPLY_ON_LOAD: extern "C" fn() = apply_on_load;

    #[cfg(all(not(test), any(target_os = "linux", target_os = "freebsd")))]
    extern "C" fn apply_on_load() {
        apply();
    }

    pub(crate) fn apply() {
        // SAFETY: 在程序装载时或 main 一开始调用，还没有别的线程；这个选项随时可以改
        // SAFETY: called while the program loads or at the very start of main, before any other thread
        // exists; the option may change at any time
        unsafe {
            mi_option_set(ARENA_EAGER_COMMIT, 0);
        }
        // 内核早于 3.15 时不认这个选项、返回错误，那就照旧 / Kernels before 3.15 reject the option, and
        // things stay as they were
        // SAFETY: 只改本进程的一个标记，不碰内存；参数按内核要求都是 unsigned long
        // SAFETY: only flips a flag of this process and touches no memory; every argument is an
        // unsigned long, as the kernel reads them
        #[cfg(target_os = "linux")]
        unsafe {
            libc::prctl(
                libc::PR_SET_THP_DISABLE,
                1 as c_ulong,
                0 as c_ulong,
                0 as c_ulong,
                0 as c_ulong,
            );
        }
    }

    #[cfg(test)]
    mod tests {
        #[cfg(target_os = "linux")]
        use super::c_ulong;
        use super::{
            ARENA_EAGER_COMMIT, COLLECT_EVERY, PURGE_DELAY, apply, collect_due, collect_when_idle,
            mi_option_get,
        };
        use std::time::Instant;

        /// 一个线程头一次停下就整理，之后一秒最多一次；整理本身随时可以调
        /// A thread tidies up the first time it parks and then at most once a second; the tidy-up itself
        /// may be called at any time
        #[test]
        fn an_idle_thread_tidies_up_at_most_once_a_second() {
            let now = Instant::now();
            assert!(collect_due(None, now));
            assert!(!collect_due(Some(now), now));
            assert!(!collect_due(Some(now), now + COLLECT_EVERY / 2));
            assert!(collect_due(Some(now), now + COLLECT_EVERY));
            assert!(
                !collect_due(Some(now + COLLECT_EVERY), now),
                "a clock read out of order waits"
            );
            let freed: Vec<Vec<u8>> = (0..1000).map(|_| vec![1; 4096]).collect();
            drop(freed);
            collect_when_idle();
            collect_when_idle();
        }

        /// 两个编号还对应这两个选项（默认值分别是 1000 毫秒和 2）；`apply` 把预先提交设成 0，归还延迟
        /// 留着默认值，在 Linux 上还关掉本进程的透明大页
        /// The two positions still name these options (their defaults are 1000 ms and 2); `apply` sets
        /// eager commit to 0, leaves the purge delay at its default, and on Linux also turns transparent
        /// huge pages off for the process
        #[test]
        fn allocator_tuning_is_found_and_applied() {
            // SAFETY: 只读选项 / Only reads the options
            let read = || unsafe {
                (
                    mi_option_get(PURGE_DELAY),
                    mi_option_get(ARENA_EAGER_COMMIT),
                )
            };
            assert_eq!(
                read(),
                (1_000, 2),
                "the defaults of purge_delay and arena_eager_commit"
            );
            apply();
            assert_eq!(read(), (1_000, 0), "the purge delay stays at its default");
            // SAFETY: 只读本进程的标记 / Only reads a flag of this process
            #[cfg(target_os = "linux")]
            assert_eq!(
                unsafe {
                    libc::prctl(
                        libc::PR_GET_THP_DISABLE,
                        0 as c_ulong,
                        0 as c_ulong,
                        0 as c_ulong,
                        0 as c_ulong,
                    )
                },
                1,
                "transparent huge pages are off for the process"
            );
        }
    }
}
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use kixdns::config::load_config_with_source;
use kixdns::engine::Engine;
use kixdns::listeners::BoundListeners;
use kixdns::matcher::RuntimePipelineConfig;
use kixdns::observe::{EngineObserver, TracingObserver};
#[cfg(unix)]
use kixdns::panel::PanelMetrics;
use kixdns::watcher;

#[derive(Parser, Debug)]
#[command(author, version, about = "KixDNS async DNS with hot-reload pipelines", long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run DNS server / 运行 DNS 服务器
    Run(RunArgs),
    /// 面板诊断的草稿试跑（面板内部使用）：从标准输入读请求、往标准输出写结果，不绑定任何端口
    /// Panel diagnostics' draft trial (internal): request on stdin, result on stdout, no port bound
    #[cfg(unix)]
    #[command(hide = true)]
    PanelTrial,
    /// Convert GeoIP .dat to MMDB format / 转换 GeoIP .dat 为 MMDB 格式
    ConvertGeoIp {
        /// 输入 .dat 文件路径 / Input .dat file path
        #[arg(short = 'i', long = "input")]
        input: PathBuf,
        /// 输出 MMDB 文件路径 / Output MMDB file path
        #[arg(short = 'o', long = "output")]
        output: PathBuf,
        /// 过滤国家代码（逗号分隔，如 CN,US,JP）/ Filter country codes (comma-separated, e.g., CN,US,JP)
        #[arg(short = 'f', long = "filter")]
        filter: Option<String>,
    },
}

impl Args {
    /// 要做的事：不带子命令就是不带参数的 `run`，默认值照 [`RunArgs`] 里写的取 / What to do: no
    /// subcommand is `run` with no arguments, taking the defaults [`RunArgs`] writes
    fn command(self) -> Commands {
        self.command
            .unwrap_or_else(|| Commands::Run(RunArgs::parse_from(["kixdns"])))
    }
}

/// `run` 的参数 / The arguments of `run`
#[derive(Parser, Debug)]
struct RunArgs {
    /// 配置文件路径（JSON） / Config file path (JSON)
    #[arg(short = 'c', long = "config", default_value = "config/pipeline.json")]
    config: PathBuf,
    /// 监听实例标签，用于 pipeline 选择（可选）。 / Listener instance label for pipeline selection (optional)
    #[arg(long = "listener-label", default_value = "default")]
    listener_label: String,
    /// 启用调试日志 / Enable debug logging
    #[arg(long = "debug", default_value_t = false)]
    debug: bool,
    /// UDP worker 数量（默认 CPU 核心数） / Number of UDP workers (defaults to CPU core count)
    #[arg(long = "udp-workers", default_value_t = 0)]
    udp_workers_count: usize,
    /// 本机管理 Socket；不设置时禁用增强管理接口。 / Local panel control socket; disabled when omitted.
    // 控制通道只有 Unix 上有（见 lib.rs）：别的系统没有这个参数，写了 clap 就拒绝 / Only Unix has the control
    // socket (see lib.rs): elsewhere there is no such argument, and clap refuses it
    #[cfg(unix)]
    #[arg(long = "admin-socket")]
    admin_socket: Option<PathBuf>,
}

fn main() {
    #[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
    allocator_tuning::apply();
    // 先装 panic 钩子再做任何事：journald 只按每行开头的 `<N>` 定优先级，而默认 panic 输出和
    // `Termination` 打印的 `Error: …` 都没有前缀，会被记成 info（6），面板只看 ≤3 的错误过滤器
    // 恰好把“为什么没启动”这一行藏掉。
    // Install the panic hook before anything else: journald assigns priority only from a
    // leading `<N>` per line, and neither the default panic output nor the `Error: …` that
    // `Termination` prints carries one, so both land at info (6) and the panel's ≤3 error
    // filter hides exactly the line that explains why KixDNS did not start.
    install_panic_hook();
    if let Err(err) = real_main() {
        let _ = writeln!(std::io::stderr(), "{}", fatal_report(&err));
        std::process::exit(1);
    }
}

fn real_main() -> anyhow::Result<()> {
    // 防御性关闭启动链遗传的 fd：OPNsense boot 时序的 daemon/configd 链可能遗传数万个
    // 构建/部署 fd（2026-08-30 事故：fd 水位 90%，28180 个已删除构建产物文件的句柄被遗传且持有 3 天）。
    // Defensively close fds inherited from the startup chain: the OPNsense boot sequence
    // (daemon/configd/build processes) can leak tens of thousands of inherited fds into the
    // process (2026-08-30 incident: 28180 fds pointing to deleted build artifacts held for 3 days).
    // 注意：closefrom 必须先于 tokio runtime 创建执行——runtime 的 kqueue/定时器 fd 从 3 号
    // （closefrom 后的最低可用号）起分配，晚关会误杀。因此这里不能使用 #[tokio::main]，手动构建 runtime。
    // Note: closefrom must run before the tokio runtime is created (its kqueue/timer fds are
    // allocated from 3, the lowest free fd after closefrom), so #[tokio::main] cannot be used here; build manually.
    #[cfg(target_os = "freebsd")]
    unsafe {
        // 保留 0/1/2 stdio；closefrom 为 FreeBSD 原生系统调用（手册页 closefrom(2)）。
        // Keep stdio only; closefrom is a native FreeBSD syscall (see man closefrom(2)).
        libc::closefrom(3);
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .on_thread_park(allocator_tuning::collect_when_idle)
        .build()
        .context("build tokio runtime")?
        .block_on(async_main())
}

async fn async_main() -> anyhow::Result<()> {
    match Args::parse().command() {
        #[cfg(unix)]
        Commands::PanelTrial => kixdns::panel::trial_from_stdio().await,
        Commands::ConvertGeoIp {
            input,
            output,
            filter,
        } => {
            // Convert GeoIP .dat to MMDB
            let filter_countries: Option<Vec<String>> =
                filter.map(|f| f.split(',').map(|s| s.trim().to_uppercase()).collect());

            let filter_slice = filter_countries.as_deref();

            // 失败时由 main 连同原因链打出来：这里还没装日志 / A failure is printed by main with its
            // cause chain: no logging is installed here
            let stats = kixdns::matcher::geoip_converter::convert_dat_to_mmdb(
                &input,
                &output,
                filter_slice,
            )?;
            println!("Conversion completed successfully:\n{}", stats);
            Ok(())
        }
        Commands::Run(args) => run_dns_server(args).await,
    }
}

/// 运行 DNS 服务器 / Run DNS server
async fn run_dns_server(
    RunArgs {
        config,
        listener_label,
        debug,
        udp_workers_count,
        #[cfg(unix)]
        admin_socket,
    }: RunArgs,
) -> anyhow::Result<()> {
    // Run DNS server
    init_tracing(debug);

    // Install default CryptoProvider for rustls
    // 安装 rustls 的默认 CryptoProvider
    // This is required for rustls 0.23+ when multiple crypto backends are available
    // 当有多个加密后端可用时，rustls 0.23+ 需要此调用
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install rustls crypto provider"))?;

    // 读配置之前先装好配置文件的监视，读的时候文件又改了也不会漏（见 `watcher::ConfigWatch`）
    // The configuration file is watched before it is read, so a change made while it is read is
    // not missed (see `watcher::ConfigWatch`)
    let watch = watcher::ConfigWatch::new(&config);
    let (cfg, config_source) = load_config_with_source(&config).context("load initial config")?;
    // 启动时照旧加载，升级以后已经在用的配置行为不变；重载和面板的校验会拒绝它们。和重载拒绝时一样记 error，
    // 默认日志级别就看得到：以前只记 warn，默认级别下谁也不知道下一次改配置会被拒
    // Startup loads them as before, so a configuration in use keeps its behaviour across an
    // upgrade; a reload and the panel's validation refuse them. They are logged at error, as
    // the reload refusing them is, so the default log level shows them: they used to be a
    // warn, and at the default level nobody learnt that the next change would be refused
    let problems = kixdns::config::problems(&cfg);
    let version = cfg.version.clone();
    for problem in &problems {
        error!(%problem, "configuration problem, loaded as before; a reload or a save from the panel refuses it");
    }
    let cfg = RuntimePipelineConfig::from_config(cfg).context("compile matchers")?;
    // Listener addresses and DoH prerequisites, checked exactly as
    // config::validate does / 监听地址与 DoH 前置条件，检查方式与 config::validate 一致
    let listeners = cfg.settings.listeners()?;
    let bind_addr = listeners.udp;
    let bind_tcp = listeners.tcp;

    // UDP worker 数量：默认为 CPU 核心数，最少 1 个 / UDP worker count: defaults to CPU core count, minimum 1
    let udp_workers_final = if udp_workers_count > 0 {
        udp_workers_count
    } else {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    };

    // 先占住监听端口，再建引擎：引擎要打开一批上游 socket，系统给它们挑的端口可能正好是要监听的那个，内核就起不来了。
    // 建引擎这一小段时间里来的查询排在 socket 里，建好就答
    // The listening ports are taken before the engine is built: it opens a batch of upstream sockets, and
    // the ports the system picks for them may be the very one to listen on, and the kernel would not start.
    // Queries arriving while the engine is built wait in the sockets and are answered once it is ready
    let bound = BoundListeners::bind(listeners, udp_workers_final)?;

    // 面板的统计只能经控制通道读，所以只在开了控制通道时装面板观察者；控制通道只有 Unix 上有（见 lib.rs）/ The
    // panel's statistics can only be read over the control socket, so the panel observer is
    // installed only with one; only Unix has the control socket (see lib.rs)
    #[cfg(unix)]
    let panel_metrics = admin_socket
        .as_ref()
        .map(|_| Arc::new(PanelMetrics::new(debug)));
    // 面板经控制通道读上面那些问题（`config` 的 `problems`）和入站 DoH 为什么没起来（`doh_error`）/ The
    // panel reads the problems above over the control channel (`config`'s `problems`), and why the
    // inbound DoH did not start (`doh_error`)
    #[cfg(unix)]
    if let Some(metrics) = &panel_metrics {
        metrics.startup_problems(problems);
        if let Some(error) = bound.doh_error() {
            metrics.doh_not_started(error.to_owned());
        }
    }
    #[cfg(unix)]
    let panel_observer = panel_metrics
        .clone()
        .map(|metrics| metrics as Arc<dyn EngineObserver>);
    #[cfg(not(unix))]
    let panel_observer = None;
    let mut engine = Engine::builder(cfg)
        .listener_label(listener_label.clone())
        .config_source(&config, config_source);
    if let Some(observer) = engine_observer(panel_observer, debug) {
        engine = engine.observer(observer);
    }
    let engine = engine.build().context("initialize DNS engine")?;

    // 监视不了时配置文件改了不会重载，面板保存的配置也不生效：记一条 error，默认日志级别看得到，面板经控制通道读
    // （`config` 的 `watch_error`）
    // Without the watch a change to the configuration file is not reloaded, nor is a save from
    // the panel applied: an error is logged, seen at the default log level, and the panel reads
    // it over the control channel (`config`'s `watch_error`)
    let _config_watch = watch
        .and_then(|watch| watch.start(engine.clone()))
        .inspect_err(|err| {
            error!(path = %config.display(), error = %err, "cannot watch the config file, changes to it are not reloaded");
            #[cfg(unix)]
            if let Some(metrics) = &panel_metrics {
                metrics.config_not_watched(err.to_string());
            }
        })
        .ok();

    info!(bind_udp = %bind_addr, bind_tcp = %bind_tcp, udp_workers_count = udp_workers_final, config_version = version, "dns server started");

    let mut all_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    #[cfg(unix)]
    if let (Some(path), Some(panel_metrics)) = (admin_socket, panel_metrics) {
        let engine = engine.clone();
        all_handles.push(tokio::spawn(async move {
            if let Err(err) = kixdns::panel::serve_admin(path, engine, panel_metrics).await {
                error!(error = %format!("{err:#}"), "panel control socket exited");
            }
        }));
    }

    // 流控按设备分时要认出和内核在同一个网段上的 IPv6 主机（见 `fair_queue::note_local_networks`）：隔一阵看一次本机网卡的
    // 地址，换了网段跟着换 / Flow control, going by device, tells the IPv6 hosts on the kernel's own
    // network (see `fair_queue::note_local_networks`): the interfaces' addresses are looked at
    // now and then, following any new network
    if engine.flow_control_state.is_some() {
        tokio::spawn(async {
            loop {
                kixdns::engine::fair_queue::note_local_networks(
                    &kixdns::socket_utils::local_ipv6_networks(),
                );
                tokio::time::sleep(LOCAL_NETWORKS_LOOKED_AT).await;
            }
        });
    }

    bound.serve(&engine, &mut all_handles);

    // 等待所有任务 / Wait for all tasks
    for h in all_handles {
        let _ = h.await;
    }

    Ok(())
}

/// 隔这么久看一次本机网卡上的 IPv6 地址：重新拨号换了网段，最多这么久以后跟上 / How often this machine's IPv6
/// addresses are looked at: after a redial brings another network, it follows within this long
const LOCAL_NETWORKS_LOOKED_AT: Duration = Duration::from_secs(30);

/// 引擎的观察者：有面板时是面板观察者，`--debug` 的事件由它转发；没有面板时和上游一样，
/// 只有 `--debug` 才装参考观察者，否则不装，请求不付任何观察的开销
/// The engine's observer: with the panel, the panel observer, which forwards the `--debug`
/// events itself; without the panel, as upstream, the reference observer only with `--debug`
/// and otherwise none, so requests pay nothing for observation
fn engine_observer(
    panel: Option<Arc<dyn EngineObserver>>,
    debug: bool,
) -> Option<Arc<dyn EngineObserver>> {
    panel.or_else(|| debug.then(|| Arc::new(TracingObserver) as Arc<dyn EngineObserver>))
}

fn init_tracing(debug: bool) {
    let (filter, unreadable) = log_filter(std::env::var(EnvFilter::DEFAULT_ENV).ok(), debug);
    let registry = tracing_subscriber::registry().with(filter);
    if stdout_is_journald() {
        // journald 自己记时间，优先级靠行首的 `<N>` 前缀，行里的时间和级别只是给人看的，照旧
        // journald keeps its own timestamps and takes the priority from the `<N>` prefix, so the
        // time and level inside the line are for people only and stay as they were
        let format = fmt::format()
            .with_timer(fmt::time::LocalTime::rfc_3339())
            .with_target(false)
            .with_ansi(false)
            .with_level(debug);
        registry
            .with(fmt::layer().event_format(JournalPriority(format)))
            .init();
    } else {
        registry
            .with(fmt::layer().event_format(plain_log_format()))
            .init();
    }
    if let Some(error) = unreadable {
        error!(%error, "RUST_LOG is not a log filter, logging at the default level instead");
    }
}

/// 日志过滤：设了 RUST_LOG（`rust_log`，空的当没设）就照它，否则只记 error；`--debug` 时 KixDNS 自己记到 debug，依赖（h2、hyper、
/// rustls、quinn）只到 warn，免得淹在它们的 debug 里。RUST_LOG 写错时也用默认的，连同为什么读不了一起交回来，日志装好
/// 以后记一条 error：以前悄悄退回 error 级别，看着就像设了没用
/// The log filter: RUST_LOG (`rust_log`, empty taken as unset) when set, error alone otherwise; with `--debug` KixDNS
/// itself logs down to debug and its dependencies (h2, hyper, rustls, quinn) to warn, so as not
/// to drown in their debug. A RUST_LOG written wrong gets the default too, handed back with why
/// it cannot be read, to be logged as an error once logging is in place: it used to fall back to
/// the error level in silence, looking as if setting it did nothing
fn log_filter(
    rust_log: Option<String>,
    debug: bool,
) -> (EnvFilter, Option<tracing_subscriber::filter::ParseError>) {
    let default = || EnvFilter::new(if debug { "kixdns=debug,warn" } else { "error" });
    match rust_log.filter(|directives| !directives.trim().is_empty()) {
        None => (default(), None),
        Some(directives) => match EnvFilter::try_new(directives) {
            Ok(filter) => (filter, None),
            Err(error) => (default(), Some(error)),
        },
    }
}

/// 不接 journald 时每行日志的格式（终端，或者 OpenWrt 上 procd 把输出写进文件）：UTC 的
/// RFC 3339 时间、级别、消息，比如 `2026-11-22T07:00:00.123456Z ERROR upstream exploded`。
/// 没有 journald 记优先级和时间，级别和时间就只能写在行里：面板的 procd 后端读日志文件时，
/// 级别取时间后面的第一个词。时间用 UTC，读的一方不用管时区。
/// The line format when stdout is not journald (a terminal, or a file procd writes on
/// `OpenWrt`): an RFC 3339 time in UTC, the level, the message, such as
/// `2026-11-22T07:00:00.123456Z ERROR upstream exploded`. With no journald to record the
/// priority and time, both have to be in the line: the panel's procd backend reads the log
/// file taking the first word after the time as the level. The time is in UTC, so a reader
/// need not know the time zone.
fn plain_log_format<S, N>() -> impl fmt::FormatEvent<S, N>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    N: for<'a> fmt::FormatFields<'a> + 'static,
{
    fmt::format()
        .with_timer(fmt::time::UtcTime::rfc_3339())
        .with_target(false)
        .with_ansi(false)
        .with_level(true)
}

/// journald 只解析每行开头的优先级前缀，所以致命错误必须压成一行；换行会让后半段掉回 info。
/// journald parses the priority prefix per line, so a fatal report must be flattened to one
/// line; an embedded newline would drop the tail back to info.
fn flatten_line(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// `{err:#}` 把整条 cause 链用 `: ` 接在同一行，journald 才能在一条 err 记录里看到完整原因。
/// `{err:#}` joins the whole cause chain with `: ` on one line so a single journald err
/// record carries the full reason.
fn fatal_line(err: &anyhow::Error) -> String {
    flatten_line(&format!("<3>fatal: {err:#}"))
}

/// 终端下保持 Rust `Termination` 原本的 `Error: {err:?}` 输出，不改变旧有排查习惯。
/// On a terminal keep the `Error: {err:?}` output Rust's `Termination` used to print, so
/// existing troubleshooting habits still work.
fn fatal_report(err: &anyhow::Error) -> String {
    if stdout_is_journald() {
        fatal_line(err)
    } else {
        format!("Error: {err:?}")
    }
}

/// panic 用 crit（2）：它比普通 err 更严重，release 配置下紧接着就是 abort。
/// A panic is crit (2): worse than an ordinary err, and under the release profile it is
/// immediately followed by abort.
fn panic_line(location: Option<&std::panic::Location<'_>>, message: &str) -> String {
    let mut line = String::from("<2>panicked");
    if let Some(location) = location {
        line.push_str(&format!(
            " at {}:{}:{}",
            location.file(),
            location.line(),
            location.column()
        ));
    }
    line.push_str(": ");
    line.push_str(message);
    flatten_line(&line)
}

/// `panic!` 的载荷只有 `&str`（字面量）和 `String`（格式化）两种常见形态，其余无法呈现。
/// A `panic!` payload is normally either `&str` (literal) or `String` (formatted); anything
/// else cannot be rendered.
fn panic_message(payload: &(dyn Any + Send)) -> &str {
    if let Some(message) = payload.downcast_ref::<&str>() {
        message
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.as_str()
    } else {
        "Box<dyn Any>"
    }
}

/// 只在 journald 下接管：终端里仍交给原钩子，保留带 backtrace 提示的标准输出。
/// Only takes over under journald; on a terminal the previous hook keeps the standard
/// output with its backtrace hint.
fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if stdout_is_journald() {
            let line = panic_line(info.location(), panic_message(info.payload()));
            let _ = writeln!(std::io::stderr(), "{line}");
        } else {
            previous(info);
        }
    }));
}

/// systemd 把 stdout 接到 journald 时会设置 JOURNAL_STREAM。
/// systemd sets JOURNAL_STREAM when stdout is connected to journald.
fn stdout_is_journald() -> bool {
    std::env::var_os("JOURNAL_STREAM").is_some()
}

/// 给每行日志加上 journald 识别的 `<N>` 优先级前缀，否则 journald 会把所有行都记为 info，
/// 日志工具就无法按 warn / error 筛选。
/// Prefix each line with the syslog priority journald parses; without it every line lands
/// at priority 6 (info) and log viewers cannot filter warnings or errors.
struct JournalPriority<F>(F);

impl<S, N, F> fmt::FormatEvent<S, N> for JournalPriority<F>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    N: for<'a> fmt::FormatFields<'a> + 'static,
    F: fmt::FormatEvent<S, N>,
{
    fn format_event(
        &self,
        ctx: &fmt::FmtContext<'_, S, N>,
        mut writer: fmt::format::Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        write!(writer, "<{}>", journal_priority(*event.metadata().level()))?;
        self.0.format_event(ctx, writer, event)
    }
}

fn journal_priority(level: tracing::Level) -> u8 {
    match level {
        tracing::Level::ERROR => 3,
        tracing::Level::WARN => 4,
        tracing::Level::INFO => 6,
        _ => 7,
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for SharedBuffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedBuffer {
        type Writer = SharedBuffer;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// journald 前缀按级别映射到 syslog 优先级，每行恰好一个前缀。
    #[test]
    fn journal_priority_prefixes_each_line_by_level() {
        use tracing_subscriber::layer::SubscriberExt;

        let buffer = SharedBuffer::default();
        let format = tracing_subscriber::fmt::format()
            .without_time()
            .with_target(false)
            .with_ansi(false)
            .with_level(false);
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .event_format(super::JournalPriority(format))
                .with_writer(buffer.clone()),
        );
        tracing::subscriber::with_default(subscriber, || {
            tracing::error!("upstream exploded");
            tracing::warn!(upstream = "1.1.1.1:53", "single upstream call failed");
            tracing::info!("config reloaded");
            tracing::debug!("noisy");
        });
        buffer.clone().flush().unwrap();
        let output = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        let lines = output.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 4, "{output}");
        assert!(lines[0].starts_with("<3>") && lines[0].contains("upstream exploded"));
        assert!(lines[1].starts_with("<4>") && lines[1].contains("single upstream call failed"));
        assert!(lines[2].starts_with("<6>") && lines[2].contains("config reloaded"));
        assert!(lines[3].starts_with("<7>"));
        assert_eq!(super::journal_priority(tracing::Level::TRACE), 7);
    }

    /// 不接 journald 时每行是「UTC 时间 级别 消息」：面板的 procd 后端按时间后面的第一个词认级别，
    /// 时间以 Z 结尾。
    /// Without journald each line is "UTC time, level, message": the panel's procd backend
    /// takes the first word after the time as the level, and the time ends in Z.
    #[test]
    fn plain_lines_carry_utc_time_and_level() {
        use tracing_subscriber::layer::SubscriberExt;

        let buffer = SharedBuffer::default();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .event_format(super::plain_log_format())
                .with_writer(buffer.clone()),
        );
        tracing::subscriber::with_default(subscriber, || {
            tracing::error!("upstream exploded");
            tracing::warn!(upstream = "1.1.1.1:53", "single upstream call failed");
            tracing::info!("config reloaded");
        });
        let output = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        let lines = output.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 3, "{output}");
        for (line, level, message) in [
            (lines[0], "ERROR", "upstream exploded"),
            (lines[1], "WARN", "single upstream call failed"),
            (lines[2], "INFO", "config reloaded"),
        ] {
            let mut words = line.split_whitespace();
            let time = words.next().unwrap_or_default();
            assert!(
                time.len() >= 20 && time.as_bytes()[4] == b'-' && time.ends_with('Z'),
                "{line}"
            );
            assert_eq!(words.next(), Some(level), "{line}");
            assert!(line.contains(message), "{line}");
        }
    }

    /// 致命错误一行 `<3>fatal:`，cause 链完整，消息里的换行被压平。
    #[test]
    fn fatal_line_is_one_err_line_with_cause_chain() {
        let err = anyhow::anyhow!("No such file or directory")
            .context("read /nonexistent.json")
            .context("load initial config");
        let line = super::fatal_line(&err);
        assert_eq!(
            line,
            "<3>fatal: load initial config: read /nonexistent.json: No such file or directory"
        );

        let err = anyhow::anyhow!("first line\nsecond line\n").context("outer");
        let line = super::fatal_line(&err);
        assert!(!line.contains('\n'), "{line}");
        assert_eq!(line, "<3>fatal: outer: first line second line");

        let terminal = format!("{:?}", anyhow::anyhow!("boom").context("outer"));
        assert!(terminal.starts_with("outer"), "{terminal}");
    }

    /// panic 一行 `<2>panicked at file:line:col: message`，没有位置时也不产生第二行。
    #[test]
    fn panic_line_is_one_crit_line() {
        let location = std::panic::Location::caller();
        let line = super::panic_line(Some(location), "index out of bounds\nmore");
        assert!(!line.contains('\n'), "{line}");
        assert_eq!(
            line,
            format!(
                "<2>panicked at {}:{}:{}: index out of bounds more",
                location.file(),
                location.line(),
                location.column()
            )
        );
        assert_eq!(super::panic_line(None, "boom"), "<2>panicked: boom");
    }

    /// `panic!("literal")` 和 `panic!("{}", value)` 的载荷类型不同，两种都要能取出消息。
    #[test]
    fn panic_message_reads_str_and_string_payloads() {
        let literal: Box<dyn std::any::Any + Send> = Box::new("literal payload");
        assert_eq!(super::panic_message(literal.as_ref()), "literal payload");
        let formatted: Box<dyn std::any::Any + Send> = Box::new(String::from("formatted 42"));
        assert_eq!(super::panic_message(formatted.as_ref()), "formatted 42");
        let opaque: Box<dyn std::any::Any + Send> = Box::new(42u8);
        assert_eq!(super::panic_message(opaque.as_ref()), "Box<dyn Any>");
    }

    /// 不设 RUST_LOG（或设成空的）时只记 error，`--debug` 时 KixDNS 自己记到 debug、依赖只到 warn；设了就照它。写错了
    /// 的照默认的记，交回为什么读不了。以前写错时悄悄退回 error 级别，`--debug` 把 h2、hyper、rustls 也开到 debug
    /// Without RUST_LOG (or with it empty) only errors are logged, and with `--debug` KixDNS itself
    /// down to debug and its dependencies to warn; when set, as it says. One written wrong logs by
    /// the default, handed back with why it cannot be read. It used to fall back to the error level
    /// in silence, and `--debug` turned h2, hyper and rustls to debug too
    #[test]
    fn the_log_filter_reads_rust_log_and_says_when_it_cannot() {
        let filter = |rust_log: Option<&str>, debug| {
            let (filter, error) = super::log_filter(rust_log.map(str::to_owned), debug);
            (filter.to_string(), error.is_some())
        };
        assert_eq!(filter(None, false), ("error".to_owned(), false));
        assert_eq!(filter(Some(" "), false), ("error".to_owned(), false));
        let (debug, unreadable) = filter(None, true);
        assert!(!unreadable);
        let mut directives: Vec<&str> = debug.split(',').collect();
        directives.sort_unstable();
        assert_eq!(directives, ["kixdns=debug", "warn"]);
        assert_eq!(
            filter(Some("kixdns::engine::phases=info"), true),
            ("kixdns::engine::phases=info".to_owned(), false)
        );
        assert_eq!(
            filter(Some("kixdns=loud"), false),
            ("error".to_owned(), true)
        );
    }

    /// 不带子命令和不带参数的 `run` 一样，默认值只写在 `RunArgs` 里 / No subcommand is the same as
    /// `run` with no arguments, the defaults written in `RunArgs` alone
    #[test]
    fn no_subcommand_runs_with_the_defaults_of_run() {
        use clap::Parser as _;
        let command = |args: &[&str]| format!("{:?}", super::Args::parse_from(args).command());
        assert_eq!(command(&["kixdns"]), command(&["kixdns", "run"]));
        assert!(
            command(&["kixdns"]).contains("config/pipeline.json"),
            "{}",
            command(&["kixdns"])
        );
    }

    /// `--admin-socket` 只有 Unix 上有：别的系统没有控制通道，写了 clap 就拒绝，`--help` 也不列
    /// `--admin-socket` is there on Unix alone: elsewhere there is no control socket, clap refuses
    /// the argument and `--help` does not list it
    #[test]
    fn the_admin_socket_is_an_argument_on_unix_alone() {
        use clap::{CommandFactory as _, Parser as _};
        let parsed =
            super::Args::try_parse_from(["kixdns", "run", "--admin-socket", "kixdns.sock"]);
        assert_eq!(parsed.is_ok(), cfg!(unix), "{parsed:?}");
        let help = super::RunArgs::command().render_help().to_string();
        assert_eq!(help.contains("--admin-socket"), cfg!(unix), "{help}");
    }

    /// 没有面板时和上游一样：不带 `--debug` 不装观察者，带了装参考观察者；有面板时装的就是面板观察者
    /// Without the panel, as upstream: no observer without `--debug` and the reference observer
    /// with it; with the panel, the panel observer itself
    #[cfg(unix)]
    #[test]
    fn only_the_panel_brings_the_panel_observer() {
        assert!(super::engine_observer(None, false).is_none());
        assert!(super::engine_observer(None, true).is_some());
        let panel = Arc::new(super::PanelMetrics::new(false));
        for debug in [false, true] {
            let observer = super::engine_observer(Some(panel.clone()), debug).unwrap();
            assert!(std::ptr::addr_eq(
                Arc::as_ptr(&observer),
                Arc::as_ptr(&panel)
            ));
        }
    }
}
