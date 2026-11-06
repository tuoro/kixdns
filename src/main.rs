use std::any::Any;
use std::io::Write as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use bytes::{Bytes, BytesMut};
use clap::{Parser, Subcommand};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};

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
/// （空闲时、GeoSite 规则压测后、20 万条缓存压满后都是）。到期的归还在之后的分配里顺带完成。
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
/// and with 200,000 cached answers alike). Purges that fall due are carried out by later allocations.
///
/// On Linux transparent huge pages are also turned off for this process alone, leaving the system
/// setting as it is. With them, memory that was returned piecemeal and is touched again makes the
/// system zero a whole 2 MiB page, which stalls the event loop on a single core (an external load test
/// measured p99 in the hundreds of milliseconds with mimalloc's defaults). Without committing up front
/// mimalloc no longer asks for huge pages, but a system set to `always` hands them out unasked, so they
/// are turned off outright.
mod allocator_tuning {
    #[cfg(target_os = "linux")]
    use std::ffi::c_ulong;
    use std::ffi::{c_int, c_long};

    unsafe extern "C" {
        #[cfg(test)]
        fn mi_option_get(option: c_int) -> c_long;
        fn mi_option_set(option: c_int, value: c_long);
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
        use super::{ARENA_EAGER_COMMIT, PURGE_DELAY, apply, mi_option_get};

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
use tracing::{debug, error, info, warn};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use kixdns::config::{DohListenerConfig, ListenerConfig, load_config_with_source};
use kixdns::engine::concurrency::QUEUE_TARGET;
#[cfg(target_os = "linux")]
use kixdns::engine::fair_queue::{Device, FairQueue};
use kixdns::engine::{Engine, FastPathResponse, PreParsedData, engine_helpers, write_cache_hit};
use kixdns::matcher::RuntimePipelineConfig;
use kixdns::observe::{ClientTransport, EngineObserver, TracingObserver};
use kixdns::panel::PanelMetrics;
use kixdns::proto_utils::{is_standard_query_header, truncate_udp_response};
#[cfg(target_os = "linux")]
use kixdns::socket_utils::udp_batch;
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
    Run {
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
        #[arg(long = "admin-socket")]
        admin_socket: Option<PathBuf>,
    },
    /// 面板诊断的草稿试跑（面板内部使用）：从标准输入读请求、往标准输出写结果，不绑定任何端口
    /// Panel diagnostics' draft trial (internal): request on stdin, result on stdout, no port bound
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
        .build()
        .context("build tokio runtime")?
        .block_on(async_main())
}

async fn async_main() -> anyhow::Result<()> {
    let args = Args::parse();

    match args.command {
        Some(Commands::PanelTrial) => kixdns::panel::trial_from_stdio().await,
        Some(Commands::ConvertGeoIp {
            input,
            output,
            filter,
        }) => {
            // Convert GeoIP .dat to MMDB
            let filter_countries: Option<Vec<String>> =
                filter.map(|f| f.split(',').map(|s| s.trim().to_uppercase()).collect());

            let filter_slice = filter_countries.as_deref();

            match kixdns::matcher::geoip::GeoIpManager::convert_dat_to_mmdb(
                &input,
                &output,
                filter_slice,
            ) {
                Ok(stats) => {
                    println!("Conversion completed successfully:\n{}", stats);
                    Ok(())
                }
                Err(e) => {
                    error!("Conversion failed: {}", e);
                    Err(e)
                }
            }
        }
        Some(Commands::Run {
            config,
            listener_label,
            debug,
            udp_workers_count,
            admin_socket,
        }) => {
            run_dns_server(
                config,
                listener_label,
                debug,
                udp_workers_count,
                admin_socket,
            )
            .await
        }
        None => {
            // No subcommand provided - run DNS server with defaults
            run_dns_server(
                PathBuf::from("config/pipeline.json"),
                "default".to_string(),
                false,
                0,
                None,
            )
            .await
        }
    }
}

/// 运行 DNS 服务器 / Run DNS server
/// 提取公共逻辑以消除代码重复 / Extract common logic to eliminate code duplication
async fn run_dns_server(
    config: PathBuf,
    listener_label: String,
    debug: bool,
    udp_workers_count: usize,
    admin_socket: Option<PathBuf>,
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

    let (cfg, config_source) = load_config_with_source(&config).context("load initial config")?;
    // 启动时只记警告、照旧加载，升级以后已经在用的配置行为不变；重载和面板的校验会拒绝它们
    // Startup only warns and loads as before, so a configuration in use keeps its
    // behaviour across an upgrade; a reload and the panel's validation refuse these
    for problem in kixdns::config::problems(&cfg) {
        warn!(%problem, "configuration problem, loaded as before; a reload or a save from the panel refuses it");
    }
    kixdns::config::warn_ignored_settings(&cfg);
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
    let bound = BoundListeners::bind(listeners, udp_workers_final).await?;

    // 面板的统计只能经控制通道读，所以只在开了控制通道时装面板观察者 / The panel's statistics can
    // only be read over the control socket, so the panel observer is installed only with one
    let panel_metrics = admin_socket
        .as_ref()
        .filter(|_| cfg!(unix))
        .map(|_| Arc::new(PanelMetrics::new(debug)));
    let mut engine = Engine::builder(cfg)
        .listener_label(listener_label.clone())
        .config_source(&config, config_source);
    if let Some(observer) = engine_observer(panel_metrics.as_ref(), debug) {
        engine = engine.observer(observer);
    }
    let engine = engine.build().context("initialize DNS engine")?;

    watcher::spawn(config.clone(), engine.clone());

    info!(bind_udp = %bind_addr, bind_tcp = %bind_tcp, udp_workers_count = udp_workers_final, "dns server started");

    let mut all_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    #[cfg(unix)]
    if let (Some(path), Some(panel_metrics)) = (admin_socket, panel_metrics) {
        let engine = engine.clone();
        all_handles.push(tokio::spawn(async move {
            if let Err(err) = kixdns::panel::serve_admin(path, engine, panel_metrics).await {
                error!(target = "panel", error = %err, "panel control socket exited");
            }
        }));
    }

    #[cfg(not(unix))]
    if admin_socket.is_some() {
        warn!(
            target = "panel",
            "admin-socket is not supported on this platform"
        );
    }

    bound.serve(&engine, &mut all_handles);

    // 等待所有任务 / Wait for all tasks
    for h in all_handles {
        let _ = h.await;
    }

    Ok(())
}

/// 绑定好、还没开始答的 UDP socket，每个 worker 一个 / UDP sockets bound and not answering yet, one per worker
struct BoundUdp {
    addr: SocketAddr,
    family: &'static str,
    sockets: Vec<Arc<UdpSocket>>,
}

/// 绑定好、还没开始答的监听口 / Listeners bound and not answering yet
struct BoundListeners {
    udp: Vec<BoundUdp>,
    tcp: Vec<(TcpListener, &'static str)>,
    doh: Option<(TcpListener, DohListenerConfig)>,
}

impl BoundListeners {
    async fn bind(listeners: ListenerConfig, udp_workers: usize) -> anyhow::Result<Self> {
        let ListenerConfig {
            udp: bind_addr,
            tcp: bind_tcp,
            doh,
        } = listeners;
        let mut udp = Vec::new();

        #[cfg(unix)]
        {
            // ✅ OpenBSD 兼容性方案：双 socket（IPv4 + IPv6）+ 零拷贝 recv_buf_from
            // ✅ OpenBSD compatibility: dual sockets (IPv4 + IPv6) + zero-copy recv_buf_from
            // 为每个地址族创建独立的 socket 和 workers，避免 sockaddr 大小断言失败
            // Create separate sockets and workers for each address family to avoid sockaddr size assertion failures

            // 根据配置地址决定创建哪种 socket / Determine which socket type to create based on config
            // IPv6 unspecified address (::) 需要同时创建 IPv4 和 IPv6 socket
            // IPv6 other addresses 只创建 IPv6 socket
            // IPv4 addresses 只创建 IPv4 socket
            let ipv4_addr = ipv4_listen_addr(bind_addr);
            let needs_ipv6 = bind_addr.is_ipv6();
            let workers_per_family = if ipv4_addr.is_some() && needs_ipv6 {
                udp_workers.div_ceil(2)
            } else {
                udp_workers
            };

            if let Some(ipv4_addr) = ipv4_addr {
                udp.push(bind_udp_workers(ipv4_addr, workers_per_family)?);
            }

            if needs_ipv6 {
                udp.push(bind_udp_workers(bind_addr, workers_per_family)?);
            }
        }

        #[cfg(not(unix))]
        udp.push(bind_udp_workers(bind_addr, udp_workers)?);

        // TCP listener / TCP 监听器
        // ✅ 双 socket 方案，与 UDP 行为一致 / Dual-socket approach, consistent with UDP
        let mut tcp = Vec::new();
        // --- 启动 IPv4 TCP 监听 / Start IPv4 TCP listener ---
        if let Some(addr) = ipv4_listen_addr(bind_tcp) {
            // 纯 IPv4 绑定，不受 bindv6only 影响 / Pure IPv4 bind, unaffected by bindv6only
            let listener = TcpListener::bind(addr).await.context("bind ipv4 tcp")?;
            tcp.push((listener, "ipv4"));
        }

        // --- 启动 IPv6 TCP 监听 / Start IPv6 TCP listener ---
        if bind_tcp.is_ipv6() {
            use socket2::{Domain, Protocol, Socket, Type};
            let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;

            // ⭐️ 核心：强制 IPV6_V6ONLY=1，避免和 IPv4 监听器冲突
            // ⭐️ Key: force IPV6_V6ONLY=1 to avoid conflict with IPv4 listener
            socket
                .set_only_v6(true)
                .context("set ipv6 only for kixdns")?;
            socket.set_reuse_address(true)?;

            socket
                .bind(&bind_tcp.into())
                .context("bind ipv6 tcp socket")?;
            socket.listen(128)?;
            socket.set_nonblocking(true)?;

            tcp.push((TcpListener::from_std(socket.into())?, "ipv6"));
        }

        // DoH listener — 仅在配置了 bind_doh 时启动：绑不上只记错误，DNS 照常答
        // DoH listener — only if bind_doh is configured: failing to bind is only logged, DNS answers as usual
        let doh = match doh {
            Some(doh) => match TcpListener::bind(doh.bind).await {
                Ok(listener) => Some((listener, doh)),
                Err(err) => {
                    error!(error = %err, "DoH server exited");
                    None
                }
            },
            None => None,
        };

        Ok(Self { udp, tcp, doh })
    }

    /// 开始答 / Starts answering
    fn serve(self, engine: &Engine, all_handles: &mut Vec<tokio::task::JoinHandle<()>>) {
        for BoundUdp {
            addr,
            family,
            sockets,
        } in self.udp
        {
            info!(bind_addr = %addr, workers = sockets.len(), "Starting {family} UDP workers");
            for (worker_id, socket) in sockets.into_iter().enumerate() {
                let engine = engine.clone();
                all_handles.push(tokio::spawn(async move {
                    if let Err(err) = run_udp_worker(worker_id, socket, engine).await {
                        error!(worker_id, error = %err, "{family} udp worker exited");
                    }
                }));
            }
        }

        for (listener, family) in self.tcp {
            all_handles.push(spawn_tcp(listener, engine.clone(), family));
        }

        if let Some((listener, doh)) = self.doh {
            info!(addr = %doh.bind, doh_path = %doh.path, "DoH server listening");
            let engine = engine.clone();
            all_handles.push(tokio::spawn(async move {
                if let Err(err) = kixdns::doh_server::run_doh_with_listener(
                    listener,
                    &doh.tls_cert,
                    &doh.tls_key,
                    engine,
                    doh.path,
                )
                .await
                {
                    error!(error = %err, "DoH server exited");
                }
            }));
        }
    }
}

/// 引擎的观察者：有面板时是面板观察者，`--debug` 的事件由它转发；没有面板时和上游一样，
/// 只有 `--debug` 才装参考观察者，否则不装，请求不付任何观察的开销
/// The engine's observer: with the panel, the panel observer, which forwards the `--debug`
/// events itself; without the panel, as upstream, the reference observer only with `--debug`
/// and otherwise none, so requests pay nothing for observation
fn engine_observer(
    panel_metrics: Option<&Arc<PanelMetrics>>,
    debug: bool,
) -> Option<Arc<dyn EngineObserver>> {
    match panel_metrics {
        Some(panel_metrics) => Some(panel_metrics.clone()),
        None if debug => Some(Arc::new(TracingObserver)),
        None => None,
    }
}

fn init_tracing(debug: bool) {
    // 默认仅保留错误日志以平衡性能与可观测性，除非显式指定
    // Default to error-level logging to balance performance with observability unless explicitly enabled
    let format = fmt::format()
        .with_timer(fmt::time::LocalTime::rfc_3339())
        .with_target(false)
        .with_ansi(false)
        .with_level(debug);

    let level = if debug { "debug" } else { "error" };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    let registry = tracing_subscriber::registry().with(filter);
    if stdout_is_journald() {
        registry
            .with(fmt::layer().event_format(JournalPriority(format)))
            .init();
    } else {
        registry.with(fmt::layer().event_format(format)).init();
    }
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

/// 要单独监听的 IPv4 地址：IPv4 地址本身，或者 `[::]` 的同伴 `0.0.0.0`（端口相同）；别的 IPv6 地址
/// 没有
/// The IPv4 address to listen on separately: an IPv4 address itself, or `0.0.0.0` on the
/// same port as the twin of `[::]`; other IPv6 addresses have none
fn ipv4_listen_addr(addr: SocketAddr) -> Option<SocketAddr> {
    match addr {
        SocketAddr::V4(_) => Some(addr),
        SocketAddr::V6(v6) if v6.ip().is_unspecified() => Some(SocketAddr::new(
            std::net::Ipv4Addr::UNSPECIFIED.into(),
            addr.port(),
        )),
        SocketAddr::V6(_) => None,
    }
}

/// 在 `listener` 上跑 TCP 服务；`family` 是日志里的地址族
/// Run the TCP server on `listener`; `family` names the address family in the logs
fn spawn_tcp(
    listener: TcpListener,
    engine: Engine,
    family: &'static str,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(err) = run_tcp(listener, engine).await {
            error!(error = %err, "{family} tcp server exited");
        }
    })
}

// 为一个地址绑定 UDP workers 的 socket / Bind the UDP workers' sockets for one address
#[cfg(unix)]
fn bind_udp_workers(addr: SocketAddr, worker_count: usize) -> anyhow::Result<BoundUdp> {
    let (family, lowercase) = if addr.is_ipv4() {
        ("IPv4", "ipv4")
    } else {
        ("IPv6", "ipv6")
    };

    // ✅ Per-worker SO_REUSEPORT_LB sockets: each worker gets its own fd.
    // On FreeBSD, SO_REUSEPORT_LB enables kernel hash-based packet distribution
    // across sockets. On Linux, SO_REUSEPORT already includes this behavior.
    // This gives perfect multi-core scaling with zero contention — each worker
    // owns its socket, no Arc<UdpSocket> sharing, no reactor thundering herd.
    //
    // ✅ 每 worker 独立 SO_REUSEPORT_LB socket：每个 worker 拥有自己的 fd。
    // FreeBSD 上 SO_REUSEPORT_LB 启用内核级哈希分发，
    // Linux 上 SO_REUSEPORT 已自带此行为。
    // 实现无竞争的多核扩展——每个 worker 独占 socket，
    // 无 Arc<UdpSocket> 共享，无 reactor 惊群效应。
    let sockets = (0..worker_count)
        .map(|worker_id| {
            let std_socket = create_reuseport_udp_socket(addr)
                .with_context(|| format!("create {lowercase} udp socket for worker {worker_id}"))?;
            Ok(Arc::new(UdpSocket::from_std(std_socket)?))
        })
        .collect::<anyhow::Result<_>>()?;

    Ok(BoundUdp {
        addr,
        family,
        sockets,
    })
}

// Non-Unix: create a single shared socket that the workers share / 非 Unix：创建单个共享套接字，工作线程共用它
#[cfg(not(unix))]
fn bind_udp_workers(addr: SocketAddr, worker_count: usize) -> anyhow::Result<BoundUdp> {
    // Use socket2 to set buffer sizes / 使用 socket2 设置缓冲区大小
    use socket2::{Domain, Protocol, Socket, Type};
    let (domain, family) = if addr.is_ipv4() {
        (Domain::IPV4, "IPv4")
    } else {
        (Domain::IPV6, "IPv6")
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).context("create socket")?;

    // ✅ Windows 上设置 IPV6_V6ONLY=0 以支持双栈，与 Linux 行为一致
    // ✅ On Windows, set IPV6_V6ONLY=0 for dual-stack support, consistent with Linux behavior
    if domain == Domain::IPV6 {
        if let Err(e) = socket.set_only_v6(false) {
            debug!(
                "failed to set IPV6_V6ONLY=0: {}, IPv4 may not work on [::] bind",
                e
            );
        } else {
            info!("UDP IPv6 socket set to dual-stack mode (IPV6_V6ONLY=0)");
        }
    }

    set_udp_buffers(&socket);

    socket.set_nonblocking(true).context("set nonblocking")?;
    socket.bind(&addr.into()).context("bind socket")?;

    let udp_socket = Arc::new(UdpSocket::from_std(socket.into()).context("from_std")?);
    Ok(BoundUdp {
        addr,
        family,
        sockets: vec![udp_socket; worker_count],
    })
}

// 在 Unix 上创建带 SO_REUSEPORT 的 UDP socket；非 Unix 使用标准绑定 / Create UDP socket with SO_REUSEPORT on Unix; use standard binding on non-Unix
#[cfg(unix)]
fn create_reuseport_udp_socket(addr: SocketAddr) -> anyhow::Result<std::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;

    // ✅ OpenBSD/FreeBSD 安全措施：为 IPv6 socket 显式设置 IPV6_V6ONLY=1
    // ✅ OpenBSD/FreeBSD safety: explicitly set IPV6_V6ONLY=1 for IPv6 sockets
    // 双 socket 方案下，IPv6 socket 只处理 IPv6 流量，确保地址族一致性，避免 sockaddr 大小断言失败
    // With dual-socket approach, IPv6 socket only handles IPv6 traffic, ensuring address family consistency
    // 这使得我们可以安全地使用零拷贝的 recv_buf_from
    // This allows us to safely use zero-copy recv_buf_from
    if domain == Domain::IPV6
        && let Err(e) = kixdns::socket_utils::set_ipv6_v6only(&socket, true)
    {
        tracing::warn!(
            "Failed to set IPV6_V6ONLY=1: {}, this may cause issues on OpenBSD",
            e
        );
    }

    // Try to set SO_REUSEPORT_LB (FreeBSD) or SO_REUSEPORT (Linux) via safe wrapper
    // 尝试通过安全封装设置 SO_REUSEPORT_LB (FreeBSD) 或 SO_REUSEPORT (Linux)
    if let Err(e) = kixdns::socket_utils::set_reuseport_lb(&socket) {
        // Log warning if SO_REUSEPORT_LB fails / SO_REUSEPORT_LB 失败时记录警告
        tracing::warn!(
            "SO_REUSEPORT_LB failed: {}, falling back to plain SO_REUSEPORT",
            e
        );
        if let Err(e2) = kixdns::socket_utils::set_reuseport(&socket, true) {
            tracing::warn!("SO_REUSEPORT also failed: {}", e2);
        }
    }

    set_udp_buffers(&socket);

    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    Ok(socket.into())
}

/// UDP 收发缓冲平时的大小 / The usual size of the UDP send and receive buffers
const UDP_BUFFER_SIZE: usize = 4 * 1024 * 1024;

/// 设置 UDP 收发缓冲区，免得负载高时丢包：先试 4 MiB，设不上再退到 1 MiB
/// Set the UDP buffer sizes to prevent packet loss under load: 4 MiB first, falling back
/// to 1 MiB if that fails
fn set_udp_buffers(socket: &socket2::Socket) {
    let desired_size = UDP_BUFFER_SIZE;
    let fallback_size = 1024 * 1024;

    if let Err(e) = socket.set_recv_buffer_size(desired_size) {
        debug!(
            "failed to set udp recv buffer to {} bytes: {}, trying {}",
            desired_size, e, fallback_size
        );
        let _ = socket.set_recv_buffer_size(fallback_size);
    }
    if let Err(e) = socket.set_send_buffer_size(desired_size) {
        debug!(
            "failed to set udp send buffer to {} bytes: {}, trying {}",
            desired_size, e, fallback_size
        );
        let _ = socket.set_send_buffer_size(fallback_size);
    }
}

/// 发送 UDP 数据报：try_send_to 优先（避免 reactor 开销），WouldBlock 回退异步
/// Send UDP datagram: try non-blocking first, async fallback on WouldBlock
async fn send_udp_datagram(
    socket: &UdpSocket,
    data: &[u8],
    peer: SocketAddr,
) -> std::io::Result<usize> {
    match socket.try_send_to(data, peer) {
        Ok(sent) => Ok(sent),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
            socket.send_to(data, peer).await
        }
        Err(error) => Err(error),
    }
}

/// UDP 回答：超过客户端声明的上限就截断（RFC 6891）/ A UDP reply, cut to the client's advertised
/// limit when over it (RFC 6891)
fn udp_reply(request: &[u8], response: Bytes) -> Bytes {
    truncate_udp_response(request, &response).unwrap_or(response)
}

/// 非阻塞发送 UDP 响应（过载保护路径）：截断 + 纯 try_send_to，WouldBlock 背压丢弃
/// Non-blocking UDP send for overload paths: truncate + try_send_to only; drop on WouldBlock
fn try_send_udp_response(socket: &UdpSocket, request: &[u8], response: &[u8], peer: SocketAddr) {
    let truncated = truncate_udp_response(request, response);
    let response = truncated.as_deref().unwrap_or(response);
    if let Err(error) = socket.try_send_to(response, peer)
        && error.kind() != std::io::ErrorKind::WouldBlock
    {
        debug!(%peer, %error, response_len = response.len(), "failed to send UDP response");
    }
    // WouldBlock: 发送缓冲满，丢弃（背压）/ send buffer full, drop (backpressure)
}

/// 转发回来、等着和下一批一起发出去的回答。接收循环忙着的时候（它很快会回来收发下一批），转发完的任务把
/// 回答放在这里，接收循环把它们和当场答出的回答拼进同一批，一次 sendmmsg 发出；接收循环在等新报文时，回答
/// 直接发，不为一个回答把它叫醒。只有 Linux 的批量循环会说自己在忙，其他平台的回答都直接发。
/// Replies back from a forward, waiting to go out with the next batch. While the receive loop is busy
/// (it will soon be back to receive and send the next batch), a task done forwarding leaves its reply
/// here, and the loop puts it in the same batch as the replies it gave on the spot, one sendmmsg for
/// all; while the loop waits for datagrams the reply goes directly, without waking the loop for it.
/// Only Linux's batched loop ever says it is busy; on other platforms every reply goes directly.
struct PendingReplies {
    queue: parking_lot::Mutex<Vec<(Bytes, SocketAddr)>>,
    /// 接收循环在等新报文 / The receive loop is waiting for datagrams
    idle: std::sync::atomic::AtomicBool,
    /// 接收循环在等新报文时有回答放了进来 / A reply came in while the receive loop waited for datagrams
    wake: tokio::sync::Notify,
}

impl Default for PendingReplies {
    fn default() -> Self {
        Self {
            queue: parking_lot::Mutex::new(Vec::new()),
            idle: std::sync::atomic::AtomicBool::new(true),
            wake: tokio::sync::Notify::new(),
        }
    }
}

impl PendingReplies {
    /// 接收循环忙着时收下这个回答；它在等新报文时不收，返回 false，由调用方直接发
    /// Takes the reply while the receive loop is busy; while it waits for datagrams the reply is
    /// not taken and false comes back, for the caller to send it directly
    fn try_queue(&self, reply: &Bytes, peer: SocketAddr) -> bool {
        use std::sync::atomic::Ordering::SeqCst;
        if self.idle.load(SeqCst) {
            return false;
        }
        self.queue_and_wake(reply, peer);
        true
    }

    /// 放进队列。放进来的时候循环正好转去等待、可能没看到它，就叫醒它（见 `begin_wait`）
    /// Queues the reply, and wakes the loop should it have turned to waiting just as the reply
    /// came in, possibly without seeing it (see `begin_wait`)
    fn queue_and_wake(&self, reply: &Bytes, peer: SocketAddr) {
        use std::sync::atomic::Ordering::SeqCst;
        self.queue.lock().push((reply.clone(), peer));
        if self.idle.load(SeqCst) {
            self.wake.notify_one();
        }
    }

    /// 排着的回答按先后挪进 `replies`，直到这一批放满 / Moves queued replies into `replies` in order
    /// until the batch is full
    #[cfg(target_os = "linux")]
    fn fill(&self, replies: &mut kixdns::socket_utils::udp_batch::Replies) {
        use kixdns::socket_utils::udp_batch::Peer;
        let mut queue = self.queue.lock();
        let room = queue
            .len()
            .min(kixdns::socket_utils::udp_batch::BATCH - replies.len());
        for (reply, peer) in queue.drain(..room) {
            let buf = replies.next_buf();
            buf.clear();
            buf.extend_from_slice(&reply);
            replies.push(Peer::of(peer));
        }
    }

    /// 接收循环没有报文可收了：先把排着的回答发掉，再等新报文或者放进来的回答
    /// The receive loop has nothing to receive: it sends the queued replies, then waits for a
    /// datagram or a queued reply
    #[cfg(target_os = "linux")]
    async fn wait(
        &self,
        socket: &UdpSocket,
        replies: &mut kixdns::socket_utils::udp_batch::Replies,
    ) {
        send_pending(socket, self, replies).await;
        if self.begin_wait() {
            tokio::select! {
                _ = socket.readable() => {}
                _ = self.wake.notified() => {}
            }
        }
        self.idle.store(false, std::sync::atomic::Ordering::SeqCst);
    }

    /// 说自己在等，再看一眼队列：在这之前放进来的回答 `queue_and_wake` 不会叫醒循环。队列空着才可以睡
    /// Says the loop waits, then looks at the queue once more: `queue_and_wake` wakes the loop for
    /// nothing queued before this. The loop may sleep only when the queue is empty
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))] // 只有 Linux 的批量循环会等 / Only Linux's batched loop waits
    fn begin_wait(&self) -> bool {
        self.idle.store(true, std::sync::atomic::Ordering::SeqCst);
        self.queue.lock().is_empty()
    }
}

/// 高性能 UDP worker：直接在接收循环中处理请求，避免 spawn 开销 / High-performance UDP worker: process requests directly in receive loop, avoiding spawn overhead
async fn run_udp_worker(
    worker_id: usize,
    socket: Arc<UdpSocket>,
    engine: Engine,
) -> anyhow::Result<()> {
    // 共享不复制：要等上游的查询各自起一个任务，每个只加一次引用计数，不复制整个 Engine（二十多个 Arc）
    // Shared, not copied: each query that waits on an upstream gets its own task, which takes one
    // reference count instead of a copy of the whole Engine (twenty-odd Arcs)
    let engine = Arc::new(engine.with_client_transport(ClientTransport::Udp));
    info!(worker_id, "UDP worker started");
    #[cfg(target_os = "linux")]
    receive_in_batches(&socket, &engine).await;
    #[cfg(not(target_os = "linux"))]
    receive_one_by_one(&socket, &engine).await;
}

/// 一个 worker 的接收循环里，快速路径要用的几样东西 / What the fast path needs in one worker's receive loop
struct UdpAnswering<'a> {
    socket: &'a Arc<UdpSocket>,
    engine: &'a Arc<Engine>,
    pending: &'a Arc<PendingReplies>,
    /// 自适应流控：每 100 个请求检查一次是否需要调整 permits / Adaptive flow control: check if adjustment needed every 100 requests
    request_count: u32,
    /// socket 上次收空的时刻，流控靠它判断内核忙不忙 / When the socket last ran empty, by which flow control tells whether the kernel is busy
    emptied_at: Instant,
    /// 上次收空以后看过几次接收缓冲 / How many times the receive buffer was looked at since the socket last ran empty
    checks_since_empty: u32,
    /// 接收缓冲现在是不是收小的 / Whether the receive buffer is shrunk right now
    buffer_shrunk: bool,
    /// 这一段积压里上次读到的丢包数 / The drop count last read during this backlog
    drops_seen: Option<u32>,
    /// 上次读丢包数的时刻，到下一次之间处理了多少查询是定数，这就量出了处理速度
    /// When the drops were last read; a set number of queries is handled until the next read, which gives the speed
    looked_at: Instant,
    /// 上次见到跟不上的时刻：丢包或者拒绝 / When falling behind was last seen: drops or refusals
    behind_at: Instant,
    /// 这一段跟不上从什么时候开始 / When this spell of falling behind began
    behind_since: Instant,
    /// 上次看过以后，这个 worker 读到的查询有没有被流控拒绝。只算自己的：别的 worker、TCP 和 DoH 被拒，
    /// 轮流时排不下丢的，都不是这个 socket 跟不上
    /// Whether flow control refused a query this worker read since the last look. Only its own
    /// count: refusals in another worker or over TCP and DoH, and what taking turns drops for not
    /// fitting, are not this socket falling behind
    refused: bool,
    /// 正在按设备轮流：只看内存，内核跟不上时丢的是还排着队的设备 / Devices are taking turns: only memory is
    /// looked at, as falling behind drops from devices with more queued
    taking_turns: bool,
    /// 这台机器 `QUEUE_TARGET` 内处理得完多少查询，上次读丢包数时量的 / How many queries this machine handles
    /// within `QUEUE_TARGET`, measured when the drops were last read
    queries_within_target: usize,
    /// 这会儿在丢包或者拒绝 / Dropping or refusing just now
    behind: bool,
    /// 丢包持续了够久，就按设备轮流 / Drops have lasted long enough, so devices take turns
    overloaded: bool,
}

/// 每 100 个查询看一次接收缓冲，看到这么多次的整数倍、socket 还没收空就读一次丢包数，平时不多这一次系统调用
/// The receive buffer is looked at every 100 queries, and at every multiple of this many looks without the socket
/// running empty the drops are read, sparing the usual path that system call
const BEHIND_AFTER_CHECKS: u32 = 10;

/// 一个小查询在接收缓冲里算多少字节：内核给每个小报文记 960 字节，再把 `SO_RCVBUF` 的值翻倍当上限。网卡收进来的报文记得
/// 更多，放得下的少，排队只会更短
/// What a small query counts for in the receive buffer: the kernel charges a small datagram 960 bytes and doubles
/// the `SO_RCVBUF` value for its limit. A datagram from a network card is charged more, so fewer fit and the wait
/// only gets shorter
const RECV_BUFFER_PER_QUERY: usize = 480;

/// 大接收缓冲放得下多少个小查询，读不到实际大小时按这个算 / How many small queries the large receive
/// buffer holds, taken when the actual size cannot be read
#[cfg(target_os = "linux")]
const QUERIES_IN_RECV_BUFFER: usize = UDP_BUFFER_SIZE / RECV_BUFFER_PER_QUERY;

/// 这个 socket 的接收缓冲实际放得下多少个小查询。`net.core.rmem_max` 比 4 MiB 小时，设下去的大小会被内核截短；
/// 内核报的是翻过倍的大小，一个小查询记 `2 * RECV_BUFFER_PER_QUERY`
/// How many small queries this socket's receive buffer actually holds. With `net.core.rmem_max`
/// below 4 MiB the kernel cuts the size that was set; it reports the doubled size, a small query
/// being charged `2 * RECV_BUFFER_PER_QUERY`
#[cfg(target_os = "linux")]
fn queries_in_recv_buffer(socket: &UdpSocket) -> usize {
    socket2::SockRef::from(socket)
        .recv_buffer_size()
        .map_or(QUERIES_IN_RECV_BUFFER, |size| {
            size / (2 * RECV_BUFFER_PER_QUERY)
        })
        .max(MIN_QUERIES_IN_RECV_BUFFER)
}

/// 接收缓冲至少放得下这么多查询（两批）/ The receive buffer holds at least this many queries (two batches)
const MIN_QUERIES_IN_RECV_BUFFER: usize = 64;

/// 丢包停了这么久才算跟上。缓冲收小以后只排 `QUEUE_TARGET` 那么多，到达有一小段空档就会收空；这时放回大缓冲，下一波要排
/// 满它才会再收小，这段时间答的都要排很久
/// Drops have to stop for this long to count as having caught up. Once shrunk the buffer holds
/// only `QUEUE_TARGET`, so a short gap in arrivals runs it empty; putting the large buffer back
/// then means the next wave has to fill it before it shrinks again, and what gets answered
/// meanwhile waits long
const CAUGHT_UP_AFTER: Duration = Duration::from_secs(1);

/// 跟不上（丢包或者拒绝）持续这么久才按设备轮流。一阵突发很快就处理完，不该有人因此被丢
/// Falling behind (drops or refusals) has to last this long before devices take turns. A burst
/// is soon handled, and nobody should lose queries over it
const BEHIND_BEFORE_TURNS: Duration = Duration::from_secs(1);

/// 这台机器 `QUEUE_TARGET` 内处理得完多少查询，`took` 是处理 `BEHIND_AFTER_CHECKS` 次看缓冲之间那些查询用的时间
/// How many queries this machine handles within `QUEUE_TARGET`, `took` being how long the queries
/// between `BEHIND_AFTER_CHECKS` looks took
fn queries_within_target(took: Duration) -> usize {
    let handled = u128::from(BEHIND_AFTER_CHECKS) * 100;
    let queries = handled * QUEUE_TARGET.as_nanos() / took.as_nanos().max(1);
    usize::try_from(queries)
        .unwrap_or(usize::MAX)
        .max(MIN_QUERIES_IN_RECV_BUFFER)
}

/// 缓冲满到丢包时收到多小：正好放得下这台机器 `QUEUE_TARGET` 内处理得完的查询。处理不完的查询反正要丢，缓冲越大，答得上
/// 的那些排得越久
/// How small the receive buffer gets once full enough to drop: just what this machine handles
/// within `QUEUE_TARGET`. What cannot be handled gets dropped anyway, and the larger the buffer
/// the longer the queries that do get answered wait in line
fn recv_buffer_when_behind(queries: usize) -> usize {
    queries
        .saturating_mul(RECV_BUFFER_PER_QUERY)
        .min(UDP_BUFFER_SIZE)
}

impl<'a> UdpAnswering<'a> {
    fn new(
        socket: &'a Arc<UdpSocket>,
        engine: &'a Arc<Engine>,
        pending: &'a Arc<PendingReplies>,
    ) -> Self {
        Self {
            socket,
            engine,
            pending,
            request_count: 0,
            emptied_at: Instant::now(),
            checks_since_empty: 0,
            buffer_shrunk: false,
            drops_seen: None,
            looked_at: Instant::now(),
            behind_at: Instant::now() - CAUGHT_UP_AFTER,
            behind_since: Instant::now(),
            refused: false,
            taking_turns: false,
            queries_within_target: MIN_QUERIES_IN_RECV_BUFFER,
            behind: false,
            overloaded: false,
        }
    }

    /// 量处理速度，记下在不在丢包、过没过载。没开流控时一丢包就把接收缓冲收小，压住排队延迟；只看积压
    /// 不够，贴着处理能力时大缓冲一个包都不丢，收小才是白丢
    /// Measures the handling speed and notes whether it is dropping and overloaded. Without flow
    /// control a drop shrinks the receive buffer, holding down the wait in line; a backlog alone is
    /// not enough, as right at capacity the large buffer drops nothing and shrinking would throw
    /// queries away for nothing
    fn shrink_buffer_if_overflowing(&mut self) {
        self.checks_since_empty += 1;
        if !self.checks_since_empty.is_multiple_of(BEHIND_AFTER_CHECKS) {
            return;
        }
        let now = Instant::now();
        let took = now.duration_since(std::mem::replace(&mut self.looked_at, now));
        let Some(drops) = kixdns::socket_utils::udp_receive_drops(self.socket) else {
            return;
        };
        let dropping = self
            .drops_seen
            .replace(drops)
            .is_some_and(|seen| seen != drops);
        let refusing = std::mem::take(&mut self.refused);
        // 这一段积压第一次看：到上一次之间可能空闲过，量不出速度 / The first look of this backlog: it may
        // have been idle since the last, so this measures no speed
        if self.checks_since_empty == BEHIND_AFTER_CHECKS {
            return;
        }
        self.queries_within_target = queries_within_target(took);
        if dropping || refusing {
            if now.duration_since(self.behind_at) >= CAUGHT_UP_AFTER {
                self.behind_since = now;
            }
            self.behind_at = now;
        }
        self.behind = now.duration_since(self.behind_at) < CAUGHT_UP_AFTER;
        self.overloaded = self.engine.flow_control_state.is_some()
            && now.duration_since(self.behind_since) >= BEHIND_BEFORE_TURNS
            && self.behind;
        // 开了流控不收小：过载了就按设备轮流，排队压在各设备自己的队列里。缓冲收小了，发得少的那台的包在被读到
        // 之前就在内核里和洪泛一起丢了，接收循环见不到它，它也就轮不上
        // With flow control it is never shrunk: overload means taking turns, with the wait held down in
        // each device's own queue. A shrunk buffer would lose a device sending little in the kernel
        // along with the flood, before it is ever read, so it would never get a turn
        if dropping && self.engine.flow_control_state.is_none() {
            self.set_recv_buffer(recv_buffer_when_behind(self.queries_within_target));
            self.buffer_shrunk = true;
        }
    }

    /// 开始按设备轮流。接收缓冲一直是大的：排队在各设备自己的队列里，缓冲小了只会在读不及时满出来，不分来源地丢
    /// Devices begin to take turns. The receive buffer stays large: the wait in line is in each
    /// device's own queue, and a small buffer would only overflow when a read comes late, dropping
    /// whatever comes from anyone
    #[cfg(target_os = "linux")]
    fn begin_turns(&mut self) -> Box<TakingTurns> {
        self.taking_turns = true;
        Box::new(TakingTurns::new(
            self.queries_within_target,
            queries_in_recv_buffer(self.socket),
        ))
    }

    fn set_recv_buffer(&self, size: usize) {
        if let Err(error) = socket2::SockRef::from(self.socket.as_ref()).set_recv_buffer_size(size)
        {
            debug!(%error, size, "failed to resize udp recv buffer");
        }
    }

    /// socket 读空了，就要开始等：到这一刻的丢包算在等之前。等完再读的话，等了再久都会当成刚丢过，跟上了也算没跟上
    /// The socket was read empty and the wait is about to begin: the drops so far come before the
    /// wait. Read after it, they would seem just dropped however long the wait, and being caught
    /// up would not count
    fn note_drops_before_waiting(&mut self) {
        if self.buffer_shrunk || self.taking_turns {
            let drops = kixdns::socket_utils::udp_receive_drops(self.socket);
            if drops != self.drops_seen {
                self.drops_seen = drops;
                self.behind_at = Instant::now();
            }
        } else {
            self.drops_seen = None;
        }
    }

    /// socket 收空了，刚等到新东西：等的这段时间不算没收空，否则空闲之后的第一个查询就算内核忙。丢包停得够久，接收缓冲
    /// 也放回去接突发
    /// The socket ran empty and the wait just ended: the wait does not count as not running empty, or the first
    /// query after a quiet spell would find the kernel busy. With the drops stopped long enough, the receive buffer
    /// goes back to catching bursts
    #[inline]
    fn socket_ran_empty(&mut self) {
        if self.engine.flow_control_state.is_some() {
            self.emptied_at = Instant::now();
        }
        self.checks_since_empty = 0;
        if (self.buffer_shrunk || self.overloaded || self.taking_turns)
            && self.behind_at.elapsed() >= CAUGHT_UP_AFTER
        {
            if self.buffer_shrunk {
                self.set_recv_buffer(UDP_BUFFER_SIZE);
                self.buffer_shrunk = false;
            }
            self.drops_seen = None;
            self.behind = false;
            self.overloaded = false;
            self.taking_turns = false;
        }
    }

    /// 处理收到的一个报文。快速路径当场答得上的（缓存命中、静态规则、解析出错的 SERVFAIL），把回答写进 `reply`
    /// 并返回 true，超过客户端上限的已经截断；要等上游的交给单独的任务，不是查询的丢掉，都返回 false。
    /// Handles one received datagram. What the fast path answers on the spot (a cache hit, a static rule, the
    /// SERVFAIL for an error) is written to `reply`, already cut to the client's limit, and gives true; a query
    /// that waits on an upstream goes to its own task and anything that is not a query is dropped, both giving false.
    fn answer(&mut self, packet: &[u8], peer: SocketAddr, reply: &mut BytesMut) -> bool {
        if !is_standard_query_header(packet) {
            return false;
        }
        self.request_count += 1;
        if self.request_count >= 100 {
            self.request_count = 0;
            self.shrink_buffer_if_overflowing();
        }
        // ✅ 优化：使用 handle_packet_fast 避免重复解析 / ✅ Optimization: Use handle_packet_fast to avoid re-parsing
        match self.engine.handle_packet_fast(packet, peer) {
            Ok(Some(FastPathResponse::Direct(bytes))) => {
                // 已包含正确 TXID / Already contains correct TXID
                reply.clear();
                reply.extend_from_slice(&bytes);
            }
            Ok(Some(FastPathResponse::CacheHit {
                cached,
                tx_id,
                elapsed_secs,
            })) => write_cache_hit(reply, &cached, tx_id, elapsed_secs),
            Ok(Some(FastPathResponse::AsyncNeeded(pre_parsed))) => {
                // 缓存未命中，使用预解析的数据避免重复解析 / Cache miss, use pre-parsed data to avoid re-parsing
                let packet = Bytes::copy_from_slice(packet);
                self.refused |= !spawn_udp_answer(self, packet, peer, Some(pre_parsed));
                return false;
            }
            Ok(None) => {
                // 快速解析失败，回退到完整处理 / Fast parse failed, fallback to full processing
                let packet = Bytes::copy_from_slice(packet);
                self.refused |= !spawn_udp_answer(self, packet, peer, None);
                return false;
            }
            Err(error) => {
                self.engine.log_fast_path_error(&error);
                let Some(failure) = engine_helpers::try_build_listener_failure_from_wire(packet)
                else {
                    return false;
                };
                reply.clear();
                reply.extend_from_slice(&failure);
            }
        }
        // 截断超限响应，避免 UDP 报文超过客户端声明上限 / Truncate to the client's advertised UDP limit
        if let Some(truncated) = truncate_udp_response(packet, reply) {
            reply.clear();
            reply.extend_from_slice(&truncated);
        }
        true
    }
}

/// 接收循环连着收到这么多个报文、socket 一直没空过，就让出一次线程。socket 里有包时非阻塞接收一直成功，
/// 循环从不 await；不让出的话，同一线程上要等上游的查询和上游回答的接收就轮不到，过载时转发全停
/// After this many datagrams in a row without the socket running empty, a receive loop yields its
/// thread once. While the socket holds datagrams the non-blocking receive keeps succeeding and the loop
/// never awaits; without the yield the queries waiting on an upstream and the readers of upstream
/// answers on the same thread never run, and under overload forwarding stops altogether
const RECEIVED_BEFORE_YIELD: usize = 32;

/// Linux：一次系统调用收一批、回一批（recvmmsg / sendmmsg）。满负荷时省下每个报文各自进出内核的那一趟；
/// 空闲时一批只有一个，和单收单发一样。没有报文时让出 tokio，worker 不空转。
/// Linux: one system call takes a batch and one sends the replies (recvmmsg / sendmmsg). Under full load
/// this saves each datagram its own trip into the kernel; when idle a batch holds one, the same as single
/// receives and sends. With nothing to read the worker yields to tokio and does not spin.
#[cfg(target_os = "linux")]
async fn receive_in_batches(socket: &Arc<UdpSocket>, engine: &Arc<Engine>) -> ! {
    use std::os::fd::AsRawFd;
    use tokio::io::Interest;
    use udp_batch::{Received, Replies};

    let fd = socket.as_raw_fd();
    let mut received = Received::default();
    let mut replies = Replies::default();
    let pending = Arc::new(PendingReplies::default());
    pending
        .idle
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let mut answering = UdpAnswering::new(socket, engine, &pending);
    let mut received_in_row = 0;
    let mut turns: Option<Box<TakingTurns>> = None;
    loop {
        let got = match socket.try_io(Interest::READABLE, || received.recv(fd)) {
            Ok(got) => got,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if turns.as_ref().is_none_or(|turns| turns.queue.is_empty()) {
                    // 当前无包可读：先把排着的回答发掉，再等新报文或新回答 / Nothing to receive right now:
                    // send the queued replies, then wait for a datagram or a queued reply
                    received_in_row = 0;
                    answering.note_drops_before_waiting();
                    pending.wait(socket, &mut replies).await;
                    answering.socket_ran_empty();
                    if !answering.taking_turns {
                        turns = None;
                    }
                    continue;
                }
                0
            }
            Err(_) => continue,
        };
        if let Some(taking) = &mut turns {
            taking.queue_received(&received, got, &mut answering);
            if got == udp_batch::BATCH && taking.may_read_more() {
                continue;
            }
            taking.answer_in_turn(&mut answering, &mut replies);
            received_in_row = RECEIVED_BEFORE_YIELD;
        } else {
            for k in 0..got {
                let Some((packet, peer)) = received.get(k) else {
                    continue;
                };
                if answering.answer(packet, peer.addr(), replies.next_buf()) {
                    replies.push(peer);
                }
            }
            received_in_row += got;
            if answering.overloaded {
                turns = Some(answering.begin_turns());
            }
        }
        // 转发回来的回答搭上这一批，放不下的随后成批发 / Replies back from forwards ride along with this
        // batch; what does not fit goes in batches right after
        pending.fill(&mut replies);
        send_replies(socket, &replies).await;
        replies.clear();
        send_pending(socket, &pending, &mut replies).await;
        if received_in_row >= RECEIVED_BEFORE_YIELD {
            received_in_row = 0;
            tokio::task::yield_now().await;
        }
    }
}

/// 过载时按设备轮流：能读多少先读多少，排不下的不解析就丢，所以读得比处理得快得多，socket 不再因为满了而不分来源地丢包；
/// 然后轮流答一批。只有一台设备在刷也这样：别的设备隔多久才问一次都读得到、轮得上。不轮流也不会丢包了就是跟上了：
/// 读到的按量到的速度消得掉，大接收缓冲放得下
/// Devices taking turns under overload: as much as there is gets read first and what does not fit
/// is dropped unparsed, so reading is far faster than handling and the socket no longer drops
/// whatever comes for being full; then a batch is answered in turn. A single device flooding gets
/// the same, so another asking however rarely is read and gets its turn. It has caught up once
/// there would be no drops without turns either: what is read is worked off at the measured speed
/// and the large receive buffer holds it
#[cfg(target_os = "linux")]
struct TakingTurns {
    queue: FairQueue<udp_batch::Peer>,
    /// 答一批之前已经读了几批 / How many batches were read before answering one
    reads: usize,
    /// 不轮流的话接收缓冲里会积着多少查询：读到的加上，按量到的速度消掉。轮流时读得比处理快，缓冲满不了，排不下
    /// 的也只是这台设备超出了自己那一份，所以看这个数：超过缓冲放得下的，不轮流也会丢包，才算还跟不上
    /// How many queries the receive buffer would hold without turns: what is read adds to it and the
    /// measured speed works it off. Taking turns reads faster than it handles, so the buffer does not
    /// fill, and what does not fit only means a device went past its share; this tells instead: past
    /// what the buffer holds there would be drops without turns, and only that is still falling behind
    backlog: usize,
    /// `backlog` 上次算到的时刻 / When `backlog` was last worked out
    counted_at: Instant,
    /// 接收缓冲放得下多少个查询 / How many queries the receive buffer holds
    holds: usize,
}

/// 答一批之前最多读这么多批，再多的洪泛也要留时间处理 / At most this many batches are read before one is
/// answered, leaving time for handling under any flood
#[cfg(target_os = "linux")]
const READS_PER_TURN: usize = 64;

#[cfg(target_os = "linux")]
impl TakingTurns {
    fn new(room: usize, holds: usize) -> Self {
        Self {
            queue: FairQueue::new(room),
            reads: 0,
            backlog: 0,
            counted_at: Instant::now(),
            holds,
        }
    }

    /// 收到的排进队列，排不下的丢掉。丢掉的不算跟不上：一台设备一次发得比自己那一份多、平均却没到处理能力，不轮流的话
    /// 大缓冲照样接得住；不轮流也会丢包时才算
    /// Queues what was received and drops what does not fit. What is dropped is not falling behind: a
    /// device sending more than its share at once but below capacity on average would be caught by
    /// the large buffer without turns; only drops that would happen without turns count
    fn queue_received(
        &mut self,
        received: &udp_batch::Received,
        got: usize,
        answering: &mut UdpAnswering<'_>,
    ) {
        for k in 0..got {
            let Some((packet, peer)) = received.get(k) else {
                continue;
            };
            if !self.queue.offer(packet, Device::of(peer.addr().ip()), peer) {
                answering.engine.permit_manager.count_refused();
            }
        }
        let now = Instant::now();
        if self.would_overflow(got, answering.queries_within_target, now) {
            answering.behind_at = now;
        }
    }

    /// 记下又读到 `got` 个，`within_target` 是 `QUEUE_TARGET` 内处理得完多少；不轮流的话接收缓冲这会儿放不下了，
    /// 返回 true。放不下的那些内核会丢掉，所以积压到缓冲放得下的为止
    /// Notes `got` more read, `within_target` being how many are handled within `QUEUE_TARGET`, and
    /// gives true when the receive buffer would by now overflow without turns. The kernel would drop
    /// what does not fit, so the backlog stops at what the buffer holds
    fn would_overflow(&mut self, got: usize, within_target: usize, now: Instant) -> bool {
        let took = now.saturating_duration_since(std::mem::replace(&mut self.counted_at, now));
        let handled = within_target as u128 * took.as_nanos() / QUEUE_TARGET.as_nanos();
        let backlog = self
            .backlog
            .saturating_sub(usize::try_from(handled).unwrap_or(usize::MAX))
            .saturating_add(got);
        self.backlog = backlog.min(self.holds);
        backlog > self.holds
    }

    fn may_read_more(&mut self) -> bool {
        self.reads += 1;
        self.reads < READS_PER_TURN
    }

    fn answer_in_turn(
        &mut self,
        answering: &mut UdpAnswering<'_>,
        replies: &mut udp_batch::Replies,
    ) {
        self.reads = 0;
        self.queue.set_room(answering.queries_within_target);
        let manager = &answering.engine.permit_manager;
        for _ in 0..udp_batch::BATCH {
            let Some((packet, peer, more_queued)) = self.queue.next_in_turn() else {
                return;
            };
            // 内核跟不上：还排着队的设备这一个不解析就丢，发得少的设备照常答。丢的和排不下的一样，不算跟不上
            // Falling behind: a device with more queued loses this one unparsed, and a device
            // sending little is answered as usual. As with what does not fit, this drop is not
            // falling behind
            if more_queued && answering.engine.falling_behind() {
                manager.count_refused();
                continue;
            }
            if answering.answer(&packet, peer.addr(), replies.next_buf()) {
                replies.push(peer);
            }
        }
    }
}

/// 排着的回答成批发完 / Sends every queued reply, in batches
#[cfg(target_os = "linux")]
async fn send_pending(
    socket: &UdpSocket,
    pending: &PendingReplies,
    replies: &mut kixdns::socket_utils::udp_batch::Replies,
) {
    loop {
        pending.fill(replies);
        if replies.is_empty() {
            return;
        }
        send_replies(socket, replies).await;
        replies.clear();
    }
}

/// 一批回答发出去：发送缓冲满时等到能写再接着发，和单发时一样；发不出去的那个记下来跳过
/// Sends a batch of replies: when the send buffer is full it waits until writable and goes on, as single
/// sends do; a reply that cannot be sent is logged and skipped
#[cfg(target_os = "linux")]
async fn send_replies(socket: &UdpSocket, replies: &kixdns::socket_utils::udp_batch::Replies) {
    use std::os::fd::AsRawFd;
    use tokio::io::Interest;

    let fd = socket.as_raw_fd();
    let mut next = 0;
    while next < replies.len() {
        match socket.try_io(Interest::WRITABLE, || replies.send(fd, next)) {
            // sendmmsg 要么至少发出一个，要么报错；0 只当发不出去 / sendmmsg sends at least one or
            // fails; a 0 is taken as nothing more can be sent
            Ok(0) => return,
            Ok(sent) => next += sent,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if socket.writable().await.is_err() {
                    return;
                }
            }
            Err(error) => {
                if let Some((response, peer)) = replies.get(next) {
                    debug!(%peer, %error, response_len = response.len(), "failed to send UDP response");
                }
                next += 1;
            }
        }
    }
}

/// 其他平台：一个一个收、一个一个回。先尝试非阻塞，EAGAIN 时回退到异步：高负载时消除每包的 tokio reactor
/// 开销（epoll_wait + 任务唤醒/调度循环），空闲时让出 CPU 不浪费。
/// Other platforms: one datagram received and answered at a time. A non-blocking receive comes first and
/// falls back to async on EAGAIN: under load this eliminates the per-packet tokio reactor overhead (epoll_wait
/// plus the task wake/schedule cycle), and when idle the worker yields and does not waste CPU.
#[cfg_attr(target_os = "linux", allow(dead_code))] // Linux 上只有测试用 / On Linux only the tests use it
async fn receive_one_by_one(socket: &Arc<UdpSocket>, engine: &Arc<Engine>) -> ! {
    let mut buf = vec![0; 4096];
    // 复用发送缓冲区：缓存命中时在这里改 TTL 和 TXID，避免每包堆分配 / Reuse send buffer to patch TTLs and the TXID on cache hits, avoiding per-packet heap allocation
    let mut reply = BytesMut::with_capacity(512);
    // 这个循环从不说自己在忙，转发回来的回答都直接发 / This loop never says it is busy, so replies
    // back from forwards all go directly
    let pending = Arc::new(PendingReplies::default());
    let mut answering = UdpAnswering::new(socket, engine, &pending);
    let mut received_in_row = 0;
    loop {
        let (len, peer) = match socket.try_recv_from(&mut buf) {
            Ok(result) => result,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // 当前无包可读 — 让出 tokio / No packet available right now — yield to tokio
                received_in_row = 0;
                answering.note_drops_before_waiting();
                let received = socket.recv_from(&mut buf).await;
                answering.socket_ran_empty();
                match received {
                    Ok(result) => result,
                    Err(_) => continue,
                }
            }
            Err(_) => continue,
        };
        if answering.answer(&buf[..len], peer, &mut reply)
            && let Err(error) = send_udp_datagram(socket, &reply, peer).await
        {
            debug!(%peer, %error, response_len = reply.len(), "failed to send UDP response");
        }
        received_in_row += 1;
        if received_in_row >= RECEIVED_BEFORE_YIELD {
            received_in_row = 0;
            tokio::task::yield_now().await;
        }
    }
}

/// 要等上游的查询交给单独的任务，在请求时限内回答，答不上回 SERVFAIL。流控拒绝时（过载），
/// 快速解析成了的立刻回一个现成的 SERVFAIL，非阻塞发送（发送缓冲满就丢掉，背压）；没成
/// 的多半是畸形包，静默丢弃——过载时要做最便宜的拒绝，对已经解析失败的包再完整解析一遍只会加重过载，
/// hickory 大概率同样失败。流控拒绝时返回 false。
/// A query that waits on an upstream goes to its own task, answered within the request
/// timeout and SERVFAIL when it cannot be. When flow control refuses it (overload), a query
/// the quick parse read gets a ready-made SERVFAIL at
/// once, sent without blocking (dropped when the send buffer is full, as backpressure); one
/// it could not read is most likely malformed and dropped silently. Overload rejection must
/// be cheap, and a full parse of an already-failed packet wastes CPU, as hickory most
/// likely fails too. Gives false when flow control refused it.
fn spawn_udp_answer(
    answering: &UdpAnswering<'_>,
    packet: bytes::Bytes,
    peer: SocketAddr,
    pre_parsed: Option<PreParsedData>,
) -> bool {
    // 轮流时内核跟不上已经丢过了，轮到这里的都该答，只看内存 / Taking turns, falling behind has already
    // dropped what it should, and what gets here is to be answered by memory alone
    let client = peer.ip();
    let permit = if answering.taking_turns {
        answering.engine.stream_query_permit(client)
    } else {
        answering.engine.query_permit(answering.emptied_at, client)
    };
    let Some(permit) = permit else {
        if let Some(pre_parsed) = pre_parsed
            && let Ok(response) = pre_parsed.servfail(packet[2] & 0x01 != 0)
        {
            try_send_udp_response(answering.socket, &packet, &response, peer);
        }
        return false;
    };
    let engine = Arc::clone(answering.engine);
    let socket = Arc::clone(answering.socket);
    let pending = Arc::clone(answering.pending);
    // 从排进去到开始跑等了多久：等上游不算在内，算的是内核自己跟不跟得上
    // How long it waits from being queued until it runs: waiting on an upstream is not in
    // this, so it tells whether the kernel itself keeps up
    let queued_at = engine.flow_control_state.is_some().then(Instant::now);
    tokio::spawn(async move {
        let _permit = permit; // 自动释放 / Auto-release on drop
        if let (Some(queued_at), Some(flow)) = (queued_at, &engine.flow_control_state) {
            flow.note_queue_delay(queued_at.elapsed());
        }
        // 答不上（处理失败、超时）回 SERVFAIL，读不了回 FORMERR / SERVFAIL when no answer came (a failure, a timeout), FORMERR when the query cannot be read
        let response = match engine
            .answer_after_fast_path(&packet, peer, pre_parsed)
            .await
        {
            Some(response) => response,
            None => match engine_helpers::try_build_listener_failure_from_wire(&packet) {
                Some(failure) => failure,
                None => return,
            },
        };
        let response = udp_reply(&packet, response);
        if !pending.try_queue(&response, peer)
            && let Err(error) = send_udp_datagram(&socket, &response, peer).await
        {
            debug!(%peer, %error, response_len = response.len(), "failed to send UDP response");
        }
    });
    true
}

async fn run_tcp(listener: TcpListener, engine: Engine) -> anyhow::Result<()> {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                // Never end the loop on an accept error (see accept_retry_delay)
                // 接受出错不退出循环（见 accept_retry_delay）
                warn!(error = %err, "tcp accept failed, retrying");
                tokio::time::sleep(kixdns::socket_utils::accept_retry_delay(&err)).await;
                continue;
            }
        };
        // RFC 1035 §4.2.2: DNS-over-TCP uses a 2-byte length prefix per message.
        // Disable Nagle's algorithm (TCP_NODELAY) to prevent the length-prefix write
        // and body write from being coalesced, which interacts badly with the peer's
        // delayed-ACK timer and adds ~40 ms latency per query.
        //
        // 禁用 Nagle 算法 (TCP_NODELAY)，避免长度前缀和包体两次写入被合并，
        // 否则与对端的 delayed-ACK 定时器交互导致每查询约 40ms 延迟。
        stream.set_nodelay(true).ok();
        // 内存不够时不接新连接，已有的连接照常 / With too little memory no new connection is taken, and those there go on
        let Some(permit) = engine.stream_query_permit(peer.ip()) else {
            continue;
        };
        let engine = engine.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = handle_tcp_conn(stream, peer, engine).await;
        });
    }
}

/// 入站 TCP 连接等待下一条消息、或等待当前消息剩余字节的时限。RFC 7766 §6.2.3
/// 建议服务端对空闲连接设数秒量级的超时：只建立连接却不发数据的客户端不应长期
/// 占用一个任务和一个文件描述符，而正常客户端在一个 RTT 内就会发完一条消息。
/// Time an inbound TCP connection may take to send the next message, or the rest
/// of the current one. RFC 7766 §6.2.3 recommends a server idle timeout in the
/// order of seconds: a client that connects without sending should not pin a
/// task and a file descriptor, while a normal client finishes a message within
/// one round trip.
const TCP_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// 同一条入站 TCP 连接上最多同时处理这么多个查询。RFC 7766 第 6.2.1.1 节：流水线发来的查询要并发
/// 处理、答完就回；以前一个接一个地处理，一个慢查询把后面的快查询都挡住。满了就先不读下一个，一个
/// 客户端开不出没有上限的任务。
/// At most this many queries are handled at once on one inbound TCP connection. RFC 7766
/// section 6.2.1.1: pipelined queries are handled concurrently and answered as they complete;
/// they used to be handled one after another, a slow one holding up every fast one behind
/// it. With all slots taken the next query is not read yet, so one client cannot start an
/// unbounded number of tasks.
const TCP_MAX_QUERIES_PER_CONN: usize = 64;

/// 一次至少读这么多：流水线发来的几个查询一次读进来，不再每个查询读两次（长度前缀、正文）
/// Each read asks for at least this much: queries pipelined together come in with one read,
/// instead of two reads (length prefix, body) per query
const TCP_READ_CHUNK: usize = 4096;

/// 当场答好的回答攒到这么多就先写出去，不等这一批读完 / Answers made on the spot are written out
/// once this much has gathered, without waiting for the rest of the batch
const TCP_ANSWERS_FLUSH: usize = 16 * 1024;

/// 从读进来的字节里取出下一个完整的消息（不带长度前缀）；还不完整时没有
/// Takes the next complete message (without its length prefix) out of the bytes read; none
/// while it is still incomplete
fn take_tcp_message(received: &mut bytes::BytesMut) -> Option<bytes::Bytes> {
    use bytes::Buf;

    let len = u16::from_be_bytes(received.get(..2)?.try_into().ok()?) as usize;
    if received.len() < 2 + len {
        return None;
    }
    received.advance(2);
    Some(received.split_to(len).freeze())
}

/// 当场答好的一个回答带上长度前缀排进 `answers`；放不进一个 TCP 消息的不发
/// Queues one answer made on the spot into `answers` with its length prefix; one that does not
/// fit a TCP message is not sent
fn queue_tcp_answer(answers: &mut bytes::BytesMut, response: &[u8]) {
    let Ok(len) = u16::try_from(response.len()) else {
        return;
    };
    answers.extend_from_slice(&len.to_be_bytes());
    answers.extend_from_slice(response);
}

async fn handle_tcp_conn(
    stream: TcpStream,
    peer: SocketAddr,
    engine: Engine,
) -> anyhow::Result<()> {
    serve_tcp_conn(stream, peer, engine, TCP_READ_TIMEOUT).await
}

/// 处理一条入站 TCP 连接；等下一个消息的长度前缀、等当前消息的正文，各最多 `read_timeout`（测试用短的）
/// Handles one inbound TCP connection; waiting for the next message's length prefix, and for the
/// current message's body, each take at most `read_timeout` (short in tests)
async fn serve_tcp_conn(
    stream: TcpStream,
    peer: SocketAddr,
    engine: Engine,
    read_timeout: Duration,
) -> anyhow::Result<()> {
    let engine = Arc::new(engine.with_client_transport(ClientTransport::Tcp));

    let (mut reader, writer) = stream.into_split();
    let writer = Arc::new(tokio::sync::Mutex::new(writer));
    let slots = Arc::new(tokio::sync::Semaphore::new(TCP_MAX_QUERIES_PER_CONN));
    let mut pending = tokio::task::JoinSet::<()>::new();
    // 读进来还没处理的字节：一次读到的可能是好几个查询，也可能是半个
    // Bytes read but not handled yet: one read may bring several queries, or half of one
    let mut received = bytes::BytesMut::with_capacity(TCP_READ_CHUNK);
    // 当场答好、还没写出去的回答，带着长度前缀；下一次读之前一次写出去
    // Answers made on the spot, with their length prefixes, not yet written; written in one go
    // before the next read
    let mut answers = bytes::BytesMut::new();
    // 复用的缓冲：缓存命中时在这里改 TTL 和 TXID / Reused buffer where a cache hit gets its TTLs and TXID patched
    let mut hit = bytes::BytesMut::new();
    // 正在等的是不是正文、等到什么时候：长度前缀和正文各有 read_timeout
    // Whether a body is being waited for, and until when: the length prefix and the body
    // each get read_timeout
    let mut waiting: Option<(bool, tokio::time::Instant)> = None;

    'connection: loop {
        // 收掉已经答完的 / Reap the ones already answered
        while pending.try_join_next().is_some() {}

        // 读进来的完整消息一个个处理：当场能答的排进 answers，要等上游的交给单独的任务，答完就回
        // Every complete message read is handled in turn: what is answered on the spot is
        // queued in answers, and what waits on an upstream goes to its own task, answered when done
        while let Some(packet_bytes) = take_tcp_message(&mut received) {
            waiting = None;
            if packet_bytes.is_empty() || !is_standard_query_header(&packet_bytes) {
                break 'connection;
            }
            // ✅ 优化：使用 handle_packet_fast 进行快速路径检查 / ✅ Optimization: Use handle_packet_fast for fast path check
            let async_needed = match engine.handle_packet_fast(&packet_bytes, peer) {
                Ok(Some(FastPathResponse::Direct(bytes))) => {
                    queue_tcp_answer(&mut answers, &bytes);
                    None
                }
                Ok(Some(FastPathResponse::CacheHit {
                    cached,
                    tx_id,
                    elapsed_secs,
                })) => {
                    write_cache_hit(&mut hit, &cached, tx_id, elapsed_secs);
                    queue_tcp_answer(&mut answers, &hit);
                    None
                }
                // 缓存未命中：使用预解析数据避免重复解析 / Cache miss: use pre-parsed data to avoid re-parsing
                Ok(Some(FastPathResponse::AsyncNeeded(pre_parsed))) => Some(Some(pre_parsed)),
                // 快速解析失败，回退到完整处理 / Fast parse failed, fallback to full processing
                Ok(None) => Some(None),
                Err(error) => {
                    engine.log_fast_path_error(&error);
                    if let Some(response) =
                        engine_helpers::try_build_listener_failure_from_wire(&packet_bytes)
                    {
                        queue_tcp_answer(&mut answers, &response);
                    }
                    None
                }
            };
            if answers.len() >= TCP_ANSWERS_FLUSH {
                write_tcp_answers(&writer, &mut answers).await;
            }
            let Some(pre_parsed) = async_needed else {
                continue;
            };
            let Some(permit) = engine.stream_query_permit(peer.ip()) else {
                if let Some(response) =
                    engine_helpers::try_build_listener_failure_from_wire(&packet_bytes)
                {
                    queue_tcp_answer(&mut answers, &response);
                }
                continue;
            };

            // 满了就先不读下一个；等之前把已经答好的写出去，它们不陪着等
            // With all slots taken the next query is not read yet; what is already answered
            // is written out first instead of waiting along
            let slot = match Arc::clone(&slots).try_acquire_owned() {
                Ok(slot) => slot,
                Err(_) => {
                    write_tcp_answers(&writer, &mut answers).await;
                    let Ok(slot) = Arc::clone(&slots).acquire_owned().await else {
                        break 'connection;
                    };
                    slot
                }
            };
            let engine = Arc::clone(&engine);
            let writer = Arc::clone(&writer);
            pending.spawn(async move {
                let _slot = slot;
                let _permit = permit;
                let answer = engine
                    .answer_after_fast_path(&packet_bytes, peer, pre_parsed)
                    .await
                    .or_else(|| {
                        engine_helpers::try_build_listener_failure_from_wire(&packet_bytes)
                    });
                if let Some(answer) = answer {
                    write_tcp_answer(&writer, &answer).await;
                }
            });
        }
        write_tcp_answers(&writer, &mut answers).await;

        // 读更多：至少要够把当前这个消息读完 / Read more: at least enough to finish the current message
        let in_body = received.len() >= 2;
        let deadline = match waiting {
            Some((body, deadline)) if body == in_body => deadline,
            _ => {
                let deadline = tokio::time::Instant::now() + read_timeout;
                waiting = Some((in_body, deadline));
                deadline
            }
        };
        let missing = match received.get(..2) {
            Some(prefix) => {
                2 + u16::from_be_bytes([prefix[0], prefix[1]]) as usize - received.len()
            }
            None => 2 - received.len(),
        };
        received.reserve(missing.max(TCP_READ_CHUNK));
        // 空闲超时、半截消息超时、对方读到头或出错：不再读，还在处理的查询写完回答后关闭连接，
        // 释放任务与文件描述符
        // Idle timeout, a half-sent message timing out, the peer's end of stream or an error:
        // reading stops, and once the queries still being handled have written their answers
        // the connection closes, releasing the task and the file descriptor
        if !matches!(
            tokio::time::timeout_at(deadline, reader.read_buf(&mut received)).await,
            Ok(Ok(1..))
        ) {
            break;
        }
    }

    // 读完了：先把当场答好的写出去，再等还在处理的查询把回答写出去，然后关连接；半关闭的客户端照样拿到回答
    // Reading is over: what was answered on the spot is written first, then the queries still
    // being handled write their answers before the connection closes, so a half-closed client
    // still gets them
    write_tcp_answers(&writer, &mut answers).await;
    while pending.join_next().await.is_some() {}
    Ok(())
}

/// 把排好的回答一次写出去，和 [`write_tcp_answer`] 一样：写端加锁，不和别的回答穿插；写不出去或
/// [`TCP_READ_TIMEOUT`] 内写不完时关掉写端
/// Writes the queued answers in one go, like [`write_tcp_answer`]: under the writer's lock, so
/// they cannot interleave with another answer; when they cannot be written, or not within
/// [`TCP_READ_TIMEOUT`], the write side is shut
async fn write_tcp_answers(
    writer: &tokio::sync::Mutex<tokio::net::tcp::OwnedWriteHalf>,
    answers: &mut bytes::BytesMut,
) {
    use tokio::io::AsyncWriteExt;

    if answers.is_empty() {
        return;
    }
    let mut writer = writer.lock().await;
    let written = tokio::time::timeout(TCP_READ_TIMEOUT, writer.write_all(answers)).await;
    if !matches!(written, Ok(Ok(()))) {
        let _ = writer.shutdown().await;
    }
    answers.clear();
}

/// 写回一个回答：长度前缀加正文一次写完，写端加锁，不会和别的回答穿插。写不出去或 [`TCP_READ_TIMEOUT`]
/// 内写不完（对方不读）时关掉写端：后面的回答立刻失败，任务不会一个个卡在这里。
/// Writes one answer back: length prefix and body in one go under the writer's lock, so it
/// cannot interleave with another answer. When it cannot be written, or not within
/// [`TCP_READ_TIMEOUT`] (the peer does not read), the write side is shut: later answers fail
/// at once instead of each task getting stuck here.
async fn write_tcp_answer(
    writer: &tokio::sync::Mutex<tokio::net::tcp::OwnedWriteHalf>,
    response: &[u8],
) {
    use tokio::io::AsyncWriteExt;

    if response.len() > u16::MAX as usize {
        return;
    }
    // DNS-over-TCP framing must be written completely; write_vectored may be
    // partial, so use write_all_vectored: scatter-gather single syscall with
    // no frame allocation (write_all would copy prefix+body into a new Vec).
    //
    // 长度前缀 + 包体用 write_all_vectored 保证完整写入，保持单 syscall 零分配；
    // write_all 需要拼帧（一次堆分配 + 拷贝）。
    let len_bytes = (response.len() as u16).to_be_bytes();
    let mut bufs = [
        std::io::IoSlice::new(&len_bytes),
        std::io::IoSlice::new(response),
    ];
    let mut writer = writer.lock().await;
    let written = tokio::time::timeout(
        TCP_READ_TIMEOUT,
        tokio_util::io::write_all_vectored(&mut *writer, &mut bufs),
    )
    .await;
    if !matches!(written, Ok(Ok(()))) {
        let _ = writer.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
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

    /// 没有面板时和上游一样：不带 `--debug` 不装观察者，带了装参考观察者；有面板时装的就是面板观察者
    /// Without the panel, as upstream: no observer without `--debug` and the reference observer
    /// with it; with the panel, the panel observer itself
    #[test]
    fn only_the_panel_brings_the_panel_observer() {
        assert!(super::engine_observer(None, false).is_none());
        assert!(super::engine_observer(None, true).is_some());
        let panel = Arc::new(super::PanelMetrics::new(false));
        for debug in [false, true] {
            let observer = super::engine_observer(Some(&panel), debug).unwrap();
            assert!(std::ptr::addr_eq(
                Arc::as_ptr(&observer),
                Arc::as_ptr(&panel)
            ));
        }
    }
    use super::*;
    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::{Name, RecordType};
    use hickory_proto::serialize::binary::BinDecodable;
    use std::str::FromStr;
    use tokio::io::AsyncWriteExt;

    #[ctor::ctor]
    fn init_crypto() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

    fn static_engine() -> Engine {
        Engine::new(static_runtime(), "test".to_string()).expect("initialize engine")
    }

    fn static_runtime() -> RuntimePipelineConfig {
        use kixdns::config::PipelineConfig;

        let config: PipelineConfig = serde_json::from_value(serde_json::json!({
            "settings": { "default_upstream": "127.0.0.1:9" },
            "pipelines": [{
                "id": "p",
                "rules": [{
                    "name": "static",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "static_ip_response", "ip": "192.0.2.1" }]
                }]
            }]
        }))
        .expect("parse config");
        RuntimePipelineConfig::from_config(config).expect("build runtime config")
    }

    /// 记录每个请求上报的传输 / Records the transport each request reports
    #[derive(Default)]
    struct TransportRecorder(std::sync::Mutex<Vec<Option<ClientTransport>>>);

    impl kixdns::observe::EngineObserver for TransportRecorder {
        fn request_started(&self, ctx: &kixdns::observe::RequestContext<'_>) {
            self.0.lock().unwrap().push(ctx.transport);
        }
    }

    /// UDP 与 TCP 监听器为交给引擎的请求标注查询经由的传输。
    /// The UDP and TCP listeners tag the requests they hand to the engine
    /// with the transport the query arrived over.
    #[tokio::test]
    async fn listeners_report_the_transport_the_query_arrived_over() {
        let recorder = Arc::new(TransportRecorder::default());
        let engine = Engine::builder(static_runtime())
            .observer(recorder.clone())
            .build()
            .expect("initialize engine");

        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server.local_addr().unwrap();
        let worker = tokio::spawn(run_udp_worker(0, Arc::clone(&server), engine.clone()));
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&dns_query(), server_addr).await.unwrap();
        let mut response = [0u8; 512];
        tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut response))
            .await
            .expect("udp answer")
            .unwrap();

        let (mut client, connection) = tcp_connection(engine.clone()).await;
        tcp_exchange(&mut client, &dns_query()).await;

        assert_eq!(
            *recorder.0.lock().unwrap(),
            [Some(ClientTransport::Udp), Some(ClientTransport::Tcp)]
        );
        worker.abort();
        connection.abort();
    }

    fn dns_query() -> Vec<u8> {
        query("data.xiaoheihe.cn", 0xCAFE)
    }

    /// 一批里的每个查询都拿到自己的回答：几个客户端排着的查询比一批还多，中间夹着坏包和不是查询的报文。
    /// 批量收发和一个一个收发的两种循环都这样
    /// Every query in a batch gets its own answer: several clients queue more queries than one batch
    /// holds, with malformed datagrams and non-queries among them. Both the batched and the one-by-one
    /// receive loops do so
    #[tokio::test]
    async fn every_queued_query_gets_its_own_answer() {
        #[cfg(target_os = "linux")]
        every_queued_query_is_answered_by(|server, engine| {
            tokio::spawn(async move { receive_in_batches(&server, &Arc::new(engine)).await })
        })
        .await;
        every_queued_query_is_answered_by(|server, engine| {
            tokio::spawn(async move { receive_one_by_one(&server, &Arc::new(engine)).await })
        })
        .await;
    }

    /// 排着的报文比一批多时，接收循环收一批就让出一次线程：同一线程上别的任务（要等上游的查询、上游回答的
    /// 接收）不必等排着的全收完才能跑。两种循环都这样
    /// With more datagrams queued than one batch, the receive loop yields its thread after each batch:
    /// other tasks on the same thread (queries waiting on an upstream, the readers of upstream answers)
    /// need not wait until the whole queue is received. Both loops do so
    #[tokio::test]
    async fn receive_loop_yields_while_datagrams_are_queued() {
        #[cfg(target_os = "linux")]
        yields_while_datagrams_are_queued(|server, engine| {
            tokio::spawn(async move { receive_in_batches(&server, &Arc::new(engine)).await })
        })
        .await;
        yields_while_datagrams_are_queued(|server, engine| {
            tokio::spawn(async move { receive_one_by_one(&server, &Arc::new(engine)).await })
        })
        .await;
    }

    async fn yields_while_datagrams_are_queued(
        receive: impl FnOnce(Arc<UdpSocket>, Engine) -> tokio::task::JoinHandle<()>,
    ) {
        const QUEUED: usize = 4 * RECEIVED_BEFORE_YIELD;
        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // 循环开始前查询全排进服务端 socket；静态规则当场回答，回答在下一次让出前就到了客户端
        // Every query is queued in the server socket before the loop starts; the static rule answers on
        // the spot, so the answers reach the client before the loop next yields
        for id in 0..QUEUED as u16 {
            client
                .send_to(&query("data.xiaoheihe.cn", id), server_addr)
                .await
                .unwrap();
        }
        let worker = receive(server, static_engine());

        // 这个测试本身就是同一线程上的别的任务：每轮取走已经到的回答，记下一轮最多取到几个
        // This test is itself the other task on the thread: each turn it takes the answers that have
        // arrived, noting the most taken in one turn
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut buf = [0u8; 512];
        let (mut answered, mut most_in_one_turn) = (0, 0);
        while answered < QUEUED {
            assert!(
                tokio::time::Instant::now() < deadline,
                "only {answered} of {QUEUED} answered"
            );
            tokio::task::yield_now().await;
            let mut this_turn = 0;
            while client.try_recv_from(&mut buf).is_ok() {
                this_turn += 1;
            }
            answered += this_turn;
            most_in_one_turn = most_in_one_turn.max(this_turn);
        }
        worker.abort();
        assert!(
            most_in_one_turn <= 2 * RECEIVED_BEFORE_YIELD,
            "{most_in_one_turn} of {QUEUED} queued answers came in one turn: the receive loop kept the thread"
        );
    }

    /// 记录每个请求的客户端地址 / Records each request's client address
    #[derive(Default)]
    struct ClientRecorder(std::sync::Mutex<Vec<SocketAddr>>);

    impl kixdns::observe::EngineObserver for ClientRecorder {
        fn request_started(&self, ctx: &kixdns::observe::RequestContext<'_>) {
            self.0.lock().unwrap().push(ctx.client);
        }
    }

    async fn every_queued_query_is_answered_by(
        receive: impl FnOnce(Arc<UdpSocket>, Engine) -> tokio::task::JoinHandle<()>,
    ) {
        let recorder = Arc::new(ClientRecorder::default());
        let engine = Engine::builder(static_runtime())
            .observer(recorder.clone())
            .build()
            .expect("initialize engine");
        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server.local_addr().unwrap();
        let mut clients = Vec::new();
        for _ in 0..6 {
            clients.push(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        }
        // worker 起来之前全排进接收队列：第一次收就是满满一批，后面还有 / All queued before the
        // worker starts: the first receive is a full batch, with more behind it
        const PER_CLIENT: u16 = 12;
        for (c, client) in (0u16..).zip(&clients) {
            for q in 0..PER_CLIENT {
                let name = format!("q{q}.c{c}.example");
                client
                    .send_to(&query(&name, c * 100 + q), server_addr)
                    .await
                    .unwrap();
            }
            client.send_to(&[0x12, 0x34], server_addr).await.unwrap();
            let mut answer_not_query = query("x.example", 0x7777);
            answer_not_query[2] |= 0x80;
            client
                .send_to(&answer_not_query, server_addr)
                .await
                .unwrap();
        }
        let worker = receive(Arc::clone(&server), engine);

        for (c, client) in (0u16..).zip(&clients) {
            let mut ids = Vec::new();
            for _ in 0..PER_CLIENT {
                let mut buf = [0u8; 512];
                let (len, _) =
                    tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
                        .await
                        .expect("every query is answered")
                        .unwrap();
                let response = Message::from_bytes(&buf[..len]).unwrap();
                let id = response.metadata.id;
                assert_eq!(id / 100, c, "an answer reached the wrong client");
                assert_eq!(
                    response.queries[0].name().to_string(),
                    format!("q{}.c{c}.example.", id % 100)
                );
                assert_eq!(response.answers.len(), 1);
                ids.push(id);
            }
            ids.sort_unstable();
            assert_eq!(
                ids,
                (0..PER_CLIENT).map(|q| c * 100 + q).collect::<Vec<_>>()
            );
            let mut buf = [0u8; 512];
            assert!(
                tokio::time::timeout(Duration::from_millis(100), client.recv_from(&mut buf))
                    .await
                    .is_err(),
                "malformed datagrams and non-queries get no answer"
            );
        }
        worker.abort();
        // 引擎看到的客户端就是发来这个查询的那个 / The engine sees as the client the one that sent the query
        let mut seen = recorder.0.lock().unwrap().clone();
        seen.sort_unstable();
        let mut sent = Vec::new();
        for client in &clients {
            sent.extend([client.local_addr().unwrap(); PER_CLIENT as usize]);
        }
        sent.sort_unstable();
        assert_eq!(seen, sent);
    }

    #[tokio::test]
    async fn udp_static_fast_path_rejects_non_query_and_malformed_additional_records() {
        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server.local_addr().unwrap();
        let worker = tokio::spawn(run_udp_worker(0, Arc::clone(&server), static_engine()));
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let mut qr_response = dns_query();
        qr_response[2] |= 0x80;

        let mut missing_additional = dns_query();
        missing_additional[11] = 1;

        let mut truncated_edns = dns_query();
        truncated_edns[11] = 1;
        truncated_edns.extend_from_slice(&[0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 4, 0, 1]);

        let mut invalid_pointer = dns_query();
        invalid_pointer[11] = 1;
        invalid_pointer.extend_from_slice(&[0xC0, 0xFF, 0, 16, 0, 1, 0, 0, 0, 0, 0, 0]);

        let mut response_buf = [0u8; 512];
        client.send_to(&qr_response, server_addr).await.unwrap();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(100),
                client.recv_from(&mut response_buf),
            )
            .await
            .is_err(),
            "QR=1 gets no answer, so there is nothing to reflect"
        );
        for (case, packet) in [
            ("missing Additional RR", missing_additional),
            ("truncated EDNS RDATA", truncated_edns),
            ("invalid Additional compression pointer", invalid_pointer),
        ] {
            client.send_to(&packet, server_addr).await.unwrap();
            let (len, _) =
                tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut response_buf))
                    .await
                    .unwrap_or_else(|_| panic!("{case} should get FORMERR"))
                    .unwrap();
            let response = Message::from_bytes(&response_buf[..len]).unwrap();
            assert_eq!(
                response.metadata.response_code,
                ResponseCode::FormErr,
                "{case}"
            );
            assert!(
                response.answers.is_empty(),
                "{case} must be rejected before static/cache fast paths"
            );
        }

        worker.abort();
    }

    /// 请求头是标准查询、报文读不了的回 FORMERR（RFC 6891 第 6.1.1 节），带上它的 ID、RD 和问题，不比查询长。
    /// 批量收发、一个一个收发和 TCP 都这样；超过接收缓冲的 UDP 查询被截断后也算这一类
    /// A query with a standard header that cannot be read gets FORMERR (RFC 6891 section
    /// 6.1.1) with its ID, RD and question, no longer than the query. So in the batched
    /// and one-by-one receive loops and over TCP; a UDP query cut off at the receive buffer
    /// counts too
    #[tokio::test]
    async fn a_query_that_cannot_be_read_gets_formerr() {
        #[cfg(target_os = "linux")]
        formerr_on_udp(|server, engine| {
            tokio::spawn(async move { receive_in_batches(&server, &Arc::new(engine)).await })
        })
        .await;
        formerr_on_udp(|server, engine| {
            tokio::spawn(async move { receive_one_by_one(&server, &Arc::new(engine)).await })
        })
        .await;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(run_tcp(listener, static_engine()));
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        for (case, packet) in unreadable_queries() {
            stream
                .write_all(&(packet.len() as u16).to_be_bytes())
                .await
                .unwrap();
            stream.write_all(&packet).await.unwrap();
            let mut length = [0u8; 2];
            stream.read_exact(&mut length).await.unwrap();
            let mut reply = vec![0u8; u16::from_be_bytes(length) as usize];
            stream.read_exact(&mut reply).await.unwrap();
            assert_is_formerr_for(&reply, &packet, case);
        }
        server.abort();
    }

    async fn formerr_on_udp(
        receive: impl FnOnce(Arc<UdpSocket>, Engine) -> tokio::task::JoinHandle<()>,
    ) {
        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server.local_addr().unwrap();
        let worker = receive(server, static_engine());
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut too_long = dns_query();
        too_long[11] = 1;
        let padding = 4400u16;
        too_long.extend_from_slice(&[0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0]);
        too_long.extend_from_slice(&(padding + 4).to_be_bytes());
        too_long.extend_from_slice(&[0, 12]);
        too_long.extend_from_slice(&padding.to_be_bytes());
        too_long.resize(too_long.len() + padding as usize, 0);
        let mut buf = [0u8; 512];
        for (case, packet) in unreadable_queries()
            .into_iter()
            .chain([("over 4096 bytes", too_long)])
        {
            client.send_to(&packet, server_addr).await.unwrap();
            let (len, _) = tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf))
                .await
                .unwrap_or_else(|_| panic!("{case} should get FORMERR"))
                .unwrap();
            assert_is_formerr_for(&buf[..len], &packet, case);
        }
        worker.abort();
    }

    fn unreadable_queries() -> Vec<(&'static str, Vec<u8>)> {
        let opt = [0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0];
        let mut two_opts = dns_query();
        two_opts[11] = 2;
        two_opts.extend_from_slice(&opt);
        two_opts.extend_from_slice(&opt);
        let mut opt_after_the_end = dns_query();
        opt_after_the_end[11] = 2;
        opt_after_the_end.extend_from_slice(&opt);
        vec![
            ("two OPT records", two_opts),
            ("a record missing", opt_after_the_end),
        ]
    }

    fn assert_is_formerr_for(reply: &[u8], query: &[u8], case: &str) {
        let reply_message = Message::from_bytes(reply).unwrap();
        assert_eq!(
            reply_message.metadata.response_code,
            ResponseCode::FormErr,
            "{case}"
        );
        assert_eq!(
            reply_message.metadata.message_type,
            MessageType::Response,
            "{case}"
        );
        assert_eq!(reply_message.metadata.id, 0xCAFE, "{case}");
        assert!(reply_message.metadata.recursion_desired, "{case}");
        assert_eq!(
            reply_message.queries,
            Message::from_bytes(&dns_query()).unwrap().queries,
            "{case}"
        );
        assert!(reply.len() <= query.len(), "{case}: no amplification");
    }

    fn forwarding_engine() -> Engine {
        use kixdns::config::PipelineConfig;

        let config: PipelineConfig = serde_json::from_value(serde_json::json!({
            "settings": {
                "default_upstream": "127.0.0.1:9",
                "flow_control_enabled": true
            },
            "pipelines": [{
                "id": "p",
                "rules": [{
                    "name": "forward",
                    "matchers": [{ "type": "any" }],
                    "actions": [{
                        "type": "forward",
                        "upstream": "127.0.0.1:9",
                        "transport": "udp"
                    }]
                }]
            }]
        }))
        .expect("parse config");
        let runtime = RuntimePipelineConfig::from_config(config).expect("build runtime config");
        let engine = Engine::new(runtime, "test".to_string()).expect("initialize engine");
        with_busy_after(engine, Duration::ZERO)
    }

    fn doh_timeout_engine(upstream: &str) -> Engine {
        Engine::new(doh_timeout_config(upstream, 50), "test".to_string())
            .expect("initialize engine")
    }

    fn doh_timeout_config(upstream: &str, timeout_ms: u64) -> RuntimePipelineConfig {
        use kixdns::config::PipelineConfig;

        let config: PipelineConfig = serde_json::from_value(serde_json::json!({
            "settings": {
                "default_upstream": upstream,
                "upstream_timeout_ms": timeout_ms,
                "request_timeout_ms": timeout_ms
            },
            "pipelines": [{
                "id": "p",
                "rules": [{
                    "name": "forward",
                    "matchers": [{ "type": "any" }],
                    "actions": [{
                        "type": "forward",
                        "upstream": upstream,
                        "transport": "doh"
                    }]
                }]
            }]
        }))
        .expect("parse config");
        RuntimePipelineConfig::from_config(config).expect("build runtime config")
    }

    #[tokio::test]
    async fn udp_send_datagram_surfaces_socket_errors() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ipv6_peer: SocketAddr = "[::1]:53".parse().unwrap();
        assert!(send_udp_datagram(&socket, b"dns", ipv6_peer).await.is_err());
    }

    /// 查询一直算排长队、上游慢的引擎，只差内核忙不忙就会拒绝。`busy_after_ms` 是 socket 多久没收空算忙
    /// An engine with queries always counting as queueing long and a slow upstream, refusing as
    /// soon as the kernel is busy, `busy_after_ms` being how long a socket goes without running
    /// empty before that counts as busy
    async fn behind_engine_with_slow_upstream(busy_after_ms: u64) -> Engine {
        let upstream = spawn_slow_udp_upstream(Duration::from_millis(300)).await;
        let engine = with_busy_after(
            engine_forwarding_to(
                upstream,
                serde_json::json!({ "flow_control_enabled": true }),
            ),
            Duration::from_millis(busy_after_ms),
        );
        engine
            .flow_control_state
            .as_ref()
            .unwrap()
            .note_queue_delay(Duration::from_secs(3600));
        engine
    }

    /// 发出 `count` 个不同的查询，数被拒绝（SERVFAIL）的和答上来的
    /// Sends `count` different queries and counts those refused (SERVFAIL) and those answered
    async fn refused_and_answered(client: &UdpSocket, count: u16) -> (u16, u16) {
        let (mut refused, mut answered) = (0, 0);
        let mut buf = [0u8; 512];
        for _ in 0..count {
            let (len, _) = tokio::time::timeout(Duration::from_secs(3), client.recv_from(&mut buf))
                .await
                .expect("every query gets a reply")
                .unwrap();
            match Message::from_bytes(&buf[..len])
                .unwrap()
                .metadata
                .response_code
            {
                ResponseCode::ServFail => refused += 1,
                _ => answered += 1,
            }
        }
        (refused, answered)
    }

    /// 上游慢时，等着的查询再多也不拒绝：内核并不忙，它们都等得到回答。两种循环都这样
    /// With a slow upstream, however many queries wait they are not refused: the kernel is not busy and
    /// they all get their answers. Both loops do so
    #[tokio::test]
    async fn queries_waiting_on_a_slow_upstream_are_not_refused() {
        #[cfg(target_os = "linux")]
        not_refused_while_waiting_on_an_upstream(|server, engine| {
            tokio::spawn(async move { receive_in_batches(&server, &Arc::new(engine)).await })
        })
        .await;
        not_refused_while_waiting_on_an_upstream(|server, engine| {
            tokio::spawn(async move { receive_one_by_one(&server, &Arc::new(engine)).await })
        })
        .await;
    }

    async fn not_refused_while_waiting_on_an_upstream(
        receive: impl FnOnce(Arc<UdpSocket>, Engine) -> tokio::task::JoinHandle<()>,
    ) {
        let engine = behind_engine_with_slow_upstream(2_000).await;
        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server.local_addr().unwrap();
        let worker = receive(server, engine);
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        const QUERIES: u16 = 8;
        for id in 0..QUERIES {
            let query = query(&format!("q{id}.slow.test"), id);
            client.send_to(&query, server_addr).await.unwrap();
            // 一个一个来，socket 每次都收得空 / One at a time, so the socket runs empty each time
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(refused_and_answered(&client, QUERIES).await, (0, QUERIES));
        worker.abort();
    }

    /// 积压着而且在丢包时接收缓冲收小，收空了放回去。没丢包、没积压、上一段积压留下的丢包数都不算。没开流控也一样
    /// While backed up and dropping the receive buffer shrinks, and running empty puts it back. No drops, no
    /// backlog and the drops left from an earlier backlog do not count. The same without flow control
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn the_receive_buffer_shrinks_only_while_overflowing_and_comes_back() {
        let engine = Arc::new(Engine::new(static_runtime(), "test".to_string()).unwrap());
        assert!(engine.flow_control_state.is_none());
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let target = socket.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let size = || {
            socket2::SockRef::from(socket.as_ref())
                .recv_buffer_size()
                .unwrap()
        };
        socket2::SockRef::from(socket.as_ref())
            .set_recv_buffer_size(UDP_BUFFER_SIZE)
            .unwrap();
        let full = size();
        // 一直发到丢包为止 / Sends until it drops
        let overflow = || async {
            let before = kixdns::socket_utils::udp_receive_drops(&socket).unwrap();
            for _ in 0..500_000 {
                client.send_to(&[0u8; 64], target).await.unwrap();
                if kixdns::socket_utils::udp_receive_drops(&socket).unwrap() != before {
                    return;
                }
            }
            panic!("the socket never dropped");
        };
        let pending = Arc::new(PendingReplies::default());
        let mut answering = UdpAnswering::new(&socket, &engine, &pending);
        // 看一次丢包数：处理那些查询用了一秒 / One reading of the drops: the queries took a second
        let look = |answering: &mut UdpAnswering<'_>| {
            answering.checks_since_empty = 2 * BEHIND_AFTER_CHECKS - 1;
            answering.looked_at = Instant::now() - Duration::from_secs(1);
            answering.shrink_buffer_if_overflowing();
        };

        // 积压着、队列还在涨，但没丢包 / Backed up with the queue still growing, but no drops
        look(&mut answering);
        client.send_to(&[0u8; 64], target).await.unwrap();
        look(&mut answering);
        assert!(!answering.buffer_shrunk, "no drops");
        assert_eq!(size(), full);

        overflow().await;
        answering.behind_at = Instant::now() - Duration::from_secs(3600);
        look(&mut answering);
        assert!(answering.buffer_shrunk);
        assert!(
            answering.behind_at.elapsed() < Duration::from_secs(60),
            "noted"
        );
        let shrunk = size();
        assert!(shrunk < full, "{shrunk} of {full}");

        // 这一段积压第一次看量不出速度，不动缓冲 / The first look of a backlog measures no speed and leaves the buffer
        overflow().await;
        answering.checks_since_empty = BEHIND_AFTER_CHECKS - 1;
        answering.looked_at = Instant::now() - Duration::from_millis(1);
        answering.shrink_buffer_if_overflowing();
        assert_eq!(size(), shrunk);

        // 刚才还在丢包，收空了也不放回去；又丢了就重新算 / Dropping a moment ago, running empty does not put
        // it back; new drops start the wait over
        let long_ago = || Instant::now() - CAUGHT_UP_AFTER - Duration::from_millis(1);
        answering.behind_at = Instant::now();
        answering.socket_ran_empty();
        assert!(answering.buffer_shrunk, "dropping a moment ago");
        overflow().await;
        answering.behind_at = long_ago();
        answering.note_drops_before_waiting();
        answering.socket_ran_empty();
        assert!(answering.buffer_shrunk, "new drops");
        assert_eq!(size(), shrunk);

        // 丢包停得够久才放回去 / Only with the drops stopped long enough does it go back
        answering.behind_at = long_ago();
        answering.note_drops_before_waiting();
        answering.socket_ran_empty();
        assert!(!answering.buffer_shrunk);
        assert_eq!(size(), full);

        // 没积压时丢包也不算 / Drops do not count without a backlog
        answering.shrink_buffer_if_overflowing();
        overflow().await;
        answering.shrink_buffer_if_overflowing();
        assert!(!answering.buffer_shrunk, "no backlog");

        // 上一段积压留下的丢包数不算：新的一段先记下来 / The drops left from an earlier backlog do not count:
        // a new backlog first notes the count
        look(&mut answering);
        assert!(!answering.buffer_shrunk, "old drops");

        // 每 1000 个查询读一次丢包数 / The drops are read once every 1000 queries
        overflow().await;
        let peer = SocketAddr::from(([127, 0, 0, 1], 53000));
        let mut reply = BytesMut::new();
        answering.checks_since_empty = BEHIND_AFTER_CHECKS;
        answering.looked_at = Instant::now() - Duration::from_secs(1);
        for id in 0..999 {
            answering.answer(&query("a.test", id), peer, &mut reply);
        }
        assert!(!answering.buffer_shrunk);
        answering.answer(&query("a.test", 999), peer, &mut reply);
        assert!(answering.buffer_shrunk);
    }

    /// 开了流控接收缓冲一直是大的，过载了、轮流时都不收小，但丢包还算没跟上；等之前的丢包不算等完才丢的
    /// With flow control the receive buffer stays large, overloaded or taking turns, yet drops still
    /// count as falling behind; drops from before a wait do not count as just after it
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn taking_turns_keeps_the_large_receive_buffer() {
        let engine = static_engine_with_flow_control();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let target = socket.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let size = || {
            socket2::SockRef::from(socket.as_ref())
                .recv_buffer_size()
                .unwrap()
        };
        socket2::SockRef::from(socket.as_ref())
            .set_recv_buffer_size(UDP_BUFFER_SIZE)
            .unwrap();
        let full = size();
        let overflow = || async {
            let before = kixdns::socket_utils::udp_receive_drops(&socket).unwrap();
            for _ in 0..500_000 {
                client.send_to(&[0u8; 64], target).await.unwrap();
                if kixdns::socket_utils::udp_receive_drops(&socket).unwrap() != before {
                    return;
                }
            }
            panic!("the socket never dropped");
        };
        let pending = Arc::new(PendingReplies::default());
        let mut answering = UdpAnswering::new(&socket, &engine, &pending);
        let look = |answering: &mut UdpAnswering<'_>| {
            answering.checks_since_empty = 2 * BEHIND_AFTER_CHECKS - 1;
            answering.looked_at = Instant::now() - Duration::from_secs(1);
            answering.shrink_buffer_if_overflowing();
        };
        let long_ago = || Instant::now() - CAUGHT_UP_AFTER - Duration::from_millis(1);

        look(&mut answering);
        overflow().await;
        // 开了流控，过载了（跟不上够久）也不收小：过载就按设备轮流 / With flow control even overload
        // (behind long enough) does not shrink it: overload means taking turns
        answering.behind_since = Instant::now() - BEHIND_BEFORE_TURNS - Duration::from_millis(1);
        answering.behind_at = Instant::now();
        look(&mut answering);
        assert!(answering.overloaded);
        assert!(!answering.buffer_shrunk);
        assert_eq!(size(), full);

        let _turns = answering.begin_turns();

        // 还在丢包、还过载着：轮流时也不收小，但丢包还算没跟上
        // Still dropping and still overloaded: while taking turns it is not shrunk either, yet the
        // drops still count as falling behind
        overflow().await;
        answering.behind_since = Instant::now() - BEHIND_BEFORE_TURNS - Duration::from_millis(1);
        answering.behind_at = Instant::now();
        look(&mut answering);
        assert!(
            answering.overloaded,
            "overloaded, yet taking turns keeps it large"
        );
        assert!(!answering.buffer_shrunk);
        assert_eq!(size(), full);
        assert!(answering.behind_at.elapsed() < CAUGHT_UP_AFTER, "noted");

        // 读空前丢的包也算 / Drops up to the socket being read empty count too
        overflow().await;
        answering.behind_at = long_ago();
        answering.note_drops_before_waiting();
        answering.socket_ran_empty();
        assert!(answering.taking_turns, "new drops");

        // 等了够久，等之前丢的包不算刚丢的 / After a long enough wait the drops before it are not
        // counted as just happened
        overflow().await;
        answering.note_drops_before_waiting();
        answering.behind_at = long_ago();
        answering.socket_ran_empty();
        assert!(!answering.taking_turns, "caught up");
        assert_eq!(size(), full);
    }

    /// 收小以后放得下的正好是这台机器 20 ms 处理得完的查询，机器越慢缓冲越小
    /// Once shrunk it holds just what this machine handles in 20 ms, so the slower the machine the smaller the buffer
    #[test]
    fn the_shrunk_receive_buffer_follows_the_speed() {
        // 每秒 5 万个，20 ms 是 1000 个 / At 50k a second, 20 ms is 1000
        assert_eq!(
            recv_buffer_when_behind(queries_within_target(Duration::from_millis(20))),
            1000 * RECV_BUFFER_PER_QUERY
        );
        // 每秒 1 万个，20 ms 是 200 个 / At 10k a second, 20 ms is 200
        assert_eq!(
            recv_buffer_when_behind(queries_within_target(Duration::from_millis(100))),
            200 * RECV_BUFFER_PER_QUERY
        );
        // 再慢也放得下两批 / However slow it holds two batches
        assert_eq!(
            recv_buffer_when_behind(queries_within_target(Duration::from_secs(60))),
            MIN_QUERIES_IN_RECV_BUFFER * RECV_BUFFER_PER_QUERY
        );
        // 再快也不比平时大 / However fast it is no larger than usual
        assert_eq!(
            recv_buffer_when_behind(queries_within_target(Duration::ZERO)),
            UDP_BUFFER_SIZE
        );
    }

    /// 开着流控、对什么查询都当场回答的引擎 / An engine with flow control answering every query on the spot
    fn static_engine_with_flow_control() -> Arc<Engine> {
        use kixdns::config::PipelineConfig;

        let config: PipelineConfig = serde_json::from_value(serde_json::json!({
            "settings": { "default_upstream": "127.0.0.1:9", "flow_control_enabled": true },
            "pipelines": [{
                "id": "p",
                "rules": [{
                    "name": "static",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "static_ip_response", "ip": "192.0.2.1" }]
                }]
            }]
        }))
        .unwrap();
        Arc::new(
            Engine::new(
                RuntimePipelineConfig::from_config(config).unwrap(),
                "test".to_string(),
            )
            .unwrap(),
        )
    }

    /// 跟不上持续够久、刚才还在跟不上、开着流控，三样都有才算过载；丢包和这个 worker 自己的查询被拒都算跟不上，
    /// 别处的拒绝不算
    /// Overload takes all three: falling behind for long enough, still so a moment ago, and flow
    /// control on; drops and refusals of this worker's own queries both count as falling behind,
    /// refusals elsewhere do not
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn overload_takes_lasting_trouble_and_flow_control() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let pending = Arc::new(PendingReplies::default());
        let drops = kixdns::socket_utils::udp_receive_drops(&socket).unwrap();
        let dropping = drops.wrapping_add(1);
        let long_ago = || Instant::now() - Duration::from_secs(5);
        let look = |answering: &mut UdpAnswering<'_>, since: Instant, at: Instant, seen: u32| {
            answering.behind_since = since;
            answering.behind_at = at;
            answering.drops_seen = Some(seen);
            answering.checks_since_empty = 2 * BEHIND_AFTER_CHECKS - 1;
            answering.shrink_buffer_if_overflowing();
        };
        let with_flow = static_engine_with_flow_control();
        let mut answering = UdpAnswering::new(&socket, &with_flow, &pending);

        look(&mut answering, long_ago(), Instant::now(), dropping);
        assert!(answering.overloaded);
        look(&mut answering, Instant::now(), Instant::now(), dropping);
        assert!(!answering.overloaded, "not for long enough");
        look(&mut answering, long_ago(), long_ago(), dropping);
        assert!(!answering.overloaded, "a new spell begins");
        assert!(answering.behind_since.elapsed() < BEHIND_BEFORE_TURNS);
        assert!(answering.behind_at.elapsed() < CAUGHT_UP_AFTER);
        let since = long_ago();
        look(&mut answering, since, Instant::now(), dropping);
        assert_eq!(answering.behind_since, since, "the spell goes on");
        look(&mut answering, long_ago(), Instant::now(), drops);
        assert!(answering.overloaded, "a short pause does not end it");
        look(&mut answering, long_ago(), long_ago(), drops);
        assert!(!answering.overloaded, "it is over");

        // 自己的查询被拒也算；别的 worker、TCP 和 DoH 的拒绝不算 / Its own queries refused count too;
        // refusals in another worker or over TCP and DoH do not
        with_flow.permit_manager.count_refused();
        look(&mut answering, long_ago(), long_ago(), drops);
        assert!(
            answering.behind_at.elapsed() > CAUGHT_UP_AFTER,
            "a refusal elsewhere"
        );
        answering.refused = true;
        look(&mut answering, long_ago(), long_ago(), drops);
        assert!(
            answering.behind_at.elapsed() < CAUGHT_UP_AFTER,
            "its own refusal"
        );
        let at = long_ago();
        look(&mut answering, long_ago(), at, drops);
        assert_eq!(answering.behind_at, at, "no new refusal");

        let without_flow = Arc::new(Engine::new(static_runtime(), "test".to_string()).unwrap());
        let mut answering = UdpAnswering::new(&socket, &without_flow, &pending);
        look(&mut answering, long_ago(), Instant::now(), dropping);
        assert!(!answering.overloaded, "flow control off");
    }

    /// 轮流时跟不上：还排着队的设备丢一个，只排了一个的照常答；丢的本身不算还在跟不上，那要看积压
    /// Falling behind while taking turns: a device with more queued loses one and one with a
    /// single query is answered; the drop itself is not still falling behind, the backlog tells that
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn falling_behind_drops_only_from_a_device_with_more_queued() {
        let engine = static_engine_with_flow_control();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let pending = Arc::new(PendingReplies::default());
        let mut answering = UdpAnswering::new(&socket, &engine, &pending);
        let mut replies = udp_batch::Replies::default();
        let packet = query("a.test", 1);
        let peer = |last: u8| udp_batch::Peer::of(SocketAddr::from(([192, 0, 2, last], 53000)));
        let device = |last: u8| Device::of([192, 0, 2, last].into());

        // 三个查询排在第一台，再找一台和它不落在一起的；落在一起的算第一台的
        // Three queries for the first device, then one that does not land with it; any that
        // does counts as the first's
        let mut heavy = 3;
        let fill = |turns: &mut TakingTurns, heavy: &mut u64| {
            for _ in 0..3 {
                turns.queue.offer(&packet, device(1), peer(1));
            }
            let light = (2..=255)
                .find(|&last| {
                    turns.queue.offer(&packet, device(last), peer(last));
                    *heavy += 1;
                    turns.queue.devices() == 2
                })
                .unwrap();
            *heavy -= 1;
            light
        };
        let mut turns = TakingTurns::new(1000, QUERIES_IN_RECV_BUFFER);
        let light = fill(&mut turns, &mut heavy);

        // 没跟不上时都答 / All are answered when not falling behind
        turns.answer_in_turn(&mut answering, &mut replies);
        assert_eq!(engine.permit_manager.dropped_requests(), 0);
        assert_eq!(replies.len() as u64, heavy + 1);
        replies.clear();

        let mut heavy = 3;
        let light_again = fill(&mut turns, &mut heavy);
        assert_eq!(light_again, light, "the same hash");
        engine
            .flow_control_state
            .as_ref()
            .unwrap()
            .note_queue_delay(Duration::from_secs(3600));
        answering.behind_at = Instant::now() - Duration::from_secs(5);
        turns.answer_in_turn(&mut answering, &mut replies);
        assert_eq!(engine.permit_manager.dropped_requests(), heavy - 1);
        assert_eq!(
            replies.len(),
            2,
            "the light device, and the last of the other"
        );
        assert_eq!(replies.get(0).unwrap().1, peer(light).addr());
        assert!(
            answering.behind_at.elapsed() > CAUGHT_UP_AFTER,
            "a drop is no sign of falling behind"
        );
    }

    /// 排不下的丢掉并计数；不轮流的话缓冲放得下就不算跟不上，放不下才算
    /// What does not fit is dropped and counted; it is falling behind only when the buffer would
    /// not hold it without turns either
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn what_does_not_fit_counts_only_when_the_buffer_would_overflow() {
        use std::os::fd::AsRawFd;

        let engine = static_engine_with_flow_control();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for _ in 0..5 {
            client
                .send_to(b"query", socket.local_addr().unwrap())
                .await
                .unwrap();
        }
        let pending = Arc::new(PendingReplies::default());
        let mut answering = UdpAnswering::new(&socket, &engine, &pending);
        let mut received = udp_batch::Received::default();
        let got = received.recv(socket.as_raw_fd()).unwrap();
        assert_eq!(got, 5);

        let mut turns = TakingTurns::new(2, QUERIES_IN_RECV_BUFFER);
        answering.behind_at = Instant::now() - Duration::from_secs(5);
        turns.queue_received(&received, got, &mut answering);
        assert_eq!(engine.permit_manager.dropped_requests(), 3);
        assert!(
            answering.behind_at.elapsed() > CAUGHT_UP_AFTER,
            "the buffer would hold them"
        );

        // 积压已经满了，不轮流的话这几个内核会丢 / With the backlog full, the kernel would drop these
        // without turns
        let mut turns = TakingTurns::new(100, QUERIES_IN_RECV_BUFFER);
        turns.backlog = turns.holds;
        turns.counted_at = Instant::now() + Duration::from_secs(3600);
        turns.queue_received(&received, got, &mut answering);
        assert!(
            answering.behind_at.elapsed() < CAUGHT_UP_AFTER,
            "past the buffer"
        );
        assert_eq!(engine.permit_manager.dropped_requests(), 3, "all fit");
    }

    /// 不轮流时的积压：读到的加上，按量到的速度消掉，到缓冲放得下的为止
    /// The backlog without turns: what is read adds to it, the measured speed works it off, and it
    /// stops at what the buffer holds
    #[cfg(target_os = "linux")]
    #[test]
    fn the_backlog_without_turns_is_worked_off_at_the_measured_speed() {
        let start = Instant::now();
        let mut turns = TakingTurns::new(10, QUERIES_IN_RECV_BUFFER);
        turns.counted_at = start;
        assert!(
            !turns.would_overflow(QUERIES_IN_RECV_BUFFER, 64, start),
            "just full"
        );
        assert!(turns.would_overflow(1, 64, start), "one more");
        assert_eq!(turns.backlog, QUERIES_IN_RECV_BUFFER);
        let later = start + QUEUE_TARGET;
        assert!(!turns.would_overflow(64, 64, later), "64 handled meanwhile");
        assert!(turns.would_overflow(1, 64, later));
        let much_later = later + Duration::from_secs(3600);
        assert!(!turns.would_overflow(0, 64, much_later));
        assert_eq!(turns.backlog, 0, "worked off");

        // 每半秒发一批、比份额多得多，平均却没到处理能力：缓冲接得住 / A batch far past the share
        // every half second, below capacity on average: the buffer catches it
        let mut at = much_later;
        for _ in 0..20 {
            at += Duration::from_millis(500);
            assert!(
                !turns.would_overflow(1000, 64, at),
                "{} held",
                turns.backlog
            );
        }
        // 平均超出处理能力：迟早放不下 / Past capacity on average: sooner or later it does not fit
        let overflowed = (0..100).any(|_| {
            at += Duration::from_millis(500);
            turns.would_overflow(2000, 64, at)
        });
        assert!(overflowed);
    }

    /// 洪泛停了，一台设备每次发得比自己那一份多、平均却没到处理能力：排不下的照丢，跟上了轮流就结束，不会自己一直撑着
    /// The flood over, a device sending more than its share each time but below capacity on
    /// average: what does not fit still goes, and turns end on catching up instead of keeping
    /// themselves going
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_burst_past_the_share_does_not_keep_turns_going() {
        use std::os::fd::AsRawFd;

        let engine = static_engine_with_flow_control();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        socket2::SockRef::from(socket.as_ref())
            .set_recv_buffer_size(UDP_BUFFER_SIZE)
            .unwrap();
        let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let pending = Arc::new(PendingReplies::default());
        let mut answering = UdpAnswering::new(&socket, &engine, &pending);
        let mut turns = answering.begin_turns();
        answering.overloaded = true;
        answering.behind_at = Instant::now() - CAUGHT_UP_AFTER - Duration::from_millis(1);
        // 跟不上的时候还排着队的也要丢 / Falling behind drops from devices with more queued too
        engine
            .flow_control_state
            .as_ref()
            .unwrap()
            .note_queue_delay(Duration::from_secs(3600));

        let burst = 3 * answering.queries_within_target;
        let packet = query("burst.test", 1);
        for _ in 0..burst {
            client
                .send_to(&packet, socket.local_addr().unwrap())
                .unwrap();
        }
        let mut received = udp_batch::Received::default();
        let mut read = 0;
        while read < burst {
            let got = received.recv(socket.as_raw_fd()).unwrap();
            turns.queue_received(&received, got, &mut answering);
            read += got;
        }
        let mut replies = udp_batch::Replies::default();
        while !turns.queue.is_empty() {
            turns.answer_in_turn(&mut answering, &mut replies);
            replies.clear();
        }
        assert!(
            engine.permit_manager.dropped_requests() as usize > burst / 2,
            "past its share"
        );
        answering.socket_ran_empty();
        assert!(!answering.taking_turns, "caught up");
        assert!(!answering.overloaded);
    }

    /// 轮流时只看内存：内核跟不上也不回 SERVFAIL，该丢的已经丢了；不轮流时照常拒绝
    /// Taking turns goes by memory alone: falling behind gives no SERVFAIL, as what should go
    /// has gone; without turns it refuses as usual
    #[tokio::test]
    async fn taking_turns_goes_by_memory_alone() {
        let engine = Arc::new(behind_engine_with_slow_upstream(0).await);
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let pending = Arc::new(PendingReplies::default());
        let mut answering = UdpAnswering::new(&socket, &engine, &pending);
        let peer = UdpSocket::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let mut reply = BytesMut::new();

        answering.emptied_at = Instant::now() - Duration::from_secs(1);
        answering.answer(&query("a.queue.test", 1), peer, &mut reply);
        assert_eq!(engine.permit_manager.dropped_requests(), 1);
        assert!(answering.refused, "noted as its own refusal");

        answering.refused = false;
        answering.taking_turns = true;
        answering.answer(&query("b.queue.test", 2), peer, &mut reply);
        assert_eq!(engine.permit_manager.dropped_requests(), 1);
        assert_eq!(engine.permit_manager.inflight(), 1);
        assert!(!answering.refused);

        // 快速解析读不了、从头解析的也记下 / One the quick parse cannot read, parsed from scratch, is noted too
        answering.taking_turns = false;
        answering.answer(&query_parsed_from_scratch(3), peer, &mut reply);
        assert_eq!(engine.permit_manager.dropped_requests(), 2);
        assert!(answering.refused, "noted from the full path too");
    }

    /// 轮流要等跟上才结束：还在跟不上时 socket 收空也继续 / Turns end only on catching up: still falling
    /// behind, running empty does not end them
    #[tokio::test]
    async fn turns_go_on_until_caught_up() {
        let engine = static_engine_with_flow_control();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let pending = Arc::new(PendingReplies::default());
        let mut answering = UdpAnswering::new(&socket, &engine, &pending);
        answering.taking_turns = true;
        answering.overloaded = true;
        answering.behind_at = Instant::now();
        answering.socket_ran_empty();
        assert!(answering.taking_turns, "a moment ago");
        assert!(answering.overloaded);
        answering.behind_at = Instant::now() - CAUGHT_UP_AFTER - Duration::from_millis(1);
        answering.socket_ran_empty();
        assert!(!answering.taking_turns);
        assert!(!answering.overloaded);
    }

    /// 一轮答一批：只有一台在排队时答它排着的，很多台时答满一批
    /// A turn answers one batch: what a single device has queued, or a full batch from many
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_turn_answers_one_batch() {
        let engine = static_engine_with_flow_control();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let pending = Arc::new(PendingReplies::default());
        let mut answering = UdpAnswering::new(&socket, &engine, &pending);
        let mut replies = udp_batch::Replies::default();
        let packet = query("a.test", 1);
        let offer = |turns: &mut TakingTurns, last: u8| {
            let ip = [192, 0, 2, last];
            let peer = udp_batch::Peer::of(SocketAddr::from((ip, 53000)));
            turns.queue.offer(&packet, Device::of(ip.into()), peer);
        };

        let mut turns = TakingTurns::new(1000, QUERIES_IN_RECV_BUFFER);
        offer(&mut turns, 1);
        turns.answer_in_turn(&mut answering, &mut replies);
        assert_eq!(replies.len(), 1);
        replies.clear();

        for last in 1..=255 {
            offer(&mut turns, last);
        }
        assert!(turns.queue.devices() > 1);
        turns.answer_in_turn(&mut answering, &mut replies);
        assert_eq!(replies.len(), udp_batch::BATCH, "one batch per turn");
    }

    /// 开始轮流时记下状态，队列按量到的速度算，积压按接收缓冲实际放得下的算 / Beginning turns is noted, with a
    /// queue sized by the measured speed and the backlog by what the receive buffer actually holds
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn turns_begin_with_room_from_the_measured_speed() {
        let engine = static_engine_with_flow_control();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let pending = Arc::new(PendingReplies::default());
        let mut answering = UdpAnswering::new(&socket, &engine, &pending);
        answering.queries_within_target = 2;
        let sock = socket2::SockRef::from(socket.as_ref());
        sock.set_recv_buffer_size(100_000).unwrap();
        let mut turns = answering.begin_turns();
        assert!(answering.taking_turns);
        let holds = sock.recv_buffer_size().unwrap() / (2 * RECV_BUFFER_PER_QUERY);
        assert_eq!(turns.holds, holds, "as much as the buffer actually holds");
        assert!(holds < QUERIES_IN_RECV_BUFFER);
        let device = Device::of([192, 0, 2, 1].into());
        let peer = udp_batch::Peer::of(SocketAddr::from(([192, 0, 2, 1], 53000)));
        assert!(turns.queue.offer(b"q", device, peer));
        assert!(turns.queue.offer(b"q", device, peer));
        assert!(!turns.queue.offer(b"q", device, peer));

        // 量到的速度变了，下一轮跟着变 / The measured speed changing, the next turn follows
        answering.queries_within_target = 3;
        let mut replies = udp_batch::Replies::default();
        turns.answer_in_turn(&mut answering, &mut replies);
        for _ in 0..3 {
            assert!(turns.queue.offer(b"q", device, peer));
        }
        assert!(!turns.queue.offer(b"q", device, peer));
    }

    /// 答一批之前最多读这么多批 / At most this many batches are read before one is answered
    #[cfg(target_os = "linux")]
    #[test]
    fn reads_before_a_turn_have_a_limit() {
        let mut turns = TakingTurns::new(100, QUERIES_IN_RECV_BUFFER);
        let allowed = (0..100).take_while(|_| turns.may_read_more()).count();
        assert_eq!(allowed, READS_PER_TURN - 1);
    }

    /// `fd` 这个 socket 的接收缓冲是不是已经排到四分之三；读不到（socket 已经关了）是 `None`
    /// Whether the receive buffer of socket `fd` is three quarters full already; `None` when it
    /// cannot be read, the socket being closed
    #[cfg(target_os = "linux")]
    fn receive_buffer_mostly_full(fd: std::os::fd::RawFd) -> Option<bool> {
        let mut info = [0u32; libc::SK_MEMINFO_RCVBUF as usize + 1];
        let mut len = std::mem::size_of_val(&info) as libc::socklen_t;
        // SAFETY: the buffer and its length are valid for the call, which only writes within them
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_MEMINFO,
                info.as_mut_ptr().cast(),
                &mut len,
            )
        };
        let queued = info[libc::SK_MEMINFO_RMEM_ALLOC as usize] as usize;
        (ret == 0).then(|| 4 * queued >= 3 * info[libc::SK_MEMINFO_RCVBUF as usize] as usize)
    }

    /// 洪泛怎么发：只管发 / How the flood sends: as fast as it can
    const FLOOD_FREELY: u8 = 0;
    /// 请它别挤满接收缓冲 / Asked to leave the receive buffer short of full
    const FLOOD_ASKED_GENTLE: u8 = 1;
    /// 它看到了，从此每发一个先看缓冲 / It has seen that, and from then on looks at the buffer before each send
    const FLOOD_GENTLE: u8 = 2;

    /// 一直发直到 `stop`，发的是当场能答的查询。`mode` 改成 `FLOOD_ASKED_GENTLE` 以后它回一个 `FLOOD_GENTLE`，从此
    /// `server` 的接收缓冲排到四分之三就先等一等：洪泛照样远超处理能力，只是缓冲满不了。轮流读得比洪泛快时本来就是这样，
    /// 可测试里读和发是两个线程，谁快一时半会说不准，读慢了一下缓冲就满，内核会把别的设备的包和洪泛一起丢掉
    /// Keeps sending queries answered on the spot until `stop`. Once `mode` is set to
    /// `FLOOD_ASKED_GENTLE` it answers with `FLOOD_GENTLE`, and from then on waits whenever
    /// `server`'s receive buffer is three quarters full: the flood still goes far past what can be
    /// handled, only the buffer never fills. That is how taking turns goes while it reads faster
    /// than the flood, but in a test reading and sending are two threads and either may be ahead
    /// for a moment; with reading behind for a moment the buffer fills and the kernel drops
    /// another device's datagram along with the flood
    #[cfg(target_os = "linux")]
    fn flood_from(
        source: [u8; 4],
        server: &UdpSocket,
        stop: Arc<std::sync::atomic::AtomicBool>,
        mode: Arc<std::sync::atomic::AtomicU8>,
    ) -> std::thread::JoinHandle<()> {
        use std::os::fd::AsRawFd;
        use std::sync::atomic::Ordering;

        let socket = std::net::UdpSocket::bind(SocketAddr::from((source, 0))).unwrap();
        let (target, fd) = (server.local_addr().unwrap(), server.as_raw_fd());
        let packet = query("flood.test", 1);
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let _ = mode.compare_exchange(
                    FLOOD_ASKED_GENTLE,
                    FLOOD_GENTLE,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                );
                if mode.load(Ordering::SeqCst) == FLOOD_GENTLE {
                    // 测试先失败了，socket 已经关掉 / The test failed first and closed the socket
                    let Some(mostly_full) = receive_buffer_mostly_full(fd) else {
                        return;
                    };
                    if mostly_full {
                        std::thread::yield_now();
                        continue;
                    }
                }
                let _ = socket.send_to(&packet, target);
            }
        })
    }

    /// 一台设备把 CPU 占满时，另一台偶尔才问一次的设备照样答得上：过载就轮流，不等第二台设备露面；跟上以后不再按设备
    /// 轮流，一阵突发不因排不下被丢
    /// With one device taking all the CPU another asking only now and then is still answered:
    /// overload means taking turns, with no waiting for a second device to show; once caught up
    /// devices no longer take turns and a burst is not dropped for not fitting
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_device_asking_rarely_is_answered_while_another_floods() {
        use std::os::fd::AsRawFd;

        let engine = static_engine_with_flow_control();
        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let target = server.local_addr().unwrap();
        let worker = {
            let (server, engine) = (Arc::clone(&server), Arc::clone(&engine));
            tokio::spawn(async move { receive_in_batches(&server, &engine).await })
        };
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mode = Arc::new(std::sync::atomic::AtomicU8::new(FLOOD_FREELY));
        let flood = flood_from(
            [127, 0, 0, 2],
            &server,
            Arc::clone(&stop),
            Arc::clone(&mode),
        );
        let client = UdpSocket::bind("127.0.0.3:0").await.unwrap();
        let mut buf = [0u8; 512];

        // 只有洪泛的那台也开始轮流：轮流时排不下的才计入被拒绝，这里没有别的拒绝
        // Turns begin with the flooding device alone: only then is what does not fit counted as
        // refused, and nothing else gets refused here
        let started = Instant::now();
        while engine.permit_manager.dropped_requests() == 0 {
            assert!(
                started.elapsed() < Duration::from_secs(30),
                "turns never began"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // 另一台头一次问就答得上，之后一个一个地问也都答得上。洪泛从这里起不挤满缓冲，内核一个包都不丢，没答上的只能是
        // 轮流没轮到它；还在削洪泛，就是还在轮流
        // The other is answered on its very first query, and asking one at a time after that too.
        // From here the flood leaves the buffer short of full and the kernel drops nothing, so one
        // left unanswered could only be one taking turns passed over; the flood still being cut
        // means turns go on
        mode.store(FLOOD_ASKED_GENTLE, std::sync::atomic::Ordering::SeqCst);
        let started = Instant::now();
        while mode.load(std::sync::atomic::Ordering::SeqCst) != FLOOD_GENTLE
            || receive_buffer_mostly_full(server.as_raw_fd()).unwrap()
        {
            assert!(
                started.elapsed() < Duration::from_secs(30),
                "the flood never eased"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let drops = kixdns::socket_utils::udp_receive_drops(&server).unwrap();
        let cut = engine.permit_manager.dropped_requests();
        for id in 0..20 {
            client
                .send_to(&query("light.test", id), target)
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf))
                .await
                .unwrap_or_else(|_| panic!("query {id} unanswered"))
                .unwrap();
        }
        assert_eq!(
            kixdns::socket_utils::udp_receive_drops(&server).unwrap(),
            drops,
            "nothing dropped in the kernel"
        );
        assert!(
            engine.permit_manager.dropped_requests() > cut,
            "the flood is still being cut"
        );

        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        flood.join().unwrap();
        tokio::time::sleep(CAUGHT_UP_AFTER + Duration::from_millis(200)).await;
        let refused = engine.permit_manager.dropped_requests();
        let packet = query("light.test", 3);
        let sender = std::net::UdpSocket::bind("127.0.0.4:0").unwrap();
        let sending = std::thread::spawn(move || {
            for _ in 0..3000 {
                sender.send_to(&packet, target).unwrap();
            }
        });
        sending.join().unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            engine.permit_manager.dropped_requests(),
            refused,
            "caught up, nothing is dropped for not fitting"
        );
        worker.abort();
    }

    /// 空闲了很久以后来的查询不算内核忙：等新报文的时间不算没收空。两种循环都这样
    /// Queries after a long quiet spell do not find the kernel busy: waiting for datagrams does not count as
    /// not running empty. Both loops do so
    #[tokio::test]
    async fn a_quiet_spell_does_not_count_as_busy() {
        #[cfg(target_os = "linux")]
        not_refused_after_a_quiet_spell(|server, engine| {
            tokio::spawn(async move { receive_in_batches(&server, &Arc::new(engine)).await })
        })
        .await;
        not_refused_after_a_quiet_spell(|server, engine| {
            tokio::spawn(async move { receive_one_by_one(&server, &Arc::new(engine)).await })
        })
        .await;
    }

    async fn not_refused_after_a_quiet_spell(
        receive: impl FnOnce(Arc<UdpSocket>, Engine) -> tokio::task::JoinHandle<()>,
    ) {
        let engine = behind_engine_with_slow_upstream(500).await;
        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server.local_addr().unwrap();
        let worker = receive(server, engine);
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        tokio::time::sleep(Duration::from_millis(1_000)).await;
        const QUERIES: u16 = 2;
        for id in 0..QUERIES {
            let query = query(&format!("q{id}.quiet.test"), id);
            client.send_to(&query, server_addr).await.unwrap();
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(refused_and_answered(&client, QUERIES).await, (0, QUERIES));
        worker.abort();
    }

    /// 内核忙、查询又在排长队时，两种接收循环都回 SERVFAIL。这里一开始就算忙、排队一直算过长，每个查询都该被拒。
    /// 只拒一部分的那种情况看时机，CI 上一次线程抢占就能翻，不在这里测；不忙就不拒由
    /// `queries_waiting_on_a_slow_upstream_are_not_refused` 和 `a_quiet_spell_does_not_count_as_busy` 测着
    /// With the kernel busy and queries queueing long, both receive loops answer SERVFAIL. Here it is
    /// busy from the start and queueing always runs long, so every query is refused. Refusing only some
    /// turns on timing that one preempted thread on CI can flip, so it is not tested here; that nothing
    /// is refused while not busy is what `queries_waiting_on_a_slow_upstream_are_not_refused` and
    /// `a_quiet_spell_does_not_count_as_busy` test
    #[tokio::test]
    async fn a_busy_kernel_queueing_long_refuses_in_both_loops() {
        #[cfg(target_os = "linux")]
        refused_when_busy(|server, engine| {
            tokio::spawn(async move { receive_in_batches(&server, &Arc::new(engine)).await })
        })
        .await;
        refused_when_busy(|server, engine| {
            tokio::spawn(async move { receive_one_by_one(&server, &Arc::new(engine)).await })
        })
        .await;
    }

    async fn refused_when_busy(
        receive: impl FnOnce(Arc<UdpSocket>, Engine) -> tokio::task::JoinHandle<()>,
    ) {
        let engine = behind_engine_with_slow_upstream(0).await;
        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server.local_addr().unwrap();
        let worker = receive(server, engine);
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        const QUERIES: u16 = 50;
        for id in 0..QUERIES {
            let query = query(&format!("q{id}.busy.test"), id);
            client.send_to(&query, server_addr).await.unwrap();
        }
        assert_eq!(refused_and_answered(&client, QUERIES).await, (QUERIES, 0));
        worker.abort();
    }

    /// 查询从排进去到开始跑等得超过目标，内核就算跟不上，下一个查询被拒绝；等得不久就不会
    /// A query waiting past the target from being queued until it runs means the kernel is
    /// behind, and the next query is refused; a short wait does not
    #[tokio::test]
    async fn queueing_past_the_target_refuses_queries() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let engine = Arc::new(with_busy_after(
            engine_forwarding_to(
                upstream.local_addr().unwrap(),
                serde_json::json!({
                    "flow_control_enabled": true,
                    "upstream_timeout_ms": 5000,
                    "enable_tcp_fallback": false,
                }),
            ),
            Duration::ZERO,
        ));
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let pending = Arc::new(PendingReplies::default());
        let mut answering = UdpAnswering::new(&socket, &engine, &pending);
        let peer = UdpSocket::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let mut reply = BytesMut::new();
        let mut ask = |id: u16| {
            let query = query(&format!("q{id}.queue.test"), id);
            answering.answer(&query, peer, &mut reply);
        };

        // 这个测试和查询的任务在同一线程上，它不让出，任务就跑不了
        // This test and the query's task share a thread, so the task cannot run until it yields
        ask(1);
        tokio::task::yield_now().await;
        ask(2);
        assert_eq!(engine.permit_manager.dropped_requests(), 0, "a short wait");

        ask(3);
        std::thread::sleep(Duration::from_millis(300));
        tokio::task::yield_now().await;
        ask(4);
        assert_eq!(engine.permit_manager.dropped_requests(), 1, "a long wait");
    }

    /// 开着流控的引擎，转发给一个不应答的上游，在途已有 1000 个查询，内存剩多少看 `available`
    /// An engine with flow control forwarding to a silent upstream, with 1000 queries in
    /// flight and `available` bytes of memory left
    fn engine_short_of_memory(
        silent_upstream: SocketAddr,
        available: Arc<std::sync::atomic::AtomicU64>,
    ) -> (Engine, Vec<kixdns::engine::concurrency::PermitGuard>) {
        use kixdns::config::PipelineConfig;
        use kixdns::engine::memory_watermark::{MemoryLeft, MemoryReading, MemoryWatermark};

        let config: PipelineConfig = serde_json::from_value(serde_json::json!({
            "settings": {
                "default_upstream": silent_upstream.to_string(),
                "upstream_timeout_ms": 3000,
                "enable_tcp_fallback": false,
                "flow_control_enabled": true
            },
            "pipelines": [{ "id": "main", "rules": [{
                "name": "all",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": silent_upstream.to_string() }]
            }]}]
        }))
        .unwrap();
        let mut engine = Engine::new(
            kixdns::matcher::RuntimePipelineConfig::from_config(config).unwrap(),
            "test".to_string(),
        )
        .unwrap();
        Arc::get_mut(engine.flow_control_state.as_mut().unwrap())
            .unwrap()
            .memory = MemoryWatermark::reading(move || MemoryReading {
            own: 0,
            limits: vec![MemoryLeft {
                total: 1 << 30,
                available: available.load(std::sync::atomic::Ordering::Relaxed),
            }],
        });
        let in_flight = (0..1000).map(|_| engine.permit_manager.acquire()).collect();
        (engine, in_flight)
    }

    /// 内存剩这么多字节 / This many bytes of memory left
    fn memory_left(bytes: u64) -> Arc<std::sync::atomic::AtomicU64> {
        Arc::new(std::sync::atomic::AtomicU64::new(bytes))
    }

    /// 一个 TCP 服务端，返回它的地址 / A TCP server, giving its address
    async fn tcp_server(
        engine: &Engine,
    ) -> (SocketAddr, tokio::task::JoinHandle<anyhow::Result<()>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        (address, tokio::spawn(run_tcp(listener, engine.clone())))
    }

    async fn send_tcp_query(stream: &mut TcpStream) {
        let query = dns_query();
        stream
            .write_all(&(query.len() as u16).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&query).await.unwrap();
    }

    /// 等到在途数量到 `count` / Until `count` are in flight
    async fn in_flight_reaches(engine: &Engine, count: usize) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while engine.permit_manager.inflight() != count {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{} in flight", engine.permit_manager.inflight()));
    }

    /// TCP 进来的查询也看内存：不够时当场回 SERVFAIL，不问上游，连接还在
    /// A query from TCP goes by memory too: with too little it gets SERVFAIL at once, the
    /// upstream is not asked and the connection stays
    #[tokio::test]
    async fn a_tcp_query_is_refused_when_memory_runs_short() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let available = memory_left(1 << 30);
        let (engine, _in_flight) =
            engine_short_of_memory(upstream.local_addr().unwrap(), Arc::clone(&available));
        let (address, server) = tcp_server(&engine).await;
        let mut stream = TcpStream::connect(address).await.unwrap();
        in_flight_reaches(&engine, 1001).await;

        // 看够了次数，下一次读到内存不够 / Enough looks for the next read to find memory short
        available.store(0, std::sync::atomic::Ordering::Relaxed);
        for _ in 0..3000 {
            drop(engine.stream_query_permit(std::net::Ipv4Addr::LOCALHOST.into()));
        }
        send_tcp_query(&mut stream).await;
        let mut length = [0u8; 2];
        tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut length))
            .await
            .expect("refused at once")
            .unwrap();
        let mut reply = vec![0u8; u16::from_be_bytes(length) as usize];
        stream.read_exact(&mut reply).await.unwrap();
        let reply = Message::from_bytes(&reply).unwrap();
        assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
        let mut buf = [0u8; 512];
        assert!(
            tokio::time::timeout(Duration::from_millis(100), upstream.recv_from(&mut buf))
                .await
                .is_err(),
            "the upstream is not asked"
        );
        assert_eq!(
            engine.permit_manager.inflight(),
            1001,
            "only the connection counts"
        );
        server.abort();
    }

    /// 内存够时 TCP 的连接和查询都算在途，查询照常问上游
    /// With enough memory a TCP connection and query both count as in flight, and the query
    /// asks the upstream as usual
    #[tokio::test]
    async fn a_tcp_connection_and_query_count_as_in_flight() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (engine, _in_flight) =
            engine_short_of_memory(upstream.local_addr().unwrap(), memory_left(1 << 30));
        let (address, server) = tcp_server(&engine).await;
        let mut stream = TcpStream::connect(address).await.unwrap();
        in_flight_reaches(&engine, 1001).await;
        send_tcp_query(&mut stream).await;
        let mut buf = [0u8; 512];
        tokio::time::timeout(Duration::from_secs(1), upstream.recv_from(&mut buf))
            .await
            .expect("the upstream is asked")
            .unwrap();
        in_flight_reaches(&engine, 1002).await;
        drop(stream);
        server.abort();
    }

    /// 内存不够时不接新连接：连接本身也占内存，只拒绝查询挡不住光连不发的客户端
    /// With too little memory no new connection is taken: a connection holds memory too, and
    /// refusing queries alone would not stop clients that connect and send nothing
    #[tokio::test]
    async fn a_new_tcp_connection_is_closed_when_memory_is_short() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (engine, _in_flight) =
            engine_short_of_memory(upstream.local_addr().unwrap(), memory_left(0));
        let (address, server) = tcp_server(&engine).await;

        let mut stream = TcpStream::connect(address).await.unwrap();
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut buf))
            .await
            .expect("closed at once");
        assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
        assert_eq!(engine.permit_manager.dropped_requests(), 1);
        assert_eq!(engine.permit_manager.inflight(), 1000, "it holds nothing");
        server.abort();
    }

    /// 从 `local` 连 `to` / Connects to `to` from `local`
    async fn connect_from(local: std::net::IpAddr, to: SocketAddr) -> TcpStream {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.bind(SocketAddr::new(local, 0)).unwrap();
        socket.connect(to).await.unwrap()
    }

    /// 内存紧张时，在途占满的那台设备的查询和新连接被拒，别的设备照常；UDP 和 TCP 都按真实的对端地址算
    /// With memory tight, the device holding everything in flight has its queries and new
    /// connections refused while another goes on; UDP and TCP both go by the real peer address
    #[tokio::test]
    async fn tight_memory_refuses_only_the_device_holding_the_queries() {
        use std::net::{IpAddr, Ipv4Addr};
        use std::sync::atomic::Ordering::Relaxed;

        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let available = memory_left(1 << 30);
        let (engine, plain) =
            engine_short_of_memory(upstream.local_addr().unwrap(), Arc::clone(&available));
        drop(plain);
        let manager = &engine.permit_manager;
        let heavy = IpAddr::from(Ipv4Addr::new(127, 0, 0, 4));
        // 和它不在同一份的另一台：份是按每次启动都不同的哈希分的 / Another device, not in the same
        // slot: slots go by a hash that differs at each start
        let light = (2..=250)
            .map(|n| IpAddr::from(Ipv4Addr::new(127, 0, 0, n)))
            .find(|ip| manager.slot_of(*ip) != manager.slot_of(heavy))
            .unwrap();
        let held: Vec<_> = (0..1000)
            .map(|_| engine.stream_query_permit(heavy).expect("plenty of memory"))
            .collect();
        // 内存还够时它先连上一条 TCP / While memory is plenty it opens a TCP connection first
        let (address, tcp) = tcp_server(&engine).await;
        let mut heavy_connected = connect_from(heavy, address).await;
        in_flight_reaches(&engine, 1001).await;
        // 余量 64 MiB、两倍 128 MiB，剩 100 MiB 算紧张；看够了次数，下一次读到它
        // A 64 MiB margin, twice that 128 MiB: 100 MiB left is tight; enough looks for the next read to find it
        available.store(100 << 20, Relaxed);
        for _ in 0..3000 {
            drop(engine.stream_query_permit(heavy));
        }
        assert!(engine.stream_query_permit(heavy).is_none(), "tight now");

        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server.local_addr().unwrap();
        let worker = tokio::spawn(run_udp_worker(0, Arc::clone(&server), engine.clone()));
        let mut buf = [0u8; 512];
        let light_client = UdpSocket::bind(SocketAddr::new(light, 0)).await.unwrap();
        light_client
            .send_to(&dns_query(), server_addr)
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), upstream.recv_from(&mut buf))
            .await
            .expect("the light device's query is asked of the upstream")
            .unwrap();
        in_flight_reaches(&engine, 1002).await;

        let heavy_client = UdpSocket::bind(SocketAddr::new(heavy, 0)).await.unwrap();
        heavy_client
            .send_to(&dns_query(), server_addr)
            .await
            .unwrap();
        let (len, _) =
            tokio::time::timeout(Duration::from_secs(1), heavy_client.recv_from(&mut buf))
                .await
                .expect("the heavy device is refused at once")
                .unwrap();
        // 1 秒内就回 SERVFAIL 就是被拒了：放行的要等这个不回答的上游超时，至少 3 秒。上游收没收到不在这里看，
        // 发得少的那个查询还挂在它上面，可能重发 / SERVFAIL within a second means refused: one let through waits
        // for this silent upstream to time out, 3 s at least. What the upstream receives is not looked at here, as
        // the light device's query still hangs on it and may be sent again
        let reply = Message::from_bytes(&buf[..len]).unwrap();
        assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);

        // 它在已有的连接上发的查询也被拒，当场回 SERVFAIL / Its query on the connection it has is refused
        // too, with SERVFAIL at once
        send_tcp_query(&mut heavy_connected).await;
        let mut length = [0u8; 2];
        tokio::time::timeout(
            Duration::from_secs(1),
            heavy_connected.read_exact(&mut length),
        )
        .await
        .expect("refused at once")
        .unwrap();
        let mut reply = vec![0u8; u16::from_be_bytes(length) as usize];
        heavy_connected.read_exact(&mut reply).await.unwrap();
        let reply = Message::from_bytes(&reply).unwrap();
        assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);

        let mut heavy_stream = connect_from(heavy, address).await;
        let read = tokio::time::timeout(Duration::from_secs(1), heavy_stream.read(&mut buf))
            .await
            .expect("its new connection is closed at once");
        assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
        let before = engine.permit_manager.inflight();
        let light_stream = connect_from(light, address).await;
        in_flight_reaches(&engine, before + 1).await;

        drop((held, light_stream, heavy_connected));
        worker.abort();
        tcp.abort();
    }

    #[tokio::test]
    async fn udp_permit_exhaustion_returns_servfail_but_malformed_packet_is_silent() {
        let engine = forwarding_engine();
        engine
            .flow_control_state
            .as_ref()
            .unwrap()
            .note_queue_delay(Duration::from_secs(3600));

        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server.local_addr().unwrap();
        let worker = tokio::spawn(run_udp_worker(0, Arc::clone(&server), engine));
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        client.send_to(&dns_query(), server_addr).await.unwrap();
        let mut response_buf = [0u8; 512];
        let (response_len, _) =
            tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut response_buf))
                .await
                .expect("valid query should receive a response")
                .unwrap();
        let response = Message::from_bytes(&response_buf[..response_len]).unwrap();
        assert_eq!(response.metadata.id, 0xCAFE);
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(response.queries.len(), 1);
        // 过载时的 SERVFAIL 照查询带回 RD 位和问题 / The overload SERVFAIL carries the query's RD bit and question
        assert!(response.metadata.recursion_desired);
        assert_eq!(
            response.queries,
            Message::from_bytes(&dns_query()).unwrap().queries
        );

        client.send_to(&[0x12, 0x34], server_addr).await.unwrap();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(100),
                client.recv_from(&mut response_buf),
            )
            .await
            .is_err(),
            "malformed UDP packets must not receive a reflected response"
        );

        // A packet that passes the header gate but fails parse_quick (trailing
        // data) still reaches the overload branch; it must stay silent there.
        let mut trailing = dns_query();
        trailing.extend_from_slice(&[0x00]);
        client.send_to(&trailing, server_addr).await.unwrap();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(100),
                client.recv_from(&mut response_buf),
            )
            .await
            .is_err(),
            "overload branch must drop packets that failed parse_quick"
        );

        worker.abort();
    }

    #[tokio::test]
    async fn udp_hanging_doh_returns_servfail() {
        let upstream = format!("https://{}/dns-query", spawn_silent_upstream().await);
        let engine = doh_timeout_engine(&upstream);
        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server.local_addr().unwrap();
        let worker = tokio::spawn(run_udp_worker(0, Arc::clone(&server), engine));
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        client.send_to(&dns_query(), server_addr).await.unwrap();
        let mut response_buf = [0u8; 512];
        let (response_len, _) =
            tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut response_buf))
                .await
                .expect("timed-out query should receive SERVFAIL")
                .unwrap();
        let response = Message::from_bytes(&response_buf[..response_len]).unwrap();
        assert_eq!(response.metadata.id, 0xCAFE);
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(response.queries.len(), 1);

        worker.abort();
    }

    /// 只连接不发数据的客户端此前可以永久占用一个任务和一个文件描述符；
    /// 现在服务端在空闲超时后关闭连接。
    /// A client that connects without sending used to pin a task and a file
    /// descriptor forever; the server now closes the connection when the idle
    /// timeout expires.
    #[tokio::test]
    async fn tcp_idle_connection_is_closed_after_the_read_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            handle_tcp_conn(stream, peer, static_engine()).await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 1];
        // 实际等待一次 TCP_READ_TIMEOUT：这条路径没有可注入的时钟。
        // Waits one real TCP_READ_TIMEOUT; this path has no injectable clock.
        let read = tokio::time::timeout(TCP_READ_TIMEOUT * 3, client.read(&mut buf))
            .await
            .expect("server must close the idle connection instead of waiting forever")
            .expect("read after close");
        assert_eq!(read, 0, "an idle connection must be closed by the server");
        server.await.unwrap().expect("connection handler");
    }

    /// 长连接上的查询必须跟着热重载后的 request_timeout 走。此前超时值在进入
    /// 循环前只读一次，运维调大超时之后，已有连接上的查询继续按旧值失败，
    /// 直到客户端自己重连。RFC 7766 的客户端正是长期复用一条连接。
    /// Queries on a long-lived connection must follow the request_timeout a
    /// reload installed. The value used to be read once before the loop, so
    /// after an operator raised the timeout the queries on an existing
    /// connection kept failing on the old budget until the client reconnected.
    /// An RFC 7766 client reuses one connection for exactly that long.
    #[tokio::test]
    async fn tcp_request_timeout_follows_a_reload_on_an_open_connection() {
        // 只接不答的上游，让每条查询都跑满整体请求超时
        // An upstream that accepts and never answers, so every query runs the
        // whole request timeout
        let upstream = format!("https://{}/dns-query", spawn_silent_upstream().await);
        const BEFORE_MS: u64 = 120;
        const AFTER_MS: u64 = 900;
        let engine = Engine::new(doh_timeout_config(&upstream, BEFORE_MS), "test".to_string())
            .expect("initialize engine");

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener_addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(listener_addr).await.unwrap();
        let (server_stream, peer) = listener.accept().await.unwrap();
        let server_task = tokio::spawn(handle_tcp_conn(server_stream, peer, engine.clone()));

        let first = time_one_tcp_query(&mut client).await;
        assert!(
            first < Duration::from_millis(AFTER_MS / 2),
            "the first query must use the configured {BEFORE_MS} ms budget, took {first:?}"
        );

        engine.reload(doh_timeout_config(&upstream, AFTER_MS));

        // 同一条连接上的第二次查询 / A second query on the same connection
        let second = time_one_tcp_query(&mut client).await;
        assert!(
            second >= Duration::from_millis(AFTER_MS / 2),
            "a query after the reload must use the new {AFTER_MS} ms budget, took {second:?}"
        );

        server_task.abort();
    }

    /// 在一条已建立的连接上发一次查询并读回完整应答，返回耗时
    /// Send one query on an established connection, read the whole answer back
    /// and return how long it took
    async fn time_one_tcp_query(client: &mut TcpStream) -> Duration {
        let (message, elapsed) = tcp_exchange(client, &dns_query()).await;
        assert_eq!(message.metadata.response_code, ResponseCode::ServFail);
        elapsed
    }

    /// 本机 UDP 上游：每个查询隔 `delay` 才回（标上 QR 的查询本身）
    /// Local UDP upstream answering every query after `delay` (the query itself with QR set)
    async fn spawn_slow_udp_upstream(delay: Duration) -> SocketAddr {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
                let mut answer = buf[..n].to_vec();
                answer[2] |= 0x80;
                let socket = Arc::clone(&socket);
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let _ = socket.send_to(&answer, peer).await;
                });
            }
        });
        addr
    }

    /// slow.test 转发给 `upstream`，fast.test 静态回答 / slow.test forwards to `upstream`, fast.test answers statically
    fn slow_and_fast_engine(upstream: SocketAddr) -> Engine {
        let config: kixdns::config::PipelineConfig = serde_json::from_value(serde_json::json!({
            "settings": {
                "default_upstream": "127.0.0.1:9",
                "upstream_timeout_ms": 2000,
                "request_timeout_ms": 4000
            },
            "pipelines": [{ "id": "main", "rules": [
                {
                    "name": "slow",
                    "matchers": [{ "type": "domain_suffix", "value": "slow.test" }],
                    "actions": [{ "type": "forward", "upstream": upstream.to_string() }]
                },
                {
                    "name": "fast",
                    "matchers": [{ "type": "domain_suffix", "value": "fast.test" }],
                    "actions": [{ "type": "static_ip_response", "ip": "192.0.2.1" }]
                }
            ]}]
        }))
        .expect("parse config");
        Engine::new(
            RuntimePipelineConfig::from_config(config).expect("runtime config"),
            "test".to_string(),
        )
        .expect("initialize engine")
    }

    /// `name` 的 A 查询，ID 为 `id`，带长度前缀 / An A query for `name` with ID `id`, length-prefixed
    fn tcp_frame(name: &str, id: u16) -> Vec<u8> {
        let packet = query(name, id);
        [&(packet.len() as u16).to_be_bytes()[..], &packet].concat()
    }

    /// 从连接上读一个回答，返回它的 ID / Reads one answer off the connection and returns its ID
    async fn read_answer_id(client: &mut TcpStream) -> u16 {
        let answer = read_tcp_answer(client).await;
        u16::from_be_bytes([answer[0], answer[1]])
    }

    /// 从连接上读一个回答 / Reads one answer off the connection
    async fn read_tcp_answer(client: &mut TcpStream) -> Vec<u8> {
        let mut len_buf = [0u8; 2];
        client
            .read_exact(&mut len_buf)
            .await
            .expect("length prefix");
        let mut answer = vec![0u8; u16::from_be_bytes(len_buf) as usize];
        client.read_exact(&mut answer).await.expect("dns frame");
        answer
    }

    /// 连在 `engine` 上的一条入站 TCP 连接，和处理它的任务 / An inbound TCP connection to `engine` and the task handling it
    async fn tcp_connection(
        engine: Engine,
    ) -> (TcpStream, tokio::task::JoinHandle<anyhow::Result<()>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (stream, peer) = listener.accept().await.unwrap();
        (client, tokio::spawn(handle_tcp_conn(stream, peer, engine)))
    }

    /// 一次写进来的一串查询都答上，各带自己的 ID；当场答的攒在一起写回
    /// A run of queries written in one go is answered in full, each with its own ID; the answers
    /// made on the spot are written back together
    #[tokio::test]
    async fn queries_written_together_are_all_answered() {
        let (mut client, _server) = tcp_connection(static_engine()).await;
        let frames: Vec<u8> = (0..200u16)
            .flat_map(|id| tcp_frame(&format!("q{id}.example."), id))
            .collect();
        client.write_all(&frames).await.unwrap();
        let mut ids = Vec::new();
        for _ in 0..200 {
            let answer = read_tcp_answer(&mut client).await;
            let message = Message::from_bytes(&answer).unwrap();
            assert_eq!(
                message.queries[0].name().to_string(),
                format!("q{}.example.", message.metadata.id)
            );
            ids.push(message.metadata.id);
        }
        ids.sort_unstable();
        assert_eq!(ids, (0..200).collect::<Vec<_>>());
    }

    /// 消息拆成几段到，长度前缀也拆开，照样答；拆开的段之间不超时
    /// A message arriving in pieces, its length prefix split too, is still answered; the pieces
    /// do not time out between them
    #[tokio::test]
    async fn a_message_in_pieces_is_answered() {
        let (mut client, _server) = tcp_connection(static_engine()).await;
        let frame = tcp_frame("pieces.example.", 7);
        for piece in [&frame[..1], &frame[1..2], &frame[2..9], &frame[9..]] {
            client.write_all(piece).await.unwrap();
            client.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(read_answer_id(&mut client).await, 7);
        // 下一个消息只差最后一个字节，跟在这个后面一起到 / The next message, all but its last byte, comes along with this one
        let next = [tcp_frame("a.example.", 8), tcp_frame("b.example.", 9)].concat();
        client.write_all(&next[..next.len() - 1]).await.unwrap();
        assert_eq!(read_answer_id(&mut client).await, 8);
        client.write_all(&next[next.len() - 1..]).await.unwrap();
        assert_eq!(read_answer_id(&mut client).await, 9);
    }

    /// 比一次读的大小还长的消息照样读完，后面的查询照样答
    /// A message longer than one read is still read whole, and the query after it is answered
    #[tokio::test]
    async fn a_message_longer_than_one_read_is_read_whole() {
        let (mut client, _server) = tcp_connection(static_engine()).await;
        let mut long = query("long.example.", 1);
        long.resize(TCP_READ_CHUNK * 3 + 17, 0);
        let frames = [
            &(long.len() as u16).to_be_bytes()[..],
            &long,
            &tcp_frame("after.example.", 2),
        ]
        .concat();
        client.write_all(&frames).await.unwrap();
        // 多出来的字节让完整解析出错：回 SERVFAIL 或不回都行，后面那个一定要答
        // The extra bytes make the full parse fail: a SERVFAIL or no answer is fine, the one after must be answered
        loop {
            let answer = read_tcp_answer(&mut client).await;
            if u16::from_be_bytes([answer[0], answer[1]]) == 2 {
                break;
            }
        }
    }

    /// 连接上的处理名额用满时，同一批里已经当场答好的不陪着等名额，先写回去
    /// With every slot on the connection taken, what the same batch already answered on the spot
    /// does not wait for a slot along with the rest and is written back first
    #[tokio::test]
    async fn answers_made_on_the_spot_do_not_wait_for_a_slot() {
        const DELAY: Duration = Duration::from_millis(400);
        let upstream = spawn_slow_udp_upstream(DELAY).await;
        let (mut client, _server) = tcp_connection(slow_and_fast_engine(upstream)).await;
        let slow = |i: usize| tcp_frame(&format!("q{i}.slow.test."), i as u16);
        let mut frames: Vec<u8> = (0..TCP_MAX_QUERIES_PER_CONN).flat_map(slow).collect();
        frames.extend(tcp_frame("a.fast.test.", 9999));
        frames.extend(slow(TCP_MAX_QUERIES_PER_CONN));
        let started = std::time::Instant::now();
        client.write_all(&frames).await.unwrap();
        assert_eq!(read_answer_id(&mut client).await, 9999);
        assert!(
            started.elapsed() < DELAY / 2,
            "took {:?}",
            started.elapsed()
        );
    }

    /// 测试里的读超时，比 TCP_READ_TIMEOUT 短，几次超时一会儿就跑完 / The read timeout in tests,
    /// shorter than TCP_READ_TIMEOUT, so several timeouts take little time
    const SHORT_READ_TIMEOUT: Duration = Duration::from_secs(1);

    /// 连在 `engine` 上、读超时是 SHORT_READ_TIMEOUT 的一条入站 TCP 连接 / An inbound TCP connection
    /// to `engine` with SHORT_READ_TIMEOUT as its read timeout
    async fn tcp_connection_timing_out(
        engine: Engine,
    ) -> (TcpStream, tokio::task::JoinHandle<anyhow::Result<()>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (stream, peer) = listener.accept().await.unwrap();
        let server = tokio::spawn(serve_tcp_conn(stream, peer, engine, SHORT_READ_TIMEOUT));
        (client, server)
    }

    /// 半截消息一点点地发也不能一直挂着：正文从开始等起总共一个读超时，中途到的字节不重新计时
    /// A half-sent message trickled in bit by bit cannot hang on either: the body gets one read
    /// timeout from when it was first waited for, and bytes arriving meanwhile do not restart it
    #[tokio::test]
    async fn a_trickled_message_still_times_out() {
        let (client, server) = tcp_connection_timing_out(static_engine()).await;
        let (_read, mut write) = client.into_split();
        let frame = tcp_frame("trickle.example.", 1);
        let started = std::time::Instant::now();
        write.write_all(&frame[..4]).await.unwrap();
        let trickle = tokio::spawn(async move {
            for byte in &frame[4..frame.len() - 1] {
                tokio::time::sleep(SHORT_READ_TIMEOUT / 4).await;
                if write.write_all(std::slice::from_ref(byte)).await.is_err() {
                    break;
                }
            }
        });
        tokio::time::timeout(SHORT_READ_TIMEOUT * 3, server)
            .await
            .expect("the connection is closed")
            .unwrap()
            .unwrap();
        let took = started.elapsed();
        trickle.abort();
        assert!(
            took >= SHORT_READ_TIMEOUT && took < SHORT_READ_TIMEOUT + SHORT_READ_TIMEOUT / 4,
            "took {took:?}"
        );
    }

    /// 读超时管的是每次等：一直有查询进来的连接不会因为连了很久就被关掉，空下来以后才在一个读超时后关
    /// The read timeout bounds each wait: a connection that keeps sending queries is not closed for
    /// having lasted long, and closes one read timeout after it goes quiet
    #[tokio::test]
    async fn a_busy_connection_outlives_the_read_timeout() {
        let (mut client, server) = tcp_connection_timing_out(static_engine()).await;
        let started = std::time::Instant::now();
        for id in 0..4 {
            client
                .write_all(&tcp_frame("busy.example.", id))
                .await
                .unwrap();
            assert_eq!(read_answer_id(&mut client).await, id);
            tokio::time::sleep(SHORT_READ_TIMEOUT * 3 / 5).await;
        }
        let quiet = started.elapsed();
        assert!(quiet > SHORT_READ_TIMEOUT * 2, "took {quiet:?}");
        tokio::time::timeout(SHORT_READ_TIMEOUT * 2, server)
            .await
            .expect("the quiet connection is closed")
            .unwrap()
            .unwrap();
    }

    /// 长度为 0 的消息结束连接，但它前面一起到的查询照样拿到回答
    /// A zero-length message ends the connection, yet the queries that came before it in the same
    /// read still get their answers
    #[tokio::test]
    async fn a_zero_length_message_ends_the_connection_after_the_answers_before_it() {
        let (mut client, server) = tcp_connection(static_engine()).await;
        let frames = [
            tcp_frame("a.example.", 1),
            tcp_frame("b.example.", 2),
            vec![0, 0],
        ]
        .concat();
        client.write_all(&frames).await.unwrap();
        assert_eq!(read_answer_id(&mut client).await, 1);
        assert_eq!(read_answer_id(&mut client).await, 2);
        let mut rest = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut rest))
            .await
            .expect("the connection closes")
            .unwrap();
        assert!(rest.is_empty());
        server.await.unwrap().unwrap();
    }

    /// 同一条连接上，快查询不等它前面的慢查询，答完就回（RFC 7766 第 6.2.1.1 节）。此前一个接一个地
    /// 处理，快查询要陪着慢查询等。
    /// On one connection a fast query does not wait for the slow one before it and is
    /// answered when done (RFC 7766 section 6.2.1.1). Queries used to be handled one after
    /// another, the fast one waiting out the slow one.
    #[tokio::test]
    async fn a_fast_tcp_query_is_not_held_behind_a_slow_one() {
        let upstream = spawn_slow_udp_upstream(Duration::from_millis(800)).await;
        let (mut client, _server) = tcp_connection(slow_and_fast_engine(upstream)).await;
        let started = std::time::Instant::now();
        client
            .write_all(&[tcp_frame("a.slow.test.", 1), tcp_frame("a.fast.test.", 2)].concat())
            .await
            .unwrap();
        assert_eq!(
            read_answer_id(&mut client).await,
            2,
            "the fast answer comes first"
        );
        assert!(
            started.elapsed() < Duration::from_millis(300),
            "the fast answer took {:?}",
            started.elapsed()
        );
        assert_eq!(read_answer_id(&mut client).await, 1, "then the slow one");
    }

    /// 客户端发完查询就关掉发送方向，还在处理的查询照样把回答写回去，然后连接关闭
    /// A client that shuts its sending side after its query still gets the answers being
    /// worked on, and then the connection closes
    #[tokio::test]
    async fn a_half_closed_tcp_client_gets_its_pending_answers() {
        let upstream = spawn_slow_udp_upstream(Duration::from_millis(300)).await;
        let (mut client, server) = tcp_connection(slow_and_fast_engine(upstream)).await;
        client
            .write_all(&tcp_frame("b.slow.test.", 7))
            .await
            .unwrap();
        client.shutdown().await.unwrap();
        assert_eq!(read_answer_id(&mut client).await, 7);
        let mut rest = Vec::new();
        client.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty(), "the connection closes after the answer");
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("the handler ends")
            .unwrap()
            .unwrap();
    }

    /// 一条连接上同时处理的查询有上限：一次发来 100 个慢查询，全都答了，前 64 个一起答完，剩下的接着
    /// 一起答完——并发了，也没有一下子开 100 个任务。
    /// The queries handled at once on one connection are capped: 100 slow queries sent in one
    /// go are all answered, the first 64 together and the rest together after them, so they
    /// run concurrently without 100 tasks starting at once.
    #[tokio::test]
    async fn tcp_queries_run_concurrently_up_to_the_per_connection_cap() {
        // UDP 转发每次尝试等上游超时的三分之一，延迟要短于它，一次就答上
        // A UDP forward waits a third of the upstream timeout per attempt; the delay stays
        // below that so one attempt answers
        const DELAY: Duration = Duration::from_millis(400);
        let upstream = spawn_slow_udp_upstream(DELAY).await;
        let (mut client, _server) = tcp_connection(slow_and_fast_engine(upstream)).await;
        let frames: Vec<u8> = (0..100)
            .flat_map(|i| tcp_frame(&format!("q{i}.slow.test."), i))
            .collect();
        let started = std::time::Instant::now();
        client.write_all(&frames).await.unwrap();
        let mut ids = Vec::new();
        for _ in 0..100 {
            ids.push(read_answer_id(&mut client).await);
        }
        let took = started.elapsed();
        ids.sort_unstable();
        assert_eq!(ids, (0..100).collect::<Vec<u16>>());
        assert!(
            took >= DELAY * 2 && took < DELAY * 2 + Duration::from_millis(600),
            "two rounds of {DELAY:?} expected, took {took:?}"
        );
    }

    /// 不读回答的客户端：写回在时限内写不完就关掉写端，处理这条连接的任务能结束，而不是永远卡在写上
    /// A client that never reads its answers: a write not done within the limit shuts the
    /// write side, and the task handling the connection ends instead of hanging on the write
    #[tokio::test]
    async fn a_tcp_client_that_never_reads_does_not_hold_the_handler() {
        let upstream = spawn_slow_udp_upstream(Duration::from_millis(10)).await;
        let (mut client, server) = tcp_connection(slow_and_fast_engine(upstream)).await;
        // 一直发、从不读，直到发不出去：服务端的写回早就堵住了
        // Keep sending, never reading, until sending stalls: the server's writes are long blocked
        let frame = tcp_frame("c.fast.test.", 9);
        let burst: Vec<u8> = frame
            .iter()
            .copied()
            .cycle()
            .take(frame.len() * 4096)
            .collect();
        while tokio::time::timeout(Duration::from_millis(500), client.write_all(&burst))
            .await
            .is_ok()
        {}
        tokio::time::timeout(TCP_READ_TIMEOUT * 4, server)
            .await
            .expect("the handler ends once its blocked write times out")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn tcp_hanging_doh_returns_complete_servfail_frame() {
        let upstream = format!("https://{}/dns-query", spawn_silent_upstream().await);
        let engine = doh_timeout_engine(&upstream);
        let (mut client, server_task) = tcp_connection(engine).await;
        let (response, _) = tokio::time::timeout(
            Duration::from_secs(1),
            tcp_exchange(&mut client, &dns_query()),
        )
        .await
        .expect("TCP query should receive the complete DNS frame");
        assert_eq!(response.metadata.id, 0xCAFE);
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(response.queries.len(), 1);

        server_task.abort();
    }

    #[tokio::test]
    async fn udp_response_truncates_oversized_payload() {
        use hickory_proto::rr::{RData, Record, rdata::TXT};

        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // 客户端无 EDNS → 512 字节限制 / Client without EDNS → 512-byte limit
        let request = dns_query();
        // 构造 >512 字节的大 TXT 响应 / Build a large TXT response (>512 bytes)
        let name = Name::from_str("data.xiaoheihe.cn.").unwrap();
        let mut big = Message::new(0xCAFE, MessageType::Response, OpCode::Query);
        big.metadata.recursion_desired = true;
        big.metadata.recursion_available = true;
        big.add_query(Query::query(name.clone(), RecordType::TXT));
        for i in 0..20 {
            let text = format!("verification-{i:02}-{}", "x".repeat(180));
            big.add_answer(Record::from_rdata(
                name.clone(),
                300,
                RData::TXT(TXT::new(vec![text])),
            ));
        }
        let big_response = big.to_vec().unwrap();
        assert!(big_response.len() > 512);

        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            let (len, peer) = server.recv_from(&mut buf).await.unwrap();
            let reply = udp_reply(&buf[..len], Bytes::from(big_response));
            send_udp_datagram(&server, &reply, peer).await.unwrap();
        });

        client.send_to(&request, server_addr).await.unwrap();
        let mut buf = [0u8; 4096];
        let (len, _) = tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf))
            .await
            .expect("client should receive a truncated response")
            .unwrap();
        let resp = Message::from_bytes(&buf[..len]).unwrap();
        assert!(len <= 512, "response must fit the 512-byte UDP limit");
        assert!(resp.metadata.truncation, "TC bit must be set");
        assert_eq!(resp.queries.len(), 1);
        assert_eq!(resp.metadata.id, 0xCAFE);
    }

    /// 名字为 `name`、ID 为 `id`、带 RD 的 A 查询 / An A query for `name` with ID `id` and RD set
    fn query(name: &str, id: u16) -> Vec<u8> {
        let mut request = Message::new(id, MessageType::Query, OpCode::Query);
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
        request.to_vec().unwrap()
    }

    /// 快速解析读不了、要从头解析的查询：第一个标签里有一个空格
    /// A query the quick parse cannot read and the full parse can: a space in its first label
    fn query_parsed_from_scratch(id: u16) -> Vec<u8> {
        let mut packet = query("xslow.test", id);
        // 12 字节的报头之后是第一个标签的长度，再往后是它的第一个字节
        // The 12-byte header is followed by the first label's length, then its first byte
        packet[13] = b' ';
        assert!(kixdns::proto_utils::parse_quick(&packet, &mut [0u8; 256]).is_none());
        assert!(Message::from_bytes(&packet).is_ok());
        packet
    }

    /// 本机 UDP 上游：每个查询回一条 TTL 300 的 A 记录
    /// A local UDP upstream answering every query with one A record of TTL 300
    async fn spawn_answering_udp_upstream() -> SocketAddr {
        use hickory_proto::rr::{RData, Record, rdata::A};

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
                let Ok(query) = Message::from_bytes(&buf[..n]) else {
                    continue;
                };
                let mut answer =
                    Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
                answer.metadata.recursion_desired = query.metadata.recursion_desired;
                answer.metadata.recursion_available = true;
                for question in query.queries {
                    answer.add_answer(Record::from_rdata(
                        question.name().clone(),
                        300,
                        RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 7))),
                    ));
                    answer.add_query(question);
                }
                let _ = socket.send_to(&answer.to_vec().unwrap(), peer).await;
            }
        });
        addr
    }

    /// 要转发的查询在接收循环忙着时答完：回答排进队列、和下一批一起发出，每个客户端收到的正好是自己那些
    /// 查询的回答。批量收发和一个一个收发的两种循环、单线程和多线程的运行时都这样
    /// Forwarded queries answered while the receive loop is busy: the replies queue up and go out
    /// with the next batch, and each client gets the answers to exactly its own queries. So with the
    /// batched and the one-by-one loop, on a current-thread and a multi-thread runtime alike
    #[tokio::test]
    async fn forwarded_answers_reach_their_clients_while_the_loop_is_busy() {
        forwarded_answers_reach_their_clients().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn forwarded_answers_reach_their_clients_on_several_threads() {
        forwarded_answers_reach_their_clients().await;
    }

    async fn forwarded_answers_reach_their_clients() {
        #[cfg(target_os = "linux")]
        forwarded_answers_reach_their_clients_by(|server, engine| {
            tokio::spawn(async move { receive_in_batches(&server, &Arc::new(engine)).await })
        })
        .await;
        forwarded_answers_reach_their_clients_by(|server, engine| {
            tokio::spawn(async move { receive_one_by_one(&server, &Arc::new(engine)).await })
        })
        .await;
    }

    async fn forwarded_answers_reach_their_clients_by(
        receive: impl FnOnce(Arc<UdpSocket>, Engine) -> tokio::task::JoinHandle<()>,
    ) {
        const CLIENTS: u16 = 4;
        const PER_CLIENT: u16 = 100;
        // 每个客户端最多同时等这么多个回答：几个客户端加起来装得进默认的接收缓冲，不会被内核丢掉，又足够让
        // 接收循环一直有事做
        // Each client waits for at most this many answers at once: all clients together fit in the
        // default receive buffer, so the kernel drops none, and still keep the receive loop busy
        const WINDOW: u16 = 16;
        let upstream = spawn_answering_udp_upstream().await;
        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server.local_addr().unwrap();
        let worker = receive(
            server,
            engine_forwarding_to(upstream, serde_json::json!({})),
        );
        let clients: Vec<_> = (0..CLIENTS)
            .map(|c| {
                tokio::spawn(async move {
                    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                    // 名字各不相同：每个都要转发，不会命中缓存或者合并成一个 / Every name differs: each is
                    // forwarded, none hits the cache or merges with another
                    let ask = |id: u16| query(&format!("q{id}-c{c}.forwarded.test"), id);
                    for id in 0..WINDOW {
                        client.send_to(&ask(id), server_addr).await.unwrap();
                    }
                    let (mut sent, mut ids) = (WINDOW, Vec::new());
                    let mut buf = [0u8; 512];
                    while ids.len() < PER_CLIENT as usize {
                        let (len, _) = tokio::time::timeout(
                            Duration::from_secs(5),
                            client.recv_from(&mut buf),
                        )
                        .await
                        .unwrap_or_else(|_| panic!("client {c} got only {} answers", ids.len()))
                        .unwrap();
                        let answer = Message::from_bytes(&buf[..len]).expect("an answer");
                        assert_eq!(
                            answer.queries[0].name().to_string(),
                            format!("q{}-c{c}.forwarded.test.", answer.metadata.id),
                            "client {c} got an answer to someone else's query"
                        );
                        assert_eq!(answer.answers.len(), 1, "the upstream's answer comes back");
                        ids.push(answer.metadata.id);
                        if sent < PER_CLIENT {
                            client.send_to(&ask(sent), server_addr).await.unwrap();
                            sent += 1;
                        }
                    }
                    ids.sort_unstable();
                    assert_eq!(ids, (0..PER_CLIENT).collect::<Vec<_>>(), "client {c}");
                })
            })
            .collect();
        for client in clients {
            client.await.unwrap();
        }
        worker.abort();
    }

    /// 接收循环在等新报文时（其他平台一直如此）不收回答，由转发完的任务直接发
    /// While the receive loop waits for datagrams (on other platforms, always) it takes no reply,
    /// and the task done forwarding sends it directly
    #[test]
    fn a_waiting_loop_takes_no_replies() {
        let pending = PendingReplies::default();
        assert!(!pending.try_queue(
            &Bytes::from_static(b"reply"),
            "127.0.0.1:9".parse().unwrap()
        ));
        assert!(pending.queue.lock().is_empty());
    }

    /// 循环忙着时放进来的回答让它不睡：说完在等以后看一眼队列，还有回答就接着发
    /// A reply queued while the loop is busy keeps it awake: once it has said it waits it looks at
    /// the queue, and goes on sending while a reply is there
    #[test]
    fn a_reply_queued_while_the_loop_is_busy_keeps_it_awake() {
        let pending = PendingReplies::default();
        pending
            .idle
            .store(false, std::sync::atomic::Ordering::SeqCst);
        assert!(pending.try_queue(
            &Bytes::from_static(b"reply"),
            "127.0.0.1:9".parse().unwrap()
        ));
        assert!(
            !pending.begin_wait(),
            "the loop must not sleep on a queued reply"
        );
    }

    /// 循环刚说完在等，转发完的任务才放进回答（它看的时候循环还忙着）：这个回答叫醒循环
    /// The loop has just said it waits when a task queues a reply (the loop was busy when the task
    /// looked): that reply wakes the loop
    #[tokio::test]
    async fn a_reply_queued_as_the_loop_turns_to_waiting_wakes_it() {
        let pending = PendingReplies::default();
        pending
            .idle
            .store(false, std::sync::atomic::Ordering::SeqCst);
        assert!(
            pending.begin_wait(),
            "nothing queued yet: the loop may sleep"
        );
        pending.queue_and_wake(
            &Bytes::from_static(b"reply"),
            "127.0.0.1:9".parse().unwrap(),
        );
        tokio::time::timeout(Duration::from_millis(500), pending.wake.notified())
            .await
            .expect("the queued reply wakes the loop");
    }

    /// 接收循环转去等待之前，把排着的回答都发出去 / Before the receive loop turns to waiting, it
    /// sends every queued reply
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn the_loop_sends_what_is_queued_before_it_waits() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let pending = PendingReplies::default();
        pending
            .idle
            .store(false, std::sync::atomic::Ordering::SeqCst);
        assert!(pending.try_queue(
            &Bytes::from_static(b"queued reply"),
            client.local_addr().unwrap()
        ));
        let mut replies = kixdns::socket_utils::udp_batch::Replies::default();
        // 没有新报文，这个等待不会自己结束 / With no datagram this wait never ends of itself
        let _ = tokio::time::timeout(
            Duration::from_millis(200),
            pending.wait(&server, &mut replies),
        )
        .await;
        let mut buf = [0u8; 64];
        let (len, _) = tokio::time::timeout(Duration::from_millis(500), client.recv_from(&mut buf))
            .await
            .expect("the queued reply went out before the wait")
            .unwrap();
        assert_eq!(&buf[..len], b"queued reply");
    }

    /// 一次只问一个：接收循环在等新报文时回答直接发，正在转去等待时放进队列的回答也不会卡住
    /// One query at a time: while the receive loop waits for datagrams the reply goes directly, and
    /// a reply queued just as it turns to waiting does not get stuck
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_lone_forwarded_answer_never_waits_in_the_queue() {
        let upstream = spawn_answering_udp_upstream().await;
        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server.local_addr().unwrap();
        let engine = Arc::new(engine_forwarding_to(upstream, serde_json::json!({})));
        #[cfg(target_os = "linux")]
        let worker = tokio::spawn(async move { receive_in_batches(&server, &engine).await });
        #[cfg(not(target_os = "linux"))]
        let worker = tokio::spawn(async move { receive_one_by_one(&server, &engine).await });
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut buf = [0u8; 512];
        for id in 0..200u16 {
            let name = format!("lone{id}.forwarded.test");
            client
                .send_to(&query(&name, id), server_addr)
                .await
                .unwrap();
            let (len, _) = tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf))
                .await
                .unwrap_or_else(|_| panic!("query {id} got no answer within a second"))
                .unwrap();
            assert_eq!(Message::from_bytes(&buf[..len]).unwrap().metadata.id, id);
        }
        worker.abort();
    }

    /// 本机上游，UDP 和 TCP 占同一个端口：收下查询、接下连接，从不回答
    /// A local upstream on one port for UDP and TCP: it takes queries and connections and
    /// never answers
    async fn spawn_silent_upstream() -> SocketAddr {
        // 先拿 UDP 端口，再在同号上绑 TCP：TCP 挑临时端口时不看 UDP 的占用，反过来更容易撞上别的
        // 测试占着的 UDP 端口。同号的 TCP 端口正被占着时换一对，最多试 20 次
        // The UDP port first, then TCP on the same number: the TCP ephemeral allocator
        // does not look at UDP, so the other order runs into UDP ports other tests hold
        // more often. Another pair when that TCP port is taken, at most 20 tries
        let mut tries = 0;
        let (tcp, udp) = loop {
            tries += 1;
            assert!(
                tries <= 20,
                "port conflict: no port free for both UDP and TCP in 20 tries"
            );
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            match TcpListener::bind(udp.local_addr().unwrap()).await {
                Ok(tcp) => break (tcp, udp),
                Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => continue,
                Err(err) => panic!("bind tcp on the udp port: {err}"),
            }
        };
        let addr = tcp.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            let mut buf = [0u8; 512];
            loop {
                tokio::select! {
                    Ok((stream, _)) = tcp.accept() => held.push(stream),
                    Ok(_) = udp.recv_from(&mut buf) => {}
                    else => break,
                }
            }
        });
        addr
    }

    /// 把查询都用 UDP 转发给 `upstream` 的引擎，`settings` 覆盖在默认设置上
    /// An engine forwarding every query over UDP to `upstream`, with `settings` on top of
    /// the defaults
    fn engine_forwarding_to(upstream: SocketAddr, settings: serde_json::Value) -> Engine {
        let mut all = serde_json::json!({ "default_upstream": upstream.to_string() });
        all.as_object_mut()
            .unwrap()
            .extend(settings.as_object().unwrap().clone());
        let config: kixdns::config::PipelineConfig = serde_json::from_value(serde_json::json!({
            "settings": all,
            "pipelines": [{
                "id": "p",
                "rules": [{
                    "name": "forward",
                    "matchers": [{ "type": "any" }],
                    "actions": [{
                        "type": "forward",
                        "upstream": upstream.to_string(),
                        "transport": "udp"
                    }]
                }]
            }]
        }))
        .expect("parse config");
        let runtime = RuntimePipelineConfig::from_config(config).expect("build runtime config");
        Engine::new(runtime, "test".to_string()).expect("initialize engine")
    }

    /// 换掉引擎判断「socket 多久没收空算忙」的时长。生产里它就是 `BUSY_AFTER`，配置改不了，测试要别的值只能这样换
    /// Changes how long a socket goes without running empty before the engine counts as busy. In
    /// production that is `BUSY_AFTER`, which no configuration changes, so a test wanting another value swaps it here
    fn with_busy_after(mut engine: Engine, busy_after: Duration) -> Engine {
        let flow = engine
            .flow_control_state
            .take()
            .expect("flow control is on");
        let mut flow = Arc::into_inner(flow).expect("nothing else holds it yet");
        flow.busy_after = busy_after;
        engine.flow_control_state = Some(Arc::new(flow));
        engine
    }

    /// 智能流控替代了旧参数：配置里写的 `flow_control_latency_threshold_ms` 不起作用，忙不忙始终按 `BUSY_AFTER` 判断
    /// Smart flow control replaced the old numbers: a `flow_control_latency_threshold_ms` in the
    /// configuration has no effect, and busy is always judged by `BUSY_AFTER`
    #[tokio::test]
    async fn an_old_busy_threshold_in_the_configuration_has_no_effect() {
        for threshold in [0, 1, 100, 60_000] {
            let engine = engine_forwarding_to(
                "127.0.0.1:9".parse().unwrap(),
                serde_json::json!({
                    "flow_control_enabled": true,
                    "flow_control_latency_threshold_ms": threshold,
                }),
            );
            let flow = engine
                .flow_control_state
                .as_ref()
                .expect("flow control is on");
            assert_eq!(
                flow.busy_after,
                kixdns::engine::concurrency::BUSY_AFTER,
                "{threshold}"
            );
        }
    }

    /// 发一个 UDP 查询、读回回答，连同用时一起返回
    /// Send one UDP query, read the answer back, and return it with the time it took
    async fn udp_exchange(
        client: &UdpSocket,
        server: SocketAddr,
        query: &[u8],
    ) -> (Message, Duration) {
        let start = std::time::Instant::now();
        client.send_to(query, server).await.unwrap();
        let mut buf = [0u8; 512];
        let (n, _) = tokio::time::timeout(Duration::from_secs(3), client.recv_from(&mut buf))
            .await
            .expect("udp answer")
            .unwrap();
        (Message::from_bytes(&buf[..n]).unwrap(), start.elapsed())
    }

    /// 在一条连接上发一个查询、读回回答，连同用时一起返回
    /// Send one query on a connection, read the answer back, and return it with the time
    /// it took
    async fn tcp_exchange(client: &mut TcpStream, query: &[u8]) -> (Message, Duration) {
        let start = std::time::Instant::now();
        client
            .write_all(&[&(query.len() as u16).to_be_bytes()[..], query].concat())
            .await
            .unwrap();
        let answer = read_tcp_answer(client).await;
        (Message::from_bytes(&answer).unwrap(), start.elapsed())
    }

    /// 缓存命中的应答带着这条查询自己的事务 ID；TTL 按应答在缓存里停留的整秒数调低（RFC 1035
    /// 第 5.2 节），停留不到一秒时原样不动。UDP 和 TCP 一样
    /// A cache hit carries the query's own transaction ID, and its TTLs are lowered by the
    /// whole seconds the answer sat in the cache (RFC 1035 section 5.2), untouched under a
    /// second. The same over UDP and over TCP
    #[tokio::test]
    async fn a_cache_hit_carries_the_query_id_and_ages_its_ttls() {
        let engine =
            engine_forwarding_to(spawn_answering_udp_upstream().await, serde_json::json!({}));
        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server.local_addr().unwrap();
        let worker = tokio::spawn(run_udp_worker(0, Arc::clone(&server), engine.clone()));
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (mut tcp, connection) = tcp_connection(engine).await;

        // 第一次转发给上游，写进缓存 / The first goes to the upstream and into the cache
        let (forwarded, _) = udp_exchange(&client, server_addr, &query("cached.test", 1)).await;
        assert_eq!((forwarded.metadata.id, forwarded.answers[0].ttl), (1, 300));

        // 停留不到一秒：只换 ID / Under a second in the cache: only the ID changes
        let (udp_hit, _) = udp_exchange(&client, server_addr, &query("cached.test", 2)).await;
        let (tcp_hit, _) = tcp_exchange(&mut tcp, &query("cached.test", 3)).await;
        assert_eq!((udp_hit.metadata.id, udp_hit.answers[0].ttl), (2, 300));
        assert_eq!((tcp_hit.metadata.id, tcp_hit.answers[0].ttl), (3, 300));

        // 停留过一秒：TTL 跟着调低 / Past a second in the cache the TTL goes down too
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let (udp_aged, _) = udp_exchange(&client, server_addr, &query("cached.test", 4)).await;
        let (tcp_aged, _) = tcp_exchange(&mut tcp, &query("cached.test", 5)).await;
        assert_eq!(udp_aged.metadata.id, 4);
        assert_eq!(tcp_aged.metadata.id, 5);
        for aged in [&udp_aged, &tcp_aged] {
            let ttl = aged.answers[0].ttl;
            assert!((295..300).contains(&ttl), "aged TTL {ttl}");
        }

        worker.abort();
        connection.abort();
    }

    /// 引擎在请求时限内答不上来时，监听器到点回 SERVFAIL：不早于时限，也不等引擎自己放弃。快速解析
    /// 读得了的查询和要从头解析的一样，UDP 和 TCP 一样
    /// When the engine cannot answer within the request timeout, the listener answers
    /// SERVFAIL when it runs out: not before, and without waiting for the engine to give up.
    /// A query the quick parse reads and one parsed from scratch alike, over UDP as over TCP
    #[tokio::test]
    async fn listeners_answer_servfail_when_the_request_timeout_runs_out() {
        // 上游从不回答：引擎先用 UDP 试三分之一个时限、再试一个时限，再改用 TCP 等一个时限，加起来比
        // 请求时限长得多，所以先到点的是监听器自己的计时
        // The upstream never answers: the engine tries UDP for a third of the timeout and
        // then a whole one, then TCP for another, far longer than the request timeout, so
        // the listener's own timer runs out first
        const TIMEOUT: Duration = Duration::from_millis(300);
        let engine = engine_forwarding_to(
            spawn_silent_upstream().await,
            serde_json::json!({
                "upstream_timeout_ms": TIMEOUT.as_millis() as u64,
                "request_timeout_ms": TIMEOUT.as_millis() as u64,
                "enable_tcp_fallback": true
            }),
        );
        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server.local_addr().unwrap();
        let worker = tokio::spawn(run_udp_worker(0, Arc::clone(&server), engine.clone()));
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (mut tcp_client, connection) = tcp_connection(engine).await;

        for (case, packet) in [
            ("quick parse", query("quick.test", 7)),
            ("full parse", query_parsed_from_scratch(8)),
        ] {
            let id = u16::from_be_bytes([packet[0], packet[1]]);
            let udp = udp_exchange(&client, server_addr, &packet).await;
            let tcp = tcp_exchange(&mut tcp_client, &packet).await;
            for (transport, (answer, took)) in [("UDP", udp), ("TCP", tcp)] {
                assert_eq!(
                    (answer.metadata.id, answer.metadata.response_code),
                    (id, ResponseCode::ServFail),
                    "{case} over {transport}"
                );
                assert!(
                    took >= TIMEOUT && took < TIMEOUT * 2,
                    "{case} over {transport} took {took:?}"
                );
            }
        }

        worker.abort();
        connection.abort();
    }

    /// 要单独监听的 IPv4 地址：IPv4 地址本身；`[::]` 的同伴 `0.0.0.0`，端口相同；别的 IPv6 地址没有
    /// The IPv4 address listened on separately: an IPv4 address itself; `0.0.0.0` on the same
    /// port as the twin of `[::]`; none for other IPv6 addresses
    #[test]
    fn the_ipv4_listen_address_is_the_address_itself_or_the_twin_of_any() {
        let addr = |text: &str| text.parse::<SocketAddr>().unwrap();
        assert_eq!(
            ipv4_listen_addr(addr("192.0.2.1:53")),
            Some(addr("192.0.2.1:53"))
        );
        assert_eq!(
            ipv4_listen_addr(addr("[::]:5353")),
            Some(addr("0.0.0.0:5353"))
        );
        assert_eq!(ipv4_listen_addr(addr("[::1]:53")), None);
    }

    /// 装不进一条记录的静态 TXT（一段超过 255 字节，或者总长超过 65535），UDP 和 TCP 都收到
    /// SERVFAIL，不带 TC。以前总长超长时两边收到的都是 NOERROR、TC 置位、没有答案的应答
    /// A static TXT that does not fit a record (a segment over 255 bytes, or a total over
    /// 65535) is SERVFAIL over UDP and TCP alike, without TC. A total that was too long
    /// used to give both a NOERROR answer with TC set and no records
    #[tokio::test]
    async fn a_static_txt_that_does_not_fit_a_record_is_servfail_over_udp_and_tcp() {
        let config: kixdns::config::PipelineConfig = serde_json::from_value(serde_json::json!({
            "settings": { "default_upstream": "127.0.0.1:9" },
            "pipelines": [{
                "id": "p",
                "rules": [
                    {
                        "name": "segment",
                        "matchers": [{ "type": "domain_suffix", "value": "segment.test" }],
                        "actions": [{ "type": "static_txt_response", "text": ["x".repeat(256)] }]
                    },
                    {
                        "name": "total",
                        "matchers": [{ "type": "any" }],
                        "actions": [{
                            "type": "static_txt_response",
                            "text": vec!["y".repeat(250); 300]
                        }]
                    }
                ]
            }]
        }))
        .expect("parse config");
        let engine = Engine::new(
            RuntimePipelineConfig::from_config(config).expect("build runtime config"),
            "test".to_string(),
        )
        .expect("initialize engine");
        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server.local_addr().unwrap();
        let worker = tokio::spawn(run_udp_worker(0, Arc::clone(&server), engine.clone()));
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (mut tcp, connection) = tcp_connection(engine).await;

        for (id, qname) in [(1, "segment.test"), (2, "total.test")] {
            let (udp, _) = udp_exchange(&client, server_addr, &query(qname, id)).await;
            let (tcp, _) = tcp_exchange(&mut tcp, &query(qname, id)).await;
            for (transport, answer) in [("UDP", udp), ("TCP", tcp)] {
                assert_eq!(
                    (answer.metadata.response_code, answer.metadata.truncation),
                    (ResponseCode::ServFail, false),
                    "{qname} over {transport}"
                );
            }
        }

        worker.abort();
        connection.abort();
    }
}
