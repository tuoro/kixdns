use std::any::Any;
use std::io::Write as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
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

use kixdns::config::load_config_with_source;
use kixdns::engine::{Engine, FastPathResponse, PreParsedData, engine_helpers};
use kixdns::matcher::RuntimePipelineConfig;
use kixdns::observe::ClientTransport;
use kixdns::proto_utils::{is_standard_query_header, truncate_udp_response};
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
    let cfg = RuntimePipelineConfig::from_config(cfg).context("compile matchers")?;
    // Listener addresses and DoH prerequisites, checked exactly as
    // config::validate does / 监听地址与 DoH 前置条件，检查方式与 config::validate 一致
    let listeners = cfg.settings.listeners()?;
    let bind_addr = listeners.udp;
    let bind_tcp = listeners.tcp;
    // 在 cfg 被 move 到 Engine 之前提取 DoH 配置 / Extract DoH config before cfg is moved into Engine
    let doh_config: Option<(SocketAddr, String, String, String)> = listeners
        .doh
        .map(|doh| (doh.bind, doh.tls_cert, doh.tls_key, doh.path));

    // The enhanced build installs the panel observer in the single observer
    // slot; it forwards to the --debug reference observer itself / 增强版在唯一的观察者槽位安装面板观察者，由它自行转发给 --debug 参考观察者
    let panel_metrics = kixdns::panel::PanelMetrics::new(debug);
    // 查询排行只经控制通道读；没开控制通道时不统计 / Query rankings are only read over the
    // control socket; without one they are not collected
    let panel_metrics = Arc::new(if cfg!(unix) && admin_socket.is_some() {
        panel_metrics
    } else {
        panel_metrics.without_rankings()
    });
    let engine = Engine::builder(cfg)
        .listener_label(listener_label.clone())
        .config_source(&config, config_source)
        .observer(panel_metrics.clone())
        .build()
        .context("initialize DNS engine")?;

    watcher::spawn(config.clone(), engine.clone());

    // UDP worker 数量：默认为 CPU 核心数，最少 1 个 / UDP worker count: defaults to CPU core count, minimum 1
    let udp_workers_final = if udp_workers_count > 0 {
        udp_workers_count
    } else {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    };

    info!(bind_udp = %bind_addr, bind_tcp = %bind_tcp, udp_workers_count = udp_workers_final, "dns server started");

    let mut all_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    #[cfg(unix)]
    if let Some(path) = admin_socket {
        let engine = engine.clone();
        let panel_metrics = Arc::clone(&panel_metrics);
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

    #[cfg(unix)]
    {
        // ✅ OpenBSD 兼容性方案：双 socket（IPv4 + IPv6）+ 零拷贝 recv_buf_from
        // ✅ OpenBSD compatibility: dual sockets (IPv4 + IPv6) + zero-copy recv_buf_from
        // 为每个地址族创建独立的 socket 和 workers，避免 sockaddr 大小断言失败
        // Create separate sockets and workers for each address family to avoid sockaddr size assertion failures

        // ✅ OpenBSD 兼容性方案：双 socket（IPv4 + IPv6）+ 零拷贝 recv_buf_from
        // ✅ OpenBSD compatibility: dual sockets (IPv4 + IPv6) + zero-copy recv_buf_from
        // 为每个地址族创建独立的 socket 和 workers，避免 sockaddr 大小断言失败
        // Create separate sockets and workers for each address family to avoid sockaddr size assertion failures

        // 根据配置地址决定创建哪种 socket / Determine which socket type to create based on config
        // IPv6 unspecified address (::) 需要同时创建 IPv4 和 IPv6 socket
        // IPv6 other addresses 只创建 IPv6 socket
        // IPv4 addresses 只创建 IPv4 socket
        let needs_ipv4 =
            bind_addr.is_ipv4() || (bind_addr.is_ipv6() && bind_addr.ip().is_unspecified());
        let needs_ipv6 = bind_addr.is_ipv6();

        if needs_ipv4 {
            let workers_per_family = if needs_ipv6 {
                udp_workers_final.div_ceil(2)
            } else {
                udp_workers_final
            };
            spawn_ipv4_udp_workers(
                bind_addr,
                workers_per_family,
                engine.clone(),
                &mut all_handles,
            )?;
        }

        if needs_ipv6 {
            let workers_per_family = if needs_ipv4 {
                udp_workers_final.div_ceil(2)
            } else {
                udp_workers_final
            };
            spawn_ipv6_udp_workers(
                bind_addr,
                workers_per_family,
                engine.clone(),
                &mut all_handles,
            )?;
        }
    }

    #[cfg(not(unix))]
    {
        // Non-Unix: create a single shared socket and spawn workers that share it / 非 Unix：创建单个共享套接字并生成共享它的工作线程
        // Use socket2 to set buffer sizes / 使用 socket2 设置缓冲区大小
        use socket2::{Domain, Protocol, Socket, Type};
        let domain = if bind_addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket =
            Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).context("create socket")?;

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

        // Set buffer sizes to prevent packet loss under load
        // Try 4MB first, then fall back to 1MB if it fails
        let desired_size = 4 * 1024 * 1024;
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

        socket.set_nonblocking(true).context("set nonblocking")?;
        socket.bind(&bind_addr.into()).context("bind socket")?;

        let udp_socket = Arc::new(UdpSocket::from_std(socket.into()).context("from_std")?);
        for worker_id in 0..udp_workers_final {
            let engine = engine.clone();
            let socket = Arc::clone(&udp_socket);
            let handle = tokio::spawn(async move {
                if let Err(err) = run_udp_worker(worker_id, socket, engine).await {
                    error!(worker_id, error = %err, "udp worker exited");
                }
            });
            all_handles.push(handle);
        }
    }

    // TCP listener / TCP 监听器
    // ✅ 双 socket 方案，与 UDP 行为一致 / Dual-socket approach, consistent with UDP
    let needs_ipv4_tcp =
        bind_tcp.is_ipv4() || (bind_tcp.is_ipv6() && bind_tcp.ip().is_unspecified());

    // --- 启动 IPv4 TCP 监听 / Start IPv4 TCP listener ---
    if needs_ipv4_tcp {
        let addr = if bind_tcp.is_ipv4() {
            bind_tcp
        } else {
            SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
                bind_tcp.port(),
            )
        };
        // 纯 IPv4 绑定，不受 bindv6only 影响 / Pure IPv4 bind, unaffected by bindv6only
        let listener = TcpListener::bind(addr).await.context("bind ipv4 tcp")?;
        let engine = engine.clone();
        let h = tokio::spawn(async move {
            if let Err(err) = run_tcp(listener, engine).await {
                error!(error = %err, "ipv4 tcp server exited");
            }
        });
        all_handles.push(h);
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

        let listener = TcpListener::from_std(socket.into())?;
        let engine = engine.clone();
        let h = tokio::spawn(async move {
            if let Err(err) = run_tcp(listener, engine).await {
                error!(error = %err, "ipv6 tcp server exited");
            }
        });
        all_handles.push(h);
    }

    // DoH listener — 仅在配置了 bind_doh 时启动 / DoH listener — only if bind_doh is configured
    if let Some((doh_addr, cert_path, key_path, doh_path)) = doh_config {
        let engine = engine.clone();
        let h = tokio::spawn(async move {
            if let Err(err) =
                kixdns::doh_server::run_doh(doh_addr, &cert_path, &key_path, engine, doh_path).await
            {
                error!(error = %err, "DoH server exited");
            }
        });
        all_handles.push(h);
    }

    // 等待所有任务 / Wait for all tasks
    for h in all_handles {
        let _ = h.await;
    }

    Ok(())
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

// 为 IPv4 地址创建并启动 UDP workers / Create and spawn UDP workers for IPv4 address
#[cfg(unix)]
fn spawn_ipv4_udp_workers(
    bind_addr: SocketAddr,
    worker_count: usize,
    engine: Engine,
    all_handles: &mut Vec<tokio::task::JoinHandle<()>>,
) -> anyhow::Result<()> {
    let ipv4_addr: SocketAddr = if bind_addr.is_ipv4() {
        bind_addr
    } else {
        // 预编译的常量地址，避免 unwrap / Precompiled constant address, avoid unwrap
        // 使用配置中的端口号而非硬编码 / Use port from config instead of hardcoded
        SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
            bind_addr.port(),
        )
    };

    info!(bind_addr = %ipv4_addr, workers = worker_count, "Starting IPv4 UDP workers");

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
    for worker_id in 0..worker_count {
        let engine = engine.clone();
        let std_socket = create_reuseport_udp_socket(ipv4_addr)
            .with_context(|| format!("create ipv4 udp socket for worker {}", worker_id))?;
        let socket = Arc::new(UdpSocket::from_std(std_socket)?);
        let handle = tokio::spawn(async move {
            if let Err(err) = run_udp_worker(worker_id, socket, engine).await {
                error!(worker_id, error = %err, "IPv4 udp worker exited");
            }
        });
        all_handles.push(handle);
    }

    Ok(())
}

// 为 IPv6 地址创建并启动 UDP workers / Create and spawn UDP workers for IPv6 address
#[cfg(unix)]
fn spawn_ipv6_udp_workers(
    bind_addr: SocketAddr,
    worker_count: usize,
    engine: Engine,
    all_handles: &mut Vec<tokio::task::JoinHandle<()>>,
) -> anyhow::Result<()> {
    let ipv6_addr: SocketAddr = if bind_addr.is_ipv6() {
        bind_addr
    } else {
        // 预编译的常量地址，避免 unwrap / Precompiled constant address, avoid unwrap
        // 使用配置中的端口号而非硬编码 / Use port from config instead of hardcoded
        SocketAddr::new(
            std::net::IpAddr::V6(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
            bind_addr.port(),
        )
    };

    info!(bind_addr = %ipv6_addr, workers = worker_count, "Starting IPv6 UDP workers");

    // ✅ Per-worker SO_REUSEPORT_LB sockets (same rationale as IPv4)
    // ✅ 每 worker 独立 SO_REUSEPORT_LB socket（同 IPv4）
    for worker_id in 0..worker_count {
        let engine = engine.clone();
        let std_socket = create_reuseport_udp_socket(ipv6_addr)
            .with_context(|| format!("create ipv6 udp socket for worker {}", worker_id))?;
        let socket = Arc::new(UdpSocket::from_std(std_socket)?);
        let handle = tokio::spawn(async move {
            if let Err(err) = run_udp_worker(worker_id, socket, engine).await {
                error!(worker_id, error = %err, "IPv6 udp worker exited");
            }
        });
        all_handles.push(handle);
    }

    Ok(())
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

    // Set buffer sizes to prevent packet loss under load
    // Try 4MB first, then fall back to 1MB if it fails
    let desired_size = 4 * 1024 * 1024;
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

    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    Ok(socket.into())
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

/// 发送 UDP 响应：超限响应截断（RFC 6891）+ try_send_to 优先，WouldBlock 回退异步
/// Send UDP response: truncate oversized (RFC 6891), try non-blocking first, async fallback on WouldBlock
async fn send_udp_response(socket: &UdpSocket, request: &[u8], response: &[u8], peer: SocketAddr) {
    // 截断超限响应，避免 UDP 报文超过客户端声明上限 / Truncate to the client's advertised UDP limit
    let truncated = truncate_udp_response(request, response);
    let response = truncated.as_deref().unwrap_or(response);
    if let Err(error) = send_udp_datagram(socket, response, peer).await {
        debug!(%peer, %error, response_len = response.len(), "failed to send UDP response");
    }
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

/// 异步发送 SERVFAIL（处理失败/超时路径）
async fn send_udp_servfail(socket: &UdpSocket, request: &[u8], peer: SocketAddr) {
    let Some(response) = engine_helpers::try_build_servfail_response_from_wire(request) else {
        return;
    };
    send_udp_response(socket, request, &response, peer).await;
}

/// 高性能 UDP worker：直接在接收循环中处理请求，避免 spawn 开销 / High-performance UDP worker: process requests directly in receive loop, avoiding spawn overhead
async fn run_udp_worker(
    worker_id: usize,
    socket: Arc<UdpSocket>,
    engine: Engine,
) -> anyhow::Result<()> {
    let engine = engine.with_client_transport(ClientTransport::Udp);
    // 预分配缓冲区 / Pre-allocate buffer
    // 使用 BytesMut 避免 Bytes::copy_from_slice 的内存分配 / Use BytesMut to avoid memory allocation in Bytes::copy_from_slice
    use bytes::BytesMut;
    let mut buf = BytesMut::with_capacity(4096);
    // 复用发送缓冲区：用于缓存命中时 patch TXID，避免每包堆分配 / Reuse send buffer to patch TXID on cache hits, avoiding per-packet heap allocation
    let mut send_buf = BytesMut::with_capacity(512);

    // 自适应流控：每 100 个请求检查一次是否需要调整 permits
    // Adaptive flow control: check if adjustment needed every 100 requests
    let mut request_count = 0u32;

    info!(worker_id, "UDP worker started");

    loop {
        // 确保有足够的空间 / Ensure sufficient space
        if buf.capacity() < 4096 {
            buf.reserve(4096 - buf.len());
        }

        // ✅ Hybrid recv: try non-blocking first, fall back to async on EAGAIN.
        // Under load, this eliminates tokio reactor overhead (epoll_wait +
        // task wake/schedule cycle) per packet. Under no load, falls back to
        // async await so the worker yields and doesn't waste CPU.
        //
        // ✅ 混合接收：先尝试非阻塞，EAGAIN 时回退到异步。
        // 高负载时消除每包的 tokio reactor 开销（epoll_wait + 任务唤醒/调度循环）。
        // 空闲时回退到异步 await，worker 让出 CPU 不浪费。
        let (_len, peer) = match socket.try_recv_buf_from(&mut buf) {
            Ok(result) => result,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No packet available right now — yield to tokio / 当前无包可读 — 让出 tokio
                match socket.recv_buf_from(&mut buf).await {
                    Ok(result) => result,
                    Err(_) => continue,
                }
            }
            Err(_) => continue,
        };
        {
            // 零拷贝获取 Bytes / Zero-copy obtain Bytes
            let packet_bytes = buf.split().freeze();
            if !is_standard_query_header(&packet_bytes) {
                continue;
            }

            // 每 100 个请求检查一次流控调整 / Check flow control adjustment every 100 requests
            request_count += 1;
            if request_count >= 100 {
                request_count = 0;
                engine.adjust_flow_control(); // Now synchronous with atomic CAS
            }

            // ✅ 优化：使用 handle_packet_fast 避免重复解析
            // ✅ Optimization: Use handle_packet_fast to avoid re-parsing
            // 如果缓存命中，直接返回；如果缓存未命中，返回预解析的数据
            // If cache hit, return directly; if cache miss, return pre-parsed data
            match engine.handle_packet_fast(&packet_bytes, peer) {
                Ok(Some(FastPathResponse::Direct(bytes))) => {
                    // 已包含正确 TXID，可直接发送 / Already contains correct TXID
                    send_udp_response(&socket, &packet_bytes, &bytes, peer).await;
                }
                Ok(Some(FastPathResponse::CacheHit {
                    cached,
                    tx_id,
                    inserted_at,
                })) => {
                    // RFC 1035 §5.2: Patch TTL based on residence time / 根据停留时间修正 TTL
                    let elapsed =
                        kixdns::proto_utils::saturating_u64_to_u32(inserted_at.elapsed().as_secs());

                    if elapsed == 0 && cached.len() >= 2 {
                        // Fast path: TTL hasn't decayed, only TXID (2 bytes) needs patching.
                        // Copy to reusable send_buf, patch TXID only, use try_send_to
                        // (non-blocking) to avoid tokio reactor overhead. Falls back to
                        // async send_to on EAGAIN.
                        //
                        // 快速路径：TTL 未衰减，只需 patch TXID（2 字节）。
                        // 拷贝到复用的 send_buf，仅 patch TXID，使用 try_send_to（非阻塞）
                        // 避免 tokio reactor 开销。EAGAIN 时回退到异步 send_to。
                        send_buf.clear();
                        send_buf.extend_from_slice(&cached);
                        let id_bytes = tx_id.to_be_bytes();
                        send_buf[0] = id_bytes[0];
                        send_buf[1] = id_bytes[1];
                        send_udp_response(&socket, &packet_bytes, &send_buf, peer).await;
                    } else {
                        // Slow path: TTL has decayed, must patch all TTLs in-place.
                        // 慢速路径：TTL 已衰减，必须原地 patch 所有 TTL。
                        send_buf.clear();
                        if send_buf.capacity() < cached.len() {
                            send_buf.reserve(cached.len() - send_buf.capacity());
                        }
                        send_buf.extend_from_slice(&cached);
                        if elapsed > 0 {
                            kixdns::proto_utils::patch_all_ttls(&mut send_buf, elapsed);
                        }
                        if send_buf.len() >= 2 {
                            let id_bytes = tx_id.to_be_bytes();
                            send_buf[0] = id_bytes[0];
                            send_buf[1] = id_bytes[1];
                        }
                        send_udp_response(&socket, &packet_bytes, &send_buf, peer).await;
                    }
                }
                Ok(Some(FastPathResponse::AsyncNeeded {
                    qname,
                    qtype,
                    qclass,
                    tx_id,
                    edns_present,
                    pipeline_id,
                })) => {
                    // 缓存未命中，使用预解析的数据避免重复解析
                    // Cache miss, use pre-parsed data to avoid re-parsing
                    let permit_mgr = Arc::clone(&engine.permit_manager);
                    let timeout_ms = engine.get_request_timeout_ms();
                    let timeout_dur = Duration::from_millis(timeout_ms);

                    // 非阻塞式 try_acquire，避免在接收循环中 await / Non-blocking try_acquire to avoid await in receive loop
                    if let Some(permit) = permit_mgr.try_acquire() {
                        let engine = engine.clone();
                        let socket = Arc::clone(&socket);
                        let packet_bytes = packet_bytes.clone();
                        tokio::spawn(async move {
                            let _permit = permit; // 自动释放 / Auto-release on drop

                            // ✅ 传递预解析数据给 handle_packet_internal，避免重复解析
                            // ✅ Pass pre-parsed data to handle_packet_internal to avoid re-parsing
                            match tokio::time::timeout(
                                timeout_dur,
                                engine.handle_packet_internal_with_pre_parsed(
                                    &packet_bytes,
                                    peer,
                                    false,
                                    PreParsedData::new(
                                        qname,
                                        qtype,
                                        qclass,
                                        tx_id,
                                        edns_present,
                                        pipeline_id,
                                    ),
                                ),
                            )
                            .await
                            {
                                Ok(Ok(resp)) => {
                                    send_udp_response(&socket, &packet_bytes, &resp, peer).await;
                                }
                                Ok(Err(e)) => {
                                    debug!(error = %e, "handle_packet error, returning SERVFAIL");
                                    send_udp_servfail(&socket, &packet_bytes, peer).await;
                                }
                                Err(_) => {
                                    warn!(
                                        timeout_ms,
                                        upstream_timeout_ms = engine.get_upstream_timeout_ms(),
                                        "request timeout after hedge and fallback exhausted"
                                    );
                                    send_udp_servfail(&socket, &packet_bytes, peer).await;
                                }
                            }
                        });
                    } else {
                        // 过载保护：permit 耗尽，用预解析数据快速构造 SERVFAIL 并非阻塞发送（背压丢弃）
                        // Overload: permit exhausted, fast SERVFAIL from pre-parsed data with non-blocking send
                        if let Ok(resp) = engine_helpers::build_servfail_response_fast(
                            tx_id,
                            &qname,
                            qtype,
                            qclass,
                            packet_bytes[2] & 0x01 != 0,
                        ) {
                            try_send_udp_response(&socket, &packet_bytes, &resp, peer);
                        }
                    }
                }
                Ok(None) => {
                    // 快速解析失败，回退到完整处理
                    // Fast parse failed, fallback to full processing
                    let permit_mgr = Arc::clone(&engine.permit_manager);
                    let timeout_ms = engine.get_request_timeout_ms();
                    let timeout_dur = Duration::from_millis(timeout_ms);

                    // 非阻塞式 try_acquire，避免在接收循环中 await / Non-blocking try_acquire to avoid await in receive loop
                    if let Some(permit) = permit_mgr.try_acquire() {
                        let engine = engine.clone();
                        let socket = Arc::clone(&socket);
                        let packet_bytes = packet_bytes.clone();
                        tokio::spawn(async move {
                            let _permit = permit; // 自动释放 / Auto-release on drop
                            match tokio::time::timeout(
                                timeout_dur,
                                engine.handle_packet(&packet_bytes, peer),
                            )
                            .await
                            {
                                Ok(Ok(resp)) => {
                                    send_udp_response(&socket, &packet_bytes, &resp, peer).await;
                                }
                                Ok(Err(e)) => {
                                    debug!(error = %e, "handle_packet error, returning SERVFAIL");
                                    send_udp_servfail(&socket, &packet_bytes, peer).await;
                                }
                                Err(_) => {
                                    warn!(
                                        timeout_ms,
                                        upstream_timeout_ms = engine.get_upstream_timeout_ms(),
                                        "request timeout"
                                    );
                                    send_udp_servfail(&socket, &packet_bytes, peer).await;
                                }
                            }
                        });
                    } else {
                        // 过载保护：permit 耗尽且 parse_quick 已失败（大概率畸形/非标准包）。
                        // 直接静默丢弃——过载时应做最便宜的拒绝，对已失败包做完整解析
                        // 只会加剧过载，且 hickory 大概率同样失败（解析白做）。
                        // Overload: permit exhausted and parse_quick already failed (likely
                        // malformed/non-standard). Drop silently — overload rejection must be
                        // cheap, and a full parse of an already-failed packet wastes CPU.
                    }
                }
                Err(error) => {
                    debug!(%error, "UDP fast-path error, returning SERVFAIL for valid query");
                    send_udp_servfail(&socket, &packet_bytes, peer).await;
                }
            }
        }
    }
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
        let engine = engine.clone();
        tokio::spawn(async move {
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

async fn handle_tcp_conn(
    stream: TcpStream,
    peer: SocketAddr,
    engine: Engine,
) -> anyhow::Result<()> {
    let engine = Arc::new(engine.with_client_transport(ClientTransport::Tcp));
    const MAX_TCP_FRAME: usize = 64 * 1024;
    let mut len_buf = [0u8; 2];

    // Reusable buffer to avoid per-frame heap allocation / 可复用缓冲区，避免每帧堆分配
    // 使用 BytesMut 以支持零拷贝操作 / Use BytesMut for zero-copy operations
    let mut buf = bytes::BytesMut::with_capacity(MAX_TCP_FRAME);

    let (mut reader, writer) = stream.into_split();
    let writer = Arc::new(tokio::sync::Mutex::new(writer));
    let slots = Arc::new(tokio::sync::Semaphore::new(TCP_MAX_QUERIES_PER_CONN));
    let mut pending = tokio::task::JoinSet::<()>::new();

    loop {
        // 收掉已经答完的 / Reap the ones already answered
        while pending.try_join_next().is_some() {}
        // 空闲超时：不再读，还在处理的查询写完回答后关闭连接，释放任务与文件描述符；对方读到头或出错
        // 同样结束
        // Idle timeout: reading stops, and once the queries still being handled have written
        // their answers the connection closes, releasing the task and the file descriptor;
        // the peer's end of stream or an error ends it too.
        if !matches!(
            tokio::time::timeout(TCP_READ_TIMEOUT, reader.read_exact(&mut len_buf)).await,
            Ok(Ok(_))
        ) {
            break;
        }
        let frame_len = u16::from_be_bytes(len_buf) as usize;
        if frame_len == 0 || frame_len > MAX_TCP_FRAME {
            break;
        }

        // Reuse buffer: resize to exact frame length / 复用缓冲区：调整到精确帧长度
        // resize() is safe and efficient - it only initializes new bytes if growing
        buf.clear();
        buf.resize(frame_len, 0);
        // 半截消息同样受限，发送方停在长度前缀之后不会让连接一直挂着
        // A half-sent message is bounded too: a sender that stops after the
        // length prefix cannot keep the connection hanging.
        if !matches!(
            tokio::time::timeout(TCP_READ_TIMEOUT, reader.read_exact(&mut buf)).await,
            Ok(Ok(_))
        ) {
            break;
        }

        let packet_bytes = buf.split().freeze();
        if !is_standard_query_header(&packet_bytes) {
            break;
        }

        // ✅ 优化：使用 handle_packet_fast 进行快速路径检查；当场能答的直接写回，要等上游的交给
        // 单独的任务，答完就回
        // ✅ Optimization: Use handle_packet_fast for fast path check; what it answers on the
        // spot is written back at once, and what waits on an upstream goes to its own task,
        // answered when done
        let async_needed = match engine.handle_packet_fast(&packet_bytes, peer) {
            Ok(Some(FastPathResponse::Direct(bytes))) => {
                // 快速路径命中：直接返回 / Fast path hit: return directly
                write_tcp_answer(&writer, &bytes).await;
                continue;
            }
            Ok(Some(FastPathResponse::CacheHit {
                cached,
                tx_id,
                inserted_at,
            })) => {
                // 缓存命中：patch TXID / Cache hit: patch TXID
                let mut resp_buf = bytes::BytesMut::with_capacity(cached.len());
                resp_buf.extend_from_slice(&cached);

                // RFC 1035 §5.2: Patch TTL based on residence time / 根据停留时间修正 TTL
                let elapsed =
                    kixdns::proto_utils::saturating_u64_to_u32(inserted_at.elapsed().as_secs());
                if elapsed > 0 {
                    kixdns::proto_utils::patch_all_ttls(&mut resp_buf, elapsed);
                }

                if resp_buf.len() >= 2 {
                    let id_bytes = tx_id.to_be_bytes();
                    resp_buf[0] = id_bytes[0];
                    resp_buf[1] = id_bytes[1];
                }
                write_tcp_answer(&writer, &resp_buf).await;
                continue;
            }
            Ok(Some(FastPathResponse::AsyncNeeded {
                qname,
                qtype,
                qclass,
                tx_id,
                edns_present,
                pipeline_id,
            })) => {
                // 缓存未命中：使用预解析数据避免重复解析
                // Cache miss: use pre-parsed data to avoid re-parsing
                Some(PreParsedData::new(
                    qname,
                    qtype,
                    qclass,
                    tx_id,
                    edns_present,
                    pipeline_id,
                ))
            }
            // 快速解析失败，回退到完整处理 / Fast parse failed, fallback to full processing
            Ok(None) => None,
            Err(error) => {
                debug!(%error, "TCP fast-path error, returning SERVFAIL for valid query");
                if let Some(response) =
                    engine_helpers::try_build_servfail_response_from_wire(&packet_bytes)
                {
                    write_tcp_answer(&writer, &response).await;
                }
                continue;
            }
        };

        let Ok(slot) = Arc::clone(&slots).acquire_owned().await else {
            break;
        };
        let engine = Arc::clone(&engine);
        let writer = Arc::clone(&writer);
        pending.spawn(async move {
            let _slot = slot;
            if let Some(response) =
                answer_tcp_query(&engine, &packet_bytes, peer, async_needed).await
            {
                write_tcp_answer(&writer, &response).await;
            }
        });
    }

    // 读完了：等还在处理的查询把回答写出去再关连接，半关闭的客户端照样拿到回答
    // Reading is over: the queries still being handled write their answers before the
    // connection closes, so a half-closed client still gets them
    while pending.join_next().await.is_some() {}
    Ok(())
}

/// 要等上游的查询：在整体请求时限内回答，出错或超时回 SERVFAIL；连 SERVFAIL 都构造不出时为 None。
/// `pre_parsed` 为 None 时快速解析没成，走完整处理。
/// A query that waits on an upstream: answered within the overall request timeout, SERVFAIL on
/// an error or a timeout; None when not even a SERVFAIL can be built. With `pre_parsed` None
/// the quick parse failed and the full path runs.
async fn answer_tcp_query(
    engine: &Engine,
    packet: &[u8],
    peer: SocketAddr,
    pre_parsed: Option<PreParsedData>,
) -> Option<bytes::Bytes> {
    // 每个查询重新取整体请求超时（含 hedge 与 TCP fallback）。RFC 7766 的客户端会把一条连接用很久，
    // 热重载改了 request_timeout 之后，这条连接上的后续查询必须跟着新值走；UDP 路径本来就是每请求
    // 读一次。
    // Re-read the overall request timeout (hedge and TCP fallback included) per query. An RFC
    // 7766 client keeps one connection open for a long time, so queries that follow a reload
    // must use the new request_timeout; the UDP path already reads it per request.
    let timeout_ms = engine.get_request_timeout_ms();
    let timeout_dur = Duration::from_millis(timeout_ms);
    let full_path = pre_parsed.is_none();
    let answered = match pre_parsed {
        Some(pre_parsed) => {
            tokio::time::timeout(
                timeout_dur,
                engine.handle_packet_internal_with_pre_parsed(packet, peer, false, pre_parsed),
            )
            .await
        }
        None => tokio::time::timeout(timeout_dur, engine.handle_packet(packet, peer)).await,
    };
    match answered {
        Ok(Ok(response)) => return Some(response),
        Ok(Err(error)) => {
            debug!(%error, "TCP request processing error, returning SERVFAIL");
        }
        Err(_) if full_path => {
            warn!(
                timeout_ms,
                upstream_timeout_ms = engine.get_upstream_timeout_ms(),
                "TCP request timeout"
            );
        }
        Err(_) => {
            warn!(
                timeout_ms,
                upstream_timeout_ms = engine.get_upstream_timeout_ms(),
                "TCP request timeout after hedge and fallback exhausted"
            );
        }
    }
    engine_helpers::try_build_servfail_response_from_wire(packet)
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

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server_stream, peer) = listener.accept().await.unwrap();
        let connection = tokio::spawn(handle_tcp_conn(server_stream, peer, engine.clone()));
        let query = dns_query();
        client
            .write_all(&(query.len() as u16).to_be_bytes())
            .await
            .unwrap();
        client.write_all(&query).await.unwrap();
        let mut len_buf = [0u8; 2];
        client
            .read_exact(&mut len_buf)
            .await
            .expect("length prefix");
        let mut response = vec![0u8; u16::from_be_bytes(len_buf) as usize];
        client.read_exact(&mut response).await.expect("dns frame");

        assert_eq!(
            *recorder.0.lock().unwrap(),
            [Some(ClientTransport::Udp), Some(ClientTransport::Tcp)]
        );
        worker.abort();
        connection.abort();
    }

    fn dns_query() -> Vec<u8> {
        let mut message = Message::new(0xCAFE, MessageType::Query, OpCode::Query);
        message.metadata.recursion_desired = true;
        message.add_query(Query::query(
            Name::from_str("data.xiaoheihe.cn").unwrap(),
            RecordType::A,
        ));
        message.to_vec().unwrap()
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
        for (case, packet) in [
            ("QR=1", qr_response),
            ("missing Additional RR", missing_additional),
            ("truncated EDNS RDATA", truncated_edns),
            ("invalid Additional compression pointer", invalid_pointer),
        ] {
            client.send_to(&packet, server_addr).await.unwrap();
            assert!(
                tokio::time::timeout(
                    Duration::from_millis(100),
                    client.recv_from(&mut response_buf),
                )
                .await
                .is_err(),
                "{case} must be rejected before static/cache fast paths"
            );
        }

        worker.abort();
    }

    fn forwarding_engine() -> Engine {
        use kixdns::config::PipelineConfig;

        let config: PipelineConfig = serde_json::from_value(serde_json::json!({
            "settings": {
                "default_upstream": "127.0.0.1:9",
                "flow_control_enabled": true,
                "flow_control_initial_permits": 1,
                "flow_control_min_permits": 1,
                "flow_control_max_permits": 1
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
        Engine::new(runtime, "test".to_string()).expect("initialize engine")
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

    #[tokio::test]
    async fn udp_permit_exhaustion_returns_servfail_but_malformed_packet_is_silent() {
        let engine = forwarding_engine();
        engine.permit_manager.set_max_permits(0);

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
        let blackhole = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let blackhole_addr = blackhole.local_addr().unwrap();
        let blackhole_task = tokio::spawn(async move {
            if let Ok((_stream, _)) = blackhole.accept().await {
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });

        let upstream = format!("https://{blackhole_addr}/dns-query");
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
        blackhole_task.abort();
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
        let blackhole = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let blackhole_addr = blackhole.local_addr().unwrap();
        let blackhole_task = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = blackhole.accept().await {
                held.push(stream);
            }
        });

        let upstream = format!("https://{blackhole_addr}/dns-query");
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
        blackhole_task.abort();
    }

    /// 在一条已建立的连接上发一次查询并读回完整应答，返回耗时
    /// Send one query on an established connection, read the whole answer back
    /// and return how long it took
    async fn time_one_tcp_query(client: &mut TcpStream) -> Duration {
        let query = dns_query();
        let mut frame = Vec::with_capacity(2 + query.len());
        frame.extend_from_slice(&(query.len() as u16).to_be_bytes());
        frame.extend_from_slice(&query);

        let start = std::time::Instant::now();
        client.write_all(&frame).await.unwrap();
        let mut len_buf = [0u8; 2];
        client
            .read_exact(&mut len_buf)
            .await
            .expect("length prefix");
        let mut response = vec![0u8; u16::from_be_bytes(len_buf) as usize];
        client.read_exact(&mut response).await.expect("dns frame");
        let elapsed = start.elapsed();

        let message = Message::from_bytes(&response).unwrap();
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
        let mut request = Message::new(id, MessageType::Query, OpCode::Query);
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
        let query = request.to_vec().unwrap();
        [(query.len() as u16).to_be_bytes().to_vec(), query].concat()
    }

    /// 从连接上读一个回答，返回它的 ID / Reads one answer off the connection and returns its ID
    async fn read_answer_id(client: &mut TcpStream) -> u16 {
        let mut len_buf = [0u8; 2];
        client
            .read_exact(&mut len_buf)
            .await
            .expect("length prefix");
        let mut answer = vec![0u8; u16::from_be_bytes(len_buf) as usize];
        client.read_exact(&mut answer).await.expect("answer");
        u16::from_be_bytes([answer[0], answer[1]])
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
        let blackhole = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let blackhole_addr = blackhole.local_addr().unwrap();
        let blackhole_task = tokio::spawn(async move {
            if let Ok((_stream, _)) = blackhole.accept().await {
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });

        let upstream = format!("https://{blackhole_addr}/dns-query");
        let engine = doh_timeout_engine(&upstream);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener_addr = listener.local_addr().unwrap();
        let client_task = tokio::spawn(async move {
            let mut client = TcpStream::connect(listener_addr).await.unwrap();
            let query = dns_query();
            let mut frame = Vec::with_capacity(2 + query.len());
            frame.extend_from_slice(&(query.len() as u16).to_be_bytes());
            frame.extend_from_slice(&query);
            client.write_all(&frame).await.unwrap();

            let mut len_buf = [0u8; 2];
            tokio::time::timeout(Duration::from_secs(1), client.read_exact(&mut len_buf))
                .await
                .expect("TCP query should receive a length prefix")
                .unwrap();
            let response_len = u16::from_be_bytes(len_buf) as usize;
            let mut response = vec![0u8; response_len];
            tokio::time::timeout(Duration::from_secs(1), client.read_exact(&mut response))
                .await
                .expect("TCP query should receive the complete DNS frame")
                .unwrap();
            response
        });

        let (server_stream, peer) = listener.accept().await.unwrap();
        let server_task = tokio::spawn(handle_tcp_conn(server_stream, peer, engine));
        let response_bytes = client_task.await.unwrap();
        let response = Message::from_bytes(&response_bytes).unwrap();
        assert_eq!(response.metadata.id, 0xCAFE);
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(response.queries.len(), 1);

        server_task.abort();
        blackhole_task.abort();
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
            send_udp_response(&server, &buf[..len], &big_response, peer).await;
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
}
