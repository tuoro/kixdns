//! The kernel takes its listening ports before anything else, and says so when it
//! cannot.
//!
//! The kernel's upstream sockets get their ports from the system. They used to be
//! opened before the listening ports were bound, so a listening port in that range
//! could be among them, and the kernel did not start.
//!
//! 内核最先占住监听端口，占不到时说清楚。内核的上游 socket 由系统挑端口，以前它们在绑定监听口之前打开，
//! 系统分配范围里的监听口可能正好被挑走，内核就起不来了。
#![cfg(unix)]

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};

mod common;
use common::{Kernel, free_port};

/// 跑真的程序，日志写进 `dir` 里的 kixdns.log / Runs the real binary, logging into kixdns.log in `dir`
fn start(dir: &Path, settings: serde_json::Value) -> Kernel {
    let config = dir.join("config.json");
    let mut full = serde_json::json!({
        "default_upstream": "127.0.0.1:9",
    });
    full.as_object_mut()
        .unwrap()
        .extend(settings.as_object().unwrap().clone());
    let config_text = serde_json::json!({
        "settings": full,
        "pipelines": [{
            "id": "main",
            "rules": [{
                "name": "ok",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "static_ip_response", "ip": "192.0.2.1" }],
            }],
        }],
    });
    std::fs::write(&config, config_text.to_string()).unwrap();
    let output = std::fs::File::create(dir.join("kixdns.log")).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_kixdns"));
    command
        .args(["run", "--config"])
        .arg(&config)
        .stdout(output.try_clone().unwrap())
        .stderr(output)
        .stdin(Stdio::null());
    Kernel(command.spawn().unwrap())
}

fn log_of(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("kixdns.log")).unwrap()
}

/// 端口被占时日志里写的那段错误：C 库给的文字连同错误号，内核和测试用的是同一个 C 库（glibc 写 "Address already in
/// use"，musl 写 "Address in use"）
/// What the log writes for a taken port: the C library's text with the error number, the kernel
/// and the test using the same C library (glibc writes "Address already in use", musl "Address
/// in use")
fn address_in_use() -> String {
    std::io::Error::from_raw_os_error(libc::EADDRINUSE).to_string()
}

fn query() -> Vec<u8> {
    let mut query = Message::new(7, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(
        "ok.test.".parse::<Name>().unwrap(),
        RecordType::A,
    ));
    query.to_vec().unwrap()
}

fn udp_answers(to: SocketAddr) -> bool {
    let from: SocketAddr = match to {
        SocketAddr::V4(_) => (Ipv4Addr::LOCALHOST, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::LOCALHOST, 0).into(),
    };
    let socket = UdpSocket::bind(from).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    socket.send_to(&query(), to).unwrap();
    socket.recv(&mut [0u8; 512]).is_ok()
}

fn tcp_answers(to: SocketAddr) -> bool {
    use std::io::{Read, Write};
    let attempt = || -> std::io::Result<()> {
        let mut stream = TcpStream::connect_timeout(&to, Duration::from_millis(500))?;
        stream.set_read_timeout(Some(Duration::from_millis(500)))?;
        let query = query();
        stream.write_all(&(query.len() as u16).to_be_bytes())?;
        stream.write_all(&query)?;
        stream.read_exact(&mut [0u8; 2])
    };
    attempt().is_ok()
}

/// 等 `check` 成立；内核退出了或者等太久就是 false / Waits for `check`; false once the kernel has exited or too long has passed
fn until(kernel: &mut Kernel, check: impl Fn() -> bool) -> bool {
    let start = Instant::now();
    loop {
        if check() {
            return true;
        }
        if kernel.0.try_wait().unwrap().is_some() || start.elapsed() > Duration::from_secs(60) {
            return false;
        }
    }
}

/// 等内核自己退出，最多 10 秒：到时还在跑就带着它的日志失败，不一直挂着 / Waits for the kernel to exit by
/// itself, 10 seconds at most: one still running by then fails the test with its log instead of
/// hanging
fn exit_of(kernel: &mut Kernel, dir: &Path) -> std::process::ExitStatus {
    let start = Instant::now();
    loop {
        if let Some(status) = kernel.0.try_wait().unwrap() {
            return status;
        }
        if start.elapsed() > Duration::from_secs(10) {
            panic!("the kernel did not exit in 10 s: {}", log_of(dir));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// 系统分配范围里只空出比最大的上游池多四分之一的端口，监听口是其中一个：上游 socket 要是先开，多半会挑走它。
/// 分配范围从 /proc 读，只在 Linux 上测
/// With only a quarter more ports of the system's range free than the largest upstream pool, the listening
/// port among them, upstream sockets would mostly take it, were they opened first. The range is
/// read from /proc, so this runs on Linux alone
#[cfg(target_os = "linux")]
#[test]
fn a_listening_port_in_the_system_range_is_not_taken_by_upstream_sockets() {
    let range = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range").unwrap();
    let mut ports = range
        .split_whitespace()
        .map(|port| port.parse::<u16>().unwrap());
    let range = ports.next().unwrap()..=ports.next().unwrap();
    // 句柄上限提到顶，占端口要用；内核继承这个上限，上游 socket 也够用
    // The descriptor limit raised to its top for holding ports; the kernel inherits it, enough for its
    // upstream sockets
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit and setrlimit touch only this process's limit
    unsafe {
        assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit), 0);
        limit.rlim_cur = limit.rlim_max;
        assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &limit), 0);
    }
    let upstream_sockets = kixdns::config::MAX_POOL_SIZE;
    // 空端口均匀散开：上游 socket 先开时挑走监听口的机会和挑走哪个空端口都一样，八成；本机别的程序（包括同时跑的
    // 测试）这时要一个端口，碰上监听口的机会只有一千多分之一。句柄不够时少占一些
    // The free ports spread evenly: upstream sockets opened first would take the listening port as
    // likely as any free one, four times in five, while a port another program (a test running
    // alongside, say) asks for meanwhile is the listening port about once in a thousand. Fewer are held
    // when descriptors run short
    let step = (range.len() / (upstream_sockets * 5 / 4)).max(1);
    let (free, held): (Vec<u16>, Vec<u16>) = range
        .clone()
        .partition(|port| usize::from(port - range.start()) % step == 0);
    let most =
        usize::try_from(limit.rlim_cur).map_or(usize::MAX, |limit| limit.saturating_sub(256));

    for _ in 0..3 {
        let _held: Vec<UdpSocket> = held
            .iter()
            .take(most)
            .filter_map(|&port| UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port)).ok())
            .collect();
        // 空端口里 UDP 和 TCP 都空着的一个 / A free port free for UDP and TCP alike
        let port = free
            .iter()
            .copied()
            .find(|&port| {
                UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port)).is_ok()
                    && TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok()
            })
            .unwrap();

        let dir = tempfile::TempDir::new().unwrap();
        let mut kernel = start(
            dir.path(),
            serde_json::json!({
                "bind_udp": format!("127.0.0.1:{port}"),
                "bind_tcp": format!("127.0.0.1:{port}"),
                "udp_pool_size": upstream_sockets,
            }),
        );
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        assert!(
            until(&mut kernel, || udp_answers(address)),
            "kernel did not start on port {port} with {upstream_sockets} upstream sockets: {}",
            log_of(dir.path())
        );
    }
}

/// UDP 或 TCP 端口被占，内核退出并说明原因，不会先说自己启动了
/// With the UDP or the TCP port taken the kernel exits and says why, without first saying it started
#[test]
fn a_taken_dns_port_ends_the_kernel_with_the_reason() {
    let port = free_port();
    let bind = (Ipv4Addr::LOCALHOST, port);
    let settings = serde_json::json!({
        "bind_udp": format!("127.0.0.1:{port}"),
        "bind_tcp": format!("127.0.0.1:{port}"),
    });
    for (held_udp, reason) in [
        (true, "bind IPv4 UDP socket"),
        (false, "bind IPv4 TCP listener"),
    ] {
        let _udp = held_udp.then(|| UdpSocket::bind(bind).unwrap());
        let _tcp = (!held_udp).then(|| TcpListener::bind(bind).unwrap());
        let dir = tempfile::TempDir::new().unwrap();
        let mut kernel = start(dir.path(), settings.clone());
        let status = exit_of(&mut kernel, dir.path());
        let log = log_of(dir.path());
        assert!(!status.success());
        assert!(log.contains(reason), "{log}");
        assert!(log.contains(&address_in_use()), "{log}");
        assert!(!log.contains("dns server started"), "{log}");
    }
}

/// DoH 端口被占只记一条错误，DNS 照常答 / A taken DoH port is only logged, and DNS answers as usual
#[test]
fn a_taken_doh_port_leaves_dns_answering() {
    let dir = tempfile::TempDir::new().unwrap();
    let port = free_port();
    // 占着的端口直接由系统给，拿到时就已经占上：先挑一个空着的再去占，中间可能被别的测试抢走
    // The taken port comes straight from the system, taken the moment it is had: picking a free one
    // and then taking it left a gap in which another test could take it first
    let doh = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let doh_port = doh.local_addr().unwrap().port();
    let mut kernel = start(
        dir.path(),
        serde_json::json!({
            "bind_udp": format!("127.0.0.1:{port}"),
            "bind_tcp": format!("127.0.0.1:{port}"),
            "bind_doh": format!("127.0.0.1:{doh_port}"),
            "doh_tls_cert": dir.path().join("not-needed.pem"),
            "doh_tls_key": dir.path().join("not-needed.pem"),
        }),
    );
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    assert!(until(&mut kernel, || udp_answers(address) && tcp_answers(address)));
    let log = log_of(dir.path());
    assert!(log.contains("DoH server cannot start"), "{log}");
    assert!(log.contains(&address_in_use()), "{log}");
}

/// 监听 `[::]` 时 IPv4 和 IPv6 都答，UDP 和 TCP 都一样；这台机器没有 IPv6 就不测
/// Listening on `[::]` answers over IPv4 and IPv6, on UDP and TCP alike; skipped on a machine without IPv6
#[test]
fn a_wildcard_address_answers_on_both_families() {
    if UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).is_err() {
        return;
    }
    let dir = tempfile::TempDir::new().unwrap();
    let port = free_port();
    let mut kernel = start(
        dir.path(),
        serde_json::json!({
            "bind_udp": format!("[::]:{port}"),
            "bind_tcp": format!("[::]:{port}"),
        }),
    );
    let v4 = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let v6 = SocketAddr::from((Ipv6Addr::LOCALHOST, port));
    assert!(
        until(&mut kernel, || {
            udp_answers(v4) && udp_answers(v6) && tcp_answers(v4) && tcp_answers(v6)
        }),
        "{}",
        log_of(dir.path())
    );
}
