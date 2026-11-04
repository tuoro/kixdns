//! The kernel takes its listening ports before anything else, and says so when it
//! cannot.
//!
//! The kernel's upstream sockets get their ports from the system. They used to be
//! opened before the listening ports were bound, so a listening port in that range
//! could be among them, and the kernel did not start.
//!
//! 内核最先占住监听端口，占不到时说清楚。内核的上游 socket 由系统挑端口，以前它们在绑定监听口之前打开，
//! 系统分配范围里的监听口可能正好被挑走，内核就起不来了。
#![cfg(target_os = "linux")]

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};

mod common;
use common::{Kernel, free_port};

/// 跑真的程序，日志写进 `dir` 里的 kixdns.log；句柄上限提到顶，上游 socket 多的时候够用
/// Runs the real binary, logging into kixdns.log in `dir`; the descriptor limit is raised to its top, enough
/// for many upstream sockets
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
    // SAFETY: getrlimit and setrlimit are async-signal-safe and touch only this process's limit
    unsafe {
        command.pre_exec(|| {
            let mut limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) == 0 {
                limit.rlim_cur = limit.rlim_max;
                libc::setrlimit(libc::RLIMIT_NOFILE, &limit);
            }
            Ok(())
        });
    }
    Kernel(command.spawn().unwrap())
}

fn log_of(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("kixdns.log")).unwrap()
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

/// 上游 socket 占掉系统分配范围的七成（句柄不够时少开一些），这时多数启动都会挑走范围里的监听口，如果它们先打开的话
/// With upstream sockets filling seven tenths of the system's range (fewer if descriptors run short), most starts
/// would hand them a listening port in that range, were they opened first
#[test]
fn a_listening_port_in_the_system_range_is_not_taken_by_upstream_sockets() {
    let range = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range").unwrap();
    let mut ports = range.split_whitespace().map(|port| port.parse::<u64>());
    let (first, last) = (
        ports.next().unwrap().unwrap(),
        ports.next().unwrap().unwrap(),
    );
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit only writes the struct it is handed
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
        0
    );
    let upstream_sockets = ((last - first) * 7 / 10).min(limit.rlim_max.saturating_sub(1024));

    for _ in 0..3 {
        let dir = tempfile::TempDir::new().unwrap();
        // 系统现在空着的一个端口 / A port the system has free now
        let port = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
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
    for (held_udp, reason) in [(true, "udp socket"), (false, "bind ipv4 tcp")] {
        let _udp = held_udp.then(|| UdpSocket::bind(bind).unwrap());
        let _tcp = (!held_udp).then(|| TcpListener::bind(bind).unwrap());
        let dir = tempfile::TempDir::new().unwrap();
        let mut kernel = start(dir.path(), settings.clone());
        let status = kernel.0.wait().unwrap();
        let log = log_of(dir.path());
        assert!(!status.success());
        assert!(log.contains(reason), "{log}");
        assert!(log.contains("Address already in use"), "{log}");
        assert!(!log.contains("dns server started"), "{log}");
    }
}

/// DoH 端口被占只记一条错误，DNS 照常答 / A taken DoH port is only logged, and DNS answers as usual
#[test]
fn a_taken_doh_port_leaves_dns_answering() {
    let dir = tempfile::TempDir::new().unwrap();
    let port = free_port();
    let doh_port = free_port();
    let _doh = TcpListener::bind((Ipv4Addr::LOCALHOST, doh_port)).unwrap();
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
    assert!(log.contains("DoH server exited"), "{log}");
    assert!(log.contains("Address already in use"), "{log}");
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
