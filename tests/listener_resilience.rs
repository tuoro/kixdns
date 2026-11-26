//! Listeners outlive accept errors.
//!
//! Runs the real binary under a low descriptor limit, uses up its descriptors
//! with DNS-over-TCP connections, has the DoH listener and the control socket
//! hit the same accept error, then lets the connections go. Every listener must
//! answer again, and the TCP and DoH listeners and the control socket, meeting
//! the error every 100 ms meanwhile, log it once in a while rather than each time.
//!
//! 监听口熬得过接受出错：在压低的句柄上限下跑真的程序，用 DNS over TCP 连接把句柄用光，让 DoH
//! 监听口和控制通道也碰上同一个接受错误，再把连接放掉，每个监听口都要能再应答；这期间 TCP、DoH
//! 监听口和控制通道每 100 ms 碰上一次这个错误，隔一阵才记一条，不是每次都记。
#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpStream, UdpSocket};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::str::FromStr;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};

mod common;
use common::{Kernel, control_answers, free_port};

/// Descriptors the process may hold: a few dozen are taken at start-up, so a
/// hundred-odd client connections use the rest up.
/// 进程可持有的句柄数：启动就占掉几十个，一百多个客户端连接就能把剩下的用光。
const NOFILE: libc::rlim_t = 128;

// SAFETY: 在 main 之前跑，只把加密实现存成 rustls 的进程级默认值 / Runs before main, only
// storing the crypto provider as rustls' process-wide default
#[ctor::ctor(unsafe)]
fn init() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn query(name: &str, id: u16) -> Vec<u8> {
    let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
    msg.to_vec().unwrap()
}

fn udp_answers(port: u16) -> bool {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    socket
        .send_to(&query("ok.test", 1), (Ipv4Addr::LOCALHOST, port))
        .unwrap();
    let mut buf = [0u8; 512];
    socket.recv(&mut buf).is_ok()
}

fn tcp_answers(port: u16) -> bool {
    let attempt = || -> std::io::Result<bool> {
        let mut stream = TcpStream::connect_timeout(
            &(Ipv4Addr::LOCALHOST, port).into(),
            Duration::from_secs(1),
        )?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        let msg = query("ok.test", 2);
        stream.write_all(&(msg.len() as u16).to_be_bytes())?;
        stream.write_all(&msg)?;
        let mut len = [0u8; 2];
        stream.read_exact(&mut len)?;
        let mut answer = vec![0u8; u16::from_be_bytes(len) as usize];
        stream.read_exact(&mut answer)?;
        Ok(answer.len() > 12 && answer[..2] == [0, 2])
    };
    attempt().unwrap_or(false)
}

async fn doh_answers(port: u16) -> bool {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    client
        .post(format!("https://127.0.0.1:{port}/dns-query"))
        .header("content-type", "application/dns-message")
        .body(query("ok.test", 3))
        .send()
        .await
        .is_ok_and(|r| r.status() == reqwest::StatusCode::OK)
}

/// 连上几个，好让监听口一再碰上接受错误：XNU 的 accept 碰上 EMFILE 会丢掉排队的那个连接，只连一个只碰上一次，
/// 每次都记和隔一阵才记一条分不出来。监听口每 100 ms 再接受一次，等的 300 ms 里五个约有三个这样碰上，其余的等句柄
/// 放出来以后照常接受（Linux 上连接留在队列里，排头那个每 100 ms 再碰一次）
/// Several connect, so that the listener meets the accept error again and again: XNU's
/// accept, meeting EMFILE, drops the connection queued, so one alone meets it once, and logging
/// each time could not be told from logging once in a while. The listener accepts again every
/// 100 ms, so in the 300 ms waited about three of the five meet it so, the rest accepted as
/// usual once descriptors are free (on Linux the connection stays queued, the one at its head
/// met again every 100 ms)
fn probes<T>(connect: impl FnMut() -> std::io::Result<T>) -> Vec<std::io::Result<T>> {
    std::iter::repeat_with(connect).take(5).collect()
}

/// Poll until `check` holds, for up to `limit`.
async fn eventually<F, Fut>(limit: Duration, mut check: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let start = Instant::now();
    while start.elapsed() < limit {
        if check().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listeners_answer_again_after_running_out_of_descriptors() {
    let dir = tempfile::TempDir::new().unwrap();
    let (cert, key) = {
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params
            .subject_alt_names
            .push(rcgen::SanType::IpAddress(Ipv4Addr::LOCALHOST.into()));
        let pair = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&pair).unwrap();
        (cert.pem(), pair.serialize_pem())
    };
    std::fs::write(dir.path().join("cert.pem"), cert).unwrap();
    std::fs::write(dir.path().join("key.pem"), key).unwrap();
    let dns_port = free_port();
    let doh_port = free_port();
    let control = dir.path().join("control.sock");
    let config = serde_json::json!({
        "version": "1.0",
        "settings": {
            "bind_udp": format!("127.0.0.1:{dns_port}"),
            "bind_tcp": format!("127.0.0.1:{dns_port}"),
            "bind_doh": format!("127.0.0.1:{doh_port}"),
            "doh_tls_cert": dir.path().join("cert.pem"),
            "doh_tls_key": dir.path().join("key.pem"),
            "default_upstream": "127.0.0.1:9",
        },
        "pipelines": [{
            "id": "main",
            "rules": [{
                "name": "ok",
                "matchers": [{ "type": "domain_suffix", "value": "ok.test" }],
                "actions": [{ "type": "static_ip_response", "ip": "192.0.2.1" }],
            }],
        }],
    });
    let config_path = dir.path().join("config.json");
    std::fs::write(&config_path, config.to_string()).unwrap();

    let log = dir.path().join("kixdns.log");
    let output = std::fs::File::create(&log).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_kixdns"));
    command
        .args(["run", "--config"])
        .arg(&config_path)
        .arg("--admin-socket")
        .arg(&control)
        .env("RUST_LOG", "warn")
        .stdout(output.try_clone().unwrap())
        .stderr(output);
    // SAFETY: setrlimit is async-signal-safe and touches only the child.
    unsafe {
        command.pre_exec(|| {
            let limit = libc::rlimit {
                rlim_cur: NOFILE,
                rlim_max: NOFILE,
            };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
    let _kernel = Kernel(command.spawn().unwrap());

    let ready = eventually(Duration::from_secs(20), || async {
        udp_answers(dns_port) && control.exists()
    })
    .await;
    assert!(ready, "kernel did not start");
    assert!(tcp_answers(dns_port), "TCP must answer before the test");

    // Use up the descriptors with idle DNS-over-TCP connections. Connections past
    // the limit still complete in the listen backlog, so stop at a fixed count.
    // 用不说话的 DNS over TCP 连接把句柄用光；超出上限的连接仍会在监听队列里建立，所以按固定数目停。
    let mut held = Vec::new();
    for _ in 0..(NOFILE as usize + 32) {
        match TcpStream::connect_timeout(
            &(Ipv4Addr::LOCALHOST, dns_port).into(),
            Duration::from_millis(200),
        ) {
            Ok(stream) => held.push(stream),
            Err(_) => break,
        }
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    // With the descriptors gone, the DoH listener and the control socket meet the
    // same accept error.
    // 句柄用光以后，DoH 监听口和控制通道也碰上同一个接受错误。
    let doh_probes = probes(|| {
        TcpStream::connect_timeout(
            &(Ipv4Addr::LOCALHOST, doh_port).into(),
            Duration::from_millis(500),
        )
    });
    let control_probes = probes(|| UnixStream::connect(&control));
    tokio::time::sleep(Duration::from_millis(300)).await;
    drop(doh_probes);
    drop(control_probes);
    drop(held);

    assert!(
        eventually(Duration::from_secs(5), || async { tcp_answers(dns_port) }).await,
        "DNS over TCP must answer again once descriptors are free"
    );
    assert!(
        eventually(Duration::from_secs(5), || doh_answers(doh_port)).await,
        "DoH must answer again once descriptors are free"
    );
    assert!(
        eventually(Duration::from_secs(5), || async {
            control_answers(&control)
        })
        .await,
        "the control socket must answer again once descriptors are free"
    );
    assert!(udp_answers(dns_port), "UDP keeps answering throughout");
    let log = std::fs::read_to_string(&log).unwrap();
    let logged = |what: &str| log.lines().filter(|line| line.contains(what)).count();
    assert_eq!(logged("tcp accept failed"), 1, "{log}");
    assert_eq!(logged("DoH accept failed"), 1, "{log}");
    assert_eq!(logged("control socket accept failed"), 1, "{log}");
}
