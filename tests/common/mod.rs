//! What the integration tests that run the real binary share.
//!
//! 跑真程序的集成测试共用的部分。

// Each test binary uses its own part of this / 每个测试程序只用到其中一部分
#![allow(dead_code)]

use std::net::{Ipv4Addr, TcpListener, UdpSocket};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, RecordType};

/// A local port free for both TCP and UDP / 本机上 TCP 和 UDP 都空着的端口
///
/// 挑在系统分配临时端口的范围之下（Linux 从 32768 起）。范围内的端口查完以后到内核绑定之前是空着的，
/// 这期间任何新开的 socket 都可能拿走它，包括内核自己的上游 socket，内核就起不来了。起点从进程号算，
/// 同时跑的测试程序不容易挑到同一个；一个测试程序里不会挑到两次。最多试 200 次。
/// Picked below the range the system hands out ephemeral ports from (32768 up on Linux). A port in that
/// range sits free between this check and the kernel binding it, and any new socket may take it
/// meanwhile, the kernel's own upstream sockets included, and the kernel does not start. The starting
/// point comes from the process id, so test binaries running together rarely pick the same; one binary
/// never picks a port twice. At most 200 tries.
pub fn free_port() -> u16 {
    const FIRST: u32 = 20_000;
    const PORTS: u32 = 12_000;
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let start = std::process::id().wrapping_mul(61);
    for _ in 0..200 {
        let next = NEXT.fetch_add(1, Ordering::Relaxed);
        let port = (FIRST + start.wrapping_add(next) % PORTS) as u16;
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, port));
        if udp.is_ok() && TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok() {
            return port;
        }
    }
    panic!("port conflict: no port free for both UDP and TCP in 200 tries");
}

/// The running binary, ended when the test ends, a failing one too
/// 跑着的程序，测试结束时（失败也一样）结束它
pub struct Kernel(pub Child);

impl Drop for Kernel {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// 起一个读 `config` 的内核，不等它开始应答。日志像 OpenWrt 上 procd 那样写进文件 `log`，既不是终端也不是 journald，
/// 级别是 `level`（None 是默认级别，不看测试自己的 RUST_LOG）
/// Starts a kernel reading `config`, without waiting for it to answer. It logs into the file
/// `log` as procd has it on OpenWrt, neither a terminal nor journald, at `level` (None for the
/// default level, whatever RUST_LOG the test itself has)
pub fn run_logging(config: &Path, log: &Path, level: Option<&str>) -> Kernel {
    let output = std::fs::File::create(log).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_kixdns"));
    command
        .args(["run", "--config"])
        .arg(config)
        .env_remove("RUST_LOG")
        .env_remove("JOURNAL_STREAM");
    if let Some(level) = level {
        command.env("RUST_LOG", level);
    }
    Kernel(
        command
            .stdout(output.try_clone().unwrap())
            .stderr(output)
            .stdin(Stdio::null())
            .spawn()
            .unwrap(),
    )
}

/// 等 `check` 成立，最多等 `limit`，每 100 毫秒看一次 / Waits up to `limit` for `check` to hold,
/// looking every 100 milliseconds
pub fn eventually(limit: Duration, mut check: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < limit {
        if check() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// 经 UDP 问本机 `port` 上的内核 `name` 的 A 记录，等半秒；没有回答是 None
/// Asks the kernel on local `port` over UDP for `name`'s A record, waiting half a second; None
/// when no reply comes
pub fn ask(port: u16, name: &str) -> Option<Message> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let mut query = Message::new(7, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
    socket
        .send_to(&query.to_vec().unwrap(), (Ipv4Addr::LOCALHOST, port))
        .unwrap();
    let mut buf = [0u8; 512];
    let n = socket.recv(&mut buf).ok()?;
    Message::from_vec(&buf[..n]).ok()
}

/// 回答里的第一个 A 记录 / The first A record of a reply
pub fn first_a(reply: &Message) -> Option<Ipv4Addr> {
    reply.answers.iter().find_map(|record| match &record.data {
        RData::A(a) => Some(a.0),
        _ => None,
    })
}

/// Whether the control socket at `path` answers /v1/health with 200
/// 控制通道 `path` 对 /v1/health 回不回 200
#[cfg(unix)]
pub fn control_answers(path: &std::path::Path) -> bool {
    use std::io::{Read, Write};
    let attempt = || -> std::io::Result<bool> {
        let mut stream = std::os::unix::net::UnixStream::connect(path)?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
        stream
            .write_all(b"GET /v1/health HTTP/1.1\r\nHost: kixdns\r\nConnection: close\r\n\r\n")?;
        let mut head = [0u8; 12];
        stream.read_exact(&mut head)?;
        Ok(head.starts_with(b"HTTP/1.1 200"))
    };
    attempt().unwrap_or(false)
}

/// 经控制通道 `control` 发一个请求，读完整个回答，返回状态码和 JSON 正文。`head` 是另加的请求头（每行以 `\r\n` 结尾）
/// Sends one request over the control socket `control` and reads the whole answer, returning its
/// status and JSON body. `head` holds the extra request headers, each line ending in `\r\n`
#[cfg(unix)]
pub fn control_request(
    control: &Path,
    method: &str,
    path: &str,
    head: &str,
    body: &[u8],
) -> (u16, serde_json::Value) {
    use std::io::{Read, Write};
    let mut stream = std::os::unix::net::UnixStream::connect(control).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    let request =
        format!("{method} {path} HTTP/1.1\r\nHost: kixdns\r\nConnection: close\r\n{head}\r\n");
    stream.write_all(request.as_bytes()).unwrap();
    // 正文太大时，服务端读到上限就回答、关掉连接，后面写不进去不算错
    // With a body too large the server answers and closes once it reaches the limit, so
    // a write failing after that is no error
    let _ = stream.write_all(body);
    let mut answer = Vec::new();
    let _ = stream.read_to_end(&mut answer);
    let text = String::from_utf8_lossy(&answer);
    let (head, body) = text.split_once("\r\n\r\n").expect("a whole answer");
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .expect("a status line");
    (status, serde_json::from_str(body).expect("a JSON body"))
}

/// 经控制通道发一个 GET，读完整个回答 / Sends one GET over the control socket and reads the whole answer
#[cfg(unix)]
pub fn control_get(control: &Path, path: &str) -> (u16, serde_json::Value) {
    control_request(control, "GET", path, "", b"")
}

/// 在 `dir` 里写下 `config`，起一个读它、开着控制通道的内核，等控制通道应答；返回内核、配置文件和控制通道
/// Writes `config` in `dir`, starts a kernel reading it with its control socket, and waits for the
/// socket to answer; returns the kernel, the configuration file and the control socket
#[cfg(unix)]
pub fn start_with_control(
    dir: &Path,
    config: &serde_json::Value,
) -> (Kernel, std::path::PathBuf, std::path::PathBuf) {
    let control = dir.join("control.sock");
    let config_path = dir.join("config.json");
    std::fs::write(&config_path, config.to_string()).unwrap();
    let kernel = Kernel(
        Command::new(env!("CARGO_BIN_EXE_kixdns"))
            .args(["run", "--config"])
            .arg(&config_path)
            .arg("--admin-socket")
            .arg(&control)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    assert!(
        eventually(Duration::from_secs(20), || control_answers(&control)),
        "kernel did not start"
    );
    (kernel, config_path, control)
}
