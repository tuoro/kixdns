//! A configuration with a problem (see `config::problems`) still starts, as it
//! did before, but a reload carrying one is refused.
//!
//! Runs the real binary on a configuration with a misspelt rcode, which used to
//! answer NXDOMAIN without a word. Startup logs the problem and answers as
//! before. A reload that keeps the problem is refused, so the running
//! configuration stays; once the problem is fixed the reload goes through.
//!
//! 有问题的配置（见 `config::problems`）照旧能启动，但带着问题的重载会被拒绝。在一份 rcode 拼错的
//! 配置上跑真的程序（以前它不声不响地回 NXDOMAIN）：启动时记下问题、照旧应答；保留着问题的重载
//! 被拒绝，正在用的配置不变；问题改掉以后重载才生效。

use std::net::{Ipv4Addr, UdpSocket};
use std::path::Path;
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};

mod common;
use common::{Kernel, free_port};

/// The reply to an A query for `name`, if one comes
fn ask(port: u16, name: &str) -> Option<Message> {
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

fn static_ip(port: u16) -> Option<Ipv4Addr> {
    ask(port, "ok.test")?
        .answers
        .iter()
        .find_map(|r| match &r.data {
            RData::A(a) => Some(a.0),
            _ => None,
        })
}

/// A configuration answering ok.test with `ip` and old.test with `rcode`
fn write_config(path: &Path, port: u16, ip: &str, rcode: &str) {
    let config = serde_json::json!({
        "settings": {
            "bind_udp": format!("127.0.0.1:{port}"),
            "bind_tcp": format!("127.0.0.1:{port}"),
            "default_upstream": "127.0.0.1:9",
        },
        "pipelines": [{
            "id": "main",
            "rules": [
                {
                    "name": "ok",
                    "matchers": [{ "type": "domain_suffix", "value": "ok.test" }],
                    "actions": [{ "type": "static_ip_response", "ip": ip }],
                },
                {
                    "name": "old",
                    "matchers": [{ "type": "domain_suffix", "value": "old.test" }],
                    "actions": [{ "type": "static_response", "rcode": rcode }],
                },
            ],
        }],
    });
    // Replace it atomically, as the panel does / 和面板一样原子替换
    let staged = path.with_extension("staged");
    std::fs::write(&staged, config.to_string()).unwrap();
    std::fs::rename(&staged, path).unwrap();
}

fn eventually(limit: Duration, mut check: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < limit {
        if check() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

#[test]
fn a_problem_starts_as_before_and_refuses_a_reload() {
    let dir = tempfile::TempDir::new().unwrap();
    let config = dir.path().join("config.json");
    let log = dir.path().join("kixdns.log");
    let port = free_port();
    write_config(&config, port, "192.0.2.1", "WHATEVER");

    let output = std::fs::File::create(&log).unwrap();
    let _kernel = Kernel(
        Command::new(env!("CARGO_BIN_EXE_kixdns"))
            .args(["run", "--config"])
            .arg(&config)
            .env("RUST_LOG", "info")
            .stdout(output.try_clone().unwrap())
            .stderr(output)
            .stdin(Stdio::null())
            .spawn()
            .unwrap(),
    );
    assert!(
        eventually(Duration::from_secs(20), || static_ip(port).is_some()),
        "kernel did not start"
    );
    let logged = |needle: &str| std::fs::read_to_string(&log).unwrap().contains(needle);

    // 启动照旧：记下问题，拼错的 rcode 还是回 NXDOMAIN
    // Startup as before: the problem is logged and the misspelt rcode still answers NXDOMAIN
    assert!(logged("WHATEVER"), "startup names the problem");
    assert_eq!(
        ask(port, "old.test").map(|reply| reply.metadata.response_code),
        Some(ResponseCode::NXDomain)
    );

    // 保留着问题的重载被拒绝，正在用的配置不变
    // A reload keeping the problem is refused and the running configuration stays
    write_config(&config, port, "192.0.2.2", "WHATEVER");
    assert!(
        eventually(Duration::from_secs(10), || logged("reload failed")),
        "the reload is refused"
    );
    assert_eq!(static_ip(port), Some(Ipv4Addr::new(192, 0, 2, 1)));

    // 问题改掉以后重载生效 / Once the problem is fixed the reload goes through
    write_config(&config, port, "192.0.2.3", "REFUSED");
    assert!(
        eventually(Duration::from_secs(10), || {
            static_ip(port) == Some(Ipv4Addr::new(192, 0, 2, 3))
        }),
        "the fixed configuration loads"
    );
    assert_eq!(
        ask(port, "old.test").map(|reply| reply.metadata.response_code),
        Some(ResponseCode::Refused)
    );
}
