//! A configuration with a problem (see `config::problems`) still starts, as it
//! did before, but a reload carrying one is refused.
//!
//! Runs the real binary on a configuration with a misspelt rcode, which used to
//! answer NXDOMAIN without a word. Startup logs the problem and answers as
//! before. A reload that keeps the problem is refused, so the running
//! configuration stays; once the problem is fixed the reload goes through.
//!
//! A background_refresh_rule, which never takes effect, is no problem: it only logs a
//! warn at startup and on each reload.
//!
//! 有问题的配置（见 `config::problems`）照旧能启动，但带着问题的重载会被拒绝。在一份 rcode 拼错的
//! 配置上跑真的程序（以前它不声不响地回 NXDOMAIN）：启动时记下问题、照旧应答；保留着问题的重载
//! 被拒绝，正在用的配置不变；问题改掉以后重载才生效。不会生效的 background_refresh_rule 不算问题，
//! 只在启动和每次重载时记一条 warn。

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
    write_config_with(path, port, ip, rcode, serde_json::json!({}));
}

/// [`write_config`] with the top-level fields of `extra` on top
fn write_config_with(path: &Path, port: u16, ip: &str, rcode: &str, extra: serde_json::Value) {
    let mut config = serde_json::json!({
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
    config
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
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

/// 起一个读 `config` 的内核，日志写进 `log`，等它开始应答
/// Start a kernel reading `config`, logging into `log`, and wait until it answers
fn start(config: &Path, log: &Path, port: u16) -> Kernel {
    let output = std::fs::File::create(log).unwrap();
    let kernel = Kernel(
        Command::new(env!("CARGO_BIN_EXE_kixdns"))
            .args(["run", "--config"])
            .arg(config)
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
    kernel
}

/// 旧配置里的 background_refresh_rule 不会生效，也不算问题：启动照常、重载照常，两次都记一条
/// warn 说它不会生效。规则本身写得对不对都一样（这里它跳去一个不存在的 pipeline）
/// A background_refresh_rule from an older configuration never takes effect and is no
/// problem: startup and reload go as usual, each logging a warn that it has no effect,
/// whether or not the rule itself is written right (here it jumps to a pipeline that
/// does not exist)
#[test]
fn a_background_refresh_rule_only_warns_at_startup_and_on_reload() {
    let dir = tempfile::TempDir::new().unwrap();
    let config = dir.path().join("config.json");
    let log = dir.path().join("kixdns.log");
    let port = free_port();
    let refresh_rule = serde_json::json!({
        "background_refresh_rule": {
            "name": "refresh",
            "matchers": [{ "type": "any" }],
            "actions": [{ "type": "jump_to_pipeline", "pipeline": "gone" }]
        }
    });
    write_config_with(&config, port, "192.0.2.1", "REFUSED", refresh_rule.clone());
    let _kernel = start(&config, &log, port);
    let warnings = || {
        std::fs::read_to_string(&log)
            .unwrap()
            .matches("background_refresh_rule has no effect")
            .count()
    };
    assert_eq!(warnings(), 1, "startup warns once");

    write_config_with(&config, port, "192.0.2.2", "REFUSED", refresh_rule);
    assert!(
        eventually(Duration::from_secs(10), || {
            static_ip(port) == Some(Ipv4Addr::new(192, 0, 2, 2))
        }),
        "the reload goes through"
    );
    assert!(
        eventually(Duration::from_secs(5), || warnings() == 2),
        "the reload warns once more"
    );
}

#[test]
fn a_problem_starts_as_before_and_refuses_a_reload() {
    let dir = tempfile::TempDir::new().unwrap();
    let config = dir.path().join("config.json");
    let log = dir.path().join("kixdns.log");
    let port = free_port();
    write_config(&config, port, "192.0.2.1", "WHATEVER");
    let _kernel = start(&config, &log, port);
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
