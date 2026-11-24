//! A configuration that stops the kernel from starting is told in one log record.
//!
//! Runs the real binary with its output going to a file, as procd writes it on OpenWrt:
//! neither a terminal nor journald. The fatal error takes one line alone as an event does,
//! the UTC time first and ERROR the second word, so the panel reading the file shows why the
//! kernel did not start under its error filter.
//!
//! 让内核起不来的配置写成一条日志。像 OpenWrt 上 procd 那样把输出写进文件（既不是终端也不是 journald）跑真程序：
//! 致命错误和事件一样只占一行，UTC 时间开头、第二个词是 ERROR，面板读这个文件时只看 error 也看得到内核为什么没起来。

use std::net::{Ipv4Addr, UdpSocket};
use std::path::Path;
use std::time::{Duration, Instant};

mod common;
use common::{free_port, run_logging};

/// 跑一个读 `config` 的内核，日志写进 `log`，等它起不来、以 1 退出，交回它记下的日志
/// Runs a kernel reading `config` and logging into `log` until it fails to start, exiting with 1,
/// and hands back what it logged
fn run_to_the_end(config: &Path, log: &Path) -> String {
    let mut kernel = run_logging(config, log, None);
    let start = Instant::now();
    let status = loop {
        if let Some(status) = kernel.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "kernel did not exit"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(status.code(), Some(1));
    std::fs::read_to_string(log).unwrap()
}

/// 正则写错的错误说明有好几行，照样只占一行，里面的换行写成 `\n`。以前写成 `Error: {err:?}`，这份配置是 7 行，
/// 没有时间也没有级别
/// The error for a regex written wrong runs over several lines and still takes one, the line
/// breaks within written `\n`. It used to be `Error: {err:?}`, seven lines for this
/// configuration with neither time nor level
#[test]
fn a_fatal_error_in_a_log_file_is_one_line_with_time_and_level() {
    let dir = tempfile::TempDir::new().unwrap();
    let config = dir.path().join("config.json");
    let log = dir.path().join("kixdns.log");
    let port = free_port();
    std::fs::write(
        &config,
        serde_json::json!({
            "settings": {
                "bind_udp": format!("127.0.0.1:{port}"),
                "bind_tcp": format!("127.0.0.1:{port}"),
                "default_upstream": "127.0.0.1:9",
            },
            "pipelines": [{
                "id": "main",
                "rules": [{
                    "name": "broken",
                    "matchers": [{ "type": "domain_regex", "value": "(" }],
                    "actions": [{ "type": "allow" }],
                }],
            }],
        })
        .to_string(),
    )
    .unwrap();
    let logged = run_to_the_end(&config, &log);
    let lines = logged.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 1, "{logged}");
    let mut words = lines[0].split_whitespace();
    let time = words.next().unwrap_or_default();
    assert!(
        time.len() >= 20 && time.as_bytes()[4] == b'-' && time.ends_with('Z'),
        "{logged}"
    );
    assert_eq!(words.next(), Some("ERROR"), "{logged}");
    assert_eq!(words.next(), Some("fatal:"), "{logged}");
    assert!(
        lines[0].ends_with("regex parse error:\\n    (\\n    ^\\nerror: unclosed group"),
        "{logged}"
    );
}

/// 配置里有问题（见 `config::problems`）、又有让内核起不来的正则时，只记那一条致命错误，问题在前、和正则一起列在里面，
/// 和重载被拒时列出的一字不差；没有哪一行说问题「照样加载」，内核并没有起来
/// A configuration with a problem (see `config::problems`) and a regex that stops the kernel
/// logs that one fatal error alone, listing the problem first and the regex with it, word for
/// word as a refused reload does; no line says the problem was loaded all the same, the kernel
/// not having started
#[test]
fn a_fatal_error_lists_the_problems_as_a_reload_does() {
    let dir = tempfile::TempDir::new().unwrap();
    let config = dir.path().join("config.json");
    let log = dir.path().join("kixdns.log");
    let port = free_port();
    let raw = serde_json::json!({
        "settings": {
            "bind_udp": format!("127.0.0.1:{port}"),
            "bind_tcp": format!("127.0.0.1:{port}"),
            "default_upstream": "127.0.0.1:9",
        },
        "pipelines": [{
            "id": "main",
            "rules": [{
                "name": "broken",
                "matchers": [{ "type": "domain_regex", "value": "(" }],
                "actions": [{ "type": "static_response", "rcode": "WHATEVER" }],
            }],
        }],
    })
    .to_string();
    std::fs::write(&config, &raw).unwrap();
    // 重载拒掉它时列出的：拼错的 rcode 在前，正则在后 / What a reload refusing it lists: the
    // misspelt rcode first, the regex after
    let refused =
        kixdns::config::compile(kixdns::config::parse_config(&raw).unwrap()).expect_err("refused");
    let reasons = kixdns::config::Problems::of(&refused);
    assert_eq!(reasons.len(), 2, "{reasons:#?}");
    assert!(reasons[0].contains("WHATEVER"), "{reasons:#?}");

    let logged = run_to_the_end(&config, &log);
    let lines = logged.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 1, "{logged}");
    let fatal = format!(" ERROR fatal: {refused:#}").replace('\n', "\\n");
    assert!(lines[0].ends_with(&fatal), "{logged}");
}

/// 配置里有问题、UDP 端口又被占着时，只记绑不上的那条致命错误：内核没起来，没有哪一行说问题「照样加载」
/// A configuration with a problem whose UDP port is taken logs the fatal error of the bind
/// alone: the kernel not having started, no line says the problem was loaded all the same
#[test]
fn a_taken_port_logs_the_bind_alone_not_a_problem_loaded() {
    let dir = tempfile::TempDir::new().unwrap();
    let config = dir.path().join("config.json");
    let log = dir.path().join("kixdns.log");
    let port = free_port();
    let _held = UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
    // 内核绑这个端口时得到的错误 / The error the kernel gets binding this port
    let taken = UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).unwrap_err();
    std::fs::write(
        &config,
        serde_json::json!({
            "settings": {
                "bind_udp": format!("127.0.0.1:{port}"),
                "bind_tcp": format!("127.0.0.1:{port}"),
                "default_upstream": "127.0.0.1:9",
            },
            "pipelines": [{
                "id": "main",
                "rules": [{
                    "name": "misspelt",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "static_response", "rcode": "WHATEVER" }],
                }],
            }],
        })
        .to_string(),
    )
    .unwrap();
    let logged = run_to_the_end(&config, &log);
    let lines = logged.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 1, "{logged}");
    assert!(lines[0].contains(" ERROR fatal: bind "), "{logged}");
    assert!(lines[0].ends_with(&taken.to_string()), "{logged}");
}
