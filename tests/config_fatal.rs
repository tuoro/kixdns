//! A configuration that stops the kernel from starting is told in one log record.
//!
//! Runs the real binary with its output going to a file, as procd writes it on OpenWrt:
//! neither a terminal nor journald. The fatal error takes one line alone as an event does,
//! the UTC time first and ERROR the second word, so the panel reading the file shows why the
//! kernel did not start under its error filter.
//!
//! 让内核起不来的配置写成一条日志。像 OpenWrt 上 procd 那样把输出写进文件（既不是终端也不是 journald）跑真程序：
//! 致命错误和事件一样只占一行，UTC 时间开头、第二个词是 ERROR，面板读这个文件时只看 error 也看得到内核为什么没起来。

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

mod common;
use common::{Kernel, free_port};

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
    let output = std::fs::File::create(&log).unwrap();
    let mut kernel = Kernel(
        Command::new(env!("CARGO_BIN_EXE_kixdns"))
            .args(["run", "--config"])
            .arg(&config)
            .env_remove("RUST_LOG")
            .env_remove("JOURNAL_STREAM")
            .stdout(output.try_clone().unwrap())
            .stderr(output)
            .stdin(Stdio::null())
            .spawn()
            .unwrap(),
    );
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

    let logged = std::fs::read_to_string(&log).unwrap();
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
