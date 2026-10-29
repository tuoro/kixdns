//! The control socket's answers to request bodies it refuses or cannot use: too
//! large, unreadable, not the JSON asked for, a configuration that fails to
//! validate; and its answer to one that passes.
//!
//! Runs the real binary with its control socket and checks each answer's status,
//! error code and message word for word.
//!
//! 控制通道对拒收或用不了的请求正文的回答：太大、读不出来、不是要的 JSON、校验不过的配置；以及对
//! 校验通过的配置的回答。在真的程序上开控制通道，逐个核对回答的状态码、错误码和说明。
#![cfg(unix)]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

mod common;
use common::{Kernel, control_answers, free_port};

/// 发一个 POST，读完整个回答，返回状态码和 JSON 正文。`head` 是另加的请求头（每行以 `\r\n` 结尾）
/// Send one POST and read the whole answer, returning its status and JSON body. `head`
/// holds the extra request headers, each line ending in `\r\n`
fn post(control: &Path, path: &str, head: &str, body: &[u8]) -> (u16, serde_json::Value) {
    let mut stream = UnixStream::connect(control).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    let request =
        format!("POST {path} HTTP/1.1\r\nHost: kixdns\r\nConnection: close\r\n{head}\r\n");
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

/// 带 Content-Length 的正文 / A body with its Content-Length
fn sized(control: &Path, path: &str, body: &[u8]) -> (u16, serde_json::Value) {
    post(
        control,
        path,
        &format!(
            "Content-Length: {}\r\nContent-Type: application/json\r\n",
            body.len()
        ),
        body,
    )
}

/// 回答里的错误码和说明 / An answer's error code and message
fn error(body: &serde_json::Value) -> (&str, &str) {
    (
        body["error"]["code"].as_str().expect("an error code"),
        body["error"]["message"].as_str().expect("an error message"),
    )
}

#[test]
fn the_control_socket_answers_bodies_it_cannot_use_in_its_own_words() {
    let dir = tempfile::TempDir::new().unwrap();
    let control = dir.path().join("control.sock");
    let port = free_port();
    let config = serde_json::json!({
        "settings": {
            "bind_udp": format!("127.0.0.1:{port}"),
            "bind_tcp": format!("127.0.0.1:{port}"),
            "default_upstream": "127.0.0.1:9",
        },
        "pipelines": [{ "id": "main", "rules": [] }],
    });
    let config_path = dir.path().join("config.json");
    std::fs::write(&config_path, config.to_string()).unwrap();
    let _kernel = Kernel(
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
    let started = Instant::now();
    while !control_answers(&control) {
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "kernel did not start"
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    // 太大：诊断上限 2 KiB，试跑和配置 4 MiB（试跑另加 4 KiB 给请求的其余字段）
    // Too large: 2 KiB for a diagnostic, 4 MiB for a trial and a configuration (a trial
    // has 4 KiB more for the request's other fields)
    for (path, size, expected) in [
        (
            "/v1/diagnostics/trace",
            2 * 1024 + 1,
            ("diagnostic_body_invalid", "诊断请求不能超过 2 KiB"),
        ),
        (
            "/v1/diagnostics/trace-candidate",
            4 * 1024 * 1024 + 4 * 1024 + 1,
            ("diagnostic_body_invalid", "试跑请求不能超过 4 MiB"),
        ),
        (
            "/v1/config/validate",
            4 * 1024 * 1024 + 1,
            ("config_body_invalid", "配置不能超过 4 MiB"),
        ),
    ] {
        let (status, body) = sized(&control, path, &vec![b' '; size]);
        assert_eq!(status, 413, "{path}: {body}");
        assert_eq!(error(&body), expected, "{path}");
        assert_eq!(body["protocol_version"], 1, "{path}");
    }

    // 读不出来：chunked 正文的块长度写坏了 / Unreadable: a chunked body with a broken chunk size
    for (path, expected) in [
        (
            "/v1/diagnostics/trace",
            ("diagnostic_body_invalid", "诊断请求不能超过 2 KiB"),
        ),
        (
            "/v1/diagnostics/trace-candidate",
            ("diagnostic_body_invalid", "试跑请求不能超过 4 MiB"),
        ),
        (
            "/v1/config/validate",
            ("config_body_invalid", "读取配置请求失败"),
        ),
    ] {
        let (status, body) = post(&control, path, "Transfer-Encoding: chunked\r\n", b"zz\r\n");
        assert_eq!(status, 413, "{path}: {body}");
        assert_eq!(error(&body), expected, "{path}");
    }

    // 不是要的 JSON / Not the JSON asked for
    for (path, prefix) in [
        ("/v1/diagnostics/trace", "诊断请求无效："),
        ("/v1/diagnostics/trace-candidate", "试跑请求无效："),
    ] {
        let (status, body) = sized(&control, path, b"{");
        assert_eq!(status, 400, "{path}: {body}");
        let (code, message) = error(&body);
        assert_eq!(code, "diagnostic_request_invalid", "{path}");
        assert!(
            message.starts_with(prefix) && message.len() > prefix.len(),
            "{path}: {message}"
        );
    }

    // 配置校验不过、校验通过 / A configuration that fails to validate, and one that passes
    let (status, body) = sized(
        &control,
        "/v1/config/validate",
        br#"{ "settings": { "default_upstream": "1.1.1.1:53" }, "pipelines": [{ "id": "main", "rules": [{ "name": "x", "matchers": [{ "type": "no_such_matcher" }], "actions": [] }] }] }"#,
    );
    assert_eq!(status, 422, "{body}");
    let (code, message) = error(&body);
    assert_eq!(code, "config_invalid");
    assert!(message.contains("no_such_matcher"), "{message}");
    let (status, body) = sized(
        &control,
        "/v1/config/validate",
        br#"{ "settings": { "default_upstream": "1.1.1.1:53" }, "pipelines": [{ "id": "main", "rules": [{ "name": "x", "matchers": [{ "type": "any" }], "actions": [{ "type": "allow" }] }] }] }"#,
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body,
        serde_json::json!({ "protocol_version": 1, "valid": true, "pipeline_count": 1, "rule_count": 1 })
    );
}
