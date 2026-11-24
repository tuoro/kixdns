//! The control socket's answers to request bodies it refuses or cannot use: too
//! large, unreadable, not UTF-8 or not the JSON asked for, a configuration that
//! fails to validate, every problem of one listed; and its answer to one that passes.
//!
//! Runs the real binary with its control socket and checks each answer's status,
//! error code and message word for word.
//!
//! 控制通道对拒收或用不了的请求正文的回答：太大、读不出来、不是 UTF-8 或不是要的 JSON、校验不过的配置（有问题的一条
//! 不落地列出来）；以及对校验通过的配置的回答。在真的程序上开控制通道，逐个核对回答的状态码、错误码和说明。
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
    request(control, "POST", path, head, body)
}

/// 发一个 GET，读完整个回答 / Send one GET and read the whole answer
fn get(control: &Path, path: &str) -> (u16, serde_json::Value) {
    request(control, "GET", path, "", b"")
}

fn request(
    control: &Path,
    method: &str,
    path: &str,
    head: &str,
    body: &[u8],
) -> (u16, serde_json::Value) {
    let mut stream = UnixStream::connect(control).unwrap();
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

/// 在本机的一个空端口上跑 `pipelines` 的配置 / A configuration running `pipelines` on a free local port
fn config_of(pipelines: serde_json::Value) -> serde_json::Value {
    let port = free_port();
    serde_json::json!({
        "settings": {
            "bind_udp": format!("127.0.0.1:{port}"),
            "bind_tcp": format!("127.0.0.1:{port}"),
            "default_upstream": "127.0.0.1:9",
        },
        "pipelines": pipelines,
    })
}

/// 在 `dir` 里写下 `config`，起一个读它、开着控制通道的内核，等控制通道应答；返回内核、配置文件和控制通道
/// Write `config` in `dir`, start a kernel reading it with its control socket, and wait for the
/// socket to answer; returns the kernel, the configuration file and the control socket
fn start(
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
    let started = Instant::now();
    while !control_answers(&control) {
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "kernel did not start"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    (kernel, config_path, control)
}

#[test]
fn the_control_socket_answers_bodies_it_cannot_use_in_its_own_words() {
    let dir = tempfile::TempDir::new().unwrap();
    let (_kernel, _, control) = start(
        dir.path(),
        &config_of(serde_json::json!([{ "id": "main", "rules": [] }])),
    );

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

    // 读不出来：chunked 正文的块长度写坏了。是请求本身坏了，回 400，不是 413；以前三个都回 413，诊断和试跑还说成太大
    // Unreadable: a chunked body with a broken chunk size. The request itself is broken, a 400
    // and no 413; all three used to answer 413, the diagnostic and the trial calling it too large
    for (path, expected) in [
        (
            "/v1/diagnostics/trace",
            ("diagnostic_body_invalid", "读取诊断请求失败"),
        ),
        (
            "/v1/diagnostics/trace-candidate",
            ("diagnostic_body_invalid", "读取试跑请求失败"),
        ),
        (
            "/v1/config/validate",
            ("config_body_invalid", "读取配置请求失败"),
        ),
    ] {
        let (status, body) = post(&control, path, "Transfer-Encoding: chunked\r\n", b"zz\r\n");
        assert_eq!(status, 400, "{path}: {body}");
        assert_eq!(error(&body), expected, "{path}");
    }

    // 不是 UTF-8 的配置：400，以前当成空串去校验，回一份空配置的解析错误
    // A configuration that is not UTF-8: 400; it used to be validated as an empty string,
    // answered with the parse error of an empty configuration
    let (status, body) = sized(&control, "/v1/config/validate", b"{\xff}");
    assert_eq!(status, 400, "{body}");
    assert_eq!(error(&body), ("config_body_invalid", "配置不是 UTF-8 文本"));

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
        serde_json::json!({
            "protocol_version": 1,
            "valid": true,
            "pipeline_count": 1,
            "rule_count": 1,
            "warnings": []
        })
    );
}

/// 一份有 30 条问题的配置：校验的 422 回答和重载失败以后 `config` 结果的 `last_reload` 都把 30 条一条不落地放进
/// `problems`，每条完整；`message` 和 `last_reload.error` 还是连起来的一句，截到 2048 个字符。以前只有那一句，
/// 30 条只看得到 14 条，最后一条截在半句
/// A configuration with 30 problems: the validation's 422 answer and, after the reload fails,
/// the `config` result's `last_reload` both hold all 30 in `problems`, each whole; `message` and
/// `last_reload.error` are still the one sentence joining them, cut to 2048 characters. There
/// used to be that sentence alone, which showed 14 of the 30, the last cut off midway
#[test]
fn a_refused_configuration_lists_every_problem() {
    let dir = tempfile::TempDir::new().unwrap();
    let main =
        |rules: Vec<serde_json::Value>| serde_json::json!([{ "id": "main", "rules": rules }]);
    let mut config = config_of(main(vec![]));
    let (_kernel, config_path, control) = start(dir.path(), &config);
    let rules = (0..30)
        .map(|n| {
            serde_json::json!({
                "name": format!("r{n}"),
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "static_response", "rcode": format!("WHATEVER{n}") }],
            })
        })
        .collect();
    config["pipelines"] = main(rules);
    let expected =
        kixdns::config::problems(&kixdns::config::parse_config(&config.to_string()).unwrap());
    assert_eq!(expected.len(), 30, "{expected:#?}");
    let every_problem = serde_json::json!(expected);

    let (status, body) = sized(
        &control,
        "/v1/config/validate",
        config.to_string().as_bytes(),
    );
    assert_eq!(status, 422, "{body}");
    let (code, message) = error(&body);
    assert_eq!(code, "config_invalid");
    assert_eq!(message.chars().count(), 2048, "{message}");
    assert_eq!(body["error"]["problems"], every_problem);

    let staged = config_path.with_extension("staged");
    std::fs::write(&staged, config.to_string()).unwrap();
    std::fs::rename(&staged, &config_path).unwrap();
    let started = Instant::now();
    let active = loop {
        let (status, active) = get(&control, "/v1/config/active");
        assert_eq!(status, 200, "{active}");
        if active["reload_sequence"] != 0 {
            break active;
        }
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "the reload did not come: {active}"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    let reload = &active["last_reload"];
    assert_eq!(reload["success"], false, "{active}");
    assert_eq!(
        reload["error"].as_str().unwrap().chars().count(),
        2048,
        "{active}"
    );
    assert_eq!(reload["problems"], every_problem);
}

/// `config` 结果说出起不来的和没有数据的：入站 DoH 的证书读不了时 `doh_error` 写着原因，DNS 照常答；配置的 GeoSite
/// 数据文件不存在时 `data_warnings` 说它不存在，规则用到的标签也就没有数据。写成空的 geo_site_not 算一条问题，不在
/// 那些标签里列一个空名字（以前写成「GeoSite tags , cn」）
/// The `config` result says what cannot start and what has no data: with the inbound DoH's
/// certificate unreadable `doh_error` gives the reason, DNS answering as usual; with a configured
/// GeoSite data file missing `data_warnings` says it is not there, and that the tags rules use so
/// have no data. A geo_site_not written empty is a problem and lists no empty name among those
/// tags (it used to say "GeoSite tags , cn")
#[test]
fn the_config_result_says_why_doh_is_off_and_which_geo_data_is_missing() {
    let dir = tempfile::TempDir::new().unwrap();
    let geosite = dir.path().join("geosite.dat");
    let rule = |name: &str, kind: &str, value: &str| {
        serde_json::json!({
            "name": name,
            "matchers": [{ "type": kind, "value": value }],
            "actions": [{ "type": "allow" }],
        })
    };
    let mut config = config_of(serde_json::json!([{ "id": "main", "rules": [
        rule("cn", "geo_site", "cn"),
        rule("empty", "geo_site_not", ""),
    ] }]));
    let settings = config["settings"].as_object_mut().unwrap();
    for (setting, value) in [
        (
            "bind_doh",
            serde_json::json!(format!("127.0.0.1:{}", free_port())),
        ),
        (
            "doh_tls_cert",
            serde_json::json!(dir.path().join("cert.pem")),
        ),
        ("doh_tls_key", serde_json::json!(dir.path().join("key.pem"))),
        ("geosite_data_paths", serde_json::json!([geosite])),
    ] {
        settings.insert(setting.to_owned(), value);
    }
    let (_kernel, _, control) = start(dir.path(), &config);
    let (status, active) = get(&control, "/v1/config/active");
    assert_eq!(status, 200, "{active}");
    let doh_error = active["doh_error"]
        .as_str()
        .unwrap_or_else(|| panic!("{active}"));
    assert!(doh_error.contains("cert"), "{doh_error}");
    assert_eq!(
        active["data_warnings"],
        serde_json::json!([
            format!("GeoSite data file {} does not exist", geosite.display()),
            "GeoSite tags cn are in no data file: geo_site never matches them and geo_site_not always does",
        ]),
        "{active}"
    );
    assert_eq!(
        active["problems"],
        serde_json::json!([
            "pipelines[0].rules[1].matchers[0]: geo_site_not \"\" matches every name"
        ]),
        "{active}"
    );
}
