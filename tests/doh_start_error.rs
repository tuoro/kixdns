//! 入站 DoH 起不来时 DNS 照常答，控制通道 `config` 结果的 `doh_error` 写着原因；没配 DoH 时它是 null。
//!
//! 在真程序上跑：配了 bind_doh，证书或私钥的文件却不存在。DNS 照常应答，`doh_error` 说读不了的是证书还是私钥、哪个文件，
//! 带着原因链；不配 DoH 时 `doh_error` 在，是 null。
//!
//! The inbound DoH failing to start leaves DNS answering, and `doh_error` in the control
//! channel's `config` result gives the reason; with no DoH configured it is null.
//!
//! Runs the real binary with bind_doh configured and the certificate or the key file missing.
//! DNS answers as usual, and `doh_error` says whether the certificate or the key could not be
//! read and which file, with its cause chain; without DoH configured `doh_error` is there and
//! null.
#![cfg(unix)]

use std::net::Ipv4Addr;
use std::time::Duration;

mod common;
use common::{ask, control_get, eventually, first_a, free_port, start_with_control};

/// ok.test 的应答 / The answer to ok.test
const ANSWER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

/// 在空端口上答 ok.test 的配置，`settings` 另加进全局设置；返回配置和 DNS 端口
/// A configuration answering ok.test on a free port, with `settings` added to the global
/// settings; returns the configuration and the DNS port
fn config_with(settings: serde_json::Value) -> (serde_json::Value, u16) {
    let port = free_port();
    let mut config = serde_json::json!({
        "settings": {
            "bind_udp": format!("127.0.0.1:{port}"),
            "bind_tcp": format!("127.0.0.1:{port}"),
            "default_upstream": "127.0.0.1:9",
        },
        "pipelines": [{
            "id": "main",
            "rules": [{
                "name": "ok",
                "matchers": [{ "type": "domain_suffix", "value": "ok.test" }],
                "actions": [{ "type": "static_ip_response", "ip": ANSWER.to_string() }],
            }],
        }],
    });
    config["settings"]
        .as_object_mut()
        .unwrap()
        .extend(settings.as_object().unwrap().clone());
    (config, port)
}

/// 起一个跑 `config` 的内核，等它经 UDP 答上 ok.test，给出控制通道 `config` 结果里的 `doh_error`；结果里没有这个字段时
/// 测试失败
/// Starts a kernel running `config`, waits for it to answer ok.test over UDP, and gives
/// `doh_error` from the control channel's `config` result, failing the test when the result
/// has no such field
fn doh_error_of(config: &serde_json::Value, port: u16) -> serde_json::Value {
    let dir = tempfile::TempDir::new().unwrap();
    let (_kernel, _, control) = start_with_control(dir.path(), config);
    assert!(
        eventually(Duration::from_secs(10), || {
            ask(port, "ok.test").as_ref().and_then(first_a) == Some(ANSWER)
        }),
        "DNS does not answer"
    );
    let (status, active) = control_get(&control, "/v1/config/active");
    assert_eq!(status, 200, "{active}");
    active
        .get("doh_error")
        .unwrap_or_else(|| panic!("no doh_error: {active}"))
        .clone()
}

/// 证书和私钥都不存在时说证书，证书在、私钥不存在时说私钥：DNS 照常答，`doh_error` 写着读不了的文件和系统给的原因
/// With the certificate and the key both missing it is the certificate, and with the
/// certificate there and the key missing the key: DNS answers as usual, and `doh_error` names
/// the file that cannot be read, with the reason the system gives
#[test]
fn dns_answers_and_doh_error_says_which_file_cannot_be_read() {
    for certificate_there in [false, true] {
        let dir = tempfile::TempDir::new().unwrap();
        let (cert, key) = (dir.path().join("cert.pem"), dir.path().join("key.pem"));
        if certificate_there {
            let pair = rcgen::KeyPair::generate().unwrap();
            let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
            std::fs::write(&cert, params.self_signed(&pair).unwrap().pem()).unwrap();
        }
        let (config, port) = config_with(serde_json::json!({
            "bind_doh": format!("127.0.0.1:{}", free_port()),
            "doh_tls_cert": cert,
            "doh_tls_key": key,
        }));
        let doh_error = doh_error_of(&config, port);
        let reason = doh_error
            .as_str()
            .unwrap_or_else(|| panic!("doh_error is not a reason: {doh_error}"));
        let prefix = if certificate_there {
            format!("read DoH private key {}: ", key.display())
        } else {
            format!("read DoH certificate {}: ", cert.display())
        };
        assert!(
            reason.starts_with(&prefix) && reason.len() > prefix.len(),
            "{reason}"
        );
    }
}

/// 没配 DoH：`doh_error` 是 null / Without DoH configured `doh_error` is null
#[test]
fn doh_error_is_null_without_doh() {
    let (config, port) = config_with(serde_json::json!({}));
    assert_eq!(doh_error_of(&config, port), serde_json::Value::Null);
}
