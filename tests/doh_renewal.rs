//! 入站 DoH 的证书续期一次只读一次：证书和私钥一起换，监视给两个文件各回调一次，读的只有头一次。
//!
//! 在真程序上跑：配了 bind_doh，日志级别 info。证书和私钥都换成新的一对（先写好再改名盖过去，像 certbot、acme.sh 的
//! deploy hook 那样），日志里只有一条 reloaded；两个都换成读不了的，只有一条 reload failed；私钥先到、证书隔一会儿才到，
//! 也只有一条 reloaded。
//!
//! A renewal of the inbound DoH certificate is read once: the certificate and the key are
//! replaced together, the watch calls back once for each file, and the first callback alone
//! reads them.
//!
//! Runs the real binary with bind_doh configured, logging at info. The certificate and the key
//! both replaced by a new pair (written aside and renamed over them, as the deploy hooks of
//! certbot and acme.sh do) log one "reloaded" alone; both replaced by unreadable ones, one
//! "reload failed" alone; the key first and the certificate a while later, one "reloaded" alone
//! too.
#![cfg(unix)]

use std::path::Path;
use std::time::Duration;

mod common;
use common::{eventually, free_port, run_logging};

/// 把 `contents` 先写到旁边，再改名盖过 `path` / Writes `contents` aside, then renames it over `path`
fn replace(path: &Path, contents: &str) {
    let aside = path.with_extension("new");
    std::fs::write(&aside, contents).unwrap();
    std::fs::rename(&aside, path).unwrap();
}

/// 一对新的自签证书和私钥（给 localhost）的 PEM / The PEM of a new self-signed certificate (for
/// localhost) and its key
fn certificate() -> (String, String) {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    (cert.pem(), key.serialize_pem())
}

/// 日志里有几行带着 `wanted` / How many lines of the log carry `wanted`
fn lines_with(log: &Path, wanted: &str) -> usize {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .filter(|line| line.contains(wanted))
        .count()
}

/// 换掉证书和私钥以后，等日志里有了 `wanted`，再等一会儿，给出它一共几行 / Once the certificate and
/// the key are replaced, waits for `wanted` in the log, then a while more, and gives how many
/// lines carry it
fn after_replacing(
    log: &Path,
    (cert, key): (&Path, &Path),
    (cert_pem, key_pem): (&str, &str),
    wanted: &str,
) -> usize {
    let before = lines_with(log, wanted);
    replace(cert, cert_pem);
    replace(key, key_pem);
    assert!(
        eventually(Duration::from_secs(10), || lines_with(log, wanted) > before),
        "{wanted}: {}",
        std::fs::read_to_string(log).unwrap_or_default()
    );
    std::thread::sleep(Duration::from_millis(1500));
    lines_with(log, wanted) - before
}

/// 续期一次，日志里一条 reloaded；换成读不了的，一条 reload failed。以前两个文件各读一遍，各记一条
/// One renewal logs one "reloaded"; replaced by unreadable files, one "reload failed". Each
/// file used to be read on its own, each logging a line
#[test]
fn a_renewal_reads_the_certificate_once() {
    let dir = tempfile::TempDir::new().unwrap();
    let (cert, key) = (dir.path().join("cert.pem"), dir.path().join("key.pem"));
    let (cert_pem, key_pem) = certificate();
    std::fs::write(&cert, cert_pem).unwrap();
    std::fs::write(&key, key_pem).unwrap();
    let port = free_port();
    let config = serde_json::json!({
        "settings": {
            "bind_udp": format!("127.0.0.1:{port}"),
            "bind_tcp": format!("127.0.0.1:{port}"),
            "bind_doh": format!("127.0.0.1:{}", free_port()),
            "doh_tls_cert": cert,
            "doh_tls_key": key,
            "default_upstream": "127.0.0.1:9",
        },
        "pipelines": [],
    });
    let (path, log) = (
        dir.path().join("config.json"),
        dir.path().join("kixdns.log"),
    );
    std::fs::write(&path, config.to_string()).unwrap();
    let _kernel = run_logging(&path, &log, Some("info"));
    assert!(
        eventually(Duration::from_secs(10), || {
            std::fs::read_to_string(&log)
                .unwrap_or_default()
                .lines()
                .any(|line| line.contains("doh-cert-watcher") && line.contains("started"))
        }),
        "the certificate is not watched: {}",
        std::fs::read_to_string(&log).unwrap_or_default()
    );
    let files = (cert.as_path(), key.as_path());

    let (cert_pem, key_pem) = certificate();
    let reloaded = after_replacing(
        &log,
        files,
        (&cert_pem, &key_pem),
        "DoH TLS certificate reloaded",
    );
    assert_eq!(reloaded, 1, "{}", std::fs::read_to_string(&log).unwrap());
    let failed = after_replacing(
        &log,
        files,
        ("not a certificate", "not a key"),
        "DoH TLS certificate reload failed",
    );
    assert_eq!(failed, 1, "{}", std::fs::read_to_string(&log).unwrap());

    // 私钥先到、隔 0.5 秒证书才到（比别的平台等写入停下的 0.3 秒还久，哪儿都是两阵），只有一条 reloaded，没有 reload
    // failed / The key first and the certificate 0.5 s later (longer than the 0.3 s other platforms
    // wait for writing to stop, two bursts anywhere): one "reloaded" alone, no "reload failed"
    let (reloaded, failed) = (
        lines_with(&log, "DoH TLS certificate reloaded"),
        lines_with(&log, "DoH TLS certificate reload failed"),
    );
    let (cert_pem, key_pem) = certificate();
    replace(&key, &key_pem);
    std::thread::sleep(Duration::from_millis(500));
    replace(&cert, &cert_pem);
    assert!(
        eventually(Duration::from_secs(10), || {
            lines_with(&log, "DoH TLS certificate reloaded") > reloaded
        }),
        "{}",
        std::fs::read_to_string(&log).unwrap_or_default()
    );
    std::thread::sleep(Duration::from_millis(1500));
    let log_text = std::fs::read_to_string(&log).unwrap();
    assert_eq!(
        lines_with(&log, "DoH TLS certificate reloaded") - reloaded,
        1,
        "{log_text}"
    );
    assert_eq!(
        lines_with(&log, "DoH TLS certificate reload failed") - failed,
        0,
        "{log_text}"
    );
}
