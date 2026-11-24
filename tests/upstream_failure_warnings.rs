//! 上游失败的 warn 按上游分开限频：一个一直坏着的上游挡不住别的上游的失败。一次失败记一条，写着问的是哪个名字、哪个上游、
//! 为什么失败。
//!
//! 在真程序上跑，日志级别 warn：规则 a、b 各经 TCP 转发到本机一个没人听的端口，规则 ab 把这两个上游一起问。a 连着失败两次，
//! 第二次在 10 秒之内，只数不记；紧接着 b 失败，照样记上一条，带着它自己的原因；ab 失败也记一条，两个上游各自的原因都在里面。
//! 以前限频按调用点算，a 失败以后 10 秒内 b 的失败一行都不出。那时一次失败要记好几行（传输层每个失败的上游一行，调用方
//! 再记一行）；后来改成一次失败只记调用方那一条，几个上游一起问时原因里写明每个上游和它为什么失败，这里按现在的写法查。
//!
//! Upstream failure warnings are throttled per upstream: one upstream that stays down keeps no
//! other's failures from showing. Each failure logs one line, naming the query, the upstream and
//! why it failed.
//!
//! Runs the real binary at the warn level: rules a and b each forward over TCP to a local port
//! nobody listens on, and rule ab asks both of those upstreams together. a fails twice in a row,
//! the second time within 10 seconds, which is counted and not logged; b failing right after
//! still logs its line, with its own reason; ab failing logs one too, holding each upstream's
//! own reason. The throttle used to go by call site, so for 10 seconds after a failed not a line
//! of b's failures showed. A failure then took several lines (one from the transport for each
//! upstream failing, one more from the caller); since then a failure logs the caller's line
//! alone, its reason naming each upstream asked together and why it failed, and that is what
//! is checked here.

use std::time::Duration;

use hickory_proto::op::ResponseCode;

mod common;
use common::{ask, eventually, first_a, free_port, run_logging};

/// `line` 是不是 `upstream` 在问 `qname` 时失败的那条 warn：限频没有挡过它，原因说的是这个上游
/// Whether `line` is the warning of `upstream` failing as `qname` was asked: no throttling held
/// one back before it, and the reason is about this upstream
fn is_the_failure_of(line: &str, qname: &str, upstream: &str) -> bool {
    let reason = line.split_once(" error=").map_or("", |(_, reason)| reason);
    line.contains(r#"event="upstream_failure""#)
        && line.contains(" skipped=0 ")
        && line.contains(&format!(" upstream={upstream} "))
        && line.contains(&format!(" qname={qname} "))
        && reason.starts_with("the upstream failed: ")
        && reason.contains(upstream)
}

#[test]
fn each_upstream_failure_shows_and_none_hides_another() {
    let dir = tempfile::TempDir::new().unwrap();
    let port = free_port();
    // 没人听的端口：连上去当场被拒 / Ports nobody listens on, a connection refused at once
    let (a, b) = (
        format!("127.0.0.1:{}", free_port()),
        format!("127.0.0.1:{}", free_port()),
    );
    let forward = |name: &str, upstream: &str| {
        serde_json::json!({
            "name": name,
            "matchers": [{ "type": "domain_suffix", "value": format!("{name}.test") }],
            "actions": [{ "type": "forward", "upstream": upstream, "transport": "tcp" }],
        })
    };
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
                    "actions": [{ "type": "static_ip_response", "ip": "192.0.2.1" }],
                },
                forward("a", &a),
                forward("b", &b),
                forward("ab", &format!("{a},{b}")),
            ],
        }],
    });
    let config_path = dir.path().join("config.json");
    std::fs::write(&config_path, config.to_string()).unwrap();
    let log = dir.path().join("kixdns.log");
    let _kernel = run_logging(&config_path, &log, Some("warn"));
    assert!(
        eventually(Duration::from_secs(20), || {
            ask(port, "ok.test").as_ref().and_then(first_a).is_some()
        }),
        "kernel did not start"
    );

    for name in ["one.a.test", "two.a.test", "one.b.test", "one.ab.test"] {
        assert_eq!(
            ask(port, name).map(|reply| reply.metadata.response_code),
            Some(ResponseCode::ServFail),
            "{name}"
        );
    }
    // 三个规则的失败各有一条（日志写下来要一点时间）。一次失败要是多记了几行，都记在调用方那一条之前，这时也都写下了
    // A line for each rule's failure (the log takes a moment to be written). Any more lines a
    // failure logged come before the caller's, so by now they are written too
    let warnings = || -> Vec<String> {
        std::fs::read_to_string(&log)
            .unwrap()
            .lines()
            .filter(|line| line.contains(" WARN "))
            .map(str::to_owned)
            .collect()
    };
    let both = format!(" upstream={a},{b} ");
    let upstreams = [
        format!(" upstream={a} "),
        format!(" upstream={b} "),
        both.clone(),
    ];
    assert!(
        eventually(Duration::from_secs(5), || {
            let warnings = warnings();
            upstreams
                .iter()
                .all(|upstream| warnings.iter().any(|line| line.contains(upstream)))
        }),
        "not every upstream's failure is logged: {:#?}",
        warnings()
    );
    let warnings = warnings();
    let about = |this: &str, not: &str| -> Vec<&String> {
        warnings
            .iter()
            .filter(|line| line.contains(this) && !line.contains(not))
            .collect()
    };

    // a 两次失败只记第一次那一条，第二次在 10 秒之内，只数不记
    // Of a's two failures only the first logs, its one line; the second, within 10 seconds, is
    // counted and not logged
    let of_a = about(&a, &b);
    assert_eq!(of_a.len(), 1, "{warnings:#?}");
    assert!(is_the_failure_of(of_a[0], "one.a.test", &a), "{}", of_a[0]);

    // b 紧接着失败，照样记上一条：a 挡不住它 / b failing right after still logs its line: a does
    // not keep it from showing
    let of_b = about(&b, &a);
    assert_eq!(of_b.len(), 1, "{warnings:#?}");
    assert!(is_the_failure_of(of_b[0], "one.b.test", &b), "{}", of_b[0]);

    // ab：一条，两个上游各自的原因都在 / ab: one line, holding each upstream's own reason
    let of_ab: Vec<&String> = warnings
        .iter()
        .filter(|line| line.contains(&a) && line.contains(&b))
        .collect();
    assert_eq!(of_ab.len(), 1, "{warnings:#?}");
    let line = of_ab[0];
    let reason = line.split_once(" error=").map_or("", |(_, reason)| reason);
    assert!(
        line.contains(r#"event="upstream_failure""#)
            && line.contains(" skipped=0 ")
            && line.contains(&both)
            && line.contains(" qname=one.ab.test ")
            && reason.starts_with("all upstreams failed: ")
            && reason.contains(&format!("tcp:{a}: "))
            && reason.contains(&format!("tcp:{b}: ")),
        "{line}"
    );
}
