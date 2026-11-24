//! 上游地址读法的测试 / Tests of how upstream addresses are read

use super::*;
use rustls::pki_types::ServerName;

#[test]
fn doq_target_requires_sni_for_ip() {
    assert!(parse_doq_target("doq://223.5.5.5:853").is_err());
    assert!(parse_doq_target("doq://223.5.5.5:853?sni=alidns.com").is_ok());
    assert!(parse_doq_target("doq://dns.alidns.com:853").is_ok());
}

/// DoT、DoQ 的上游必须有建连时用得上的主机名：空的不行，做不成 TLS 服务器名的（`%20`、`.`）
/// 也不行，建连时都必然失败
/// A DoT or DoQ upstream needs a host its connect can use: not an empty one, nor one that
/// makes no TLS server name (`%20`, `.`), which would fail every connect
#[test]
fn a_dot_or_doq_upstream_without_a_usable_host_is_refused() {
    use crate::config::Transport;
    for address in [
        "",
        ":853",
        "?sni=dns.example",
        "%20",
        ".",
        ".:853",
        "dns.example?sni=%20",
    ] {
        assert!(
            check_upstream_address(address, Transport::Dot).is_err(),
            "dot {address:?}"
        );
    }
    for address in [
        "",
        ":853",
        "?sni=dns.example",
        "%20",
        ".",
        ".:853",
        "dns.example?sni=%20",
    ] {
        assert!(
            check_upstream_address(address, Transport::Doq).is_err(),
            "doq {address:?}"
        );
    }
    assert!(check_upstream_address("dns.example:853", Transport::Dot).is_ok());
    assert!(check_upstream_address("dns.example:853", Transport::Doq).is_ok());
}

/// DoT 和 DoQ 的上游地址：`sni`/`servername` 取最后一个非空的；出错时错误文字带着协议名
/// DoT and DoQ upstream addresses: the last non-empty `sni`/`servername` counts, and the
/// errors name the protocol
#[test]
fn dot_and_doq_addresses_take_the_last_sni_and_name_their_protocol_in_errors() {
    for (upstream, sni) in [
        ("1.1.1.1:853?sni=a.example&sni=b.example", "b.example"),
        ("1.1.1.1:853?sni=a.example&sni=", "a.example"),
        ("1.1.1.1:853?servername=c.example", "c.example"),
    ] {
        assert_eq!(parse_dot_target(upstream).expect("dot").sni.as_ref(), sni);
        assert_eq!(parse_doq_target(upstream).expect("doq").sni.as_ref(), sni);
    }
    let dot_error = |upstream: &str| format!("{:#}", parse_dot_target(upstream).err().unwrap());
    let doq_error = |upstream: &str| format!("{:#}", parse_doq_target(upstream).err().unwrap());
    assert_eq!(
        dot_error("dns.example/path"),
        "dot upstream should not contain path"
    );
    assert_eq!(
        doq_error("dns.example/path?sni=dns.example"),
        "doq upstream should not contain path"
    );
    assert!(dot_error("dot://[::1").starts_with("invalid dot upstream url"));
    assert!(doq_error("doq://[::1").starts_with("invalid doq upstream url"));
}

#[test]
fn dot_target_accepts_an_ipv6_literal() {
    let target = parse_dot_target("[2400:3200::1]:853").expect("parse an IPv6 DoT upstream");
    assert_eq!(&*target.connect_addr, "[2400:3200::1]:853");
    assert_eq!(&*target.sni, "2400:3200::1");
    assert!(
        matches!(build_server_name(&target.sni), Ok(ServerName::IpAddress(_))),
        "the server name for an IP literal must be the address itself"
    );
}

#[test]
fn doq_target_with_an_ipv6_literal_requires_sni() {
    assert!(
        parse_doq_target("[2400:3200::1]:853").is_err(),
        "an IPv6 literal without sni must be refused like an IPv4 one"
    );
    let target = parse_doq_target("[2400:3200::1]:853?sni=dns.alidns.com")
        .expect("an IPv6 literal with sni is fine");
    assert_eq!(host_port(&target.host, target.port), "[2400:3200::1]:853");
}
