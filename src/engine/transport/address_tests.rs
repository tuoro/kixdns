//! 上游地址读法的测试 / Tests of how upstream addresses are read

use super::*;
use rustls::pki_types::ServerName;

#[test]
fn doq_target_requires_sni_for_ip() {
    assert!(parse_doq_target("223.5.5.5:853").is_err());
    assert!(parse_doq_target("223.5.5.5:853?sni=alidns.com").is_ok());
    assert!(parse_doq_target("dns.alidns.com:853").is_ok());
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
    assert!(dot_error("[::1").starts_with("invalid dot upstream url"));
    assert!(doq_error("[::1").starts_with("invalid doq upstream url"));
}

/// DoT、DoQ 的上游和 DoH 一样不收第二个前缀，配置检查报出来：`dot://tcp://1.1.1.1:53` 不会在 53 端口上做 DoT，
/// `tls://https://dns.google:443` 不会去连 853
/// DoT and DoQ upstreams take no second prefix, as DoH ones do, and the configuration check
/// reports it: `dot://tcp://1.1.1.1:53` does not speak DoT on port 53, nor does
/// `tls://https://dns.google:443` dial 853
#[test]
fn a_dot_or_doq_upstream_with_a_second_prefix_is_refused() {
    use crate::config::Transport;
    for (address, transport) in [
        ("tcp://1.1.1.1:53", Transport::Dot),
        ("https://dns.google:443", Transport::Dot),
        ("dot://dns.example", Transport::Dot),
        ("http://dns.example:853?sni=dns.example", Transport::Doq),
        ("doq://dns.example", Transport::Doq),
    ] {
        let err = check_upstream_address(address, transport)
            .expect_err(address)
            .to_string();
        assert!(err.contains("a second prefix"), "{address}: {err}");
    }
}

/// DoT 只收 `sni`、`servername` 参数，DoQ 再收 `0rtt`、`enable_0rtt`（值不分大小写）；拼错的参数、另一种传输的参数、
/// 读不懂的 0rtt 值都报出来，不悄悄忽略或者改照全局设置
/// DoT takes the `sni` and `servername` parameters alone, DoQ `0rtt` and `enable_0rtt` too
/// (values in any case); a misspelt parameter, one of the other transport and a 0rtt value it
/// cannot read are all reported, neither ignored unseen nor left to the global setting
#[test]
fn a_tls_upstream_takes_only_the_parameters_its_transport_reads() {
    use crate::config::Transport;
    for (address, transport, fragment) in [
        ("1.1.1.1:853?sin=one.one.one.one", Transport::Dot, "\"sin\""),
        ("dns.example:853?0rtt=1", Transport::Dot, "\"0rtt\""),
        ("dns.example:853?zerortt=1", Transport::Doq, "\"zerortt\""),
        ("dns.example:853?0rtt=ture", Transport::Doq, "\"ture\""),
        (
            "dns.example:853?enable_0rtt=",
            Transport::Doq,
            "enable_0rtt",
        ),
    ] {
        let err = format!(
            "{:#}",
            check_upstream_address(address, transport).expect_err(address)
        );
        assert!(err.contains(fragment), "{address}: {err}");
    }
    for (address, enable_0rtt) in [
        ("dns.example:853?0rtt=false", Some(false)),
        ("dns.example:853?ENABLE_0RTT=On&sni=dns.example", Some(true)),
        ("dns.example:853?0rtt=yes&0rtt=0", Some(false)),
        ("dns.example:853?SNI=dns.example", None),
    ] {
        assert_eq!(
            parse_doq_target(address).expect(address).enable_0rtt,
            enable_0rtt,
            "{address}"
        );
    }
    assert!(
        check_upstream_address("1.1.1.1:853?ServerName=one.one.one.one", Transport::Dot).is_ok()
    );
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

/// DoH 上游一律走 https：地址是去掉前缀的那部分（见 `config::parse_upstream_addr`），没写路径时用 `/dns-query`，`host`
/// 参数拿出来做覆盖的 Host。后面又写了一个前缀的不认，配置检查也就报出来：以前 `doh://http://…` 过得了检查，却悄悄走明文
/// A DoH upstream always goes over https: its address is what follows the prefix (see
/// `config::parse_upstream_addr`), `/dns-query` taken with no path written and the `host`
/// parameter taken out as the Host override. One with a second prefix after the first is not
/// taken, so the configuration check reports it: `doh://http://…` used to pass the check and go
/// over plain http unseen
#[test]
fn a_doh_upstream_always_goes_over_https() {
    let (url, host) = build_doh_url("dns.example").unwrap();
    assert_eq!(
        (url.as_str(), host),
        ("https://dns.example/dns-query", None)
    );
    let (url, host) = build_doh_url("192.0.2.1:8443/q?host=front.example&x=1").unwrap();
    assert_eq!(
        (url.as_str(), host.as_deref()),
        ("https://192.0.2.1:8443/q?x=1", Some("front.example"))
    );
    for second in [
        "http://dns.example/dns-query",
        "https://dns.example/dns-query",
        "doh://dns.example",
    ] {
        let err = check_upstream_address(second, crate::config::Transport::Doh)
            .expect_err(second)
            .to_string();
        assert!(err.contains("a second prefix"), "{second}: {err}");
    }
}
