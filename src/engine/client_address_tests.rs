//! 双栈套接字交来的 IPv4 映射地址（::ffff:a.b.c.d）：按它背后的 IPv4 地址对待。
//! IPv4-mapped addresses (::ffff:a.b.c.d) from a dual-stack socket: treated as
//! the IPv4 address they carry.

use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

use bytes::Bytes;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use serde_json::{Value, json};

use crate::engine::{Engine, FastPathResponse, PreParsedData};
use crate::matcher::RuntimePipelineConfig;

/// 规则命中时的应答 / The answer when the rule matches
const MATCHED: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 50);
/// 其余请求的应答 / The answer to everything else
const OTHER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 60);

/// 双栈套接字上 IPv4 客户端 `v4` 的来源地址 / The source address of IPv4 client `v4` on a dual-stack socket
fn mapped(v4: &str) -> SocketAddr {
    format!("[::ffff:{v4}]:53000").parse().unwrap()
}

/// 唯一的 pipeline 里，带 `matcher` 的规则静态应答 [`MATCHED`]，其余请求得到 [`OTHER`]
/// One pipeline: a rule with `matcher` answers [`MATCHED`], and every other
/// request gets [`OTHER`]
fn engine_matching(matcher: Value) -> Engine {
    engine_with(json!({}), matcher)
}

/// 同上，另加 `settings` / The same, with `settings` added
fn engine_with(settings: Value, matcher: Value) -> Engine {
    let mut all_settings = json!({ "default_upstream": "127.0.0.1:9" });
    all_settings
        .as_object_mut()
        .unwrap()
        .extend(settings.as_object().unwrap().clone());
    let config: crate::config::PipelineConfig = serde_json::from_value(json!({
        "settings": all_settings,
        "pipelines": [{ "id": "main", "rules": [
            {
                "name": "matched",
                "matchers": [matcher],
                "actions": [{ "type": "static_ip_response", "ip": MATCHED.to_string() }]
            },
            {
                "name": "other",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "static_ip_response", "ip": OTHER.to_string() }]
            }
        ]}]
    }))
    .expect("parse config");
    Engine::new(
        RuntimePipelineConfig::from_config(config).expect("build runtime config"),
        "test".to_string(),
    )
    .expect("engine")
}

fn query() -> Vec<u8> {
    let mut request = Message::new(0x4d41, MessageType::Query, OpCode::Query);
    request.metadata.recursion_desired = true;
    request.add_query(Query::query(
        Name::from_str("example.com.").unwrap(),
        RecordType::A,
    ));
    request.to_vec().unwrap()
}

fn first_a(reply: &Bytes) -> Option<Ipv4Addr> {
    match Message::from_bytes(reply)
        .expect("parse reply")
        .answers
        .first()
        .map(|record| &record.data)
    {
        Some(RData::A(address)) => Some(address.0),
        _ => None,
    }
}

/// 只走异步路径 / The async path alone
async fn ask(engine: &Engine, peer: SocketAddr) -> Option<Ipv4Addr> {
    let reply = tokio::time::timeout(Duration::from_secs(5), engine.handle_packet(&query(), peer))
        .await
        .expect("answer in time")
        .expect("answer");
    first_a(&reply)
}

/// 像监听器那样：先走快速路径，需要时再走异步路径
/// As a listener does: the fast path first, then the async path when needed
async fn ask_like_a_listener(engine: &Engine, peer: SocketAddr) -> Option<Ipv4Addr> {
    let packet = query();
    let reply = match engine.handle_packet_fast(&packet, peer).expect("fast path") {
        Some(FastPathResponse::Direct(reply)) => reply,
        Some(FastPathResponse::CacheHit { cached, .. }) => cached,
        Some(FastPathResponse::AsyncNeeded {
            qname,
            qtype,
            qclass,
            tx_id,
            edns_present,
            pipeline_id,
        }) => tokio::time::timeout(
            Duration::from_secs(5),
            engine.handle_packet_internal_with_pre_parsed(
                &packet,
                peer,
                false,
                PreParsedData::new(qname, qtype, qclass, tx_id, edns_present, pipeline_id),
            ),
        )
        .await
        .expect("answer in time")
        .expect("answer"),
        None => panic!("a query the fast path cannot read"),
    };
    first_a(&reply)
}

#[tokio::test]
async fn client_ip_matches_an_ipv4_client_on_a_dual_stack_socket() {
    let engine = engine_matching(json!({ "type": "client_ip", "cidr": "198.51.100.0/24" }));
    for peer in [
        mapped("198.51.100.7"),
        "198.51.100.7:53000".parse().unwrap(),
    ] {
        assert_eq!(ask(&engine, peer).await, Some(MATCHED), "{peer}");
        assert_eq!(
            ask_like_a_listener(&engine, peer).await,
            Some(MATCHED),
            "{peer}"
        );
    }
    assert_eq!(ask(&engine, mapped("203.0.113.9")).await, Some(OTHER));
    assert_eq!(
        ask_like_a_listener(&engine, mapped("203.0.113.9")).await,
        Some(OTHER)
    );
}

#[tokio::test]
async fn a_private_ipv4_client_on_a_dual_stack_socket_is_private() {
    let engine = engine_matching(json!({ "type": "geoip_private", "expect": true }));
    assert_eq!(ask(&engine, mapped("192.168.1.5")).await, Some(MATCHED));
    assert_eq!(
        ask_like_a_listener(&engine, mapped("192.168.1.5")).await,
        Some(MATCHED)
    );
    assert_eq!(ask(&engine, mapped("203.0.113.9")).await, Some(OTHER));
}

#[tokio::test]
async fn geoip_data_finds_an_ipv4_client_on_a_dual_stack_socket() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("geoip.json");
    std::fs::write(
        &data,
        r#"{"entries":[{"country_code":"TESTNET","ips":["198.51.100.0/24"]}]}"#,
    )
    .unwrap();
    let engine = engine_with(
        json!({ "geoip_dat_path": data.to_str().unwrap() }),
        json!({ "type": "geoip_country", "country_codes": ["TESTNET"] }),
    );
    assert_eq!(ask(&engine, mapped("198.51.100.7")).await, Some(MATCHED));
    assert_eq!(
        ask_like_a_listener(&engine, mapped("198.51.100.7")).await,
        Some(MATCHED)
    );
    assert_eq!(ask(&engine, mapped("203.0.113.9")).await, Some(OTHER));
}

/// 为绕开旧问题而写成映射形式的网段照样命中，IPv4 和双栈套接字上的客户端都一样
/// A network written in the IPv4-mapped form, as a way around the old behaviour,
/// still matches, for clients on IPv4 and on dual-stack sockets alike
#[tokio::test]
async fn a_client_ip_network_written_in_the_mapped_form_still_matches() {
    let engine = engine_matching(json!({ "type": "client_ip", "cidr": "::ffff:198.51.100.0/120" }));
    for peer in [
        mapped("198.51.100.7"),
        "198.51.100.7:53000".parse().unwrap(),
    ] {
        assert_eq!(ask(&engine, peer).await, Some(MATCHED), "{peer}");
        assert_eq!(
            ask_like_a_listener(&engine, peer).await,
            Some(MATCHED),
            "{peer}"
        );
    }
    assert_eq!(ask(&engine, mapped("203.0.113.9")).await, Some(OTHER));
}

#[tokio::test]
async fn a_pipeline_selector_written_in_the_mapped_form_still_matches() {
    let config: crate::config::PipelineConfig = serde_json::from_value(json!({
        "settings": { "default_upstream": "127.0.0.1:9" },
        "pipeline_select": [{
            "pipeline": "matched",
            "matchers": [{ "type": "client_ip", "cidr": "::ffff:198.51.100.0/120" }]
        }],
        "pipelines": [
            { "id": "other", "rules": [{
                "name": "other", "matchers": [{ "type": "any" }],
                "actions": [{ "type": "static_ip_response", "ip": OTHER.to_string() }]
            }]},
            { "id": "matched", "rules": [{
                "name": "matched", "matchers": [{ "type": "any" }],
                "actions": [{ "type": "static_ip_response", "ip": MATCHED.to_string() }]
            }]}
        ]
    }))
    .expect("parse config");
    let engine = Engine::new(
        RuntimePipelineConfig::from_config(config).expect("build runtime config"),
        "test".to_string(),
    )
    .expect("engine");
    for peer in [
        mapped("198.51.100.7"),
        "198.51.100.7:53000".parse().unwrap(),
    ] {
        assert_eq!(ask(&engine, peer).await, Some(MATCHED), "{peer}");
        assert_eq!(
            ask_like_a_listener(&engine, peer).await,
            Some(MATCHED),
            "{peer}"
        );
    }
    assert_eq!(ask(&engine, mapped("203.0.113.9")).await, Some(OTHER));
}
