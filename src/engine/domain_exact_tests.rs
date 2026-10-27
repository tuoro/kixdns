//! domain_exact 只命中这个名字本身；域名值结尾的点不改变含义。快速路径和完整路径、规则、
//! pipeline_select 和响应匹配器都一样。
//! domain_exact matches the name itself only, and a trailing dot on a domain value changes
//! nothing. The fast and the full path, rules, pipeline_select and response matchers agree.

use std::net::Ipv4Addr;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, Record};
use serde_json::{Value, json};

use crate::engine::Engine;
use crate::engine::test_support::{self as support, engine_from, first_a, peer};

/// 规则命中时的应答 / The answer when the rule matches
const MATCHED: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 50);
/// 其余请求的应答 / The answer to everything else
const OTHER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 60);
/// 假上游的应答 / The fake upstream's answer
const UPSTREAM: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);

/// `matcher` 命中时回 [`MATCHED`]，其余回 [`OTHER`] / [`MATCHED`] when `matcher` matches, else [`OTHER`]
fn engine_matching(matcher: Value) -> Engine {
    engine_from(json!({
        "settings": { "default_upstream": "127.0.0.1:9" },
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
}

/// `name` 的 A 查询，后面再接 `trailing` / An A query for `name`, then `trailing`
fn query(name: &str, trailing: &[u8]) -> Vec<u8> {
    let mut packet = vec![0x4e, 0x54, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.extend_from_slice(&[0, 0, 1, 0, 1]);
    packet.extend_from_slice(trailing);
    packet
}

/// 只走完整路径 / The full path alone
async fn full_path(engine: &Engine, packet: &[u8]) -> Option<Ipv4Addr> {
    first_a(&support::ask(engine, packet, peer()).await)
}

/// 两条路径都问一遍：快速路径读得了的直接问，结尾多一个字节的同一个查询走完整路径
/// Ask both ways: the query as it is on the fast path, and the same query with a trailing
/// byte, which the fast path leaves to the full one
async fn both_paths(engine: &Engine, name: &str) -> [Option<Ipv4Addr>; 2] {
    let packet = query(name, b"");
    let fast = match engine
        .handle_packet_fast(&packet, peer())
        .expect("fast path")
    {
        Some(crate::engine::FastPathResponse::Direct(reply)) => first_a(&reply),
        other => panic!("a static answer is direct, got {other:?}"),
    };
    let full = full_path(engine, &query(name, b"\0")).await;
    [fast, full]
}

#[tokio::test]
async fn domain_exact_matches_the_name_itself_only() {
    let engine = engine_matching(json!({ "type": "domain_exact", "value": "api.example.test" }));
    for (name, want) in [
        ("api.example.test", MATCHED),
        ("API.Example.TEST", MATCHED),
        ("www.api.example.test", OTHER),
        ("example.test", OTHER),
        ("api.example.test.cn", OTHER),
        ("xapi.example.test", OTHER),
    ] {
        assert_eq!(both_paths(&engine, name).await, [Some(want); 2], "{name}");
    }
}

#[tokio::test]
async fn a_trailing_dot_on_a_domain_value_changes_nothing() {
    for (matcher, name, subdomain_matches) in [
        (
            json!({ "type": "domain_exact", "value": "exact.test." }),
            "exact.test",
            false,
        ),
        (
            json!({ "type": "domain_suffix", "value": "suffix.test." }),
            "suffix.test",
            true,
        ),
        (
            json!({ "type": "domain_suffix", "value": ".dotted.test." }),
            "x.dotted.test",
            true,
        ),
    ] {
        let engine = engine_matching(matcher.clone());
        assert_eq!(
            both_paths(&engine, name).await,
            [Some(MATCHED); 2],
            "{matcher}"
        );
        let below = format!("www.{name}");
        let want = if subdomain_matches { MATCHED } else { OTHER };
        assert_eq!(
            both_paths(&engine, &below).await,
            [Some(want); 2],
            "{matcher} {below}"
        );
    }
}

#[tokio::test]
async fn pipeline_select_takes_domain_exact() {
    let engine = engine_from(json!({
        "settings": { "default_upstream": "127.0.0.1:9" },
        "pipeline_select": [
            { "pipeline": "picked", "matchers": [{ "type": "domain_exact", "value": "picked.test" }] }
        ],
        "pipelines": [
            { "id": "main", "rules": [{ "name": "other", "matchers": [{ "type": "any" }],
                "actions": [{ "type": "static_ip_response", "ip": OTHER.to_string() }] }] },
            { "id": "picked", "rules": [{ "name": "matched", "matchers": [{ "type": "any" }],
                "actions": [{ "type": "static_ip_response", "ip": MATCHED.to_string() }] }] }
        ]
    }));
    assert_eq!(both_paths(&engine, "picked.test").await, [Some(MATCHED); 2]);
    assert_eq!(
        both_paths(&engine, "www.picked.test").await,
        [Some(OTHER); 2]
    );
}

/// 回答 [`UPSTREAM`] 的本机 UDP 上游 / A local UDP upstream answering [`UPSTREAM`]
async fn upstream() -> String {
    support::upstream(|query| {
        let Some(question) = query.queries.first() else {
            return Vec::new();
        };
        let mut reply = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
        reply.metadata.recursion_desired = query.metadata.recursion_desired;
        reply.add_query(question.clone());
        reply.add_answer(Record::from_rdata(
            question.name().clone(),
            300,
            RData::A(A(UPSTREAM)),
        ));
        vec![(Duration::ZERO, reply.to_vec().unwrap())]
    })
    .await
    .address
}

#[tokio::test]
async fn response_matchers_take_request_domain_exact() {
    let upstream = upstream().await;
    let engine = engine_from(json!({
        "settings": { "default_upstream": upstream },
        "pipelines": [{ "id": "main", "rules": [{
            "name": "checked",
            "matchers": [{ "type": "any" }],
            "actions": [{ "type": "forward", "upstream": upstream }],
            "response_matchers": [{ "type": "request_domain_exact", "value": "checked.test" }],
            "response_actions_on_match": [{ "type": "static_ip_response", "ip": MATCHED.to_string() }],
            "response_actions_on_miss": [{ "type": "allow" }]
        }]}]
    }));
    assert_eq!(
        full_path(&engine, &query("checked.test", b"")).await,
        Some(MATCHED)
    );
    assert_eq!(
        full_path(&engine, &query("www.checked.test", b"")).await,
        Some(UPSTREAM)
    );
}
