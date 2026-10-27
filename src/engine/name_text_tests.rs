//! 不论哪个解析器读的查询，规则看到的都是同一段名字文本（见 `proto_utils::name_text`）：快速
//! 解析读不了的查询（结尾多了字节、标签里有要转义的字节）照样遇到同样的规则。
//! Whichever parser reads a query, its rules see the same name text (see
//! `proto_utils::name_text`): a query the fast parser cannot read (trailing bytes, a label
//! byte that needs an escape) meets the same rules.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use bytes::Bytes;
use hickory_proto::op::Message;
use hickory_proto::rr::RData;
use hickory_proto::serialize::binary::BinDecodable;
use serde_json::json;

use crate::engine::Engine;
use crate::matcher::RuntimePipelineConfig;

/// 规则命中时的应答 / The answer when the rule matches
const MATCHED: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 50);
/// 其余请求的应答 / The answer to everything else
const OTHER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 60);

const CLIENT: &str = "127.0.0.1:53000";

/// 名字以 `matched.test` 结尾的请求得到 [`MATCHED`]，其余得到 [`OTHER`]
/// A name ending in `matched.test` gets [`MATCHED`], every other one [`OTHER`]
fn engine() -> Engine {
    let config: crate::config::PipelineConfig = serde_json::from_value(json!({
        "settings": { "default_upstream": "127.0.0.1:9" },
        "pipelines": [{ "id": "main", "rules": [
            {
                "name": "matched",
                "matchers": [{ "type": "domain_suffix", "value": "matched.test" }],
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

/// 一个 A 查询，名字由 `labels` 组成，后面再接 `trailing` / An A query for `labels`, then `trailing`
fn query(labels: &[&[u8]], trailing: &[u8]) -> Vec<u8> {
    let mut packet = vec![0x4e, 0x54, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in labels {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label);
    }
    packet.extend_from_slice(&[0, 0, 1, 0, 1]);
    packet.extend_from_slice(trailing);
    packet
}

/// 像监听器那样问：快速路径答不了才走完整路径；返回应答里的地址，以及快速路径是否读得了
/// Ask as a listener does: the full path only when the fast path cannot answer; the
/// address in the reply, and whether the fast path could read the query
async fn ask(engine: &Engine, packet: &[u8]) -> (Option<Ipv4Addr>, bool) {
    let peer: SocketAddr = CLIENT.parse().unwrap();
    let fast = engine.handle_packet_fast(packet, peer).expect("fast path");
    let read_fast = fast.is_some();
    let reply = match fast {
        Some(crate::engine::FastPathResponse::Direct(reply)) => reply,
        Some(other) => panic!("a static answer is direct, got {other:?}"),
        None => tokio::time::timeout(Duration::from_secs(5), engine.handle_packet(packet, peer))
            .await
            .expect("answer in time")
            .expect("answer"),
    };
    (first_a(&reply), read_fast)
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

#[tokio::test]
async fn a_query_with_trailing_bytes_meets_the_same_rules() {
    let engine = engine();
    let name: &[&[u8]] = &[b"www", b"matched", b"test"];
    assert_eq!(ask(&engine, &query(name, b"")).await, (Some(MATCHED), true));
    for trailing in [&b"\0"[..], b"junk"] {
        assert_eq!(
            ask(&engine, &query(name, trailing)).await,
            (Some(MATCHED), false),
            "{trailing:?}"
        );
    }
    assert_eq!(
        ask(&engine, &query(&[b"www", b"else", b"test"], b"\0")).await,
        (Some(OTHER), false)
    );
}

#[tokio::test]
async fn a_name_with_bytes_to_escape_meets_the_same_rules() {
    let engine = engine();
    for label in [&b"x\xffy"[..], b"x\x01y", b"caf\xc3\xa9", b"a b"] {
        assert_eq!(
            ask(&engine, &query(&[label, b"matched", b"test"], b"")).await,
            (Some(MATCHED), false),
            "{label:?}"
        );
    }
}

#[tokio::test]
async fn a_dot_inside_a_label_is_not_a_label_boundary() {
    let engine = engine();
    // 两个标签 "www.matched" 和 "test"，不在 matched.test 之下
    // Two labels, "www.matched" and "test": not under matched.test
    assert_eq!(
        ask(&engine, &query(&[b"www.matched", b"test"], b"")).await,
        (Some(OTHER), false)
    );
    // 一个标签 "matched.test" / One label, "matched.test"
    assert_eq!(
        ask(&engine, &query(&[b"matched.test"], b"")).await,
        (Some(OTHER), false)
    );
}
