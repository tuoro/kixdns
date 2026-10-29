//! 后台刷新按客户端问的类别重放请求：CH 类查询的缓存条目，刷新时问的仍是 CH 类，拿回的 CH 应答
//! 写回那个条目。
//! A background refresh replays the request in the class the client asked: the cached
//! entry of a CH query is refreshed with a CH query, and the CH answer that comes back
//! renews that entry.

use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::TXT;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use serde_json::json;

use crate::engine::Engine;
use crate::engine::test_support::{self as support, Upstream, counting_settings, engine_from};

/// 回答问题所在类别的本机上游：TXT 写的是类别名（IN、CH……），TTL 10 秒
/// A local upstream answering in the question's class: the TXT says the class (IN, CH, …),
/// TTL 10 seconds
async fn upstream() -> Upstream {
    support::upstream(|query| {
        let Some(question) = query.queries.first() else {
            return Vec::new();
        };
        let mut reply = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
        reply.metadata.recursion_desired = query.metadata.recursion_desired;
        reply.add_query(question.clone());
        let mut record = Record::from_rdata(
            question.name().clone(),
            10,
            RData::TXT(TXT::new(vec![question.query_class().to_string()])),
        );
        record.dns_class = question.query_class();
        reply.add_answer(record);
        vec![(Duration::ZERO, reply.to_vec().unwrap())]
    })
    .await
}

/// 一秒以后就到刷新时机（10 秒还剩 9 秒）的引擎，把所有请求转发给 `up`
/// An engine whose entries are due for a refresh after a second (9 of 10 seconds left),
/// forwarding everything to `up`
fn engine(up: &Upstream) -> Engine {
    engine_from(json!({
        "settings": counting_settings(json!({
            "default_upstream": up.address,
            "cache_background_refresh": true,
            "cache_refresh_threshold_percent": 95,
            "cache_refresh_min_ttl": 0
        })),
        "pipelines": [{ "id": "main", "rules": [{
            "name": "all", "matchers": [{ "type": "any" }], "actions": [{ "type": "allow" }]
        }] }]
    }))
}

fn chaos_query() -> Vec<u8> {
    let mut request = Message::new(0x4321, MessageType::Query, OpCode::Query);
    request.metadata.recursion_desired = true;
    let mut query = Query::query(Name::from_str("version.test.").unwrap(), RecordType::TXT);
    query.set_query_class(DNSClass::CH);
    request.add_query(query);
    request.to_vec().unwrap()
}

/// 应答里第一条 TXT 的内容 / The text of the first TXT in a reply
fn first_txt(reply: &[u8]) -> Option<String> {
    Message::from_bytes(reply)
        .expect("parse reply")
        .answers
        .iter()
        .find_map(|record| match &record.data {
            RData::TXT(txt) => Some(txt.to_string()),
            _ => None,
        })
}

fn peer() -> SocketAddr {
    "10.0.0.1:53000".parse().unwrap()
}

/// 等上游收到 `count` 个查询 / Wait until the upstream received `count` queries
async fn until_queries(up: &Upstream, count: usize) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while up.queries() < count {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the refresh reaches the upstream");
}

/// CH 类查询的缓存条目到了刷新时机，后台刷新问上游的仍是 CH 类
/// When the cached entry of a CH query is due, the background refresh asks the upstream
/// in class CH as well
#[tokio::test]
async fn a_background_refresh_asks_in_the_class_the_client_asked() {
    let up = upstream().await;
    let engine = engine(&up);
    support::ask(&engine, &chaos_query(), peer()).await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    // 这次命中发起刷新 / This hit starts the refresh
    support::ask(&engine, &chaos_query(), peer()).await;
    until_queries(&up, 2).await;
    let classes: Vec<DNSClass> = up
        .received()
        .iter()
        .map(|query| query.queries[0].query_class())
        .collect();
    assert_eq!(classes, [DNSClass::CH, DNSClass::CH]);
}

/// 刷新拿回的 CH 应答写回原来那个条目，下一个 CH 查询拿到的仍是 CH 的应答
/// The CH answer the refresh brings back renews the entry, and the next CH query still
/// gets the CH answer
#[tokio::test]
async fn a_refreshed_entry_still_answers_in_the_class_asked() {
    let up = upstream().await;
    let engine = engine(&up);
    let first = support::ask(&engine, &chaos_query(), peer()).await;
    assert_eq!(first_txt(&first).as_deref(), Some("CH"));
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let refreshes_started = std::time::Instant::now();
    support::ask(&engine, &chaos_query(), peer()).await;
    until_queries(&up, 2).await;
    let slot = Engine::cache_slot(
        engine.state.load().cache_namespace("main"),
        "main",
        b"version.test",
        RecordType::TXT,
        DNSClass::CH,
        crate::proto_utils::QueryFlags::RECURSIVE,
        &crate::matcher::RequesterKey::NONE,
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        while !engine
            .cached_entries(slot)
            .iter()
            .any(|entry| entry.fetched_at > refreshes_started)
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the refreshed answer renews the entry");
    let next = support::ask(&engine, &chaos_query(), peer()).await;
    assert_eq!(first_txt(&next).as_deref(), Some("CH"));
    assert_eq!(up.queries(), 2, "the next query is answered from the cache");
}
