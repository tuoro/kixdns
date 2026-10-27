//! 同一个问题已经有请求在问上游时，后来的请求等它的应答，不再自己去问：`forward` 规则这样，
//! `allow` 规则也这样，响应跳转之后的路径上也一样。
//! A request for a question another request is already asking upstream waits for that
//! answer instead of asking again: for a `forward` rule, for an `allow` rule, and on the
//! path after a response jump alike.

use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use serde_json::json;

use crate::engine::test_support::{
    self as support, Upstream, counting_settings, engine_from, first_a,
};

/// 假上游给的地址 / The address the fake upstream answers
const ANSWER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 90);

/// 用 [`ANSWER`] 作答的本机上游，应答晚 `delay` 发出
/// A local upstream answering [`ANSWER`], every reply `delay` late
async fn upstream(delay: Duration) -> Upstream {
    support::upstream(move |query| {
        let Some(question) = query.queries.first() else {
            return Vec::new();
        };
        let mut reply = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
        reply.metadata.recursion_desired = query.metadata.recursion_desired;
        reply.metadata.recursion_available = true;
        reply.add_query(question.clone());
        reply.add_answer(Record::from_rdata(
            question.name().clone(),
            300,
            RData::A(A(ANSWER)),
        ));
        vec![(delay, reply.to_vec().unwrap())]
    })
    .await
}

fn query() -> Vec<u8> {
    let mut request = Message::new(0x5157, MessageType::Query, OpCode::Query);
    request.metadata.recursion_desired = true;
    request.add_query(Query::query(
        Name::from_str("example.com.").unwrap(),
        RecordType::A,
    ));
    request.to_vec().unwrap()
}

fn peer(client: &str) -> SocketAddr {
    format!("{client}:53000").parse().unwrap()
}

/// 两个请求同时问，各自拿到的地址 / Two requests at once, and the address each gets
async fn ask_at_once(engine: &crate::engine::Engine, clients: [&str; 2]) -> [Option<Ipv4Addr>; 2] {
    let packet = query();
    let (one, two) = tokio::join!(
        support::ask(engine, &packet, peer(clients[0])),
        support::ask(engine, &packet, peer(clients[1]))
    );
    [first_a(&one), first_a(&two)]
}

/// `allow` 规则把请求转发给默认上游；同时到达的第二个请求等第一个的应答
/// An `allow` rule forwards to the default upstream; a second request arriving at the
/// same time waits for the first one's answer
#[tokio::test]
async fn requests_an_allow_rule_forwards_wait_together() {
    let up = upstream(Duration::from_millis(150)).await;
    let engine = engine_from(json!({
        "settings": counting_settings(json!({ "default_upstream": up.address })),
        "pipelines": [{ "id": "main", "rules": [{
            "name": "allow", "matchers": [{ "type": "any" }], "actions": [{ "type": "allow" }]
        }] }]
    }));
    assert_eq!(
        ask_at_once(&engine, ["10.0.0.1", "10.0.0.2"]).await,
        [Some(ANSWER), Some(ANSWER)]
    );
    assert_eq!(up.queries(), 1, "the second request waited on the first");
}

/// 两个客户端经不同的 pipeline 进来，响应跳转以后都走到同一条 `allow` 规则：第二个等第一个的
/// 应答
/// Two clients come in through different pipelines and, after a response jump, both
/// reach the same `allow` rule: the second waits for the first one's answer
#[tokio::test]
async fn requests_reaching_an_allow_rule_after_a_response_jump_wait_together() {
    let pre = upstream(Duration::ZERO).await;
    let last = upstream(Duration::from_millis(150)).await;
    let entry = |id: &str| {
        json!({ "id": id, "rules": [{
            "name": "r", "matchers": [{ "type": "any" }],
            "actions": [{ "type": "forward", "upstream": pre.address }],
            "response_matchers": [{ "type": "upstream_equals", "value": pre.address }],
            "response_actions_on_match": [{ "type": "jump_to_pipeline", "pipeline": "other" }]
        }] })
    };
    let engine = engine_from(json!({
        "settings": counting_settings(json!({ "default_upstream": last.address })),
        "pipeline_select": [
            { "pipeline": "a", "matchers": [{ "type": "client_ip", "cidr": "10.0.0.1/32" }] },
            { "pipeline": "b", "matchers": [{ "type": "client_ip", "cidr": "10.0.0.2/32" }] }
        ],
        "pipelines": [
            entry("a"),
            entry("b"),
            { "id": "other", "rules": [{
                "name": "allow", "matchers": [{ "type": "any" }], "actions": [{ "type": "allow" }]
            }] }
        ]
    }));
    assert_eq!(
        ask_at_once(&engine, ["10.0.0.1", "10.0.0.2"]).await,
        [Some(ANSWER), Some(ANSWER)]
    );
    assert_eq!(pre.queries(), 2, "each entry pipeline asks on its own");
    assert_eq!(
        last.queries(),
        1,
        "the second request waited on the jump path"
    );
}
