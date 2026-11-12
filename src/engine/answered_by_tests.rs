//! 回答检查里的「回答来自哪个上游」（`upstream_equals`、`response_upstream_ip`）看的是这次实际作答的那个上游，
//! 不是规则里写的那一串地址。以前拿规则里写的整串去比：一条规则里它是个定值，写了几个上游、或带了前缀时永远
//! 不成立，文档写的 `udp:1.1.1.1:53` 也永远不成立。
//! What the answer check knows as "the upstream the answer came from" (`upstream_equals`,
//! `response_upstream_ip`) is the upstream that answered this time, not the addresses the rule
//! writes. It used to be compared with the whole text the rule writes: a constant within one
//! rule, never holding with several upstreams or a prefix written, and never for the
//! `udp:1.1.1.1:53` the documentation gives.

use std::net::Ipv4Addr;
use std::str::FromStr;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use serde_json::{Value, json};

use crate::engine::test_support::{
    Upstream, answering_upstream, answering_upstream_after, ask, counting_settings, engine_from,
    first_a, peer, upstream,
};

/// 先答的上游给的地址 / The address the upstream that answers first gives
const QUICK: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
/// 晚答的上游给的地址 / The address the upstream that answers late gives
const SLOW: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
/// 回答检查不通过时规则给的地址 / The address the rules give when the answer check fails
const OTHERWISE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 99);

fn query() -> Vec<u8> {
    let mut query = Message::new(0x5a5a, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(
        Name::from_str("name.test.").unwrap(),
        RecordType::A,
    ));
    query.to_vec().unwrap()
}

/// 先答和晚答（晚 300 毫秒）的两个上游 / Two upstreams, one answering at once and one 300 ms late
async fn quick_and_slow() -> (Upstream, Upstream) {
    (
        answering_upstream(QUICK, 60).await,
        answering_upstream_after(SLOW, 60, Duration::from_millis(300)).await,
    )
}

/// 一条规则转发给 `upstreams`，回答检查是 `check`：通过就照上游的回答，不通过回 [`OTHERWISE`]。返回客户端拿到的地址
/// One rule forwarding to `upstreams` with the answer check `check`: the upstream's answer
/// when it holds, [`OTHERWISE`] when not. Gives the address the client gets
async fn answer_checked_by(upstreams: &str, check: Value) -> Option<Ipv4Addr> {
    let engine = engine_from(json!({
        "settings": counting_settings(json!({})),
        "pipelines": [{ "id": "main", "rules": [
            { "name": "all", "matchers": [{ "type": "any" }],
              "actions": [{ "type": "forward", "upstream": upstreams }],
              "response_matchers": [check],
              "response_actions_on_miss": [{ "type": "static_ip_response", "ip": OTHERWISE.to_string() }] },
        ]}]
    }));
    first_a(&ask(&engine, &query(), peer()).await)
}

/// 规则同时问两个上游，先答的那个作答。`upstream_equals` 写它时成立：照文档写成 `udp:地址`、照转发里的写法写成
/// 地址或 `udp://地址`、把几个地址用逗号写在一起（其中之一）都算。写没作答的那个不成立
/// A rule asks two upstreams at once and the quicker answers. `upstream_equals` naming it
/// holds: written `udp:address` as the documentation has it, as a forward writes it (the
/// address or `udp://address`), or among several addresses separated by commas. Naming the
/// one that did not answer does not hold
#[tokio::test]
async fn upstream_equals_is_about_the_upstream_that_answered() {
    let (quick, slow) = quick_and_slow().await;
    let both = format!("{},{}", quick.address, slow.address);
    for (value, answer) in [
        (format!("udp:{}", quick.address), QUICK),
        (quick.address.clone(), QUICK),
        (format!("udp://{}", quick.address), QUICK),
        (both.clone(), QUICK),
        (format!("{}, {}", slow.address, quick.address), QUICK),
        (slow.address.clone(), OTHERWISE),
        (format!("udp:{}", slow.address), OTHERWISE),
        (format!("tcp:{}", quick.address), OTHERWISE),
    ] {
        let check = json!({ "type": "upstream_equals", "value": value });
        assert_eq!(
            answer_checked_by(&both, check).await,
            Some(answer),
            "upstream_equals {value}"
        );
    }
}

/// `response_upstream_ip` 看的是作答的上游的地址：规则里带前缀、写了几个上游都一样
/// `response_upstream_ip` reads the address of the upstream that answered, whether the rule
/// writes a prefix or several upstreams
#[tokio::test]
async fn response_upstream_ip_is_about_the_upstream_that_answered() {
    let (quick, slow) = quick_and_slow().await;
    for upstreams in [
        quick.address.clone(),
        format!("udp://{}", quick.address),
        format!("{},{}", quick.address, slow.address),
    ] {
        for (cidr, answer) in [("127.0.0.0/8", QUICK), ("10.0.0.0/8", OTHERWISE)] {
            let check = json!({ "type": "response_upstream_ip", "cidr": cidr });
            assert_eq!(
                answer_checked_by(&upstreams, check).await,
                Some(answer),
                "upstreams {upstreams}, cidr {cidr}"
            );
        }
    }
}

/// 每个查询回 SERVFAIL 的上游，晚 `delay` 才回 / An upstream answering every query SERVFAIL, `delay` late
async fn failing_upstream(delay: Duration) -> Upstream {
    upstream(move |query| {
        let mut reply = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
        reply.metadata.recursion_desired = query.metadata.recursion_desired;
        reply.metadata.response_code = ResponseCode::ServFail;
        reply.add_queries(query.queries.iter().cloned());
        vec![(delay, reply.to_vec().unwrap())]
    })
    .await
}

/// 几个上游都回了失败应答时，回答检查看的是最先收到的那个，「回答来自」也是它
/// When several upstreams all reply with a failure the answer check reads the first of those
/// replies, and that reply's upstream is the one the answer came from
#[tokio::test]
async fn a_failure_reply_is_checked_against_the_upstream_that_sent_it() {
    let first = failing_upstream(Duration::ZERO).await;
    let second = failing_upstream(Duration::from_millis(200)).await;
    for (named, answer) in [(&first, Some(OTHERWISE)), (&second, None)] {
        let engine = engine_from(json!({
            "settings": counting_settings(json!({})),
            "pipelines": [{ "id": "main", "rules": [
                { "name": "all", "matchers": [{ "type": "any" }],
                  "actions": [{ "type": "forward", "upstream": format!("{},{}", first.address, second.address) }],
                  "response_matchers": [{ "type": "upstream_equals", "value": named.address }],
                  "response_actions_on_match": [{ "type": "static_ip_response", "ip": OTHERWISE.to_string() }] },
            ]}]
        }));
        assert_eq!(
            first_a(&ask(&engine, &query(), peer()).await),
            answer,
            "naming {}",
            named.address
        );
    }
}

/// 回答检查跳转过去的规则组里也一样：几个上游都回失败应答时，检查看的是最先收到的那个应答和回它的上游
/// The same in a pipeline an answer check jumps to: with several upstreams all replying with a
/// failure, the check reads the first of those replies and the upstream that sent it
#[tokio::test]
async fn a_failure_reply_after_a_response_jump_is_checked_against_the_upstream_that_sent_it() {
    let entry = answering_upstream(Ipv4Addr::new(192, 0, 2, 50), 60).await;
    let first = failing_upstream(Duration::ZERO).await;
    let second = failing_upstream(Duration::from_millis(200)).await;
    for (named, answer) in [(&first, Some(OTHERWISE)), (&second, None)] {
        let engine = engine_from(json!({
            "settings": counting_settings(json!({})),
            "pipelines": [
                { "id": "main", "rules": [
                    { "name": "all", "matchers": [{ "type": "any" }],
                      "actions": [{ "type": "forward", "upstream": entry.address }],
                      "response_actions_on_match": [{ "type": "jump_to_pipeline", "pipeline": "second" }] },
                ]},
                { "id": "second", "rules": [
                    { "name": "all", "matchers": [{ "type": "any" }],
                      "actions": [{ "type": "forward", "upstream": format!("{},{}", first.address, second.address) }],
                      "response_matchers": [{ "type": "upstream_equals", "value": named.address }],
                      "response_actions_on_match": [{ "type": "static_ip_response", "ip": OTHERWISE.to_string() }] },
                ]},
            ]
        }));
        assert_eq!(
            first_a(&ask(&engine, &query(), peer()).await),
            answer,
            "naming {}",
            named.address
        );
    }
}

/// 回答检查之后跳到别的规则组，那里的转发同样按作答的上游判断
/// A forward in the pipeline an answer check jumps to judges by the upstream that answered too
#[tokio::test]
async fn a_forward_after_a_response_jump_is_checked_against_the_upstream_that_answered() {
    let (quick, slow) = quick_and_slow().await;
    let entry = answering_upstream(Ipv4Addr::new(192, 0, 2, 50), 60).await;
    for (named, answer) in [(&quick, QUICK), (&slow, OTHERWISE)] {
        let engine = engine_from(json!({
            "settings": counting_settings(json!({})),
            "pipelines": [
                { "id": "main", "rules": [
                    { "name": "all", "matchers": [{ "type": "any" }],
                      "actions": [{ "type": "forward", "upstream": entry.address }],
                      "response_actions_on_match": [{ "type": "jump_to_pipeline", "pipeline": "second" }] },
                ]},
                { "id": "second", "rules": [
                    { "name": "all", "matchers": [{ "type": "any" }],
                      "actions": [{ "type": "forward", "upstream": format!("{},{}", quick.address, slow.address) }],
                      "response_matchers": [{ "type": "upstream_equals", "value": named.address }],
                      "response_actions_on_miss": [{ "type": "static_ip_response", "ip": OTHERWISE.to_string() }] },
                ]},
            ]
        }));
        assert_eq!(
            first_a(&ask(&engine, &query(), peer()).await),
            Some(answer),
            "naming {}",
            named.address
        );
    }
}
