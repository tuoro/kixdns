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
use hickory_proto::serialize::binary::BinDecodable;
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

/// 两个请求同时问，先到的响应跳转以后走到 `allow` 规则，问默认上游：后到的等在先到的跳转之前登记的条目上，
/// 拿到它最后的应答
/// Two requests at once, the earlier one reaching an `allow` rule after a response jump and
/// asking the default upstream: the later one waits on the entry the earlier one registered
/// before its jump and gets its final answer
#[tokio::test]
async fn requests_reaching_an_allow_rule_after_a_response_jump_wait_together() {
    let pre = upstream(Duration::ZERO).await;
    let last = upstream(Duration::from_millis(150)).await;
    let engine = engine_from(json!({
        "settings": counting_settings(json!({ "default_upstream": last.address })),
        "pipelines": [
            { "id": "main", "rules": [{
                "name": "r", "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": pre.address }],
                "response_matchers": [{ "type": "upstream_equals", "value": pre.address }],
                "response_actions_on_match": [{ "type": "jump_to_pipeline", "pipeline": "other" }]
            }] },
            { "id": "other", "rules": [{
                "name": "allow", "matchers": [{ "type": "any" }], "actions": [{ "type": "allow" }]
            }] }
        ]
    }));
    assert_eq!(
        ask_at_once(&engine, ["10.0.0.1", "10.0.0.2"]).await,
        [Some(ANSWER), Some(ANSWER)]
    );
    assert_eq!(
        (pre.queries(), last.queries()),
        (1, 1),
        "the second request waited on the first"
    );
}

/// 入口 pipeline 问 `pre`，响应跳转到 `second` 转发给 `last`，`last` 应答以后执行响应动作 `then`；同时来的请求等在先到的
/// 那个跳转之前登记的条目上。`more` 是另外的 pipeline，`settings` 盖在 [`counting_settings`] 上面
/// The entry pipeline asks `pre` and jumps through an answer check to `second`, which forwards
/// to `last`, and once `last` answers the response actions `then` run; requests coming at the
/// same time wait on the entry the earlier one registered before its jump. `more` are further
/// pipelines, `settings` go on top of [`counting_settings`]
fn waiting_on_the_jump_path(
    pre: &Upstream,
    last: &Upstream,
    then: serde_json::Value,
    more: serde_json::Value,
    settings: serde_json::Value,
) -> crate::engine::Engine {
    let mut pipelines = vec![
        json!({ "id": "main", "rules": [{
            "name": "r", "matchers": [{ "type": "any" }],
            "actions": [{ "type": "forward", "upstream": pre.address }],
            "response_matchers": [{ "type": "upstream_equals", "value": pre.address }],
            "response_actions_on_match": [{ "type": "jump_to_pipeline", "pipeline": "second" }]
        }] }),
        json!({ "id": "second", "rules": [{
            "name": "ask", "matchers": [{ "type": "any" }],
            "actions": [{ "type": "forward", "upstream": last.address }],
            "response_matchers": [{ "type": "upstream_equals", "value": last.address }],
            "response_actions_on_match": then
        }] }),
    ];
    pipelines.extend(more.as_array().unwrap().iter().cloned());
    engine_from(json!({
        "settings": counting_settings(settings),
        "pipelines": pipelines
    }))
}

/// 两个请求同时问，各自拿到的应答码和地址 / Two requests at once, and the rcode and address each gets
async fn rcodes_at_once(
    engine: &crate::engine::Engine,
) -> [(hickory_proto::op::ResponseCode, Option<Ipv4Addr>); 2] {
    let packet = query();
    let (one, two) = tokio::join!(
        support::ask(engine, &packet, peer("10.0.0.1")),
        support::ask(engine, &packet, peer("10.0.0.2"))
    );
    let read = |reply: &[u8]| {
        let message = Message::from_bytes(reply).expect("parse reply");
        (message.metadata.response_code, first_a(reply))
    };
    [read(&one), read(&two)]
}

/// 跳转路径上，等着的请求拿到先到的请求最后的应答，不再自己去问 `last`：响应跳转的目标不存在、
/// 规则级跳转的目标不存在、跳转目标给出静态应答、响应动作给出静态应答，都是这样。配置检查会
/// 拒收不存在的跳转目标，这里绕过它直接建引擎
/// After a jump a waiting request gets the earlier request's final answer and does
/// not ask `last` itself: when the response jump's target does not exist, when a
/// rule-level jump's target does not exist, when the jump target answers statically,
/// and when a response action does. The configuration check refuses a missing jump
/// target; the engine is built past it
#[tokio::test]
async fn waiters_on_the_jump_path_get_the_answer_it_ends_in() {
    use hickory_proto::op::ResponseCode;
    let jump = |to: &str| json!([{ "type": "jump_to_pipeline", "pipeline": to }]);
    let cases = [
        (jump("gone"), json!([]), (ResponseCode::ServFail, None)),
        (
            jump("third"),
            json!([{ "id": "third", "rules": [{
                "name": "jump", "matchers": [{ "type": "any" }],
                "actions": [{ "type": "jump_to_pipeline", "pipeline": "gone" }]
            }] }]),
            (ResponseCode::ServFail, None),
        ),
        (
            jump("third"),
            json!([{ "id": "third", "rules": [{
                "name": "static", "matchers": [{ "type": "any" }],
                "actions": [{ "type": "static_ip_response", "ip": "192.0.2.7" }]
            }] }]),
            (ResponseCode::NoError, Some(Ipv4Addr::new(192, 0, 2, 7))),
        ),
        (
            json!([{ "type": "static_ip_response", "ip": "192.0.2.8" }]),
            json!([]),
            (ResponseCode::NoError, Some(Ipv4Addr::new(192, 0, 2, 8))),
        ),
    ];
    for (then, more, expected) in cases {
        let pre = upstream(Duration::ZERO).await;
        let last = upstream(Duration::from_millis(150)).await;
        let case = format!("{then} {more}");
        let engine = waiting_on_the_jump_path(&pre, &last, then, more, json!({}));
        assert_eq!(
            rcodes_at_once(&engine).await,
            [expected, expected],
            "{case}"
        );
        assert_eq!(
            (pre.queries(), last.queries()),
            (1, 1),
            "the second request waited on the first: {case}"
        );
    }
}

/// 跳转以后转发失败（上游不应答），等着的请求拿到先到的请求最后给出的 SERVFAIL，不再自己去问
/// When the forward after the jump fails (the upstream never answers), a waiting request gets
/// the SERVFAIL the earlier request ends in and does not ask itself
#[tokio::test]
async fn waiters_on_the_jump_path_get_the_failure_it_ends_in() {
    use hickory_proto::op::ResponseCode;
    let pre = upstream(Duration::ZERO).await;
    let silent = support::upstream(|_| Vec::new()).await;
    let engine = waiting_on_the_jump_path(
        &pre,
        &silent,
        json!([]),
        json!([]),
        json!({ "upstream_timeout_ms": 900 }),
    );
    for (rcode, _) in rcodes_at_once(&engine).await {
        assert_eq!(rcode, ResponseCode::ServFail);
    }
    assert_eq!(
        silent.queries(),
        2,
        "only the earlier request's two UDP attempts: the later one waited on it"
    );
}

/// 同一个 pipeline 里两个请求同时问：先到的那个转发，应答由响应动作换成静态应答，或者响应跳转到
/// 给静态应答的 pipeline；等着的那个拿到同一个静态应答，不再自己去问
/// Two requests at once in one pipeline: the earlier one forwards and a response action
/// replaces the answer with a static one, or a response jump leads to a pipeline that
/// answers statically; the waiting one gets the same static answer and does not ask itself
#[tokio::test]
async fn waiters_get_the_answer_the_response_actions_end_in() {
    let given = Ipv4Addr::new(192, 0, 2, 9);
    let cases = [
        json!([{ "type": "static_ip_response", "ip": given.to_string() }]),
        json!([{ "type": "jump_to_pipeline", "pipeline": "other" }]),
    ];
    for on_match in cases {
        let up = upstream(Duration::from_millis(150)).await;
        let engine = engine_from(json!({
            "settings": counting_settings(json!({})),
            "pipelines": [
                { "id": "main", "rules": [{
                    "name": "replace", "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "forward", "upstream": up.address }],
                    "response_matchers": [{ "type": "upstream_equals", "value": up.address }],
                    "response_actions_on_match": on_match.clone()
                }] },
                { "id": "other", "rules": [{
                    "name": "static", "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "static_ip_response", "ip": given.to_string() }]
                }] }
            ]
        }));
        assert_eq!(
            ask_at_once(&engine, ["10.0.0.1", "10.0.0.2"]).await,
            [Some(given); 2],
            "{on_match}"
        );
        assert_eq!(
            up.queries(),
            1,
            "the second request waited on the first: {on_match}"
        );
    }
}

/// 同一个 pipeline 里两个请求同时问，上游不应答：先到的那个转发失败以后走 on_miss（没有 on_miss
/// 就是 SERVFAIL），等着的那个拿到同样的结果，不再自己去问
/// Two requests at once in one pipeline and an upstream that never answers: the earlier
/// one's forward fails and the miss actions run (SERVFAIL without any); the waiting one
/// gets the same result and does not ask itself
#[tokio::test]
async fn waiters_get_what_a_failed_forward_ends_in() {
    use hickory_proto::op::ResponseCode;
    let given = Ipv4Addr::new(192, 0, 2, 11);
    let other = upstream(Duration::ZERO).await;
    let cases = [
        (json!([]), (ResponseCode::ServFail, None)),
        (
            json!([{ "type": "forward", "upstream": other.address }]),
            (ResponseCode::NoError, Some(ANSWER)),
        ),
        (
            json!([{ "type": "static_ip_response", "ip": given.to_string() }]),
            (ResponseCode::NoError, Some(given)),
        ),
        (
            json!([{ "type": "jump_to_pipeline", "pipeline": "other" }]),
            (ResponseCode::NoError, Some(given)),
        ),
    ];
    for (on_miss, expected) in cases {
        let silent = support::upstream(|_| Vec::new()).await;
        let engine = engine_from(json!({
            "settings": counting_settings(json!({ "upstream_timeout_ms": 300 })),
            "pipelines": [
                { "id": "main", "rules": [{
                    "name": "ask", "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "forward", "upstream": silent.address }],
                    "response_actions_on_miss": on_miss.clone()
                }] },
                { "id": "other", "rules": [{
                    "name": "static", "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "static_ip_response", "ip": given.to_string() }]
                }] }
            ]
        }));
        let packet = query();
        let (one, two) = tokio::join!(
            support::ask(&engine, &packet, peer("10.0.0.1")),
            support::ask(&engine, &packet, peer("10.0.0.2"))
        );
        let read = |reply: &[u8]| {
            let message = Message::from_bytes(reply).expect("parse reply");
            (message.metadata.response_code, first_a(reply))
        };
        assert_eq!([read(&one), read(&two)], [expected; 2], "{on_miss}");
        // 先到的那个两次 UDP 尝试（见 `upstream::hedge_timeout`）
        // The earlier one's two UDP attempts (see `upstream::hedge_timeout`)
        assert_eq!(
            silent.queries(),
            2,
            "the second request waited on the first: {on_miss}"
        );
    }
    assert_eq!(
        other.queries(),
        1,
        "the miss action's forward was made once"
    );
}

/// 每个应答都带着自己查询的事务 ID：两个请求同时问（后到的等先到的），之后第三个从缓存拿应答，
/// 三个查询的 ID 各不相同
/// Every reply carries its own query's transaction ID: two requests at once (the later
/// waiting on the earlier), then a third answered from the cache, the three queries
/// each with an ID of its own
#[tokio::test]
async fn every_reply_carries_its_own_query_id() {
    let up = upstream(Duration::from_millis(150)).await;
    let engine = engine_from(json!({
        "settings": counting_settings(json!({ "default_upstream": up.address })),
        "pipelines": [{ "id": "main", "rules": [{
            "name": "allow", "matchers": [{ "type": "any" }], "actions": [{ "type": "allow" }]
        }] }]
    }));
    let with_id = |id: u16| {
        let mut packet = query();
        packet[..2].copy_from_slice(&id.to_be_bytes());
        packet
    };
    let id_of = |reply: &[u8]| u16::from_be_bytes([reply[0], reply[1]]);
    let (first, second) = (with_id(0x1111), with_id(0x2222));
    let (one, two) = tokio::join!(
        support::ask(&engine, &first, peer("10.0.0.1")),
        support::ask(&engine, &second, peer("10.0.0.2"))
    );
    let three = support::ask(&engine, &with_id(0x3333), peer("10.0.0.3")).await;
    assert_eq!(up.queries(), 1, "one asked, one waited, one hit the cache");
    assert_eq!(
        [id_of(&one), id_of(&two), id_of(&three)],
        [0x1111, 0x2222, 0x3333]
    );
}

/// 领头的请求被取消（客户端走了、外层先超时），等着它的请求重新排：一个接着去问，其余的等它，上游只多问一次。以前等着的
/// 各自去问，一个领头带着五个等待者走掉，上游就从一次变成六次
/// The leading request is cancelled (its client went away, an outer timeout came first), and those
/// waiting on it line up again: one asks next and the rest wait on it, the upstream asked just once
/// more. Each waiting used to ask by itself, a leader leaving with five waiting turning one query
/// upstream into six
#[tokio::test]
async fn waiters_line_up_again_when_the_leader_is_cancelled() {
    let up = upstream(Duration::from_millis(300)).await;
    let engine = engine_from(json!({
        "settings": counting_settings(json!({ "default_upstream": up.address })),
        "pipelines": [{ "id": "main", "rules": [] }]
    }));
    let packet = query();
    let ask = |client: String| {
        let (engine, packet) = (engine.clone(), packet.clone());
        tokio::spawn(async move { support::ask(&engine, &packet, peer(&client)).await })
    };
    let leader = ask("10.0.0.1".to_string());
    tokio::time::timeout(Duration::from_secs(2), async {
        while up.queries() == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the leader asks the upstream");
    let waiters: Vec<_> = (2..=6).map(|n| ask(format!("10.0.0.{n}"))).collect();
    tokio::time::sleep(Duration::from_millis(50)).await;
    leader.abort();
    for waiter in waiters {
        assert_eq!(first_a(&waiter.await.unwrap()), Some(ANSWER));
    }
    assert_eq!(
        up.queries(),
        2,
        "the leader's question and one more after it left"
    );
}
