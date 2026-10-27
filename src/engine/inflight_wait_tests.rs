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

/// 两个客户端经不同的 pipeline 进来，响应跳转以后都在 `second` 转发给 `last`，后到的等先到的；
/// `last` 应答以后执行响应动作 `then`。`more` 是另外的 pipeline，`settings` 盖在
/// [`counting_settings`] 上面
/// Two clients come in through different pipelines and, after a response jump, both
/// forward to `last` in `second`, the later one waiting on the earlier; once `last`
/// answers, the response actions `then` run. `more` are further pipelines, `settings`
/// go on top of [`counting_settings`]
fn waiting_on_the_jump_path(
    pre: &Upstream,
    last: &Upstream,
    then: serde_json::Value,
    more: serde_json::Value,
    settings: serde_json::Value,
) -> crate::engine::Engine {
    let entry = |id: &str| {
        json!({ "id": id, "rules": [{
            "name": "r", "matchers": [{ "type": "any" }],
            "actions": [{ "type": "forward", "upstream": pre.address }],
            "response_matchers": [{ "type": "upstream_equals", "value": pre.address }],
            "response_actions_on_match": [{ "type": "jump_to_pipeline", "pipeline": "second" }]
        }] })
    };
    let mut pipelines = vec![
        entry("a"),
        entry("b"),
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
        "pipeline_select": [
            { "pipeline": "a", "matchers": [{ "type": "client_ip", "cidr": "10.0.0.1/32" }] },
            { "pipeline": "b", "matchers": [{ "type": "client_ip", "cidr": "10.0.0.2/32" }] }
        ],
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
/// On the jump path a waiting request gets the earlier request's final answer and does
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
            pre.queries(),
            2,
            "each entry pipeline asks on its own: {case}"
        );
        assert_eq!(
            last.queries(),
            1,
            "the second request waited on the jump path: {case}"
        );
    }
}

/// 跳转路径上，等着别人的请求拿到应答以后，把它交给等着自己的请求：`a` 的请求先在 `third` 问
/// `last`；`b`、`c` 的请求在 `second` 合并，领头的那个再跳到 `third` 等 `a` 的应答，拿到后交给
/// 等它的那个
/// On the jump path a request waiting on another hands the answer it gets to the
/// requests waiting on it: the request from `a` asks `last` in `third` first; those from
/// `b` and `c` merge in `second`, and the leading one jumps on to `third`, waits for
/// `a`'s answer and hands it to the one waiting on it
#[tokio::test]
async fn a_waiter_on_the_jump_path_hands_what_it_got_to_its_own_waiters() {
    let pre = upstream(Duration::ZERO).await;
    let mid = upstream(Duration::from_millis(100)).await;
    let last = upstream(Duration::from_millis(300)).await;
    let entry = |id: &str, to: &str| {
        json!({ "id": id, "rules": [{
            "name": "r", "matchers": [{ "type": "any" }],
            "actions": [{ "type": "forward", "upstream": pre.address }],
            "response_matchers": [{ "type": "upstream_equals", "value": pre.address }],
            "response_actions_on_match": [{ "type": "jump_to_pipeline", "pipeline": to }]
        }] })
    };
    let engine = engine_from(json!({
        "settings": counting_settings(json!({})),
        "pipeline_select": [
            { "pipeline": "a", "matchers": [{ "type": "client_ip", "cidr": "10.0.0.1/32" }] },
            { "pipeline": "b", "matchers": [{ "type": "client_ip", "cidr": "10.0.0.2/32" }] },
            { "pipeline": "c", "matchers": [{ "type": "client_ip", "cidr": "10.0.0.3/32" }] }
        ],
        "pipelines": [
            entry("a", "third"),
            entry("b", "second"),
            entry("c", "second"),
            { "id": "second", "rules": [{
                "name": "ask", "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": mid.address }],
                "response_matchers": [{ "type": "upstream_equals", "value": mid.address }],
                "response_actions_on_match": [{ "type": "jump_to_pipeline", "pipeline": "third" }]
            }] },
            { "id": "third", "rules": [{
                "name": "ask", "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": last.address }]
            }] }
        ]
    }));
    let packet = query();
    let (one, two, three) = tokio::join!(
        support::ask(&engine, &packet, peer("10.0.0.1")),
        support::ask(&engine, &packet, peer("10.0.0.2")),
        support::ask(&engine, &packet, peer("10.0.0.3"))
    );
    assert_eq!(
        [first_a(&one), first_a(&two), first_a(&three)],
        [Some(ANSWER); 3]
    );
    assert_eq!(pre.queries(), 3, "each entry pipeline asks on its own");
    assert_eq!(
        mid.queries(),
        1,
        "the requests from `b` and `c` merged in `second`"
    );
    assert_eq!(
        last.queries(),
        1,
        "the leader from `second` waited on `a` in `third`"
    );
}

/// 跳转路径上转发失败（上游不应答），等着的请求拿到先到的请求给出的 SERVFAIL，不再自己去问。
/// 跳转路径上的请求最多等上游超时的三分之一（见 `rules::process_response_jump`），所以 `b` 的
/// 请求晚到：在 `a` 的请求失败之前的那三分之一里才到 `second`
/// When the forward on the jump path fails (the upstream never answers), a waiting
/// request gets the SERVFAIL the earlier request ends in and does not ask itself. A
/// request on the jump path waits at most a third of the upstream timeout (see
/// `rules::process_response_jump`), so the one from `b` comes late: it reaches `second`
/// within the third before the one from `a` fails
#[tokio::test]
async fn waiters_on_the_jump_path_get_the_failure_it_ends_in() {
    use hickory_proto::op::ResponseCode;
    // 上游超时 900 ms：`a` 的请求两次 UDP 尝试，300 ms + 900 ms 后失败；`b` 的请求 1050 ms 时才来
    // An upstream timeout of 900 ms: the request from `a` fails after two UDP attempts,
    // 300 ms + 900 ms; the one from `b` only comes at 1050 ms
    let pre = upstream(Duration::ZERO).await;
    let silent = support::upstream(|_| Vec::new()).await;
    let engine = waiting_on_the_jump_path(
        &pre,
        &silent,
        json!([]),
        json!([]),
        json!({ "upstream_timeout_ms": 900 }),
    );
    let packet = query();
    let (one, two) = tokio::join!(support::ask(&engine, &packet, peer("10.0.0.1")), async {
        tokio::time::sleep(Duration::from_millis(1050)).await;
        support::ask(&engine, &packet, peer("10.0.0.2")).await
    });
    for reply in [&one, &two] {
        let message = Message::from_bytes(reply).expect("parse reply");
        assert_eq!(message.metadata.response_code, ResponseCode::ServFail);
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
