//! 规则的名字只是日志和面板里的标签，哪条规则已经 continue 过，按它在规则组里的位置记。以前按名字记：两条规则
//! 同名时，前一条 continue 以后后一条也被跳过，请求落到再后面的规则或默认上游。
//! A rule's name is a label for logs and the panel; which rule has continued already is kept by
//! its place in the pipeline. It used to be kept by name: of two rules with one name, the
//! second was skipped as well once the first continued, and the request fell to the rules
//! after it or the default upstream.

use std::net::Ipv4Addr;
use std::str::FromStr;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use serde_json::{Value, json};

use crate::engine::test_support::{
    answering_upstream, ask, counting_settings, engine_from, first_a, peer,
};

const FIRST: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const SECOND: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
const DEFAULT: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 3);
const ENTRY: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 50);

fn query() -> Vec<u8> {
    let mut query = Message::new(0x5a5a, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(
        Name::from_str("name.test.").unwrap(),
        RecordType::A,
    ));
    query.to_vec().unwrap()
}

/// 两条同名规则：前一条问 `first`、拿到回答以后 continue，后一条问 `second`
/// Two rules of one name: the first asks `first` and continues once answered, the second
/// asks `second`
fn namesakes(first: &str, second: &str) -> Value {
    json!([
        { "name": "same", "matchers": [{ "type": "any" }],
          "actions": [{ "type": "forward", "upstream": first }],
          "response_actions_on_match": [{ "type": "continue" }] },
        { "name": "same", "matchers": [{ "type": "any" }],
          "actions": [{ "type": "forward", "upstream": second }] },
    ])
}

/// 前一条 continue 以后，轮到同名的后一条 / Once the first continues its namesake has its turn
#[tokio::test]
async fn a_rule_that_continues_leaves_its_namesake_its_turn() {
    let first = answering_upstream(FIRST, 60).await;
    let second = answering_upstream(SECOND, 60).await;
    let default = answering_upstream(DEFAULT, 60).await;
    let engine = engine_from(json!({
        "settings": counting_settings(json!({ "default_upstream": default.address })),
        "pipelines": [{ "id": "main", "rules": namesakes(&first.address, &second.address) }]
    }));
    assert_eq!(first_a(&ask(&engine, &query(), peer()).await), Some(SECOND));
}

/// 回答检查跳转过去的规则组里也一样 / The same in a pipeline an answer check jumps to
#[tokio::test]
async fn a_rule_that_continues_after_a_response_jump_leaves_its_namesake_its_turn() {
    let entry = answering_upstream(ENTRY, 60).await;
    let first = answering_upstream(FIRST, 60).await;
    let second = answering_upstream(SECOND, 60).await;
    let default = answering_upstream(DEFAULT, 60).await;
    let engine = engine_from(json!({
        "settings": counting_settings(json!({ "default_upstream": default.address })),
        "pipelines": [
            { "id": "main", "rules": [
                { "name": "all", "matchers": [{ "type": "any" }],
                  "actions": [{ "type": "forward", "upstream": entry.address }],
                  "response_actions_on_match": [{ "type": "jump_to_pipeline", "pipeline": "next" }] },
            ]},
            { "id": "next", "rules": namesakes(&first.address, &second.address) },
        ]
    }));
    assert_eq!(first_a(&ask(&engine, &query(), peer()).await), Some(SECOND));
}

/// 回答阶段从 `main` 起一路跳 `jumps` 次，最后一个规则组回 [`FIRST`]；上限是 `limit`。返回客户端拿到的地址，
/// SERVFAIL 时为 None
/// From `main` the answer phase jumps `jumps` times in a row and the last pipeline answers
/// [`FIRST`], under the limit `limit`. Gives the address the client gets, None for SERVFAIL
async fn after_response_jumps(jumps: usize, limit: u32) -> Option<Ipv4Addr> {
    let entry = answering_upstream(ENTRY, 60).await;
    let forward_then_jump = |to: String| {
        json!({ "name": "all", "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": entry.address }],
                "response_actions_on_match": [{ "type": "jump_to_pipeline", "pipeline": to }] })
    };
    let id = |n: usize| {
        if n == 0 {
            "main".to_string()
        } else {
            format!("p{n}")
        }
    };
    let mut pipelines: Vec<Value> = (0..jumps)
        .map(|n| json!({ "id": id(n), "rules": [forward_then_jump(id(n + 1))] }))
        .collect();
    pipelines.push(json!({ "id": id(jumps), "rules": [
        { "name": "answer", "matchers": [{ "type": "any" }],
          "actions": [{ "type": "static_ip_response", "ip": FIRST.to_string() }] },
    ]}));
    let engine = engine_from(json!({
        "settings": counting_settings(json!({ "response_jump_limit": limit })),
        "pipelines": pipelines
    }));
    let reply = ask(&engine, &query(), peer()).await;
    let rcode = Message::from_bytes(&reply).unwrap().metadata.response_code;
    (rcode != ResponseCode::ServFail).then(|| first_a(&reply).expect("an address"))
}

/// `response_jump_limit` 是回答阶段最多跳几次：N 就是 N 次，第 N+1 次才回 SERVFAIL。以前 N 只让跳 N−1 次，
/// 设成 1 时一次都跳不了
/// `response_jump_limit` is how many times the answer phase may jump: N means N jumps, and
/// the one after that answers SERVFAIL. N used to allow N−1, and 1 allowed none
#[tokio::test]
async fn a_jump_limit_of_n_allows_n_response_jumps() {
    for (jumps, limit, answered) in [
        (1, 0, false),
        (1, 1, true),
        (2, 1, false),
        (2, 2, true),
        (3, 2, false),
        (3, 3, true),
    ] {
        assert_eq!(
            after_response_jumps(jumps, limit).await,
            answered.then_some(FIRST),
            "{jumps} jumps under a limit of {limit}"
        );
    }
}
