//! 取决于上游应答的静态应答（回答检查的动作给出的，或者在上游的应答上 continue、回答检查跳转以后的规则给出的）按它带的 TTL
//! 缓存：记录里最小的，不超过 cache_max_ttl；不带记录的没有自己的 TTL，按 min_ttl。规则直接给出的不进响应缓存，规则下次照样
//! 直接给出；上游失败以后兜底给出的也不进，那只是那一次请求的。按「谁在问」给的静态应答照样缓存，槽位按规则对请求方的判定分开。
//! A static answer that depends on an upstream's answer (given by an answer check's actions,
//! or by the rules after a continue or an answer check's jump on an upstream's answer) is
//! cached for the TTL it carries: the least of its records', at most cache_max_ttl; one
//! without records has no TTL of its own and goes by min_ttl. One the rules give outright
//! stays out of the response cache, the rules giving it again outright; so does one given as
//! a fallback after an upstream failure, which is for that one request. A static answer given
//! by who is asking is cached all the same, its slot kept apart by how the rules judge the
//! requester.

use std::net::Ipv4Addr;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use serde_json::{Value, json};

use crate::engine::Engine;
use crate::engine::test_support::{answering_upstream, ask, engine_from, first_a, peer};

/// 上游的回答 / The upstream's answer
const UPSTREAM_ANSWER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
/// 规则给的地址 / The address the rules give
const STATIC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 5);
/// 这里没有监听，转发过去的都失败 / Nothing listens here, so every forward to it fails
const DEAD_UPSTREAM: &str = "127.0.0.1:9";

fn query() -> Vec<u8> {
    let mut query = Message::new(0x5151, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(
        Name::from_ascii("static.test.").unwrap(),
        RecordType::A,
    ));
    query.to_vec().unwrap()
}

fn engine_with(settings: &Value, pipelines: Value) -> Engine {
    let mut all = json!({ "default_upstream": DEAD_UPSTREAM, "upstream_timeout_ms": 200 });
    for (key, value) in settings.as_object().unwrap() {
        all[key] = value.clone();
    }
    engine_from(json!({ "settings": all, "pipelines": pipelines }))
}

fn rule(name: &str, matcher: Value, actions: Value) -> Value {
    json!({ "name": name, "matchers": [matcher], "actions": actions })
}

fn any() -> Value {
    json!({ "type": "any" })
}

/// 转发给 `upstream`，回答检查执行 `on_match`（没有响应匹配器，每份回答都算通过）
/// Forwarding to `upstream`, the answer check running `on_match` (with no response
/// matchers every answer passes)
fn checked(upstream: &str, on_match: Value) -> Value {
    let mut rule = rule(
        "checked",
        any(),
        json!([{ "type": "forward", "upstream": upstream }]),
    );
    rule["response_actions_on_match"] = on_match;
    rule
}

/// 缓存里每份应答的 TTL / The TTL of every answer in the cache
fn cached_ttls(engine: &Engine) -> Vec<u32> {
    engine
        .cache
        .values()
        .iter()
        .flat_map(|slot| slot.entries().map(|entry| entry.original_ttl))
        .collect()
}

/// 带 TTL 120 的静态 CNAME、带 TTL 300 的静态地址、不带记录的 deny，在不同的设置下缓存多久：回答检查的动作给出的、回答检查
/// continue 或跳转以后的规则给出的都一样。以前一律按 min_ttl：带了 TTL 的也按它缓存，min_ttl 为 0（默认）时谁都不缓存，每次
/// 都要再问一遍上游
/// How long a static CNAME with TTL 120, a static address with TTL 300 and a deny with no
/// records are cached under various settings: given by an answer check's actions, or by the
/// rules after an answer check continued or jumped, alike. It used to go by min_ttl alone: an
/// answer carrying a TTL was cached for min_ttl too, and with min_ttl 0 (the default) none was
/// cached, the upstream asked again every time
#[tokio::test]
async fn a_static_answer_on_an_upstream_answer_is_cached_for_the_ttl_it_carries() {
    let upstream = answering_upstream(UPSTREAM_ANSWER, 600).await.address;
    let cname = json!({ "type": "static_cname_response", "target": "target.test.", "ttl": 120 });
    let address = json!({ "type": "static_ip_response", "ip": STATIC.to_string() });
    let deny = json!({ "type": "deny" });
    let cases = [
        (&cname, json!({}), Some(120)),
        (&cname, json!({ "min_ttl": 600 }), Some(120)),
        (&address, json!({}), Some(300)),
        (&address, json!({ "cache_max_ttl": 100 }), Some(100)),
        (&deny, json!({ "min_ttl": 60 }), Some(60)),
        (&deny, json!({}), None),
    ];
    for (action, settings, cached) in cases {
        let paths = [
            (
                "answer check",
                json!([{ "id": "main", "rules": [checked(&upstream, json!([action]))] }]),
            ),
            (
                "after a continue",
                json!([{ "id": "main", "rules": [
                    checked(&upstream, json!([{ "type": "continue" }])),
                    rule("static", any(), json!([action])),
                ]}]),
            ),
            (
                "after a jump",
                json!([
                    { "id": "main", "rules": [checked(
                        &upstream,
                        json!([{ "type": "jump_to_pipeline", "pipeline": "static" }]),
                    )]},
                    { "id": "static", "rules": [rule("static", any(), json!([action]))] },
                ]),
            ),
        ];
        for (path, pipelines) in paths {
            let engine = engine_with(&settings, pipelines);
            ask(&engine, &query(), peer()).await;
            assert_eq!(
                cached_ttls(&engine),
                Vec::from_iter(cached),
                "{path}: {action} with {settings}"
            );
        }
    }
}

/// 规则直接给出的静态应答不进响应缓存：快速路径、规则缓存下次照样直接给出，记在这条规则名下。请求阶段跳过去以后直接给出的也
/// 一样，哪怕跳之前越过了一份应答：那是目标 pipeline 直接给的，直接进它的请求也照样直接拿到。以前开着 min_ttl 时按它缓存，
/// 之后的请求从响应缓存拿到它，查询日志和规则计数里就没有这条规则
/// A static answer the rules give outright stays out of the response cache: the fast path
/// and the rule cache give it again outright, under its rule. So does one given outright
/// after a request-phase jump, even with an answer passed over before the jump: the target
/// pipeline gives it outright, to the requests entering it directly too. With min_ttl on it
/// used to be cached for min_ttl, later requests taking it from the response cache, absent
/// from the query log and rule counts under the rule
#[tokio::test]
async fn a_static_answer_the_rules_give_outright_is_not_cached() {
    let upstream = answering_upstream(UPSTREAM_ANSWER, 600).await.address;
    for action in [
        json!({ "type": "static_ip_response", "ip": STATIC.to_string() }),
        json!({ "type": "deny" }),
    ] {
        let paths = [
            (
                "outright",
                json!([{ "id": "main", "rules": [rule("static", any(), json!([action]))] }]),
            ),
            (
                "after a request-phase jump",
                json!([
                    { "id": "main", "rules": [
                        checked(&upstream, json!([{ "type": "continue" }])),
                        rule("jump", any(), json!([{ "type": "jump_to_pipeline", "pipeline": "static" }])),
                    ]},
                    { "id": "static", "rules": [rule("static", any(), json!([action]))] },
                ]),
            ),
        ];
        for (path, pipelines) in paths {
            let engine = engine_with(&json!({ "min_ttl": 60 }), pipelines);
            ask(&engine, &query(), peer()).await;
            assert_eq!(cached_ttls(&engine), Vec::<u32>::new(), "{path}: {action}");
        }
    }
}

/// 上游失败以后兜底给出的静态应答交给这一次请求，不进缓存：miss 动作直接给的、miss 动作 continue 到下一条规则给的、miss
/// 动作跳到别的规则组给的都一样。上游恢复以后，下一个请求拿到的是上游的回答。以前按 min_ttl 缓存，这段时间里所有请求方都拿
/// 兜底的那个
/// A static answer given as a fallback after an upstream failure goes to this request and
/// stays out of the cache, whether the miss actions give it, a rule after their continue, or
/// a pipeline they jump to. Once the upstream is back, the next request gets its answer. It
/// used to be cached for min_ttl, every requester getting the fallback meanwhile
#[tokio::test]
async fn a_static_fallback_after_an_upstream_failure_is_not_cached() {
    let fallback = json!([{ "type": "static_ip_response", "ip": STATIC.to_string() }]);
    let failing = |on_miss: Value| {
        let mut rule = rule(
            "failing",
            any(),
            json!([{ "type": "forward", "upstream": DEAD_UPSTREAM }]),
        );
        rule["response_actions_on_miss"] = on_miss;
        rule
    };
    let paths = [
        (
            "the miss actions",
            json!([{ "id": "main", "rules": [failing(fallback.clone())] }]),
        ),
        (
            "a rule after a continue",
            json!([{ "id": "main", "rules": [
                failing(json!([{ "type": "continue" }])),
                rule("fallback", any(), fallback.clone()),
            ]}]),
        ),
        (
            "a pipeline jumped to",
            json!([
                { "id": "main", "rules": [
                    failing(json!([{ "type": "jump_to_pipeline", "pipeline": "fallback" }]))
                ]},
                { "id": "fallback", "rules": [rule("fallback", any(), fallback.clone())] },
            ]),
        ),
    ];
    for (path, pipelines) in paths {
        for settings in [json!({ "min_ttl": 60 }), json!({})] {
            let engine = engine_with(&settings, pipelines.clone());
            assert_eq!(
                first_a(&ask(&engine, &query(), peer()).await),
                Some(STATIC),
                "{path} with {settings}"
            );
            assert_eq!(
                cached_ttls(&engine),
                Vec::<u32>::new(),
                "{path} with {settings}"
            );
        }
    }
}

/// 按客户端地址给不同静态应答的 pipeline，应答照样缓存：槽位按规则对请求方的判定分开（见 `RequesterScope`），判定一样的
/// 请求方共用一份，判定不一样的各有各的。以前这样的 pipeline 的静态应答一律不进缓存
/// A pipeline giving static answers by client address has them cached all the same: slots
/// are kept apart by how the rules judge the requester (see `RequesterScope`), requesters
/// judged alike sharing one and the others having their own. Such a pipeline's static answers
/// used to stay out of the cache altogether
#[tokio::test]
async fn a_static_answer_by_client_address_is_cached_for_the_requesters_judged_alike() {
    let upstream = answering_upstream(UPSTREAM_ANSWER, 600).await;
    let engine = engine_with(
        &json!({}),
        json!([{ "id": "main", "rules": [
            checked(&upstream.address, json!([{ "type": "continue" }])),
            rule(
                "device",
                json!({ "type": "client_ip", "cidr": "10.0.0.1/32" }),
                json!([{ "type": "static_ip_response", "ip": "0.0.0.0" }]),
            ),
            rule(
                "rest",
                any(),
                json!([{ "type": "static_ip_response", "ip": STATIC.to_string() }]),
            ),
        ]}]),
    );
    for (client, answer) in [
        ("10.0.0.1:53000", Ipv4Addr::UNSPECIFIED),
        ("10.0.0.2:53000", STATIC),
        ("10.0.0.3:53000", STATIC),
        ("10.0.0.1:53001", Ipv4Addr::UNSPECIFIED),
    ] {
        assert_eq!(
            first_a(&ask(&engine, &query(), client.parse().unwrap()).await),
            Some(answer),
            "{client}"
        );
    }
    assert_eq!(
        cached_ttls(&engine),
        [300, 300],
        "one answer for 10.0.0.1, one for the rest"
    );
    assert_eq!(
        upstream.queries(),
        2,
        "the requesters judged alike were answered from the cache"
    );
}
