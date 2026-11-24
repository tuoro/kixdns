//! 快速路径和完整路径一样跟着请求阶段的跳转走：第一条命中的规则或规则缓存给的是跳转时，按目标的键再查响应缓存、编译规则和
//! 规则缓存，至多跳 response_jump_limit 次。以前快速路径遇到跳转就放手，跳转式的配置每个缓存命中都要走异步路径，过载时现成的
//! 应答也成了 SERVFAIL。
//! The fast path follows request-phase jumps as the full path does: when the first rule
//! matching or the rule cache gives a jump, it looks in the response cache, the compiled rules
//! and the rule cache again under the target's keys, up to response_jump_limit jumps. The fast
//! path used to let go at a jump, so with a configuration made of jumps every cache hit took
//! the async path, and under overload an answer at hand turned into SERVFAIL.

use std::net::Ipv4Addr;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use serde_json::{Value, json};

use crate::engine::test_support::{
    answering_upstream, ask, counting_settings, engine_from, first_a, peer,
};
use crate::engine::{Engine, FastPathResponse};

/// 上游的应答 / The upstream's answer
const UPSTREAM: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
/// 静态规则的应答 / The static rule's answer
const STATIC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 80);

fn query(name: &str) -> Vec<u8> {
    let mut query = Message::new(0x4a4a, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    query.to_vec().unwrap()
}

fn rule(name: &str, matcher: Value, action: Value) -> Value {
    json!({ "name": name, "matchers": [matcher], "actions": [action] })
}

fn any() -> Value {
    json!({ "type": "any" })
}

fn jump_to(pipeline: &str) -> Value {
    json!({ "type": "jump_to_pipeline", "pipeline": pipeline })
}

fn answer_static() -> Value {
    json!({ "type": "static_ip_response", "ip": STATIC.to_string() })
}

fn engine_with(settings: Value, pipelines: Value) -> Engine {
    engine_from(json!({ "settings": counting_settings(settings), "pipelines": pipelines }))
}

/// 快速路径给出的应答；交给异步路径时为 None / The answer the fast path gives; None when it
/// hands the request to the async path
fn fast_answer(engine: &Engine, name: &str) -> Option<Vec<u8>> {
    match engine.handle_packet_fast(&query(name), peer()) {
        Some(FastPathResponse::Direct(reply)) => Some(reply.to_vec()),
        Some(FastPathResponse::CacheHit { cached, .. }) => Some(cached.to_vec()),
        Some(FastPathResponse::AsyncNeeded(_)) => None,
        None => panic!("the fast path reads the query"),
    }
}

/// 入口只跳转、目标转发：完整路径答过一次以后，快速路径跟着跳转在目标的键下找到缓存的应答，不再问上游
/// An entry that only jumps and a target that forwards: once the full path has answered, the
/// fast path follows the jump to the answer cached under the target's keys, asking no upstream
#[tokio::test]
async fn the_fast_path_answers_from_the_cache_behind_a_jump() {
    let upstream = answering_upstream(UPSTREAM, 300).await;
    let engine = engine_with(
        json!({}),
        json!([
            { "id": "main", "rules": [rule("jump", any(), jump_to("other"))] },
            { "id": "other", "rules": [rule("all", any(), json!({ "type": "forward", "upstream": upstream.address }))] }
        ]),
    );
    ask(&engine, &query("name.test."), peer()).await;
    let reply = fast_answer(&engine, "name.test.").expect("answered on the fast path");
    assert_eq!(first_a(&reply), Some(UPSTREAM));
    assert_eq!(upstream.queries(), 1);
}

/// 跳到的 pipeline 里的静态规则：快速路径头一次就答上，不用先走完整路径
/// A static rule in the pipeline jumped to: the fast path answers it the first time, with no
/// full path before
#[tokio::test]
async fn the_fast_path_answers_a_static_rule_behind_a_jump() {
    let engine = engine_with(
        json!({}),
        json!([
            { "id": "main", "rules": [rule("jump", any(), jump_to("other"))] },
            { "id": "other", "rules": [rule("static", any(), answer_static())] }
        ]),
    );
    let reply = fast_answer(&engine, "name.test.").expect("answered on the fast path");
    assert_eq!(first_a(&reply), Some(STATIC));
}

/// 快速路径不当场求值的规则（这里是 GeoSite 条件）给的跳转，由规则缓存给出：完整路径求值过一次，以后快速路径跟着规则缓存里的
/// 跳转走。以前规则缓存只在带正则条件的 pipeline 里存跳转
/// A jump given by a rule the fast path does not evaluate on the spot (here a GeoSite
/// condition) comes from the rule cache: once the full path has evaluated it, the fast path
/// follows the jump the rule cache keeps. The rule cache used to keep jumps only in a pipeline
/// with regex conditions
#[tokio::test]
async fn the_fast_path_follows_a_jump_the_rule_cache_keeps() {
    let upstream = answering_upstream(UPSTREAM, 300).await;
    let engine = engine_with(
        json!({}),
        json!([
            { "id": "main", "rules": [
                rule("domestic", json!({ "type": "geo_site", "value": "cn" }), jump_to("domestic")),
                rule("rest", any(), answer_static())
            ]},
            { "id": "domestic", "rules": [rule("all", any(), json!({ "type": "forward", "upstream": upstream.address }))] }
        ]),
    );
    let mut cn = crate::matcher::geosite::GeoSiteManager::default();
    cn.load_from_v2ray_string(r#"{"entries":[{"tag":"cn","domains":["domain:example.cn"]}]}"#)
        .expect("load geosite");
    let cn = std::sync::Arc::new(cn);
    engine.change_geo(|geo| geo.geosite = std::sync::Arc::clone(&cn));
    ask(&engine, &query("www.example.cn."), peer()).await;
    let reply = fast_answer(&engine, "www.example.cn.").expect("answered on the fast path");
    assert_eq!(first_a(&reply), Some(UPSTREAM));
    assert_eq!(upstream.queries(), 1);
}

/// 快速路径和完整路径跳的次数一样多：要跳的比 response_jump_limit 多时快速路径交给完整路径，由它回 SERVFAIL；
/// 够跳的就在快速路径上答
/// The fast path jumps as often as the full path: a request wanting more jumps than
/// response_jump_limit goes to the full path, which answers SERVFAIL; one within it is
/// answered on the fast path
#[tokio::test]
async fn the_fast_path_jumps_no_more_than_the_jump_limit() {
    let chain = json!([
        { "id": "main", "rules": [rule("first", any(), jump_to("middle"))] },
        { "id": "middle", "rules": [rule("second", any(), jump_to("last"))] },
        { "id": "last", "rules": [rule("static", any(), answer_static())] }
    ]);
    let short = engine_with(json!({ "response_jump_limit": 1 }), chain.clone());
    assert_eq!(fast_answer(&short, "name.test."), None);
    let full = Message::from_vec(&ask(&short, &query("name.test."), peer()).await).unwrap();
    assert_eq!(full.metadata.response_code, ResponseCode::ServFail);

    let enough = engine_with(json!({ "response_jump_limit": 2 }), chain);
    let reply = fast_answer(&enough, "name.test.").expect("answered on the fast path");
    assert_eq!(first_a(&reply), Some(STATIC));
}
