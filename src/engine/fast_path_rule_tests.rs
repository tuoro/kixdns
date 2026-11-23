//! 快速路径怎样用规则：先看规则缓存，存着决定的不再求值规则，和完整路径一样；求值时 GeoSite 条件也和完整路径一样判断，
//! 不再把用到它的规则整条交出去。
//! How the fast path uses the rules: the rule cache comes first, and a decision kept there
//! needs no rules evaluated, as on the full path; when evaluating, GeoSite conditions are
//! judged as on the full path too, instead of a rule using them being handed on whole.

use std::sync::mpsc;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use serde_json::{Value, json};

use crate::engine::test_support::{ask, counting_settings, engine_from, peer};
use crate::engine::{Engine, FastPathResponse};

fn query(name: &str) -> Vec<u8> {
    let mut query = Message::new(0x5b5b, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    query.to_vec().unwrap()
}

/// 名字在 GeoSite 标签 `ads` 里时规则 `ads` 命中，其余照 `rest` 处理
/// The rule `ads` matches a name in the GeoSite tag `ads`, the rest go as `rest` says
fn engine_with(ads: Value, rest: Value, more: Value) -> Engine {
    let mut pipelines = vec![json!({ "id": "main", "rules": [
        { "name": "ads", "matchers": [{ "type": "geo_site", "value": "ads" }], "actions": [ads] },
        { "name": "rest", "matchers": [{ "type": "any" }], "actions": [rest] }
    ]})];
    pipelines.extend(more.as_array().unwrap().iter().cloned());
    let engine = engine_from(json!({
        "settings": counting_settings(json!({})),
        "pipelines": pipelines
    }));
    engine
        .geosite_manager
        .write()
        .load_from_v2ray_string(r#"{"entries":[{"tag":"ads","domains":["domain:ads.example"]}]}"#)
        .expect("load geosite");
    engine
}

fn forward_nowhere() -> Value {
    json!({ "type": "forward", "upstream": "127.0.0.1:9" })
}

/// 快速路径给出的应答码；交给异步路径时为 None / The response code the fast path answers; None
/// when it hands the request to the async path
fn fast_rcode(engine: &Engine, name: &str) -> Option<ResponseCode> {
    match engine
        .handle_packet_fast(&query(name), peer())
        .expect("fast path")
    {
        Some(FastPathResponse::Direct(reply)) => {
            Some(Message::from_vec(&reply).unwrap().metadata.response_code)
        }
        Some(FastPathResponse::AsyncNeeded(_)) => None,
        _ => panic!("the fast path reads the query and has nothing cached"),
    }
}

/// 用 GeoSite 名单拦截的规则在快速路径上当场作答，名单外的名字照旧交给完整路径去转发。以前用到 GeoSite 的规则整条交给
/// 完整路径，`category-ads-all` 这样的规则排在前面时，快速路径每个查询都放手
/// A rule blocking by a GeoSite list is answered on the spot on the fast path, while a name
/// off the list still goes to the full path to be forwarded. A rule using GeoSite used to be
/// handed to the full path whole, and with a rule like `category-ads-all` in front the fast
/// path let go of every query
#[tokio::test]
async fn a_geosite_rule_is_answered_on_the_fast_path() {
    let engine = engine_with(json!({ "type": "deny" }), forward_nowhere(), json!([]));
    assert_eq!(
        fast_rcode(&engine, "track.ads.example."),
        Some(ResponseCode::Refused)
    );
    assert_eq!(fast_rcode(&engine, "example.com."), None);
}

/// 规则缓存存着决定时，快速路径不再求值规则：GeoSite 名单正在写入、读它要等的时候，存着的跳转照样当场跟过去，在目标里
/// 答上。以前快速路径先把编译规则求值一遍，才看规则缓存
/// With a decision kept in the rule cache the fast path evaluates no rules: while the GeoSite
/// lists are being written and reading them would wait, the jump kept there is still followed
/// at once and answered in the target. The fast path used to evaluate the compiled rules before
/// looking in the rule cache
#[tokio::test]
async fn a_decision_in_the_rule_cache_is_taken_without_evaluating_the_rules() {
    let engine = engine_with(
        json!({ "type": "jump_to_pipeline", "pipeline": "blocked" }),
        forward_nowhere(),
        json!([{ "id": "blocked", "rules": [
            { "name": "deny", "matchers": [{ "type": "any" }], "actions": [{ "type": "deny" }] }
        ]}]),
    );
    ask(&engine, &query("track.ads.example."), peer()).await;

    let geosite = engine.geosite_manager.clone();
    let writing = geosite.write();
    let (answered, answer) = mpsc::channel();
    let asking = engine.clone();
    let asker = std::thread::spawn(move || {
        let _ = answered.send(fast_rcode(&asking, "track.ads.example."));
    });
    let rcode = answer.recv_timeout(Duration::from_secs(2));
    drop(writing);
    asker.join().unwrap();
    assert_eq!(
        rcode,
        Ok(Some(ResponseCode::Refused)),
        "answered without reading GeoSite"
    );
}
