//! 快速路径怎样用规则：先看规则缓存，存着决定的不再求值规则，和完整路径一样；求值时 GeoSite 条件也和完整路径一样判断，
//! 不再把用到它的规则整条交出去。
//! How the fast path uses the rules: the rule cache comes first, and a decision kept there
//! needs no rules evaluated, as on the full path; when evaluating, GeoSite conditions are
//! judged as on the full path too, instead of a rule using them being handed on whole.

use std::sync::Arc;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use serde_json::{Value, json};

use crate::engine::rules::Decision;
use crate::engine::test_support::{
    ask, ask_fast_path_first, counting_settings, engine_from, first_a, peer,
};
use crate::engine::{Engine, FastPathResponse};
use crate::matcher::RequestFacts;
use crate::matcher::geosite::GeoSiteManager;

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
    let mut ads = GeoSiteManager::default();
    ads.load_from_v2ray_string(r#"{"entries":[{"tag":"ads","domains":["domain:ads.example"]}]}"#)
        .expect("load geosite");
    let ads = Arc::new(ads);
    engine.change_geo(|geo| geo.geosite = Arc::clone(&ads));
    engine
}

fn forward_nowhere() -> Value {
    json!({ "type": "forward", "upstream": "127.0.0.1:9" })
}

/// 快速路径给出的应答码；交给异步路径时为 None / The response code the fast path answers; None
/// when it hands the request to the async path
fn fast_rcode(engine: &Engine, name: &str) -> Option<ResponseCode> {
    match engine.handle_packet_fast(&query(name), peer()) {
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

/// 规则缓存存着决定时，快速路径不再求值规则，照存着的决定走：规则会转发的名字，规则缓存里存着跳转时照样当场跟过去，
/// 在目标里答上。以前快速路径先把编译规则求值一遍，才看规则缓存
/// With a decision kept in the rule cache the fast path evaluates no rules and goes by the
/// decision kept: for a name the rules would forward, a jump kept in the rule cache is still
/// followed at once and answered in the target. The fast path used to evaluate the compiled
/// rules before looking in the rule cache
#[tokio::test]
async fn a_decision_in_the_rule_cache_is_taken_without_evaluating_the_rules() {
    let engine = engine_with(
        json!({ "type": "jump_to_pipeline", "pipeline": "blocked" }),
        forward_nowhere(),
        json!([{ "id": "blocked", "rules": [
            { "name": "deny", "matchers": [{ "type": "any" }], "actions": [{ "type": "deny" }] }
        ]}]),
    );
    let state = engine.state.load_full();
    let facts = RequestFacts {
        client_ip: peer().ip(),
        ..RequestFacts::a_query("www.example.com")
    };
    let question = Engine::rule_question(&state, &state.pipeline.pipelines[0], &facts);
    let jump = Decision::Jump {
        pipeline: Arc::from("blocked"),
    };
    engine.insert_rule_cache(&question, jump, None, true);
    assert_eq!(
        fast_rcode(&engine, "www.example.com."),
        Some(ResponseCode::Refused),
        "the jump kept in the rule cache was followed"
    );
}

/// 几个 pipeline 写了同一个 id 时只有第一个生效：没有 pipeline_select 命中时选的、pipeline_select 和跳转按 id 找到的都是
/// 它，快速路径和完整路径答的一样（各用一个引擎，谁也不读对方留下的缓存）
/// Of several pipelines written with one id only the first takes effect: it is what is picked
/// with no pipeline_select matching and what pipeline_select and a jump find by the id, the
/// fast and the full path answering alike (on an engine each, neither reading what the other
/// cached)
#[tokio::test]
async fn of_pipelines_sharing_an_id_the_first_answers_on_either_path() {
    let fixed = |ip: &str| {
        json!({ "id": "main", "rules": [{
            "name": "fixed", "matchers": [{ "type": "any" }],
            "actions": [{ "type": "static_ip_response", "ip": ip }]
        }]})
    };
    let first = std::net::Ipv4Addr::new(192, 0, 2, 1);
    let entry = |rules: Value| json!({ "id": "entry", "rules": rules });
    let jump = json!([{
        "name": "on", "matchers": [{ "type": "any" }],
        "actions": [{ "type": "jump_to_pipeline", "pipeline": "main" }]
    }]);
    let select = json!([{ "pipeline": "main", "matchers": [{ "type": "any" }] }]);
    for (how, pipeline_select, before) in [
        ("picked first", json!([]), None),
        ("pipeline_select", select, Some(entry(json!([])))),
        ("jump", json!([]), Some(entry(jump))),
    ] {
        let pipelines: Vec<Value> = before
            .into_iter()
            .chain([fixed(&first.to_string()), fixed("192.0.2.2")])
            .collect();
        let engine = || {
            engine_from(json!({
                "settings": counting_settings(json!({})),
                "pipeline_select": pipeline_select,
                "pipelines": pipelines
            }))
        };
        let fast = ask_fast_path_first(&engine(), &query("name.test."), peer())
            .await
            .expect("a readable query");
        let full = ask(&engine(), &query("name.test."), peer()).await;
        assert_eq!([first_a(&fast), first_a(&full)], [Some(first); 2], "{how}");
    }
}
