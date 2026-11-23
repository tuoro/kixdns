//! 规则缓存替求值给出决定：开着后台刷新时也只按规则对请求方的判定分开，不按客户端地址；求值时执行了 log 动作的决定不进
//! 规则缓存，log 动作每次命中都记下。
//! The rule cache gives decisions in place of evaluating the rules: with background refresh
//! on it is still kept apart by how the rules judge the requester alone, not by client
//! address; a decision whose evaluation ran a log action stays out of it, and the log action
//! records every query it matches.

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use serde_json::{Value, json};

use crate::engine::test_support::{Warnings, ask, ask_like_a_listener, engine_from, peer};
use crate::engine::{Engine, FastPathResponse};

fn query() -> Vec<u8> {
    let mut query = Message::new(0x3131, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(
        Name::from_ascii("rule.test.").unwrap(),
        RecordType::TXT,
    ));
    query.to_vec().unwrap()
}

fn engine_with(settings: Value, actions: Value) -> Engine {
    let mut all = json!({ "default_upstream": "127.0.0.1:9" });
    for (key, value) in settings.as_object().unwrap() {
        all[key] = value.clone();
    }
    engine_from(json!({
        "settings": all,
        "pipelines": [{ "id": "main", "rules": [{
            "name": "rule", "matchers": [{ "type": "any" }], "actions": actions
        }]}]
    }))
}

/// 开着后台刷新时，规则判定一样的客户端照样共用规则缓存里的决定：另一个客户端问同一个名字，快速路径从规则缓存答。以前开着
/// 后台刷新时规则缓存还按客户端地址分开（刷新并不读规则缓存，用不着它），一个名字有多少个客户端问就存多少份，换一个客户端就
/// 要重新求值
/// With background refresh on, clients the rules judge alike still share the rule cache's
/// decision: another client asking the same name is answered from the rule cache on the fast
/// path. With background refresh on the rule cache used to be kept apart by client address
/// too (which the refresh, never reading the rule cache, has no use for), a name stored once
/// per client asking it, and another client meant evaluating again
#[tokio::test]
async fn clients_judged_alike_share_a_rule_decision_with_background_refresh_on() {
    let engine = engine_with(
        json!({ "cache_background_refresh": true }),
        json!([{ "type": "static_txt_response", "text": ["shared"] }]),
    );
    ask(&engine, &query(), "10.0.0.1:53000".parse().unwrap()).await;
    assert!(
        matches!(
            engine.handle_packet_fast(&query(), "10.0.0.2:53000".parse().unwrap()),
            Ok(Some(FastPathResponse::Direct(_)))
        ),
        "the rule cache answers another client"
    );
    assert_eq!(engine.rule_cache.entry_count(), 1);
}

/// 规则的 log 动作每次命中都记下：规则缓存替求值给出决定时不执行规则的动作，所以执行了 log 的决定不进规则缓存。以前只有头一次
/// 记下，之后的查询从规则缓存拿到决定，log 动作不再出声
/// A rule's log action records every query it matches: the rule cache, giving decisions in
/// place of evaluating, runs none of the rules' actions, so a decision that ran a log action is
/// not kept there. Only the first query used to be recorded, the later ones taking the
/// decision from the rule cache with the log action silent
#[tokio::test]
async fn a_log_action_logs_every_query_it_matches() {
    let (warnings, _guard) = Warnings::capture();
    let engine = engine_with(
        json!({}),
        json!([
            { "type": "log", "level": "warn" },
            { "type": "static_txt_response", "text": ["logged"] }
        ]),
    );
    for _ in 0..3 {
        ask_like_a_listener(&engine, &query(), peer()).await;
    }
    let logged = warnings
        .lines()
        .iter()
        .filter(|line| line.contains("matcher_log"))
        .count();
    assert_eq!(logged, 3);
}
