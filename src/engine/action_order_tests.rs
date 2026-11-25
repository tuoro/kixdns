//! 一条规则里的动作按写的顺序执行，先到的那个作数。几个 forward 合成一次转发（同时问所有上游）只在轮到 forward 时
//! 才算：前面已经写了给出回应的动作时，规则给的就是那个回应。规则之间也一样只走一遍：continue 以后从被越过的规则的下一条
//! 接着走，写在前面的规则不再执行一遍。
//! The actions of a rule run in the order written and the first to decide stands. Several
//! forwards merging into one (asking every upstream at once) counts only when a forward's turn
//! comes: with an action that answers written before them, that answer is what the rule gives.
//! The rules too are gone through once: after a continue evaluation resumes at the rule after
//! the one continued past, the rules written before it not run a second time.

use std::net::Ipv4Addr;
use std::str::FromStr;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use serde_json::{Value, json};

use crate::engine::Engine;
use crate::engine::test_support::{
    Warnings, answering_upstream, ask, ask_fast_path_first, counting_settings, first_a, peer,
};
use crate::matcher::RuntimePipelineConfig;

const STATIC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 9);
const UPSTREAM: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

fn query() -> Vec<u8> {
    let mut query = Message::new(0x5a5a, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(
        Name::from_str("name.test.").unwrap(),
        RecordType::A,
    ));
    query.to_vec().unwrap()
}

/// 照配置文件的读法建的引擎：几个 forward 的合并是读配置时算好的（`config::parse_config`）
/// An engine built as a configuration file is read: the merge of several forwards is worked
/// out while reading it (`config::parse_config`)
fn engine_from(config: Value) -> Engine {
    let config = crate::config::parse_config(&config.to_string()).expect("parse config");
    Engine::new(
        RuntimePipelineConfig::from_config(config).expect("build runtime config"),
        "test".to_string(),
    )
    .expect("engine")
}

/// 一条规则的动作是 `actions`、设置里另外写了 `settings` 时客户端拿到的地址：直接进它的规则组（先走快速路径），和从
/// 别的规则组跳转进来
/// What the client gets from a rule with `actions`, `settings` written on top: entering its
/// pipeline directly (the fast path first), and jumping in from another pipeline
async fn answers(settings: Value, actions: Value) -> [Option<Ipv4Addr>; 2] {
    let rule = json!({ "name": "all", "matchers": [{ "type": "any" }], "actions": actions });
    let direct = engine_from(json!({
        "settings": counting_settings(settings.clone()),
        "pipelines": [{ "id": "main", "rules": [rule.clone()] }]
    }));
    let jumped = engine_from(json!({
        "settings": counting_settings(settings),
        "pipelines": [
            { "id": "main", "rules": [
                { "name": "on", "matchers": [{ "type": "any" }],
                  "actions": [{ "type": "jump_to_pipeline", "pipeline": "next" }] },
            ]},
            { "id": "next", "rules": [rule] },
        ]
    }));
    let direct = ask_fast_path_first(&direct, &query(), peer())
        .await
        .expect("a readable query");
    let jumped = ask(&jumped, &query(), peer()).await;
    [first_a(&direct), first_a(&jumped)]
}

#[tokio::test]
async fn an_answer_written_before_the_forwards_is_what_the_rule_gives() {
    // 第一个上游不答：合成一次转发时两个一起问，第二个作答；只问第一个的话拿不到应答
    // The first upstream stays silent: merged into one forward both are asked and the second
    // answers, while asking the first alone gets no answer
    let first = answering_upstream(UPSTREAM, 60).await;
    first.silence(true);
    let second = answering_upstream(UPSTREAM, 60).await;
    let forward = |upstream: &str| json!({ "type": "forward", "upstream": upstream });
    let fixed = json!({ "type": "static_ip_response", "ip": STATIC.to_string() });
    let log = json!({ "type": "log", "level": "debug" });

    // 回应写在两个 forward 前面：怎么进来都回它 / The answer before two forwards: given either way in
    assert_eq!(
        answers(
            json!({}),
            json!([fixed, forward(&first.address), forward(&second.address)])
        )
        .await,
        [Some(STATIC); 2]
    );
    // 前面只有日志：照旧合成一次转发 / Only a log before them: merged into one forward as before
    assert_eq!(
        answers(
            json!({}),
            json!([log, forward(&first.address), forward(&second.address)])
        )
        .await,
        [Some(UPSTREAM); 2]
    );
    // 回应写在 forward 后面：轮不到它 / The answer after the forwards: its turn never comes
    assert_eq!(
        answers(
            json!({}),
            json!([forward(&first.address), forward(&second.address), fixed])
        )
        .await,
        [Some(UPSTREAM); 2]
    );
}

/// 没写 upstream 的 forward 问 default_upstream，和别的 forward 合成一次转发时也一样：写了地址的那个不答，默认上游作答，
/// 怎么进来都一样
/// A forward writing no upstream asks default_upstream, merged into one forward with another
/// too: the one written stays silent and the default upstream answers, either way in
#[tokio::test]
async fn a_forward_without_an_upstream_asks_the_default_upstream_in_a_merge_too() {
    let written = answering_upstream(STATIC, 60).await;
    written.silence(true);
    let default = answering_upstream(UPSTREAM, 60).await;
    let settings = json!({ "default_upstream": default.address, "upstream_timeout_ms": 500 });
    assert_eq!(
        answers(
            settings,
            json!([
                { "type": "forward" },
                { "type": "forward", "upstream": written.address }
            ])
        )
        .await,
        [Some(UPSTREAM); 2]
    );
}

/// 合成一次的转发和一个 forward 一样，轮到它时才给出：写在前面的 log 先执行，每个查询都记下。以前合并的转发在执行动作之前就
/// 给出，这样的规则 log 从不出声
/// A merged forward is given when its turn comes, as a single forward is: a log written before
/// it runs first and records every query. The merged forward used to be given before any action
/// ran, and such a rule's log stayed silent
#[tokio::test]
async fn a_log_written_before_the_forwards_logs_every_query() {
    let (warnings, _guard) = Warnings::capture();
    let first = answering_upstream(UPSTREAM, 60).await;
    let second = answering_upstream(UPSTREAM, 60).await;
    let engine = engine_from(json!({
        "settings": counting_settings(json!({})),
        "pipelines": [{ "id": "main", "rules": [{
            "name": "all", "matchers": [{ "type": "any" }],
            "actions": [
                { "type": "log", "level": "warn" },
                { "type": "forward", "upstream": first.address },
                { "type": "forward", "upstream": second.address }
            ]
        }]}]
    }));
    for name in ["one.test.", "two.test."] {
        let mut query = Message::new(0x5b5b, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
        let reply = ask(&engine, &query.to_vec().unwrap(), peer()).await;
        assert_eq!(first_a(&reply), Some(UPSTREAM), "{name}");
    }
    let logged = warnings
        .lines()
        .iter()
        .filter(|line| line.contains("matcher_log"))
        .count();
    assert_eq!(logged, 2);
}

/// log 动作的那条日志说是哪个 Pipeline 的规则、问的什么类型，请求阶段和回答阶段的 log 都一样
/// A log action's line says which pipeline the rule is in and what type is asked, in the
/// request phase and the answer phase alike
#[tokio::test]
async fn a_log_names_the_pipeline_and_the_query_type() {
    let (warnings, _guard) = Warnings::capture();
    let upstream = answering_upstream(UPSTREAM, 60).await;
    let engine = engine_from(json!({
        "settings": counting_settings(json!({})),
        "pipelines": [{ "id": "main", "rules": [{
            "name": "all", "matchers": [{ "type": "any" }],
            "actions": [
                { "type": "log", "level": "warn" },
                { "type": "forward", "upstream": upstream.address }
            ],
            "response_matchers": [{ "type": "response_rcode", "value": "NOERROR" }],
            "response_actions_on_match": [{ "type": "log", "level": "warn" }, { "type": "allow" }]
        }]}]
    }));
    assert_eq!(
        first_a(&ask(&engine, &query(), peer()).await),
        Some(UPSTREAM)
    );
    let logged: Vec<String> = warnings
        .lines()
        .into_iter()
        .filter(|line| line.contains("matcher_log"))
        .collect();
    assert_eq!(logged.len(), 2, "{logged:#?}");
    for line in &logged {
        assert!(
            line.contains(" pipeline=main ") && line.contains(" qtype=A "),
            "{line}"
        );
    }
}

/// continue 以后从被越过的规则的下一条接着走：写在前面、不作决定的规则不再执行一遍，它的 log 一个查询只记一次，不论后面
/// continue 了几次
/// After a continue evaluation resumes at the rule after the one continued past: a rule written
/// before it that decides nothing runs no second time, its log recording a query once however
/// many continues follow
#[tokio::test]
async fn a_log_before_the_continues_logs_a_query_once() {
    let (warnings, _guard) = Warnings::capture();
    let upstream = answering_upstream(UPSTREAM, 60).await;
    let any = json!([{ "type": "any" }]);
    let forward = json!([{ "type": "forward", "upstream": upstream.address }]);
    let checked = |name: &str| {
        json!({
            "name": name, "matchers": any, "actions": forward,
            "response_actions_on_match": [{ "type": "continue" }]
        })
    };
    let engine = engine_from(json!({
        "settings": counting_settings(json!({})),
        "pipelines": [{ "id": "main", "rules": [
            { "name": "log", "matchers": any, "actions": [{ "type": "log", "level": "warn" }] },
            checked("first check"),
            checked("second check"),
            { "name": "forward", "matchers": any, "actions": forward },
        ]}]
    }));
    assert_eq!(
        first_a(&ask(&engine, &query(), peer()).await),
        Some(UPSTREAM)
    );
    let logged = warnings
        .lines()
        .iter()
        .filter(|line| line.contains("matcher_log"))
        .count();
    assert_eq!(logged, 1);
    assert_eq!(upstream.queries(), 3, "each forward asked once");
}

/// 回答阶段的一串动作里写几个 forward 都照写的执行，一个接一个问，最后一个问到的应答作数。以前第五个起每个查询都回
/// SERVFAIL，配置检查却不报
/// However many forwards an answer-phase list writes, each runs as written, asking one after
/// another, and the reply the last one gets stands. From the fifth on every query used to get
/// SERVFAIL, the configuration check reporting nothing
#[tokio::test]
async fn every_forward_an_answer_list_writes_runs() {
    let checked = answering_upstream(UPSTREAM, 60).await;
    let last = answering_upstream(STATIC, 60).await;
    let forward = |upstream: &str| json!({ "type": "forward", "upstream": upstream });
    let mut answer_actions: Vec<Value> = (0..5).map(|_| forward(&checked.address)).collect();
    answer_actions.push(forward(&last.address));
    let engine = engine_from(json!({
        "settings": counting_settings(json!({})),
        "pipelines": [{ "id": "main", "rules": [{
            "name": "all", "matchers": [{ "type": "any" }],
            "actions": [forward(&checked.address)],
            "response_matchers": [{ "type": "response_rcode", "value": "NOERROR" }],
            "response_actions_on_match": answer_actions
        }]}]
    }));
    assert_eq!(first_a(&ask(&engine, &query(), peer()).await), Some(STATIC));
    assert_eq!(
        checked.queries(),
        6,
        "the rule's forward and five in the list"
    );
    assert_eq!(last.queries(), 1);
}
