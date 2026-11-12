//! 一条规则里的动作按写的顺序执行，先到的那个作数。几个 forward 合成一次转发（同时问所有上游）只在轮到 forward 时
//! 才算：前面已经写了给出回应的动作时，规则给的就是那个回应。以前只要有两个以上 forward，完整路径就直接转发、不看
//! 前面写了什么，而快速路径照第一个动作回静态应答：同一条规则，直接进它的规则组时回静态应答，跳转进来时却去转发。
//! The actions of a rule run in the order written and the first to decide stands. Several
//! forwards merging into one (asking every upstream at once) counts only when a forward's turn
//! comes: with an action that answers written before them, that answer is what the rule gives.
//! With two or more forwards the full path used to forward whatever came before them, while the
//! fast path answered the static first action: one rule gave the static answer to a request
//! entering its pipeline directly and forwarded one that jumped in.

use std::net::Ipv4Addr;
use std::str::FromStr;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use serde_json::{Value, json};

use crate::engine::Engine;
use crate::engine::test_support::{
    answering_upstream, ask, ask_fast_path_first, counting_settings, first_a, peer,
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

/// 一条规则的动作是 `actions` 时客户端拿到的地址：直接进它的规则组（先走快速路径），和从别的规则组跳转进来
/// What the client gets from a rule with `actions`: entering its pipeline directly (the fast
/// path first), and jumping in from another pipeline
async fn answers(actions: Value) -> [Option<Ipv4Addr>; 2] {
    let rule = json!({ "name": "all", "matchers": [{ "type": "any" }], "actions": actions });
    let direct = engine_from(json!({
        "settings": counting_settings(json!({})),
        "pipelines": [{ "id": "main", "rules": [rule.clone()] }]
    }));
    let jumped = engine_from(json!({
        "settings": counting_settings(json!({})),
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
        answers(json!([
            fixed,
            forward(&first.address),
            forward(&second.address)
        ]))
        .await,
        [Some(STATIC); 2]
    );
    // 前面只有日志：照旧合成一次转发 / Only a log before them: merged into one forward as before
    assert_eq!(
        answers(json!([
            log,
            forward(&first.address),
            forward(&second.address)
        ]))
        .await,
        [Some(UPSTREAM); 2]
    );
    // 回应写在 forward 后面：轮不到它 / The answer after the forwards: its turn never comes
    assert_eq!(
        answers(json!([
            forward(&first.address),
            forward(&second.address),
            fixed
        ]))
        .await,
        [Some(UPSTREAM); 2]
    );
}
