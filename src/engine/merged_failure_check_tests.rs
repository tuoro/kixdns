//! 几个上游一起问、全都回了失败应答（SERVFAIL、REFUSED 等）时，回答检查也要看得到那个应答，和只问一个上游时一样。
//! When several upstreams asked together all reply with a failure (SERVFAIL, REFUSED and the like),
//! the answer checks still see that reply, as they do when one upstream is asked.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::Bytes;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use parking_lot::Mutex;
use serde_json::{Value, json};

use crate::engine::Engine;
use crate::engine::test_support::{
    Throttling, Upstream, answering_upstream, ask, counting_settings, engine_from, first_a, peer,
    silent_upstream, upstream,
};
use crate::observe::{
    CacheHit, CacheHitKind, EngineObserver, RequestContext, RequestOutcome, RuleEvaluated,
    RulePhase, UpstreamOutcome, UpstreamResult,
};

/// 第一次的应答给的地址 / The address the first answer gives
const ANSWER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
/// 备用 pipeline 的上游给的地址 / The address the fallback pipeline's upstream answers
const FALLBACK: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 53);
/// on_miss 给的地址 / The address on_miss answers
const OTHERWISE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 99);

/// 对每个查询都回 `rcode`、不带答案的本机上游 / A local upstream answering every query with
/// `rcode` and no answers
async fn failing(rcode: ResponseCode) -> Upstream {
    upstream(move |query| {
        let mut reply = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
        reply.metadata.recursion_desired = query.metadata.recursion_desired;
        reply.metadata.response_code = rcode;
        reply.add_queries(query.queries.iter().cloned());
        vec![(Duration::ZERO, reply.to_vec().unwrap())]
    })
    .await
}

/// 面板的「上游回 SERVFAIL 或 REFUSED 时改问」备用组：主 pipeline 把请求一起转发给 `upstreams`，
/// 回答是 SERVFAIL 或 REFUSED 时跳到 `fallback`，那里转发给 `backup`
/// The panel's fallback group for 「上游回 SERVFAIL 或 REFUSED 时改问」: the main pipeline forwards
/// to `upstreams` together and jumps to `fallback` on a SERVFAIL or REFUSED answer, where it
/// forwards to `backup`
fn fallback_group(upstreams: &[&str], backup: &str, extra: Value) -> Engine {
    let mut rule = json!({
        "name": "group",
        "matchers": [{ "type": "any" }],
        "actions": [{ "type": "forward", "upstream": upstreams }],
        "response_matchers": [
            { "type": "response_rcode", "value": "SERVFAIL" },
            { "type": "response_rcode", "value": "REFUSED" }
        ],
        "response_matcher_operator": "or",
        "response_actions_on_match": [{ "type": "jump_to_pipeline", "pipeline": "fallback" }]
    });
    for (key, value) in extra.as_object().unwrap() {
        rule[key] = value.clone();
    }
    engine_from(json!({
        "settings": counting_settings(json!({})),
        "pipelines": [
            { "id": "main", "rules": [rule] },
            { "id": "fallback", "rules": [{
                "name": "backup",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": backup }]
            }]}
        ]
    }))
}

/// 问 `name` 的 A 记录 / An A query for `name`
fn query(name: &str) -> Vec<u8> {
    let mut query = Message::new(0x5151, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    query.to_vec().unwrap()
}

fn rcode(reply: &[u8]) -> ResponseCode {
    Message::from_vec(reply).unwrap().metadata.response_code
}

/// 只问一个上游、它回 SERVFAIL：回答检查看到 SERVFAIL，改问备用组
/// One upstream answering SERVFAIL: the answer check sees it and the fallback group is asked
#[tokio::test]
async fn one_upstream_answering_servfail_falls_back() {
    let broken = failing(ResponseCode::ServFail).await;
    let backup = answering_upstream(FALLBACK, 300).await;
    let engine = fallback_group(&[&broken.address], &backup.address, json!({}));

    let reply = ask(&engine, &query("one.test."), peer()).await;
    assert_eq!(first_a(&reply), Some(FALLBACK), "rcode {}", rcode(&reply));
    assert_eq!(backup.queries(), 1);
}

/// 两个上游一起问、都回 SERVFAIL：和只问一个时一样，改问备用组
/// Two upstreams asked together, both answering SERVFAIL: as with one, the fallback group is asked
#[tokio::test]
async fn two_upstreams_answering_servfail_fall_back() {
    let first = failing(ResponseCode::ServFail).await;
    let second = failing(ResponseCode::ServFail).await;
    let backup = answering_upstream(FALLBACK, 300).await;
    let engine = fallback_group(
        &[&first.address, &second.address],
        &backup.address,
        json!({}),
    );

    let reply = ask(&engine, &query("two.test."), peer()).await;
    assert_eq!((first.queries(), second.queries()), (1, 1));
    assert_eq!(first_a(&reply), Some(FALLBACK), "rcode {}", rcode(&reply));
    assert_eq!(backup.queries(), 1);
}

/// 观察者看到的上游结果和回答检查，`refresh` 是不是后台刷新里的
/// The upstream results and answer checks the observer saw, `refresh` telling whether a
/// background refresh did it
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seen {
    Result {
        refresh: bool,
        upstream: String,
        outcome: UpstreamOutcome,
        rcode: Option<ResponseCode>,
    },
    Checked {
        refresh: bool,
        rule: String,
        matched: bool,
    },
    Finished {
        refresh: bool,
    },
    /// 客户端请求拿到的过期缓存是哪一种 / Which kind of stale entry a client request got
    Stale(CacheHitKind),
}

#[derive(Default)]
struct Recorder(Mutex<Vec<Seen>>);

impl Recorder {
    fn take(&self) -> Vec<Seen> {
        std::mem::take(&mut self.0.lock())
    }
}

impl EngineObserver for Recorder {
    fn upstream_result(&self, ctx: &RequestContext<'_>, event: &UpstreamResult<'_>) {
        self.0.lock().push(Seen::Result {
            refresh: ctx.background_refresh,
            upstream: event.upstream.to_string(),
            outcome: event.outcome,
            rcode: event.rcode,
        });
    }

    fn rule_evaluated(&self, ctx: &RequestContext<'_>, event: &RuleEvaluated<'_>) {
        if event.phase == RulePhase::Response {
            self.0.lock().push(Seen::Checked {
                refresh: ctx.background_refresh,
                rule: event.rule.to_string(),
                matched: event.matched,
            });
        }
    }

    fn request_finished(&self, ctx: &RequestContext<'_>, _outcome: &RequestOutcome<'_>) {
        self.0.lock().push(Seen::Finished {
            refresh: ctx.background_refresh,
        });
    }

    fn cache_hit(&self, ctx: &RequestContext<'_>, event: &CacheHit<'_>) {
        if !ctx.background_refresh && event.kind != CacheHitKind::Fresh {
            self.0.lock().push(Seen::Stale(event.kind));
        }
    }
}

/// 同 [`fallback_group`]，只是像面板编译的上游组那样，请求经跳转进入这一组；由 [`Recorder`] 观察，
/// `rule` 覆盖在这一组的规则上，`settings` 覆盖在 [`counting_settings`] 上
/// As [`fallback_group`], except that the request enters the group through a jump, as the
/// panel compiles upstream groups; observed by a [`Recorder`], with `rule` on top of the
/// group's rule and `settings` on top of [`counting_settings`]
fn observed_fallback_group(
    upstreams: &[&str],
    backup: &str,
    rule: Value,
    settings: Value,
) -> (Engine, Arc<Recorder>) {
    let mut group = json!({
        "name": "group",
        "matchers": [{ "type": "any" }],
        "actions": [{ "type": "forward", "upstream": upstreams }],
        "response_matchers": [
            { "type": "response_rcode", "value": "SERVFAIL" },
            { "type": "response_rcode", "value": "REFUSED" }
        ],
        "response_matcher_operator": "or",
        "response_actions_on_match": [{ "type": "jump_to_pipeline", "pipeline": "fallback" }]
    });
    for (key, value) in rule.as_object().unwrap() {
        group[key] = value.clone();
    }
    let config: crate::config::PipelineConfig = serde_json::from_value(json!({
        "settings": counting_settings(settings),
        "pipelines": [
            { "id": "main", "rules": [{
                "name": "route",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "jump_to_pipeline", "pipeline": "group" }]
            }]},
            { "id": "group", "rules": [group] },
            { "id": "fallback", "rules": [{
                "name": "backup",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": backup }]
            }]}
        ]
    }))
    .expect("parse config");
    let recorder = Arc::new(Recorder::default());
    let engine = Engine::builder(
        crate::matcher::RuntimePipelineConfig::from_config(config).expect("build runtime config"),
    )
    .listener_label("test")
    .observer(recorder.clone())
    .build()
    .expect("engine");
    (engine, recorder)
}

/// 先回 TTL 为 1 秒的 [`ANSWER`]、`fail` 置位以后改回 `rcode` 的本机上游
/// A local upstream answering [`ANSWER`] with a one-second TTL, and `rcode` once `fail` is set
async fn answering_then_failing(rcode: ResponseCode, fail: Arc<AtomicBool>) -> Upstream {
    upstream(move |query| {
        let mut reply = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
        reply.metadata.recursion_desired = query.metadata.recursion_desired;
        reply.add_queries(query.queries.iter().cloned());
        if fail.load(Ordering::SeqCst) {
            reply.metadata.response_code = rcode;
        } else {
            reply.add_answer(Record::from_rdata(
                query.queries[0].name().clone(),
                1,
                RData::A(A(ANSWER)),
            ));
        }
        vec![(Duration::ZERO, reply.to_vec().unwrap())]
    })
    .await
}

/// 一个回 REFUSED、一个回 SERVFAIL：同样改问备用组
/// One answering REFUSED and one SERVFAIL: the fallback group is asked just the same
#[tokio::test]
async fn refused_and_servfail_together_fall_back() {
    let refused = failing(ResponseCode::Refused).await;
    let servfail = failing(ResponseCode::ServFail).await;
    let backup = answering_upstream(FALLBACK, 300).await;
    let engine = fallback_group(
        &[&refused.address, &servfail.address],
        &backup.address,
        json!({}),
    );

    let reply = ask(&engine, &query("mixed.test."), peer()).await;
    assert_eq!(first_a(&reply), Some(FALLBACK), "rcode {}", rcode(&reply));
}

/// 一个回 SERVFAIL、另一个根本不回：失败带着那个 SERVFAIL，照样改问备用组
/// One answering SERVFAIL and the other not at all: the failure carries that SERVFAIL, and
/// the fallback group is asked
#[tokio::test]
async fn a_failure_reply_beside_a_transport_error_falls_back() {
    let servfail = failing(ResponseCode::ServFail).await;
    let silent = silent_upstream().await.to_string();
    let backup = answering_upstream(FALLBACK, 300).await;
    let (engine, _) = observed_fallback_group(
        &[&servfail.address, &silent],
        &backup.address,
        json!({}),
        json!({ "upstream_timeout_ms": 300 }),
    );

    let reply = ask(&engine, &query("silent.test."), peer()).await;
    assert_eq!(first_a(&reply), Some(FALLBACK), "rcode {}", rcode(&reply));
}

/// 全是传输出错、没有失败应答：没有东西可带，照旧回 SERVFAIL，不问备用组，回答检查也没执行
/// Transport errors only, no failure reply: nothing is carried, the answer is SERVFAIL as
/// before, the fallback group is not asked and no answer check runs
#[tokio::test]
async fn transport_errors_alone_still_answer_servfail() {
    let first = silent_upstream().await.to_string();
    let second = silent_upstream().await.to_string();
    let backup = answering_upstream(FALLBACK, 300).await;
    let (engine, seen) = observed_fallback_group(
        &[&first, &second],
        &backup.address,
        json!({}),
        json!({ "upstream_timeout_ms": 300 }),
    );

    let reply = ask(&engine, &query("dead.test."), peer()).await;
    assert_eq!(rcode(&reply), ResponseCode::ServFail);
    assert_eq!(backup.queries(), 0);
    let seen = seen.take();
    assert!(
        !seen.iter().any(|seen| matches!(seen, Seen::Checked { .. })),
        "{seen:#?}"
    );
}

/// 失败应答过不了回答检查时，一切照旧：on_miss 在没有应答的情况下执行（不上报回答检查）
/// When a failure reply does not pass the answer check, nothing changes: on_miss runs with
/// no answer (no answer check is reported)
#[tokio::test]
async fn a_failure_reply_the_check_rejects_leaves_on_miss_without_an_answer() {
    let first = failing(ResponseCode::ServFail).await;
    let second = failing(ResponseCode::ServFail).await;
    let backup = answering_upstream(FALLBACK, 300).await;
    let (engine, seen) = observed_fallback_group(
        &[&first.address, &second.address],
        &backup.address,
        json!({
            "response_matchers": [{ "type": "response_rcode", "value": "NXDOMAIN" }],
            "response_actions_on_miss": [{ "type": "static_ip_response", "ip": OTHERWISE.to_string() }]
        }),
        json!({}),
    );

    let reply = ask(&engine, &query("miss.test."), peer()).await;
    assert_eq!(first_a(&reply), Some(OTHERWISE));
    assert_eq!(backup.queries(), 0);
    let seen = seen.take();
    assert!(
        !seen.iter().any(|seen| matches!(seen, Seen::Checked { .. })),
        "{seen:#?}"
    );
}

/// 在 `pipeline` 里给 `qname` 的 A 查询放一条已经过期的 [`ANSWER`] / Puts an expired [`ANSWER`]
/// for `qname` A into `pipeline`
fn cache_expired(engine: &Engine, pipeline: &str, qname: &str) {
    let state = engine.state.load_full();
    let slot = Engine::cache_keys(
        state.cache_namespace(pipeline),
        pipeline,
        qname.as_bytes(),
        RecordType::A,
        DNSClass::IN,
        crate::proto_utils::QueryFlags::RECURSIVE,
        &crate::matcher::RequesterKey::NONE,
        None,
    )
    .slot;
    let name = Name::from_ascii(qname).unwrap();
    let mut reply = Message::new(0, MessageType::Response, OpCode::Query);
    reply.add_query(Query::query(name.clone(), RecordType::A));
    reply.add_answer(Record::from_rdata(name, 0, RData::A(A(ANSWER))));
    // 不带 ECS 的客户端经不写 `ecs` 的转发得到的应答的适用范围 / The reach of an answer a client
    // without ECS gets from a forward without `ecs`
    let mut reach = crate::ecs_scope::EcsReach::default();
    reach.record(
        crate::ecs_scope::ForwardEcs {
            source: crate::ecs_scope::EcsSource::Client,
            sent: crate::ecs_scope::Sent::Absent,
        },
        crate::ecs_scope::ReplyEcs::Absent,
        true,
    );
    engine.insert_dns_cache_entry(
        slot,
        crate::cache::CacheEntry::from_response(
            Bytes::from(reply.to_vec().unwrap()),
            ResponseCode::NoError,
            Some(Arc::from("udp:192.0.2.9:53")),
            qname,
            Arc::from(pipeline),
            u16::from(RecordType::A),
            crate::proto_utils::QueryFlags::RECURSIVE,
            (0, 0),
        )
        .with_reach(reach),
    );
}

/// 失败应答过不了回答检查、也没有 on_miss 时，照旧回上游失败时的过期缓存；检查通过了、但通过以后
/// 没有动作要做时也一样，失败应答不会顶替过期的缓存。请求查缓存时那里还没有条目、等上游时才放进去一条
/// 过期的：这样请求自己去问上游，失败以后才找过期的缓存
/// When a failure reply does not pass the answer check and there is no on_miss, the stale
/// entry still answers the upstream failure; so it does when the check passes with nothing
/// to do after it, and the failure reply never takes the stale entry's place. The cache has
/// no entry when the request looks, and an expired one is put in while it waits on the
/// upstreams: the request asks them itself and looks for a stale entry once they fail
#[tokio::test]
async fn a_failure_reply_with_nothing_to_run_still_serves_stale() {
    let late = || {
        upstream(|query: &Message| {
            let mut reply = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
            reply.metadata.recursion_desired = query.metadata.recursion_desired;
            reply.metadata.response_code = ResponseCode::ServFail;
            reply.add_queries(query.queries.iter().cloned());
            vec![(Duration::from_millis(200), reply.to_vec().unwrap())]
        })
    };
    for rule in [
        json!({ "response_matchers": [{ "type": "response_rcode", "value": "NXDOMAIN" }] }),
        json!({ "response_actions_on_match": [] }),
    ] {
        let (first, second) = (late().await, late().await);
        let backup = answering_upstream(FALLBACK, 300).await;
        let (engine, seen) = observed_fallback_group(
            &[&first.address, &second.address],
            &backup.address,
            rule.clone(),
            json!({ "serve_stale": true, "serve_stale_client_timeout_ms": 0 }),
        );

        let packet = query("stale.test.");
        let (reply, ()) = tokio::join!(ask(&engine, &packet, peer()), async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            cache_expired(&engine, "group", "stale.test");
        });
        assert_eq!(
            first_a(&reply),
            Some(ANSWER),
            "{rule}: rcode {}",
            rcode(&reply)
        );
        let seen = seen.take();
        assert!(
            seen.contains(&Seen::Stale(CacheHitKind::StaleUpstreamFailure)),
            "{rule}: served because the upstreams failed: {seen:#?}"
        );
        assert_eq!(backup.queries(), 0);
    }
}

/// 后台刷新照旧：几个上游都回失败应答时，刷新拿到的是失败，不改问备用组，缓存的条目留着
/// A background refresh is as before: when every upstream replies with a failure, the
/// refresh gets the failure, does not ask the fallback group, and the cached entry stays
#[tokio::test]
async fn a_background_refresh_keeps_the_entry_on_failure_replies() {
    let fail = Arc::new(AtomicBool::new(false));
    let first = answering_then_failing(ResponseCode::ServFail, fail.clone()).await;
    let second = answering_then_failing(ResponseCode::ServFail, fail.clone()).await;
    let backup = answering_upstream(FALLBACK, 300).await;
    let (engine, seen) = observed_fallback_group(
        &[&first.address, &second.address],
        &backup.address,
        json!({}),
        json!({ "min_ttl": 0, "serve_stale": true, "serve_stale_client_timeout_ms": 0 }),
    );

    ask(&engine, &query("kept.test."), peer()).await;
    fail.store(true, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    seen.take();
    // 过期的应答当场交给客户端，同时发起后台刷新 / The stale answer goes to the client at
    // once, and a background refresh starts
    let reply = ask(&engine, &query("kept.test."), peer()).await;
    assert_eq!(first_a(&reply), Some(ANSWER));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut events = Vec::new();
    while !events.contains(&Seen::Finished { refresh: true }) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the refresh finishes: {events:#?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
        events.extend(seen.take());
    }

    assert_eq!(backup.queries(), 0, "{events:#?}");
    assert!(
        events
            .iter()
            .filter(|seen| matches!(seen, Seen::Result { refresh: true, .. }))
            .all(|seen| matches!(
                seen,
                Seen::Result {
                    outcome: UpstreamOutcome::Rejected,
                    ..
                }
            )),
        "{events:#?}"
    );
    let reply = ask(&engine, &query("kept.test."), peer()).await;
    assert_eq!(
        first_a(&reply),
        Some(ANSWER),
        "the entry is still the old answer"
    );
}

/// 带出去的是最先收到的失败应答：回答检查只认 REFUSED 时，先到的 REFUSED 让它改问备用组，先到的
/// SERVFAIL 不会
/// The failure reply carried is the first one received: with an answer check for REFUSED
/// only, a REFUSED arriving first sends it to the fallback group, a SERVFAIL arriving first
/// does not
#[tokio::test]
async fn the_first_failure_reply_is_the_one_checked() {
    let delayed = |rcode: ResponseCode, delay: Duration| {
        upstream(move |query: &Message| {
            let mut reply = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
            reply.metadata.recursion_desired = query.metadata.recursion_desired;
            reply.metadata.response_code = rcode;
            reply.add_queries(query.queries.iter().cloned());
            vec![(delay, reply.to_vec().unwrap())]
        })
    };
    let only_refused =
        json!({ "response_matchers": [{ "type": "response_rcode", "value": "REFUSED" }] });
    let backup = answering_upstream(FALLBACK, 300).await;
    for (first, later, falls_back) in [
        (ResponseCode::Refused, ResponseCode::ServFail, true),
        (ResponseCode::ServFail, ResponseCode::Refused, false),
    ] {
        let early = delayed(first, Duration::ZERO).await;
        let late = delayed(later, Duration::from_millis(200)).await;
        let (engine, _) = observed_fallback_group(
            &[&late.address, &early.address],
            &backup.address,
            only_refused.clone(),
            json!({}),
        );
        let reply = ask(&engine, &query("order.test."), peer()).await;
        assert_eq!(
            first_a(&reply) == Some(FALLBACK),
            falls_back,
            "{first} first: rcode {}",
            rcode(&reply)
        );
    }
}

/// 带出去的失败应答交到客户端手里时（这里回答检查通过后只记日志），一样不带上游的 cookie
/// A carried failure reply that reaches the client (here the check only logs once it
/// passes) carries no upstream cookie either
#[tokio::test]
async fn a_carried_failure_reply_reaches_the_client_without_a_cookie() {
    let with_cookie = || {
        upstream(|query: &Message| {
            let mut reply = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
            reply.metadata.recursion_desired = query.metadata.recursion_desired;
            reply.metadata.response_code = ResponseCode::ServFail;
            reply.add_queries(query.queries.iter().cloned());
            let mut edns = Edns::new();
            edns.options_mut().insert(EdnsOption::Unknown(
                u16::from(EdnsCode::Cookie),
                b"STRANGERSRVCOOKI".to_vec(),
            ));
            reply.edns = Some(edns);
            vec![(Duration::ZERO, reply.to_vec().unwrap())]
        })
    };
    let first = with_cookie().await;
    let second = with_cookie().await;
    let backup = answering_upstream(FALLBACK, 300).await;
    let (engine, _) = observed_fallback_group(
        &[&first.address, &second.address],
        &backup.address,
        json!({ "response_actions_on_match": [{ "type": "log" }] }),
        json!({}),
    );

    // 客户端带 EDNS 来问，回给它的应答才留着 OPT / The client asks with EDNS, so the reply
    // it gets keeps an OPT
    let mut asked = Message::from_vec(&query("cookie.test.")).unwrap();
    asked.edns = Some(Edns::new());
    let reply = Message::from_vec(&ask(&engine, &asked.to_vec().unwrap(), peer()).await).unwrap();
    assert!(reply.edns.is_some(), "{reply:?}");
    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
    assert!(
        reply
            .edns
            .as_ref()
            .is_none_or(|edns| edns.options().get(EdnsCode::Cookie).is_none()),
        "{reply:?}"
    );
}

/// 响应跳转之后的转发也一样：跳进的 pipeline 里几个上游都回 SERVFAIL，它的回答检查照样改问备用组
/// A forward after a response jump is the same: when the upstreams of the pipeline jumped
/// into all answer SERVFAIL, its answer check still sends it to the fallback group
#[tokio::test]
async fn a_forward_after_a_response_jump_falls_back_too() {
    let entry = answering_upstream(ANSWER, 300).await;
    let first = failing(ResponseCode::ServFail).await;
    let second = failing(ResponseCode::ServFail).await;
    let backup = answering_upstream(FALLBACK, 300).await;
    let engine = engine_from(json!({
        "settings": counting_settings(json!({})),
        "pipelines": [
            { "id": "main", "rules": [{
                "name": "hop",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": entry.address }],
                "response_actions_on_match": [{ "type": "jump_to_pipeline", "pipeline": "group" }]
            }]},
            { "id": "group", "rules": [{
                "name": "group",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": [first.address, second.address] }],
                "response_matchers": [{ "type": "response_rcode", "value": "SERVFAIL" }],
                "response_actions_on_match": [{ "type": "jump_to_pipeline", "pipeline": "fallback" }]
            }]},
            { "id": "fallback", "rules": [{
                "name": "backup",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": backup.address }]
            }]}
        ]
    }));

    let reply = ask(&engine, &query("jumped.test."), peer()).await;
    assert_eq!((first.queries(), second.queries()), (1, 1));
    assert_eq!(first_a(&reply), Some(FALLBACK), "rcode {}", rcode(&reply));
}

/// 一组上游去掉暂停的 DoH 上游以后只剩一个时，照旧走单个上游的那条路：它回的 SERVFAIL 是
/// Success，回答检查改问备用组
/// A set left with one upstream once the paused DoH upstream is out still takes the
/// single-upstream path: its SERVFAIL is a Success, and the answer check falls back
#[tokio::test]
async fn a_set_left_with_one_upstream_by_a_doh_pause_takes_the_single_path() {
    let servfail = failing(ResponseCode::ServFail).await;
    let doh = Throttling::spawn(Some("30")).await;
    let backup = answering_upstream(FALLBACK, 300).await;
    let (engine, seen) = observed_fallback_group(
        &[&servfail.address, &doh.url],
        &backup.address,
        json!({}),
        json!({}),
    );
    engine.doh_client.use_plain_http();

    for (name, servfail_outcome) in [
        ("both.test.", UpstreamOutcome::Rejected),
        ("left.test.", UpstreamOutcome::Success),
    ] {
        let reply = ask(&engine, &query(name), peer()).await;
        assert_eq!(
            first_a(&reply),
            Some(FALLBACK),
            "{name}: rcode {}",
            rcode(&reply)
        );
        let seen = seen.take();
        assert!(
            seen.contains(&Seen::Result {
                refresh: false,
                upstream: servfail.address.clone(),
                outcome: servfail_outcome,
                rcode: Some(ResponseCode::ServFail),
            }),
            "{name}: {seen:#?}"
        );
        assert!(
            seen.contains(&Seen::Checked {
                refresh: false,
                rule: "group".to_string(),
                matched: true,
            }),
            "{name}: {seen:#?}"
        );
    }
    assert_eq!(doh.asked(), 1, "the paused DoH upstream was asked once");
}
