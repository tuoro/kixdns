//! RFC 8767 第 5 节的失败复查：一条过期应答的刷新失败以后，30 秒内不再为它发起刷新，命中它的请求直接拿过期应答，
//! 开着 `serve_stale_client_timeout_ms` 也不再等。30 秒过后的头一次命中再试一次。
//! The failure recheck of RFC 8767 section 5: once the refresh of an expired answer fails, no
//! refresh is started for it for 30 seconds, and requests hitting it get the stale answer at
//! once, without waiting even with `serve_stale_client_timeout_ms`. The first hit after the 30
//! seconds tries again.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use parking_lot::Mutex;
use serde_json::{Value, json};

use crate::engine::Engine;
use crate::engine::test_support::{Upstream, ask, counting_settings, first_a, peer, upstream};
use crate::observe::{CacheHit, CacheHitKind, EngineObserver, RequestContext};

/// 上游先给的应答 / The upstream's first answer
const OLD: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
/// 上游恢复以后给的应答 / The upstream's answer once it recovers
const NEW: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);

/// 上游的状态 / The upstream's state
const ANSWERS_OLD: u8 = 0;
const FAILS: u8 = 1;
const SILENT: u8 = 2;
const ANSWERS_NEW: u8 = 3;

/// 按 `state` 作答的上游：TTL 1 的 [`OLD`] 或 [`NEW`]，马上回 SERVFAIL，或者不回
/// An upstream answering by `state`: [`OLD`] or [`NEW`] with TTL 1, SERVFAIL at once, or nothing
async fn scripted(state: Arc<AtomicU8>) -> Upstream {
    upstream(move |query| {
        let mut reply = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
        reply.metadata.recursion_desired = query.metadata.recursion_desired;
        reply.add_queries(query.queries.iter().cloned());
        let address = match state.load(Ordering::SeqCst) {
            SILENT => return Vec::new(),
            FAILS => {
                reply.metadata.response_code = ResponseCode::ServFail;
                return vec![(Duration::ZERO, reply.to_vec().unwrap())];
            }
            ANSWERS_NEW => NEW,
            _ => OLD,
        };
        reply.add_answer(Record::from_rdata(
            query.queries[0].name().clone(),
            1,
            RData::A(A(address)),
        ));
        vec![(Duration::ZERO, reply.to_vec().unwrap())]
    })
    .await
}

/// 记下客户端请求拿到的过期缓存是哪一种 / Records which kind of stale entry client requests got
#[derive(Default)]
struct StaleKinds(Mutex<Vec<CacheHitKind>>);

impl EngineObserver for StaleKinds {
    fn cache_hit(&self, ctx: &RequestContext<'_>, event: &CacheHit<'_>) {
        if !ctx.background_refresh && event.kind != CacheHitKind::Fresh {
            self.0.lock().push(event.kind);
        }
    }
}

fn engine(upstream: &Upstream, settings: Value, kinds: Arc<StaleKinds>) -> Engine {
    let mut all = json!({ "min_ttl": 0, "serve_stale": true });
    all.as_object_mut()
        .unwrap()
        .extend(settings.as_object().unwrap().clone());
    let config: crate::config::PipelineConfig = serde_json::from_value(json!({
        "settings": counting_settings(all),
        "pipelines": [{ "id": "main", "rules": [{
            "name": "all", "matchers": [{ "type": "any" }],
            "actions": [{ "type": "forward", "upstream": upstream.address }]
        }]}]
    }))
    .expect("parse config");
    Engine::builder(
        crate::matcher::RuntimePipelineConfig::from_config(config).expect("build runtime config"),
    )
    .listener_label("test")
    .observer(kinds)
    .build()
    .expect("engine")
}

fn query() -> Vec<u8> {
    let mut query = Message::new(0x8282, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(
        Name::from_ascii("recheck.test.").unwrap(),
        RecordType::A,
    ));
    query.to_vec().unwrap()
}

/// 等这次请求发起的刷新（如果有）结束：刷新标记在请求返回之前就打上了，标记放开时刷新已经结束
/// Waits for the refresh this request started, if any, to end: the refresh mark is set before
/// the request returns, and once it is clear the refresh has ended
async fn refreshes_done(engine: &Engine) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !engine.refreshing_set.is_empty() {
        assert!(Instant::now() < deadline, "the refresh must end");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// 问一次、等它发起的刷新结束，给出拿到的地址 / Asks once and waits for the refresh it started to end,
/// giving the address it got
async fn ask_and_settle(engine: &Engine) -> Option<Ipv4Addr> {
    let reply = ask(engine, &query(), peer()).await;
    refreshes_done(engine).await;
    first_a(&reply)
}

/// 上游很快报错时，过期应答的刷新失败一次以后，接下来的命中都拿过期应答、不再问上游。以前每次命中都再发起一次
/// 刷新，故障期间每个查询都打到坏掉的上游上
/// With an upstream failing fast, once the refresh of the expired answer has failed, the hits
/// that follow get the stale answer and the upstream is not asked again. Every hit used to
/// start another refresh, so during the outage every query reached the broken upstream
#[tokio::test]
async fn a_failed_refresh_is_not_tried_again_at_once() {
    let state = Arc::new(AtomicU8::new(ANSWERS_OLD));
    let up = scripted(state.clone()).await;
    let engine = engine(&up, json!({}), Arc::default());
    assert_eq!(ask_and_settle(&engine).await, Some(OLD));
    state.store(FAILS, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(1_200)).await;

    assert_eq!(ask_and_settle(&engine).await, Some(OLD), "the stale answer");
    assert_eq!(up.queries(), 2, "the first stale hit refreshed once");
    for round in 0..4 {
        assert_eq!(ask_and_settle(&engine).await, Some(OLD), "round {round}");
    }
    assert_eq!(up.queries(), 2, "no refresh since the failure");
}

/// 开着 `serve_stale_client_timeout_ms` 时，上游不应答的刷新失败以后，接下来的请求马上拿到过期应答，记成上游失败时的
/// 那种，也不再问上游。以前每个请求都发起一次新的刷新、再等它失败
/// With `serve_stale_client_timeout_ms`, once a refresh to a silent upstream has failed, the
/// requests that follow get the stale answer at once, recorded as the stale answer of an
/// upstream failure, and the upstream is not asked again. Every request used to start a new
/// refresh and wait for it to fail
#[tokio::test]
async fn after_a_failed_refresh_stale_answers_go_out_without_waiting() {
    let state = Arc::new(AtomicU8::new(ANSWERS_OLD));
    let up = scripted(state.clone()).await;
    let kinds = Arc::new(StaleKinds::default());
    let engine = engine(
        &up,
        json!({ "serve_stale_client_timeout_ms": 1500, "upstream_timeout_ms": 300 }),
        kinds.clone(),
    );
    assert_eq!(ask_and_settle(&engine).await, Some(OLD));
    state.store(SILENT, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(1_200)).await;

    // 头一个请求等刷新失败 / The first request waits for the refresh to fail
    assert_eq!(ask_and_settle(&engine).await, Some(OLD));
    let asked = up.queries();
    for round in 0..3 {
        let started = Instant::now();
        assert_eq!(ask_and_settle(&engine).await, Some(OLD), "round {round}");
        let took = started.elapsed();
        assert!(
            took < Duration::from_millis(100),
            "round {round}: took {took:?}, the refresh failed already"
        );
    }
    assert_eq!(up.queries(), asked, "no refresh since the failure");
    assert_eq!(
        *kinds.0.lock(),
        vec![CacheHitKind::StaleUpstreamFailure; 4],
        "each a stale answer of an upstream failure"
    );
}

/// 30 秒过后的头一次命中再刷新一次：上游恢复了，接下来就是新应答
/// The first hit after the 30 seconds refreshes again: with the upstream back, the new answer
/// follows
#[tokio::test]
async fn the_refresh_is_tried_again_once_the_recheck_time_passes() {
    let state = Arc::new(AtomicU8::new(ANSWERS_OLD));
    let up = scripted(state.clone()).await;
    let engine = engine(&up, json!({}), Arc::default());
    ask_and_settle(&engine).await;
    state.store(FAILS, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    ask_and_settle(&engine).await;
    assert_eq!(up.queries(), 2);

    state.store(ANSWERS_NEW, Ordering::SeqCst);
    // 失败时刻往前挪过复查时间，不必真等 30 秒 / The failure moved back past the recheck time,
    // instead of waiting 30 seconds
    for mut failure in engine.refresh_failures.map.iter_mut() {
        failure.failed_at = failure
            .failed_at
            .checked_sub(super::refresh::REFRESH_FAILURE_RECHECK + Duration::from_secs(1))
            .expect("the clock is far enough from its start");
    }
    assert_eq!(
        ask_and_settle(&engine).await,
        Some(OLD),
        "still the stale answer"
    );
    assert_eq!(up.queries(), 3, "refreshed again");
    assert_eq!(
        ask_and_settle(&engine).await,
        Some(NEW),
        "then the new answer"
    );
    assert!(
        engine.refresh_failures.map.is_empty(),
        "the failure past the recheck time is gone"
    );
}

/// 失败只算在失败的那份应答上：之后从上游重新取得的应答过期了，照常刷新。在 main 上也通过，作为对照
/// A failure counts against the answer that failed only: an answer fetched from the upstream
/// again afterwards is refreshed as usual once it expires. Passes on main too, as a control
#[tokio::test]
async fn a_failure_counts_only_against_the_answer_that_failed() {
    let state = Arc::new(AtomicU8::new(ANSWERS_OLD));
    let up = scripted(state.clone()).await;
    // 过期 1 秒以上的应答不再续用，下一个请求重新转发 / An answer expired over a second ago is no
    // longer served stale, and the next request forwards again
    let engine = engine(&up, json!({ "serve_stale_expire_ttl": 1 }), Arc::default());
    ask_and_settle(&engine).await;
    state.store(FAILS, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    assert_eq!(
        ask_and_settle(&engine).await,
        Some(OLD),
        "stale, refresh failed"
    );
    assert_eq!(up.queries(), 2);

    state.store(ANSWERS_NEW, Ordering::SeqCst);
    // 过期多久按整秒算：过期满 2 秒才算超过 1 秒 / How long it has been expired counts in whole
    // seconds: only 2 of them are past 1
    tokio::time::sleep(Duration::from_millis(2_000)).await;
    assert_eq!(ask_and_settle(&engine).await, Some(NEW), "forwarded afresh");
    assert_eq!(up.queries(), 3);
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    assert_eq!(ask_and_settle(&engine).await, Some(NEW), "stale again");
    assert_eq!(up.queries(), 4, "the new answer was refreshed");
}
