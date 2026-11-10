//! `serve_stale_client_timeout_ms` 大于 0 时，命中过期条目的请求等后台刷新带回新应答；刷新结束却没带回新应答时，
//! 不再等满这段时间，马上交出过期应答。
//! With `serve_stale_client_timeout_ms` above 0 a request hitting an expired entry waits for
//! the background refresh to bring a fresh answer; once the refresh ends without one, it no
//! longer waits the time out and hands out the stale answer at once.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use parking_lot::Mutex;
use serde_json::json;

use crate::engine::Engine;
use crate::engine::test_support::{Upstream, ask, counting_settings, first_a, peer, upstream};
use crate::observe::{CacheHit, CacheHitKind, EngineObserver, RequestContext};

const ANSWER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
/// 客户端最多等这么久 / How long a client waits at most
const CLIENT_WAIT_MS: u64 = 1500;

/// 先回 TTL 1 的 [`ANSWER`]；`failing` 置位以后，`delay` 之后回 SERVFAIL
/// [`ANSWER`] with TTL 1 at first; once `failing` is set, SERVFAIL after `delay`
async fn failing_later(failing: Arc<AtomicBool>, delay: Duration) -> Upstream {
    upstream(move |query| {
        let mut reply = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
        reply.metadata.recursion_desired = query.metadata.recursion_desired;
        reply.add_queries(query.queries.iter().cloned());
        if failing.load(Ordering::SeqCst) {
            reply.metadata.response_code = ResponseCode::ServFail;
            return vec![(delay, reply.to_vec().unwrap())];
        }
        reply.add_answer(Record::from_rdata(
            query.queries[0].name().clone(),
            1,
            RData::A(A(ANSWER)),
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

fn engine(upstream: &Upstream, kinds: Arc<StaleKinds>) -> Engine {
    let config: crate::config::PipelineConfig = serde_json::from_value(json!({
        "settings": counting_settings(json!({
            "min_ttl": 0,
            "serve_stale": true,
            "serve_stale_client_timeout_ms": CLIENT_WAIT_MS
        })),
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
    let mut query = Message::new(0x8181, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(
        Name::from_ascii("stale.test.").unwrap(),
        RecordType::A,
    ));
    query.to_vec().unwrap()
}

/// 上游很快报错时，刷新一结束就交出过期应答，不等满客户端等待的时间；拿到的过期应答记成上游失败时的那种。
/// 以前每个查询都等满 1.5 秒
/// When the upstream fails fast, the stale answer goes out as soon as the refresh ends,
/// without waiting out the client wait, and is recorded as the stale answer of an upstream
/// failure. Every query used to wait the whole 1.5 seconds
#[tokio::test]
async fn a_failed_refresh_ends_the_stale_wait() {
    let failing = Arc::new(AtomicBool::new(false));
    let up = failing_later(failing.clone(), Duration::ZERO).await;
    let kinds = Arc::new(StaleKinds::default());
    let engine = engine(&up, kinds.clone());
    assert_eq!(first_a(&ask(&engine, &query(), peer()).await), Some(ANSWER));
    failing.store(true, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(1_200)).await;

    for round in 0..3 {
        let started = Instant::now();
        let reply = ask(&engine, &query(), peer()).await;
        let took = started.elapsed();
        assert_eq!(
            first_a(&reply),
            Some(ANSWER),
            "round {round}: the stale answer"
        );
        assert!(
            took < Duration::from_millis(500),
            "round {round}: took {took:?}, the refresh had failed long before"
        );
    }
    assert!(
        kinds
            .0
            .lock()
            .iter()
            .all(|kind| *kind == CacheHitKind::StaleUpstreamFailure),
        "{:?}",
        kinds.0.lock()
    );
}

/// 刷新还在等上游时照旧等；客户端等待的时间先到，就按等待超时交出过期应答
/// While the refresh still waits on the upstream the request waits as before; when the
/// client wait runs out first, the stale answer goes out as a client timeout
#[tokio::test]
async fn a_refresh_still_running_is_waited_for() {
    let failing = Arc::new(AtomicBool::new(false));
    // 上游 2 秒后才报错，比客户端等待长 / The upstream fails after 2 s, past the client wait
    let up = failing_later(failing.clone(), Duration::from_secs(2)).await;
    let kinds = Arc::new(StaleKinds::default());
    let engine = engine(&up, kinds.clone());
    ask(&engine, &query(), peer()).await;
    failing.store(true, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(1_200)).await;

    let started = Instant::now();
    let reply = ask(&engine, &query(), peer()).await;
    let took = started.elapsed();
    assert_eq!(first_a(&reply), Some(ANSWER));
    assert!(
        took >= Duration::from_millis(CLIENT_WAIT_MS - 100),
        "took {took:?}: the refresh was still running"
    );
    assert_eq!(*kinds.0.lock(), vec![CacheHitKind::StaleClientTimeout]);
}
