//! DoH 上游回 HTTP 429 以后暂停一会儿：几个上游一起问时，这期间不问它（见
//! `upstream::without_paused`、`DohClient::pause`）。
//! A DoH upstream that answers HTTP 429 pauses for a while: when several upstreams are asked
//! together, it is not asked meanwhile (see `upstream::without_paused`, `DohClient::pause`).

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use parking_lot::Mutex;
use serde_json::{Value, json};

use crate::config::Transport;
use crate::engine::Engine;
use crate::engine::test_support::{
    Throttling, Warnings, answering_upstream_after, ask, counting_settings, first_a, peer, upstream,
};
use crate::matcher::RuntimePipelineConfig;
use crate::observe::{
    EngineObserver, RequestContext, RequestOutcome, UpstreamAttempt, UpstreamOutcome,
    UpstreamResult, UpstreamSkipReason, UpstreamSkipped,
};

/// UDP 上游给的地址 / The address the UDP upstream answers
const ANSWER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

/// UDP 上游晚这么久才答，好让 DoH 的 429 总是先到：不然 UDP 先答，DoH 那一路就被取消了
/// The UDP upstream answers this late, so the DoH 429 always arrives first: otherwise UDP
/// answers first and the DoH attempt is cancelled
const UDP_DELAY: Duration = Duration::from_millis(200);

/// 观察者看到的一件事，`refresh` 是不是后台刷新里的
/// One thing the observer saw, `refresh` telling whether a background refresh did it
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seen {
    Attempt {
        refresh: bool,
        upstream: String,
    },
    Result {
        refresh: bool,
        upstream: String,
        outcome: UpstreamOutcome,
        rcode: Option<ResponseCode>,
        error: Option<String>,
    },
    Skipped {
        refresh: bool,
        upstream: String,
        transport: Transport,
        reason: UpstreamSkipReason,
    },
    Finished {
        refresh: bool,
    },
}

#[derive(Default)]
struct Recorder(Mutex<Vec<Seen>>);

impl Recorder {
    /// 取走到现在为止看到的 / Takes what was seen so far
    fn take(&self) -> Vec<Seen> {
        std::mem::take(&mut self.0.lock())
    }

    /// 对 `upstream` 上报过的结果：哪种、响应码 / The results reported for `upstream`: which, and the
    /// response code
    fn results_of(seen: &[Seen], upstream: &str) -> Vec<(UpstreamOutcome, Option<ResponseCode>)> {
        seen.iter()
            .filter_map(|seen| match seen {
                Seen::Result {
                    upstream: of,
                    outcome,
                    rcode,
                    ..
                } if of == upstream => Some((*outcome, *rcode)),
                _ => None,
            })
            .collect()
    }

    /// 发给 `upstream` 的尝试有几次 / How many attempts went to `upstream`
    fn attempts_at(seen: &[Seen], upstream: &str) -> usize {
        seen.iter()
            .filter(|seen| matches!(seen, Seen::Attempt { upstream: of, .. } if of == upstream))
            .count()
    }

    /// 被跳过的上游 / The upstreams left out
    fn skipped(seen: &[Seen]) -> Vec<String> {
        seen.iter()
            .filter_map(|seen| match seen {
                Seen::Skipped { upstream, .. } => Some(upstream.clone()),
                _ => None,
            })
            .collect()
    }
}

impl EngineObserver for Recorder {
    fn upstream_attempt(&self, ctx: &RequestContext<'_>, event: &UpstreamAttempt<'_>) {
        self.0.lock().push(Seen::Attempt {
            refresh: ctx.background_refresh,
            upstream: event.upstream.to_string(),
        });
    }

    fn upstream_result(&self, ctx: &RequestContext<'_>, event: &UpstreamResult<'_>) {
        self.0.lock().push(Seen::Result {
            refresh: ctx.background_refresh,
            upstream: event.upstream.to_string(),
            outcome: event.outcome,
            rcode: event.rcode,
            error: event.error.map(|error| format!("{error:#}")),
        });
    }

    fn upstream_skipped(&self, ctx: &RequestContext<'_>, event: &UpstreamSkipped<'_>) {
        self.0.lock().push(Seen::Skipped {
            refresh: ctx.background_refresh,
            upstream: event.upstream.to_string(),
            transport: event.transport,
            reason: event.reason,
        });
    }

    fn request_finished(&self, ctx: &RequestContext<'_>, _outcome: &RequestOutcome<'_>) {
        self.0.lock().push(Seen::Finished {
            refresh: ctx.background_refresh,
        });
    }
}

/// 把请求都同时转发给 `upstreams` 的引擎，DoH 走明文 http，由 [`Recorder`] 观察；`settings` 覆盖在
/// [`counting_settings`] 上
/// An engine forwarding everything to `upstreams` together, DoH over plain http, observed
/// by a [`Recorder`]; `settings` go on top of [`counting_settings`]
fn engine(upstreams: &[&str], settings: Value) -> (Engine, Arc<Recorder>) {
    let config: crate::config::PipelineConfig = serde_json::from_value(json!({
        "settings": counting_settings(settings),
        "pipelines": [{ "id": "main", "rules": [{
            "name": "all",
            "matchers": [{ "type": "any" }],
            "actions": [{ "type": "forward", "upstream": upstreams }]
        }]}]
    }))
    .expect("parse config");
    let recorder = Arc::new(Recorder::default());
    let engine =
        Engine::builder(RuntimePipelineConfig::from_config(config).expect("build runtime config"))
            .listener_label("test")
            .observer(recorder.clone())
            .build()
            .expect("engine");
    engine.doh_client.use_plain_http();
    (engine, recorder)
}

/// 问 `name` 的 A 记录 / An A query for `name`
fn query(name: &str) -> Vec<u8> {
    let mut query = Message::new(0x4242, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    query.to_vec().unwrap()
}

fn rcode(reply: &[u8]) -> ResponseCode {
    Message::from_vec(reply).unwrap().metadata.response_code
}

/// 回了 429 的 DoH 上游，下一次合并转发不问它，也不算一次尝试；答案照样从别的上游来。429 那次是
/// Throttled，带着原来的错误原文。以前每次都问它，每次都记一次 Error。
/// A DoH upstream that answered 429 is not asked by the next merged forward, which counts no
/// attempt for it; the answer still comes from the other upstream. The 429 itself is
/// Throttled, with the error text as before. It used to be asked every time, an Error each
/// time.
#[tokio::test]
async fn a_429_leaves_the_doh_upstream_out_of_the_next_merged_forward() {
    let udp = answering_upstream_after(ANSWER, 300, UDP_DELAY).await;
    let doh = Throttling::spawn(Some("30")).await;
    let (engine, seen) = engine(&[&udp.address, &doh.url], json!({}));

    let reply = ask(&engine, &query("first.test."), peer()).await;
    assert_eq!(first_a(&reply), Some(ANSWER));
    assert_eq!(doh.asked(), 1);
    let first = seen.take();
    assert!(
        first.contains(&Seen::Result {
            refresh: false,
            upstream: doh.address.clone(),
            outcome: UpstreamOutcome::Throttled,
            rcode: None,
            error: Some("doh http status 429 Too Many Requests".to_string()),
        }),
        "{first:#?}"
    );
    assert!(Recorder::skipped(&first).is_empty(), "{first:#?}");

    let reply = ask(&engine, &query("second.test."), peer()).await;
    assert_eq!(first_a(&reply), Some(ANSWER));
    assert_eq!(doh.asked(), 1, "the paused DoH upstream is not asked");
    let second = seen.take();
    assert_eq!(
        second
            .iter()
            .filter(|seen| matches!(seen, Seen::Skipped { .. }))
            .collect::<Vec<_>>(),
        vec![&Seen::Skipped {
            refresh: false,
            upstream: doh.address.clone(),
            transport: Transport::Doh,
            reason: UpstreamSkipReason::Throttled,
        }],
        "{second:#?}"
    );
    assert_eq!(
        Recorder::attempts_at(&second, &doh.address),
        0,
        "{second:#?}"
    );
    assert!(
        Recorder::results_of(&second, &doh.address).is_empty(),
        "{second:#?}"
    );
    assert_eq!(
        Recorder::results_of(&second, &udp.address),
        vec![(UpstreamOutcome::Success, Some(ResponseCode::NoError))]
    );
}

/// 一批同时发出的合并转发都碰上 429：只在暂停开始时记一条 warn。以前每个请求记一条「upstream call
/// failed, waiting for others」
/// A burst of merged forwards all meeting 429s logs a single warn, as the pause starts. Each
/// request used to log an "upstream call failed, waiting for others"
#[tokio::test]
async fn a_burst_of_429s_logs_one_warn() {
    let udp = answering_upstream_after(ANSWER, 300, UDP_DELAY).await;
    let doh = Throttling::spawn(None).await;
    let (engine, seen) = engine(&[&udp.address, &doh.url], json!({}));
    let queries: Vec<_> = (0..20).map(|n| query(&format!("burst{n}.test."))).collect();

    let (warnings, guard) = Warnings::capture();
    let replies =
        futures::future::join_all(queries.iter().map(|query| ask(&engine, query, peer()))).await;
    drop(guard);

    assert!(replies.iter().all(|reply| first_a(reply) == Some(ANSWER)));
    let throttled = Recorder::results_of(&seen.take(), &doh.address).len();
    assert!(
        throttled > 1,
        "several 429s came back for one pause: {throttled}"
    );
    let lines = warnings.lines();
    assert_eq!(lines.len(), 1, "{lines:#?}");
    assert!(
        lines[0].contains("DoH upstream answered 429 Too Many Requests"),
        "{}",
        lines[0]
    );
}

/// 只写了一个 DoH 上游时，429 也不再记「single upstream call failed」；客户端拿到 SERVFAIL，那条
/// 「upstream failed」照记
/// With a single DoH upstream a 429 no longer logs "single upstream call failed"; the client
/// gets a SERVFAIL, and its "upstream failed" is logged as before
#[tokio::test]
async fn a_429_from_a_single_upstream_logs_the_failed_request_only() {
    let doh = Throttling::spawn(Some("30")).await;
    let (engine, _) = engine(&[&doh.url], json!({}));

    let (warnings, guard) = Warnings::capture();
    for n in 0..3 {
        ask(&engine, &query(&format!("single{n}.test.")), peer()).await;
    }
    drop(guard);

    let lines = warnings.lines();
    let count = |text: &str| lines.iter().filter(|line| line.contains(text)).count();
    assert_eq!(
        count("DoH upstream answered 429 Too Many Requests"),
        1,
        "{lines:#?}"
    );
    assert_eq!(count("single upstream call failed"), 0, "{lines:#?}");
    assert_eq!(count("upstream failed"), 3, "{lines:#?}");
    assert_eq!(lines.len(), 4, "{lines:#?}");
}

/// 没带 Retry-After 时暂停 1 秒，过了就又一起问
/// Without Retry-After the pause lasts one second, after which it is asked again with the
/// others
#[tokio::test]
async fn a_pause_without_retry_after_ends_after_a_second() {
    let udp = answering_upstream_after(ANSWER, 300, UDP_DELAY).await;
    let doh = Throttling::spawn(None).await;
    let (engine, seen) = engine(&[&udp.address, &doh.url], json!({}));

    ask(&engine, &query("one.test."), peer()).await;
    ask(&engine, &query("two.test."), peer()).await;
    assert_eq!(doh.asked(), 1, "paused right after the 429");
    assert_eq!(Recorder::skipped(&seen.take()), vec![doh.address.clone()]);

    tokio::time::sleep(Duration::from_millis(1_100)).await;
    ask(&engine, &query("three.test."), peer()).await;
    assert_eq!(doh.asked(), 2, "asked again once the second is over");
    let after = seen.take();
    assert!(Recorder::skipped(&after).is_empty(), "{after:#?}");
    assert_eq!(
        Recorder::results_of(&after, &doh.address),
        vec![(UpstreamOutcome::Throttled, None)]
    );
}

/// 一组上游全都在暂停时，照常全问：暂停只让别的上游来答，不会让一次转发谁都不问
/// While every upstream of a set is paused, all are asked as usual: a pause only lets the
/// others answer, it never leaves a forward with nobody to ask
#[tokio::test]
async fn while_every_upstream_is_paused_all_are_asked() {
    let first = Throttling::spawn(Some("30")).await;
    let second = Throttling::spawn(Some("30")).await;
    let (engine, seen) = engine(&[&first.url, &second.url], json!({}));

    for (round, name) in [(1, "one.test."), (2, "two.test.")] {
        let reply = ask(&engine, &query(name), peer()).await;
        assert_eq!(rcode(&reply), ResponseCode::ServFail);
        assert_eq!((first.asked(), second.asked()), (round, round));
        let events = seen.take();
        assert!(Recorder::skipped(&events).is_empty(), "{events:#?}");
        for doh in [&first, &second] {
            assert_eq!(
                Recorder::results_of(&events, &doh.address),
                vec![(UpstreamOutcome::Throttled, None)]
            );
        }
    }
}

/// 只写了一个 DoH 上游时，它在暂停也照问
/// A forward of one DoH upstream asks it while it is paused too
#[tokio::test]
async fn a_single_doh_upstream_is_asked_while_paused() {
    let doh = Throttling::spawn(Some("30")).await;
    let (engine, seen) = engine(&[&doh.url], json!({}));

    for round in 1..=2 {
        let reply = ask(&engine, &query(&format!("n{round}.test.")), peer()).await;
        assert_eq!(rcode(&reply), ResponseCode::ServFail);
        assert_eq!(doh.asked(), round);
        assert!(engine.doh_client.is_paused(&doh.address));
        let events = seen.take();
        assert!(Recorder::skipped(&events).is_empty(), "{events:#?}");
        assert_eq!(
            Recorder::results_of(&events, &doh.address),
            vec![(UpstreamOutcome::Throttled, None)]
        );
    }
}

/// 去掉暂停的上游以后只剩一个时，这次转发和只写了那一个上游一模一样。看得出来的一处：只有一个上游时
/// 不挑应答，它回的 SERVFAIL 就是这次的应答（Success）；几个一起问时 SERVFAIL 被丢掉（Rejected）
/// A merged forward left with one upstream once the paused one is out forwards exactly as a
/// forward of that one upstream alone. Where it shows: with one upstream no answer is
/// picked over another, so its SERVFAIL is this forward's answer (Success); asked with
/// others, a SERVFAIL is dropped (Rejected)
#[tokio::test]
async fn a_merged_forward_left_with_one_upstream_forwards_as_that_one_alone() {
    let failing = upstream(|query| {
        let mut reply = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
        reply.metadata.recursion_desired = query.metadata.recursion_desired;
        reply.metadata.response_code = ResponseCode::ServFail;
        reply.add_queries(query.queries.iter().cloned());
        vec![(UDP_DELAY, reply.to_vec().unwrap())]
    })
    .await;
    let alone = {
        let (engine, seen) = engine(&[&failing.address], json!({}));
        ask(&engine, &query("alone.test."), peer()).await;
        Recorder::results_of(&seen.take(), &failing.address)
    };
    assert_eq!(
        alone,
        vec![(UpstreamOutcome::Success, Some(ResponseCode::ServFail))]
    );

    let doh = Throttling::spawn(Some("30")).await;
    let (engine, seen) = engine(&[&failing.address, &doh.url], json!({}));
    ask(&engine, &query("together.test."), peer()).await;
    assert_eq!(
        Recorder::results_of(&seen.take(), &failing.address),
        vec![(UpstreamOutcome::Rejected, Some(ResponseCode::ServFail))],
        "asked with the DoH upstream, the SERVFAIL is dropped"
    );
    ask(&engine, &query("left.test."), peer()).await;
    let left = seen.take();
    assert_eq!(Recorder::skipped(&left), vec![doh.address.clone()]);
    assert_eq!(Recorder::results_of(&left, &failing.address), alone);
}

/// 后台刷新也走同一条路：暂停期间刷新不问那个 DoH 上游
/// A background refresh takes the same path: while paused, the refresh does not ask the DoH
/// upstream
#[tokio::test]
async fn a_background_refresh_during_a_pause_leaves_the_upstream_out() {
    let udp = answering_upstream_after(ANSWER, 1, UDP_DELAY).await;
    let doh = Throttling::spawn(Some("30")).await;
    let (engine, seen) = engine(
        &[&udp.address, &doh.url],
        json!({ "min_ttl": 0, "serve_stale": true, "serve_stale_client_timeout_ms": 0 }),
    );

    ask(&engine, &query("stale.test."), peer()).await;
    assert_eq!(doh.asked(), 1);
    // 应答的 TTL 是 1 秒；过期以后再问，拿到过期的应答，同时发起后台刷新
    // The answer's TTL is one second; asked again once it expired, the request gets the
    // stale answer and starts a background refresh
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    seen.take();
    ask(&engine, &query("stale.test."), peer()).await;
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

    assert_eq!(
        doh.asked(),
        1,
        "the refresh did not ask the paused upstream"
    );
    assert!(
        events.contains(&Seen::Skipped {
            refresh: true,
            upstream: doh.address.clone(),
            transport: Transport::Doh,
            reason: UpstreamSkipReason::Throttled,
        }),
        "{events:#?}"
    );
    assert!(
        events.contains(&Seen::Attempt {
            refresh: true,
            upstream: udp.address.clone(),
        }),
        "{events:#?}"
    );
}
