//! 失败不进缓存：上游回的失败应答（SERVFAIL、REFUSED、扩展 RCODE，见 `upstream::is_failure_reply`）带着记录也
//! 不缓存，SERVFAIL 不管从哪里来都不缓存（RFC 2308 第 7.1 节最多允许 5 分钟）。规则自己给出的应答照常缓存。
//! Failures stay out of the cache: a failure reply from an upstream (SERVFAIL, REFUSED, an
//! extended RCODE, see `upstream::is_failure_reply`) is not cached even with records in it,
//! and a SERVFAIL is not cached wherever it comes from (RFC 2308 section 7.1 allows five
//! minutes at most). An answer the rules give themselves is cached as before.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, CNAME};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use serde_json::{Value, json};

use crate::engine::Engine;
use crate::engine::test_support::{
    Upstream, answering_upstream, ask, counting_settings, engine_from, first_a, peer, upstream,
};

/// 恢复以后的应答给的地址 / The address answered once recovered
const ANSWER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

fn query(name: &str) -> Vec<u8> {
    let mut query = Message::new(0x6161, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    query.to_vec().unwrap()
}

fn rcode(reply: &[u8]) -> ResponseCode {
    Message::from_vec(reply).unwrap().metadata.response_code
}

/// `failing` 置位时回 `rcode` 加一条 TTL 一天的 CNAME（解析到一半失败时带回的那种），否则回 TTL 300 的 [`ANSWER`]
/// While `failing` is set, `rcode` with a CNAME of a day's TTL (as a resolution failing
/// half way brings back), otherwise [`ANSWER`] with TTL 300
async fn failing_with_records(rcode: ResponseCode, failing: Arc<AtomicBool>) -> Upstream {
    upstream(move |query| {
        let name = query.queries[0].name().clone();
        let mut reply = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
        reply.metadata.recursion_desired = query.metadata.recursion_desired;
        reply.add_queries(query.queries.iter().cloned());
        if failing.load(Ordering::SeqCst) {
            reply.metadata.response_code = rcode;
            reply.add_answer(Record::from_rdata(
                name,
                86400,
                RData::CNAME(CNAME(Name::from_ascii("target.example.").unwrap())),
            ));
        } else {
            reply.add_answer(Record::from_rdata(name, 300, RData::A(A(ANSWER))));
        }
        vec![(Duration::ZERO, reply.to_vec().unwrap())]
    })
    .await
}

fn engine_with(settings: Value, rules: Value) -> Engine {
    engine_from(json!({
        "settings": counting_settings(settings),
        "pipelines": [{ "id": "main", "rules": rules }]
    }))
}

fn forward_to(upstream: &str) -> Value {
    json!({ "name": "forward", "matchers": [{ "type": "any" }], "actions": [{ "type": "forward", "upstream": upstream }] })
}

/// 只写一个上游时，它回的失败应答带着记录也不缓存：上游恢复以后，下一个查询就问到它。以前按记录的 TTL 缓存，
/// 默认设置下最长一天，这期间所有客户端都从缓存拿到 SERVFAIL。正常的应答照旧缓存
/// With a single upstream its failure reply is not cached even with records in it: once
/// the upstream recovers, the next query reaches it. It used to be cached for the
/// records' TTL, up to a day with the defaults, every client getting the SERVFAIL from the
/// cache meanwhile. A normal answer is cached as before
#[tokio::test]
async fn a_failure_reply_with_records_is_not_cached() {
    for failure in [ResponseCode::ServFail, ResponseCode::Refused] {
        let failing = Arc::new(AtomicBool::new(true));
        let up = failing_with_records(failure, failing.clone()).await;
        let engine = engine_with(json!({}), json!([forward_to(&up.address)]));

        let first = ask(&engine, &query("broken.test."), peer()).await;
        assert_eq!(rcode(&first), failure);
        failing.store(false, Ordering::SeqCst);
        let second = ask(&engine, &query("broken.test."), peer()).await;
        assert_eq!(first_a(&second), Some(ANSWER), "{failure}: asked again");
        assert_eq!(up.queries(), 2, "{failure}");
        // 正常的应答写进缓存，第三次不再问上游 / The normal answer is cached: the third query
        // does not reach the upstream
        ask(&engine, &query("broken.test."), peer()).await;
        assert_eq!(up.queries(), 2, "{failure}: the answer is cached");
    }
}

/// 回答动作里那次 forward 拿到的失败应答也一样不缓存
/// A failure reply that a response action's forward gets is not cached either
#[tokio::test]
async fn a_failure_reply_to_a_response_action_forward_is_not_cached() {
    let first = answering_upstream(Ipv4Addr::new(192, 0, 2, 9), 300).await;
    let failing = Arc::new(AtomicBool::new(true));
    let second = failing_with_records(ResponseCode::ServFail, failing.clone()).await;
    let engine = engine_with(
        json!({}),
        json!([{
            "name": "again",
            "matchers": [{ "type": "any" }],
            "actions": [{ "type": "forward", "upstream": first.address }],
            "response_actions_on_match": [{ "type": "forward", "upstream": second.address }]
        }]),
    );

    assert_eq!(
        rcode(&ask(&engine, &query("again.test."), peer()).await),
        ResponseCode::ServFail
    );
    failing.store(false, Ordering::SeqCst);
    let reply = ask(&engine, &query("again.test."), peer()).await;
    assert_eq!(first_a(&reply), Some(ANSWER), "asked again");
    assert_eq!(second.queries(), 2);
}

/// 主上游失败、on_miss 里的备用 forward 也失败时，回答动作得出的 SERVFAIL 不按 min_ttl 缓存：两个上游恢复以后，
/// 下一个查询就问到它们。以前缓存 min_ttl 秒，恢复以后照样回 SERVFAIL
/// When the main upstream fails and the backup forward in on_miss fails too, the SERVFAIL
/// the response actions arrive at is not cached for min_ttl: once both upstreams recover,
/// the next query reaches them. It used to be cached for min_ttl seconds, SERVFAIL after
/// the recovery all the same
#[tokio::test]
async fn a_servfail_from_failed_response_actions_is_not_cached() {
    let main = answering_upstream(ANSWER, 300).await;
    let backup = answering_upstream(Ipv4Addr::new(192, 0, 2, 2), 300).await;
    main.silence(true);
    backup.silence(true);
    let engine = engine_with(
        json!({ "min_ttl": 60, "upstream_timeout_ms": 300 }),
        json!([{
            "name": "with_backup",
            "matchers": [{ "type": "any" }],
            "actions": [{ "type": "forward", "upstream": main.address }],
            "response_actions_on_miss": [{ "type": "forward", "upstream": backup.address }]
        }]),
    );

    let during = ask(&engine, &query("outage.test."), peer()).await;
    assert_eq!(rcode(&during), ResponseCode::ServFail);
    main.silence(false);
    backup.silence(false);
    let (main_before, backup_before) = (main.queries(), backup.queries());
    let after = ask(&engine, &query("outage.test."), peer()).await;
    assert_eq!(first_a(&after), Some(ANSWER), "rcode {}", rcode(&after));
    assert_eq!(
        main.queries(),
        main_before + 1,
        "the main upstream is asked again"
    );
    assert_eq!(backup.queries(), backup_before);
}

/// 规则自己给出的应答照常按 min_ttl 缓存：回答阶段的 deny（REFUSED）就是一例，拦截名单靠它走缓存
/// An answer the rules give themselves is cached for min_ttl as before: a response-phase
/// deny (REFUSED) is one, and blocking relies on it being cached
#[tokio::test]
async fn a_deny_the_rules_give_is_still_cached() {
    let up = answering_upstream(ANSWER, 300).await;
    let engine = engine_with(
        json!({ "min_ttl": 60 }),
        json!([{
            "name": "block_after",
            "matchers": [{ "type": "any" }],
            "actions": [{ "type": "forward", "upstream": up.address }],
            "response_actions_on_match": [{ "type": "deny" }]
        }]),
    );

    for _ in 0..2 {
        let reply = ask(&engine, &query("blocked.test."), peer()).await;
        assert_eq!(rcode(&reply), ResponseCode::Refused);
    }
    assert_eq!(up.queries(), 1, "the second deny came from the cache");
}
