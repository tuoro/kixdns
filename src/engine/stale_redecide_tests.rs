//! 过期应答只在重新取得结果的那一会儿顶着用（RFC 8767）。不管它当初是上游的回答还是规则给的应答，过期以后都要重新
//! 决定一次；重新决定得到的结果不能缓存时，旧应答也不再留着。
//! A stale answer stands in only while a new outcome is being fetched (RFC 8767). Whether it
//! was an upstream's answer or one the rules gave, once expired it is decided again; and when
//! what deciding again gives cannot be cached, the old answer is not kept either.

use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use serde_json::json;

use crate::engine::Engine;
use crate::engine::test_support::{
    answering_upstream, ask, counting_settings, engine_from, first_a, peer, upstream,
};

/// 上游的回答 / The upstream's answer
const REAL: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
/// 上游失败时规则给的地址 / The address the rules give when the upstream fails
const FALLBACK: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 99);

fn query(name: &str) -> Vec<u8> {
    let mut query = Message::new(0x5a5a, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
    query.to_vec().unwrap()
}

/// 一直问到 `settled` 认可为止，最多两秒；返回最后一个应答
/// Asks until `settled` accepts the reply, two seconds at most; gives the last reply
async fn ask_until(engine: &Engine, name: &str, settled: impl Fn(&[u8]) -> bool) -> bytes::Bytes {
    let mut reply = ask(engine, &query(name), peer()).await;
    for _ in 0..40 {
        if settled(&reply) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        reply = ask(engine, &query(name), peer()).await;
    }
    reply
}

/// 上游不通时规则给了一个兜底地址，缓存 1 秒。上游恢复以后它过期了：头一次命中还可以拿它顶着，但要重新去问，之后
/// 拿到的是上游的回答。以前规则给的应答过期以后不再重新决定，每次命中又把它续上，只要一直有人问，兜底地址就一直用下去
/// With the upstream down the rules gave a fallback address, cached for a second. Once the
/// upstream is back and that has expired, the first hit may still be served it but has it
/// asked again, and from then on the upstream's answer comes. An answer the rules gave used
/// not to be decided again once expired, each hit renewing it, so the fallback went on being
/// served for as long as anyone kept asking
#[tokio::test]
async fn a_fallback_given_during_an_outage_is_decided_again_once_it_expires() {
    let up = answering_upstream(REAL, 300).await;
    up.silence(true);
    let engine = engine_from(json!({
        "settings": counting_settings(json!({
            "min_ttl": 1,
            "serve_stale": true,
            "upstream_timeout_ms": 150,
        })),
        "pipelines": [{ "id": "main", "rules": [
            { "name": "all", "matchers": [{ "type": "any" }],
              "actions": [{ "type": "forward", "upstream": up.address }],
              "response_actions_on_miss": [{ "type": "static_ip_response", "ip": FALLBACK.to_string() }] },
        ]}]
    }));
    let during = ask(&engine, &query("name.test."), peer()).await;
    assert_eq!(
        first_a(&during),
        Some(FALLBACK),
        "the rules' answer in the outage"
    );

    up.silence(false);
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let after = ask_until(&engine, "name.test.", |reply| first_a(reply) == Some(REAL)).await;
    assert_eq!(first_a(&after), Some(REAL), "decided again once expired");
}

/// 刷新问到了上游，但拿到的应答不能缓存（这里是没有 SOA 的 NXDOMAIN）：旧应答不再留着，下一个查询自己去问，拿到
/// 上游现在的回答。以前这样的刷新算成功、什么都不写也不删，旧应答每次命中都被当过期应答交出去再续上，上游明明答得上
/// 别的，客户端一直拿旧地址
/// A refresh reaches the upstream but gets an answer that cannot be cached (here NXDOMAIN
/// with no SOA): the old answer is kept no longer, and the next query asks for itself and gets
/// what the upstream says now. Such a refresh used to count as done while writing and removing
/// nothing, the old answer going out stale and being renewed on every hit: with the upstream
/// answering otherwise, clients went on getting the old address
#[tokio::test]
async fn an_answer_a_refresh_cannot_cache_ends_the_old_one() {
    let gone = Arc::new(AtomicBool::new(false));
    let up = {
        let gone = Arc::clone(&gone);
        upstream(move |query| {
            let mut reply = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
            reply.metadata.recursion_desired = query.metadata.recursion_desired;
            reply.add_queries(query.queries.iter().cloned());
            if gone.load(Ordering::SeqCst) {
                reply.metadata.response_code = ResponseCode::NXDomain;
            } else {
                reply.add_answer(Record::from_rdata(
                    query.queries[0].name().clone(),
                    1,
                    RData::A(A(REAL)),
                ));
            }
            vec![(Duration::ZERO, reply.to_vec().unwrap())]
        })
        .await
    };
    let engine = engine_from(json!({
        "settings": counting_settings(json!({
            "default_upstream": up.address,
            "min_ttl": 0,
            "serve_stale": true,
        })),
        "pipelines": []
    }));
    let rcode = |reply: &[u8]| Message::from_vec(reply).unwrap().metadata.response_code;
    let first = ask(&engine, &query("name.test."), peer()).await;
    assert_eq!(first_a(&first), Some(REAL));

    gone.store(true, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let after = ask_until(&engine, "name.test.", |reply| {
        rcode(reply) == ResponseCode::NXDomain
    })
    .await;
    assert_eq!(
        rcode(&after),
        ResponseCode::NXDomain,
        "what the upstream says now"
    );
}

/// 没有 SOA 的 NXDOMAIN：不进缓存 / NXDOMAIN with no SOA, which is not cached
fn nxdomain(query: &Message) -> Vec<u8> {
    let mut reply = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
    reply.metadata.recursion_desired = query.metadata.recursion_desired;
    reply.add_queries(query.queries.iter().cloned());
    reply.metadata.response_code = ResponseCode::NXDomain;
    reply.to_vec().unwrap()
}

/// TTL 1 的 [`REAL`] / [`REAL`] with a TTL of 1
fn real(query: &Message) -> Vec<u8> {
    let mut reply = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
    reply.metadata.recursion_desired = query.metadata.recursion_desired;
    reply.add_queries(query.queries.iter().cloned());
    reply.add_answer(Record::from_rdata(
        query.queries[0].name().clone(),
        1,
        RData::A(A(REAL)),
    ));
    reply.to_vec().unwrap()
}

/// 响应动作里的转发也一样：刷新时它问到的上游给了不能缓存的应答，旧应答不再留着
/// The same with a forward among the response actions: on a refresh the upstream it asks
/// gives an answer that cannot be cached, and the old answer is kept no longer
#[tokio::test]
async fn an_answer_a_response_actions_forward_cannot_cache_ends_the_old_one() {
    let first = answering_upstream(Ipv4Addr::new(192, 0, 2, 7), 1).await;
    let gone = Arc::new(AtomicBool::new(false));
    let second = {
        let gone = Arc::clone(&gone);
        upstream(move |query| {
            let reply = if gone.load(Ordering::SeqCst) {
                nxdomain(query)
            } else {
                real(query)
            };
            vec![(Duration::ZERO, reply)]
        })
        .await
    };
    let engine = engine_from(json!({
        "settings": counting_settings(json!({ "min_ttl": 0, "serve_stale": true })),
        "pipelines": [{ "id": "main", "rules": [
            { "name": "all", "matchers": [{ "type": "any" }],
              "actions": [{ "type": "forward", "upstream": first.address }],
              "response_actions_on_match": [{ "type": "forward", "upstream": second.address }] },
        ]}]
    }));
    let rcode = |reply: &[u8]| Message::from_vec(reply).unwrap().metadata.response_code;
    let before = ask(&engine, &query("name.test."), peer()).await;
    assert_eq!(first_a(&before), Some(REAL), "the second upstream's answer");

    gone.store(true, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let after = ask_until(&engine, "name.test.", |reply| {
        rcode(reply) == ResponseCode::NXDomain
    })
    .await;
    assert_eq!(
        rcode(&after),
        ResponseCode::NXDomain,
        "what the upstream says now"
    );
}

/// 上游失败以后由别的上游兜底、兜底的应答又不能缓存：这是一次失败的刷新，旧应答照旧留着顶着用，不因为兜底的上游说了
/// 别的就丢掉
/// With the upstream failing, another covering for it, and that one's answer not cacheable:
/// this is a failed refresh, and the old answer stays to stand in as before, not thrown away
/// for what the covering upstream says
#[tokio::test]
async fn after_an_upstream_failure_an_uncacheable_fallback_answer_keeps_the_old_one() {
    let primary = upstream(|query| vec![(Duration::ZERO, real(query))]).await;
    let fallback = upstream(|query| vec![(Duration::ZERO, nxdomain(query))]).await;
    let engine = engine_from(json!({
        "settings": counting_settings(json!({
            "min_ttl": 0,
            "serve_stale": true,
            "upstream_timeout_ms": 150,
        })),
        "pipelines": [{ "id": "main", "rules": [
            { "name": "all", "matchers": [{ "type": "any" }],
              "actions": [{ "type": "forward", "upstream": primary.address }],
              "response_actions_on_miss": [{ "type": "forward", "upstream": fallback.address }] },
        ]}]
    }));
    let before = ask(&engine, &query("name.test."), peer()).await;
    assert_eq!(first_a(&before), Some(REAL));

    primary.silence(true);
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let stale = ask(&engine, &query("name.test."), peer()).await;
    assert_eq!(first_a(&stale), Some(REAL), "stale while the refresh runs");
    // 等这次刷新走完：主上游超时，兜底的上游回了 NXDOMAIN / Until that refresh is over: the
    // primary times out and the covering upstream says NXDOMAIN
    let asked = fallback.queries();
    for _ in 0..40 {
        if fallback.queries() > asked {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        fallback.queries() > asked,
        "the refresh reached the fallback"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    let still = ask(&engine, &query("name.test."), peer()).await;
    assert_eq!(first_a(&still), Some(REAL), "the old answer is still there");
}
