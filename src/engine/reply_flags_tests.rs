//! 应答头部的两个位：AD 交给客户端前按它自己问的样子留或去（RFC 6840 第 5.8 节），转发时一律带着 AD；AA 不交出去，
//! KixDNS 转交别人的数据，自己不是权威（RFC 1035 第 4.1.1 节）。
//! Two bits of a reply's header: AD is kept or taken off for each client as it asked (RFC
//! 6840 section 5.8), forwards always asking with AD; AA is never handed on, KixDNS handing
//! on others' data without being the authority (RFC 1035 section 4.1.1).

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use serde_json::json;

use crate::engine::Engine;
use crate::engine::signed_answer_tests::signed;
use crate::engine::test_support::{Upstream, ask, counting_settings, engine_from, upstream};

/// 照 RFC 6840 做的验证型上游：查询带 AD 或 DO 时应答置 AD；它是这个名字的权威，应答都置 AA
/// A validating upstream as RFC 6840 has it: the reply has AD when the query has AD or DO;
/// it is the authority for the name, so every reply has AA
async fn validating() -> Upstream {
    upstream(|query| {
        let question = query.queries[0].clone();
        let mut reply = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
        reply.metadata.recursion_desired = query.metadata.recursion_desired;
        reply.metadata.authoritative = true;
        let dnssec_ok = query
            .edns
            .as_ref()
            .is_some_and(|edns| edns.flags().dnssec_ok);
        reply.metadata.authentic_data = query.metadata.authentic_data || dnssec_ok;
        reply.add_answer(Record::from_rdata(
            question.name().clone(),
            300,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
        ));
        reply.add_query(question);
        if query.edns.is_some() {
            reply.set_edns(Edns::new());
        }
        vec![(Duration::ZERO, reply.to_vec().unwrap())]
    })
    .await
}

fn forwarding_to(upstream: &Upstream) -> Engine {
    engine_from(json!({
        "settings": counting_settings(json!({})),
        "pipelines": [{ "id": "main", "rules": [{
            "name": "all", "matchers": [{ "type": "any" }],
            "actions": [{ "type": "forward", "upstream": upstream.address }]
        }]}]
    }))
}

/// 问 `name` 的 A 记录，`ad` 时置 AD / An A query for `name`, with AD set for `ad`
fn query(name: &str, ad: bool) -> Vec<u8> {
    let mut query = Message::new(0x7171, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.metadata.authentic_data = ad;
    query.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    query.to_vec().unwrap()
}

fn client(last: u8) -> SocketAddr {
    SocketAddr::from(([198, 51, 100, last], 5300))
}

/// 应答的 AD 和 AA / A reply's AD and AA
fn ad_and_aa(reply: &[u8]) -> (bool, bool) {
    (reply[3] & 0x20 != 0, reply[2] & 0x04 != 0)
}

/// 两个客户端先后问同一个名字，一个带 AD、一个不带：各自拿到照自己问的样子的 AD，不论谁先把缓存填上；
/// 上游只问一次。以前看谁先填的缓存：先来的不带 AD，后来带 AD 的也拿到 AD=0
/// Two clients ask for the same name one after the other, one with AD and one without:
/// each gets AD as it asked, whoever filled the cache; the upstream is asked once. It used
/// to depend on who filled the cache: with the first asking without AD, the later one
/// asking with AD got AD=0 too
#[tokio::test]
async fn a_cached_reply_has_ad_as_each_client_asked() {
    for first_asks_ad in [false, true] {
        let up = validating().await;
        let engine = forwarding_to(&up);
        let first = ask(&engine, &query("signed.test.", first_asks_ad), client(1)).await;
        let second = ask(&engine, &query("signed.test.", !first_asks_ad), client(2)).await;
        assert_eq!(
            up.queries(),
            1,
            "first asks AD {first_asks_ad}: one forward"
        );
        assert_eq!(
            ad_and_aa(&first).0,
            first_asks_ad,
            "first asks AD {first_asks_ad}"
        );
        assert_eq!(
            ad_and_aa(&second).0,
            !first_asks_ad,
            "second asks AD {}",
            !first_asks_ad
        );
        assert!(
            up.received()[0].metadata.authentic_data,
            "the forward asks with AD whatever the client did"
        );
    }
}

/// 上游置了 AA，客户端拿到的应答不带 AA：刚转发回来的和缓存里取出的都一样。以前缓存命中也留着 AA=1
/// The upstream sets AA, and the client's reply has none: freshly forwarded and from the
/// cache alike. A cache hit used to keep AA=1
#[tokio::test]
async fn no_reply_claims_to_be_authoritative() {
    let up = validating().await;
    let engine = forwarding_to(&up);
    let forwarded = ask(&engine, &query("auth.test.", false), client(1)).await;
    let cached = ask(&engine, &query("auth.test.", false), client(2)).await;
    assert_eq!(up.queries(), 1);
    assert!(!ad_and_aa(&forwarded).1, "forwarded");
    assert!(!ad_and_aa(&cached).1, "from the cache");
}

/// 签过名的查询原样发给上游，不添 AD：改了一位签名就失效
/// A signed query goes upstream as it is, without AD added: one changed bit breaks the
/// signature
#[tokio::test]
async fn a_signed_query_is_forwarded_without_ad_added() {
    let up = validating().await;
    let engine = forwarding_to(&up);
    ask(&engine, &signed(query("sig.test.", false)), client(1)).await;
    assert!(!up.received()[0].metadata.authentic_data);
}
