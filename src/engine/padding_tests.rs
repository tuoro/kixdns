//! EDNS 填充（RFC 7830）只在相邻两跳之间有意义：经加密传输发给上游的查询补到 128 字节的整数倍（RFC 8467
//! 第 4.1 节），明文传输上不填充；客户端的填充和上游的填充都不越过自己那一跳。引擎层面的测试。
//! EDNS padding (RFC 7830) means something between two neighbouring hops only: a query sent
//! upstream over an encrypted transport is padded to a multiple of 128 bytes (RFC 8467
//! section 4.1) and none over a cleartext one; neither the client's padding nor the upstream's
//! goes past its own hop. Engine-level tests.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use serde_json::json;

use crate::engine::Engine;
use crate::engine::test_support::{
    self as support, DohReply, counting_settings, engine_from, http_ok, peer, spawn_doh_upstream,
};
use crate::engine::transport::DOH_MEDIA_TYPE;

/// 上游在应答里补的填充，长短随便取的 / The padding the upstream puts in its replies, of an arbitrary length
const UPSTREAM_PADDING: usize = 301;

/// 问 `name` 的 A 记录；`padding` 为 Some 时带 EDNS 和这么长的客户端填充，None 时 EDNS 也不带
/// An A query for `name`; with EDNS and client padding this long for Some, no EDNS at all for None
fn query(name: &str, padding: Option<usize>) -> Vec<u8> {
    let mut query = Message::new(0x4242, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    if let Some(padding) = padding {
        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        edns.options_mut().insert(EdnsOption::Unknown(
            u16::from(EdnsCode::Padding),
            vec![0; padding],
        ));
        query.edns = Some(edns);
    }
    query.to_vec().unwrap()
}

/// `query` 的回答：192.0.2.1；查询带 EDNS 时应答也带，并且像守 RFC 7830 第 4 节的上游那样填充
/// The answer to `query`: 192.0.2.1; with EDNS, and padded as an upstream keeping to RFC 7830
/// section 4 pads it, when the query has EDNS
fn answer(query: &Message) -> Vec<u8> {
    let question = query.queries.first().expect("a question").clone();
    let mut reply = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
    reply.add_answer(Record::from_rdata(
        question.name().clone(),
        300,
        RData::A(A::new(192, 0, 2, 1)),
    ));
    reply.add_query(question);
    if query.edns.is_some() {
        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        edns.options_mut().insert(EdnsOption::Unknown(
            u16::from(EdnsCode::Padding),
            vec![0; UPSTREAM_PADDING],
        ));
        reply.edns = Some(edns);
    }
    reply.to_vec().unwrap()
}

/// 报文里的填充选项，一个一个列出 / The padding options in a message, one by one
fn paddings(message: &Message) -> Vec<Vec<u8>> {
    message.edns.as_ref().map_or_else(Vec::new, |edns| {
        edns.options()
            .get_all(EdnsCode::Padding)
            .into_iter()
            .map(|option| match option {
                EdnsOption::Unknown(_, data) => data.clone(),
                other => panic!("padding read as {other:?}"),
            })
            .collect()
    })
}

fn engine(upstream: &str) -> Engine {
    let engine = engine_from(json!({
        "settings": counting_settings(json!({})),
        "pipeline_select": [],
        "pipelines": [{ "id": "main", "rules": [{
            "name": "all", "matchers": [{ "type": "any" }],
            "actions": [{ "type": "forward", "upstream": upstream }]
        }] }]
    }));
    engine.doh_client.use_plain_http();
    engine
}

async fn reply(engine: &Engine, query: &[u8]) -> Message {
    Message::from_bytes(&support::ask(engine, query, peer()).await).expect("parse the reply")
}

/// 经 DoH 发的查询补到 128 字节的整数倍：OPT 的最后一个选项是全零的填充，只有这一个，客户端原来的填充
/// 不在了；没带 EDNS 的查询补一条带填充的 OPT，那样的客户端拿到的应答照旧不带 OPT
/// A query over DoH is padded to a multiple of 128 bytes: the last option of its OPT is padding
/// of zeros, the only padding there, the client's own gone; a query without EDNS gets an OPT
/// carrying it, and such a client still gets a reply without an OPT
#[tokio::test]
async fn a_query_over_doh_is_padded_to_a_multiple_of_128_bytes() {
    let received = Arc::new(Mutex::new(Vec::new()));
    let (addr, _) = spawn_doh_upstream({
        let received = Arc::clone(&received);
        move |_, body| {
            received.lock().unwrap().push(body.to_vec());
            let query = Message::from_bytes(body).expect("parse the query");
            DohReply::Raw(http_ok(Some(DOH_MEDIA_TYPE), &answer(&query)))
        }
    })
    .await;
    let engine = engine(&format!("https://{addr}/dns-query"));

    let without_edns = reply(&engine, &query("plain.test.", None)).await;
    reply(&engine, &query("padded.test.", Some(5))).await;

    let received = received.lock().unwrap().split_off(0);
    assert_eq!(received.len(), 2);
    for sent in &received {
        assert_eq!(sent.len() % 128, 0, "{} bytes", sent.len());
        let sent = Message::from_bytes(sent).expect("parse the query");
        let padding = paddings(&sent);
        assert_eq!(padding.len(), 1, "one padding option");
        assert!(padding[0].iter().all(|&byte| byte == 0));
        let options = &sent.edns.as_ref().unwrap().options().options;
        assert_eq!(
            options.last().map(|(code, _)| *code),
            Some(EdnsCode::Padding)
        );
    }
    assert!(without_edns.edns.is_none(), "{without_edns:?}");
}

/// 明文的 UDP 上游收到的查询不带填充（RFC 7830 第 6 节）：客户端的填充是按它到 KixDNS 这一跳补的
/// A cleartext UDP upstream gets the query without padding (RFC 7830 section 6): the client's
/// padding was sized for its hop to KixDNS
#[tokio::test]
async fn a_query_over_udp_carries_no_padding() {
    let upstream = support::upstream(|query| vec![(Duration::ZERO, answer(query))]).await;
    let engine = engine(&upstream.address);

    reply(&engine, &query("padded.test.", Some(5))).await;
    let received = upstream.received();
    assert_eq!(received.len(), 1);
    assert!(received[0].edns.is_some(), "EDNS itself is forwarded");
    assert_eq!(paddings(&received[0]), Vec::<Vec<u8>>::new());
}

/// 上游的填充是按它到 KixDNS 这一跳补的，不进缓存、不进客户端的应答：缓存里的应答会经明文传输交出去
/// The upstream's padding was sized for its hop to KixDNS and enters neither the cache nor a
/// client's reply: a cached reply goes out over cleartext transports
#[tokio::test]
async fn the_upstreams_padding_reaches_no_client() {
    let upstream = support::upstream(|query| vec![(Duration::ZERO, answer(query))]).await;
    let engine = engine(&upstream.address);

    for _ in 0..2 {
        let reply = reply(&engine, &query("padded.test.", Some(5))).await;
        assert!(reply.edns.is_some());
        assert_eq!(paddings(&reply), Vec::<Vec<u8>>::new());
        assert!(
            reply
                .answers
                .iter()
                .any(|record| matches!(record.data, RData::A(_))),
            "the answer itself is intact"
        );
    }
    assert_eq!(
        upstream.queries(),
        1,
        "the second reply comes from the cache"
    );
}
