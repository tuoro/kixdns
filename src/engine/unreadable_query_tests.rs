//! 快速解析读得了、hickory 读不了的查询（附加段里有一条 RDATA 不合规的非 OPT 记录）照常回答：响应动作给的应答照线上格式
//! 从查询写，不为它解析请求，等着的请求也拿到它；转发失败时不论怎样失败都回 SERVFAIL。读不读得了在读的那一刻定下，只有那时就
//! 读不了的查询回 FORMERR。
//! A query the quick parse reads and hickory does not (a non-OPT record with improper RDATA in
//! its additional section) is answered as usual: what the response actions give is written on
//! the wire from the query, with no parse of the request for it, and the requests waiting get it
//! too; a failed forward is answered SERVFAIL however it fails. Whether a query can be read is
//! settled the moment it is read, and only one that cannot be read then gets FORMERR.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::serialize::binary::BinDecodable;
use serde_json::{Value, json};

use crate::engine::test_support::{counting_settings, engine_from, first_a};
use crate::engine::{Engine, OnTheSpot};

/// 上游给的地址 / The address the upstream answers
const ANSWER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
/// 回答检查给的地址 / The address the answer check gives
const STATIC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 5);

/// 问 `example.com.` 的 A 记录，附加段里一条 A 记录只有 3 字节 RDATA：快速解析只查记录的框架，收下它；hickory 读不了
/// An A query for `example.com.` whose additional section holds an A record with 3 bytes of
/// RDATA: the quick parse checks only the record framing and takes it; hickory cannot read it
fn query_hickory_cannot_read() -> Vec<u8> {
    let mut packet = vec![0x51, 0x57, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1];
    packet.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
    packet.extend_from_slice(&[0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 3, 1, 2, 3]);
    let mut buffer = [0u8; 256];
    assert!(crate::proto_utils::parse_quick(&packet, &mut buffer).is_some());
    assert!(Message::from_bytes(&packet).is_err());
    packet
}

/// 照原始字节作答的本机 UDP 上游：照抄查询的 ID 和问题，`broken` 时应答段说有一条记录、报文却到问题段就完了（两种解析都
/// 读不了），否则带一条 [`ANSWER`]；应答晚 100 毫秒发出。给出它的地址和数查询的计数
/// A local UDP upstream answering raw bytes: the query's ID and question copied, and when
/// `broken` an answer count of one with the message ending after the question (neither parser
/// reads it), one [`ANSWER`] record otherwise; every reply 100 ms late. Gives its address and
/// the count of queries
async fn raw_upstream(broken: bool) -> (String, Arc<AtomicUsize>) {
    let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let address = socket.local_addr().unwrap().to_string();
    let asked = Arc::new(AtomicUsize::new(0));
    let counted = asked.clone();
    tokio::spawn(async move {
        let mut buffer = [0u8; 1500];
        while let Ok((n, peer)) = socket.recv_from(&mut buffer).await {
            counted.fetch_add(1, Ordering::SeqCst);
            let query = &buffer[..n];
            let question_end = crate::proto_utils::question_name_end(query).unwrap() + 4;
            let mut reply = BytesMut::from(&query[..question_end]);
            reply[2] |= 0x80;
            reply[3] = 0x80;
            reply[6..12].copy_from_slice(&[0, 1, 0, 0, 0, 0]);
            if !broken {
                reply.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 1, 0x2C, 0, 4]);
                reply.extend_from_slice(&ANSWER.octets());
            }
            let socket = socket.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(100)).await;
                let _ = socket.send_to(&reply, peer).await;
            });
        }
    });
    (address, asked)
}

fn engine_with_rule(rule: Value) -> Engine {
    engine_from(json!({
        "settings": counting_settings(json!({})),
        "pipelines": [{ "id": "main", "rules": [rule] }]
    }))
}

/// 像监听器那样回答：快速路径当场答不了的走完整路径（见 `Engine::answer_after_fast_path`）
/// Answer as a listener does: what the fast path cannot answer on the spot takes the full path
/// (see `Engine::answer_after_fast_path`)
async fn listen(engine: &Engine, packet: &[u8], client: u8) -> Bytes {
    let peer = SocketAddr::from(([10, 0, 0, client], 53000));
    let mut reply = BytesMut::new();
    match engine.on_the_spot(packet, peer, &mut reply) {
        OnTheSpot::Reply => reply.freeze(),
        OnTheSpot::Forward(pre_parsed) => tokio::time::timeout(
            Duration::from_secs(5),
            engine.answer_after_fast_path(packet, peer, pre_parsed),
        )
        .await
        .expect("answered in time"),
        OnTheSpot::Drop => panic!("the query was dropped"),
    }
}

fn rcode(reply: &[u8]) -> ResponseCode {
    ResponseCode::from(0, reply[3] & 0x0f)
}

/// 回答检查给的静态应答照线上格式从查询写，hickory 读不读得了查询都一样；同时在等的请求拿到同一个，上游只问一次。以前
/// 为了它把请求整个解析一遍，解析不了这次请求就出错：客户端拿到 FORMERR，等着的请求一个接一个自己再去问
/// The static answer an answer check gives is written on the wire from the query, whether or
/// not hickory reads the query; the requests waiting at once get the same, the upstream asked
/// once. The whole request used to be parsed for it, and with that failing the request ended
/// in an error: the client got FORMERR, and the waiters asked again one after another
#[tokio::test]
async fn an_answer_checks_static_answer_needs_no_parse_of_the_query() {
    let (upstream, asked) = raw_upstream(false).await;
    let engine = engine_with_rule(json!({
        "name": "checked", "matchers": [{ "type": "any" }],
        "actions": [{ "type": "forward", "upstream": upstream }],
        "response_actions_on_match": [{ "type": "static_ip_response", "ip": STATIC.to_string() }]
    }));
    let packet = query_hickory_cannot_read();
    let replies =
        futures::future::join_all((1..=6).map(|client| listen(&engine, &packet, client))).await;
    for reply in &replies {
        assert_eq!(first_a(reply), Some(STATIC));
    }
    assert_eq!(asked.load(Ordering::SeqCst), 1);
}

/// 这样的查询转发失败时回 SERVFAIL，上游的应答读不了也一样，和上游不回答、超时时一致。以前读不了的应答让这次请求出错，
/// 监听器事后再解析一遍查询，解析不了就回 FORMERR
/// Such a query whose forward fails is answered SERVFAIL, an upstream reply that cannot be read
/// included, as when the upstream does not answer or times out. A reply that cannot be read used
/// to end the request in an error, the listener parsed the query again afterwards, and failing
/// to, answered FORMERR
#[tokio::test]
async fn a_failed_forward_is_answered_servfail_whether_or_not_hickory_reads_the_query() {
    let (broken, _) = raw_upstream(true).await;
    for upstream in [broken.as_str(), "127.0.0.1:9"] {
        let engine = engine_with_rule(json!({
            "name": "all", "matchers": [{ "type": "any" }],
            "actions": [{ "type": "forward", "upstream": upstream }]
        }));
        let reply = listen(&engine, &query_hickory_cannot_read(), 1).await;
        assert_eq!(rcode(&reply), ResponseCode::ServFail, "{upstream}");
    }
}

/// 读的那一刻就读不了的查询（问题名的压缩指针指进报文头）回 FORMERR
/// A query that cannot be read the moment it is read (its question name's compression pointer
/// pointing into the header) is answered FORMERR
#[tokio::test]
async fn a_query_that_cannot_be_read_is_answered_formerr() {
    let engine = engine_with_rule(json!({
        "name": "all", "matchers": [{ "type": "any" }],
        "actions": [{ "type": "forward", "upstream": "127.0.0.1:9" }]
    }));
    let packet = [
        0x51, 0x57, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 0x00, 0, 1, 0, 1,
    ];
    assert_eq!(
        rcode(&listen(&engine, &packet, 1).await),
        ResponseCode::FormErr
    );
}
