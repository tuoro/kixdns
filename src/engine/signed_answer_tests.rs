//! TSIG 签过的应答只对签它的那个请求有效（RFC 8945）：不写进缓存，也不交给等在同一个查询上的别的请求，
//! 它们各自转发。发起转发的那个请求照旧原样拿到它。
//! A TSIG-signed answer holds for the one request that was signed (RFC 8945): it is not
//! cached and not handed to other requests waiting on the same query, which forward
//! themselves. The request whose forward got it still receives it as it is.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use serde_json::json;

use crate::engine::Engine;
use crate::engine::test_support::{
    Upstream, ask, ask_fast_path_first, counting_settings, engine_from, upstream,
};
use crate::proto_utils::last_record_is_tsig;

/// 末尾补一条 hickory 读得懂的 TSIG（密钥 `key.`、hmac-sha256、32 字节的 MAC）
/// Appends a TSIG record hickory can read (key `key.`, hmac-sha256, a 32-byte MAC)
fn signed(mut message: Vec<u8>) -> Vec<u8> {
    let mut rdata = vec![11];
    rdata.extend_from_slice(b"hmac-sha256");
    rdata.push(0);
    rdata.extend_from_slice(&[0, 0, 0x65, 0, 0, 0, 1, 44, 0, 32]);
    rdata.extend_from_slice(&[0xAB; 32]);
    rdata.extend_from_slice(&[message[0], message[1], 0, 0, 0, 0]);
    message[11] += 1;
    message.extend_from_slice(b"\x03key\x00");
    message.extend_from_slice(&[0, 250, 0, 255, 0, 0, 0, 0]);
    message.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    message.extend_from_slice(&rdata);
    assert!(
        Message::from_vec(&message).is_ok(),
        "hickory reads the TSIG"
    );
    message
}

/// 问 `name` 的 A 记录，`edns` 时带 OPT，`tsig` 时签名 / An A query for `name`, with an OPT
/// for `edns` and signed for `tsig`
fn query(id: u16, name: &str, edns: bool, tsig: bool) -> Vec<u8> {
    let mut query = Message::new(id, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    if edns {
        let mut opt = Edns::new();
        opt.set_max_payload(1232);
        query.set_edns(opt);
    }
    let bytes = query.to_vec().unwrap();
    if tsig { signed(bytes) } else { bytes }
}

/// 报文里照原样写着的问题名 / The question name exactly as a message writes it
fn question_bytes(message: &[u8]) -> Vec<u8> {
    let mut pos = 12;
    while message[pos] != 0 {
        pos += 1 + message[pos] as usize;
    }
    message[12..=pos].to_vec()
}

/// 照收到的问题回一条 A 记录的本机上游，`sign` 时给应答签名，每个应答晚 `delay` 才发
/// A local upstream answering the question as received with one A record, signing the
/// answer for `sign`, each answer sent `delay` late
async fn answering(sign: bool, delay: Duration) -> Upstream {
    upstream(move |query| {
        let Some(question) = query.queries.first() else {
            return Vec::new();
        };
        let mut reply = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
        reply.metadata.recursion_desired = query.metadata.recursion_desired;
        reply.metadata.recursion_available = true;
        reply.add_query(question.clone());
        reply.add_answer(Record::from_rdata(
            question.name().clone(),
            300,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 7))),
        ));
        let bytes = reply.to_vec().unwrap();
        vec![(delay, if sign { signed(bytes) } else { bytes })]
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

fn client(last: u8) -> SocketAddr {
    SocketAddr::from(([198, 51, 100, last], 5300))
}

/// 签过的应答不写缓存：A 签名、大小写混写来问，原样拿到签过的应答；B 不签名、小写来问，完整路径和
/// 快速路径都自己转发，拿到的问题名是它自己的写法。以前 B 从缓存拿到 A 的写法（0x20 客户端会丢掉它）。
/// 不签名的应答照旧缓存
/// A signed answer is not cached: A asks signed and in mixed case and gets the signed answer
/// as it is; B asks unsigned in lower case and forwards itself on the full path and the
/// fast path, getting the question spelled as it asked. B used to get A's spelling from the
/// cache (a 0x20 client drops it). An unsigned answer is cached as before
#[tokio::test]
async fn a_signed_answer_is_not_cached() {
    for sign in [false, true] {
        let up = answering(sign, Duration::ZERO).await;
        let engine = forwarding_to(&up);
        let first = query(0x1111, "WwW.ExAmPlE.TeSt.", true, true);
        let first_reply = ask(&engine, &first, client(1)).await;
        assert_eq!(last_record_is_tsig(&first_reply), sign);

        let second = query(0x2222, "www.example.test.", false, false);
        let full = ask(&engine, &second, client(2)).await;
        let fast = ask_fast_path_first(&engine, &second, client(2))
            .await
            .expect("the fast path reads it");
        let asked = if sign { 3 } else { 1 };
        assert_eq!(up.queries(), asked, "signed {sign}: forwards");
        for (path, reply) in [("full", &full), ("fast", &fast)] {
            assert_eq!(
                String::from_utf8_lossy(&question_bytes(reply)),
                String::from_utf8_lossy(&question_bytes(&second)),
                "signed {sign}, {path} path: the question spelled as B asked"
            );
        }
    }
}

/// 签过的应答不交给等在同一个查询上的请求：B 在 A 转发时到来，等 A 的结果；A 拿到签过的应答以后，B
/// 自己转发，拿到的问题名是它自己的写法。以前 B 拿到的是 A 的应答、A 的写法。不签名的应答照旧交给 B
/// A signed answer is not handed to a request waiting on the same query: B arrives while A
/// forwards and waits on A's result; once A gets a signed answer, B forwards itself and
/// gets the question spelled as it asked. B used to get A's answer in A's spelling. An
/// unsigned answer is handed to B as before
#[tokio::test]
async fn a_signed_answer_is_not_handed_to_a_waiter() {
    for sign in [false, true] {
        let up = answering(sign, Duration::from_millis(300)).await;
        let engine = forwarding_to(&up);
        let first = query(0x1111, "WwW.ExAmPlE.TeSt.", false, true);
        let second = query(0x2222, "www.example.test.", false, false);
        let (first_reply, waiter) = tokio::join!(ask(&engine, &first, client(1)), async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            ask(&engine, &second, client(2)).await
        });
        assert_eq!(last_record_is_tsig(&first_reply), sign);
        let asked = if sign { 2 } else { 1 };
        assert_eq!(up.queries(), asked, "signed {sign}: forwards");
        assert_eq!(
            String::from_utf8_lossy(&question_bytes(&waiter)),
            String::from_utf8_lossy(&question_bytes(&second)),
            "signed {sign}: the waiter's question is spelled as it asked"
        );
    }
}

/// 后台刷新拿到签过的应答时也不写缓存：条目照旧是原来那个不签名的应答，过期以后照旧当作过期应答给出。
/// 以前刷新把签过的应答写进缓存，之后每个客户端拿到的都是它
/// A background refresh that gets a signed answer does not cache it either: the entry
/// stays the unsigned answer it was, served stale once expired as before. The refresh
/// used to cache the signed answer, which every client then got
#[tokio::test]
async fn a_refresh_that_gets_a_signed_answer_keeps_the_entry() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let sign = Arc::new(AtomicBool::new(false));
    let signing = sign.clone();
    let up = upstream(move |query| {
        let question = query.queries[0].clone();
        let mut reply = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
        reply.metadata.recursion_desired = query.metadata.recursion_desired;
        let signs = signing.load(Ordering::SeqCst);
        reply.add_query(question.clone());
        reply.add_answer(Record::from_rdata(
            question.name().clone(),
            1,
            RData::A(A(Ipv4Addr::new(192, 0, 2, if signs { 9 } else { 7 }))),
        ));
        let bytes = reply.to_vec().unwrap();
        vec![(Duration::ZERO, if signs { signed(bytes) } else { bytes })]
    })
    .await;
    let engine = engine_from(json!({
        "settings": counting_settings(json!({
            "min_ttl": 0, "serve_stale": true, "serve_stale_client_timeout_ms": 0
        })),
        "pipelines": [{ "id": "main", "rules": [{
            "name": "all", "matchers": [{ "type": "any" }],
            "actions": [{ "type": "forward", "upstream": up.address }]
        }]}]
    }));
    let asked = query(0x1111, "www.example.test.", false, false);
    let answer = |reply: &[u8]| Message::from_vec(reply).unwrap().answers[0].data.clone();
    let unsigned = RData::A(A(Ipv4Addr::new(192, 0, 2, 7)));
    assert_eq!(answer(&ask(&engine, &asked, client(1)).await), unsigned);

    sign.store(true, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    // 过期的应答当场给出，同时发起刷新；等刷新问过上游、拿到签过的应答
    // The stale answer goes out at once and a refresh starts; wait until the refresh has
    // asked and got the signed answer
    assert_eq!(answer(&ask(&engine, &asked, client(1)).await), unsigned);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while up.queries() < 2 {
        assert!(tokio::time::Instant::now() < deadline, "the refresh asks");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    let next = ask(&engine, &asked, client(1)).await;
    assert!(
        !last_record_is_tsig(&next),
        "no signed answer from the cache"
    );
    assert_eq!(answer(&next), unsigned, "the entry is the one it was");
}
