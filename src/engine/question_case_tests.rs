//! 回答的问题段照客户端发来的写法（见 `proto_utils::question_as_asked`）：缓存命中、合并的在途
//! 查询、静态回答和改写了大小写的上游，客户端拿回的都是自己问的写法。
//! The question in an answer is written as the client wrote it (see
//! `proto_utils::question_as_asked`): from the cache, for a merged inflight query, from a
//! static rule, or from an upstream that rewrote the case, the client gets back its own
//! spelling.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;

use crate::engine::{Engine, FastPathResponse, PreParsedData};
use crate::matcher::RuntimePipelineConfig;

/// 假上游给的地址 / The address the fake upstream answers
const ANSWER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 70);
/// 静态规则给的地址 / The address the static rule answers
const STATIC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 80);

/// 假上游怎样写应答的问题名 / How the fake upstream writes its reply's question name
#[derive(Clone, Copy)]
enum Spelling {
    /// 照查询的写法 / As the query wrote it
    Echo,
    /// 全部小写 / All lowercase
    Lower,
}

/// 假上游；`queries` 是它收到的查询个数 / A fake upstream; `queries` counts what it received
struct Upstream {
    address: String,
    queries: Arc<AtomicUsize>,
}

/// 用 [`ANSWER`] 作答的本机上游，应答晚 `delay` 发出，问题名按 `spelling` 写
/// A local upstream answering [`ANSWER`], every reply `delay` late, its question name
/// written as `spelling` says
async fn upstream(spelling: Spelling, delay: Duration) -> Upstream {
    let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let address = sock.local_addr().unwrap().to_string();
    let queries = Arc::new(AtomicUsize::new(0));
    let counted = queries.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            let Ok(query) = Message::from_bytes(&buf[..n]) else {
                continue;
            };
            let Some(question) = query.queries.first().cloned() else {
                continue;
            };
            counted.fetch_add(1, Ordering::SeqCst);
            let name = match spelling {
                Spelling::Echo => question.name().clone(),
                Spelling::Lower => question.name().to_lowercase(),
            };
            let mut resp = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
            resp.metadata.recursion_desired = query.metadata.recursion_desired;
            resp.metadata.recursion_available = true;
            resp.add_query(Query::query(name.clone(), question.query_type()));
            resp.add_answer(Record::from_rdata(name, 300, RData::A(A(ANSWER))));
            let resp = resp.to_vec().unwrap();
            let sock = sock.clone();
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                let _ = sock.send_to(&resp, peer).await;
            });
        }
    });
    Upstream { address, queries }
}

/// 名字以 `matched.test` 结尾的请求得到静态的 [`STATIC`]，以 `text.test` 结尾的得到静态 TXT（它不能
/// 预先算好，第一次走完整路径，之后从规则缓存作答），其余转发给 `upstream`
/// A name ending in `matched.test` gets the static [`STATIC`], one ending in `text.test` a
/// static TXT (which cannot be computed ahead, so the full path answers it first and the
/// rule cache afterwards), and the rest go to `upstream`
fn engine(upstream: &str) -> Engine {
    let config: crate::config::PipelineConfig = serde_json::from_value(serde_json::json!({
        "settings": {
            "default_upstream": "127.0.0.1:9",
            // A UDP query is sent again after a third of this (`upstream::hedge_timeout`),
            // and the tests count upstream queries
            // UDP 查询过了这个时间的三分之一会再发一次（`upstream::hedge_timeout`），而这些测试
            // 数上游收到的查询
            "upstream_timeout_ms": 3000,
            "enable_tcp_fallback": false
        },
        "pipelines": [{ "id": "main", "rules": [
            {
                "name": "static",
                "matchers": [{ "type": "domain_suffix", "value": "matched.test" }],
                "actions": [{ "type": "static_ip_response", "ip": STATIC.to_string() }]
            },
            {
                "name": "text",
                "matchers": [{ "type": "domain_suffix", "value": "text.test" }],
                "actions": [{ "type": "static_txt_response", "text": ["hello"] }]
            },
            {
                "name": "all",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": upstream }]
            }
        ]}]
    }))
    .expect("parse config");
    Engine::new(
        RuntimePipelineConfig::from_config(config).expect("build runtime config"),
        "test".to_string(),
    )
    .expect("engine")
}

/// 查询 `name` 的 A 记录，再接 `trailing`；名字照原样写（`Name::from_str` 会转成小写）
/// An A query for `name`, then `trailing`; the name is written as given
/// (`Name::from_str` would lowercase it)
fn query(name: &str, trailing: &[u8]) -> Vec<u8> {
    query_of_type(name, RecordType::A, trailing)
}

/// 同上，查询类型为 `qtype` / The same, for `qtype`
fn query_of_type(name: &str, qtype: RecordType, trailing: &[u8]) -> Vec<u8> {
    let mut request = Message::new(0x5157, MessageType::Query, OpCode::Query);
    request.metadata.recursion_desired = true;
    request.add_query(Query::query(Name::from_ascii(name).unwrap(), qtype));
    let mut packet = request.to_vec().unwrap();
    packet.extend_from_slice(trailing);
    packet
}

fn peer() -> SocketAddr {
    "127.0.0.1:53000".parse().unwrap()
}

/// 应答的问题名（照写法）和第一个地址 / The reply's question name, as written, and its first address
fn read(reply: &Bytes) -> (String, Option<Ipv4Addr>) {
    let reply = Message::from_bytes(reply).expect("parse reply");
    let address = match reply.answers.first().map(|record| &record.data) {
        Some(RData::A(address)) => Some(address.0),
        _ => None,
    };
    (reply.queries[0].name().to_string(), address)
}

/// 走完整路径 / Through the full path
async fn ask(engine: &Engine, packet: &[u8]) -> (String, Option<Ipv4Addr>) {
    let reply = tokio::time::timeout(Duration::from_secs(5), engine.handle_packet(packet, peer()))
        .await
        .expect("answer in time")
        .expect("answer");
    read(&reply)
}

/// 像监听器那样问：先走快速路径，需要时再走异步路径
/// Ask as a listener does: the fast path first, then the async path when needed
async fn ask_like_a_listener(engine: &Engine, packet: &[u8]) -> (String, Option<Ipv4Addr>) {
    let reply = match engine
        .handle_packet_fast(packet, peer())
        .expect("fast path")
    {
        Some(FastPathResponse::Direct(reply)) => reply,
        Some(FastPathResponse::CacheHit { cached, .. }) => cached,
        Some(FastPathResponse::AsyncNeeded {
            qname,
            qtype,
            qclass,
            tx_id,
            edns_present,
            pipeline_id,
        }) => tokio::time::timeout(
            Duration::from_secs(5),
            engine.handle_packet_internal_with_pre_parsed(
                packet,
                peer(),
                false,
                PreParsedData::new(qname, qtype, qclass, tx_id, edns_present, pipeline_id),
            ),
        )
        .await
        .expect("answer in time")
        .expect("answer"),
        None => return ask(engine, packet).await,
    };
    read(&reply)
}

fn answered(name: &str, address: Ipv4Addr) -> (String, Option<Ipv4Addr>) {
    (name.to_string(), Some(address))
}

/// 缓存里的应答是第一个客户端问的写法；后来的客户端拿回的是自己的写法，快速路径和完整路径都是
/// A cached answer carries the first client's spelling; later clients get their own
/// back, on the fast path and on the full path
#[tokio::test]
async fn a_cached_answer_goes_back_with_the_askers_spelling() {
    let up = upstream(Spelling::Echo, Duration::ZERO).await;
    let engine = engine(&up.address);
    assert_eq!(
        ask_like_a_listener(&engine, &query("Example.COM.", b"")).await,
        answered("Example.COM.", ANSWER)
    );
    assert_eq!(
        ask_like_a_listener(&engine, &query("eXAMPLE.com.", b"")).await,
        answered("eXAMPLE.com.", ANSWER)
    );
    assert_eq!(
        ask(&engine, &query("EXAMPLE.COM.", b"")).await,
        answered("EXAMPLE.COM.", ANSWER)
    );
    // A trailing byte keeps the fast parser out / 结尾多一个字节，快速解析就读不了
    assert_eq!(
        ask_like_a_listener(&engine, &query("example.Com.", b"\0")).await,
        answered("example.Com.", ANSWER)
    );
    assert_eq!(
        up.queries.load(Ordering::SeqCst),
        1,
        "answered from the cache"
    );
}

/// 同时到达、只差大小写的查询合并成一次上游查询，各自拿回自己的写法
/// Queries arriving at once that differ only in case are merged into one upstream
/// query, and each gets its own spelling back
#[tokio::test]
async fn merged_queries_each_get_their_own_spelling() {
    // Late replies, so the later queries arrive while the first is in flight
    // 应答来得晚，后面的查询到达时第一个还在途中
    let up = upstream(Spelling::Echo, Duration::from_millis(200)).await;
    let engine = engine(&up.address);
    let (one, two, three) = (
        query("Example.com.", b""),
        query("EXAMPLE.COM.", b""),
        query("example.com.", b""),
    );
    let answers = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(ask(&engine, &one), ask(&engine, &two), ask(&engine, &three))
    })
    .await
    .expect("answers in time");
    assert_eq!(
        answers,
        (
            answered("Example.com.", ANSWER),
            answered("EXAMPLE.COM.", ANSWER),
            answered("example.com.", ANSWER)
        )
    );
    assert_eq!(up.queries.load(Ordering::SeqCst), 1, "merged");
}

/// 静态回答拿回客户端的写法，不论是快速路径当场构造的还是完整路径上的（规则缓存见下一个测试）
/// A static answer goes back with the client's spelling, whether built on the spot on
/// the fast path or on the full path (the rule cache has the next test)
#[tokio::test]
async fn a_static_answer_goes_back_with_the_askers_spelling() {
    let engine = engine("127.0.0.1:9");
    for name in [
        "WWW.Matched.TEST.",
        "www.MATCHED.test.",
        "Www.Matched.Test.",
    ] {
        assert_eq!(
            ask_like_a_listener(&engine, &query(name, b"")).await,
            answered(name, STATIC)
        );
        assert_eq!(
            ask_like_a_listener(&engine, &query(name, b"\0")).await,
            answered(name, STATIC),
            "{name} with a trailing byte"
        );
        assert_eq!(
            ask(&engine, &query(name, b"")).await,
            answered(name, STATIC)
        );
    }
}

/// 规则缓存里的静态回答也拿回客户端的写法
/// A static answer from the rule cache goes back with the client's spelling too
#[tokio::test]
async fn a_static_answer_from_the_rule_cache_goes_back_with_the_askers_spelling() {
    let engine = engine("127.0.0.1:9");
    // The full path answers first and caches the rule's decision
    // 第一次由完整路径作答，并缓存规则的决定
    ask(
        &engine,
        &query_of_type("first.text.test.", RecordType::TXT, b""),
    )
    .await;
    for name in ["WWW.Text.TEST.", "www.TEXT.test.", "first.Text.Test."] {
        let packet = query_of_type(name, RecordType::TXT, b"");
        // Asked once on the full path, so the rule cache holds the decision for it
        // 先在完整路径上问一次，规则缓存里就有了它的决定
        ask(&engine, &packet).await;
        let Some(FastPathResponse::Direct(reply)) = engine
            .handle_packet_fast(&packet, peer())
            .expect("fast path")
        else {
            panic!("{name}: the rule cache answers on the fast path");
        };
        assert_eq!(read(&reply).0, name);
    }
}

/// 上游把问题名改成了小写，客户端拿回的仍是自己的写法
/// An upstream that lowercases the question name: the client still gets its own
/// spelling back
#[tokio::test]
async fn an_upstream_that_rewrites_the_case_does_not_change_the_clients() {
    let up = upstream(Spelling::Lower, Duration::ZERO).await;
    let engine = engine(&up.address);
    assert_eq!(
        ask_like_a_listener(&engine, &query("MiXeD.Example.ORG.", b"")).await,
        answered("MiXeD.Example.ORG.", ANSWER)
    );
}
