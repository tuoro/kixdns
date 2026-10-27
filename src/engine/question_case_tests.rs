//! 回答的问题段照客户端发来的写法（见 `proto_utils::question_as_asked`）：缓存命中、合并的在途
//! 查询、静态回答和改写了大小写的上游，客户端拿回的都是自己问的写法。
//! The question in an answer is written as the client wrote it (see
//! `proto_utils::question_as_asked`): from the cache, for a merged inflight query, from a
//! static rule, or from an upstream that rewrote the case, the client gets back its own
//! spelling.

use std::net::Ipv4Addr;
use std::time::Duration;

use bytes::Bytes;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;

use crate::engine::test_support::{
    self as support, STATIC, Upstream, first_a, peer, static_or_forward,
};
use crate::engine::{Engine, FastPathResponse};

/// 假上游给的地址 / The address the fake upstream answers
const ANSWER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 70);

/// 假上游怎样写应答的问题名 / How the fake upstream writes its reply's question name
#[derive(Clone, Copy)]
enum Spelling {
    /// 照查询的写法 / As the query wrote it
    Echo,
    /// 全部小写 / All lowercase
    Lower,
}

/// 用 [`ANSWER`] 作答的本机上游，应答晚 `delay` 发出，问题名按 `spelling` 写
/// A local upstream answering [`ANSWER`], every reply `delay` late, its question name
/// written as `spelling` says
async fn upstream(spelling: Spelling, delay: Duration) -> Upstream {
    support::upstream(move |query| {
        let Some(question) = query.queries.first() else {
            return Vec::new();
        };
        let name = match spelling {
            Spelling::Echo => question.name().clone(),
            Spelling::Lower => question.name().to_lowercase(),
        };
        let mut resp = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
        resp.metadata.recursion_desired = query.metadata.recursion_desired;
        resp.metadata.recursion_available = true;
        resp.add_query(Query::query(name.clone(), question.query_type()));
        resp.add_answer(Record::from_rdata(name, 300, RData::A(A(ANSWER))));
        vec![(delay, resp.to_vec().unwrap())]
    })
    .await
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

/// 应答的问题名（照写法）和第一个地址 / The reply's question name, as written, and its first address
fn read(reply: &Bytes) -> (String, Option<Ipv4Addr>) {
    let message = Message::from_bytes(reply).expect("parse reply");
    (message.queries[0].name().to_string(), first_a(reply))
}

/// 走完整路径 / Through the full path
async fn ask(engine: &Engine, packet: &[u8]) -> (String, Option<Ipv4Addr>) {
    read(&support::ask(engine, packet, peer()).await)
}

/// 像监听器那样问 / Ask as a listener does
async fn ask_like_a_listener(engine: &Engine, packet: &[u8]) -> (String, Option<Ipv4Addr>) {
    read(&support::ask_like_a_listener(engine, packet, peer()).await)
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
    let engine = static_or_forward(&up.address);
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
    assert_eq!(up.queries(), 1, "answered from the cache");
}

/// 同时到达、只差大小写的查询合并成一次上游查询，各自拿回自己的写法
/// Queries arriving at once that differ only in case are merged into one upstream
/// query, and each gets its own spelling back
#[tokio::test]
async fn merged_queries_each_get_their_own_spelling() {
    // Late replies, so the later queries arrive while the first is in flight
    // 应答来得晚，后面的查询到达时第一个还在途中
    let up = upstream(Spelling::Echo, Duration::from_millis(200)).await;
    let engine = static_or_forward(&up.address);
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
    assert_eq!(up.queries(), 1, "merged");
}

/// 静态回答拿回客户端的写法，不论是快速路径当场构造的还是完整路径上的（规则缓存见下一个测试）
/// A static answer goes back with the client's spelling, whether built on the spot on
/// the fast path or on the full path (the rule cache has the next test)
#[tokio::test]
async fn a_static_answer_goes_back_with_the_askers_spelling() {
    let engine = static_or_forward("127.0.0.1:9");
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
    let engine = static_or_forward("127.0.0.1:9");
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
    let engine = static_or_forward(&up.address);
    assert_eq!(
        ask_like_a_listener(&engine, &query("MiXeD.Example.ORG.", b"")).await,
        answered("MiXeD.Example.ORG.", ANSWER)
    );
}
