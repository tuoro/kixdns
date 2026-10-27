//! 应答的 EDNS 跟着查询走（见 `proto_utils::edns_as_asked`）：带 EDNS 的查询拿回 OPT，DO 位照抄；
//! 不带的拿不到 OPT。静态回答、缓存命中、合并的在途查询和监听器自己构造的 SERVFAIL 都一样，
//! RD、CD 位也照抄查询。
//! The reply's EDNS follows the query (see `proto_utils::edns_as_asked`): a query with
//! EDNS gets an OPT back with its DO bit, one without gets none. So do static answers,
//! answers from the cache, merged inflight queries and the SERVFAIL a listener builds,
//! and the RD and CD bits are the query's too.

use std::net::Ipv4Addr;
use std::time::Duration;

use bytes::Bytes;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;

use crate::engine::test_support::{
    self as support, STATIC, Upstream, first_a, peer, static_or_forward,
};
use crate::engine::utils::engine_helpers;
use crate::engine::{Engine, FastPathResponse};

/// 假上游给的地址 / The address the fake upstream answers
const ANSWER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 70);

/// 用 [`ANSWER`] 作答的本机上游，应答晚 `delay` 发出。查询带 OPT 时应答才带 OPT；`copies_do`
/// 为 false 时应答的 DO 位总是 0。
/// A local upstream answering [`ANSWER`], every reply `delay` late. A reply carries an
/// OPT only when the query does; with `copies_do` false its DO bit is always 0.
async fn upstream(copies_do: bool, delay: Duration) -> Upstream {
    support::upstream(move |query| {
        let Some(question) = query.queries.first() else {
            return Vec::new();
        };
        let mut resp = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
        resp.metadata.recursion_desired = query.metadata.recursion_desired;
        resp.metadata.checking_disabled = query.metadata.checking_disabled;
        resp.metadata.recursion_available = true;
        resp.add_query(question.clone());
        resp.add_answer(Record::from_rdata(
            question.name().clone(),
            300,
            RData::A(A(ANSWER)),
        ));
        if let Some(asked) = &query.edns {
            let mut edns = Edns::new();
            edns.set_max_payload(1232);
            edns.set_dnssec_ok(copies_do && asked.flags().dnssec_ok);
            resp.edns = Some(edns);
        }
        vec![(delay, resp.to_vec().unwrap())]
    })
    .await
}

/// 一个查询怎样问 / How a query asks
#[derive(Debug, Clone, Copy)]
struct Asked {
    /// None：不带 EDNS；Some(DO 位) / None: no EDNS; Some(the DO bit)
    edns: Option<bool>,
    recursion_desired: bool,
    checking_disabled: bool,
}

const PLAIN: Asked = Asked {
    edns: None,
    recursion_desired: true,
    checking_disabled: false,
};

const WITH_EDNS: Asked = Asked {
    edns: Some(false),
    ..PLAIN
};

/// 带 EDNS 与否、DO、RD、CD 的全部组合 / Every combination of EDNS, DO, RD and CD
fn every_way() -> Vec<Asked> {
    let mut all = Vec::new();
    for edns in [None, Some(false), Some(true)] {
        for recursion_desired in [true, false] {
            for checking_disabled in [false, true] {
                all.push(Asked {
                    edns,
                    recursion_desired,
                    checking_disabled,
                });
            }
        }
    }
    all
}

/// 照 `asked` 查询 `name` 的 A 记录，再接 `trailing` / An A query for `name` asked as
/// `asked`, then `trailing`
fn query(name: &str, asked: Asked, trailing: &[u8]) -> Vec<u8> {
    query_of_type(name, RecordType::A, asked, trailing)
}

/// 同上，查询类型为 `qtype` / The same, for `qtype`
fn query_of_type(name: &str, qtype: RecordType, asked: Asked, trailing: &[u8]) -> Vec<u8> {
    let mut request = Message::new(0x5157, MessageType::Query, OpCode::Query);
    request.metadata.recursion_desired = asked.recursion_desired;
    request.metadata.checking_disabled = asked.checking_disabled;
    request.add_query(Query::query(Name::from_ascii(name).unwrap(), qtype));
    if let Some(dnssec_ok) = asked.edns {
        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        edns.set_dnssec_ok(dnssec_ok);
        request.edns = Some(edns);
    }
    let mut packet = request.to_vec().unwrap();
    packet.extend_from_slice(trailing);
    packet
}

/// 应答是怎样答的：EDNS 和 DO、RD、CD，以及第一个地址
/// How a reply answers: EDNS and DO, RD, CD, and its first address
#[derive(Debug, PartialEq, Eq)]
struct Answered {
    edns: Option<bool>,
    recursion_desired: bool,
    checking_disabled: bool,
    address: Option<Ipv4Addr>,
}

fn read(reply: &Bytes) -> Answered {
    let message = Message::from_bytes(reply).expect("parse reply");
    Answered {
        edns: message.edns.as_ref().map(|edns| edns.flags().dnssec_ok),
        recursion_desired: message.metadata.recursion_desired,
        checking_disabled: message.metadata.checking_disabled,
        address: first_a(reply),
    }
}

/// 照 `asked` 问、拿到 `address` 时应有的应答 / The reply asking as `asked` should get with `address`
fn answered(asked: Asked, address: Ipv4Addr) -> Answered {
    Answered {
        edns: asked.edns,
        recursion_desired: asked.recursion_desired,
        checking_disabled: asked.checking_disabled,
        address: Some(address),
    }
}

/// 走完整路径 / Through the full path
async fn ask(engine: &Engine, packet: &[u8]) -> Answered {
    read(&support::ask(engine, packet, peer()).await)
}

/// 像监听器那样问 / Ask as a listener does
async fn ask_like_a_listener(engine: &Engine, packet: &[u8]) -> Answered {
    read(&support::ask_like_a_listener(engine, packet, peer()).await)
}

/// 静态回答照查询带 OPT、DO、RD 和 CD：快速路径当场构造的和完整路径上的都一样（规则缓存见下一个
/// 测试）
/// A static answer carries the OPT, DO, RD and CD its query had: built on the spot on
/// the fast path and on the full path alike (the rule cache has the next test)
#[tokio::test]
async fn a_static_answer_carries_what_its_query_asked() {
    let engine = static_or_forward("127.0.0.1:9");
    for round in 0..2 {
        for asked in every_way() {
            let name = "www.matched.test.";
            let case = format!("round {round}, {asked:?}");
            assert_eq!(
                ask_like_a_listener(&engine, &query(name, asked, b"")).await,
                answered(asked, STATIC),
                "{case}"
            );
            assert_eq!(
                ask(&engine, &query(name, asked, b"")).await,
                answered(asked, STATIC),
                "{case}, full path"
            );
            // A trailing byte keeps the fast parser out / 结尾多一个字节，快速解析就读不了
            assert_eq!(
                ask_like_a_listener(&engine, &query(name, asked, b"\0")).await,
                answered(asked, STATIC),
                "{case}, trailing byte"
            );
        }
    }
}

/// 规则缓存里的静态回答也照查询带 OPT、DO、RD 和 CD
/// A static answer from the rule cache carries the OPT, DO, RD and CD its query had too
#[tokio::test]
async fn a_static_answer_from_the_rule_cache_carries_what_its_query_asked() {
    let engine = static_or_forward("127.0.0.1:9");
    for asked in every_way() {
        let packet = query_of_type("www.text.test.", RecordType::TXT, asked, b"");
        // Asked once on the full path, so the rule cache holds the decision for it
        // 先在完整路径上问一次，规则缓存里就有了它的决定
        ask(&engine, &packet).await;
        let Some(FastPathResponse::Direct(reply)) = engine
            .handle_packet_fast(&packet, peer())
            .expect("fast path")
        else {
            panic!("{asked:?}: the rule cache answers on the fast path");
        };
        assert_eq!(
            read(&reply),
            Answered {
                address: None,
                ..answered(asked, STATIC)
            },
            "{asked:?}"
        );
    }
}

/// 缓存里的应答是第一个客户端问的样子；带不带 EDNS 的客户端各自拿到自己该有的 OPT
/// A cached answer is shaped as its first client asked; clients with and without
/// EDNS each get the OPT they should
#[tokio::test]
async fn a_cached_answer_carries_the_edns_its_client_asked() {
    let up = upstream(true, Duration::ZERO).await;
    let engine = static_or_forward(&up.address);
    for (name, first, then) in [
        ("edns-first.example.", WITH_EDNS, PLAIN),
        ("plain-first.example.", PLAIN, WITH_EDNS),
    ] {
        assert_eq!(
            ask_like_a_listener(&engine, &query(name, first, b"")).await,
            answered(first, ANSWER),
            "{name}"
        );
        assert_eq!(
            ask_like_a_listener(&engine, &query(name, then, b"")).await,
            answered(then, ANSWER),
            "{name}, from the cache"
        );
        assert_eq!(
            ask(&engine, &query(name, then, b"")).await,
            answered(then, ANSWER),
            "{name}, from the cache on the full path"
        );
    }
    assert_eq!(up.queries(), 2, "answered from the cache");
}

/// 同时到达、一个带 EDNS 一个不带的查询合并成一次上游查询，各自拿到自己该有的 OPT
/// Queries at once, one with EDNS and one without, are merged into one upstream query,
/// and each gets the OPT it should
#[tokio::test]
async fn merged_queries_each_get_the_edns_they_asked() {
    // Late replies, so the second query arrives while the first is in flight
    // 应答来得晚，第二个查询到达时第一个还在途中
    let up = upstream(true, Duration::from_millis(200)).await;
    let engine = static_or_forward(&up.address);
    for (name, first, second) in [
        ("edns-first.example.", WITH_EDNS, PLAIN),
        ("plain-first.example.", PLAIN, WITH_EDNS),
    ] {
        let (one, two) = (query(name, first, b""), query(name, second, b""));
        let answers = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(ask(&engine, &one), ask(&engine, &two))
        })
        .await
        .expect("answers in time");
        assert_eq!(
            answers,
            (answered(first, ANSWER), answered(second, ANSWER)),
            "{name}"
        );
    }
    assert_eq!(up.queries(), 2, "merged");
}

/// 上游不照抄 DO 位，客户端拿到的 DO 位仍是自己问的
/// An upstream that does not copy the DO bit: the client still gets its own back
#[tokio::test]
async fn an_upstream_that_drops_do_does_not_change_the_clients() {
    let up = upstream(false, Duration::ZERO).await;
    let engine = static_or_forward(&up.address);
    let dnssec = Asked {
        edns: Some(true),
        ..PLAIN
    };
    assert_eq!(
        ask_like_a_listener(&engine, &query("signed.example.", dnssec, b"")).await,
        answered(dnssec, ANSWER)
    );
    assert_eq!(
        ask_like_a_listener(&engine, &query("signed.example.", dnssec, b"")).await,
        answered(dnssec, ANSWER),
        "from the cache"
    );
}

/// 监听器自己构造的 SERVFAIL 也照查询带 OPT、DO、RD 和 CD
/// The SERVFAIL a listener builds itself carries the OPT, DO, RD and CD its query had
#[test]
fn a_listener_servfail_carries_what_its_query_asked() {
    for asked in every_way() {
        let packet = query("www.example.", asked, b"");
        let servfail = Answered {
            address: None,
            ..answered(asked, ANSWER)
        };
        assert_eq!(
            read(
                &engine_helpers::try_build_servfail_response_from_wire(&packet).expect("SERVFAIL")
            ),
            servfail,
            "{asked:?}"
        );
        assert_eq!(
            read(&engine_helpers::build_servfail_response_from_wire(&packet)),
            servfail,
            "{asked:?}, from wire"
        );
    }
}
