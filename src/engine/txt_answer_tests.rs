//! 引擎自己编出来的 TXT 应答（静态 TXT、替换 TXT）整个报文都装得下，不管客户端带不带 EDNS、ECS；装不下时回
//! SERVFAIL（见 `response::txt_size_problem`）。RDATA 里每段除了内容还有一个长度字节。
//! A TXT answer the engine builds itself (a static TXT, a replaced TXT) fits a message whole,
//! whether or not the client asked with EDNS and ECS, and is SERVFAIL when it does not (see
//! `response::txt_size_problem`). In RDATA each segment has a length byte besides its content.

use std::net::{IpAddr, Ipv6Addr};
use std::time::Duration;

use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsOption};
use hickory_proto::rr::{Name, RecordType};
use serde_json::{Value, json};

use crate::engine::Engine;
use crate::engine::response::{name_wire_len, txt_size_problem};
use crate::engine::test_support::{answering_upstream, counting_settings, engine_from, peer};

/// 问的名字，编码以后 8 字节 / The name asked, 8 bytes once encoded
const QNAME: &str = "t.test.";
/// 问 [`QNAME`] 时一条静态 TXT 的 RDATA 最多能有多长：65535 减去报文头 12、问题段 8 + 4、记录名字的指针 2
/// 和固定部分 10、OPT 11、ECS 选项 24 / The longest RDATA a static TXT can have when [`QNAME`] is
/// asked: 65535 less the header (12), the question (8 + 4), the record's name pointer (2)
/// and fixed part (10), an OPT (11) and an ECS option (24)
const ROOM: usize = 65535 - 12 - 8 - 4 - 2 - 10 - 11 - 24;

/// RDATA 正好 `rdata` 字节的 TXT 内容：一段 255 字节（加长度字节 256），最后一段补齐
/// TXT content whose RDATA is exactly `rdata` bytes: segments of 255 (256 with the length
/// byte), the last one making up the rest
fn text_of_rdata(rdata: usize) -> Vec<String> {
    let mut left = rdata;
    let mut text = Vec::new();
    while left > 0 {
        let take = left.min(256);
        text.push("a".repeat(take - 1));
        left -= take;
    }
    text
}

/// 三种问法：不带 EDNS，带 EDNS，带 EDNS 和一个回显最长的 ECS（IPv6 /128）
/// Three ways of asking: without EDNS, with EDNS, and with EDNS and the ECS whose echo is
/// longest (IPv6 /128)
fn queries() -> [(&'static str, Vec<u8>); 3] {
    let base = || {
        let mut query = Message::new(0x3333, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(
            Name::from_ascii(QNAME).unwrap(),
            RecordType::TXT,
        ));
        query
    };
    let with_edns = |subnet: bool| {
        let mut query = base();
        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        if subnet {
            edns.options_mut()
                .insert(EdnsOption::Subnet(ClientSubnet::new(
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 3, 4, 5, 6)),
                    128,
                    0,
                )));
        }
        query.set_edns(edns);
        query.to_vec().unwrap()
    };
    [
        ("plain", base().to_vec().unwrap()),
        ("edns", with_edns(false)),
        ("ecs", with_edns(true)),
    ]
}

/// 请求、回答两个阶段都给出 `text` 的引擎：名字以 `req.test` 结尾的在请求阶段给出静态 TXT，其余转发出去，
/// 回答以后用 `replace_txt_response` 换成它
/// An engine giving `text` in both phases: a name under `req.test` gets a static TXT in the
/// request phase, the rest are forwarded and the answer replaced with it by
/// `replace_txt_response`
fn engine_with(rules: Value) -> Engine {
    engine_from(json!({
        "settings": counting_settings(json!({})),
        "pipelines": [{ "id": "main", "rules": rules }]
    }))
}

async fn reply(engine: &Engine, packet: &[u8]) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(5), engine.handle_packet(packet, peer()))
        .await
        .expect("answer in time")
        .expect("answer")
        .to_vec()
}

/// 应答的响应码、TC 位、回答个数 / A reply's response code, TC bit and answer count
fn summary(reply: &[u8]) -> (ResponseCode, bool, u16) {
    (
        ResponseCode::from(0, reply[3] & 0x0F),
        reply[2] & 0x02 != 0,
        u16::from_be_bytes([reply[6], reply[7]]),
    )
}

#[test]
fn name_wire_len_counts_a_length_byte_per_label_and_the_root() {
    for (name, len) in [(".", 1), ("t.test.", 8), ("www.example.com.", 17)] {
        assert_eq!(
            name_wire_len(&Name::from_ascii(name).unwrap()),
            len,
            "{name}"
        );
    }
}

/// 上限算上每段的长度字节，按问的名字和留给 OPT、ECS 的地方算到字节：正好 [`ROOM`] 装得下，多一个字节不行。
/// 以前只数内容：256 段 255 字节（RDATA 65536）也算放得下
/// The limit counts each segment's length byte and is exact to the byte for the name asked
/// and the room kept for an OPT and ECS: exactly [`ROOM`] fits, one byte more does not. Only
/// the content used to count: 256 segments of 255 bytes (RDATA 65536) passed
#[test]
fn txt_size_problem_counts_length_bytes_against_the_whole_message() {
    let name_len = name_wire_len(&Name::from_ascii(QNAME).unwrap());
    assert_eq!(txt_size_problem(&text_of_rdata(ROOM), name_len), None);
    assert!(txt_size_problem(&text_of_rdata(ROOM + 1), name_len).is_some());
    assert!(txt_size_problem(&vec!["a".repeat(255); 256], name_len).is_some());
    // 配置检查按最短的根名字算 / The configuration check takes the shortest name, the root
    let root_room = ROOM + 7;
    assert_eq!(txt_size_problem(&text_of_rdata(root_room), 1), None);
    assert!(txt_size_problem(&text_of_rdata(root_room + 1), 1).is_some());
    let long_segment = txt_size_problem(&["a".repeat(256)], 1).unwrap();
    assert!(
        long_segment.contains("segment of 256 bytes"),
        "{long_segment}"
    );
}

/// 配置检查报出不管问什么名字都装不下的 TXT，静态的和替换的一样；按根名字正好装得下的不报
/// The configuration check names a TXT that fits no question at all, static or replaced
/// alike; one that just fits for the root name is no problem
#[test]
fn the_configuration_check_names_a_txt_no_answer_can_hold() {
    let problems = |text: Vec<String>| {
        crate::config::problems(
            &serde_json::from_value(json!({
                "settings": { "default_upstream": "192.0.2.53:53" },
                "pipelines": [{ "id": "main", "rules": [
                    {
                        "name": "static",
                        "matchers": [{ "type": "any" }],
                        "actions": [{ "type": "static_txt_response", "text": text }]
                    },
                    {
                        "name": "replaced",
                        "matchers": [{ "type": "any" }],
                        "actions": [{ "type": "forward", "upstream": "192.0.2.53:53" }],
                        "response_actions_on_match": [{ "type": "replace_txt_response", "text": text }]
                    }
                ]}]
            }))
            .unwrap(),
        )
    };
    assert_eq!(problems(text_of_rdata(ROOM + 7)), Vec::<String>::new());
    for text in [text_of_rdata(ROOM + 8), vec!["a".repeat(255); 256]] {
        let found = problems(text);
        assert_eq!(found.len(), 2, "{found:#?}");
        assert!(
            found
                .iter()
                .all(|problem| problem.contains("in its record")),
            "{found:#?}"
        );
    }
}

/// 请求阶段的静态 TXT：正好装得下的不管怎么问都作答，报文不超过 65535 字节；多一个字节的回 SERVFAIL、不带 TC。
/// 第二次问由规则缓存作答，结果一样。以前装不下时回 NOERROR、TC 置位、没有答案，带 EDNS 来问时还会交出超过
/// 65535 字节的报文
/// A request-phase static TXT: one that just fits is answered however it is asked, the
/// message at most 65535 bytes; one byte more is SERVFAIL without TC. Asked again, the rule
/// cache answers, alike. What did not fit used to be NOERROR with TC set and no answers,
/// and asked with EDNS a message over 65535 bytes could come out
#[tokio::test]
async fn a_static_txt_fits_the_message_or_is_servfail() {
    // 65490：以前客户端带 EDNS 来问时，引擎交出 65537 字节的报文，比一个 DNS 报文的上限还长
    // 65490: asked with EDNS, the engine used to hand out a 65537-byte message, longer than a
    // DNS message can be
    for (rdata, fits) in [
        (ROOM, true),
        (ROOM + 1, false),
        (65490, false),
        (65536, false),
    ] {
        let engine = engine_with(json!([{
            "name": "txt",
            "matchers": [{ "type": "any" }],
            "actions": [{ "type": "static_txt_response", "text": text_of_rdata(rdata) }]
        }]));
        for (asked, packet) in queries() {
            for round in ["first", "again"] {
                let answer = reply(&engine, &packet).await;
                let expected = if fits {
                    (ResponseCode::NoError, false, 1)
                } else {
                    (ResponseCode::ServFail, false, 0)
                };
                assert_eq!(
                    summary(&answer),
                    expected,
                    "rdata {rdata}, {asked}, {round}"
                );
                assert!(
                    answer.len() <= 65535,
                    "rdata {rdata}, {asked}: {} bytes",
                    answer.len()
                );
            }
        }
    }
}

/// 回答以后换成的 TXT 也一样：正好装得下的作答，多一个字节的回 SERVFAIL。以前替换时不查大小
/// A TXT the answer is replaced with is the same: one that just fits is answered, one byte
/// more is SERVFAIL. Replacing used not to check the size at all
#[tokio::test]
async fn a_replaced_txt_fits_the_message_or_is_servfail() {
    let upstream = answering_upstream(std::net::Ipv4Addr::new(192, 0, 2, 1), 300).await;
    for (rdata, fits) in [(ROOM, true), (ROOM + 1, false)] {
        let engine = engine_with(json!([{
            "name": "replace",
            "matchers": [{ "type": "any" }],
            "actions": [{ "type": "forward", "upstream": upstream.address }],
            "response_actions_on_match": [{ "type": "replace_txt_response", "text": text_of_rdata(rdata) }]
        }]));
        for (asked, packet) in queries() {
            let answer = reply(&engine, &packet).await;
            let expected = if fits {
                (ResponseCode::NoError, false, 1)
            } else {
                (ResponseCode::ServFail, false, 0)
            };
            assert_eq!(summary(&answer), expected, "rdata {rdata}, {asked}");
            assert!(
                answer.len() <= 65535,
                "rdata {rdata}, {asked}: {} bytes",
                answer.len()
            );
        }
    }
}
