//! 静态应答只答它答得上的问题：静态 TXT 只答 TXT（和 ANY）查询，别的类型回 NODATA，和 static_ip_response 一样；
//! 静态应答的记录都是 IN 类的，问题的类别是 IN 或 ANY 时才答，别的类别（比如 CH）回 NODATA。
//! A static answer answers only what it can: a static TXT answers only TXT (and ANY)
//! queries, other types getting NODATA as static_ip_response gives; a static answer's
//! records are all of class IN, so only a question of class IN or ANY is answered, and
//! another class (CH, say) gets NODATA.

use std::net::Ipv4Addr;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use serde_json::{Value, json};

use crate::engine::Engine;
use crate::engine::test_support::{
    answering_upstream, ask, ask_like_a_listener, counting_settings, engine_from, peer,
};

fn engine_with(rules: Value) -> Engine {
    engine_from(json!({
        "settings": counting_settings(json!({})),
        "pipelines": [{ "id": "main", "rules": rules }]
    }))
}

fn static_rule(action: Value) -> Value {
    json!([{ "name": "static", "matchers": [{ "type": "any" }], "actions": [action] }])
}

fn query(name: &str, qtype: RecordType, class: DNSClass) -> Vec<u8> {
    let mut query = Message::new(0x9191, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    let mut question = Query::query(Name::from_ascii(name).unwrap(), qtype);
    question.set_query_class(class);
    query.add_query(question);
    query.to_vec().unwrap()
}

/// 应答的响应码和每条回答的类型、类别 / A reply's response code, and each answer's type and class
fn answers(reply: &[u8]) -> (ResponseCode, Vec<(RecordType, DNSClass)>) {
    let reply = Message::from_vec(reply).unwrap();
    (
        reply.metadata.response_code,
        reply
            .answers
            .iter()
            .map(|record| (record.record_type(), record.dns_class))
            .collect(),
    )
}

/// 静态 TXT 只答 TXT 和 ANY 查询，A、AAAA、MX 查询回 NODATA；请求阶段和回答阶段一样。以前每种查询的回答里
/// 都是一条 TXT
/// A static TXT answers only TXT and ANY queries, and A, AAAA and MX queries get NODATA;
/// the request phase and the response phase alike. Every query type used to get a TXT
/// record in its answer
#[tokio::test]
async fn a_static_txt_answers_only_txt_queries() {
    let upstream = answering_upstream(Ipv4Addr::new(192, 0, 2, 1), 300).await;
    let txt = json!({ "type": "static_txt_response", "text": ["v=spf1 -all"] });
    for (phase, engine) in [
        ("request", engine_with(static_rule(txt.clone()))),
        (
            "response",
            engine_with(json!([{
                "name": "after",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": upstream.address }],
                "response_actions_on_match": [txt.clone()]
            }])),
        ),
    ] {
        for (qtype, expected) in [
            (RecordType::TXT, vec![(RecordType::TXT, DNSClass::IN)]),
            (RecordType::ANY, vec![(RecordType::TXT, DNSClass::IN)]),
            (RecordType::A, vec![]),
            (RecordType::AAAA, vec![]),
            (RecordType::MX, vec![]),
        ] {
            let reply = ask(&engine, &query("a.txt.test.", qtype, DNSClass::IN), peer()).await;
            assert_eq!(
                answers(&reply),
                (ResponseCode::NoError, expected),
                "{phase} phase, {qtype}"
            );
        }
    }
}

/// 问题的类别不是 IN 也不是 ANY 时，静态 IP、CNAME、TXT 都回 NODATA：快速路径和完整路径一样。以前 CH 类的问题
/// 得到 IN 类的记录
/// For a question of a class other than IN and ANY, a static IP, CNAME and TXT all give
/// NODATA: the fast path and the full path alike. A CH-class question used to get IN-class
/// records
#[tokio::test]
async fn a_static_answer_gives_records_only_for_class_in() {
    for (action, qtype, record) in [
        (
            json!({ "type": "static_ip_response", "ip": "192.0.2.7" }),
            RecordType::A,
            RecordType::A,
        ),
        (
            json!({ "type": "static_cname_response", "target": "target.example" }),
            RecordType::A,
            RecordType::CNAME,
        ),
        (
            json!({ "type": "static_txt_response", "text": ["hello"] }),
            RecordType::TXT,
            RecordType::TXT,
        ),
    ] {
        let engine = engine_with(static_rule(action.clone()));
        for (class, expected) in [
            (DNSClass::IN, vec![(record, DNSClass::IN)]),
            (DNSClass::ANY, vec![(record, DNSClass::IN)]),
            (DNSClass::CH, vec![]),
            (DNSClass::HS, vec![]),
        ] {
            let packet = query("s.static.test.", qtype, class);
            for (path, reply) in [
                ("full", ask(&engine, &packet, peer()).await),
                (
                    "listener",
                    ask_like_a_listener(&engine, &packet, peer()).await,
                ),
            ] {
                assert_eq!(
                    answers(&reply),
                    (ResponseCode::NoError, expected.clone()),
                    "{action}, {class}, {path} path"
                );
            }
        }
    }
}

/// 回答阶段的静态 IP 也一样：CH 类的问题拿到 NODATA / A response-phase static IP is the same:
/// a CH-class question gets NODATA
#[tokio::test]
async fn a_response_phase_static_answer_gives_records_only_for_class_in() {
    let upstream = answering_upstream(Ipv4Addr::new(192, 0, 2, 1), 300).await;
    let engine = engine_with(json!([{
        "name": "after",
        "matchers": [{ "type": "any" }],
        "actions": [{ "type": "forward", "upstream": upstream.address }],
        "response_actions_on_match": [{ "type": "static_ip_response", "ip": "192.0.2.8" }]
    }]));
    let reply = ask(
        &engine,
        &query("r.static.test.", RecordType::A, DNSClass::CH),
        peer(),
    )
    .await;
    assert_eq!(answers(&reply), (ResponseCode::NoError, vec![]));
    let reply = ask(
        &engine,
        &query("r.static.test.", RecordType::A, DNSClass::IN),
        peer(),
    )
    .await;
    assert_eq!(
        Message::from_vec(&reply).unwrap().answers[0].data,
        RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(192, 0, 2, 8)))
    );
}
