//! 槽位里的应答连同问题的类别一起核对：落在同一个槽位上的别的类别的应答不会交出去。
//! The answers in a slot are checked against the question's class too: an answer for another
//! class landing in the same slot is not handed out.

use std::net::Ipv4Addr;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{DNSClass, Name, RecordType};
use serde_json::json;

use crate::engine::test_support::{answering_upstream, ask, engine_from, peer};
use crate::matcher::RequesterKey;
use crate::proto_utils::QueryFlags;

fn query(class: DNSClass) -> Vec<u8> {
    let mut query = Message::new(0x7171, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    let mut question = Query::query(Name::from_ascii("class.test.").unwrap(), RecordType::A);
    question.set_query_class(class);
    query.add_query(question);
    query.to_vec().unwrap()
}

/// 槽位里有一份 CH 类问题的应答（槽位撞上了，这里直接放进去），同一个名字的 IN 类问题不拿它，去问上游。以前槽位里的应答
/// 只核对名字、类型、查询位和 pipeline，不核对类别
/// With an answer to the CH question in the slot (the slots collided, put there directly
/// here), the IN question for the same name does not take it and asks the upstream. The
/// answers in a slot used to be checked by name, type, query bits and pipeline, and not by
/// class
#[tokio::test]
async fn an_answer_for_another_class_in_the_slot_is_not_taken() {
    let upstream = answering_upstream(Ipv4Addr::new(192, 0, 2, 1), 300).await;
    let engine = engine_from(json!({
        "settings": { "default_upstream": "127.0.0.1:9" },
        "pipelines": [{ "id": "main", "rules": [{
            "name": "all", "matchers": [{ "type": "any" }],
            "actions": [{ "type": "forward", "upstream": upstream.address }]
        }]}]
    }));
    let slot = |class| {
        crate::engine::types::KeyedQuestion {
            namespace: engine.state.load().cache_namespace("main"),
            pipeline_id: "main",
            qname: b"class.test",
            qtype: RecordType::A,
            qclass: class,
            flags: QueryFlags::RECURSIVE,
            requester: RequesterKey::NONE,
            client_ecs: None,
        }
        .slot()
    };
    ask(&engine, &query(DNSClass::CH), peer()).await;
    let chaos = engine
        .cached(slot(DNSClass::CH))
        .expect("the CH answer is cached");
    engine.cache_insert(slot(DNSClass::IN), chaos);

    ask(&engine, &query(DNSClass::IN), peer()).await;
    assert_eq!(upstream.queries(), 2, "the IN question went upstream");
}
