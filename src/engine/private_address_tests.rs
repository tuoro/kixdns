//! 「是不是内网地址」在两处各多算一些：255.255.255.255 只在 `geoip_private` 这边算，其他不可全球路由的网段只在
//! ECS 那边算（见 `ecs_scope_tests`）。这里固定 `geoip_private` 这边的两条路：客户端的来源地址，和应答里的地址。
//! Whether an address is on a local network counts some more in each of two places:
//! 255.255.255.255 only for `geoip_private`, the other ranges that are not globally routable
//! only on the ECS side (see `ecs_scope_tests`). This pins the two paths of `geoip_private`:
//! the client's source address and the addresses in an answer.

use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use serde_json::json;

use crate::engine::test_support::{self as support, counting_settings, engine_from, first_a};

/// 客户端不是内网地址时的静态应答 / The static answer for a client not on a local network
const PUBLIC_CLIENT: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
/// 客户端是内网地址时的静态应答 / The static answer for a client on a local network
const PRIVATE_CLIENT: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 100);
/// 上游回的是内网地址时，响应动作换上的应答 / What a response action answers instead when the upstream answers a local network address
const PRIVATE_ANSWER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 200);

fn query(name: &str) -> Vec<u8> {
    let mut request = Message::new(0x2468, MessageType::Query, OpCode::Query);
    request.metadata.recursion_desired = true;
    request.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
    request.to_vec().unwrap()
}

fn peer(client: &str) -> SocketAddr {
    format!("{client}:53000").parse().unwrap()
}

/// `geoip_private` 把 0.0.0.0 和 255.255.255.255 都当作内网地址，来源地址和应答里的地址都这样。以前 0.0.0.0 不算：
/// 上游回 0.0.0.0（在 Linux、macOS 上连过去就是本机）时，防重绑定的规则放过了它
/// `geoip_private` counts 0.0.0.0 and 255.255.255.255 as local network addresses, for the
/// source address and for the addresses in an answer alike. 0.0.0.0 used not to count: an
/// upstream answering it (which reaches this machine on Linux and macOS) got past
/// anti-rebinding rules
#[tokio::test]
async fn geoip_private_counts_0_0_0_0_and_255_255_255_255() {
    // 上游回问题名第一个标签写的地址：zero 回 0.0.0.0，broadcast 回 255.255.255.255
    // The upstream answers the address the first label names: zero 0.0.0.0, broadcast
    // 255.255.255.255
    let up = support::upstream(|query| {
        let Some(question) = query.queries.first() else {
            return Vec::new();
        };
        let address = if question.name().to_ascii().starts_with("zero.") {
            Ipv4Addr::UNSPECIFIED
        } else {
            Ipv4Addr::BROADCAST
        };
        let mut reply = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
        reply.metadata.recursion_desired = query.metadata.recursion_desired;
        reply.add_query(question.clone());
        reply.add_answer(Record::from_rdata(
            question.name().clone(),
            300,
            RData::A(A(address)),
        ));
        vec![(std::time::Duration::ZERO, reply.to_vec().unwrap())]
    })
    .await;
    let engine = engine_from(json!({
        "settings": counting_settings(json!({})),
        "pipelines": [{ "id": "main", "rules": [
            {
                "name": "private-client",
                "matchers": [
                    { "type": "domain_suffix", "value": "client.test" },
                    { "type": "geoip_private", "expect": true }
                ],
                "actions": [{ "type": "static_ip_response", "ip": PRIVATE_CLIENT.to_string() }]
            },
            {
                "name": "public-client",
                "matchers": [{ "type": "domain_suffix", "value": "client.test" }],
                "actions": [{ "type": "static_ip_response", "ip": PUBLIC_CLIENT.to_string() }]
            },
            {
                "name": "answer",
                "matchers": [{ "type": "domain_suffix", "value": "answer.test" }],
                "actions": [{ "type": "forward", "upstream": up.address }],
                "response_matchers": [{ "type": "response_answer_ip_geoip_private", "expect": true }],
                "response_actions_on_match": [
                    { "type": "static_ip_response", "ip": PRIVATE_ANSWER.to_string() }
                ]
            }
        ] }]
    }));
    let answer = |reply: bytes::Bytes| first_a(&reply);
    // 客户端的来源地址 / The client's source address
    let public = peer("198.51.100.7");
    assert_eq!(
        answer(support::ask(&engine, &query("client.test."), public).await),
        Some(PUBLIC_CLIENT)
    );
    assert_eq!(
        answer(support::ask(&engine, &query("client.test."), peer("0.0.0.0")).await),
        Some(PRIVATE_CLIENT)
    );
    assert_eq!(
        answer(support::ask(&engine, &query("client.test."), peer("255.255.255.255")).await),
        Some(PRIVATE_CLIENT)
    );
    // 应答里的地址 / The address in an answer
    assert_eq!(
        answer(support::ask(&engine, &query("zero.answer.test."), public).await),
        Some(PRIVATE_ANSWER)
    );
    assert_eq!(
        answer(support::ask(&engine, &query("broadcast.answer.test."), public).await),
        Some(PRIVATE_ANSWER)
    );
}
