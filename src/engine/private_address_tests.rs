//! 「是不是内网地址」只有一份，`geoip_private` 和 ECS 都用它（见 `geoip::is_private_ip`；ECS 另外再算本地用的转换前缀
//! 64:ff9b:1::/48 和基准测试的 198.18.0.0/15，见 `ecs_scope_tests` 和 `ecs` 的测试）。这里固定 `geoip_private` 这边的
//! 两条路：客户端的来源地址，和应答里的地址。
//! Whether an address is on a local network is one list, which `geoip_private` and ECS both
//! use (see `geoip::is_private_ip`; ECS counts the local-use translation prefix
//! 64:ff9b:1::/48 and benchmarking's 198.18.0.0/15 more, see `ecs_scope_tests` and the tests
//! of `ecs`). This pins the two paths of `geoip_private`: the client's source address and the
//! addresses in an answer.

use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::{A, AAAA};
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

/// `geoip_private` 的两条路，来源地址和应答里的地址，按同一份内网地址判断：0.0.0.0、255.255.255.255，运营商级 NAT 和
/// Tailscale 的 100.64.0.0/10，嵌着内网地址的 NAT64 地址都算；公网地址和嵌着公网地址的 NAT64 地址（DNS64 的寻常回答）
/// 不算。以前 0.0.0.0 不算：上游回 0.0.0.0（在 Linux、macOS 上连过去就是本机）时，防重绑定的规则放过了它；100.64.0.0/10
/// 和 NAT64 地址也都不算
/// Both paths of `geoip_private`, the source address and the addresses in an answer, judge by
/// the one list of local network addresses: 0.0.0.0, 255.255.255.255, carrier-grade NAT's and
/// Tailscale's 100.64.0.0/10, and NAT64 addresses embedding a local one count; public
/// addresses and NAT64 addresses embedding a public one (an ordinary DNS64 answer) do not.
/// 0.0.0.0 used not to count: an upstream answering it (which reaches this machine on Linux
/// and macOS) got past anti-rebinding rules; nor did 100.64.0.0/10 or NAT64 addresses
#[tokio::test]
async fn geoip_private_counts_every_local_network_address() {
    // 上游回问题名第一个标签说的地址 / The upstream answers the address the first label names
    let up = support::upstream(|query| {
        let Some(question) = query.queries.first() else {
            return Vec::new();
        };
        let name = question.name().to_ascii();
        let label = name.split('.').next().unwrap_or_default();
        let data = match label {
            "zero" => RData::A(A(Ipv4Addr::UNSPECIFIED)),
            "broadcast" => RData::A(A(Ipv4Addr::BROADCAST)),
            "cgnat" => RData::A(A(Ipv4Addr::new(100, 64, 1, 1))),
            "nat64" => RData::AAAA(AAAA("64:ff9b::c0a8:101".parse().unwrap())),
            "dns64" => RData::AAAA(AAAA("64:ff9b::808:808".parse().unwrap())),
            _ => RData::A(A(Ipv4Addr::new(8, 8, 8, 8))),
        };
        let mut reply = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
        reply.metadata.recursion_desired = query.metadata.recursion_desired;
        reply.add_query(question.clone());
        reply.add_answer(Record::from_rdata(question.name().clone(), 300, data));
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
    for (client, expected) in [
        ("198.51.100.7", PUBLIC_CLIENT),
        ("0.0.0.0", PRIVATE_CLIENT),
        ("255.255.255.255", PRIVATE_CLIENT),
        ("100.100.100.100", PRIVATE_CLIENT),
    ] {
        assert_eq!(
            answer(support::ask(&engine, &query("client.test."), peer(client)).await),
            Some(expected),
            "{client}"
        );
    }
    // 应答里的地址 / The address in an answer
    let public = peer("198.51.100.7");
    for (label, private) in [
        ("zero", true),
        ("broadcast", true),
        ("cgnat", true),
        ("nat64", true),
        ("dns64", false),
        ("public", false),
    ] {
        let reply = support::ask(&engine, &query(&format!("{label}.answer.test.")), public).await;
        assert_eq!(answer(reply) == Some(PRIVATE_ANSWER), private, "{label}");
    }
}
