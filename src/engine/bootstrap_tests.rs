//! 写成主机名的上游经 `bootstrap` 的服务器解析（见 `engine::bootstrap`）：引擎层面的测试
//! Upstreams written with a host name are resolved through the `bootstrap` servers (see
//! `engine::bootstrap`): engine-level tests

use std::net::Ipv4Addr;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::engine::test_support::{
    self as support, DohReply, counting_settings, engine_from, first_a, http_ok,
    loopback_bootstrap, peer, spawn_doh_upstream,
};
use crate::engine::transport::DOH_MEDIA_TYPE;

/// DoH 上游给的地址 / The address the DoH upstream answers
const ANSWER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

/// 设了 `bootstrap` 时，写成 `upstream.test` 的 DoH 上游由它解析：这个名字只有本机的 bootstrap 服务器认得，
/// 系统的解析器解析不出来
/// With `bootstrap` set, a DoH upstream written as `upstream.test` is resolved through it: the
/// name is known to the local bootstrap server only, and the system resolver cannot resolve it
#[tokio::test]
async fn a_named_upstream_is_resolved_through_bootstrap() {
    let bootstrap = loopback_bootstrap(300).await;
    let (doh, _) = spawn_doh_upstream(|_, body| {
        let query = Message::from_bytes(body).expect("parse the query");
        let mut answer = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
        let question = query.queries[0].clone();
        answer.add_answer(Record::from_rdata(
            question.name().clone(),
            300,
            RData::A(A(ANSWER)),
        ));
        answer.add_query(question);
        DohReply::Raw(http_ok(Some(DOH_MEDIA_TYPE), &answer.to_vec().unwrap()))
    })
    .await;
    let engine = engine_from(json!({
        "settings": counting_settings(json!({ "bootstrap": bootstrap.address })),
        "pipelines": [{ "id": "main", "rules": [{
            "name": "all", "matchers": [{ "type": "any" }],
            "actions": [{
                "type": "forward",
                "upstream": format!("https://upstream.test:{}/dns-query", doh.port())
            }]
        }] }]
    }));
    engine.doh_client.use_plain_http();

    let mut query = Message::new(7, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(
        Name::from_ascii("named.example.").unwrap(),
        RecordType::A,
    ));
    let reply = support::ask(&engine, &query.to_vec().unwrap(), peer()).await;
    assert_eq!(first_a(&reply), Some(ANSWER));
    let mut asked: Vec<_> = bootstrap
        .received()
        .iter()
        .map(|query| {
            let question = &query.queries[0];
            (question.name().to_ascii(), question.query_type())
        })
        .collect();
    asked.sort_by_key(|(_, record_type)| u16::from(*record_type));
    assert_eq!(
        asked,
        [
            ("upstream.test.".to_string(), RecordType::A),
            ("upstream.test.".to_string(), RecordType::AAAA),
        ]
    );
}

/// 本机的 TCP 上游，每条连接只答一个查询（一条 [`ANSWER`]）就关掉：下一个查询要新连，也就要再解析一次名字
/// A local TCP upstream answering a single query (with one [`ANSWER`]) on each connection and
/// closing it: the next query connects again, and so resolves the name again
async fn one_answer_per_connection() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut length = [0; 2];
                stream.read_exact(&mut length).await?;
                let mut query = vec![0; usize::from(u16::from_be_bytes(length))];
                stream.read_exact(&mut query).await?;
                let query = Message::from_bytes(&query).expect("parse the query");
                let mut answer =
                    Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
                let question = query.queries[0].clone();
                answer.add_answer(Record::from_rdata(
                    question.name().clone(),
                    300,
                    RData::A(A(ANSWER)),
                ));
                answer.add_query(question);
                let answer = answer.to_vec().unwrap();
                stream
                    .write_all(&(answer.len() as u16).to_be_bytes())
                    .await?;
                stream.write_all(&answer).await
            });
        }
    });
    port
}

/// `name` 的 A 查询 / An A query for `name`
fn a_query(name: &str) -> Vec<u8> {
    let mut query = Message::new(7, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    query.to_vec().unwrap()
}

/// 上游的地址的 TTL 过了、bootstrap 又不答时，新连接马上用上次问到的地址，查询照常得到回答。以前新连接先等 bootstrap
/// 答，等满 `upstream_timeout_ms` 才轮到上次的地址，那时查询已经超时
/// With the upstream's addresses past their TTL and bootstrap not answering, a new connection
/// uses the addresses last given at once, and the query is answered as usual. A new connection
/// used to wait for bootstrap first, the last addresses standing in only after
/// `upstream_timeout_ms`, by when the query had timed out
#[tokio::test]
async fn a_new_connection_uses_the_last_addresses_at_once() {
    let bootstrap = loopback_bootstrap(0).await;
    let port = one_answer_per_connection().await;
    let engine = engine_from(json!({
        "settings": counting_settings(json!({ "bootstrap": bootstrap.address })),
        "pipelines": [{ "id": "main", "rules": [{
            "name": "all", "matchers": [{ "type": "any" }],
            "actions": [{ "type": "forward", "upstream": format!("tcp://upstream.test:{port}") }]
        }] }]
    }));
    let reply = support::ask(&engine, &a_query("first.example."), peer()).await;
    assert_eq!(first_a(&reply), Some(ANSWER));
    bootstrap.silence(true);
    let reply = support::ask(&engine, &a_query("second.example."), peer()).await;
    assert_eq!(first_a(&reply), Some(ANSWER));
}
