//! DNS cookie（RFC 7873）只在相邻两跳之间有效：引擎层面的测试。
//! DNS cookies (RFC 7873) hold between two neighbouring hops only: engine-level tests.

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use parking_lot::Mutex;

use crate::engine::Engine;
use crate::matcher::RuntimePipelineConfig;

/// 测试上游给出的服务器 cookie / The server cookie the test upstream hands out
const SERVER_COOKIE: &[u8] = b"SRVCOOKI";

/// 假上游怎样处理 cookie / How the fake upstream treats cookies
#[derive(Clone, Copy)]
enum Cookies {
    /// 照 RFC 7873 回显查询带来的客户端 cookie，再附上自己的服务器 cookie
    /// Echo the client cookie a query brings, plus its own server cookie, as RFC 7873 says
    Echo,
    /// 不管查询带没带，都塞一个 cookie（不守规矩的上游）
    /// Add a cookie whether or not the query brought one (a misbehaving upstream)
    Always,
}

/// 假上游 / A fake upstream
struct Upstream {
    address: String,
    /// 收到的查询个数 / How many queries it received
    queries: Arc<AtomicUsize>,
    /// 每个查询带来的 cookie / The cookie each query brought
    seen: Arc<Mutex<Vec<Option<Vec<u8>>>>>,
}

/// 消息里的 cookie 选项 / The cookie option in a message
fn cookie_of(message: &Message) -> Option<Vec<u8>> {
    // hickory 不认识 cookie，按未知选项保存 / hickory keeps a cookie as an unknown option
    match message.edns.as_ref()?.options().get(EdnsCode::Cookie)? {
        EdnsOption::Unknown(_, data) => Some(data.clone()),
        _ => None,
    }
}

/// 回答 example.com A 192.0.2.1 的本机 UDP 上游，cookie 按 `cookies` 处理
/// A local UDP upstream answering example.com A 192.0.2.1, treating cookies as `cookies` says
async fn upstream(cookies: Cookies) -> Upstream {
    let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let address = sock.local_addr().unwrap().to_string();
    let queries = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (counted, recorded) = (queries.clone(), seen.clone());
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
            let client_cookie =
                cookie_of(&query).map(|cookie| cookie[..8.min(cookie.len())].to_vec());
            recorded.lock().push(client_cookie.clone());
            let mut resp = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
            resp.add_query(question.clone());
            resp.add_answer(Record::from_rdata(
                question.name().clone(),
                300,
                RData::A(A::new(192, 0, 2, 1)),
            ));
            let cookie = match (cookies, client_cookie) {
                (_, Some(client)) => Some([client.as_slice(), SERVER_COOKIE].concat()),
                (Cookies::Always, None) => Some([b"STRANGER".as_slice(), SERVER_COOKIE].concat()),
                (Cookies::Echo, None) => None,
            };
            if query.edns.is_some() || cookie.is_some() {
                let mut edns = Edns::new();
                edns.set_max_payload(1232);
                if let Some(cookie) = cookie {
                    edns.options_mut()
                        .insert(EdnsOption::Unknown(u16::from(EdnsCode::Cookie), cookie));
                }
                resp.edns = Some(edns);
            }
            let _ = sock.send_to(&resp.to_vec().unwrap(), peer).await;
        }
    });
    Upstream {
        address,
        queries,
        seen,
    }
}

fn engine(upstream: &str) -> Engine {
    let raw = serde_json::json!({
        "settings": {
            "default_upstream": "127.0.0.1:9",
            "upstream_timeout_ms": 3000,
            "enable_tcp_fallback": false
        },
        "pipeline_select": [],
        "pipelines": [{ "id": "main", "rules": [{
            "name": "all", "matchers": [{ "type": "any" }],
            "actions": [{ "type": "forward", "upstream": upstream }]
        }] }]
    });
    let config: crate::config::PipelineConfig = serde_json::from_value(raw).expect("parse config");
    Engine::new(
        RuntimePipelineConfig::from_config(config).expect("build runtime config"),
        "test".to_string(),
    )
    .expect("engine")
}

/// 查询 example.com A，带上客户端 cookie `cookie`（None 时 EDNS 也不带）
/// A query for example.com A carrying the client cookie `cookie` (no EDNS at all with None)
fn query(cookie: Option<&[u8; 8]>) -> Vec<u8> {
    let mut request = Message::new(0xBEEF, MessageType::Query, OpCode::Query);
    request.metadata.recursion_desired = true;
    request.add_query(Query::query(
        Name::from_str("example.com").unwrap(),
        RecordType::A,
    ));
    if let Some(cookie) = cookie {
        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        edns.options_mut().insert(EdnsOption::Unknown(
            u16::from(EdnsCode::Cookie),
            cookie.to_vec(),
        ));
        request.edns = Some(edns);
    }
    request.to_vec().unwrap()
}

async fn reply(engine: &Engine, client: &str, cookie: Option<&[u8; 8]>) -> Message {
    let peer: SocketAddr = format!("{client}:53000").parse().unwrap();
    let bytes: Bytes = tokio::time::timeout(
        Duration::from_secs(5),
        engine.handle_packet(&query(cookie), peer),
    )
    .await
    .expect("answer in time")
    .expect("answer");
    Message::from_bytes(&bytes).expect("parse the reply")
}

/// 客户端的 cookie 是它和 KixDNS 之间的，不能转给上游：上游会把它带回来，随应答进缓存，
/// 再交给别的客户端——会校验 cookie 的客户端于是把命中缓存的应答当成伪造的丢掉，没发
/// cookie 的客户端也会收到一个。
/// A client's cookie belongs between it and KixDNS and must not go upstream: the
/// upstream brings it back, it enters the cache with the answer and goes to other
/// clients, so a client that checks cookies throws a cached answer away as forged,
/// and a client that sent none gets one too.
#[tokio::test]
async fn a_client_cookie_stays_off_the_upstream_and_out_of_the_cache() {
    let upstream = upstream(Cookies::Echo).await;
    let engine = engine(&upstream.address);

    let first = reply(&engine, "192.168.1.10", Some(b"CLIENT-1")).await;
    assert_eq!(
        upstream.seen.lock().as_slice(),
        &[None],
        "the client's cookie must not be forwarded"
    );
    assert_eq!(cookie_of(&first), None, "the reply carries no cookie back");

    let second = reply(&engine, "192.168.1.20", Some(b"CLIENT-2")).await;
    assert_eq!(
        upstream.queries.load(Ordering::SeqCst),
        1,
        "the second client is answered from the cache"
    );
    assert_eq!(
        cookie_of(&second),
        None,
        "nobody gets another client's cookie"
    );
    let third = reply(&engine, "192.168.1.30", None).await;
    assert_eq!(
        cookie_of(&third),
        None,
        "a client that sent no cookie gets none"
    );
}

/// 上游不守规矩、自己塞了 cookie 时，它也进不了缓存，到不了任何客户端
/// A cookie a misbehaving upstream adds on its own enters neither the cache nor any reply
#[tokio::test]
async fn a_cookie_the_upstream_adds_reaches_no_client() {
    let upstream = upstream(Cookies::Always).await;
    let engine = engine(&upstream.address);

    let first = reply(&engine, "192.168.1.10", Some(b"CLIENT-1")).await;
    assert_eq!(
        cookie_of(&first),
        None,
        "the reply that missed the cache carries none"
    );
    let second = reply(&engine, "192.168.1.20", None).await;
    assert_eq!(
        upstream.queries.load(Ordering::SeqCst),
        1,
        "the second client is answered from the cache"
    );
    assert_eq!(cookie_of(&second), None, "the cached answer carries none");
    assert!(
        second
            .answers
            .iter()
            .any(|record| matches!(record.data, RData::A(_))),
        "the answer itself is intact"
    );
}
