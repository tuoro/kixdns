//! 按 RFC 7871 的作用范围缓存应答：引擎层面的测试。
//! Caching answers by their RFC 7871 scope: engine-level tests.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};
use hickory_proto::rr::rdata::{A, SOA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use parking_lot::Mutex;

use crate::engine::Engine;
use crate::matcher::RuntimePipelineConfig;

/// 查询没带 ECS 时应答的地址 / The address answered when a query carries no ECS
const NO_SUBNET: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 99);

/// 假上游怎样在应答里写 ECS / How the fake upstream writes ECS into its reply
#[derive(Clone, Copy)]
enum Echo {
    /// 不带 ECS 选项 / No ECS option
    Nothing,
    /// 回显查询的子网，作用范围为这个长度 / Echo the query's subnet with this scope
    Scope(u8),
    /// 回显另一个子网 / Echo another subnet
    Other(&'static str, u8, u8),
}

/// 每个查询带来的 ECS（地址、前缀）/ The ECS (address, prefix) each query carried
type Seen = Arc<Mutex<Vec<Option<(IpAddr, u8)>>>>;

/// 假上游 / A fake upstream
struct Upstream {
    address: String,
    /// 收到的查询个数 / How many queries it received
    queries: Arc<AtomicUsize>,
    seen: Seen,
    /// 置位后不再应答 / Once set, it stops answering
    silent: Arc<AtomicBool>,
}

impl Upstream {
    fn queries(&self) -> usize {
        self.queries.load(Ordering::SeqCst)
    }
}

/// 按查询带来的 ECS 子网作答的本机上游：应答的地址就是子网地址（没有 ECS 时是 NO_SUBNET），
/// TTL 为 `ttl`，RCODE 为 `rcode`（报错时不带应答记录，带一条 SOA，所以也能缓存），按 `echo`
/// 回显 ECS，每个应答晚 `delay` 发出。
/// A local upstream answering with the ECS subnet the query carries (NO_SUBNET
/// without one) at TTL `ttl` with RCODE `rcode` (an error carries no answer but a
/// SOA, so it can be cached), echoing ECS as `echo` says, every reply `delay` late.
async fn upstream_with(echo: Echo, rcode: ResponseCode, ttl: u32, delay: Duration) -> Upstream {
    upstream_answering(move |_| (echo, ttl), rcode, delay).await
}

/// 同上，回显方式和 TTL 由 `per_query` 按查询带来的 ECS 决定
/// The same, with the echo and TTL `per_query` picks from the ECS a query carries
async fn upstream_answering(
    per_query: impl Fn(Option<ClientSubnet>) -> (Echo, u32) + Send + 'static,
    rcode: ResponseCode,
    delay: Duration,
) -> Upstream {
    let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let address = sock.local_addr().unwrap().to_string();
    let queries = Arc::new(AtomicUsize::new(0));
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let silent = Arc::new(AtomicBool::new(false));
    let (counted, recorded, muted) = (queries.clone(), seen.clone(), silent.clone());
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
            let subnet =
                query
                    .edns
                    .as_ref()
                    .and_then(|edns| match edns.options().get(EdnsCode::Subnet) {
                        Some(EdnsOption::Subnet(subnet)) => Some(*subnet),
                        _ => None,
                    });
            recorded
                .lock()
                .push(subnet.map(|s| (s.addr(), s.source_prefix())));
            if muted.load(Ordering::SeqCst) {
                continue;
            }
            let (echo, ttl) = per_query(subnet);
            let mut resp = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
            resp.metadata.response_code = rcode;
            resp.add_query(question.clone());
            if rcode == ResponseCode::NoError {
                let answer = match subnet.map(|subnet| subnet.addr()) {
                    Some(IpAddr::V4(v4)) => v4,
                    _ => NO_SUBNET,
                };
                resp.add_answer(Record::from_rdata(
                    question.name().clone(),
                    ttl,
                    RData::A(A(answer)),
                ));
            } else {
                let zone = Name::from_str("example.com.").unwrap();
                resp.add_authority(Record::from_rdata(
                    zone.clone(),
                    ttl,
                    RData::SOA(SOA::new(zone.clone(), zone, 1, 60, 60, 60, ttl)),
                ));
            }
            if query.edns.is_some() {
                let mut edns = Edns::new();
                edns.set_max_payload(1232);
                let echoed = match (echo, subnet) {
                    (Echo::Scope(scope), Some(subnet)) => Some(ClientSubnet::new(
                        subnet.addr(),
                        subnet.source_prefix(),
                        scope,
                    )),
                    (Echo::Other(address, source, scope), Some(_)) => {
                        Some(ClientSubnet::new(address.parse().unwrap(), source, scope))
                    }
                    _ => None,
                };
                if let Some(echoed) = echoed {
                    edns.options_mut().insert(EdnsOption::Subnet(echoed));
                }
                resp.edns = Some(edns);
            }
            let resp = resp.to_vec().unwrap();
            let sock = sock.clone();
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                let _ = sock.send_to(&resp, peer).await;
            });
        }
    });
    Upstream {
        address,
        queries,
        seen,
        silent,
    }
}

async fn upstream(echo: Echo) -> Upstream {
    upstream_with(echo, ResponseCode::NoError, 300, Duration::ZERO).await
}

fn engine_with(settings: serde_json::Value, pipelines: serde_json::Value) -> Engine {
    let mut all = serde_json::json!({
        "default_upstream": "127.0.0.1:9",
        "upstream_timeout_ms": 1000,
        "enable_tcp_fallback": false
    });
    all.as_object_mut()
        .unwrap()
        .extend(settings.as_object().unwrap().clone());
    let raw = serde_json::json!({
        "settings": all,
        "pipeline_select": [],
        "pipelines": pipelines
    });
    let config: crate::config::PipelineConfig = serde_json::from_value(raw).expect("parse config");
    Engine::new(
        RuntimePipelineConfig::from_config(config).expect("build runtime config"),
        "test".to_string(),
    )
    .expect("engine")
}

fn engine(pipelines: serde_json::Value) -> Engine {
    engine_with(serde_json::json!({}), pipelines)
}

fn forward_to(upstream: &str, ecs: Option<serde_json::Value>) -> serde_json::Value {
    let mut forward = serde_json::json!({ "type": "forward", "upstream": upstream });
    if let Some(ecs) = ecs {
        forward["ecs"] = ecs;
    }
    forward
}

/// 一个 pipeline，唯一的规则把所有请求转发给 `upstream`，转发带着 `ecs`（None 表示不写）
/// One pipeline whose only rule forwards everything to `upstream` with `ecs`
/// (None leaves it out)
fn forward_all(upstream: &str, ecs: Option<serde_json::Value>) -> serde_json::Value {
    serde_json::json!([{ "id": "main", "rules": [{
        "name": "all", "matchers": [{ "type": "any" }], "actions": [forward_to(upstream, ecs)]
    }] }])
}

fn from_client_ip() -> Option<serde_json::Value> {
    Some(serde_json::json!({ "mode": "from_client_ip" }))
}

/// 查询 example.com A，`subnet` 是客户端自己带的 ECS（地址/前缀，地址照原样写进去）
/// A query for example.com A, `subnet` the ECS the client carries (address/prefix,
/// the address written as given)
fn query(subnet: Option<(&str, u8)>) -> Vec<u8> {
    let mut request = Message::new(0xBEEF, MessageType::Query, OpCode::Query);
    request.metadata.recursion_desired = true;
    request.add_query(Query::query(
        Name::from_str("example.com").unwrap(),
        RecordType::A,
    ));
    if let Some((address, prefix)) = subnet {
        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        edns.options_mut()
            .insert(EdnsOption::Subnet(ClientSubnet::new(
                address.parse().unwrap(),
                prefix,
                0,
            )));
        request.edns = Some(edns);
    }
    request.to_vec().unwrap()
}

fn first_a(response: &Bytes) -> Option<Ipv4Addr> {
    let response = Message::from_bytes(response).expect("parse");
    match response.answers.first().map(|record| &record.data) {
        Some(RData::A(address)) => Some(address.0),
        _ => None,
    }
}

/// 应答里的 ECS：地址、SOURCE、SCOPE / The ECS in a reply: address, SOURCE, SCOPE
fn reply_ecs(response: &Bytes) -> Option<(IpAddr, u8, u8)> {
    let response = Message::from_bytes(response).expect("parse");
    match response.edns.as_ref()?.options().get(EdnsCode::Subnet)? {
        EdnsOption::Subnet(subnet) => {
            Some((subnet.addr(), subnet.source_prefix(), subnet.scope_prefix()))
        }
        _ => None,
    }
}

fn peer(client: &str) -> SocketAddr {
    format!("{client}:53000").parse().unwrap()
}

/// 整个应答 / The whole reply
async fn reply(engine: &Engine, client: &str, subnet: Option<(&str, u8)>) -> Bytes {
    reply_from(engine, peer(client), subnet).await
}

/// 同上，来源地址照原样给出 / The same, with the source address given as it is
async fn reply_from(engine: &Engine, peer: SocketAddr, subnet: Option<(&str, u8)>) -> Bytes {
    tokio::time::timeout(
        Duration::from_secs(5),
        engine.handle_packet(&query(subnet), peer),
    )
    .await
    .expect("answer in time")
    .expect("answer")
}

/// 应答里的第一个地址 / The first address in the reply
async fn ask(engine: &Engine, client: &str, subnet: Option<(&str, u8)>) -> Option<Ipv4Addr> {
    first_a(&reply(engine, client, subnet).await)
}

/// 像监听器那样应答：先走快速路径，需要时再走异步路径
/// Answer as a listener does: the fast path first, then the async path when needed
async fn ask_like_a_listener(
    engine: &Engine,
    client: &str,
    subnet: Option<(&str, u8)>,
) -> Option<Ipv4Addr> {
    use crate::engine::{FastPathResponse, PreParsedData};
    let packet = query(subnet);
    let reply = match engine
        .handle_packet_fast(&packet, peer(client))
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
                &packet,
                peer(client),
                false,
                PreParsedData::new(qname, qtype, qclass, tx_id, edns_present, pipeline_id),
            ),
        )
        .await
        .expect("answer in time")
        .expect("answer"),
        None => panic!("a query the fast path cannot read"),
    };
    first_a(&reply)
}

/// 两个请求同时到达 / Two requests at once
async fn ask_at_once(
    engine: &Engine,
    first: (&str, Option<(&str, u8)>),
    second: (&str, Option<(&str, u8)>),
) -> [Option<Ipv4Addr>; 2] {
    let (one, two) = (query(first.1), query(second.1));
    let (one, two) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            engine.handle_packet(&one, peer(first.0)),
            engine.handle_packet(&two, peer(second.0))
        )
    })
    .await
    .expect("answers in time");
    [first_a(&one.unwrap()), first_a(&two.unwrap())]
}

fn v4(text: &str) -> Option<Ipv4Addr> {
    Some(text.parse().unwrap())
}

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

/// 不写 `ecs` 的转发把客户端自己带的 ECS 原样转给上游。上游按子网作答（作用范围 /24），
/// 另一个子网的客户端不能从缓存拿到这份应答。
/// A forward without `ecs` passes the client's own ECS upstream. The upstream
/// answers per subnet (scope /24), so a client in another subnet must not get
/// that answer from the cache.
#[tokio::test]
async fn a_passed_through_client_subnet_keeps_cached_answers_apart() {
    let up = upstream(Echo::Scope(24)).await;
    let engine = engine(forward_all(&up.address, None));
    assert_eq!(
        ask(&engine, "10.0.0.1", Some(("198.51.100.0", 24))).await,
        v4("198.51.100.0")
    );
    assert_eq!(
        ask(&engine, "10.0.0.1", Some(("203.0.113.0", 24))).await,
        v4("203.0.113.0")
    );
    assert_eq!(
        ask(&engine, "10.0.0.2", Some(("198.51.100.0", 24))).await,
        v4("198.51.100.0")
    );
    assert_eq!(up.queries(), 2);
}

/// 同上，两个请求同时到达：后到的不能等在先到的那个上游请求上。
/// The same with both requests at once: the later one must not wait on the
/// earlier one's upstream query.
#[tokio::test]
async fn a_passed_through_client_subnet_keeps_waiting_requests_apart() {
    let up = upstream_with(
        Echo::Scope(24),
        ResponseCode::NoError,
        300,
        Duration::from_millis(150),
    )
    .await;
    let engine = engine(forward_all(&up.address, None));
    assert_eq!(
        ask_at_once(
            &engine,
            ("10.0.0.1", Some(("198.51.100.0", 24))),
            ("10.0.0.2", Some(("203.0.113.0", 24)))
        )
        .await,
        [v4("198.51.100.0"), v4("203.0.113.0")]
    );
    assert_eq!(up.queries(), 2);
}

/// `from_client_ip` 遇到私有地址的客户端时，也原样转发客户端自己带的 ECS。
/// `from_client_ip` passes the client's own ECS through for a private client too.
#[tokio::test]
async fn from_client_ip_with_a_private_client_keeps_its_subnets_apart() {
    let up = upstream(Echo::Scope(24)).await;
    let engine = engine(forward_all(&up.address, from_client_ip()));
    assert_eq!(
        ask(&engine, "192.168.1.10", Some(("198.51.100.0", 24))).await,
        v4("198.51.100.0")
    );
    assert_eq!(
        ask(&engine, "192.168.1.10", Some(("203.0.113.0", 24))).await,
        v4("203.0.113.0")
    );
    assert_eq!(up.queries(), 2);
}

/// pipeline 级 `ecs` 不再进任何键，同时到达、子网不同的两个公网客户端也不会互相等待。
/// The pipeline-level `ecs` keys nothing any more, and two public clients in
/// different subnets asking at once still do not wait on each other.
#[tokio::test]
async fn requests_with_a_pipeline_level_ecs_still_wait_apart() {
    let up = upstream_with(
        Echo::Scope(24),
        ResponseCode::NoError,
        300,
        Duration::from_millis(150),
    )
    .await;
    let engine = engine(serde_json::json!([{
        "id": "main",
        "ecs": { "mode": "from_client_ip" },
        "rules": [{
            "name": "all", "matchers": [{ "type": "any" }],
            "actions": [forward_to(&up.address, from_client_ip())]
        }]
    }]));
    assert_eq!(
        ask_at_once(&engine, ("198.51.100.7", None), ("203.0.113.9", None)).await,
        [v4("198.51.100.0"), v4("203.0.113.0")]
    );
    assert_eq!(up.queries(), 2);
}

/// RFC 7871 第 7.3 节：带 ECS 的查询得到不带 ECS 的应答，按作用范围 0 处理，每个发出 ECS 的
/// 请求方共用它；不发 ECS 的请求发给上游的是另一种查询，各自转发。
/// RFC 7871 section 7.3: a reply without ECS to a query with it counts as scope 0
/// and every requester that sends ECS shares it; a request that sends none asks
/// another kind of query and forwards on its own.
#[tokio::test]
async fn a_reply_without_ecs_is_shared_by_every_client_subnet() {
    let up = upstream(Echo::Nothing).await;
    let engine = engine(forward_all(&up.address, None));
    assert_eq!(
        ask(&engine, "10.0.0.1", Some(("198.51.100.0", 24))).await,
        v4("198.51.100.0")
    );
    assert_eq!(
        ask(&engine, "10.0.0.2", Some(("203.0.113.0", 24))).await,
        v4("198.51.100.0")
    );
    assert_eq!(up.queries(), 1);
    assert_eq!(ask(&engine, "10.0.0.3", None).await, Some(NO_SUBNET));
    assert_eq!(up.queries(), 2);
}

/// 作用范围 0 和不带 ECS 一样共用 / Scope 0 is shared just as a reply without ECS
#[tokio::test]
async fn scope_zero_is_shared_by_every_client_subnet() {
    let up = upstream(Echo::Scope(0)).await;
    let engine = engine(forward_all(&up.address, None));
    ask(&engine, "10.0.0.1", Some(("198.51.100.0", 24))).await;
    assert_eq!(
        ask(&engine, "10.0.0.2", Some(("203.0.113.0", 24))).await,
        v4("198.51.100.0")
    );
    assert_eq!(up.queries(), 1);
}

/// 作用范围 /16：同一个 /16 里的子网共用，别的 /16 各自转发。
/// Scope /16: subnets in the same /16 share it, another /16 forwards on its own.
#[tokio::test]
async fn a_scope_shares_the_answer_within_its_network() {
    let up = upstream(Echo::Scope(16)).await;
    let engine = engine(forward_all(&up.address, None));
    assert_eq!(
        ask(&engine, "10.0.0.1", Some(("198.51.100.0", 24))).await,
        v4("198.51.100.0")
    );
    assert_eq!(
        ask(&engine, "10.0.0.2", Some(("198.51.7.0", 24))).await,
        v4("198.51.100.0")
    );
    assert_eq!(up.queries(), 1);
    assert_eq!(
        ask(&engine, "10.0.0.3", Some(("203.0.113.0", 24))).await,
        v4("203.0.113.0")
    );
    assert_eq!(up.queries(), 2);
}

/// 作用范围比发出的前缀长：只给前缀相同的同一子网（第 7.3.1 节）。
/// A scope longer than the prefix sent: only the same subnet at the same prefix
/// (section 7.3.1).
#[tokio::test]
async fn a_scope_longer_than_the_source_serves_only_the_same_prefix() {
    let up = upstream(Echo::Scope(28)).await;
    let engine = engine(forward_all(&up.address, None));
    ask(&engine, "10.0.0.1", Some(("198.51.100.0", 24))).await;
    ask(&engine, "10.0.0.2", Some(("198.51.100.0", 24))).await;
    assert_eq!(up.queries(), 1);
    ask(&engine, "10.0.0.3", Some(("198.51.100.0", 25))).await;
    assert_eq!(up.queries(), 2);
}

/// 前缀为 0 的查询拿到的应答只给前缀为 0 的查询，即使应答不带 ECS。
/// An answer to a query with prefix 0 serves only queries with prefix 0, even
/// when the reply carries no ECS.
#[tokio::test]
async fn a_source_of_zero_answers_only_source_zero() {
    let up = upstream(Echo::Nothing).await;
    let engine = engine(forward_all(&up.address, None));
    ask(&engine, "10.0.0.1", Some(("0.0.0.0", 0))).await;
    ask(&engine, "10.0.0.2", Some(("198.51.100.0", 24))).await;
    assert_eq!(up.queries(), 2);
    ask(&engine, "10.0.0.3", Some(("0.0.0.0", 0))).await;
    assert_eq!(up.queries(), 2);
}

/// 应答回显的子网与发出的对不上：只给发出完全相同子网的请求。
/// A reply echoing another subnet serves only requests sending exactly the subnet
/// sent.
#[tokio::test]
async fn a_mismatched_echo_serves_only_the_subnet_sent() {
    let up = upstream(Echo::Other("203.0.113.0", 24, 16)).await;
    let engine = engine(forward_all(&up.address, None));
    ask(&engine, "10.0.0.1", Some(("198.51.100.0", 24))).await;
    ask(&engine, "10.0.0.2", Some(("198.51.100.0", 24))).await;
    assert_eq!(up.queries(), 1);
    assert_eq!(
        ask(&engine, "10.0.0.3", Some(("198.51.7.0", 24))).await,
        v4("198.51.7.0")
    );
    assert_eq!(up.queries(), 2);
}

/// 不带 ECS 的报错（这里是 REFUSED，带 SOA 所以能缓存）说的是发出的这个子网，不给别的子网。
/// An error without ECS (REFUSED here, with a SOA so it can be cached) speaks of
/// the subnet sent and does not go to another.
#[tokio::test]
async fn an_error_reply_without_ecs_is_not_shared() {
    let up = upstream_with(Echo::Nothing, ResponseCode::Refused, 300, Duration::ZERO).await;
    let engine = engine(forward_all(&up.address, None));
    reply(&engine, "10.0.0.1", Some(("198.51.100.0", 24))).await;
    reply(&engine, "10.0.0.2", Some(("198.51.100.0", 24))).await;
    assert_eq!(up.queries(), 1, "the error is cached for its own subnet");
    reply(&engine, "10.0.0.3", Some(("203.0.113.0", 24))).await;
    assert_eq!(up.queries(), 2);
}

/// `from_client_ip`：作用范围 0 时公网客户端共用，私有地址又不带 ECS 的客户端发的是没有 ECS
/// 的另一种查询，自己转发。
/// `from_client_ip`: at scope 0 public clients share the answer, while a private
/// client without ECS sends another kind of query, without ECS, and forwards on
/// its own.
#[tokio::test]
async fn a_private_client_without_ecs_does_not_take_a_public_clients_answer() {
    let up = upstream(Echo::Nothing).await;
    let engine = engine(forward_all(&up.address, from_client_ip()));
    assert_eq!(ask(&engine, "198.51.100.7", None).await, v4("198.51.100.0"));
    assert_eq!(ask(&engine, "203.0.113.9", None).await, v4("198.51.100.0"));
    assert_eq!(up.queries(), 1);
    assert_eq!(ask(&engine, "192.168.1.2", None).await, Some(NO_SUBNET));
    assert_eq!(up.queries(), 2);
}

/// 从缓存交给带 ECS 的客户端的应答，回显的是它自己的子网，作用范围是这份应答对它的作用范围；
/// 没带 ECS 的客户端拿到的应答不带 ECS。
/// A cached reply handed to a client that sent ECS echoes the client's own
/// subnet, with the scope the answer has for it; a client that sent none gets no
/// ECS.
#[tokio::test]
async fn a_cached_reply_echoes_the_clients_own_subnet() {
    let up = upstream(Echo::Scope(16)).await;
    let engine = engine(forward_all(&up.address, None));
    let fresh = reply(&engine, "10.0.0.1", Some(("198.51.100.0", 24))).await;
    assert_eq!(reply_ecs(&fresh), Some((ip("198.51.100.0"), 24, 16)));
    let cached = reply(&engine, "10.0.0.2", Some(("198.51.7.0", 24))).await;
    assert_eq!(first_a(&cached), v4("198.51.100.0"));
    assert_eq!(reply_ecs(&cached), Some((ip("198.51.7.0"), 24, 16)));
    assert_eq!(up.queries(), 1);
}

/// 转发替客户端加上的 ECS 不会带给没带 ECS 的客户端，刚转发回来的和缓存里的都一样。
/// The ECS a forward adds for a client that sent none never reaches it, whether
/// the reply was just forwarded or cached.
#[tokio::test]
async fn a_client_without_ecs_gets_no_ecs_back() {
    let up = upstream(Echo::Scope(0)).await;
    let engine = engine(forward_all(&up.address, from_client_ip()));
    let fresh = reply(&engine, "198.51.100.7", None).await;
    assert_eq!(first_a(&fresh), v4("198.51.100.0"));
    assert_eq!(reply_ecs(&fresh), None);
    // 缓存的应答不能把第一个客户端的子网交给第二个 / The cached reply must not hand the first client's subnet to the second
    let cached = reply(&engine, "203.0.113.9", None).await;
    assert_eq!(first_a(&cached), v4("198.51.100.0"));
    assert_eq!(reply_ecs(&cached), None);
    assert_eq!(up.queries(), 1);
}

/// 客户端带的 ECS 不完全合规（前缀之后的位不为零）：它照样原样转给上游，应答不缓存，也就
/// 不会交给别的客户端；它自己也不拿别人共用的应答。
/// A client ECS that does not follow the rules (bits set beyond the prefix) still
/// goes upstream as it is; the answer is not cached, so it never reaches another
/// client, and that client takes no shared answer either.
#[tokio::test]
async fn an_answer_to_a_malformed_client_ecs_is_not_cached() {
    let up = upstream(Echo::Nothing).await;
    let engine = engine(forward_all(&up.address, None));
    assert_eq!(
        ask(&engine, "10.0.0.1", Some(("198.51.127.0", 20))).await,
        v4("198.51.127.0")
    );
    assert_eq!(up.seen.lock()[0], Some((ip("198.51.127.0"), 20)));
    assert_eq!(
        ask(&engine, "10.0.0.2", Some(("203.0.113.0", 24))).await,
        v4("203.0.113.0")
    );
    assert_eq!(up.queries(), 2);
    // 合规的那份是大家共用的，读不懂的 ECS 不拿它 / The well-formed one is shared, but not with an unreadable ECS
    ask(&engine, "10.0.0.1", Some(("198.51.127.0", 20))).await;
    assert_eq!(up.queries(), 3);
}

/// 快速路径原样交出缓存的字节：存进缓存时已经去掉了 ECS。带 ECS 的请求只拿适用于它自己
/// 那份 ECS 的应答，给不带 ECS 的客户端的那份不适用。
/// The fast path hands cached bytes over as they are: the ECS was removed when
/// they were stored. A request with ECS takes only answers that apply to its own
/// ECS, and one for clients without ECS does not.
#[tokio::test]
async fn the_fast_path_hands_out_no_other_clients_subnet() {
    use crate::engine::FastPathResponse;
    let up = upstream(Echo::Scope(0)).await;
    let by_peer = engine(forward_all(&up.address, from_client_ip()));
    reply(&by_peer, "198.51.100.7", None).await;
    match by_peer.handle_packet_fast(&query(None), peer("203.0.113.9")) {
        Ok(Some(FastPathResponse::CacheHit { cached, .. })) => {
            assert_eq!(first_a(&cached), v4("198.51.100.0"));
            assert_eq!(reply_ecs(&cached), None);
        }
        _ => panic!("a cache hit on the fast path"),
    }
    // An answer for clients without ECS does not apply to a client with ECS, which
    // goes on to the async path and its own forward
    // 给不带 ECS 的客户端的应答不适用于带 ECS 的客户端，它接着走异步路径、自己转发
    let plain = upstream(Echo::Nothing).await;
    let passing = engine(forward_all(&plain.address, None));
    reply(&passing, "10.0.0.1", None).await;
    assert!(matches!(
        passing.handle_packet_fast(&query(Some(("198.51.100.0", 24))), peer("10.0.0.1")),
        Ok(Some(FastPathResponse::AsyncNeeded { .. }))
    ));
    assert_eq!(
        ask(&passing, "10.0.0.1", Some(("198.51.100.0", 24))).await,
        v4("198.51.100.0")
    );
}

/// 规则越过一个按 /24 作答的应答（continue），最终应答来自不带 ECS 的上游：它仍只适用于
/// 第一个应答适用的 /24，因为别的子网在第一步可能拿到另一个应答、不会越过它。
/// A rule continues past an answer scoped /24, and the final answer comes from an
/// upstream without ECS: it still applies only within that /24, since another
/// subnet might get another first answer and not continue past it.
#[tokio::test]
async fn a_continue_past_a_scoped_answer_keeps_the_final_answer_within_its_scope() {
    let checked = upstream(Echo::Scope(24)).await;
    let last = upstream(Echo::Nothing).await;
    let engine = engine(serde_json::json!([{ "id": "main", "rules": [
        {
            "name": "check", "matchers": [{ "type": "any" }],
            "actions": [forward_to(&checked.address, None)],
            "response_matchers": [{ "type": "upstream_equals", "value": checked.address }],
            "response_actions_on_match": [{ "type": "continue" }]
        },
        { "name": "last", "matchers": [{ "type": "any" }], "actions": [forward_to(&last.address, None)] }
    ] }]));
    assert_eq!(
        ask(&engine, "10.0.0.1", Some(("198.51.100.0", 24))).await,
        v4("198.51.100.0")
    );
    assert_eq!(
        ask(&engine, "10.0.0.2", Some(("203.0.113.0", 24))).await,
        v4("203.0.113.0")
    );
    assert_eq!(checked.queries(), 2);
    assert_eq!(last.queries(), 2);
}

/// 回答检查之后响应动作再转发一次：那次的应答（作用范围 /24）同样决定最终应答适用于谁。
/// A response action forwards once more after the answer check: that reply
/// (scope /24) decides whom the final answer applies to as well.
#[tokio::test]
async fn a_response_action_forward_keeps_its_answer_within_its_scope() {
    let checked = upstream(Echo::Nothing).await;
    let second = upstream(Echo::Scope(24)).await;
    let engine = engine(serde_json::json!([{ "id": "main", "rules": [{
        "name": "check", "matchers": [{ "type": "any" }],
        "actions": [forward_to(&checked.address, None)],
        "response_matchers": [{ "type": "upstream_equals", "value": checked.address }],
        "response_actions_on_match": [{ "type": "forward", "upstream": second.address }]
    }] }]));
    assert_eq!(
        ask(&engine, "10.0.0.1", Some(("198.51.100.0", 24))).await,
        v4("198.51.100.0")
    );
    assert_eq!(
        ask(&engine, "10.0.0.2", Some(("203.0.113.0", 24))).await,
        v4("203.0.113.0")
    );
    assert_eq!(second.queries(), 2);
}

/// 后台刷新带着触发它的客户端的 ECS 重放请求，不同子网的条目各自刷新。
/// A background refresh replays the request with the ECS of the client that
/// triggered it, and entries for different subnets refresh on their own.
#[tokio::test]
async fn a_background_refresh_replays_the_clients_ecs() {
    // Replies come late, so the first refresh is still running when the second starts
    // 应答来得晚，第二次刷新开始时第一次还没结束
    let up = upstream_with(
        Echo::Scope(24),
        ResponseCode::NoError,
        10,
        Duration::from_millis(200),
    )
    .await;
    let engine = engine_with(
        serde_json::json!({
            "cache_background_refresh": true,
            "cache_refresh_threshold_percent": 95,
            "cache_refresh_min_ttl": 0
        }),
        forward_all(&up.address, None),
    );
    ask(&engine, "10.0.0.1", Some(("198.51.100.0", 24))).await;
    ask(&engine, "10.0.0.2", Some(("203.0.113.0", 24))).await;
    // A second on, both entries are due for a refresh (9 of 10 seconds left)
    // 一秒之后两条都到了刷新时机（10 秒还剩 9 秒）
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let refreshes_started = std::time::Instant::now();
    // Hits that start a refresh of each entry / 两次命中各自发起一次刷新
    ask(&engine, "10.0.0.1", Some(("198.51.100.0", 24))).await;
    ask(&engine, "10.0.0.2", Some(("203.0.113.0", 24))).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while up.queries() < 4 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("both refreshes reach the upstream");
    let mut refreshed = up.seen.lock()[2..4].to_vec();
    refreshed.sort();
    // Each refreshed answer replaced its subnet's entry / 每份刷新回来的应答都换下了它那个子网的条目
    let slot = Engine::cache_keys(
        engine.state.load().cache_namespace("main"),
        "main",
        b"example.com",
        RecordType::A,
        hickory_proto::rr::DNSClass::IN,
        &crate::matcher::RequesterKey::NONE,
        None,
    )
    .slot;
    tokio::time::timeout(Duration::from_secs(5), async {
        while engine
            .cached_entries(slot)
            .iter()
            .filter(|entry| entry.fetched_at > refreshes_started)
            .count()
            < 2
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("both refreshed answers are cached");
    assert_eq!(engine.cached_entries(slot).len(), 2);
    assert_eq!(
        refreshed,
        [
            Some((ip("198.51.100.0"), 24)),
            Some((ip("203.0.113.0"), 24))
        ]
    );
}

/// 上游失败时，过期兜底给的是这个请求方自己子网的旧应答：立即续用，以及先等一会儿刷新
/// （serve_stale_client_timeout_ms）再续用，两条路都一样。
/// When the upstream fails, the stale fallback gives the requester the old answer
/// for its own subnet, whether it is served at once or after waiting for a refresh
/// (serve_stale_client_timeout_ms).
#[tokio::test]
async fn the_stale_fallback_serves_the_requesters_own_subnet() {
    for client_timeout_ms in [0, 100] {
        let up = upstream_with(Echo::Scope(24), ResponseCode::NoError, 1, Duration::ZERO).await;
        let engine = engine_with(
            serde_json::json!({
                "serve_stale": true,
                "serve_stale_client_timeout_ms": client_timeout_ms,
                "upstream_timeout_ms": 200
            }),
            forward_all(&up.address, None),
        );
        ask(&engine, "10.0.0.1", Some(("198.51.100.0", 24))).await;
        ask(&engine, "10.0.0.2", Some(("203.0.113.0", 24))).await;
        up.silent.store(true, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert_eq!(
            ask(&engine, "10.0.0.3", Some(("203.0.113.0", 24))).await,
            v4("203.0.113.0"),
            "client timeout {client_timeout_ms}"
        );
        assert_eq!(
            ask(&engine, "10.0.0.4", Some(("198.51.100.0", 24))).await,
            v4("198.51.100.0"),
            "client timeout {client_timeout_ms}"
        );
    }
}

/// 回答检查之后响应动作再转发一次，然后 continue 到下一条规则，由它的 allow 复用这个应答：
/// 应答适用于谁，由再转发那次（作用范围 /24）决定，不论这次是回答检查匹配还是没匹配。
/// A response action forwards once more after the answer check and then
/// continues, and the next rule's allow reuses that reply: whom it applies to is
/// decided by that second forward (scope /24), whether the check matched or not.
#[tokio::test]
async fn a_reply_a_response_action_fetched_and_continued_past_keeps_its_scope() {
    for on in ["response_actions_on_match", "response_actions_on_miss"] {
        let checked = upstream(Echo::Nothing).await;
        let second = upstream(Echo::Scope(24)).await;
        let value = if on == "response_actions_on_match" {
            checked.address.clone()
        } else {
            "127.0.0.1:9".to_string()
        };
        let mut check = serde_json::json!({
            "name": "check", "matchers": [{ "type": "any" }],
            "actions": [forward_to(&checked.address, None)],
            "response_matchers": [{ "type": "upstream_equals", "value": value }]
        });
        check[on] = serde_json::json!([
            { "type": "forward", "upstream": second.address },
            { "type": "continue" }
        ]);
        let engine = engine(serde_json::json!([{ "id": "main", "rules": [
            check,
            { "name": "take", "matchers": [{ "type": "any" }], "actions": [{ "type": "allow" }] }
        ] }]));
        assert_eq!(
            ask(&engine, "10.0.0.1", Some(("198.51.100.0", 24))).await,
            v4("198.51.100.0"),
            "{on}"
        );
        assert_eq!(
            ask(&engine, "10.0.0.2", Some(("203.0.113.0", 24))).await,
            v4("203.0.113.0"),
            "{on}"
        );
        assert_eq!(second.queries(), 2, "{on}");
    }
}

/// 读不懂的 ECS 选项从缓存拿到应答时，不会被回显一个它读不懂的选项：应答照样合规。
/// A client whose ECS option cannot be read gets a cached answer without an echo
/// it could not read either: the reply stays well-formed.
#[tokio::test]
async fn a_client_with_a_malformed_ecs_gets_a_well_formed_cached_reply() {
    let up = upstream(Echo::Nothing).await;
    let engine = engine(forward_all(
        &up.address,
        Some(serde_json::json!({ "mode": "clear" })),
    ));
    ask(&engine, "10.0.0.1", None).await;
    let cached = reply(&engine, "10.0.0.2", Some(("198.51.127.0", 20))).await;
    assert_eq!(up.queries(), 1, "a cleared ECS shares the answer");
    assert_eq!(first_a(&cached), Some(NO_SUBNET));
    assert_eq!(reply_ecs(&cached), None);
}

/// 刚转发回来的、不带 ECS 的报错，回显客户端子网时以它自己的前缀作为作用范围，与缓存里一样。
/// A fresh error without ECS echoes the client's subnet with the client's own
/// prefix as the scope, as the cache does.
#[tokio::test]
async fn a_fresh_error_echoes_the_clients_own_prefix() {
    let up = upstream_with(Echo::Nothing, ResponseCode::Refused, 300, Duration::ZERO).await;
    let engine = engine(forward_all(&up.address, None));
    let fresh = reply(&engine, "10.0.0.1", Some(("198.51.100.0", 24))).await;
    assert_eq!(reply_ecs(&fresh), Some((ip("198.51.100.0"), 24, 24)));
    let cached = reply(&engine, "10.0.0.2", Some(("198.51.100.0", 24))).await;
    assert_eq!(up.queries(), 1);
    assert_eq!(reply_ecs(&cached), Some((ip("198.51.100.0"), 24, 24)));
}

/// 带 ECS 的客户端也走快速路径：缓存命中直接给出回显它自己子网的应答，静态规则的应答也回显它
/// （作用范围 0）。
/// A client with ECS takes the fast path too: a cache hit is answered at once with
/// the echo of its own subnet, and so is a static rule's answer (scope 0).
#[tokio::test]
async fn a_client_with_ecs_is_answered_on_the_fast_path_with_its_echo() {
    use crate::engine::FastPathResponse;
    let up = upstream(Echo::Scope(16)).await;
    let engine = engine(serde_json::json!([{ "id": "main", "rules": [
        {
            "name": "block", "matchers": [{ "type": "domain_suffix", "value": "blocked.example" }],
            "actions": [{ "type": "static_ip_response", "ip": "0.0.0.0" }]
        },
        { "name": "all", "matchers": [{ "type": "any" }], "actions": [forward_to(&up.address, None)] }
    ] }]));
    reply(&engine, "10.0.0.1", Some(("198.51.100.0", 24))).await;
    match engine.handle_packet_fast(&query(Some(("198.51.7.0", 24))), peer("10.0.0.2")) {
        Ok(Some(FastPathResponse::Direct(reply))) => {
            assert_eq!(first_a(&reply), v4("198.51.100.0"));
            assert_eq!(reply_ecs(&reply), Some((ip("198.51.7.0"), 24, 16)));
            assert_eq!(Message::from_bytes(&reply).unwrap().metadata.id, 0xBEEF);
        }
        _ => panic!("a cache hit on the fast path"),
    }
    let mut blocked = Message::new(0xBEEF, MessageType::Query, OpCode::Query);
    blocked.add_query(Query::query(
        Name::from_str("ads.blocked.example").unwrap(),
        RecordType::A,
    ));
    let mut edns = Edns::new();
    edns.options_mut()
        .insert(EdnsOption::Subnet(ClientSubnet::new(
            ip("203.0.113.0"),
            24,
            0,
        )));
    blocked.edns = Some(edns);
    match engine.handle_packet_fast(&blocked.to_vec().unwrap(), peer("10.0.0.3")) {
        Ok(Some(FastPathResponse::Direct(reply))) => {
            assert_eq!(first_a(&reply), v4("0.0.0.0"));
            assert_eq!(reply_ecs(&reply), Some((ip("203.0.113.0"), 24, 0)));
        }
        _ => panic!("a static answer on the fast path"),
    }
    assert_eq!(up.queries(), 1);
}

/// 上游失败时（转发之后的那条兜底路径），过期兜底同样只给请求方自己子网的旧应答。目标
/// pipeline 按客户端地址判断，跳转之后不查缓存，请求直接转发、失败，再落到兜底。
/// When the upstream fails (the fallback taken after a forward), the stale answer
/// is again the one for the requester's own subnet. The target pipeline judges by
/// client address, so nothing is looked up after the jump: the request forwards,
/// fails and falls back.
#[tokio::test]
async fn the_fallback_after_a_failed_forward_serves_the_requesters_own_subnet() {
    let up = upstream_with(Echo::Scope(24), ResponseCode::NoError, 1, Duration::ZERO).await;
    let engine = engine_with(
        serde_json::json!({ "serve_stale": true, "upstream_timeout_ms": 200 }),
        serde_json::json!([
            { "id": "main", "rules": [{
                "name": "jump", "matchers": [{ "type": "any" }],
                "actions": [{ "type": "jump_to_pipeline", "pipeline": "target" }]
            }] },
            { "id": "target", "rules": [{
                "name": "all", "matchers": [{ "type": "client_ip", "cidr": "0.0.0.0/0" }],
                "actions": [forward_to(&up.address, None)]
            }] }
        ]),
    );
    ask(&engine, "10.0.0.1", Some(("198.51.100.0", 24))).await;
    ask(&engine, "10.0.0.2", Some(("203.0.113.0", 24))).await;
    up.silent.store(true, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(
        ask(&engine, "10.0.0.3", Some(("203.0.113.0", 24))).await,
        v4("203.0.113.0")
    );
    assert_eq!(
        ask(&engine, "10.0.0.4", Some(("198.51.100.0", 24))).await,
        v4("198.51.100.0")
    );
    // Both forwarded (a failed forward retries, so the count varies) and fell back
    // 两个请求都转发了（失败的转发会重试，次数不定），然后落到兜底
    assert!(up.queries() > 2, "both fell back after forwarding");
}

/// 一个子网的应答（作用范围 /24）过期后，这个子网的客户端经快速路径进来时重新去问上游，而不是
/// 退到别的子网取来的、所有人共用的那份（RFC 7871 第 7.3.2 节按最长前缀选，过期由选中的那份
/// 自己处理）。
/// Once a subnet's answer (scope /24) has expired, a client of that subnet coming
/// in through the fast path asks the upstream again rather than falling back to
/// the answer another subnet fetched for everyone (RFC 7871 section 7.3.2 picks
/// by longest prefix, and the picked answer's expiry decides).
#[tokio::test]
async fn an_expired_subnet_answer_is_fetched_again_rather_than_widened() {
    let up = upstream_answering(
        |subnet| match subnet.map(|subnet| subnet.addr()) {
            Some(address) if address == ip("198.51.100.0") => (Echo::Scope(24), 1),
            _ => (Echo::Scope(0), 300),
        },
        ResponseCode::NoError,
        Duration::ZERO,
    )
    .await;
    let engine = engine(forward_all(&up.address, None));
    assert_eq!(
        ask_like_a_listener(&engine, "10.0.0.1", Some(("198.51.100.0", 24))).await,
        v4("198.51.100.0")
    );
    assert_eq!(
        ask_like_a_listener(&engine, "10.0.0.2", Some(("203.0.113.0", 24))).await,
        v4("203.0.113.0")
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(
        ask_like_a_listener(&engine, "10.0.0.1", Some(("198.51.100.0", 24))).await,
        v4("198.51.100.0")
    );
    assert_eq!(up.queries(), 3);
}

/// 规则越过一个按 /24 作答的应答（continue），最终应答来自作用范围为 0 的上游：缓存只在这个
/// /24 里共用它，回给带 ECS 的客户端的作用范围也是 24，刚转发回来的、等在同一个条目上的、从缓存
/// 拿的都一样。报 0 会让下游的解析器把它分给所有子网。
/// A rule continues past an answer scoped /24, and the final answer comes from an
/// upstream answering scope 0: the cache shares it only within that /24, and the
/// scope reported to a client with ECS is 24 too, whether the reply was just
/// forwarded, handed to a request waiting on the same entry, or cached. Reporting
/// 0 would let a downstream resolver hand it to every subnet.
#[tokio::test]
async fn the_echo_keeps_the_scope_of_an_answer_continued_past() {
    let checked = upstream(Echo::Scope(24)).await;
    let last = upstream_with(
        Echo::Scope(0),
        ResponseCode::NoError,
        300,
        Duration::from_millis(150),
    )
    .await;
    let engine = engine(serde_json::json!([{ "id": "main", "rules": [
        {
            "name": "check", "matchers": [{ "type": "any" }],
            "actions": [forward_to(&checked.address, None)],
            "response_matchers": [{ "type": "upstream_equals", "value": checked.address }],
            "response_actions_on_match": [{ "type": "continue" }]
        },
        { "name": "last", "matchers": [{ "type": "any" }], "actions": [forward_to(&last.address, None)] }
    ] }]));
    let subnet = Some(("198.51.100.0", 24));
    let (one, two) = (query(subnet), query(subnet));
    let (one, two) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            engine.handle_packet(&one, peer("10.0.0.1")),
            engine.handle_packet(&two, peer("10.0.0.2"))
        )
    })
    .await
    .expect("answers in time");
    for fresh in [one.unwrap(), two.unwrap()] {
        assert_eq!(reply_ecs(&fresh), Some((ip("198.51.100.0"), 24, 24)));
    }
    assert_eq!(last.queries(), 1, "the second request waited on the first");
    let cached = reply(&engine, "10.0.0.3", subnet).await;
    assert_eq!(reply_ecs(&cached), Some((ip("198.51.100.0"), 24, 24)));
    assert_eq!(last.queries(), 1);
}

/// 转发失败后 on_miss 给出的应答（这里缓存 60 秒）只对同一个子网有效：另一个子网的转发可能
/// 不会失败。
/// The answer on_miss gives after a failed forward (cached for 60 seconds here)
/// holds only for the same subnet: another subnet's forward might not fail.
#[tokio::test]
async fn an_answer_after_a_failed_forward_stays_with_its_subnet() {
    let up = upstream(Echo::Scope(24)).await;
    up.silent.store(true, Ordering::SeqCst);
    let engine = engine_with(
        serde_json::json!({ "min_ttl": 60, "upstream_timeout_ms": 200 }),
        serde_json::json!([{ "id": "main", "rules": [{
            "name": "all", "matchers": [{ "type": "any" }],
            "actions": [forward_to(&up.address, None)],
            "response_actions_on_miss": [{ "type": "static_ip_response", "ip": "192.0.2.53" }]
        }] }]),
    );
    assert_eq!(
        ask(&engine, "10.0.0.1", Some(("198.51.100.0", 24))).await,
        v4("192.0.2.53")
    );
    let failed = up.queries();
    up.silent.store(false, Ordering::SeqCst);
    assert_eq!(
        ask(&engine, "10.0.0.2", Some(("203.0.113.0", 24))).await,
        v4("203.0.113.0")
    );
    assert!(up.queries() > failed);
}

/// 响应动作再转发一次却失败了：得到的 SERVFAIL（这里缓存 60 秒）同样只对同一个子网有效。
/// A response action's forward fails: the SERVFAIL it ends in (cached for 60
/// seconds here) holds only for the same subnet as well.
#[tokio::test]
async fn a_failed_response_action_forward_stays_with_its_subnet() {
    let checked = upstream(Echo::Nothing).await;
    let second = upstream(Echo::Scope(24)).await;
    second.silent.store(true, Ordering::SeqCst);
    let engine = engine_with(
        serde_json::json!({ "min_ttl": 60, "upstream_timeout_ms": 200 }),
        serde_json::json!([{ "id": "main", "rules": [{
            "name": "check", "matchers": [{ "type": "any" }],
            "actions": [forward_to(&checked.address, None)],
            "response_matchers": [{ "type": "upstream_equals", "value": checked.address }],
            "response_actions_on_match": [{ "type": "forward", "upstream": second.address }]
        }] }]),
    );
    reply(&engine, "10.0.0.1", Some(("198.51.100.0", 24))).await;
    let failed = second.queries();
    second.silent.store(false, Ordering::SeqCst);
    assert_eq!(
        ask(&engine, "10.0.0.2", Some(("203.0.113.0", 24))).await,
        v4("203.0.113.0")
    );
    assert!(second.queries() > failed);
}

/// 过期续用（serve_stale_ttl_reset）换下的是那一份应答本身：同一份应答（取得时刻不变）重新
/// 存一次，过期计时从头开始。
/// Renewing a stale answer (serve_stale_ttl_reset) replaces that answer itself:
/// the same answer (fetched at the same moment) is stored again, its stale clock
/// starting over.
#[tokio::test]
async fn renewing_a_stale_answer_stores_the_same_answer_again() {
    let up = upstream_with(Echo::Scope(24), ResponseCode::NoError, 1, Duration::ZERO).await;
    let engine = engine_with(
        serde_json::json!({ "serve_stale": true, "serve_stale_ttl_reset": true }),
        forward_all(&up.address, None),
    );
    ask(&engine, "10.0.0.1", Some(("198.51.100.0", 24))).await;
    let slot = Engine::cache_keys(
        engine.state.load().cache_namespace("main"),
        "main",
        b"example.com",
        RecordType::A,
        hickory_proto::rr::DNSClass::IN,
        &crate::matcher::RequesterKey::NONE,
        None,
    )
    .slot;
    let before = engine.cached(slot).expect("cached");
    tokio::time::sleep(Duration::from_millis(1100)).await;
    up.silent.store(true, Ordering::SeqCst);
    assert_eq!(
        ask(&engine, "10.0.0.2", Some(("198.51.100.0", 24))).await,
        v4("198.51.100.0")
    );
    let after = engine.cached(slot).expect("still cached");
    assert!(!Arc::ptr_eq(&before, &after), "renewed");
    assert_eq!(after.fetched_at, before.fetched_at);
    assert!(after.stored_at > before.stored_at);
    // Expired just now again: aged exactly its TTL, less than before the renewal
    // 又是刚刚过期：存了正好一个 TTL，比续用之前短
    assert!(
        after.inserted_at.elapsed() < before.inserted_at.elapsed(),
        "the stale clock starts over"
    );
}

/// 上游把作用范围从 /16 收窄到 /24：刷新回来的应答只适用于这个 /24，被刷新的 /16 那份让位，
/// /16 里别的子网各自重新查询，而不是一直拿旧的那份、每次命中都再刷新一次。
/// The upstream narrows its scope from /16 to /24: the refreshed answer applies
/// to that /24 alone, the renewed /16 answer gives way, and the other subnets of
/// the /16 ask again rather than keep the old one and refresh it on every hit.
#[tokio::test]
async fn a_refresh_with_a_narrower_scope_retires_the_wider_answer() {
    let answered = Arc::new(AtomicUsize::new(0));
    let counted = answered.clone();
    let up = upstream_answering(
        move |_| {
            let scope = if counted.fetch_add(1, Ordering::SeqCst) == 0 {
                16
            } else {
                24
            };
            (Echo::Scope(scope), 10)
        },
        ResponseCode::NoError,
        Duration::ZERO,
    )
    .await;
    let engine = engine_with(
        serde_json::json!({
            "cache_background_refresh": true,
            "cache_refresh_threshold_percent": 95,
            "cache_refresh_min_ttl": 0
        }),
        forward_all(&up.address, None),
    );
    ask(&engine, "10.0.0.1", Some(("198.51.100.0", 24))).await;
    let slot = Engine::cache_keys(
        engine.state.load().cache_namespace("main"),
        "main",
        b"example.com",
        RecordType::A,
        hickory_proto::rr::DNSClass::IN,
        &crate::matcher::RequesterKey::NONE,
        None,
    )
    .slot;
    let wider = engine.cached(slot).expect("cached");
    tokio::time::sleep(Duration::from_millis(1100)).await;
    // A hit due for a refresh / 到了刷新时机的一次命中
    ask(&engine, "10.0.0.1", Some(("198.51.100.0", 24))).await;
    // Until the refreshed answer is written and the wider one is gone
    // 等到刷新回来的应答写入、更宽的那份不在了
    tokio::time::timeout(Duration::from_secs(5), async {
        while engine
            .cached_entries(slot)
            .iter()
            .any(|entry| entry.reach == wider.reach)
            || engine.cached_entries(slot).len() != 1
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the refreshed answer replaces the wider one");
    // Another /24 of the old /16 now asks the upstream / 原来那个 /16 里的另一个 /24 现在去问上游
    ask(&engine, "10.0.0.2", Some(("198.51.7.0", 24))).await;
    assert_eq!(up.queries(), 3);
}

/// main 里规则 `check` 转发给按 /24 作答的上游，应答落在 198.51.100.0/24 时 continue，下一条
/// 规则跳到 `other`，那里的上游作用范围为 0
/// In main, rule `check` forwards to an upstream answering scope /24 and continues
/// when the answer lies in 198.51.100.0/24; the next rule jumps to `other`, whose
/// upstream answers scope 0
fn continue_then_jump(checked: &str, last: &str) -> serde_json::Value {
    serde_json::json!([
        { "id": "main", "rules": [
            {
                "name": "check", "matchers": [{ "type": "any" }],
                "actions": [forward_to(checked, None)],
                "response_matchers": [{ "type": "response_answer_ip", "cidr": "198.51.100.0/24" }],
                "response_actions_on_match": [{ "type": "continue" }]
            },
            { "name": "go", "matchers": [{ "type": "any" }],
              "actions": [{ "type": "jump_to_pipeline", "pipeline": "other" }] }
        ] },
        { "id": "other", "rules": [
            { "name": "last", "matchers": [{ "type": "any" }], "actions": [forward_to(last, None)] }
        ] }
    ])
}

/// 跳转之前让应答依赖客户端 /24 的那次转发，跳转之后仍算在回显的作用范围里：这个客户端拿到
/// `other` 的应答，只是因为 `check` 给它的 /24 那样作答。报 0 会让下游把它交给所有子网。等在
/// 同一个请求上的请求也一样。
/// A forward before a jump that made the answer depend on the client's /24 still
/// counts in the echo's scope after the jump: this client gets `other`'s answer
/// only because `check` answered its /24 the way it did. Reporting 0 would let a
/// downstream cache hand it to every subnet. The same goes for a request waiting
/// on this one.
#[tokio::test]
async fn the_echo_keeps_the_scope_through_a_request_jump() {
    let checked = upstream(Echo::Scope(24)).await;
    let last = upstream_with(
        Echo::Scope(0),
        ResponseCode::NoError,
        300,
        Duration::from_millis(150),
    )
    .await;
    let engine = engine(continue_then_jump(&checked.address, &last.address));
    let subnet = Some(("198.51.100.0", 24));
    let (one, two) = (query(subnet), query(subnet));
    let (one, two) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            engine.handle_packet(&one, peer("10.0.0.1")),
            engine.handle_packet(&two, peer("10.0.0.2"))
        )
    })
    .await
    .expect("answers in time");
    for reply in [one.unwrap(), two.unwrap()] {
        assert_eq!(reply_ecs(&reply), Some((ip("198.51.100.0"), 24, 24)));
    }
    assert_eq!(last.queries(), 1, "the second request waited on the first");
}

/// 响应跳转路径上同样：那里按 /24 作答、决定 continue 的转发，算在最终应答的回显里
/// The same on the response-jump path: a forward there answering /24 and deciding
/// a continue counts in the final answer's echo
#[tokio::test]
async fn the_echo_keeps_the_scope_through_the_response_jump_path() {
    let pre = upstream(Echo::Nothing).await;
    let checked = upstream(Echo::Scope(24)).await;
    let last = upstream(Echo::Scope(0)).await;
    let engine = engine(serde_json::json!([
        { "id": "main", "rules": [{
            "name": "r", "matchers": [{ "type": "any" }],
            "actions": [forward_to(&pre.address, None)],
            "response_matchers": [{ "type": "upstream_equals", "value": pre.address }],
            "response_actions_on_match": [{ "type": "jump_to_pipeline", "pipeline": "other" }]
        }] },
        { "id": "other", "rules": [
            {
                "name": "check", "matchers": [{ "type": "any" }],
                "actions": [forward_to(&checked.address, None)],
                "response_matchers": [{ "type": "response_answer_ip", "cidr": "198.51.100.0/24" }],
                "response_actions_on_match": [{ "type": "continue" }]
            },
            { "name": "last", "matchers": [{ "type": "any" }], "actions": [forward_to(&last.address, None)] }
        ] }
    ]));
    let reply = reply(&engine, "10.0.0.1", Some(("198.51.100.0", 24))).await;
    assert_eq!(last.queries(), 1);
    assert_eq!(reply_ecs(&reply), Some((ip("198.51.100.0"), 24, 24)));
}

/// 回答检查之后响应动作转发给作用范围为 0 的上游：等在同一个请求上的请求拿到的回显，也算上
/// 规则自己那次 /24 的转发。
/// A response action forwards to an upstream answering scope 0 after the answer
/// check: a request waiting on the same request gets an echo that counts the
/// rule's own /24 forward too.
#[tokio::test]
async fn waiters_get_the_full_echo_after_a_response_action_forward() {
    let checked = upstream(Echo::Scope(24)).await;
    let last = upstream_with(
        Echo::Scope(0),
        ResponseCode::NoError,
        300,
        Duration::from_millis(150),
    )
    .await;
    let engine = engine(serde_json::json!([{ "id": "main", "rules": [{
        "name": "check", "matchers": [{ "type": "any" }],
        "actions": [forward_to(&checked.address, None)],
        "response_matchers": [{ "type": "upstream_equals", "value": checked.address }],
        "response_actions_on_match": [{ "type": "forward", "upstream": last.address }]
    }] }]));
    let subnet = Some(("198.51.100.0", 24));
    let (one, two) = (query(subnet), query(subnet));
    let (one, two) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            engine.handle_packet(&one, peer("10.0.0.1")),
            engine.handle_packet(&two, peer("10.0.0.2"))
        )
    })
    .await
    .expect("answers in time");
    assert_eq!(last.queries(), 1);
    for reply in [one.unwrap(), two.unwrap()] {
        assert_eq!(reply_ecs(&reply), Some((ip("198.51.100.0"), 24, 24)));
    }
}

/// 应答把 OPT 放在别的附加记录前面（RFC 6891 允许），`echo` 为真时回显查询的 ECS（作用范围 0）
/// An upstream whose reply puts OPT before another additional record (RFC 6891
/// allows it), echoing the query's ECS at scope 0 when `echo` is set
async fn opt_not_last_upstream(echo: bool) -> String {
    let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let address = sock.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            let Ok(query) = Message::from_bytes(&buf[..n]) else {
                continue;
            };
            let Some(question) = query.queries.first().cloned() else {
                continue;
            };
            let mut resp = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
            resp.add_query(question.clone());
            resp.add_answer(Record::from_rdata(
                question.name().clone(),
                300,
                RData::A(A(Ipv4Addr::new(192, 0, 2, 77))),
            ));
            let mut edns = Edns::new();
            edns.set_max_payload(1232);
            if echo
                && let Some(EdnsOption::Subnet(subnet)) = query
                    .edns
                    .as_ref()
                    .and_then(|edns| edns.options().get(EdnsCode::Subnet))
            {
                edns.options_mut()
                    .insert(EdnsOption::Subnet(ClientSubnet::new(
                        subnet.addr(),
                        subnet.source_prefix(),
                        0,
                    )));
            }
            resp.edns = Some(edns);
            let mut wire = resp.to_vec().unwrap();
            // An A record after the OPT, named by a pointer to the question
            // OPT 之后一条 A 记录，名字指向问题
            wire.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 8]);
            wire[11] += 1;
            let _ = sock.send_to(&wire, peer).await;
        }
    });
    address
}

/// OPT 后面还有记录的应答，在报文层面改不动 OPT：回显改由重新编码整个报文写上，客户端照样
/// 拿到应有的作用范围；不带 ECS 的这种应答照常缓存。
/// A reply with records after its OPT cannot have the OPT changed in place: the
/// echo is written by encoding the whole message again, and the client still gets
/// the scope it should; such a reply without ECS is cached as usual.
#[tokio::test]
async fn the_echo_is_written_when_records_follow_the_opt() {
    let checked = upstream(Echo::Scope(24)).await;
    let last = opt_not_last_upstream(false).await;
    let continuing = engine(serde_json::json!([{ "id": "main", "rules": [
        {
            "name": "check", "matchers": [{ "type": "any" }],
            "actions": [forward_to(&checked.address, None)],
            "response_matchers": [{ "type": "response_answer_ip", "cidr": "198.51.100.0/24" }],
            "response_actions_on_match": [{ "type": "continue" }]
        },
        { "name": "last", "matchers": [{ "type": "any" }], "actions": [forward_to(&last, None)] }
    ] }]));
    let fresh = reply(&continuing, "10.0.0.1", Some(("198.51.100.0", 24))).await;
    assert_eq!(first_a(&fresh), v4("192.0.2.77"));
    assert_eq!(reply_ecs(&fresh), Some((ip("198.51.100.0"), 24, 24)));
    let cached = reply(&continuing, "10.0.0.2", Some(("198.51.100.0", 24))).await;
    assert_eq!(checked.queries(), 1, "cached");
    assert_eq!(reply_ecs(&cached), Some((ip("198.51.100.0"), 24, 24)));

    let plain = engine(forward_all(&last, None));
    reply(&plain, "10.0.0.1", None).await;
    assert!(matches!(
        plain.handle_packet_fast(&query(None), peer("10.0.0.1")),
        Ok(Some(crate::engine::FastPathResponse::CacheHit { .. }))
    ));
}

/// 响应跳转路径上，响应动作再转发给按 /24 作答的上游并 continue，最终应答来自作用范围为 0 的
/// 上游：那次再转发同样算在回显里。
/// On the response-jump path a response action forwards once more to an upstream
/// answering /24 and continues, and the final answer comes from an upstream
/// answering scope 0: that extra forward counts in the echo too.
#[tokio::test]
async fn the_echo_counts_a_response_action_forward_on_the_jump_path() {
    let pre = upstream(Echo::Nothing).await;
    let first = upstream(Echo::Scope(0)).await;
    let second = upstream(Echo::Scope(24)).await;
    let last = upstream(Echo::Scope(0)).await;
    let engine = engine(serde_json::json!([
        { "id": "main", "rules": [{
            "name": "r", "matchers": [{ "type": "any" }],
            "actions": [forward_to(&pre.address, None)],
            "response_matchers": [{ "type": "upstream_equals", "value": pre.address }],
            "response_actions_on_match": [{ "type": "jump_to_pipeline", "pipeline": "other" }]
        }] },
        { "id": "other", "rules": [
            {
                "name": "check", "matchers": [{ "type": "any" }],
                "actions": [forward_to(&first.address, None)],
                "response_matchers": [{ "type": "upstream_equals", "value": first.address }],
                "response_actions_on_match": [
                    { "type": "forward", "upstream": second.address },
                    { "type": "continue" }
                ]
            },
            { "name": "last", "matchers": [{ "type": "any" }], "actions": [forward_to(&last.address, None)] }
        ] }
    ]));
    let reply = reply(&engine, "10.0.0.1", Some(("198.51.100.0", 24))).await;
    assert_eq!((second.queries(), last.queries()), (1, 1));
    assert_eq!(reply_ecs(&reply), Some((ip("198.51.100.0"), 24, 24)));
}

/// 转发替没带 ECS 的客户端加了 ECS，上游的应答把 OPT 放在别的记录前面：报文层面去不掉回显，
/// 改由重新编码去掉，客户端拿到的应答不带 ECS。
/// A forward added ECS for a client that sent none, and the upstream's reply puts
/// its OPT before another record: the echo cannot be taken out in place, so the
/// message is encoded again without it, and the client gets no ECS.
#[tokio::test]
async fn a_client_without_ecs_gets_no_ecs_when_records_follow_the_opt() {
    let up = opt_not_last_upstream(true).await;
    let engine = engine(forward_all(&up, from_client_ip()));
    let fresh = reply(&engine, "198.51.100.7", None).await;
    assert_eq!(first_a(&fresh), v4("192.0.2.77"));
    assert_eq!(reply_ecs(&fresh), None);
}

/// 两个客户端经不同的 pipeline 进来，都在响应跳转之后走到同一条路径，第二个等在第一个的条目
/// 上：它拿到的回显同样算上跳转路径上那次 /24 的转发。
/// Two clients come in through different pipelines and both reach the same
/// response-jump path, the second waiting on the first's entry there: its echo
/// counts that path's /24 forward as well.
#[tokio::test]
async fn waiters_on_the_response_jump_path_get_the_full_echo() {
    let pre = upstream(Echo::Nothing).await;
    let checked = upstream_with(
        Echo::Scope(24),
        ResponseCode::NoError,
        300,
        Duration::from_millis(150),
    )
    .await;
    let last = upstream(Echo::Scope(0)).await;
    let entry = |id: &str| {
        serde_json::json!({ "id": id, "rules": [{
            "name": "r", "matchers": [{ "type": "any" }],
            "actions": [forward_to(&pre.address, None)],
            "response_matchers": [{ "type": "upstream_equals", "value": pre.address }],
            "response_actions_on_match": [{ "type": "jump_to_pipeline", "pipeline": "other" }]
        }] })
    };
    let raw = serde_json::json!({
        "settings": {
            "default_upstream": "127.0.0.1:9",
            "upstream_timeout_ms": 1000,
            "enable_tcp_fallback": false
        },
        "pipeline_select": [
            { "pipeline": "a", "matchers": [{ "type": "client_ip", "cidr": "10.0.0.1/32" }] },
            { "pipeline": "b", "matchers": [{ "type": "client_ip", "cidr": "10.0.0.2/32" }] }
        ],
        "pipelines": [
            entry("a"),
            entry("b"),
            { "id": "other", "rules": [{
                "name": "check", "matchers": [{ "type": "any" }],
                "actions": [forward_to(&checked.address, None)],
                "response_matchers": [{ "type": "upstream_equals", "value": checked.address }],
                "response_actions_on_match": [{ "type": "forward", "upstream": last.address }]
            }] }
        ]
    });
    let config: crate::config::PipelineConfig = serde_json::from_value(raw).expect("parse config");
    let engine = Engine::new(
        RuntimePipelineConfig::from_config(config).expect("build runtime config"),
        "test".to_string(),
    )
    .expect("engine");
    let subnet = Some(("198.51.100.0", 24));
    let (one, two) = (query(subnet), query(subnet));
    let (one, two) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            engine.handle_packet(&one, peer("10.0.0.1")),
            engine.handle_packet(&two, peer("10.0.0.2"))
        )
    })
    .await
    .expect("answers in time");
    assert_eq!(
        checked.queries(),
        1,
        "the second request waited on the jump path"
    );
    for reply in [one.unwrap(), two.unwrap()] {
        assert_eq!(reply_ecs(&reply), Some((ip("198.51.100.0"), 24, 24)));
    }
}

/// RFC 7871 第 7.1 节：客户端自己带了 ECS 时，由它决定给上游多少地址。`from_client_ip` 转发它
/// 自己的子网：前缀不超过这里的设置时原样转发，更长时截短到设置的前缀，前缀为 0 的不加地址；
/// 公网和私有地址的客户端都一样。缓存按实际发出的子网保存应答。
/// RFC 7871 section 7.1: a client that sent ECS itself decides how much of its
/// address goes upstream. `from_client_ip` forwards the client's own subnet: as it
/// is when its prefix is no longer than the one set here, cut to that prefix when
/// it is longer, and a prefix of 0 adds no address; public and private clients
/// alike. The cache keeps each answer for the subnet that actually went out.
#[tokio::test]
async fn from_client_ip_sends_no_more_of_a_client_subnet_than_the_client_did() {
    // 作用范围比任何发出的前缀都长：每份应答只给它那个子网
    // A scope longer than any prefix sent: every answer is for its own subnet only
    let up = upstream(Echo::Scope(32)).await;
    let engine = engine(forward_all(&up.address, from_client_ip()));
    assert_eq!(
        ask(&engine, "198.51.100.7", Some(("0.0.0.0", 0))).await,
        v4("0.0.0.0")
    );
    assert_eq!(
        ask(&engine, "198.51.100.7", Some(("203.0.0.0", 16))).await,
        v4("203.0.0.0")
    );
    let long = reply(&engine, "198.51.100.7", Some(("203.0.113.9", 32))).await;
    assert_eq!(first_a(&long), v4("203.0.113.0"));
    assert_eq!(reply_ecs(&long), Some((ip("203.0.113.9"), 32, 32)));
    assert_eq!(
        ask(&engine, "192.168.1.10", Some(("198.18.0.1", 32))).await,
        v4("198.18.0.0")
    );
    assert_eq!(
        *up.seen.lock(),
        vec![
            Some((ip("0.0.0.0"), 0)),
            Some((ip("203.0.0.0"), 16)),
            Some((ip("203.0.113.0"), 24)),
            Some((ip("198.18.0.0"), 24)),
        ]
    );
    // 别的客户端发出同样的子网时，拿缓存里的这几份 / Another client sending the same subnet takes these from the cache
    assert_eq!(
        ask(&engine, "203.0.113.50", Some(("203.0.113.77", 32))).await,
        v4("203.0.113.0")
    );
    assert_eq!(
        ask(&engine, "203.0.113.50", Some(("0.0.0.0", 0))).await,
        v4("0.0.0.0")
    );
    assert_eq!(up.queries(), 4);
}

/// RFC 7871 第 11.3 节：客户端自己带的私有网段不发给上游。公网客户端照样发来源地址的子网，
/// 私有地址的客户端什么也不发；缓存按实际发出的保存应答。
/// RFC 7871 section 11.3: a private network in the client's own ECS does not go
/// upstream. A public client sends its address's subnet as usual, a private client
/// sends nothing, and the cache keeps each answer for what actually went out.
#[tokio::test]
async fn from_client_ip_does_not_pass_on_a_private_client_network() {
    let up = upstream(Echo::Scope(16)).await;
    let engine = engine(forward_all(&up.address, from_client_ip()));
    let public = reply(&engine, "198.51.100.7", Some(("10.1.2.0", 28))).await;
    assert_eq!(first_a(&public), v4("198.51.100.0"));
    // 回显的作用范围说的是来源地址的子网，与客户端的网段无关，所以报客户端自己的前缀
    // The echoed scope speaks of the source address's subnet, not the client's
    // network, so the client's own prefix is reported
    assert_eq!(reply_ecs(&public), Some((ip("10.1.2.0"), 28, 28)));
    assert_eq!(
        ask(&engine, "192.168.1.10", Some(("10.1.2.0", 28))).await,
        Some(NO_SUBNET)
    );
    assert_eq!(*up.seen.lock(), vec![Some((ip("198.51.100.0"), 24)), None]);
    // 同样的请求再来一次，都从缓存拿 / The same requests again come from the cache
    ask(&engine, "198.51.100.7", Some(("10.1.2.0", 28))).await;
    ask(&engine, "192.168.1.10", Some(("10.1.2.0", 28))).await;
    assert_eq!(up.queries(), 2);
}

/// 转发把客户端的 /32 截短成 /24：第一次的应答和之后命中缓存的应答，回显的都是客户端自己的
/// 子网和上游给的作用范围。
/// The forward cuts the client's /32 to /24: the first reply and the cache hits
/// after it echo the client's own subnet with the scope the upstream gave.
#[tokio::test]
async fn the_echo_after_a_cut_reports_the_upstream_scope() {
    let up = upstream(Echo::Scope(24)).await;
    let engine = engine(forward_all(&up.address, from_client_ip()));
    let first = reply(&engine, "198.51.100.7", Some(("203.0.113.9", 32))).await;
    assert_eq!(reply_ecs(&first), Some((ip("203.0.113.9"), 32, 24)));
    let hit = reply(&engine, "198.51.100.8", Some(("203.0.113.77", 32))).await;
    assert_eq!(first_a(&hit), v4("203.0.113.0"));
    assert_eq!(reply_ecs(&hit), Some((ip("203.0.113.77"), 32, 24)));
    assert_eq!(up.queries(), 1);
}

/// 两个公网客户端同时到达、带着同一个子网：`from_client_ip` 为二者发出的都是这个子网，后到的
/// 等在先到的请求上，上游只问一次。
/// Two public clients arrive at once carrying the same subnet: `from_client_ip`
/// sends that subnet for both, so the later one waits on the earlier and the
/// upstream is asked once.
#[tokio::test]
async fn clients_sending_the_same_subnet_through_from_client_ip_wait_together() {
    let up = upstream_with(
        Echo::Scope(16),
        ResponseCode::NoError,
        300,
        Duration::from_millis(150),
    )
    .await;
    let engine = engine(forward_all(&up.address, from_client_ip()));
    assert_eq!(
        ask_at_once(
            &engine,
            ("198.51.100.7", Some(("203.0.0.0", 16))),
            ("192.0.2.200", Some(("203.0.0.0", 16)))
        )
        .await,
        [v4("203.0.0.0"), v4("203.0.0.0")]
    );
    assert_eq!(up.queries(), 1);
}

/// 双栈套接字上的 IPv4 客户端（::ffff:a.b.c.d）：`from_client_ip` 按它的 IPv4 地址取子网，
/// 私有地址照样不加。
/// An IPv4 client on a dual-stack socket (::ffff:a.b.c.d): `from_client_ip` takes
/// the subnet of its IPv4 address, and adds none for a private one as usual.
#[tokio::test]
async fn from_client_ip_takes_the_ipv4_subnet_of_a_mapped_client() {
    let up = upstream(Echo::Scope(24)).await;
    let engine = engine(forward_all(&up.address, from_client_ip()));
    let public: SocketAddr = "[::ffff:198.51.100.7]:53000".parse().unwrap();
    let private: SocketAddr = "[::ffff:192.168.1.5]:53000".parse().unwrap();
    assert_eq!(
        first_a(&reply_from(&engine, public, None).await),
        v4("198.51.100.0")
    );
    assert_eq!(
        first_a(&reply_from(&engine, private, None).await),
        Some(NO_SUBNET)
    );
    assert_eq!(*up.seen.lock(), vec![Some((ip("198.51.100.0"), 24)), None]);
}

/// 客户端带的 ECS 读不懂（这里是查询里 SCOPE 不为 0，RFC 7871 第 6 节不允许）：它允许给上游
/// 多少地址无从得知，`from_client_ip` 既不转发这个选项，也不替它加上来源地址的子网
/// （第 7.1 节）。公网和私有地址的客户端都一样，发给上游的是同一个不带 ECS 的查询，共用应答。
/// A client ECS nobody can read (here a nonzero SCOPE in a query, which RFC 7871
/// section 6 does not allow): how much of its address it lets go upstream is
/// unknown, so `from_client_ip` neither passes the option on nor adds the source
/// address's subnet in its place (section 7.1). Public and private clients alike
/// send the same query without ECS upstream, and share its answer.
#[tokio::test]
async fn from_client_ip_sends_no_address_for_an_unreadable_client_ecs() {
    let up = upstream(Echo::Scope(24)).await;
    let engine = engine(forward_all(&up.address, from_client_ip()));
    let unreadable = query_with_ecs_option(&[0, 1, 0, 5]);
    for client in ["198.51.100.7", "192.168.1.10"] {
        let reply = tokio::time::timeout(
            Duration::from_secs(5),
            engine.handle_packet(&unreadable, peer(client)),
        )
        .await
        .expect("answer in time")
        .expect("answer");
        assert_eq!(first_a(&reply), Some(NO_SUBNET), "{client}");
    }
    assert_eq!(*up.seen.lock(), vec![None]);
    assert_eq!(up.queries(), 1);
}

/// 查询 example.com A，带一个 ECS 选项，选项内容（FAMILY、SOURCE、SCOPE、ADDRESS）照原样写进去
/// A query for example.com A carrying one ECS option whose data (FAMILY, SOURCE,
/// SCOPE, ADDRESS) is written as given
fn query_with_ecs_option(data: &[u8]) -> Vec<u8> {
    let mut request = Message::new(0xBEEF, MessageType::Query, OpCode::Query);
    request.metadata.recursion_desired = true;
    request.add_query(Query::query(
        Name::from_str("example.com").unwrap(),
        RecordType::A,
    ));
    let mut packet = request.to_vec().unwrap();
    // ARCOUNT 1, then the OPT record: root name, type 41, payload 1232, TTL 0
    // ARCOUNT 为 1，接着是 OPT 记录：根名、类型 41、载荷 1232、TTL 0
    packet[11] = 1;
    packet.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0]);
    let rdlen = 4 + data.len();
    packet.extend_from_slice(&(rdlen as u16).to_be_bytes());
    packet.extend_from_slice(&8u16.to_be_bytes());
    packet.extend_from_slice(&(data.len() as u16).to_be_bytes());
    packet.extend_from_slice(data);
    packet
}

/// 读不懂的 ECS 选项也要去掉，包括 hickory 解不开的（地址族未知、前缀超长）
/// An ECS option nobody can read goes too, including ones hickory cannot decode
/// (an unknown family, a prefix too long)
#[tokio::test]
async fn from_client_ip_removes_ecs_options_hickory_cannot_decode() {
    let up = upstream(Echo::Scope(24)).await;
    let engine = engine(forward_all(&up.address, from_client_ip()));
    for (case, data) in [
        ("unknown family", vec![0, 3, 24, 0, 1, 2, 3]),
        (
            "an IPv4 prefix over 32",
            vec![0, 1, 33, 0, 198, 51, 100, 7, 1],
        ),
        ("a nonzero SCOPE", vec![0, 1, 24, 5, 198, 51, 100]),
    ] {
        let reply = tokio::time::timeout(
            Duration::from_secs(5),
            engine.handle_packet(&query_with_ecs_option(&data), peer("198.51.100.7")),
        )
        .await
        .expect("answer in time")
        .expect("answer");
        assert_eq!(first_a(&reply), Some(NO_SUBNET), "{case}");
    }
    // 三次请求发给上游的都不带 ECS，所以第一次之后都从缓存拿
    // All three send the upstream a query without ECS, so after the first they come from the cache
    assert_eq!(*up.seen.lock(), vec![None]);
}

/// 后台刷新照样不加地址：刷新重放的包放不进读不懂的选项，按缓存记下的请求方判断，和原请求一样
/// 发出不带 ECS 的查询，换下的也是原来那份应答。
/// A background refresh adds no address either: the replayed packet cannot carry
/// the unreadable option, so the refresh judges by the requester the cache
/// recorded, sends a query without ECS as the request did, and renews that same
/// answer.
#[tokio::test]
async fn a_refresh_for_an_unreadable_client_ecs_sends_no_address() {
    let up = upstream_with(Echo::Scope(24), ResponseCode::NoError, 10, Duration::ZERO).await;
    let engine = engine_with(
        serde_json::json!({
            "cache_background_refresh": true,
            "cache_refresh_threshold_percent": 95,
            "cache_refresh_min_ttl": 0
        }),
        forward_all(&up.address, from_client_ip()),
    );
    let unreadable = query_with_ecs_option(&[0, 1, 0, 5]);
    let ask_unreadable = || async {
        tokio::time::timeout(
            Duration::from_secs(5),
            engine.handle_packet(&unreadable, peer("198.51.100.7")),
        )
        .await
        .expect("answer in time")
        .expect("answer")
    };
    ask_unreadable().await;
    // 一秒之后到了刷新时机（10 秒还剩 9 秒），这次命中发起刷新
    // A second on the entry is due for a refresh (9 of 10 seconds left); this hit starts it
    tokio::time::sleep(Duration::from_millis(1100)).await;
    ask_unreadable().await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while up.queries() < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the refresh reaches the upstream");
    tokio::time::sleep(Duration::from_millis(100)).await;
    // 刷新回来的应答换下了原来那份，下一次照样命中缓存
    // The refreshed answer replaced the one before, so the next request still hits the cache
    assert_eq!(first_a(&ask_unreadable().await), Some(NO_SUBNET));
    assert_eq!(*up.seen.lock(), vec![None, None]);
    assert_eq!(up.queries(), 2);
}

/// 查询名用一个指向后面的压缩指针，指到 OPT 里 ECS 选项的地址字节上（那里写着
/// example.com），选项后面紧跟着另一段写着 evil.com 的字节。RFC 1035 第 4.1.4 节只许指针指向
/// 前面已经出现过的名字；这种查询要被拒绝，否则去掉 ECS 选项后字节前移，指针就落到 evil.com
/// 上：规则看到的是 example.com，上游解析的却是 evil.com。
/// The query name is a compression pointer pointing forward, at the ECS option's
/// address bytes in the OPT record (which spell example.com), and another option
/// spelling evil.com follows. RFC 1035 section 4.1.4 allows pointers only to a name
/// that came before; such a query must be refused, or removing the ECS option moves
/// the bytes and the pointer lands on evil.com: the rules see example.com while the
/// upstream resolves evil.com.
#[tokio::test]
async fn a_query_name_pointing_forward_is_refused() {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream = sock.local_addr().unwrap().to_string();
    let received = Arc::new(AtomicUsize::new(0));
    let counter = received.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while sock.recv_from(&mut buf).await.is_ok() {
            counter.fetch_add(1, Ordering::SeqCst);
        }
    });
    let engine = engine(serde_json::json!([{ "id": "main", "rules": [
        {
            "name": "block", "matchers": [{ "type": "domain_suffix", "value": "evil.com" }],
            "actions": [{ "type": "static_ip_response", "ip": "0.0.0.0" }]
        },
        {
            "name": "all", "matchers": [{ "type": "any" }],
            "actions": [forward_to(&upstream, Some(serde_json::json!({ "mode": "clear" })))]
        }
    ] }]));
    let mut packet = vec![0xbe, 0xef, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1];
    // QNAME: a pointer to offset 37, then QTYPE A, QCLASS IN
    // QNAME：指向偏移 37 的指针，接着 QTYPE A、QCLASS IN
    packet.extend_from_slice(&[0xc0, 37, 0, 1, 0, 1]);
    let example = b"\x07example\x03com\x00";
    let evil = b"\x04evil\x03com\x00";
    let ecs_len = 4 + example.len();
    let other_len = 4 + evil.len();
    let rdlen = 4 + ecs_len + 4 + other_len;
    // OPT: root name, type 41, payload 1232, TTL 0, RDLENGTH
    packet.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0]);
    packet.extend_from_slice(&(rdlen as u16).to_be_bytes());
    // ECS option: family 3 (unknown), source 24, scope 0, then the address bytes at offset 37
    // ECS 选项：地址族 3（未知）、前缀 24、SCOPE 0，地址字节从偏移 37 开始
    packet.extend_from_slice(&8u16.to_be_bytes());
    packet.extend_from_slice(&(ecs_len as u16).to_be_bytes());
    packet.extend_from_slice(&[0, 3, 24, 0]);
    assert_eq!(packet.len(), 37);
    packet.extend_from_slice(example);
    // Another option: 4 bytes of padding, then evil.com, which lands at offset 37 once
    // the ECS option is gone / 另一个选项：4 字节填充，接着是 evil.com，去掉 ECS 选项后它正好在偏移 37
    packet.extend_from_slice(&65001u16.to_be_bytes());
    packet.extend_from_slice(&(other_len as u16).to_be_bytes());
    packet.extend_from_slice(&[0, 0, 0, 0]);
    packet.extend_from_slice(evil);

    let outcome = tokio::time::timeout(
        Duration::from_secs(5),
        engine.handle_packet(&packet, peer("198.51.100.7")),
    )
    .await
    .expect("answer in time");
    assert!(outcome.is_err(), "{outcome:?}");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(received.load(Ordering::SeqCst), 0);
    assert!(crate::proto_utils::parse_quick(&packet, &mut [0u8; 256]).is_none());
    // Taking the ECS option out at the wire level must not move the name either: the
    // packet is left as it is / 在报文层去掉 ECS 选项也不能挪动名字：包保持原样
    assert_eq!(
        crate::ecs::apply_ecs(&packet, &crate::config::EcsMode::Clear, ip("198.51.100.7")),
        packet
    );
}
