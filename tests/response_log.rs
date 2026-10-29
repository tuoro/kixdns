//! Client response logs must count answers, not cache insertions or refresh work.
use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use kixdns::config::parse_config;
use kixdns::engine::{Engine, FastPathResponse, PreParsedData};
use kixdns::matcher::RuntimePipelineConfig;
use serde_json::{Value, json};

#[derive(Clone, Default)]
struct Log(Arc<Mutex<Vec<u8>>>);

impl Write for Log {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Log {
    fn capture(&self) -> tracing::subscriber::DefaultGuard {
        let writer = self.clone();
        tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_env_filter("warn,kixdns::engine::phases=info")
                .json()
                .with_writer(move || writer.clone())
                .finish(),
        )
    }

    fn responses(&self) -> Vec<Value> {
        self.events("dns_response")
    }

    fn events(&self, event: &str) -> Vec<Value> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap()["fields"].clone())
            .filter(|fields| fields["event"] == event)
            .collect()
    }
}

fn query() -> Vec<u8> {
    let mut message = Message::new(42, MessageType::Query, OpCode::Query);
    message.add_query(Query::query(
        Name::from_ascii("cache.test").unwrap(),
        RecordType::A,
    ));
    message.to_vec().unwrap()
}

fn peer() -> SocketAddr {
    "127.0.0.1:53000".parse().unwrap()
}

async fn upstream_with_ttl(ttl: u32) -> (String, tokio::task::JoinHandle<()>) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap().to_string();
    let task = tokio::spawn(async move {
        let mut buf = [0; 1500];
        while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
            let request = Message::from_bytes(&buf[..n]).unwrap();
            let question = request.queries[0].clone();
            let mut response =
                Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
            response.add_query(question.clone());
            response.add_answer(Record::from_rdata(
                question.name().clone(),
                ttl,
                RData::A(A(Ipv4Addr::LOCALHOST)),
            ));
            socket
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    (addr, task)
}

async fn upstream() -> (String, tokio::task::JoinHandle<()>) {
    upstream_with_ttl(60).await
}

fn engine(upstream: &str) -> Engine {
    configured(json!({
        "settings": {"default_upstream": upstream, "cache_background_refresh": false},
        "pipelines": []
    }))
}

fn configured(config: Value) -> Engine {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    Engine::builder(
        RuntimePipelineConfig::from_config(parse_config(&config.to_string()).unwrap()).unwrap(),
    )
    .build()
    .unwrap()
}

#[tokio::test]
async fn forwarded_response_is_not_a_cache_hit() {
    let log = Log::default();
    let _capture = log.capture();
    let (addr, task) = upstream().await;
    engine(&addr).handle_packet(&query(), peer()).await.unwrap();
    task.abort();
    let responses = log.responses();
    assert_eq!(responses.len(), 1);
    assert_eq!(
        responses[0]["cache_hit"], false,
        "a cacheable upstream answer is not a cache hit"
    );
    assert!(
        responses[0].get("cache").is_none(),
        "the flipped `cache` alias is gone"
    );
}

#[tokio::test]
async fn info_logs_include_fast_and_slow_cache_hits() {
    let log = Log::default();
    let _capture = log.capture();
    let (addr, task) = upstream().await;
    let engine = engine(&addr);
    let packet = query();
    engine.handle_packet(&packet, peer()).await.unwrap();
    assert!(matches!(
        engine.handle_packet_fast(&packet, peer()).unwrap(),
        Some(FastPathResponse::CacheHit { .. })
    ));
    engine.handle_packet(&packet, peer()).await.unwrap();
    task.abort();
    let responses = log.responses();
    assert_eq!(
        responses.len(),
        3,
        "three client answers need three INFO response records: {responses:?}"
    );
    assert_eq!(
        responses
            .iter()
            .map(|r| r["cache_hit"].clone())
            .collect::<Vec<_>>(),
        vec![json!(false), json!(true), json!(true)]
    );
    assert!(responses.iter().all(|r| r["status"] == "completed"));
}

#[tokio::test]
async fn background_refresh_is_not_a_client_response() {
    let log = Log::default();
    let _capture = log.capture();
    let (addr, task) = upstream().await;
    let engine = engine(&addr);
    let pre = PreParsedData::new("cache.test".into(), 1, 1, 42, false, "default".into());
    engine
        .handle_packet_internal_with_pre_parsed(&query(), peer(), true, pre)
        .await
        .unwrap();
    task.abort();
    assert!(
        log.responses().is_empty(),
        "refresh work must not inflate client queries"
    );
    engine.handle_packet(&query(), peer()).await.unwrap();
    let responses = log.responses();
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0]["cache_hit"], true);
}

#[tokio::test]
async fn static_fast_path_and_cached_static_answer_are_distinct() {
    let log = Log::default();
    let _capture = log.capture();
    let engine = configured(json!({
        "settings": {"default_upstream": "127.0.0.1:9", "min_ttl": 60},
        "pipelines": [{"id": "main", "rules": [{
            "name": "block", "matchers": [{"type": "any"}],
            "actions": [{"type": "static_response", "rcode": "NXDOMAIN"}]
        }]}]
    }));
    let packet = query();
    assert!(matches!(
        engine.handle_packet_fast(&packet, peer()).unwrap(),
        Some(FastPathResponse::Direct(_))
    ));
    engine.handle_packet(&packet, peer()).await.unwrap();
    assert!(matches!(
        engine.handle_packet_fast(&packet, peer()).unwrap(),
        Some(FastPathResponse::CacheHit { .. })
    ));
    let responses = log.responses();
    assert_eq!(responses.len(), 3);
    assert_eq!(
        responses
            .iter()
            .map(|r| r["cache_hit"].clone())
            .collect::<Vec<_>>(),
        vec![json!(false), json!(false), json!(true)]
    );
    assert!(
        responses.iter().all(|r| r["rcode"] == "NXDomain"
            && r["pipeline"] == "main"
            && r["upstream"] == "static")
    );
}

#[tokio::test]
async fn inflight_followers_each_count_once_without_claiming_a_cache_hit() {
    let log = Log::default();
    let _capture = log.capture();
    let (addr, task) = upstream().await;
    let engine = engine(&addr);
    let packet = query();
    let second_peer = "127.0.0.2:53001".parse().unwrap();
    let (first, second) = tokio::join!(
        engine.handle_packet(&packet, peer()),
        engine.handle_packet(&packet, second_peer)
    );
    first.unwrap();
    second.unwrap();
    task.abort();
    let responses = log.responses();
    assert_eq!(responses.len(), 2);
    assert!(responses.iter().all(|r| r["cache_hit"] == false));
    assert!(responses.iter().any(|r| r["upstream"] == "inflight"));
    assert!(responses.iter().any(|r| r["client_ip"] == "127.0.0.2"));
}

#[tokio::test]
async fn stale_answer_counts_once_and_its_refresh_does_not_count() {
    let log = Log::default();
    let _capture = log.capture();
    let (addr, task) = upstream_with_ttl(1).await;
    let engine = configured(json!({
        "settings": {"default_upstream": addr, "serve_stale": true, "serve_stale_client_timeout_ms": 0, "cache_background_refresh": false},
        "pipelines": []
    }));
    let packet = query();
    engine.handle_packet(&packet, peer()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    engine.handle_packet(&packet, peer()).await.unwrap();
    // Let the automatically spawned refresh complete before checking the count.
    tokio::time::sleep(Duration::from_millis(50)).await;
    task.abort();
    let responses = log.responses();
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[1]["cache_hit"], true);
    assert_eq!(responses[1]["rcode"], "NoError");
}

#[tokio::test]
async fn cancelled_request_does_not_invent_a_response_or_rcode() {
    let log = Log::default();
    let _capture = log.capture();
    let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let engine = engine(&silent.local_addr().unwrap().to_string());
    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            engine.handle_packet(&query(), peer())
        )
        .await
        .is_err()
    );
    assert!(log.responses().is_empty());
    let finished = log.events("dns_request_finished");
    assert_eq!(finished.len(), 1);
    assert_eq!(finished[0]["status"], "cancelled");
    assert!(finished[0].get("rcode").is_none());
}

fn truncated(request: &Message) -> Vec<u8> {
    let mut response = Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
    response.add_query(request.queries[0].clone());
    response.metadata.truncation = true;
    response.to_vec().unwrap()
}

/// UDP always answers TC=1; the Nth TCP request (0-based) gets `tcp(n, request)`.
async fn truncating_upstream(
    tcp: fn(usize, &[u8]) -> Vec<u8>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // UDP first, and another pair when the TCP port of the same number is taken
    // already (by another test's connection, say), so the shared-port bind does not flake.
    let (udp, listener) = loop {
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        match tokio::net::TcpListener::bind(udp.local_addr().unwrap()).await {
            Ok(listener) => break (udp, listener),
            Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => continue,
            Err(err) => panic!("bind tcp on the udp port: {err}"),
        }
    };
    let addr = udp.local_addr().unwrap();
    let task = tokio::spawn(async move {
        tokio::spawn(async move {
            let mut buf = [0; 1500];
            while let Ok((n, peer)) = udp.recv_from(&mut buf).await {
                let request = Message::from_bytes(&buf[..n]).unwrap();
                let _ = udp.send_to(&truncated(&request), peer).await;
            }
        });
        let seen = Arc::new(AtomicUsize::new(0));
        while let Ok((mut stream, _)) = listener.accept().await {
            let seen = seen.clone();
            tokio::spawn(async move {
                let mut len = [0; 2];
                while stream.read_exact(&mut len).await.is_ok() {
                    let mut request = vec![0; u16::from_be_bytes(len) as usize];
                    stream.read_exact(&mut request).await.unwrap();
                    let body = tcp(seen.fetch_add(1, Ordering::SeqCst), &request);
                    let mut out = (body.len() as u16).to_be_bytes().to_vec();
                    out.extend_from_slice(&body);
                    let _ = stream.write_all(&out).await;
                }
            });
        }
    });
    (addr, task)
}

fn udp_forwarder(addr: SocketAddr) -> Engine {
    configured(json!({
        "settings": {"default_upstream": "127.0.0.1:9"},
        "pipelines": [{"id": "main", "rules": [{
            "name": "fwd", "matchers": [{"type": "any"}],
            "actions": [{"type": "forward", "upstream": addr.to_string(), "transport": "udp"}]
        }]}]
    }))
}

#[tokio::test]
async fn tcp_fallback_answer_is_labelled_with_the_transport_that_carried_it() {
    let log = Log::default();
    let _capture = log.capture();
    let (addr, task) = truncating_upstream(|_, request| {
        let request = Message::from_bytes(request).unwrap();
        let mut response = Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
        response.add_query(request.queries[0].clone());
        response.to_vec().unwrap()
    })
    .await;
    udp_forwarder(addr)
        .handle_packet(&query(), peer())
        .await
        .unwrap();
    task.abort();
    let responses = log.responses();
    assert_eq!(responses.len(), 1, "{responses:?}");
    assert_eq!(responses[0]["upstream"], format!("tcp:{addr}"));
}

#[tokio::test]
async fn unparsable_answer_after_a_tcp_retry_is_one_servfail_response() {
    let log = Log::default();
    let _capture = log.capture();
    // The first TCP answer is truncated again, so the engine retries over TCP.
    // The second, non-DNS body fails to parse like an unparsable answer on any
    // other path: the client gets SERVFAIL, counted as one response. The retry
    // used to relay the body as-is, without parsing it.
    let (addr, task) = truncating_upstream(|n, request| {
        if n == 0 {
            truncated(&Message::from_bytes(request).unwrap())
        } else {
            let mut body = request[..2].to_vec();
            body.extend_from_slice(&[0xff; 11]);
            body
        }
    })
    .await;
    let answer = udp_forwarder(addr)
        .handle_packet(&query(), peer())
        .await
        .unwrap();
    task.abort();
    let answer = Message::from_bytes(&answer).expect("the client receives a DNS answer");
    assert_eq!(answer.metadata.response_code, ResponseCode::ServFail);
    assert!(log.events("dns_request_finished").is_empty());
    let responses = log.responses();
    assert_eq!(responses.len(), 1, "{responses:?}");
    assert_eq!(responses[0]["status"], "completed");
    assert_eq!(responses[0]["rcode"], "ServFail");
}

/// 响应跳转路径上到了跳转上限，回的是本地给的 SERVFAIL，日志的 upstream 记成 "static"，和请求
/// 阶段的跳转上限一样；以前要么空着，要么留着之前那次转发的上游。到上限的地方有三处：
/// - 进入下一个 pipeline 时；
/// - 规则级跳转一路跳下去时；
/// - 跳转路径上转发以后，响应动作还要跳转时。
///
/// A jump limit reached on the response jump path answers a local SERVFAIL, which the log
/// labels "static" as for the request-phase jump limit; it used to be left empty, or to
/// keep the upstream of an earlier forward. The limit is reached in three places:
/// - when entering the next pipeline;
/// - when rule-level jumps run on;
/// - when a response action wants to jump after a forward on the jump path.
#[tokio::test]
async fn a_jump_limit_on_the_response_jump_path_is_logged_as_static() {
    let (addr, task) = upstream().await;
    let jump = |to: &str| json!([{ "type": "jump_to_pipeline", "pipeline": to }]);
    let forward_then = |name: &str, then: Value| {
        json!({
            "name": name, "matchers": [{ "type": "any" }],
            "actions": [{ "type": "forward", "upstream": addr }],
            "response_matchers": [{ "type": "upstream_equals", "value": addr }],
            "response_actions_on_match": then
        })
    };
    let jump_rule = |name: &str, to: &str| json!({ "name": name, "matchers": [{ "type": "any" }], "actions": jump(to) });
    let answer_rule = json!({
        "name": "answer", "matchers": [{ "type": "any" }],
        "actions": [{ "type": "static_ip_response", "ip": "192.0.2.1" }]
    });
    let cases = [
        // 进入 second 时已经没有跳转次数 / No jumps left when entering second
        (
            1,
            json!([
                { "id": "main", "rules": [forward_then("ask", jump("second"))] },
                { "id": "second", "rules": [answer_rule] }
            ]),
        ),
        // second 里规则级跳转一路跳下去 / Rule-level jumps from second run on
        (
            2,
            json!([
                { "id": "main", "rules": [forward_then("ask", jump("second"))] },
                { "id": "second", "rules": [jump_rule("on", "third")] },
                { "id": "third", "rules": [jump_rule("on", "fourth")] },
                { "id": "fourth", "rules": [jump_rule("on", "main")] }
            ]),
        ),
        // third 里转发以后，响应动作还要跳转 / After a forward in third a response action wants to jump
        (
            2,
            json!([
                { "id": "main", "rules": [forward_then("ask", jump("second"))] },
                { "id": "second", "rules": [jump_rule("on", "third")] },
                { "id": "third", "rules": [forward_then("again", jump("main"))] }
            ]),
        ),
    ];
    for (limit, pipelines) in cases {
        let log = Log::default();
        let _capture = log.capture();
        let engine = configured(json!({
            "settings": { "default_upstream": addr, "response_jump_limit": limit },
            "pipelines": pipelines
        }));
        let reply = engine.handle_packet(&query(), peer()).await.unwrap();
        assert_eq!(
            Message::from_bytes(&reply).unwrap().metadata.response_code,
            ResponseCode::ServFail,
            "{pipelines}"
        );
        let responses = log.responses();
        assert_eq!(responses.len(), 1, "{pipelines}");
        assert_eq!(responses[0]["rcode"], "ServFail", "{pipelines}");
        assert_eq!(responses[0]["upstream"], "static", "{pipelines}");
    }
    task.abort();
}

/// 不支持的 EDNS 版本回 BADVERS（16），完整路径的日志也记 BADVERS。头部和 OPT 合起来的 RCODE 16 只会是
/// BADVERS：TSIG 的 BADSIG 写在 TSIG 记录里，头部是 NOTAUTH。hickory 把 16 读成 BADSIG，日志以前
/// 跟着记成 BADSIG
/// An unsupported EDNS version is answered BADVERS (16), and the full path logs it so. RCODE 16
/// from the header and the OPT together can only be BADVERS: TSIG's BADSIG goes in the
/// TSIG record, with NOTAUTH in the header. hickory reads 16 as BADSIG, and the log used
/// to follow it
#[tokio::test]
async fn an_unsupported_edns_version_is_logged_as_badvers() {
    let log = Log::default();
    let _capture = log.capture();
    let engine = engine("127.0.0.1:9");
    let mut message = Message::from_bytes(&query()).unwrap();
    let mut edns = hickory_proto::op::Edns::new();
    edns.set_version(1);
    message.edns = Some(edns);
    let reply = engine
        .handle_packet(&message.to_vec().unwrap(), peer())
        .await
        .unwrap();
    // 按数值比较：hickory 把 16 读成 BADSIG / Compared as a number: hickory reads 16 as BADSIG
    assert_eq!(
        u16::from(Message::from_bytes(&reply).unwrap().metadata.response_code),
        16
    );
    let responses = log.responses();
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0]["rcode"], "BADVERS");
}

/// 快速路径回 BADVERS 时也记一条响应日志，字段和完整路径的那条一样（耗时除外）；以前快速路径
/// 只上报观察者，不写这条日志
/// A BADVERS answered on the fast path gets a response record too, with the same fields as
/// the full path's (latency aside); the fast path used to tell only the observer
#[tokio::test]
async fn a_badvers_on_the_fast_path_is_logged_as_on_the_full_path() {
    let log = Log::default();
    let _capture = log.capture();
    let engine = engine("127.0.0.1:9");
    let mut message = Message::from_bytes(&query()).unwrap();
    let mut edns = hickory_proto::op::Edns::new();
    edns.set_version(1);
    message.edns = Some(edns);
    let packet = message.to_vec().unwrap();
    assert!(matches!(
        engine.handle_packet_fast(&packet, peer()).unwrap(),
        Some(FastPathResponse::Direct(_))
    ));
    engine.handle_packet(&packet, peer()).await.unwrap();
    let mut responses = log.responses();
    assert_eq!(responses.len(), 2, "one record for each path");
    for response in &mut responses {
        response.as_object_mut().unwrap().remove("latency_ms");
    }
    assert_eq!(responses[0], responses[1]);
    assert_eq!(responses[0]["rcode"], "BADVERS");
}
