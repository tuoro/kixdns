//! 引擎测试共用的部分：本机假上游、按配置建引擎，以及像监听器那样问。
//! What the engine tests share: a local fake upstream, an engine built from a config,
//! and asking as a listener does.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::Bytes;
use hickory_proto::op::{Message, MessageType, OpCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, Record};
use hickory_proto::serialize::binary::BinDecodable;
use parking_lot::Mutex;
use serde_json::{Value, json};

use crate::engine::{Engine, FastPathResponse};
use crate::matcher::RuntimePipelineConfig;

/// 假上游对一个查询发出的应答：每个在多久之后发、发什么
/// What the fake upstream sends for one query: each reply, and how long after it
pub(super) type Replies = Vec<(Duration, Vec<u8>)>;

/// 假上游 / A fake upstream
pub(crate) struct Upstream {
    pub(crate) address: String,
    /// 收到的每个查询 / Every query it received
    received: Arc<Mutex<Vec<Vec<u8>>>>,
    /// 置位后照样收、照样记，只是不再应答 / Once set, it still receives and records but no
    /// longer answers
    silent: Arc<AtomicBool>,
}

impl Upstream {
    /// 收到的查询个数 / How many queries it received
    pub(super) fn queries(&self) -> usize {
        self.received.lock().len()
    }

    /// 收到的每个查询 / Every query it received
    pub(super) fn received(&self) -> Vec<Message> {
        self.received
            .lock()
            .iter()
            .map(|query| Message::from_bytes(query).expect("parse query"))
            .collect()
    }

    /// 停止或恢复应答 / Stop or resume answering
    pub(super) fn silence(&self, silent: bool) {
        self.silent.store(silent, Ordering::SeqCst);
    }
}

/// 按 `replies` 对每个查询作答的本机 UDP 上游 / A local UDP upstream answering each query as `replies` says
pub(crate) async fn upstream(replies: impl Fn(&Message) -> Replies + Send + 'static) -> Upstream {
    let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let address = sock.local_addr().unwrap().to_string();
    let received = Arc::new(Mutex::new(Vec::new()));
    let silent = Arc::new(AtomicBool::new(false));
    let (recorded, muted) = (received.clone(), silent.clone());
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            let Ok(query) = Message::from_bytes(&buf[..n]) else {
                continue;
            };
            recorded.lock().push(buf[..n].to_vec());
            if muted.load(Ordering::SeqCst) {
                continue;
            }
            for (delay, reply) in replies(&query) {
                let sock = sock.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let _ = sock.send_to(&reply, peer).await;
                });
            }
        }
    });
    Upstream {
        address,
        received,
        silent,
    }
}

/// 每个查询回一条 TTL 为 `ttl` 的 A 记录 `address` 的本机 UDP 上游
/// A local UDP upstream answering every query with one A record `address` of TTL `ttl`
pub(crate) async fn answering_upstream(address: Ipv4Addr, ttl: u32) -> Upstream {
    answering_upstream_after(address, ttl, Duration::ZERO).await
}

/// 同 [`answering_upstream`]，但每个应答晚 `delay` 才发出
/// The same as [`answering_upstream`], with every answer sent `delay` late
pub(crate) async fn answering_upstream_after(
    address: Ipv4Addr,
    ttl: u32,
    delay: Duration,
) -> Upstream {
    upstream(move |query| {
        let Some(question) = query.queries.first() else {
            return Vec::new();
        };
        let mut reply = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
        reply.metadata.recursion_desired = query.metadata.recursion_desired;
        reply.add_query(question.clone());
        reply.add_answer(Record::from_rdata(
            question.name().clone(),
            ttl,
            RData::A(A(address)),
        ));
        vec![(delay, reply.to_vec().unwrap())]
    })
    .await
}

/// UDP 和 TCP 占同一个端口的本机上游：收下查询、接下连接，从不回答
/// A local upstream on one port for UDP and TCP: it takes queries and connections and
/// never answers
pub(crate) async fn silent_upstream() -> SocketAddr {
    // 先拿 UDP 端口，再在同号上绑 TCP（顺序的道理见 upstream.rs 测试里的
    // `bind_udp_and_tcp_on_one_port`）；同号的 TCP 端口正被占着时换一对，最多试 20 次
    // The UDP port first, then TCP on the same number (see `bind_udp_and_tcp_on_one_port`
    // in the upstream.rs tests for the order); another pair when that TCP port is
    // taken, at most 20 tries
    let mut tries = 0;
    let (tcp, udp) = loop {
        tries += 1;
        assert!(
            tries <= 20,
            "port conflict: no port free for both UDP and TCP in 20 tries"
        );
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        match tokio::net::TcpListener::bind(udp.local_addr().unwrap()).await {
            Ok(tcp) => break (tcp, udp),
            Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => continue,
            Err(err) => panic!("bind tcp on the udp port: {err}"),
        }
    };
    let address = tcp.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        let mut buf = [0u8; 1500];
        loop {
            tokio::select! {
                Ok((stream, _)) = tcp.accept() => held.push(stream),
                Ok(_) = udp.recv_from(&mut buf) => {}
                else => break,
            }
        }
    });
    address
}

/// 照 `config` 建的引擎 / An engine built from `config`
pub(crate) fn engine_from(config: Value) -> Engine {
    let config: crate::config::PipelineConfig =
        serde_json::from_value(config).expect("parse config");
    Engine::new(
        RuntimePipelineConfig::from_config(config).expect("build runtime config"),
        "test".to_string(),
    )
    .expect("engine")
}

/// 数上游查询的测试用的设置，`extra` 覆盖在上面 / Settings for tests that count upstream
/// queries, with `extra` on top
pub(super) fn counting_settings(extra: Value) -> Value {
    let mut all = json!({
        "default_upstream": "127.0.0.1:9",
        // A UDP query is sent again after a third of this (`upstream::hedge_timeout`). The
        // tests count upstream queries, and on a busy machine 1 s let an answer arrive
        // after that point now and then; tests that wait on a silent upstream set less.
        // UDP 查询过了这个时间的三分之一会再发一次（`upstream::hedge_timeout`）。这些测试数上游
        // 收到的查询，机器忙时 1 秒偶尔会让应答晚过这个点；要等上游不应答的测试自己设得更短。
        "upstream_timeout_ms": 3000,
        "enable_tcp_fallback": false
    });
    all.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    all
}

/// 静态规则给的地址 / The address the static rule answers
pub(super) const STATIC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 80);

/// 名字以 `matched.test` 结尾的请求得到静态的 [`STATIC`]，以 `text.test` 结尾的得到静态 TXT（它不能
/// 预先算好，第一次走完整路径，之后从规则缓存作答），其余转发给 `upstream`
/// A name ending in `matched.test` gets the static [`STATIC`], one ending in `text.test` a
/// static TXT (which cannot be computed ahead, so the full path answers it first and the
/// rule cache afterwards), and the rest go to `upstream`
pub(super) fn static_or_forward(upstream: &str) -> Engine {
    engine_from(json!({
        "settings": counting_settings(json!({})),
        "pipelines": [{ "id": "main", "rules": [
            {
                "name": "static",
                "matchers": [{ "type": "domain_suffix", "value": "matched.test" }],
                "actions": [{ "type": "static_ip_response", "ip": STATIC.to_string() }]
            },
            {
                "name": "text",
                "matchers": [{ "type": "domain_suffix", "value": "text.test" }],
                "actions": [{ "type": "static_txt_response", "text": ["hello"] }]
            },
            {
                "name": "all",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": upstream }]
            }
        ]}]
    }))
}

pub(super) fn peer() -> SocketAddr {
    "127.0.0.1:53000".parse().unwrap()
}

/// 应答里的第一个 A 记录 / The first A record in a reply
pub(super) fn first_a(reply: &[u8]) -> Option<Ipv4Addr> {
    match Message::from_bytes(reply)
        .expect("parse reply")
        .answers
        .first()
        .map(|record| &record.data)
    {
        Some(RData::A(address)) => Some(address.0),
        _ => None,
    }
}

/// 走完整路径 / Through the full path
pub(super) async fn ask(engine: &Engine, packet: &[u8], peer: SocketAddr) -> Bytes {
    tokio::time::timeout(Duration::from_secs(5), engine.handle_packet(packet, peer))
        .await
        .expect("answer in time")
        .expect("answer")
}

/// 像监听器那样先走快速路径，要等上游的再带着预解析的数据走异步路径；快速路径读不了这个查询时
/// 为 None
/// The fast path first as a listener does, then the async path with the pre-parsed data
/// when an upstream has to answer; None when the fast path cannot read the query
pub(super) async fn ask_fast_path_first(
    engine: &Engine,
    packet: &[u8],
    peer: SocketAddr,
) -> Option<Bytes> {
    Some(
        match engine
            .handle_packet_fast(packet, peer)
            .expect("fast path")?
        {
            FastPathResponse::Direct(reply) => reply,
            FastPathResponse::CacheHit { cached, .. } => cached,
            FastPathResponse::AsyncNeeded(pre_parsed) => tokio::time::timeout(
                Duration::from_secs(5),
                engine.handle_packet_internal_with_pre_parsed(packet, peer, false, pre_parsed),
            )
            .await
            .expect("answer in time")
            .expect("answer"),
        },
    )
}

/// 像监听器那样问：快速路径读不了的查询，和监听器一样交给完整路径
/// Ask as a listener does: a query the fast path cannot read goes to the full path,
/// as a listener sends it
pub(super) async fn ask_like_a_listener(engine: &Engine, packet: &[u8], peer: SocketAddr) -> Bytes {
    match ask_fast_path_first(engine, packet, peer).await {
        Some(reply) => reply,
        None => ask(engine, packet, peer).await,
    }
}
