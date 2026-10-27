//! 上游的应答先要真是应答（见 `proto_utils::answers_query`）；缓存前把结构走一遍（见
//! `proto_utils::well_formed_reply`）；TTL 最高位为 1 时按 0 算（见 `proto_utils::received_ttl`）；
//! RCODE 带上 OPT 里的扩展部分，扩展 RCODE 算作失败的尝试（见 `upstream::is_failure_reply`）。
//! An upstream's reply has to be a reply at all (see `proto_utils::answers_query`); its
//! structure is walked before it is cached (see `proto_utils::well_formed_reply`); a TTL
//! with the top bit set counts as 0 (see `proto_utils::received_ttl`); and the RCODE
//! includes the OPT's extended part, an extended RCODE counting as a failed attempt (see
//! `upstream::is_failure_reply`).

use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::svcb::{Alpn, SVCB, SvcParamKey, SvcParamValue};
use hickory_proto::rr::rdata::{A, CNAME, HTTPS, SOA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;

use crate::engine::Engine;
use crate::matcher::RuntimePipelineConfig;

/// 真正的应答给的地址 / The address the real answer gives
const ANSWER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

/// 假上游对一个查询发出的应答：每个在多久之后发、发什么
/// What the fake upstream sends for one query: each reply, and how long after it
type Replies = Vec<(Duration, Vec<u8>)>;

/// 假上游；`queries` 是它收到的查询个数 / A fake upstream; `queries` counts what it received
struct Upstream {
    address: String,
    queries: Arc<AtomicUsize>,
}

impl Upstream {
    fn queries(&self) -> usize {
        self.queries.load(Ordering::SeqCst)
    }
}

/// 按 `replies` 对每个查询作答的本机上游 / A local upstream answering each query as `replies` says
async fn upstream(replies: impl Fn(&Message) -> Replies + Send + 'static) -> Upstream {
    let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let address = sock.local_addr().unwrap().to_string();
    let queries = Arc::new(AtomicUsize::new(0));
    let counted = queries.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            let Ok(query) = Message::from_bytes(&buf[..n]) else {
                continue;
            };
            counted.fetch_add(1, Ordering::SeqCst);
            for (delay, reply) in replies(&query) {
                let sock = sock.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let _ = sock.send_to(&reply, peer).await;
                });
            }
        }
    });
    Upstream { address, queries }
}

/// `query` 的应答：照抄 ID、RD 和问题，RCODE 为 `rcode`，带上 `answers`
/// The reply to `query`: its ID, RD and question, RCODE `rcode`, with `answers`
fn reply_to(query: &Message, rcode: ResponseCode, answers: Vec<Record>) -> Message {
    let mut reply = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
    reply.metadata.recursion_desired = query.metadata.recursion_desired;
    reply.metadata.recursion_available = true;
    reply.metadata.response_code = rcode;
    reply.add_queries(query.queries.iter().cloned());
    reply.insert_answers(answers);
    reply
}

/// 一条 TTL 为 `ttl` 的 [`ANSWER`] 记录 / An [`ANSWER`] record with TTL `ttl`
fn a_record(query: &Message, ttl: u32) -> Record {
    Record::from_rdata(query.queries[0].name().clone(), ttl, RData::A(A(ANSWER)))
}

/// 真正的应答：一条 TTL 300 的 A 记录 / The real answer: one A record with TTL 300
fn answer(query: &Message) -> Vec<u8> {
    reply_to(query, ResponseCode::NoError, vec![a_record(query, 300)])
        .to_vec()
        .unwrap()
}

/// 把请求都转发给 `upstreams` 的引擎 / An engine forwarding everything to `upstreams`
fn engine(upstreams: &[&str]) -> Engine {
    let config: crate::config::PipelineConfig = serde_json::from_value(serde_json::json!({
        "settings": {
            "default_upstream": "127.0.0.1:9",
            // A UDP query is sent again after a third of this (`upstream::hedge_timeout`),
            // and the tests count upstream queries
            // UDP 查询过了这个时间的三分之一会再发一次（`upstream::hedge_timeout`），而这些测试
            // 数上游收到的查询
            "upstream_timeout_ms": 3000,
            "enable_tcp_fallback": false
        },
        "pipelines": [{ "id": "main", "rules": [{
            "name": "all",
            "matchers": [{ "type": "any" }],
            "actions": [{ "type": "forward", "upstream": upstreams }]
        }]}]
    }))
    .expect("parse config");
    Engine::new(
        RuntimePipelineConfig::from_config(config).expect("build runtime config"),
        "test".to_string(),
    )
    .expect("engine")
}

fn query(name: &str, qtype: RecordType) -> Vec<u8> {
    let mut request = Message::new(0x5157, MessageType::Query, OpCode::Query);
    request.metadata.recursion_desired = true;
    request.add_query(Query::query(Name::from_str(name).unwrap(), qtype));
    request.to_vec().unwrap()
}

fn peer() -> SocketAddr {
    "127.0.0.1:53000".parse().unwrap()
}

async fn ask(engine: &Engine, name: &str, qtype: RecordType) -> Bytes {
    tokio::time::timeout(
        Duration::from_secs(5),
        engine.handle_packet(&query(name, qtype), peer()),
    )
    .await
    .expect("answer in time")
    .expect("answer")
}

/// 应答的 RCODE 和第一条 A 记录（地址、TTL）/ A reply's RCODE and its first A record (address, TTL)
fn read(reply: &Bytes) -> (ResponseCode, Option<(Ipv4Addr, u32)>) {
    let reply = Message::from_bytes(reply).expect("parse reply");
    let first = reply.answers.iter().find_map(|record| match &record.data {
        RData::A(address) => Some((address.0, record.ttl)),
        _ => None,
    });
    (reply.metadata.response_code, first)
}

/// QR 没置位（查询原样弹了回来）或 opcode 不对的报文不是应答：查询接着等真正的应答
/// A message without QR (the query itself coming back) or with another opcode is no
/// reply: the query keeps waiting for the real answer
#[tokio::test]
async fn a_message_that_answers_nothing_is_not_taken_as_the_answer() {
    let up = upstream(|query| {
        let echoed = query.to_vec().unwrap();
        // Another address, so taking it would show / 换一个地址，收下它就看得出来
        let mut other = a_record(query, 300);
        other.data = RData::A(A::new(192, 0, 2, 66));
        let mut other_opcode = reply_to(query, ResponseCode::NoError, vec![other])
            .to_vec()
            .unwrap();
        // Opcode STATUS (2) / opcode 为 STATUS（2）
        other_opcode[2] = (other_opcode[2] & !0x78) | (2 << 3);
        vec![
            (Duration::ZERO, echoed),
            (Duration::ZERO, other_opcode),
            (Duration::from_millis(100), answer(query)),
        ]
    })
    .await;
    let engine = engine(&[&up.address]);
    assert_eq!(
        read(&ask(&engine, "example.com.", RecordType::A).await),
        (ResponseCode::NoError, Some((ANSWER, 300)))
    );
}

/// 快的上游回一个扩展 RCODE（BADVERS，16），慢的上游给真正的应答：用慢的那个
/// The fast upstream replies with an extended RCODE (BADVERS, 16) and the slow one
/// with the real answer: the slow one's is used
#[tokio::test]
async fn an_extended_rcode_does_not_win_the_race() {
    let fast = upstream(|query| {
        let mut badvers = reply_to(query, ResponseCode::BADVERS, Vec::new());
        badvers.set_edns(Edns::new());
        vec![(Duration::ZERO, badvers.to_vec().unwrap())]
    })
    .await;
    let slow = upstream(|query| vec![(Duration::from_millis(100), answer(query))]).await;
    let engine = engine(&[&fast.address, &slow.address]);
    assert_eq!(
        read(&ask(&engine, "example.com.", RecordType::A).await),
        (ResponseCode::NoError, Some((ANSWER, 300)))
    );
    assert_eq!(fast.queries(), 1, "the fast upstream was asked");
}

/// 记录结构 hickory 读不了的应答照样交给客户端，但不缓存：同一个问题再问一次又问上游
/// A reply whose records hickory cannot read still goes to the client but is not
/// cached: asking the same again asks the upstream again
#[tokio::test]
async fn a_reply_hickory_cannot_read_is_passed_on_but_not_cached() {
    let up = upstream(|query| {
        let target = Name::from_str("target.example.").unwrap();
        let mut reply = reply_to(
            query,
            ResponseCode::NoError,
            vec![Record::from_rdata(
                query.queries[0].name().clone(),
                300,
                RData::CNAME(CNAME(target)),
            )],
        )
        .to_vec()
        .unwrap();
        // Two bytes more in the CNAME's RDATA than its name: the framing holds, the
        // record does not / CNAME 的 RDATA 比名字多两个字节：记录框架没问题，记录本身不对
        let rd_len_at = reply.len() - 2 - "target.example.".len() - 1;
        let rd_len = u16::from_be_bytes([reply[rd_len_at], reply[rd_len_at + 1]]) + 2;
        reply[rd_len_at..rd_len_at + 2].copy_from_slice(&rd_len.to_be_bytes());
        reply.extend_from_slice(&[0xAB, 0xCD]);
        assert!(Message::from_vec(&reply).is_err(), "hickory refuses it");
        vec![(Duration::ZERO, reply)]
    })
    .await;
    let engine = engine(&[&up.address]);
    for round in 1..=2 {
        let reply = ask(&engine, "example.com.", RecordType::A).await;
        assert_eq!(&reply[reply.len() - 2..], [0xAB, 0xCD], "round {round}");
        assert_eq!(up.queries(), round, "round {round}");
    }
}

/// 这里不逐字节检查的类型（HTTPS）由 hickory 读，读得了就照常缓存
/// A type not checked byte by byte here (HTTPS) is read by hickory and cached as usual
/// when it can be read
#[tokio::test]
async fn a_reply_only_hickory_reads_is_still_cached() {
    let up = upstream(|query| {
        let https = SVCB::new(
            1,
            Name::root(),
            vec![(
                SvcParamKey::Alpn,
                SvcParamValue::Alpn(Alpn(vec!["h2".to_string()])),
            )],
        );
        let record = Record::from_rdata(
            query.queries[0].name().clone(),
            300,
            RData::HTTPS(HTTPS(https)),
        );
        vec![(
            Duration::ZERO,
            reply_to(query, ResponseCode::NoError, vec![record])
                .to_vec()
                .unwrap(),
        )]
    })
    .await;
    let engine = engine(&[&up.address]);
    for _ in 0..2 {
        let reply = Message::from_bytes(&ask(&engine, "example.com.", RecordType::HTTPS).await)
            .expect("parse reply");
        assert_eq!(reply.answers[0].record_type(), RecordType::HTTPS);
    }
    assert_eq!(up.queries(), 1, "answered from the cache");
}

/// 最高位为 1 的 TTL 按 0 算（RFC 2181 第 8 节）：客户端看到 0，应答不缓存；否定应答的 SOA 也一样
/// A TTL with the top bit set counts as 0 (RFC 2181 section 8): the client sees 0 and
/// the answer is not cached; so with a negative answer's SOA
#[tokio::test]
async fn a_ttl_with_the_top_bit_set_counts_as_zero() {
    const TOP_BIT: u32 = 0x8000_0001;
    let up = upstream(|query| {
        let reply = if query.queries[0].name().to_string().starts_with("missing") {
            let zone = Name::from_str("example.com.").unwrap();
            let mut reply = reply_to(query, ResponseCode::NXDomain, Vec::new());
            reply.add_authority(Record::from_rdata(
                zone.clone(),
                TOP_BIT,
                RData::SOA(SOA::new(zone.clone(), zone, 1, 60, 60, 60, TOP_BIT)),
            ));
            reply
        } else {
            reply_to(query, ResponseCode::NoError, vec![a_record(query, TOP_BIT)])
        };
        vec![(Duration::ZERO, reply.to_vec().unwrap())]
    })
    .await;
    let engine = engine(&[&up.address]);
    for round in 1..=2 {
        assert_eq!(
            read(&ask(&engine, "example.com.", RecordType::A).await),
            (ResponseCode::NoError, Some((ANSWER, 0))),
            "round {round}"
        );
        let negative = ask(&engine, "missing.example.com.", RecordType::A).await;
        let negative = Message::from_bytes(&negative).expect("parse reply");
        assert_eq!(negative.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(negative.authorities[0].ttl, 0, "round {round}");
        assert_eq!(up.queries(), 2 * round, "round {round}: nothing cached");
    }
}
