//! UDP 转发过了上游时限的三分之一还没等到回答，就把查询再发一次。再发以后，第一次的回答这时才到也照样收下：两次里
//! 谁的回答先到用谁的。以前再发的那一刻就不再等第一次的回答：回答比时限的三分之一慢的上游，每个查询都要多等一个重发的
//! 间隔才拿到重发那一次的回答，上游还白白多答一次。
//! A UDP forward with no answer after a third of the upstream's timeout sends the query again.
//! After that the first query's reply is still taken should it arrive only then: of the two,
//! whichever is answered first is used. It used to stop waiting for the first the moment it
//! sent again: with an upstream slower than a third of the timeout every query waited a
//! resend's interval more for the reply to the resend, and the upstream answered once more for
//! nothing.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use serde_json::json;

use crate::engine::Engine;
use crate::engine::test_support::{ask, counting_settings, engine_from, first_a, peer};

const ANSWER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 44);
/// 上游的时限：过了它的三分之一（300 毫秒）重发 / The upstream's timeout: the query is sent again
/// after a third of it (300 ms)
const LIMIT: Duration = Duration::from_millis(900);

fn query(name: &str) -> Vec<u8> {
    let mut query = Message::new(0x4b42, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
    query.to_vec().unwrap()
}

/// 假上游对同一个名字先后收到的两个查询回答哪一个 / Which of the two queries a fake upstream
/// receives for one name it answers
#[derive(Clone, Copy)]
enum Answers {
    /// 第一个，而且等第二个到了才回答它：回答一定晚于重发，不靠猜一段时间
    /// The first, and only once the second has arrived: the reply is sure to come after the
    /// resend, with no stretch of time guessed
    TheFirstOnceResent,
    /// 只回答第二个 / The second alone
    TheResend,
    /// 都不回答 / Neither
    Neither,
}

/// 对 `query` 的回答：一条 A 记录 [`ANSWER`] / The answer to `query`: one A record [`ANSWER`]
fn answer_to(query: &[u8]) -> Vec<u8> {
    let query = Message::from_bytes(query).expect("parse query");
    let question = query.queries.first().expect("a question").clone();
    let mut reply = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
    reply.metadata.recursion_desired = query.metadata.recursion_desired;
    reply.add_answer(Record::from_rdata(
        question.name().clone(),
        300,
        RData::A(A(ANSWER)),
    ));
    reply.add_query(question);
    reply.to_vec().unwrap()
}

/// 按 `answers` 作答的本机 UDP 上游，以及它收到了几个查询。每个查询的回答发回这个查询自己来的地方：内核每次发查询
/// 用的 socket 和 ID 都是另挑的
/// A local UDP upstream answering as `answers` says, and how many queries it received. The
/// reply to a query goes back to where that query came from: the kernel picks another socket
/// and another ID each time it sends one
async fn upstream(answers: Answers) -> (String, Arc<AtomicUsize>) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap().to_string();
    let received = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&received);
    tokio::spawn(async move {
        let mut first_of: HashMap<String, (SocketAddr, Vec<u8>)> = HashMap::new();
        let mut buf = [0u8; 1500];
        while let Ok((len, from)) = socket.recv_from(&mut buf).await {
            counted.fetch_add(1, Ordering::SeqCst);
            let Ok(query) = Message::from_bytes(&buf[..len]) else {
                continue;
            };
            let name = query.queries[0].name().to_string().to_lowercase();
            let Some((first_from, first)) = first_of.get(&name) else {
                first_of.insert(name, (from, buf[..len].to_vec()));
                continue;
            };
            let _ = match answers {
                Answers::TheFirstOnceResent => socket.send_to(&answer_to(first), first_from).await,
                Answers::TheResend => socket.send_to(&answer_to(&buf[..len]), from).await,
                Answers::Neither => continue,
            };
        }
    });
    (address, received)
}

/// 把什么查询都转发给 `upstream` 的引擎，上游时限 [`LIMIT`]，不用 TCP 重试
/// An engine forwarding every query to `upstream`, with an upstream timeout of [`LIMIT`] and
/// no retry over TCP
fn engine(upstream: &str, flow_control: bool) -> Engine {
    engine_from(json!({
        "settings": counting_settings(json!({
            "upstream_timeout_ms": LIMIT.as_millis() as u64,
            "flow_control_enabled": flow_control,
        })),
        "pipelines": [{ "id": "main", "rules": [
            { "name": "all", "matchers": [{ "type": "any" }],
              "actions": [{ "type": "forward", "upstream": upstream }] },
        ]}]
    }))
}

fn rcode(reply: &[u8]) -> ResponseCode {
    Message::from_bytes(reply).unwrap().metadata.response_code
}

/// 第一次查询的回答在重发以后才到，照样收下。以前这时已经不等它了：重发的那一次上游又没回答，客户端拿到的是 SERVFAIL
/// The reply to the first query arriving only after the resend is still taken. It was no
/// longer waited for by then: with the resend going unanswered, the client got SERVFAIL
#[tokio::test]
async fn the_first_querys_reply_is_taken_after_the_resend() {
    let (upstream, received) = upstream(Answers::TheFirstOnceResent).await;
    let engine = engine(&upstream, false);
    let reply = ask(&engine, &query("late.test."), peer()).await;
    assert_eq!(first_a(&reply), Some(ANSWER));
    assert_eq!(received.load(Ordering::SeqCst), 2, "sent twice");
}

/// 第一次查询没有回答、重发的那一次有，用重发的回答，和以前一样；重发在时限的三分之一
/// With the first query unanswered and the resend answered, the resend's reply is used, as
/// before; the resend goes out at a third of the timeout
#[tokio::test]
async fn the_resends_reply_is_taken_when_the_first_goes_unanswered() {
    let (upstream, received) = upstream(Answers::TheResend).await;
    let engine = engine(&upstream, false);
    let started = std::time::Instant::now();
    let reply = ask(&engine, &query("resent.test."), peer()).await;
    assert_eq!(first_a(&reply), Some(ANSWER));
    assert_eq!(received.load(Ordering::SeqCst), 2);
    // 重发在时限的三分之一，不是等满一个时限 / The resend goes out at a third of the timeout,
    // not after the whole of it
    let took = started.elapsed();
    assert!(took >= LIMIT / 3 && took < LIMIT, "took {took:?}");
}

/// 两次都没有回答，算上游失败；一共只发两次，等的时间和以前一样（三分之一个时限加一个时限）
/// With neither answered the upstream has failed; two are sent in all, and the wait is what it
/// was (a third of the timeout and then the timeout)
#[tokio::test]
async fn with_neither_query_answered_the_upstream_has_failed() {
    let (upstream, received) = upstream(Answers::Neither).await;
    let engine = engine(&upstream, false);
    let started = std::time::Instant::now();
    let reply = ask(&engine, &query("dead.test."), peer()).await;
    assert_eq!(rcode(&reply), ResponseCode::ServFail);
    assert_eq!(received.load(Ordering::SeqCst), 2, "sent twice and no more");
    assert!(
        started.elapsed() >= LIMIT + LIMIT / 3,
        "took {:?}",
        started.elapsed()
    );
}

/// 回答是哪一次发出去的查询等到的，上游回答要多久就记那一次的用时：第一次查询的回答在重发以后才到，记的是从第一次发出算起
/// 的时间（至少一个重发的间隔），不是从重发算起的那几毫秒。流控靠这个时间判断查询等多久算卡住
/// How long the upstream takes is noted by the exchange whose reply came: with the first
/// query's reply arriving after the resend, what is noted counts from the first send (a
/// resend's interval at least), not the few milliseconds since the resend. Flow control tells
/// by this time how long a query waits before it counts as stuck
#[tokio::test]
async fn a_reply_to_the_first_query_is_timed_from_the_first_send() {
    let (upstream, _) = upstream(Answers::TheFirstOnceResent).await;
    let engine = engine(&upstream, true);
    let reply = ask(&engine, &query("late.test."), peer()).await;
    assert_eq!(first_a(&reply), Some(ANSWER));
    let stuck_after = engine.permit_manager.stuck_after(&upstream, LIMIT);
    assert!(stuck_after >= 2 * (LIMIT / 3), "{stuck_after:?}");
}
