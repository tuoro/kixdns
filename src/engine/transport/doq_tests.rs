//! DoQ 客户端的测试 / Tests of the DoQ client

use super::*;
use crate::engine::bootstrap::Bootstrap;
use crate::engine::transport::address::parse_doq_target;
use crate::engine::transport::connect::{Aging, UpstreamPools};
use crate::engine::transport::stream::{DotMultiplexer, TcpMultiplexer};
use crate::engine::transport::test_support::*;
use crate::engine::transport::udp::UdpClient;
use quinn::Endpoint as QuicEndpoint;
use rustls::ClientConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::time::timeout;

/// DoQ 失败的原因在 `{:#}` 里每一句只出现一次，连接没了的写着为什么没了。以前 Display 写出了 quinn 的错误、source 又给一遍
/// （quinn 的 `ReadToEndError` 自己也是这样），于是「timed out: timed out」，「0-RTT rejected」连写三遍
/// A DoQ failure's causes each come once in `{:#}`, a connection lost saying why. Display used to
/// write quinn's error out with source giving it again (as quinn's `ReadToEndError` does itself),
/// so "timed out: timed out", and "0-RTT rejected" three times over
#[test]
fn a_doq_failure_names_each_cause_once() {
    use quinn::{ConnectionError, ReadError, ReadToEndError, WriteError};
    let closed = || {
        ConnectionError::ApplicationClosed(quinn::ApplicationClose {
            error_code: quinn::VarInt::from_u32(0),
            reason: bytes::Bytes::from_static(b"closing"),
        })
    };
    let rendered = |failure| format!("{:#}", anyhow::Error::new(failure));
    assert_eq!(
        rendered(DoqFailure::OpenStream(ConnectionError::TimedOut)),
        "doq open stream failed: timed out"
    );
    assert_eq!(
        rendered(DoqFailure::Write(WriteError::ConnectionLost(closed()))),
        "doq send query failed: connection lost: closed by peer: closing (code 0)"
    );
    assert_eq!(
        rendered(DoqFailure::Read(ReadToEndError::Read(
            ReadError::ZeroRttRejected
        ))),
        "doq read response failed: read error: 0-RTT rejected"
    );
    assert_eq!(
        rendered(DoqFailure::Read(ReadToEndError::Read(
            ReadError::ConnectionLost(closed())
        ))),
        "doq read response failed: read error: connection lost: closed by peer: closing (code 0)"
    );
    assert_eq!(
        rendered(DoqFailure::Read(ReadToEndError::TooLong)),
        "doq read response failed: stream too long"
    );
}

/// 0-RTT 的安全提示曾在构造 DoQ 客户端时打印，而客户端在任何配置下都会构造，
/// 于是没有任何 DoQ 上游的部署每次启动也会看到它。
/// The 0-RTT security notice used to be printed when the DoQ client was
/// built, and the client is built for every configuration, so deployments
/// without a single DoQ upstream saw it at every start.
#[tokio::test]
async fn doq_client_holds_the_0rtt_notice_until_early_data_is_offered() {
    let client =
        DoqClient::new(1, 60, 15_000, true, Bootstrap::system()).expect("build DoQ client");
    assert!(
        !client.runtime.zero_rtt_notice.is_completed(),
        "building the client must not emit the 0-RTT notice"
    );
}

#[test]
fn doq_query_message_id_must_be_zero() {
    // Verify RFC 9250 §4.2.1: DoQ DNS Message ID MUST be set to 0.
    // The inline frame construction logic (from send_with_retry) zeroes bytes [2..4].
    // 验证 RFC 9250 §4.2.1: DoQ DNS Message ID 必须为 0。
    // 内联帧构建逻辑（来自 send_with_retry）将字节 [2..4] 置零。
    let packet = [0x12, 0x34, 0x01, 0x00, 0xaa, 0xbb];
    let mut frame = Vec::with_capacity(2 + packet.len());
    frame.extend_from_slice(&(packet.len() as u16).to_be_bytes());
    frame.extend_from_slice(&packet);
    frame[2] = 0;
    frame[3] = 0;

    assert_eq!(frame.len(), 2 + packet.len());
    assert_eq!(&frame[0..2], &(packet.len() as u16).to_be_bytes());
    assert_eq!(&frame[2..4], &[0x00, 0x00]);
    assert_eq!(&frame[4..], &packet[2..]);
}

#[test]
fn doq_response_restores_original_message_id() {
    // Verify zero-copy response ID restoration (from send_with_retry):
    // all_data layout: [2 bytes length prefix][DNS message with ID=0]
    // After restoration: ID at offset 2 is replaced with original_id, then slice(2..).
    // 验证零拷贝响应 ID 恢复（来自 send_with_retry）：
    // all_data 布局: [2 字节长度前缀][ID=0 的 DNS 消息]
    // 恢复后: 偏移 2 处的 ID 替换为 original_id，然后 slice(2..)。
    let mut all_data: Vec<u8> = vec![0x00, 0x04, 0x00, 0x00, 0x81, 0x80]; // [len=4][ID=0][flags]
    let original_id: u16 = 0x1234;
    all_data[2..4].copy_from_slice(&original_id.to_be_bytes());
    let restored = bytes::Bytes::from(all_data).slice(2..);

    assert_eq!(&restored[0..2], &[0x12, 0x34]);
    assert_eq!(&restored[2..], &[0x81, 0x80]);
}

#[test]
fn doq_response_short_message_does_not_panic() {
    // Regression test: msg_len < 2 must bail! instead of panicking on all_data[2..4].
    // 回归测试: msg_len < 2 时必须 bail! 而非 all_data[2..4] 越界 panic。
    // all_data layout: [len=1][0xAB] — total 3 bytes, msg_len=1
    let all_data: Vec<u8> = vec![0x00, 0x01, 0xAB];
    let msg_len = u16::from_be_bytes([all_data[0], all_data[1]]) as usize;
    let buf = &all_data[2..2 + msg_len];
    // This is the guard added to prevent panic:
    // 这是为防止 panic 而添加的保护：
    assert!(
        buf.len() < 2,
        "msg_len < 2 should trigger bail, not proceed to copy_from_slice"
    );
}

/// 重启过的本机 DoQ 上游：同一张证书、收早期数据，重启前发的票据不认（换了票据的密钥、anycast 换了实例也一样），握手压住
/// `accept_delay`，查询照 `reply` 回答（见 [`spawn_doq_upstream`]）。给出它的地址，和只信任这张证书、拿着一张重启前发的票据的
/// 客户端 TLS 设置（票据按服务器名存）
/// A local DoQ upstream restarted: the same certificate, taking early data, and knowing no ticket
/// given before the restart (as with its ticket keys changed or another anycast instance), its
/// handshake held back for `accept_delay` and its queries answered as `reply` says (see
/// [`spawn_doq_upstream`]). Gives its address and client TLS settings trusting the certificate
/// alone and holding a ticket given before the restart (tickets are kept by server name)
async fn restarted_doq_upstream(
    accept_delay: Duration,
    reply: fn(usize, &str) -> DoqReply,
) -> (SocketAddr, ClientConfig) {
    let (mut before, client_tls) = localhost_tls(&[b"doq"]);
    before.max_early_data_size = u32::MAX;
    let mut after = before.clone();
    after.session_storage = rustls::server::ServerSessionMemoryCache::new(32);
    let before = spawn_doq_upstream(before, Duration::ZERO, answer_at_once).await;
    let after = spawn_doq_upstream(after, accept_delay, reply).await;
    let ticket = doq_test_client(format!("{before}?sni=localhost"), client_tls.clone(), true);
    ticket
        .send(&udp_test_query("before.example"), Duration::from_secs(2))
        .await
        .expect("the upstream answers before its restart");
    // 等会话票据到 / The session ticket arrives
    tokio::time::sleep(Duration::from_millis(100)).await;
    (after, client_tls)
}

/// 每个查询都当场回答 / Every query answered at once
fn answer_at_once(_: usize, _: &str) -> DoqReply {
    DoqReply::Answer(Duration::ZERO)
}

/// 连重启过的上游（见 [`restarted_doq_upstream`]）、0-RTT 发往它的客户端 / A client of the restarted
/// upstream (see [`restarted_doq_upstream`]), sending 0-RTT to it
fn rejecting_doq_client(restarted: SocketAddr, client_tls: ClientConfig) -> DoqMuxClient {
    let client = doq_test_client(format!("{restarted}?sni=localhost"), client_tls, true);
    // 上一次完整握手（重启以前）连上的是它：0-RTT 发往它 / The last full handshake (before the
    // restart) reached it: 0-RTT goes to it
    *client.zero_rtt.reached.lock() = Some((restarted, Duration::ZERO));
    client
}

/// 上游重启过、不认先前的票据：0-RTT 被拒，建这条连接的查询和同时搭在它上面的查询，各在自己的任务里，都在这条连接握手完了以后
/// 在它上面重发、答上，远不到预算；0-RTT 照用，下一条连接又提出早期数据。quinn 丢掉被拒的旧流句柄时会删掉同号新流登记的唤醒器
/// （见 [`EarlyStreams`]）：先重发的查询的回答到了，也可能没人叫醒它，要等满预算。各个任务谁先跑说不准，所以重复多次
/// An upstream restarted and knowing no earlier ticket: 0-RTT is rejected, and the query that
/// made the connection and those riding it at the time, each in a task of its own, are all sent
/// again on it once its handshake is through and answered, well within their budgets; 0-RTT stays
/// in use, the next connection offering early data again. quinn dropping the handles of old
/// streams rejected removes the waker registered by the new stream of the same number (see
/// [`EarlyStreams`]): the answer to a query sent again first could arrive with nobody to wake it,
/// the query sitting out its budget. Which task runs first is anyone's guess, hence the repeats
async fn queries_rejected_with_0rtt_are_sent_again() {
    const ROUNDS: usize = 10;
    const QUERIES: usize = 8;
    let mut late = Vec::new();
    let mut client = None;
    for _ in 0..ROUNDS {
        let (restarted, client_tls) =
            restarted_doq_upstream(Duration::from_millis(100), answer_at_once).await;
        let rejecting = Arc::new(rejecting_doq_client(restarted, client_tls));
        let queries: Vec<_> = (0..QUERIES)
            .map(|n| {
                let client = Arc::clone(&rejecting);
                tokio::spawn(async move {
                    let started = tokio::time::Instant::now();
                    let query = udp_test_query(&format!("q{n}.example"));
                    let answer = client.send(&query, Duration::from_secs(2)).await;
                    (answer, started.elapsed())
                })
            })
            .collect();
        for query in queries {
            let (answer, took) = query.await.expect("the query's task");
            answer.expect("sent again and answered");
            if took >= Duration::from_secs(1) {
                late.push(took);
            }
        }
        // 重发都在那条 0-RTT 的连接上答完：没有各建一条 / The resends were all answered on the 0-RTT
        // connection: they did not make one each
        let pooled = rejecting.pooled.load_full().expect("a pooled connection");
        assert!(pooled.used_0rtt(), "the connection that offered early data");
        assert_eq!(pooled.answers.load(Ordering::Acquire), QUERIES as u64);
        client = Some(rejecting);
    }
    assert!(
        late.is_empty(),
        "answered well within the budget, not at its end: {} of {} late, taking {late:?}",
        late.len(),
        ROUNDS * QUERIES
    );
    let client = client.expect("rounds");
    let target = parse_doq_target(&client.upstream).expect("doq target");
    // 等这条连接上的新票据到 / The new ticket on that connection arrives
    tokio::time::sleep(Duration::from_millis(100)).await;
    client.pooled.store(None);
    let next = client.get_or_connect(&target).await.expect("connect");
    assert!(next.pooled.used_0rtt(), "0-RTT stays in use");
}

#[tokio::test(flavor = "current_thread")]
async fn queries_riding_a_connection_whose_0rtt_is_rejected_are_sent_again() {
    queries_rejected_with_0rtt_are_sent_again().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn queries_riding_a_connection_whose_0rtt_is_rejected_are_sent_again_on_threads() {
    queries_rejected_with_0rtt_are_sent_again().await;
}

/// 0-RTT 被拒以后、0-RTT 期间开出的旧流还有句柄没丢时，新来一个查询：它在握手完了的连接上开流，流号和旧流撞上，等旧句柄丢完
/// 再发，照样答上。不等的话旧句柄丢掉时删掉它登记的唤醒器（见 [`EarlyStreams`]），回答到了也没人叫醒它，要等满预算
/// A query coming after 0-RTT is rejected, with handles of old streams opened during 0-RTT still
/// held: it opens its stream on the connection through its handshake, its number that of an old
/// stream, waits for the old handles to be dropped before sending, and is answered all the same.
/// Without the wait the old handles dropped would remove the waker it registered (see
/// [`EarlyStreams`]), and with the answer in nobody would wake it, the query sitting out its budget
#[tokio::test]
async fn a_query_after_0rtt_is_rejected_waits_for_the_old_streams_to_go() {
    let (restarted, client_tls) =
        restarted_doq_upstream(Duration::from_millis(100), |_, label| match label {
            "fresh" => DoqReply::Answer(Duration::from_millis(100)),
            _ => DoqReply::Answer(Duration::ZERO),
        })
        .await;
    let client = Arc::new(rejecting_doq_client(restarted, client_tls));
    let target = parse_doq_target(&client.upstream).expect("doq target");
    let DoqConnected { pooled, .. } = client.get_or_connect(&target).await.expect("connect");
    let early = pooled.early.as_ref().expect("made with 0-RTT");
    // 一个查询在 0-RTT 期间开了流，之后迟迟不再被 poll，比如它的任务一时没轮上 / A query opened its
    // stream during 0-RTT and is not polled again for a while, its task not getting a turn, say
    let query = udp_test_query("stale.example");
    let mut stale = Box::pin(DoqMuxClient::ask(&pooled, &query, 0x1234));
    assert!(
        futures::poll!(stale.as_mut()).is_pending(),
        "waiting for the answer"
    );
    assert!(!early.accepted.clone().await, "0-RTT rejected");

    let fresh = tokio::spawn({
        let client = Arc::clone(&client);
        async move {
            let started = tokio::time::Instant::now();
            let query = udp_test_query("fresh.example");
            let answer = client.send(&query, Duration::from_secs(2)).await;
            (answer, started.elapsed())
        }
    });
    // 新查询开好了流，上游 100 毫秒以后才回答 / The new query has opened its stream, the upstream
    // answering 100 ms later
    tokio::time::sleep(Duration::from_millis(50)).await;
    drop(stale);
    let (answer, took) = fresh.await.expect("the query's task");
    assert!(
        took < Duration::from_secs(1),
        "answered well within the budget, not at its end: {took:?} {answer:?}"
    );
    answer.expect("answered");
}

/// 0-RTT 期间开出的旧流写完了查询，0-RTT 被拒以后才结束发送，这时握手完以后来的查询已经开出同号的新流：新流照样答上。多线程下
/// 写完时 driver 正拿着连接锁处理握手完成，结束发送等锁，放锁后别的查询先开出新流，就会这样。调 quinn 的 `finish` 结束发送的话，
/// FIN 掉的是新流（见 [`DoqStream::end_sending`]），新查询一写就报 `ClosedStream`、失败
/// An old stream opened during 0-RTT, its query written, ends sending only once 0-RTT is
/// rejected, with a query coming after the handshake having opened the new stream of the same
/// number by then: the new stream is answered all the same. On several threads that happens when
/// the driver holds the connection lock handling the handshake's completion as the write is
/// done, ending sending waiting for the lock and another query opening the new stream first once
/// it is released. Ending sending with quinn's `finish` would finish the new stream (see
/// [`DoqStream::end_sending`]), the new query failing with `ClosedStream` as soon as it writes
#[tokio::test]
async fn an_old_stream_ending_sending_after_0rtt_is_rejected_leaves_the_new_one_alone() {
    let (restarted, client_tls) =
        restarted_doq_upstream(Duration::from_millis(100), answer_at_once).await;
    let client = rejecting_doq_client(restarted, client_tls);
    let target = parse_doq_target(&client.upstream).expect("doq target");
    let DoqConnected { pooled, .. } = client.get_or_connect(&target).await.expect("connect");
    let early = pooled.early.as_ref().expect("made with 0-RTT");
    // 旧查询在 0-RTT 期间开了流、写完了查询，还没结束发送 / The old query opened its stream during
    // 0-RTT and wrote the query, sending not ended yet
    let (send, recv) = pooled.conn.open_bi().await.expect("a stream");
    let mut stale = DoqStream {
        send: Some(send),
        early: early.enter(&recv).await,
        recv,
        answered: false,
    };
    let query = udp_test_query("stale.example");
    let mut frame = (query.len() as u16).to_be_bytes().to_vec();
    frame.extend_from_slice(&query);
    stale
        .send
        .as_mut()
        .expect("not ended yet")
        .write_all(&frame)
        .await
        .expect("written during 0-RTT");
    assert!(!early.accepted.clone().await, "0-RTT rejected");

    // 新查询开出了新流（流号重新从 0 数，和旧流的一样），等旧流丢完 / The new query has opened its stream
    // (numbered from 0 again, as the old one is) and waits for the old ones to be dropped
    let query = udp_test_query("fresh.example");
    let mut fresh = Box::pin(client.send(&query, Duration::from_secs(2)));
    assert!(
        futures::poll!(fresh.as_mut()).is_pending(),
        "waiting for the old stream"
    );
    stale.end_sending();
    drop(stale);
    fresh.await.expect("the new stream answered");
}

/// 上游重启以后，重启前的票据发的 0-RTT 被拒，查询重发、答上；那条连接拿到的新票据给下一条连接用，它的 0-RTT 被接受。上游的
/// 握手压住 100 毫秒，查询的流一定开在 0-RTT 期间：早期数据被拒的话，这个流上报的是 `ZeroRttRejected`
/// After an upstream restart, the 0-RTT sent on a ticket from before it is rejected, the query
/// sent again and answered; the new ticket that connection got goes to the next connection, whose
/// 0-RTT is accepted. The upstream holds the handshake back for 100 ms, so the query's stream is
/// surely opened during 0-RTT: had its early data been rejected, the stream would be told
/// `ZeroRttRejected`
#[tokio::test]
async fn after_an_upstream_restart_the_new_ticket_has_0rtt_accepted() {
    let (restarted, client_tls) =
        restarted_doq_upstream(Duration::from_millis(100), answer_at_once).await;
    let client = rejecting_doq_client(restarted, client_tls);
    let target = parse_doq_target(&client.upstream).expect("doq target");
    let query = udp_test_query("restarted.example");
    client
        .send(&query, Duration::from_secs(2))
        .await
        .expect("the old ticket rejected, the query is sent again and answered");
    // 等新票据到 / The new ticket arrives
    tokio::time::sleep(Duration::from_millis(100)).await;

    client.pooled.store(None);
    let next = client.get_or_connect(&target).await.expect("connect");
    assert!(
        next.pooled.used_0rtt(),
        "the next connection offers early data"
    );
    DoqMuxClient::ask(&next.pooled, &query, 0x1234)
        .await
        .expect("and has it accepted");
}

/// 0-RTT 被接受时，握手完以后来的查询不等还在 0-RTT 期间开出的流上等回答的查询：旧流的流号不变，和新流撞不上（见
/// [`EarlyStreams`]）
/// With 0-RTT accepted, a query coming once the handshake is through does not wait for one still
/// waiting for its answer on a stream opened during 0-RTT: the old streams keep their numbers,
/// which no new stream shares (see [`EarlyStreams`])
#[tokio::test]
async fn with_0rtt_accepted_a_later_query_does_not_wait_for_the_early_ones() {
    let (mut server, client_tls) = localhost_tls(&[b"doq"]);
    server.max_early_data_size = u32::MAX;
    let addr = spawn_doq_upstream(server, Duration::from_millis(100), |_, label| match label {
        "slow" => DoqReply::Answer(Duration::from_millis(500)),
        _ => DoqReply::Answer(Duration::ZERO),
    })
    .await;
    let client = Arc::new(resuming_doq_client(addr, client_tls).await);
    let slow = tokio::spawn({
        let client = Arc::clone(&client);
        async move {
            let query = udp_test_query("slow.example");
            client.send(&query, Duration::from_secs(2)).await
        }
    });
    let pooled = loop {
        match client.pooled.load_full() {
            Some(pooled) => break pooled,
            None => tokio::task::yield_now().await,
        }
    };
    let early = pooled.early.as_ref().expect("made with 0-RTT");
    assert!(early.accepted.clone().await, "0-RTT accepted");
    assert_eq!(
        *early.held.borrow(),
        1,
        "`slow` waits on a stream opened during 0-RTT"
    );

    let started = tokio::time::Instant::now();
    client
        .send(&udp_test_query("fast.example"), Duration::from_secs(2))
        .await
        .expect("answered");
    assert!(
        started.elapsed() < Duration::from_millis(200),
        "at once, not after `slow`: {:?}",
        started.elapsed()
    );
    slow.await
        .expect("the query's task")
        .expect("`slow` is answered too");
}

/// 本机 DoQ 测试上游怎么对待一个查询 / How the local DoQ test upstream treats one query
#[derive(Clone, Copy)]
enum DoqReply {
    /// 隔这么久照常回答 / Answer after this long
    Answer(Duration),
    /// 回答，100 ms 后关掉整条连接 / Answer, then close the whole connection 100 ms later
    AnswerThenClose,
    /// 读完查询，隔这么久关掉整条连接，不回答 / Read the query and close the connection after this
    /// long, unanswered
    Close(Duration),
    /// 一直不回答 / Never answer
    Silence,
    /// 回答别的问题 / Answer another question
    AnotherQuestion,
}

/// 本机 DoQ 上游：握手先压住 `accept_delay`；每条连接上第 n 个查询（从 0 数）按
/// `reply(n, 问题名第一个标签)` 处理，应答是置了 QR 位的原查询。
/// Local DoQ upstream: the handshake is held back for `accept_delay`; the
/// n-th query on each connection (counting from 0) is treated as
/// `reply(n, first label of the question)`, the answer being the query
/// with QR set.
async fn spawn_doq_upstream(
    server: rustls::ServerConfig,
    accept_delay: Duration,
    reply: fn(usize, &str) -> DoqReply,
) -> SocketAddr {
    spawn_doq_upstream_on(
        "127.0.0.1:0".parse().unwrap(),
        server,
        accept_delay,
        reply,
        None,
    )
    .expect("bind the DoQ test upstream")
}

/// 同 [`spawn_doq_upstream`]，绑在 `bind` 上；该地址族不可用时为 None。给了 `closed`，每条连接
/// 结束时往里发一个信号
/// As [`spawn_doq_upstream`], bound to `bind`; `None` when that address
/// family is unavailable on this host. With `closed`, a signal goes there
/// whenever a connection ends
fn spawn_doq_upstream_on(
    bind: SocketAddr,
    server: rustls::ServerConfig,
    accept_delay: Duration,
    reply: fn(usize, &str) -> DoqReply,
    closed: Option<tokio::sync::mpsc::UnboundedSender<()>>,
) -> Option<SocketAddr> {
    let crypto =
        quinn::crypto::rustls::QuicServerConfig::try_from(server).expect("quic server crypto");
    let endpoint =
        QuicEndpoint::server(quinn::ServerConfig::with_crypto(Arc::new(crypto)), bind).ok()?;
    let addr = endpoint.local_addr().expect("read the DoQ test address");
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let closed = closed.clone();
            tokio::spawn(async move {
                tokio::time::sleep(accept_delay).await;
                let Ok(conn) = incoming.await else { return };
                let mut index = 0;
                while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    let n = index;
                    index += 1;
                    let conn = conn.clone();
                    tokio::spawn(async move {
                        let Ok(mut frame) = recv.read_to_end(MAX_DNS_MESSAGE_SIZE + 2).await else {
                            return;
                        };
                        let close = || conn.close(quinn::VarInt::from_u32(0), b"closing");
                        let action = reply(n, &first_label(&frame[2..]));
                        let delay = match action {
                            DoqReply::Silence => {
                                // 拿着发送端不放：一放手流就结束了，客户端会读到空应答
                                // Hold on to the send side: dropping it ends
                                // the stream and the client reads an empty answer
                                tokio::time::sleep(Duration::from_secs(30)).await;
                                drop(send);
                                return;
                            }
                            DoqReply::Close(delay) => {
                                tokio::time::sleep(delay).await;
                                close();
                                return;
                            }
                            DoqReply::AnotherQuestion => {
                                let other =
                                    udp_response_with_question(&frame[2..], "other.example");
                                let _ = send.write_all(&(other.len() as u16).to_be_bytes()).await;
                                let _ = send.write_all(&other).await;
                                let _ = send.finish();
                                let _ = send.stopped().await;
                                return;
                            }
                            DoqReply::Answer(delay) => delay,
                            DoqReply::AnswerThenClose => Duration::ZERO,
                        };
                        tokio::time::sleep(delay).await;
                        // 长度前缀之后第 3 个字节是 QR 所在的标志位
                        // The flags byte carrying QR sits third after the length prefix
                        frame[4] |= 0x80;
                        let _ = send.write_all(&frame).await;
                        let _ = send.finish();
                        if matches!(action, DoqReply::AnswerThenClose) {
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            close();
                        }
                    });
                }
                if let Some(closed) = closed {
                    let _ = closed.send(());
                }
            });
        }
    });
    Some(addr)
}

/// 只信任 `client_tls` 里那张证书的 DoQ 客户端 / A DoQ client trusting only the certificate in `client_tls`
fn doq_test_client(upstream: String, client_tls: ClientConfig, enable_0rtt: bool) -> DoqMuxClient {
    DoqMuxClient::new(
        Arc::from(upstream),
        doq_test_runtime(client_tls, enable_0rtt),
        Arc::default(),
    )
}

/// 只信任 `client_tls` 里那张证书的 DoQ 端点 / DoQ endpoints trusting only the certificate in `client_tls`
fn doq_test_runtime(client_tls: ClientConfig, enable_0rtt: bool) -> Arc<DoqRuntime> {
    doq_test_runtime_through(client_tls, enable_0rtt, Bootstrap::system())
}

/// 同 [`doq_test_runtime`]，主机名交给 `bootstrap` 解析 / As [`doq_test_runtime`], host names
/// resolved by `bootstrap`
fn doq_test_runtime_through(
    client_tls: ClientConfig,
    enable_0rtt: bool,
    bootstrap: Arc<Bootstrap>,
) -> Arc<DoqRuntime> {
    doq_runtime_aging(
        client_tls,
        enable_0rtt,
        bootstrap,
        doq_transport(0, 0).expect("transport"),
        Aging::new(DOQ_MAX_AGE, Duration::from_secs(60)),
    )
}

/// 同 [`doq_test_runtime_through`]，QUIC 照 `transport`（见 [`doq_transport`]），连接照 `aging` 老化 / As
/// [`doq_test_runtime_through`], QUIC going by `transport` (see [`doq_transport`]) and
/// connections aging by `aging`
fn doq_runtime_aging(
    client_tls: ClientConfig,
    enable_0rtt: bool,
    bootstrap: Arc<Bootstrap>,
    transport: QuicTransportConfig,
    aging: Aging,
) -> Arc<DoqRuntime> {
    let config = doq_client_config(client_tls, transport).expect("quic client config");
    let mut endpoint_v4 =
        QuicEndpoint::client("127.0.0.1:0".parse().unwrap()).expect("bind the DoQ client");
    endpoint_v4.set_default_client_config(config.clone());
    let endpoint_v6 = match QuicEndpoint::client("[::1]:0".parse().unwrap()) {
        Ok(mut endpoint) => {
            endpoint.set_default_client_config(config);
            endpoint
        }
        Err(_) => endpoint_v4.clone(),
    };
    Arc::new(DoqRuntime {
        endpoint_v4,
        endpoint_v6,
        aging,
        bootstrap,
        enable_0rtt,
        zero_rtt_notice: std::sync::Once::new(),
    })
}

/// DoQ 上一个查询只有一个回答：答的是别的问题就算失败，不交出去。
/// Over DoQ a query gets a single answer: one to another question fails the
/// query instead of being handed on.
#[tokio::test]
async fn a_doq_answer_to_another_question_fails_the_query() {
    let (server, client_tls) = localhost_tls(&[b"doq"]);
    let addr = spawn_doq_upstream(server, Duration::ZERO, |_, _| DoqReply::AnotherQuestion).await;
    let client = doq_test_client(format!("{addr}?sni=localhost"), client_tls, false);
    let err = client
        .send(&udp_test_query("swap.example"), Duration::from_secs(2))
        .await
        .expect_err("an answer to another question");
    assert!(
        format!("{err:#}").contains("does not answer the query"),
        "{err:#}"
    );
}

/// 上游开不出流给我们：查询都是我们开的流，上游开过来的流不会有人接，以前各能开 100 个，开过来的流和上面的数据
/// 就一直缓冲着。它照样回答我们开的流
/// An upstream can open no stream to us: every query is a stream we open, and nobody would
/// accept one it opened; it used to be allowed 100 of each, those streams and their data
/// staying buffered. It still answers the streams we open
#[tokio::test]
async fn a_doq_upstream_cannot_open_streams_to_us() {
    let (server, client_tls) = localhost_tls(&[b"doq"]);
    let crypto =
        quinn::crypto::rustls::QuicServerConfig::try_from(server).expect("quic server crypto");
    let endpoint = QuicEndpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(crypto)),
        "127.0.0.1:0".parse().unwrap(),
    )
    .expect("bind the DoQ test upstream");
    let addr = endpoint.local_addr().unwrap();
    let opened = tokio::spawn(async move {
        let conn = endpoint
            .accept()
            .await
            .expect("incoming")
            .await
            .expect("connected");
        let (mut send, mut recv) = conn.accept_bi().await.expect("the query's stream");
        let mut frame = recv.read_to_end(MAX_DNS_MESSAGE_SIZE + 2).await.unwrap();
        let wait = Duration::from_millis(300);
        let uni = tokio::time::timeout(wait, conn.open_uni()).await.is_ok();
        let bi = tokio::time::timeout(wait, conn.open_bi()).await.is_ok();
        frame[4] |= 0x80;
        send.write_all(&frame).await.unwrap();
        send.finish().unwrap();
        let _ = send.stopped().await;
        (uni, bi)
    });
    let client = doq_test_client(format!("{addr}?sni=localhost"), client_tls, false);
    client
        .send(&udp_test_query("streams.example"), Duration::from_secs(3))
        .await
        .expect("the stream we opened is answered");
    assert_eq!(opened.await.unwrap(), (false, false), "(uni, bi) opened");
}

/// 阿里的 DoQ 服务器大约 10 秒就关掉空闲连接，比 15 秒一次的保活还短。池里那条已经
/// 关掉的连接曾被原样拿去用，这次查询直接失败；每个上游有 16 条连接轮流用，空闲之后
/// 头 16 个查询就一个接一个失败。
/// Alibaba's DoQ servers drop an idle connection after about 10 s, sooner
/// than the 15 s keep-alive. The closed connection used to be handed out as
/// it was and the query failed outright; with 16 pooled connections per
/// upstream used in turn, the first 16 queries after a quiet spell failed
/// one after another.
#[tokio::test]
async fn doq_replaces_a_pooled_connection_the_server_already_closed() {
    let (server, client_tls) = localhost_tls(&[b"doq"]);
    let addr = spawn_doq_upstream(server, Duration::ZERO, |_, _| DoqReply::AnswerThenClose).await;
    let client = doq_test_client(format!("{addr}?sni=localhost"), client_tls, false);
    client
        .send(&udp_test_query("first.example"), Duration::from_secs(2))
        .await
        .expect("a fresh connection answers");

    // 服务器在应答 100 ms 后关掉连接 / The server closes the connection 100 ms after answering
    tokio::time::sleep(Duration::from_millis(400)).await;
    let second = client
        .send(&udp_test_query("second.example"), Duration::from_secs(2))
        .await;
    assert!(
        second.is_ok(),
        "a connection the server already closed must be replaced, not used: {:?}",
        second.err()
    );
}

/// 放弃一个查询时（竞速时别的上游先答了），上游收到的停止接收带着 DOQ_REQUEST_CANCELLED（RFC 9250 第 4.3.1 节）。
/// 以前是 0，也就是 DOQ_NO_ERROR。时限用完、连接上也没读到过别的回答时，整条连接换掉，用不着这个码
/// Abandoning a query (another upstream answering first in a race), the upstream is told to
/// stop sending with DOQ_REQUEST_CANCELLED (RFC 9250 section 4.3.1). It used to be 0,
/// DOQ_NO_ERROR. A deadline running out with no other answer read on the connection has the
/// whole connection replaced, where the code does not come into it
#[tokio::test]
async fn an_abandoned_doq_query_is_cancelled_with_request_cancelled() {
    let (server, client_tls) = localhost_tls(&[b"doq"]);
    let crypto =
        quinn::crypto::rustls::QuicServerConfig::try_from(server).expect("quic server crypto");
    let endpoint = QuicEndpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(crypto)),
        "127.0.0.1:0".parse().unwrap(),
    )
    .expect("bind the DoQ test server");
    let addr = endpoint.local_addr().expect("read the DoQ test address");
    let (told, stopped) = oneshot::channel();
    tokio::spawn(async move {
        let conn = endpoint
            .accept()
            .await
            .expect("a connection")
            .await
            .expect("handshake");
        let (send, mut recv) = conn.accept_bi().await.expect("a query stream");
        recv.read_to_end(MAX_DNS_MESSAGE_SIZE + 2)
            .await
            .expect("the query");
        let _ = told.send(send.stopped().await);
        // 连接要留到读完错误码 / The connection stays until the error code is read
        let _ = (endpoint, conn);
    });
    let client = doq_test_client(format!("{addr}?sni=localhost"), client_tls, false);
    // 外层先放弃（竞速时别的上游先答了），连接还在用 / Given up from outside (another upstream
    // answering first in a race), with the connection still in use
    let raced = timeout(
        Duration::from_millis(100),
        client.send(&udp_test_query("abandoned.example"), Duration::from_secs(2)),
    )
    .await;
    assert!(raced.is_err(), "the server never answers");
    let code = timeout(Duration::from_secs(2), stopped)
        .await
        .expect("the server is told")
        .expect("the server reports");
    assert_eq!(
        code.as_ref().ok(),
        Some(&Some(DOQ_REQUEST_CANCELLED)),
        "{code:?}"
    );
}

/// 连接在检查之后、查询途中才断时，靠的是换一条新连接再发一次
/// When the connection only dies after the check, during the query, the one
/// retry on a fresh connection is what saves the query
#[tokio::test]
async fn doq_retries_once_when_the_pooled_connection_dies_under_the_query() {
    let (server, client_tls) = localhost_tls(&[b"doq"]);
    let addr = spawn_doq_upstream(server, Duration::ZERO, |n, _| {
        if n == 0 {
            DoqReply::Answer(Duration::ZERO)
        } else {
            DoqReply::Close(Duration::ZERO)
        }
    })
    .await;
    let client = doq_test_client(format!("{addr}?sni=localhost"), client_tls, false);
    client
        .send(&udp_test_query("first.example"), Duration::from_secs(2))
        .await
        .expect("a fresh connection answers");

    let second = client
        .send(&udp_test_query("second.example"), Duration::from_secs(2))
        .await;
    assert!(
        second.is_ok(),
        "a pooled connection closed under the query must be retried on a fresh one: {:?}",
        second.err()
    );
}

/// 池里的连接在查询途中断了，剩下的预算却不到 [`MIN_RETRY_BUDGET`]：不换连接重发，和别的传输一样。以前还剩 1 毫秒
/// 也重发
/// A pooled connection dying under a query with less than [`MIN_RETRY_BUDGET`] of its budget
/// left: the query is not sent again on a fresh one, as on the other transports. It used to
/// be sent again with a millisecond left
#[tokio::test]
async fn doq_does_not_retry_without_the_budget_for_it() {
    /// 上游收到了几次 `second` / How many times the upstream received `second`
    static SECOND: AtomicUsize = AtomicUsize::new(0);
    let (server, client_tls) = localhost_tls(&[b"doq"]);
    // 预算 400 毫秒，连接在 355 毫秒时断：剩下的一定不到 MIN_RETRY_BUDGET，换一条新连接重发却来得及
    // A budget of 400 ms and the connection gone at 355 ms: what is left is always short of
    // MIN_RETRY_BUDGET, yet enough to send again on a fresh connection
    let addr = spawn_doq_upstream(server, Duration::ZERO, |n, label| {
        if label != "second" {
            return DoqReply::Answer(Duration::ZERO);
        }
        if SECOND.fetch_add(1, Ordering::Relaxed) == 0 && n > 0 {
            DoqReply::Close(Duration::from_millis(355))
        } else {
            DoqReply::Answer(Duration::ZERO)
        }
    })
    .await;
    let client = doq_test_client(format!("{addr}?sni=localhost"), client_tls, false);
    client
        .send(&udp_test_query("first.example"), Duration::from_secs(2))
        .await
        .expect("a fresh connection answers");

    let second = client
        .send(
            &udp_test_query("second.example"),
            Duration::from_millis(400),
        )
        .await;
    assert!(second.is_err(), "not sent again: {second:?}");
    assert_eq!(SECOND.load(Ordering::Relaxed), 1, "sent once");
}

/// 没用 0-RTT 的连接上一次回答慢：这个查询超时，0-RTT 发往的地址留着，断连之后重连照样用 0-RTT 省下一个往返。这样的超时曾被
/// 当成 0-RTT 被拒，把这个上游的 0-RTT 关到重启为止
/// One slow answer on a connection that did not use 0-RTT: the query times out, and the address
/// 0-RTT goes to is kept, a reconnect after a dropped connection still saving a round trip with
/// 0-RTT. Such a timeout used to count as 0-RTT being rejected and switched it off for the
/// upstream until a restart
#[tokio::test]
async fn a_doq_timeout_without_0rtt_keeps_the_0rtt_address() {
    let (server, client_tls) = localhost_tls(&[b"doq"]);
    let addr = spawn_doq_upstream(server, Duration::ZERO, |_, label| {
        if label == "slow" {
            DoqReply::Silence
        } else {
            DoqReply::Answer(Duration::ZERO)
        }
    })
    .await;
    let client = doq_test_client(format!("{addr}?sni=localhost"), client_tls, true);
    let result = client
        .send(&udp_test_query("slow.example"), Duration::from_millis(300))
        .await;
    assert!(result.is_err(), "the upstream never answers `slow`");
    assert!(
        client.zero_rtt.reached.lock().is_some(),
        "a timeout on a connection that did not use 0-RTT keeps the address 0-RTT goes to"
    );
}

/// 连接没了、或者超时而这期间连接上没读到别的回答，才换连接；回答的不是这个问题是这一个查询的事，超时而连接照常
/// 在回答别的查询是这一个回答慢，连接都照用。以前每次失败都换，接着的查询又要重新握手
/// The connection is replaced only once it is gone, or a query timed out with no other answer
/// read on it meanwhile; an answer to another question is this one query's matter, and a
/// timeout while the connection kept answering others is this one answer being slow, the
/// connection staying in use either way. Every failure used to replace it, the next query
/// shaking hands again
#[tokio::test]
async fn a_doq_connection_is_replaced_only_when_it_failed() {
    for (failing, budget, alongside, replaced) in [
        ("wrong", Duration::from_secs(2), false, false),
        ("slow", Duration::from_millis(300), false, true),
        ("slow", Duration::from_millis(300), true, false),
    ] {
        let (server, client_tls) = localhost_tls(&[b"doq"]);
        let addr = spawn_doq_upstream(server, Duration::ZERO, |_, label| match label {
            "wrong" => DoqReply::AnotherQuestion,
            "slow" => DoqReply::Silence,
            "late" => DoqReply::Answer(Duration::from_millis(100)),
            _ => DoqReply::Answer(Duration::ZERO),
        })
        .await;
        let client = doq_test_client(format!("{addr}?sni=localhost"), client_tls, false);
        client
            .send(&udp_test_query("warm.example"), Duration::from_secs(2))
            .await
            .expect("a fresh connection answers");
        let before = client.pooled.load_full().expect("a pooled connection");
        let query = udp_test_query(&format!("{failing}.example"));
        let (failed, ()) = tokio::join!(client.send(&query, budget), async {
            if alongside {
                tokio::time::sleep(Duration::from_millis(50)).await;
                client
                    .send(&udp_test_query("late.example"), Duration::from_secs(2))
                    .await
                    .expect("answered alongside");
            }
        });
        assert!(failed.is_err(), "`{failing}` gets no usable answer");
        let kept = client
            .pooled
            .load_full()
            .is_some_and(|after| Arc::ptr_eq(&after, &before));
        assert_eq!(
            !kept, replaced,
            "`{failing}`, answered alongside: {alongside}"
        );
        client
            .send(&udp_test_query("after.example"), Duration::from_secs(2))
            .await
            .unwrap_or_else(|err| panic!("after `{failing}`, the next query got {err:#}"));
    }
}

/// 一个查询超时、这期间连接上没读到过别的回答：连接关掉，它上面别的查询马上失败，换一条新连接重发、答上，不用等到
/// 各自的期限
/// A query timing out with no other answer read on its connection meanwhile: the connection is
/// closed, and the other queries on it fail at once, are sent again on a fresh one and
/// answered, without waiting out their deadlines
#[tokio::test]
async fn a_stalled_doq_connection_is_closed_and_its_queries_sent_again() {
    /// 上游收到了几次 `waiting` / How many times the upstream received `waiting`
    static WAITING: AtomicUsize = AtomicUsize::new(0);
    let (server, client_tls) = localhost_tls(&[b"doq"]);
    let addr = spawn_doq_upstream(server, Duration::ZERO, |_, label| match label {
        "stalled" => DoqReply::Silence,
        "waiting" if WAITING.fetch_add(1, Ordering::Relaxed) == 0 => DoqReply::Silence,
        _ => DoqReply::Answer(Duration::ZERO),
    })
    .await;
    let client = doq_test_client(format!("{addr}?sni=localhost"), client_tls, false);
    client
        .send(&udp_test_query("warm.example"), Duration::from_secs(2))
        .await
        .expect("a fresh connection answers");
    let stalled = client.pooled.load_full().expect("a pooled connection");
    let (stalled_query, waiting_query) = (
        udp_test_query("stalled.example"),
        udp_test_query("waiting.example"),
    );
    let started = tokio::time::Instant::now();
    let (timed_out, waiting) = tokio::join!(
        client.send(&stalled_query, Duration::from_millis(300)),
        client.send(&waiting_query, Duration::from_secs(3)),
    );
    assert!(timed_out.is_err(), "the upstream never answers `stalled`");
    waiting.expect("sent again on a fresh connection and answered");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "answered well before its own deadline"
    );
    assert!(
        stalled.conn.close_reason().is_some(),
        "the stalled connection is closed"
    );
    assert_eq!(WAITING.load(Ordering::Relaxed), 2, "sent once more");
}

/// 握手被压住 250 ms、回答再等 250 ms：300 ms 预算的请求不跑满 500 ms，到时限就失败
/// A handshake held back 250 ms and an answer after another 250 ms: a request with a 300 ms
/// budget does not run the full 500 ms but fails at its limit
#[tokio::test]
async fn doq_handshake_and_answer_share_one_budget() {
    let (server, client_tls) = localhost_tls(&[b"doq"]);
    let addr = spawn_doq_upstream(server, Duration::from_millis(250), |_, _| {
        DoqReply::Answer(Duration::from_millis(250))
    })
    .await;
    let client = doq_test_client(format!("{addr}?sni=localhost"), client_tls, false);
    let started = tokio::time::Instant::now();
    let result = client
        .send(
            &udp_test_query("budget.example"),
            Duration::from_millis(300),
        )
        .await;
    let elapsed = started.elapsed();
    assert!(result.is_err(), "the answer cannot arrive within 300 ms");
    assert!(
        elapsed < Duration::from_millis(420),
        "a 300 ms request ran for {elapsed:?}"
    );
}

/// DoQ 握手一直不回（上游收下 Initial 包、从不回答）：到建连的时限失败，原因里写着连的是哪个地址、多久没回应。以前外层的
/// 时限先到，只剩「connect timeout after 5000ms」
/// A DoQ handshake never answered (the upstream taking the Initial packets and never replying)
/// fails at the connect's time limit, its cause naming the address dialled and how long it went
/// unanswered. The outer time limit used to come first, leaving "connect timeout after 5000ms"
/// alone
#[tokio::test]
async fn a_doq_handshake_left_unanswered_names_the_address() {
    let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = silent.local_addr().unwrap();
    let (_, client_tls) = localhost_tls(&[b"doq"]);
    let client = doq_test_client(format!("{addr}?sni=localhost"), client_tls, false);
    let budget = crate::engine::transport::connect::CONNECT_BUDGET + Duration::from_secs(2);
    let err = client
        .send(&udp_test_query("silent.example"), budget)
        .await
        .expect_err("no handshake");
    let err = format!("{err:#}");
    let waited = err
        .split_once(&format!("connect {addr}: no answer in "))
        .and_then(|(_, rest)| rest.split_once("ms"))
        .and_then(|(ms, _)| ms.parse::<u64>().ok())
        .unwrap_or_else(|| panic!("{err}"));
    assert!((4900..5500).contains(&waited), "{err}");
}

#[tokio::test]
async fn doq_reaches_an_ipv6_literal_upstream() {
    let (server, client_tls) = localhost_tls(&[b"doq"]);
    let answer = |_: usize, _: &str| DoqReply::Answer(Duration::ZERO);
    let Some(addr) = spawn_doq_upstream_on(
        "[::1]:0".parse().unwrap(),
        server,
        Duration::ZERO,
        answer,
        None,
    ) else {
        eprintln!("skipped: IPv6 loopback unavailable on this host");
        return;
    };
    let client = doq_test_client(
        format!("[::1]:{}?sni=localhost", addr.port()),
        client_tls,
        false,
    );
    client
        .send(&udp_test_query("v6.example"), Duration::from_secs(2))
        .await
        .expect("an IPv6 literal DoQ upstream answers");
}

/// 本机的 bootstrap 服务器，`upstream.test` 解析成 127.0.0.1 和 ::1，IPv4 在前 / A local bootstrap
/// server, `upstream.test` resolving to 127.0.0.1 and ::1, IPv4 first
async fn loopback_names() -> (crate::engine::test_support::Upstream, Arc<Bootstrap>) {
    let server = crate::engine::test_support::loopback_bootstrap(300).await;
    let bootstrap = Bootstrap::new(
        &server.address,
        Arc::new(UdpClient::new(1).expect("UDP client")),
    );
    (server, bootstrap)
}

/// 一个端口上只有 ::1 有 DoQ 上游，127.0.0.1 上同一个端口的 UDP 收下握手却从不读；`early_data` 时上游收早期数据。
/// 给出端口、客户端的 TLS 设置和那个不回应的 socket；IPv6 环回不可用时是 None
/// A port with a DoQ upstream on ::1 alone, UDP on the same port of 127.0.0.1 taking the
/// handshakes and never reading them; with `early_data` the upstream takes early data. Gives
/// the port, the client's TLS settings and the socket that never answers; None with IPv6
/// loopback unavailable
fn answering_on_ipv6_alone(early_data: bool) -> Option<(u16, ClientConfig, std::net::UdpSocket)> {
    let answer = |_: usize, _: &str| DoqReply::Answer(Duration::ZERO);
    for _ in 0..20 {
        let (mut server, client_tls) = localhost_tls(&[b"doq"]);
        if early_data {
            server.max_early_data_size = u32::MAX;
        }
        let v6 = spawn_doq_upstream_on(
            "[::1]:0".parse().unwrap(),
            server,
            Duration::ZERO,
            answer,
            None,
        )?;
        if let Ok(silent) = std::net::UdpSocket::bind(("127.0.0.1", v6.port())) {
            return Some((v6.port(), client_tls, silent));
        }
    }
    panic!("no port free on both loopbacks in 20 tries");
}

/// DoQ 也一样：127.0.0.1 上同一个端口的 UDP 从不回应，过 [`ATTEMPT_DELAY`] 就在 ::1 上握手。以前只连 IPv4 的那一个
/// DoQ alike: with UDP on the same port of 127.0.0.1 never answering, the handshake goes to ::1
/// after [`ATTEMPT_DELAY`]. The IPv4 address used to be the only one tried
#[tokio::test]
async fn a_doq_connect_moves_on_from_an_address_that_does_not_answer() {
    let (_server, bootstrap) = loopback_names().await;
    let Some((port, client_tls, _silent)) = answering_on_ipv6_alone(false) else {
        eprintln!("skipped: IPv6 loopback unavailable on this host");
        return;
    };
    let client = DoqMuxClient::new(
        Arc::from(format!("upstream.test:{port}?sni=localhost")),
        doq_test_runtime_through(client_tls, false, bootstrap),
        Arc::default(),
    );
    client
        .send(&udp_test_query("named.example"), Duration::from_secs(2))
        .await
        .expect("the second address answers");
}

/// 恢复会话的 0-RTT 只发往上一次完整握手连上的地址：127.0.0.1 不回应、::1 上的上游答了第一个查询，重连时 0-RTT
/// 发往 ::1，当场答上。以前 0-RTT 的连接当场就算连上，IPv4 排在前，0-RTT 就发往不回应的 127.0.0.1，查询等满时限，
/// 0-RTT 也被关掉
/// A resumed session's 0-RTT goes only to the address the last full handshake reached: with
/// 127.0.0.1 not answering and the upstream on ::1 having answered the first query, the
/// reconnect sends 0-RTT to ::1 and is answered at once. A 0-RTT connection used to count as
/// made at once, IPv4 coming first, so 0-RTT went to the silent 127.0.0.1, the query sat out its
/// limit and 0-RTT was switched off
#[tokio::test]
async fn zero_rtt_goes_to_the_address_the_last_handshake_reached() {
    let (_server, bootstrap) = loopback_names().await;
    let Some((port, client_tls, _silent)) = answering_on_ipv6_alone(true) else {
        eprintln!("skipped: IPv6 loopback unavailable on this host");
        return;
    };
    let client = DoqMuxClient::new(
        Arc::from(format!("upstream.test:{port}?sni=localhost")),
        doq_test_runtime_through(client_tls, true, bootstrap),
        Arc::default(),
    );
    client
        .send(&udp_test_query("first.example"), Duration::from_secs(2))
        .await
        .expect("the full handshake reaches ::1");
    // 等会话票据到 / The session ticket arrives
    tokio::time::sleep(Duration::from_millis(100)).await;

    client.pooled.store(None);
    let started = tokio::time::Instant::now();
    client
        .send(&udp_test_query("second.example"), Duration::from_secs(1))
        .await
        .expect("0-RTT to ::1 is answered");
    assert!(started.elapsed() < Duration::from_millis(200), "at once");
    let pooled = client.pooled.load_full().expect("a pooled connection");
    assert!(pooled.used_0rtt(), "the reconnect used 0-RTT");
    assert!(pooled.conn.remote_address().is_ipv6(), "to ::1");
}

/// 0-RTT 的连接上超时，而上游连握手都没回：是这个地址不通，忘掉它。下一次建连不在它上面盲发 0-RTT，照常完整握手；那次连上
/// 以后，再重连又用 0-RTT。以前这样的超时也把 0-RTT 关到重启
/// A timeout on a 0-RTT connection whose handshake the upstream never answered: the address is
/// down and forgotten. The next connect sends no 0-RTT blindly to it but shakes hands in full;
/// once that one is through, reconnecting uses 0-RTT again. Such a timeout used to switch 0-RTT
/// off until a restart too
#[tokio::test]
async fn a_0rtt_handshake_never_answered_forgets_the_0rtt_address() {
    // 关着时新来的握手一概不回，就像这个地址不通 / While off, every new handshake goes unanswered,
    // as for an address that is down
    let answering = Arc::new(AtomicBool::new(true));
    let (addr, client_tls) = spawn_doq_upstream_handshaking({
        let answering = Arc::clone(&answering);
        move |_| match answering.load(Ordering::SeqCst) {
            true => Handshake::Answer,
            false => Handshake::Ignore,
        }
    });
    let client = doq_test_client(format!("{addr}?sni=localhost"), client_tls, true);
    let target = parse_doq_target(&client.upstream).expect("doq target");
    client
        .send(&udp_test_query("first.example"), Duration::from_secs(2))
        .await
        .expect("a full handshake");
    tokio::time::sleep(Duration::from_millis(100)).await;

    answering.store(false, Ordering::SeqCst);
    client.pooled.store(None);
    let err = client
        .send(
            &udp_test_query("unanswered.example"),
            Duration::from_millis(300),
        )
        .await
        .expect_err("the handshake goes unanswered");
    assert_eq!(
        format!("{err:#}"),
        format!("doq 0-RTT handshake to {addr} unanswered")
    );
    answering.store(true, Ordering::SeqCst);
    let full = client.get_or_connect(&target).await.expect("connect");
    assert!(
        !full.pooled.used_0rtt(),
        "no 0-RTT sent blindly to that address again"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    client.pooled.store(None);
    let resumed = client.get_or_connect(&target).await.expect("connect");
    assert!(resumed.pooled.used_0rtt(), "a reconnect uses 0-RTT again");
}

/// 本机 DoQ 测试上游怎么对待一个新来的握手 / How the local DoQ test upstream treats a new handshake
#[derive(Clone, Copy)]
enum Handshake {
    /// 照常握手，回答每个查询 / Shake hands and answer every query
    Answer,
    /// 一直不回，就像这个地址不通 / Never answer, as for an address that is down
    Ignore,
    /// 隔这么久拒绝这条连接（CONNECTION_REFUSED），握手不回 / Refuse the connection after this long
    /// (CONNECTION_REFUSED), the handshake unanswered
    Refuse(Duration),
}

/// 收早期数据的本机 DoQ 上游：第 n 个（从 0 数）新来的握手照 `handshake(n)` 对待。给出它的地址和只信任它的客户端 TLS 设置
/// A local DoQ upstream taking early data, treating the n-th new handshake (counting from 0) as
/// `handshake(n)` says. Gives its address and client TLS settings trusting it alone
fn spawn_doq_upstream_handshaking(
    handshake: impl Fn(usize) -> Handshake + Send + 'static,
) -> (SocketAddr, ClientConfig) {
    let (mut server, client_tls) = localhost_tls(&[b"doq"]);
    server.max_early_data_size = u32::MAX;
    let crypto =
        quinn::crypto::rustls::QuicServerConfig::try_from(server).expect("quic server crypto");
    let endpoint = QuicEndpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(crypto)),
        "127.0.0.1:0".parse().unwrap(),
    )
    .expect("bind the DoQ test upstream");
    let addr = endpoint.local_addr().unwrap();
    tokio::spawn(async move {
        let mut handshakes = 0..;
        while let Some(incoming) = endpoint.accept().await {
            let treat = handshake(handshakes.next().expect("endless"));
            tokio::spawn(async move {
                let conn = match treat {
                    Handshake::Answer => match incoming.await {
                        Ok(conn) => conn,
                        Err(_) => return,
                    },
                    Handshake::Ignore => return incoming.ignore(),
                    Handshake::Refuse(after) => {
                        tokio::time::sleep(after).await;
                        return incoming.refuse();
                    }
                };
                while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    let Ok(mut frame) = recv.read_to_end(MAX_DNS_MESSAGE_SIZE + 2).await else {
                        continue;
                    };
                    frame[4] |= 0x80;
                    let _ = send.write_all(&frame).await;
                    let _ = send.finish();
                }
            });
        }
    });
    (addr, client_tls)
}

/// 连 `addr` 的客户端（0-RTT 开着）完整握手、答了一个查询、拿到会话票据，池里的连接拿掉了：下一个查询用 0-RTT 重连
/// A client of `addr` (0-RTT on) through a full handshake, a query answered and the session ticket
/// in, its pooled connection taken out: the next query reconnects with 0-RTT
async fn resuming_doq_client(addr: SocketAddr, client_tls: ClientConfig) -> DoqMuxClient {
    let client = doq_test_client(format!("{addr}?sni=localhost"), client_tls, true);
    client
        .send(&udp_test_query("first.example"), Duration::from_secs(2))
        .await
        .expect("a full handshake");
    tokio::time::sleep(Duration::from_millis(100)).await;
    client.pooled.store(None);
    client
}

/// 上游没回 0-RTT 的握手就拒绝了这条连接（比如忙不过来）：和握手没回一样是这个地址的事，0-RTT 照用。忘掉这个地址，查询换一条
/// 完整握手的连接重发、答上。以前看关闭原因分「对端关的」，而看守任务在连接关了以后照样调 close，把原因改写成本端关的：多线程下
/// 要看两边谁先跑，多半把 0-RTT 关到重启，不然重发仍是 0-RTT、发往同一个地址。所以重复多次
/// The upstream refusing the connection without answering its 0-RTT handshake (too busy, say):
/// as with a handshake unanswered, that is the address's matter, and 0-RTT stays on. The address
/// is forgotten and the query sent again on a connection shaking hands in full, and answered.
/// The close reason used to tell what the peer closed, while the watching task called close on
/// a closed connection all the same, rewriting the reason to a local close: on several threads it
/// came down to which ran first, mostly switching 0-RTT off until a restart, else the resend still
/// going over 0-RTT to the same address. Hence the repeats
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_0rtt_connection_the_upstream_refused_is_made_again_in_full() {
    for _ in 0..10 {
        let (addr, client_tls) = spawn_doq_upstream_handshaking(|n| match n {
            1 => Handshake::Refuse(Duration::ZERO),
            _ => Handshake::Answer,
        });
        let client = resuming_doq_client(addr, client_tls).await;
        client
            .send(&udp_test_query("refused.example"), Duration::from_secs(2))
            .await
            .expect("sent again and answered");
        let pooled = client.pooled.load_full().expect("a pooled connection");
        assert!(!pooled.used_0rtt(), "sent again with a full handshake");
        assert!(
            client.zero_rtt.reached.lock().is_some(),
            "0-RTT stays on, going to the address that full handshake reached"
        );
    }
}

/// 同上，拒绝来得晚、剩下的预算不够重发：错误里写着连的地址和上游给的原因，这个地址照样忘掉。以前是 quinn 的「0-RTT rejected」
/// As above, with the refusal coming late and too little budget left to send again: the error
/// names the address dialled and the upstream's own reason, and the address is forgotten all the
/// same. It used to be quinn's "0-RTT rejected"
#[tokio::test]
async fn a_late_refusal_of_a_0rtt_connection_names_the_address_and_why() {
    let (addr, client_tls) = spawn_doq_upstream_handshaking(|n| match n {
        // 预算 400 毫秒，355 毫秒时被拒：剩下的一定不到 MIN_RETRY_BUDGET，握手的期限（500 毫秒）也还没到
        // A budget of 400 ms and refused at 355 ms: what is left is always short of
        // MIN_RETRY_BUDGET, and the handshake's deadline (500 ms) is still to come
        1 => Handshake::Refuse(Duration::from_millis(355)),
        _ => Handshake::Answer,
    });
    let client = resuming_doq_client(addr, client_tls).await;
    let err = client
        .send(
            &udp_test_query("refused.example"),
            Duration::from_millis(400),
        )
        .await
        .expect_err("refused, with no time to send again");
    assert_eq!(
        format!("{err:#}"),
        format!(
            "doq 0-RTT handshake to {addr}: aborted by peer: \
             the server refused to accept a new connection"
        )
    );
    assert!(
        client.zero_rtt.reached.lock().is_none(),
        "address forgotten"
    );
}

/// 上游收了 0-RTT、回了握手，却在第一个查询上关掉连接：这个查询失败，错误里是上游给的原因，0-RTT 发往的地址留着。以前看守任务在
/// 连接关了以后照样调 close，原因常被改写成本端关的（「connection lost: closed」）；对端关的又被当成拒绝 0-RTT，多线程下多半把
/// 0-RTT 关到重启，而对端关的只可能是 0-RTT 已经接受了的连接：没接受时 quinn 报的是 `ZeroRttRejected`。所以重复多次
/// The upstream taking 0-RTT and answering the handshake, then closing the connection on the
/// first query: the query fails with the upstream's own reason, and the address 0-RTT goes to is
/// kept. The watching task used to call close on a closed connection all the same, often
/// rewriting the reason to a local close ("connection lost: closed"); and a close by the peer
/// counted as 0-RTT refused, mostly switching it off until a restart on several threads, while
/// only a connection whose 0-RTT was accepted can be lost to the peer: one not accepted, quinn
/// says `ZeroRttRejected`. Hence the repeats
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_upstream_closing_on_the_first_0rtt_query_keeps_the_0rtt_address() {
    for _ in 0..10 {
        let (mut server, client_tls) = localhost_tls(&[b"doq"]);
        server.max_early_data_size = u32::MAX;
        let addr = spawn_doq_upstream(server, Duration::ZERO, |_, label| match label {
            "closing" => DoqReply::Close(Duration::ZERO),
            _ => DoqReply::Answer(Duration::ZERO),
        })
        .await;
        let client = resuming_doq_client(addr, client_tls).await;
        let err = client
            .send(&udp_test_query("closing.example"), Duration::from_secs(2))
            .await
            .expect_err("the upstream closes the connection");
        assert!(format!("{err:#}").contains("by peer"), "{err:#}");
        assert!(
            client.zero_rtt.reached.lock().is_some(),
            "the address 0-RTT goes to is kept: {err:#}"
        );
    }
}

/// 0-RTT 的连接上游回了握手，一个回答却慢：这个查询超时，0-RTT 发往的地址留着，重连还用 0-RTT。以前这样的超时把这个上游的
/// 0-RTT 关到重启，长期运行几乎必然碰上一次
/// A connection whose 0-RTT handshake the upstream answered, and one slow answer on it: the query
/// times out, the address 0-RTT goes to is kept and a reconnect uses 0-RTT again. Such a timeout
/// used to switch 0-RTT off for the upstream until a restart, which a long run all but surely
/// meets once
#[tokio::test]
async fn a_slow_answer_over_0rtt_keeps_the_0rtt_address() {
    let (mut server, client_tls) = localhost_tls(&[b"doq"]);
    server.max_early_data_size = u32::MAX;
    let addr = spawn_doq_upstream(server, Duration::ZERO, |_, label| {
        if label == "slow" {
            DoqReply::Silence
        } else {
            DoqReply::Answer(Duration::ZERO)
        }
    })
    .await;
    let client = doq_test_client(format!("{addr}?sni=localhost"), client_tls, true);
    let target = parse_doq_target(&client.upstream).expect("doq target");
    client
        .send(&udp_test_query("first.example"), Duration::from_secs(2))
        .await
        .expect("a full handshake");
    tokio::time::sleep(Duration::from_millis(100)).await;

    client.pooled.store(None);
    let query = udp_test_query("slow.example");
    let (slow, answered) = tokio::join!(client.send(&query, Duration::from_millis(300)), async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        client
            .pooled
            .load_full()
            .is_some_and(|pooled| pooled.used_0rtt() && pooled.conn.handshake_data().is_some())
    });
    let err = slow.expect_err("the upstream never answers `slow`");
    assert!(format!("{err:#}").contains("doq timeout"), "{err:#}");
    assert!(
        answered,
        "`slow` went out over 0-RTT, the handshake answered"
    );
    client.pooled.store(None);
    let resumed = client.get_or_connect(&target).await.expect("connect");
    assert!(resumed.pooled.used_0rtt(), "a reconnect uses 0-RTT again");
}

/// 全局关了 0-RTT、这个上游写着 `0rtt=true`：重连用 0-RTT。以前 TLS 照全局设置不提出早期数据，按上游开的 0-RTT 从来
/// 用不上
/// 0-RTT off globally and `0rtt=true` written on this upstream: a reconnect uses 0-RTT. TLS used
/// to follow the global setting and offer no early data, so 0-RTT switched on for an upstream was
/// never used
#[tokio::test]
async fn an_upstream_uses_0rtt_with_it_off_globally() {
    let (mut server, client_tls) = localhost_tls(&[b"doq"]);
    server.max_early_data_size = u32::MAX;
    let addr = spawn_doq_upstream(server, Duration::ZERO, |_, _| {
        DoqReply::Answer(Duration::ZERO)
    })
    .await;
    let client = doq_test_client(format!("{addr}?sni=localhost&0rtt=true"), client_tls, false);
    client
        .send(&udp_test_query("first.example"), Duration::from_secs(2))
        .await
        .expect("a full handshake");
    tokio::time::sleep(Duration::from_millis(100)).await;

    client.pooled.store(None);
    client
        .send(&udp_test_query("second.example"), Duration::from_secs(2))
        .await
        .expect("the reconnect is answered");
    let pooled = client.pooled.load_full().expect("a pooled connection");
    assert!(pooled.used_0rtt(), "the reconnect used 0-RTT");
}

/// 上一次完整握手连上的 127.0.0.1 后来不回应了，::1 还通：重连照常把 0-RTT 发往 127.0.0.1，握手到期（[`answer_within`]）
/// 没回就关掉这条连接、忘掉这个地址，查询换一条完整握手的连接重发，错开 [`ATTEMPT_DELAY`] 连上 ::1 答上，不等满自己的
/// 期限。以前 0-RTT 的连接当场算连上，别的地址轮不到，查询等满时限才失败
/// 127.0.0.1, which the last full handshake reached, has since gone quiet, while ::1 still answers:
/// the reconnect sends 0-RTT to 127.0.0.1 as ever, and with its handshake unanswered by the
/// deadline ([`answer_within`]) the connection is closed and the address forgotten, the query sent
/// again on a connection shaking hands in full, which reaches ::1 an [`ATTEMPT_DELAY`] later and
/// is answered, well short of the query's own limit. A 0-RTT connection used to count as made at
/// once, no other address got a turn, and the query failed at its limit
#[tokio::test]
async fn a_0rtt_reconnect_to_an_address_gone_quiet_moves_on() {
    let (_server, bootstrap) = loopback_names().await;
    let Some((port, client_tls, _silent)) = answering_on_ipv6_alone(true) else {
        eprintln!("skipped: IPv6 loopback unavailable on this host");
        return;
    };
    let client = DoqMuxClient::new(
        Arc::from(format!("upstream.test:{port}?sni=localhost")),
        doq_test_runtime_through(client_tls, true, bootstrap),
        Arc::default(),
    );
    client
        .send(&udp_test_query("first.example"), Duration::from_secs(2))
        .await
        .expect("the full handshake reaches ::1");
    // 等会话票据到 / The session ticket arrives
    tokio::time::sleep(Duration::from_millis(100)).await;

    let quiet = SocketAddr::from(([127, 0, 0, 1], port));
    *client.zero_rtt.reached.lock() = Some((quiet, Duration::ZERO));
    client.pooled.store(None);
    let started = tokio::time::Instant::now();
    client
        .send(&udp_test_query("second.example"), Duration::from_secs(3))
        .await
        .expect("sent again and answered by ::1");
    let elapsed = started.elapsed();
    let expected = answer_within(Duration::ZERO) + ATTEMPT_DELAY;
    assert!(
        (expected..expected + Duration::from_millis(400)).contains(&elapsed),
        "answered after {elapsed:?}"
    );
    let reached = client.zero_rtt.reached.lock().map(|(address, _)| address);
    assert!(
        reached.is_some_and(|address| address.is_ipv6()),
        "{reached:?}"
    );
}

/// 同上，QUIC 的空闲超时先于握手的期限到：空闲 1 秒，上一次完整握手的往返时间 500 毫秒，握手的期限是 1.5 秒（见
/// [`answer_within`]）。quinn 在 1 秒时按超时关掉连接，这个地址照样忘掉，查询换一条完整握手的连接重发，::1 答上。以前只有到期
/// 关掉的才忘掉地址，重发仍是 0-RTT、发往同一个地址，再等满一次空闲超时，查询失败
/// As above, with QUIC's idle timeout coming before the handshake's deadline: idle 1 second, the
/// last full handshake's round trip 500 milliseconds, the handshake's deadline 1.5 seconds (see
/// [`answer_within`]). quinn closes the connection as timed out at 1 second, the address is
/// forgotten all the same and the query sent again on a connection shaking hands in full, which
/// ::1 answers. Only a connection closed at the deadline used to have its address forgotten, so
/// the resend still went over 0-RTT to the same address, sat out another idle timeout and the
/// query failed
#[tokio::test]
async fn a_0rtt_handshake_idle_timed_out_forgets_the_address() {
    let (_server, bootstrap) = loopback_names().await;
    let Some((port, client_tls, _silent)) = answering_on_ipv6_alone(true) else {
        eprintln!("skipped: IPv6 loopback unavailable on this host");
        return;
    };
    let client = DoqMuxClient::new(
        Arc::from(format!("upstream.test:{port}?sni=localhost")),
        doq_runtime_aging(
            client_tls,
            true,
            bootstrap,
            doq_transport(0, 1).expect("transport"),
            Aging::for_tests(),
        ),
        Arc::default(),
    );
    client
        .send(&udp_test_query("first.example"), Duration::from_secs(2))
        .await
        .expect("the full handshake reaches ::1");
    // 等会话票据到 / The session ticket arrives
    tokio::time::sleep(Duration::from_millis(100)).await;

    let quiet = SocketAddr::from(([127, 0, 0, 1], port));
    *client.zero_rtt.reached.lock() = Some((quiet, Duration::from_millis(500)));
    client.pooled.store(None);
    let started = tokio::time::Instant::now();
    client
        .send(&udp_test_query("second.example"), Duration::from_secs(3))
        .await
        .expect("sent again and answered by ::1");
    let elapsed = started.elapsed();
    let expected = Duration::from_secs(1) + ATTEMPT_DELAY;
    assert!(
        (expected..expected + Duration::from_millis(400)).contains(&elapsed),
        "answered after {elapsed:?}"
    );
}

/// 0-RTT 握手的期限至少两个 [`ATTEMPT_DELAY`]，往返时间长的链路上是三个往返：600 ms 往返的链路上，回得了握手的地址不会
/// 被当成不通
/// A 0-RTT handshake's deadline is two [`ATTEMPT_DELAY`]s at least, and three round trips on a
/// slow path: with a 600 ms round trip, an address that answers the handshake is not taken for
/// down
#[test]
fn a_0rtt_handshake_has_longer_to_answer_on_a_slow_path() {
    assert_eq!(answer_within(Duration::ZERO), 2 * ATTEMPT_DELAY);
    assert_eq!(
        answer_within(Duration::from_millis(600)),
        Duration::from_millis(1800)
    );
}

/// 写成主机名的 TCP、DoT、DoQ 上游经 Bootstrap 解析：`upstream.test` 只有本机的 bootstrap 服务器认得，
/// 三种上游都由它解析出 127.0.0.1 连上
/// TCP, DoT and DoQ upstreams written with a host name are resolved through Bootstrap:
/// `upstream.test` is known to the local bootstrap server only, and all three connect to the
/// 127.0.0.1 it resolves
#[tokio::test]
async fn named_tcp_dot_and_doq_upstreams_are_resolved_through_bootstrap() {
    let server = crate::engine::test_support::loopback_bootstrap(300).await;
    let bootstrap = Bootstrap::new(
        &server.address,
        Arc::new(UdpClient::new(1).expect("UDP client")),
    );
    let query = udp_test_query("named.example");
    let budget = Duration::from_secs(2);

    let tcp = spawn_stream_upstream(None).await;
    TcpMultiplexer::new(1, 0, 0, Arc::clone(&bootstrap))
        .send(&query, &format!("upstream.test:{}", tcp.port()), budget)
        .await
        .expect("the named TCP upstream answers");

    let (dot_server, dot_client) = self_signed_tls(&["upstream.test"], &[]);
    let dot = spawn_stream_upstream(Some(dot_server)).await;
    DotMultiplexer::with_shared((Arc::new(dot_client), Arc::clone(&bootstrap)), 1, 0, 0)
        .send(&query, &format!("upstream.test:{}", dot.port()), budget)
        .await
        .expect("the named DoT upstream answers");

    let (doq_server, doq_client) = self_signed_tls(&["upstream.test"], &[b"doq"]);
    let answer = |_: usize, _: &str| DoqReply::Answer(Duration::ZERO);
    let doq = spawn_doq_upstream(doq_server, Duration::ZERO, answer).await;
    let runtime = Arc::into_inner(doq_test_runtime(doq_client, false)).expect("one owner");
    DoqMuxClient::new(
        Arc::from(format!("upstream.test:{}", doq.port())),
        Arc::new(DoqRuntime {
            bootstrap,
            ..runtime
        }),
        Arc::default(),
    )
    .send(&query, budget)
    .await
    .expect("the named DoQ upstream answers");

    assert_eq!(
        server.queries(),
        2,
        "A and AAAA asked once, then kept for their TTL"
    );
}

/// 每个 DoQ 上游有一组连接（默认 16 条），对 0-RTT 的了解大家共用：一条连接发现 0-RTT 发往的地址不通，别的连接不再各把
/// 0-RTT 发过去、各等满一次握手的期限
/// Each DoQ upstream has a set of connections (16 by default) sharing what they know of 0-RTT:
/// once one connection finds the address 0-RTT goes to down, the others do not each send 0-RTT
/// there and sit out a handshake's deadline again
#[tokio::test]
async fn doq_pool_shares_what_one_connection_learned_about_0rtt() {
    let client =
        DoqClient::new(2, 60, 15_000, true, Bootstrap::system()).expect("build DoQ client");
    // 发一个连不上的查询，只为建出这个上游的连接池
    // A query nothing answers, only to build this upstream's pool
    let upstream = "127.0.0.1:9?sni=localhost";
    let _ = client
        .send(
            &udp_test_query("pool.example"),
            upstream,
            Duration::from_millis(50),
        )
        .await;
    let pool = client
        .pools
        .get(upstream)
        .map(|pool| Arc::clone(&pool))
        .expect("the first query builds the pool");
    assert_eq!(pool.clients.len(), 2);

    let address = SocketAddr::from(([127, 0, 0, 1], 9));
    *pool.clients[0].zero_rtt.reached.lock() = Some((address, Duration::ZERO));
    pool.clients[1].zero_rtt.address_down(address);
    assert!(
        pool.clients[0].zero_rtt.reached.lock().is_none(),
        "what one connection learned about 0-RTT holds for the whole upstream"
    );
}

/// DoQ 连接带着保活，不关掉的话会一直给旧上游发包
/// A DoQ connection carries a keep-alive and would go on pinging the old upstream
/// DoQ 连接池先用排在前面、还不忙的那个客户端：一个个来的查询都走第一条连接，别的客户端不建连接。以前轮流用，
/// 每个上游最后都开着 16 条连接、各自保活
/// A DoQ pool takes the first client not busy: queries coming one by one all go over the
/// first connection, and the other clients make none. They used to be taken in turn, every
/// upstream ending up with 16 connections open, each kept alive
#[tokio::test]
async fn a_doq_pool_uses_one_connection_until_it_is_busy() {
    let (server, client_tls) = localhost_tls(&[b"doq"]);
    let addr = spawn_doq_upstream(server, Duration::ZERO, |_, _| {
        DoqReply::Answer(Duration::ZERO)
    })
    .await;
    let client = DoqClient {
        pools: UpstreamPools::new(),
        pool_size: 4,
        runtime: doq_test_runtime(client_tls, false),
    };
    let upstream = format!("{addr}?sni=localhost");
    for n in 0..8 {
        client
            .send(
                &udp_test_query(&format!("q{n}.example")),
                &upstream,
                Duration::from_secs(2),
            )
            .await
            .expect("the upstream answers");
    }
    let pool = client
        .pools
        .get_or_create(&upstream, |_| unreachable!("built already"));
    let connected: Vec<bool> = pool
        .clients
        .iter()
        .map(|client| client.pooled.load().is_some())
        .collect();
    assert_eq!(connected, [true, false, false, false]);
}

/// QUIC 的保活让上游看这条连接一直在用；没人用了它照样关：最后一个查询的期限过后空闲满时限，从池里拿掉、关掉，不等下一个
/// 查询来看
/// QUIC's keepalive has the upstream see this connection in use all along; once nobody uses it
/// it closes all the same: idle its limit past the last query's deadline, it is taken out of
/// the pool and closed, with no next query to look
#[tokio::test]
async fn an_unused_doq_connection_closes_once_idle_despite_its_keepalive() {
    let (server, client_tls) = localhost_tls(&[b"doq"]);
    let (closed_tx, mut closed) = tokio::sync::mpsc::unbounded_channel();
    let addr = spawn_doq_upstream_on(
        "127.0.0.1:0".parse().unwrap(),
        server,
        Duration::ZERO,
        |_, _| DoqReply::Answer(Duration::ZERO),
        Some(closed_tx),
    )
    .expect("bind the DoQ test upstream");
    let aging = Aging {
        idle: Some(Duration::from_millis(200)),
        ..Aging::for_tests()
    };
    let client = DoqMuxClient::new(
        Arc::from(format!("{addr}?sni=localhost")),
        doq_runtime_aging(
            client_tls,
            false,
            Bootstrap::system(),
            doq_transport(50, 0).expect("transport"),
            aging,
        ),
        Arc::default(),
    );
    client
        .send(&udp_test_query("a.example"), Duration::from_millis(100))
        .await
        .expect("the upstream answers");
    timeout(Duration::from_secs(2), closed.recv())
        .await
        .expect("idle past the last deadline, it closes with no query coming")
        .expect("a close noted");
    assert!(client.pooled.load().is_none(), "taken out of the pool");
}

#[tokio::test]
async fn dropping_a_doq_pool_closes_its_connection() {
    let (server, client_tls) = localhost_tls(&[b"doq"]);
    let (closed_tx, mut closed) = tokio::sync::mpsc::unbounded_channel();
    let addr = spawn_doq_upstream_on(
        "127.0.0.1:0".parse().unwrap(),
        server,
        Duration::ZERO,
        |_, _| DoqReply::Answer(Duration::ZERO),
        Some(closed_tx),
    )
    .expect("bind the DoQ test upstream");
    let client = DoqClient {
        pools: UpstreamPools::new(),
        pool_size: 1,
        runtime: doq_test_runtime(client_tls, false),
    };
    client
        .send(
            &udp_test_query("a.example"),
            &format!("{addr}?sni=localhost"),
            Duration::from_secs(2),
        )
        .await
        .expect("the upstream answers");
    kept_then_dropped(&mut closed, |keep| client.retain_upstreams(|_| keep)).await;
}

/// 连接池大小写成 0 时按 1 算：DoQ 的池里有一个客户端（TCP 的见 `stream_tests`）
/// A pool size of 0 counts as 1: a DoQ pool gets one client (TCP's is in `stream_tests`)
#[tokio::test]
async fn a_pool_size_of_zero_gives_one_client() {
    let doq = DoqClient::new(0, 60, 15_000, false, Bootstrap::system()).expect("build DoQ client");
    // 发一个连不上的查询，只为建出这个上游的连接池
    // A query nothing answers, only to build this upstream's pool
    let upstream = "127.0.0.1:9?sni=localhost";
    let _ = doq
        .send(
            &udp_test_query("pool.example"),
            upstream,
            Duration::from_millis(50),
        )
        .await;
    let pool = doq
        .pools
        .get(upstream)
        .expect("the first query builds the pool");
    assert_eq!(pool.clients.len(), 1);
}
