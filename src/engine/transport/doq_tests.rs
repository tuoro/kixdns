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

/// 0-RTT 判定必须按类型走。此前它比对 `anyhow::Error::to_string()`，而内层
/// 每一步都被 `.context()` 包过，那个字符串永远只是三句固定短语之一或一条
/// bail 文本，于是 quinn 明说的 `ZeroRttRejected` 从来没有被识别过：判定
/// 返回 false，0-RTT 不被禁用，下次连接又用 0-RTT，该上游一直失败到重启。
/// The 0-RTT decision has to go by type. It used to compare
/// `anyhow::Error::to_string()`, and since every inner step was wrapped in
/// `.context()` that string was only ever one of three fixed phrases or a
/// bail text, so quinn saying `ZeroRttRejected` outright was never
/// recognised: the check returned false, 0-RTT stayed on, the next
/// connection used it again and the upstream kept failing until a restart.
#[test]
fn doq_zero_rtt_rejection_is_classified_by_type() {
    use quinn::{ConnectionError, ReadError, ReadToEndError, WriteError};

    // quinn 明说被拒绝 / quinn says so outright
    assert!(DoqMuxClient::zero_rtt_likely_rejected(&DoqFailure::Write(
        WriteError::ZeroRttRejected
    )));
    assert!(DoqMuxClient::zero_rtt_likely_rejected(&DoqFailure::Read(
        ReadToEndError::Read(ReadError::ZeroRttRejected)
    )));

    // 对端直接关掉连接：拒绝 0-RTT 数据的服务器常常这样做
    // The peer just closes: what a server refusing 0-RTT data often does
    let closed = || {
        ConnectionError::ApplicationClosed(quinn::ApplicationClose {
            error_code: quinn::VarInt::from_u32(0),
            reason: bytes::Bytes::new(),
        })
    };
    assert!(DoqMuxClient::zero_rtt_likely_rejected(
        &DoqFailure::OpenStream(closed())
    ));
    assert!(DoqMuxClient::zero_rtt_likely_rejected(&DoqFailure::Read(
        ReadToEndError::Read(ReadError::ConnectionLost(closed()))
    )));
    assert!(DoqMuxClient::zero_rtt_likely_rejected(&DoqFailure::Write(
        WriteError::ConnectionLost(ConnectionError::Reset)
    )));

    // 与 0-RTT 无关的失败不该触发重试
    // Failures that have nothing to do with 0-RTT must not trigger a retry
    assert!(!DoqMuxClient::zero_rtt_likely_rejected(
        &DoqFailure::OpenStream(ConnectionError::TimedOut)
    ));
    assert!(!DoqMuxClient::zero_rtt_likely_rejected(
        &DoqFailure::OpenStream(ConnectionError::LocallyClosed)
    ));
    assert!(!DoqMuxClient::zero_rtt_likely_rejected(&DoqFailure::Read(
        ReadToEndError::TooLong
    )));
    assert!(!DoqMuxClient::zero_rtt_likely_rejected(&DoqFailure::Read(
        ReadToEndError::Read(ReadError::ClosedStream)
    )));
    assert!(!DoqMuxClient::zero_rtt_likely_rejected(
        &DoqFailure::Protocol("doq response too short: 1 bytes".to_string())
    ));
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

/// 上游拒绝过 0-RTT 以后，新连接不再发早期数据：同一张会话票据，没标记时恢复出的连接用 0-RTT，
/// 标记以后就不用
/// Once an upstream rejected 0-RTT, new connections send no early data: with the same
/// session ticket, a resumed connection uses 0-RTT before the mark and not after it
#[tokio::test]
async fn doq_skips_0rtt_once_it_was_rejected() {
    let (mut server, client_tls) = localhost_tls(&[b"doq"]);
    server.max_early_data_size = u32::MAX;
    let addr = spawn_doq_upstream(server, Duration::ZERO, |_, _| {
        DoqReply::Answer(Duration::ZERO)
    })
    .await;
    let client = doq_test_client(format!("{addr}?sni=localhost"), client_tls, true);
    let target = parse_doq_target(&client.upstream).expect("doq target");
    // 第一条连接完整握手，拿到会话票据 / The first connection shakes hands in full and gets a ticket
    client
        .send(&udp_test_query("first.example"), Duration::from_secs(2))
        .await
        .expect("the upstream answers");
    tokio::time::sleep(Duration::from_millis(100)).await;

    client.pooled.store(None);
    let resumed = client.get_or_connect(&target).await.expect("connect");
    assert!(resumed.used_0rtt, "a resumed connection offers early data");

    client.pooled.store(None);
    client.disable_zero_rtt();
    let after = client.get_or_connect(&target).await.expect("connect");
    assert!(!after.used_0rtt, "no early data once 0-RTT was rejected");
}

/// 上游拒绝了 0-RTT 时，不光建这条连接的查询换一条不带 0-RTT 的连接再发一次，同时搭在这条连接上的查询也
/// 一样。以前只有建连接的那个查询重发，搭车的查询直接失败
/// When an upstream rejects 0-RTT, the query that made the connection is sent again on one
/// without 0-RTT, and so are the queries riding that connection at the time. Only the query
/// that made the connection used to be sent again, and those riding it failed
#[tokio::test]
async fn queries_riding_a_connection_whose_0rtt_is_rejected_are_sent_again() {
    let (mut accepting, client_tls) = localhost_tls(&[b"doq"]);
    accepting.max_early_data_size = u32::MAX;
    // 同一张证书的另一台上游：不认别人发的票据，早期数据也不收
    // Another upstream with the same certificate: it knows no ticket another gave, and
    // takes no early data
    let mut rejecting = accepting.clone();
    rejecting.max_early_data_size = 0;
    rejecting.session_storage = rustls::server::ServerSessionMemoryCache::new(32);
    let answer: fn(usize, &str) -> DoqReply = |_, _| DoqReply::Answer(Duration::ZERO);
    let first = spawn_doq_upstream(accepting, Duration::ZERO, answer).await;
    let second = spawn_doq_upstream(rejecting, Duration::ZERO, answer).await;

    // 先从第一台拿到允许早期数据的票据（票据按服务器名存，两台同名）
    // A ticket allowing early data comes from the first (tickets are kept by server name,
    // which the two share)
    let ticket = doq_test_client(format!("{first}?sni=localhost"), client_tls.clone(), true);
    ticket
        .send(&udp_test_query("first.example"), Duration::from_secs(2))
        .await
        .expect("the first upstream answers");
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = doq_test_client(format!("{second}?sni=localhost"), client_tls, true);
    let (a, b) = (udp_test_query("a.example"), udp_test_query("b.example"));
    // 上一次完整握手连上的是第二台，它后来换了票据的密钥，不认先前的票据：0-RTT 发往它，被拒
    // The last full handshake reached the second, which has since changed its ticket keys and
    // knows no earlier ticket: 0-RTT goes to it and is rejected
    *client.zero_rtt.reached.lock() = Some((second, Duration::ZERO));
    let (made_it, rode_it) = tokio::join!(
        client.send(&a, Duration::from_secs(2)),
        client.send(&b, Duration::from_secs(2)),
    );
    made_it.expect("the query that made the connection is sent again");
    rode_it.expect("so is the one riding it");
    assert!(
        client.zero_rtt.rejected.load(Ordering::Relaxed),
        "0-RTT is off for this upstream from then on"
    );
    // 两个查询的重发都在池里这一条连接上答完：没有各建一条 / Both resends were answered on
    // the one pooled connection: they did not make one each
    let pooled = client.pooled.load_full().expect("a pooled connection");
    assert_eq!(pooled.answers.load(Ordering::Acquire), 2);
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
        0,
        Aging::new(DOQ_MAX_AGE, Duration::from_secs(60)),
    )
}

/// 同 [`doq_test_runtime_through`]，QUIC 每 `keepalive_ms` 毫秒保活一次（0 不保活），连接照 `aging` 老化 / As
/// [`doq_test_runtime_through`], QUIC keeping alive every `keepalive_ms` (0 for never) and
/// connections aging by `aging`
fn doq_runtime_aging(
    client_tls: ClientConfig,
    enable_0rtt: bool,
    bootstrap: Arc<Bootstrap>,
    keepalive_ms: u64,
    aging: Aging,
) -> Arc<DoqRuntime> {
    let config = doq_client_config(
        client_tls,
        doq_transport(keepalive_ms, 0).expect("transport"),
    )
    .expect("quic client config");
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

/// 没用 0-RTT 的连接上一次回答慢，曾被当成 0-RTT 被拒，把这个上游的 0-RTT 关到
/// 重启为止；而断连之后要重连，0-RTT 正好省下一个往返。
/// One slow answer on a connection that did not use 0-RTT used to count as
/// 0-RTT being rejected and switched it off for the upstream until a
/// restart, while 0-RTT is exactly what saves a round trip on every
/// reconnect after a dropped connection.
#[tokio::test]
async fn a_doq_timeout_without_0rtt_leaves_0rtt_on() {
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
        !client.zero_rtt.rejected.load(Ordering::Relaxed),
        "a timeout on a connection that did not use 0-RTT says nothing about 0-RTT"
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
    assert!(pooled.used_0rtt, "the reconnect used 0-RTT");
    assert!(pooled.conn.remote_address().is_ipv6(), "to ::1");
}

/// 0-RTT 的连接上超时，而上游连握手都没回：是这个地址不通，0-RTT 照用。下一次建连不在它上面盲发 0-RTT，照常完整
/// 握手；那次连上以后，再重连又用 0-RTT。以前这样的超时也把 0-RTT 关到重启
/// A timeout on a 0-RTT connection whose handshake the upstream never answered: the address is
/// down, and 0-RTT stays on. The next connect sends no 0-RTT blindly to it but shakes hands in
/// full; once that one is through, reconnecting uses 0-RTT again. Such a timeout used to switch
/// 0-RTT off until a restart too
#[tokio::test]
async fn a_0rtt_handshake_never_answered_leaves_0rtt_on() {
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
    // 关着时新来的握手一概不回，就像这个地址不通 / While off, every new handshake goes unanswered,
    // as for an address that is down
    let answering = Arc::new(AtomicBool::new(true));
    tokio::spawn({
        let answering = Arc::clone(&answering);
        async move {
            while let Some(incoming) = endpoint.accept().await {
                if !answering.load(Ordering::SeqCst) {
                    incoming.ignore();
                    continue;
                }
                tokio::spawn(async move {
                    let Ok(conn) = incoming.await else { return };
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
    client
        .send(
            &udp_test_query("unanswered.example"),
            Duration::from_millis(300),
        )
        .await
        .expect_err("the handshake goes unanswered");
    answering.store(true, Ordering::SeqCst);
    let full = client.get_or_connect(&target).await.expect("connect");
    assert!(
        !full.used_0rtt,
        "no 0-RTT sent blindly to that address again"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    client.pooled.store(None);
    let resumed = client.get_or_connect(&target).await.expect("connect");
    assert!(resumed.used_0rtt, "0-RTT stays on");
}

/// 0-RTT 的连接上游回了握手，一个回答却慢：这个查询超时，0-RTT 照用，重连还用 0-RTT。以前这样的超时把这个上游的 0-RTT
/// 关到重启，长期运行几乎必然碰上一次
/// A connection whose 0-RTT handshake the upstream answered, and one slow answer on it: the query
/// times out, 0-RTT stays on and a reconnect uses it again. Such a timeout used to switch 0-RTT
/// off for the upstream until a restart, which a long run all but surely meets once
#[tokio::test]
async fn a_slow_answer_over_0rtt_leaves_0rtt_on() {
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
            .is_some_and(|pooled| pooled.used_0rtt && pooled.conn.handshake_data().is_some())
    });
    let err = slow.expect_err("the upstream never answers `slow`");
    assert!(format!("{err:#}").contains("doq timeout"), "{err:#}");
    assert!(
        answered,
        "`slow` went out over 0-RTT, the handshake answered"
    );
    assert!(
        !client.zero_rtt.rejected.load(Ordering::Relaxed),
        "a slow answer says nothing about 0-RTT"
    );
    client.pooled.store(None);
    let resumed = client.get_or_connect(&target).await.expect("connect");
    assert!(resumed.used_0rtt, "a reconnect uses 0-RTT again");
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
    assert!(pooled.used_0rtt, "the reconnect used 0-RTT");
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
    assert!(
        !client.zero_rtt.rejected.load(Ordering::Relaxed),
        "0-RTT stays on"
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

/// 每个 DoQ 上游有一组连接轮流用（默认 16 条）。"0-RTT 不稳定"此前是每条连接各记
/// 各的：0-RTT 在跨境线路上发不出去时，每条连接都要先失败一次、等满超时（默认 9 秒）
/// 才不再用它。
/// Each DoQ upstream has a set of connections used in turn (16 by default).
/// "0-RTT is unreliable" used to be recorded per connection: where 0-RTT
/// cannot get through, every connection had to fail once and sit out the
/// timeout (9 s by default) before it stopped using it.
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

    pool.clients[0].disable_zero_rtt();
    assert!(
        pool.clients[1].zero_rtt.rejected.load(Ordering::Relaxed),
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
        doq_runtime_aging(client_tls, false, Bootstrap::system(), 50, aging),
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
