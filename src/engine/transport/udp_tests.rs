//! UDP 客户端的测试 / Tests of the UDP client

use super::*;
use crate::engine::transport::test_support::*;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::time::timeout;

/// UDP "upstream" for UdpClient tests: records the (transaction id, source
/// port) of every query it receives and answers with each datagram of
/// `reply(query)`, in order.
/// UdpClient 测试用的 UDP "上游"：记录每个查询的 (TXID, 源端口)，按序发回
/// reply(query) 给出的每个数据报。
async fn spawn_udp_upstream(
    reply: impl Fn(&[u8]) -> Vec<Vec<u8>> + Send + 'static,
) -> (String, Arc<std::sync::Mutex<Vec<(u16, u16)>>>) {
    spawn_udp_upstream_on("127.0.0.1:0", reply)
        .await
        .expect("bind UDP test upstream")
}

/// 同 [`spawn_udp_upstream`]，绑在 `bind` 上；该地址族不可用时为 None
/// As [`spawn_udp_upstream`], bound to `bind`; `None` when that address family is
/// unavailable on this host
async fn spawn_udp_upstream_on(
    bind: &str,
    reply: impl Fn(&[u8]) -> Vec<Vec<u8>> + Send + 'static,
) -> Option<(String, Arc<std::sync::Mutex<Vec<(u16, u16)>>>)> {
    let socket = tokio::net::UdpSocket::bind(bind).await.ok()?;
    let addr = socket.local_addr().expect("read UDP test address");
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorder = Arc::clone(&seen);
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        while let Ok((n, src)) = socket.recv_from(&mut buf).await {
            let query = &buf[..n];
            let id = u16::from_be_bytes([query[0], query[1]]);
            recorder.lock().unwrap().push((id, src.port()));
            for datagram in reply(query) {
                let _ = socket.send_to(&datagram, src).await;
            }
        }
    });
    Some((addr.to_string(), seen))
}

#[tokio::test]
async fn udp_send_randomizes_transaction_id_and_source_port() {
    // RFC 5452 §4.3 / §9.2: neither the ID nor the source port may be
    // predictable. Before this, every socket numbered its IDs 0, 1, 2, …
    // and sockets were picked round-robin, so the sequence of (ID, port)
    // pairs was fully predictable.
    // RFC 5452 §4.3/§9.2：TXID 和源端口都不能可预测。此前每个 socket 的 ID 从
    // 0 顺序递增、socket 轮询选择，(ID, 端口) 序列完全可预测。
    let (upstream, seen) = spawn_udp_upstream(|query| vec![echo_answer(query)]).await;
    let client = UdpClient::new(4).expect("create UDP client");
    let sends = 16;
    for _ in 0..sends {
        client
            .send(
                &udp_test_query("id.example."),
                &upstream,
                Duration::from_secs(2),
            )
            .await
            .expect("query answered");
    }
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), sends);

    // Sequential numbering keeps every ID below the number of sends per
    // socket; random IDs spread over the whole 16-bit space.
    let ids: Vec<u16> = seen.iter().map(|(id, _)| *id).collect();
    assert!(
        ids.iter().any(|&id| id as usize >= sends),
        "transaction IDs look sequential: {ids:?}"
    );

    // Round-robin socket choice repeats the same port every pool_size sends.
    let ports: Vec<u16> = seen.iter().map(|(_, port)| *port).collect();
    assert!(
        ports
            .iter()
            .enumerate()
            .any(|(i, port)| *port != ports[i % 4]),
        "source ports cycle round-robin: {ports:?}"
    );
}

/// 一个 socket 发满 [`UDP_SOCKET_QUERIES`] 个查询就换成另一个端口上的新 socket。以前池里的端口用到进程结束
/// A socket that has sent [`UDP_SOCKET_QUERIES`] queries is replaced by a new one on another
/// port. The pool's ports used to last the process
#[tokio::test]
async fn a_udp_socket_moves_to_another_port_after_its_queries() {
    let (upstream, seen) = spawn_udp_upstream(|query| vec![echo_answer(query)]).await;
    let client = UdpClient::new(1).expect("create UDP client");
    let per_socket = UDP_SOCKET_QUERIES as usize;
    for _ in 0..2 * per_socket + 1 {
        client
            .send(
                &udp_test_query("turn.example."),
                &upstream,
                Duration::from_secs(2),
            )
            .await
            .expect("query answered");
    }
    let ports: Vec<u16> = seen.lock().unwrap().iter().map(|(_, port)| *port).collect();
    let rounds: Vec<&[u16]> = ports.chunks(per_socket).collect();
    for round in &rounds {
        assert!(round.iter().all(|port| *port == round[0]), "{round:?}");
    }
    assert_ne!(rounds[0][0], rounds[1][0]);
    assert_ne!(rounds[1][0], rounds[2][0]);
}

/// 换 socket 只换数满的那一个：取了旧 socket 的查询在它换下来以后又把它数满一轮，池里刚换上的新 socket 留着。以前不看
/// 位置上现在是哪个，照换
/// A replacement replaces only the socket counted up: a query that took the old socket counting
/// it up to another round after it was replaced leaves the new one in the pool. Whatever the
/// place held used to be replaced
#[tokio::test]
async fn a_socket_replaced_already_is_not_replaced_again() {
    let client = UdpClient::new(1).expect("create UDP client");
    let old = client.pool[0].load_full();
    old.sent.store(UDP_SOCKET_QUERIES - 1, Ordering::Relaxed);
    UdpClient::note_sent(&client.pool[0], 0, &old, false);
    let new = client.pool[0].load_full();
    assert!(!Arc::ptr_eq(&new, &old), "used up, it is replaced");
    old.sent
        .store(2 * UDP_SOCKET_QUERIES - 1, Ordering::Relaxed);
    UdpClient::note_sent(&client.pool[0], 0, &old, false);
    assert!(
        Arc::ptr_eq(&client.pool[0].load_full(), &new),
        "the new one stays"
    );
}

/// 换下来的 socket 还收它在途查询的回答：查询发出去以后它的 socket 被换掉，回答照样到得了；这个查询放手以后旧 socket 关掉
/// A replaced socket still takes the replies to its queries in flight: a query whose socket
/// is replaced after it was sent still gets its reply; once that query lets go the old socket
/// closes
#[tokio::test]
async fn a_query_in_flight_is_answered_after_its_socket_is_replaced() {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream = socket.local_addr().unwrap().to_string();
    let per_socket = UDP_SOCKET_QUERIES as usize;
    // 第一个查询的回答压着，等后面的查询把它的 socket 换掉以后再发 / The first query's reply is held
    // back until the queries after it have had its socket replaced
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let mut held = None;
        for seen in 1..=per_socket + 1 {
            let (n, src) = socket.recv_from(&mut buf).await.unwrap();
            let reply = echo_answer(&buf[..n]);
            if seen == 1 {
                held = Some((reply, src));
                continue;
            }
            socket.send_to(&reply, src).await.unwrap();
            if seen == per_socket + 1
                && let Some((reply, src)) = held.take()
            {
                socket.send_to(&reply, src).await.unwrap();
            }
        }
    });
    let client = UdpClient::new(1).expect("create UDP client");
    let query = udp_test_query("held.example.");
    let mut first = UdpExchange::new(&client, &query, &upstream);
    first.send(()).await.expect("sent");
    for _ in 0..per_socket {
        client
            .send(&query, &upstream, Duration::from_secs(2))
            .await
            .expect("query answered");
    }
    let replaced = client.pool[0].load().socket.local_addr().unwrap();
    let old_socket = Arc::downgrade(&first.sent[0].0._socket.socket);
    assert_ne!(
        old_socket.upgrade().unwrap().local_addr().unwrap(),
        replaced
    );
    let (reply, ()) = timeout(Duration::from_secs(2), first.reply())
        .await
        .expect("answered in time")
        .expect("waited for");
    assert_eq!(
        &reply.expect("answered")[..2],
        &query[..2],
        "original ID restored"
    );

    // 最后一个查询拿到了结果、放了手，接收任务停下，socket 关掉 / Once its last query has its
    // outcome and lets go, the receiving task stops and the socket closes
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        old_socket.upgrade().is_none(),
        "the replaced socket is closed"
    );
}

#[tokio::test]
async fn udp_send_ignores_answer_whose_question_differs() {
    // RFC 5452 §9.1: an answer is only accepted when its question section
    // matches the query; a matching ID and source address are not enough.
    // RFC 5452 §9.1：question 段不匹配的应答必须忽略，ID 和源地址相符不够。
    let (upstream, _seen) =
        spawn_udp_upstream(|query| vec![udp_response_with_question(query, "evil.example.")]).await;
    let client = UdpClient::new(1).expect("create UDP client");
    let err = client
        .send(
            &udp_test_query("id.example."),
            &upstream,
            Duration::from_millis(300),
        )
        .await
        .expect_err("an answer for a different question must not be delivered");
    assert!(
        err.to_string().contains("timeout"),
        "expected the query to time out, got: {err:#}"
    );
}

#[tokio::test]
async fn udp_send_accepts_case_randomized_question() {
    // DNS 0x20 upstreams answer with the query name's case scrambled; the
    // match must ignore ASCII case.
    // 0x20 大小写随机化的应答要能匹配：比较忽略 ASCII 大小写。
    let (upstream, _seen) =
        spawn_udp_upstream(|query| vec![udp_response_with_question(query, "Id.ExAmPlE.")]).await;
    let client = UdpClient::new(1).expect("create UDP client");
    let response = client
        .send(
            &udp_test_query("id.example."),
            &upstream,
            Duration::from_secs(2),
        )
        .await
        .expect("case-scrambled answer must be accepted");
    assert_eq!(&response[0..2], &[0x12, 0x34], "original ID restored");
}

/// EDNS 允许把 UDP 应答协商到 65535 字节。接收缓冲区此前只有 4096 字节，更大的应答被
/// 系统截掉尾部，解析失败，客户端拿到 SERVFAIL；公共 DNS 一般封顶 1232 字节，自建的、
/// 缓冲开得大的上游才会发这么大的应答。
/// EDNS lets a UDP answer be negotiated up to 65535 bytes. The receive buffer
/// used to hold 4096, so a larger answer lost its tail, failed to parse and
/// the client got SERVFAIL; public resolvers usually stop at 1232, but a
/// self-hosted upstream with a larger buffer sends answers this big.
#[tokio::test]
async fn udp_send_receives_an_answer_larger_than_4096_bytes() {
    let (upstream, _) = spawn_udp_upstream(|query| {
        let mut answer = echo_answer(query);
        answer.resize(5_000, 0);
        vec![answer]
    })
    .await;
    let client = UdpClient::new(1).expect("build UDP client");
    let answer = client
        .send(
            &udp_test_query("big.example"),
            &upstream,
            Duration::from_secs(2),
        )
        .await
        .expect("the upstream answers");
    assert_eq!(answer.len(), 5_000, "the whole datagram must arrive");
}

#[tokio::test]
async fn udp_send_accepts_record_less_error_without_question() {
    // Some upstreams answer FORMERR/NOTIMP with QDCOUNT = 0. Such a reply
    // carries nothing cacheable, so it is delivered as the fast failure it
    // is instead of being treated as forged and waited out.
    // 有些上游对 FORMERR/NOTIMP 回 QDCOUNT=0：没有可缓存内容，按快速失败投递，
    // 而不是当作伪造等到超时。
    let (upstream, _seen) = spawn_udp_upstream(|query| {
        let mut header_only = query[..12].to_vec();
        header_only[2] |= 0x80;
        header_only[3] = 0x01; // FORMERR
        header_only[5] = 0; // QDCOUNT = 0
        vec![header_only]
    })
    .await;
    let client = UdpClient::new(1).expect("create UDP client");
    let response = client
        .send(
            &udp_test_query("id.example."),
            &upstream,
            Duration::from_secs(2),
        )
        .await
        .expect("record-less FORMERR must be delivered");
    assert_eq!(response.len(), 12);
    assert_eq!(response[3] & 0x0F, 0x01, "RCODE = FORMERR");
}

#[tokio::test]
async fn udp_send_keeps_waiting_after_mismatched_answer() {
    // A mismatched answer must not consume the in-flight entry: the genuine
    // answer arriving right after it is still delivered.
    // 不匹配的应答不能消耗在途条目：紧随其后的真应答仍被投递。
    let (upstream, _seen) = spawn_udp_upstream(|query| {
        vec![
            udp_response_with_question(query, "evil.example."),
            echo_answer(query),
        ]
    })
    .await;
    let client = UdpClient::new(1).expect("create UDP client");
    let query = udp_test_query("id.example.");
    let response = client
        .send(&query, &upstream, Duration::from_secs(2))
        .await
        .expect("genuine answer after a bogus one must be delivered");
    assert_eq!(
        &response[12..],
        &query[12..],
        "delivered answer is the genuine one"
    );
}

/// 绑定在 `bind` 上、把每个查询置 QR 位后原样回显的 UDP 上游；该地址族不可用时为 None。
/// UDP upstream on `bind` that echoes every query back with QR set, or
/// `None` when the address family is unavailable on this host.
async fn spawn_udp_echo_upstream(bind: &str) -> Option<String> {
    let (addr, _) = spawn_udp_upstream_on(bind, |query| vec![echo_answer(query)]).await?;
    Some(addr)
}

/// v6 池此前无条件预建：默认 udp_pool_size=64 时，哪怕一个 IPv6 上游都没有
/// 也要多占 64 个 socket 和 64 个任务。
/// The v6 pool used to be built unconditionally: with the default
/// udp_pool_size of 64 a deployment without a single IPv6 upstream still
/// paid for 64 sockets and 64 tasks.
#[tokio::test]
async fn udp_ipv6_pool_is_built_only_when_an_ipv6_upstream_is_used() {
    let client = UdpClient::new(4).expect("create UDP client");
    assert!(
        client.pool_v6.get().is_none(),
        "no IPv6 socket may be created before an IPv6 upstream is used"
    );

    let upstream_v4 = spawn_udp_echo_upstream("127.0.0.1:0")
        .await
        .expect("IPv4 loopback");
    let query = [0x12, 0x34, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
    client
        .send(&query, &upstream_v4, Duration::from_secs(2))
        .await
        .expect("IPv4 upstream reachable");
    assert!(
        client.pool_v6.get().is_none(),
        "IPv4 traffic must not build the IPv6 pool"
    );

    let Some(upstream_v6) = spawn_udp_echo_upstream("[::1]:0").await else {
        eprintln!("IPv6 loopback unavailable, skipping the second half");
        return;
    };
    client
        .send(&query, &upstream_v6, Duration::from_secs(2))
        .await
        .expect("IPv6 upstream reachable");
    assert!(
        client.pool_v6.get().is_some(),
        "the IPv6 pool must appear once an IPv6 upstream is used"
    );
}

#[tokio::test]
async fn udp_send_reaches_an_ipv6_upstream() {
    // The pool only ever created AF_INET sockets, so an IPv6 UDP upstream
    // failed every send with "address family not supported" and the query
    // ended in SERVFAIL while the same host over TCP worked.
    // 连接池只建 AF_INET socket：IPv6 UDP 上游每次发送都失败，查询以 SERVFAIL 告终，
    // 而同一主机走 TCP 正常。
    let Some(upstream) = spawn_udp_echo_upstream("[::1]:0").await else {
        eprintln!("IPv6 loopback unavailable, skipping");
        return;
    };
    let client = UdpClient::new(1).expect("create UDP client");
    let query = [0x12, 0x34, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
    let response = client
        .send(&query, &upstream, Duration::from_secs(2))
        .await
        .expect("IPv6 UDP upstream must be reachable");
    assert_eq!(&response[..2], &query[..2], "original ID restored");

    // IPv4 keeps working through the same client.
    let upstream_v4 = spawn_udp_echo_upstream("127.0.0.1:0")
        .await
        .expect("IPv4 loopback");
    client
        .send(&query, &upstream_v4, Duration::from_secs(2))
        .await
        .expect("IPv4 UDP upstream still reachable");
}

/// 接收报 ConnectionReset（Windows 上 ICMP 端口不可达）时马上接着收，不记 warn 以上的日志：每个没人收的查询都有一个，记
/// 下来就是每个查询一条。别的错误记 warn（`warn_sparse`，单元测试里每条都记），歇 100 ms
/// ConnectionReset from a receive (an ICMP port unreachable on Windows) reads on at once and
/// logs nothing at warn or above: every query reaching nobody brings one, which logged would be
/// a line a query. Any other error logs a warn (`warn_sparse`, every one logged in unit tests)
/// and pauses 100 ms
#[test]
fn a_connection_reset_on_receive_reads_on_at_once_and_quietly() {
    use std::io::{Error, ErrorKind};
    let (warnings, _capturing) = crate::engine::test_support::Warnings::capture();
    for _ in 0..3 {
        assert_eq!(
            after_recv_error(0, &Error::from(ErrorKind::ConnectionReset)),
            None
        );
    }
    assert_eq!(warnings.lines(), Vec::<String>::new());
    for kind in [
        ErrorKind::Other,
        ErrorKind::ConnectionRefused,
        ErrorKind::OutOfMemory,
    ] {
        assert_eq!(
            after_recv_error(0, &Error::from(kind)),
            Some(Duration::from_millis(100)),
            "{kind:?}"
        );
    }
    let lines = warnings.lines();
    assert_eq!(lines.len(), 3, "{lines:?}");
    assert!(lines.iter().all(|line| line.contains("WARN")), "{lines:?}");
}

/// 查询超时以后，它在 UDP socket 的 inflight 表里的那一条已经删掉（TCP 的 pending 表见 `stream_tests`）
/// Once a query times out, its entry is gone from the UDP socket's inflight map (the TCP
/// connection's pending map is in `stream_tests`)
#[tokio::test]
async fn a_timed_out_query_leaves_no_entry_behind() {
    // 收下查询、从不回答的本机上游 / A local upstream that takes queries and never answers
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_addr = udp.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        while udp.recv_from(&mut buf).await.is_ok() {}
    });

    let client = UdpClient::new(2).expect("udp client");
    let result = client
        .send(
            &udp_test_query("a.example"),
            &udp_addr,
            Duration::from_millis(100),
        )
        .await;
    assert!(result.is_err(), "the upstream never answers");
    assert!(
        client
            .pool
            .iter()
            .all(|socket| socket.load().inflight.is_empty())
    );
}
