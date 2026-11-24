//! DoH 客户端的测试 / Tests of the DoH client

use super::*;
use crate::engine::bootstrap::Bootstrap;
use crate::engine::test_support::{DohReply, http_ok, spawn_doh_upstream};
use crate::engine::transport::connect::{KEEPALIVE_INTERVAL, KEEPALIVE_TIME};
use crate::engine::transport::test_support::*;
use bytes::Bytes;
use reqwest::Client as DohHttpClient;
use reqwest::header::HeaderValue;
use socket2::SockRef;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

/// README 与 config.rs 都写明阈值 0 表示禁用健康检查，而 `count >= threshold`
/// 会让 0 变成"每次错误都重建连接池"，正好相反。
/// README and config.rs both state that a threshold of 0 disables the health
/// check, while `count >= threshold` turns 0 into a rebuild on every single
/// error, the exact opposite.
#[test]
fn doh_record_error_treats_a_zero_threshold_as_disabled() {
    let client = DohClient::new(8, 0, Bootstrap::system()).expect("build doh client");
    let upstream = "doh://8.8.8.8";
    let ptr_before = Arc::as_ptr(&client.upstream(upstream).unwrap().client.load_full()) as usize;

    for attempt in 1..=5 {
        assert!(
            !client.record_error_of(upstream),
            "a disabled health check must never rebuild (error {attempt})"
        );
    }
    assert_eq!(
        Arc::as_ptr(&client.upstream(upstream).unwrap().client.load_full()) as usize,
        ptr_before,
        "the connection pool must survive a disabled health check"
    );
}

/// 热重载换掉的上游此前会一直留着自己的连接池；现在长期不用的条目会被清掉。
/// Upstreams a reload replaced used to keep their connection pools forever;
/// entries nothing has used are now dropped.
#[test]
fn doh_prunes_upstreams_nothing_has_used() {
    let client = DohClient::new(8, 3, Bootstrap::system()).expect("build doh client");
    for idx in 0..4 {
        client
            .upstream(&format!("https://{idx}.example/dns-query"))
            .expect("create upstream");
    }
    let live = "https://live.example/dns-query";
    client.upstream(live).expect("create live upstream");
    let now = age_out_idle_upstreams(&client, live);

    client
        .upstream_at("https://new.example/dns-query", now)
        .expect("create upstream");

    assert!(
        client.upstreams.len() <= 2,
        "idle upstreams must be pruned, {} left",
        client.upstreams.len()
    );
    assert!(
        client.upstreams.contains_key(live),
        "an upstream in use must never be pruned"
    );
}

/// 热重载换掉整批上游之后可能再没有新上游出现，此前清理只挂在新键插入上，
/// 旧条目会留到进程结束；现在查一次已有上游也会触发清理。
/// A reload can swap the whole upstream set and no new upstream ever follows;
/// pruning used to hang off new-key inserts alone, so the old entries lived
/// until the process exited. A lookup of an existing upstream now prunes too.
#[test]
fn doh_prunes_idle_upstreams_without_new_keys() {
    let client = DohClient::new(8, 3, Bootstrap::system()).expect("build doh client");
    for idx in 0..4 {
        client
            .upstream(&format!("https://{idx}.example/dns-query"))
            .expect("create upstream");
    }
    let live = "https://live.example/dns-query";
    client.upstream(live).expect("create live upstream");
    let now = age_out_idle_upstreams(&client, live);

    // 只重复查询已有上游，不插入任何新键
    // Only look the existing upstream up again; no new key is inserted
    client
        .upstream_at(live, now)
        .expect("look up live upstream");

    assert!(
        client.upstreams.len() <= 2,
        "idle upstreams must be pruned without a new key, {} left",
        client.upstreams.len()
    );
    assert!(
        client.upstreams.contains_key(live),
        "an upstream in use must never be pruned"
    );
}

/// 节流窗口过期、但这一轮没有任何条目可清时，时间戳同样要推后；否则每一次
/// 查询都会重新走到扫描前的检查上——正常配置的上游数很少，这条路径原先永远
/// 命中，等于每个 DoH 查询白付一次全分片的 DashMap::len()。
/// When the interval has lapsed but the round drops nothing, the timestamp
/// must still move. Otherwise every later lookup walks back into the check
/// before the scan, and since a normal deployment has only a handful of
/// upstreams that used to happen on every single DoH query.
#[test]
fn doh_prune_round_is_claimed_even_when_nothing_expires() {
    let client = DohClient::new(8, 3, Bootstrap::system()).expect("build doh client");
    let live = "https://live.example/dns-query";
    client.upstream(live).expect("create upstream");

    // 窗口过期，但条目都是刚用过的 / interval lapsed, every entry just used
    let lapsed = client.millis_since_epoch() + DOH_UPSTREAM_PRUNE_EVERY.as_millis() as u64 * 2;
    client.upstream_at(live, lapsed).expect("look up upstream");

    assert_eq!(
        client.last_prune_millis.load(Ordering::Relaxed),
        lapsed,
        "a lapsed interval must be claimed even when nothing is dropped"
    );
    assert!(
        client.upstreams.contains_key(live),
        "an upstream in use must never be pruned"
    );
}

/// 往后看一段：除 `live` 之外的条目都长期未使用，节流窗口也过期了，给出那时的 `now`（见 `DohClient::upstream_at`）
/// A look ahead: every entry but `live` has long gone unused and the prune interval has lapsed,
/// giving the `now` of then (see `DohClient::upstream_at`)
fn age_out_idle_upstreams(client: &DohClient, live: &str) -> u64 {
    let now = client.millis_since_epoch() + DOH_UPSTREAM_IDLE.as_millis() as u64 * 2;
    client
        .upstreams
        .get(live)
        .expect("the live upstream")
        .last_used_millis
        .store(now, Ordering::Relaxed);
    now
}

/// 同一代开始的请求一起断掉、一起报错，只重建一次；旧连接上迟到的错误不算，新的一代从头数。以前每数到阈值就重建
/// 一次，一百个一起报错要重建三十三次
/// Requests started under one generation, broken together and erring together, rebuild
/// once; errors arriving late from the old connections do not count, and the new generation
/// counts from scratch. Every count up to the threshold used to rebuild, thirty-three
/// rebuilds for a hundred erring together
#[test]
fn requests_broken_together_rebuild_once() {
    let client = DohClient::new(8, 3, Bootstrap::system()).expect("build doh client");
    let upstream = "doh://8.8.8.8";
    let state = client.upstream(upstream).unwrap();
    let started = state.generation.load(Ordering::Acquire);
    let before = state.client.load_full();
    let rebuilds = (0..100)
        .filter(|_| client.record_error(upstream, &state, started))
        .count();
    assert_eq!(rebuilds, 1);
    assert!(!Arc::ptr_eq(&before, &state.client.load_full()));
    assert!(!client.record_error_of(upstream));
    assert!(!client.record_error_of(upstream));
    assert!(
        client.record_error_of(upstream),
        "the third error of the new generation"
    );
}

#[test]
fn doh_record_error_rebuilds_pool_at_threshold() {
    // Verify the core self-healing contract: consecutive transport errors below
    // the threshold accumulate without rebuilding; reaching it rebuilds the pool
    // (a fresh reqwest::Client is the only way to evict dead/half-open connections
    // that reqwest cannot detect on its own).
    // 验证核心自愈契约：连续传输错误在阈值前累积不重建；
    // 达阈值时重建连接池（新 reqwest::Client 是清除 reqwest 自身无法检测的
    // 死/半开连接的唯一手段）。
    let client = DohClient::new(8, 3, Bootstrap::system()).expect("build doh client");
    let upstream = "doh://8.8.8.8";

    let ptr_before = Arc::as_ptr(&client.upstream(upstream).unwrap().client.load_full()) as usize;
    // Two errors stay below the threshold (3): no rebuild.
    assert!(
        !client.record_error_of(upstream),
        "no rebuild before threshold (1/3)"
    );
    assert!(
        !client.record_error_of(upstream),
        "no rebuild before threshold (2/3)"
    );
    assert_eq!(
        Arc::as_ptr(&client.upstream(upstream).unwrap().client.load_full()) as usize,
        ptr_before,
        "client pointer must be unchanged below threshold"
    );
    // Third error reaches the threshold: pool rebuilt.
    assert!(
        client.record_error_of(upstream),
        "rebuild at threshold (3/3)"
    );
    assert_ne!(
        Arc::as_ptr(&client.upstream(upstream).unwrap().client.load_full()) as usize,
        ptr_before,
        "client pointer must change after rebuild"
    );
}

#[test]
fn doh_rebuild_is_scoped_to_the_failing_upstream() {
    // A single reqwest client used to be shared by every DoH upstream, so
    // reaching the error threshold on one upstream replaced the pool of all
    // of them: the healthy upstream lost its keep-alive connections and had
    // to handshake again. Each upstream now owns its client.
    // 以前所有 DoH 上游共用一个 reqwest 客户端，一个上游达到错误阈值会把所有
    // 上游的连接池一起换掉，健康上游丢失 keep-alive 连接、被迫重新握手。
    // 现在每个上游各持一个客户端。
    let client = DohClient::new(8, 3, Bootstrap::system()).expect("build doh client");
    let healthy = "doh://1.1.1.1";
    let failing = "doh://bad.example";
    let healthy_before =
        Arc::as_ptr(&client.upstream(healthy).unwrap().client.load_full()) as usize;
    let failing_before =
        Arc::as_ptr(&client.upstream(failing).unwrap().client.load_full()) as usize;

    for _ in 0..2 {
        assert!(!client.record_error_of(failing));
    }
    assert!(client.record_error_of(failing), "third error rebuilds");

    assert_ne!(
        Arc::as_ptr(&client.upstream(failing).unwrap().client.load_full()) as usize,
        failing_before,
        "the failing upstream's pool is rebuilt"
    );
    assert_eq!(
        Arc::as_ptr(&client.upstream(healthy).unwrap().client.load_full()) as usize,
        healthy_before,
        "the healthy upstream keeps its pool"
    );
}

#[test]
fn doh_record_success_resets_counter() {
    // record_success clears the per-upstream counter so a transient blip does
    // not accumulate toward a rebuild across an intervening healthy request.
    // record_success 清零 per-upstream 计数，避免偶发错误跨健康请求累积到重建。
    let client = DohClient::new(8, 3, Bootstrap::system()).expect("build doh client");
    let upstream = "doh://1.1.1.1";

    client.record_error_of(upstream);
    client.record_error_of(upstream);
    client.record_success(upstream); // reset to 0
    // Counter restarted: need 3 more to rebuild, not just 1.
    assert!(
        !client.record_error_of(upstream),
        "counter reset: 1/3 after success"
    );
    assert!(
        !client.record_error_of(upstream),
        "counter reset: 2/3 after success"
    );
    assert!(
        client.record_error_of(upstream),
        "counter reset: rebuild at 3/3"
    );
}

#[test]
fn doh_error_counts_are_isolated_per_upstream() {
    // Mirrors mux clients' per-upstream consecutive_errors isolation: errors on
    // one upstream must not inflate another upstream's count.
    // 对齐 mux 的 per-upstream consecutive_errors 隔离：
    // 一个 upstream 的错误不得累加到另一个 upstream。
    let client = DohClient::new(8, 3, Bootstrap::system()).expect("build doh client");

    client.record_error_of("doh://8.8.8.8");
    client.record_error_of("doh://8.8.8.8");
    // A success on a *different* upstream must not touch 8.8.8.8's count.
    client.record_success("doh://1.1.1.1");
    // 8.8.8.8 still at 2 — the 3rd error rebuilds.
    assert!(
        client.record_error_of("doh://8.8.8.8"),
        "isolated counter reaches threshold independently"
    );
}

#[test]
fn doh_is_transport_error_classifies_correctly() {
    // Only unusable answers are non-transport (connection is healthy, retry is
    // useless). Everything else (timeout / connect / IO) indicates a possibly
    // dead connection and is safe to retry once (DoH queries are idempotent).
    // 只有用不了的回答是非传输的（连接健康，重试无益）。
    // 其余（超时/连接/IO）都指示连接可能已死，单次重试安全（DoH 查询语义幂等）。
    let timeout_err = anyhow::anyhow!("doh request timeout");
    assert!(
        is_transport_error(&timeout_err),
        "timeout is transport-level"
    );

    // A reqwest-style error wrapped via .context() must still classify as
    // transport (downcast finds no DohAnswerError at the top of the chain).
    // 经 .context() 包装的 reqwest 风格错误仍须归类为传输错误
    // （downcast 在链顶找不到 DohAnswerError）。
    let send_err = anyhow::anyhow!("doh request send failed").context("wrapped");
    assert!(
        is_transport_error(&send_err),
        "wrapped send error is transport-level"
    );

    let status_err = doh_answer_error("doh http status 503 Server Error".to_string());
    assert!(
        !is_transport_error(&status_err),
        "HTTP status is NOT transport-level"
    );

    // 没连上也不是：没有建好的连接可换 / Nor is no connection: there is none made to replace
    let not_connected = anyhow::anyhow!("doh tls handshake failed").context(DohNotConnected);
    assert!(
        !is_transport_error(&not_connected),
        "no connection is NOT transport-level"
    );
}

/// 没连上 DoH 上游（这里是 TLS 握手时连接就被关掉），直连和经 reqwest 都一样：不重发，也不算进重建连接池的门槛，没有
/// 建好的连接可换。以前都算，门槛是 1 时每个请求都要重建一次连接池，经 reqwest 的还要再连一次
/// No connection to the DoH upstream (here closed during the TLS handshake), directly or
/// through reqwest alike: it is not sent again and does not count toward rebuilding the pool,
/// there being no connection made to replace. Both used to count, so with a threshold of 1
/// every request rebuilt the pool, and through reqwest connected once more
#[tokio::test]
async fn a_failed_doh_connect_is_neither_sent_again_nor_counted() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = format!("https://{}/dns-query", listener.local_addr().unwrap());
    let accepted = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&accepted);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            counted.fetch_add(1, Ordering::Relaxed);
            drop(stream);
        }
    });
    for direct in [true, false] {
        let mut client = DohClient::new(8, 1, Bootstrap::system()).expect("build doh client");
        if !direct {
            client.reqwest_only_for_tests();
        }
        let before = accepted.load(Ordering::Relaxed);
        client
            .send(&doh_test_query("closed"), &upstream, Duration::from_secs(2))
            .await
            .expect_err("no connection");
        assert_eq!(
            accepted.load(Ordering::Relaxed) - before,
            1,
            "connected once (direct = {direct})"
        );
        let state = client.upstreams.get(upstream.as_str()).expect("state");
        assert_eq!(
            state.generation.load(Ordering::Acquire),
            0,
            "the pool is not rebuilt (direct = {direct})"
        );
    }
}

/// 经 reqwest 的 DoH 连接和别的 TCP 连接一样保活（见 [`KEEPALIVE_TIME`]）：连上以后到这个进程里找出那条连接的
/// socket，读它的保活设置
/// A DoH connection through reqwest keeps alive as every other TCP connection does (see
/// [`KEEPALIVE_TIME`]): once it is made, its socket is found in this process and its keepalive
/// read
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn a_reqwest_connection_keeps_alive_as_the_others_do() {
    let (addr, _) = spawn_doh_upstream(|_, query| {
        DohReply::Raw(http_ok(Some(DOH_MEDIA_TYPE), &echo_answer(query)))
    })
    .await;
    let mut client = DohClient::new(8, 3, Bootstrap::system()).expect("build doh client");
    client.reqwest_only_for_tests();
    let upstream = format!("http://{addr}/dns-query");
    client
        .send(&doh_test_query("kept"), &upstream, Duration::from_secs(2))
        .await
        .expect("the upstream answers");
    assert_eq!(
        tcp_keepalive_towards(addr),
        Some((KEEPALIVE_TIME, KEEPALIVE_INTERVAL))
    );
}

/// 这个进程里连到 `peer` 的那条 TCP 连接的保活：多久没有收发开始探、隔多久探一次 / The keepalive of
/// this process's TCP connection to `peer`: how long without traffic before probing, and how far
/// apart the probes are
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn tcp_keepalive_towards(peer: SocketAddr) -> Option<(Duration, Duration)> {
    use std::os::fd::{AsRawFd, BorrowedFd};
    #[cfg(target_os = "macos")]
    const IDLE: libc::c_int = libc::TCP_KEEPALIVE;
    #[cfg(target_os = "linux")]
    const IDLE: libc::c_int = libc::TCP_KEEPIDLE;
    let seconds = |fd: &BorrowedFd<'_>, option| {
        let (mut value, mut len) = (
            0 as libc::c_int,
            size_of::<libc::c_int>() as libc::socklen_t,
        );
        // SAFETY: 只读一个整数选项，写进这里的 `value`；`fd` 不是 socket 时调用失败 / Reads an
        // integer option into `value` here alone; on an `fd` that is no socket the call fails
        let read = unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::IPPROTO_TCP,
                option,
                (&raw mut value).cast(),
                &raw mut len,
            )
        };
        (read == 0).then(|| Duration::from_secs(value as u64))
    };
    (0..4096).find_map(|raw| {
        // SAFETY: 只在下面几次调用里借用；没打开的描述符让它们失败 / Borrowed for the calls below
        // only; a descriptor not open makes them fail
        let fd = unsafe { BorrowedFd::borrow_raw(raw) };
        let to = SockRef::from(&fd).peer_addr().ok()?.as_socket()?;
        (to == peer).then(|| Some((seconds(&fd, IDLE)?, seconds(&fd, libc::TCP_KEEPINTVL)?)))?
    })
}

#[tokio::test]
async fn reqwest_client_drop_closes_pooled_connections() {
    // Empirical foundation of DohClient's pool-rebuild healing: dropping a
    // reqwest::Client closes the keep-alive connections held in its pool. If
    // this did not hold, rebuilding the client (store a fresh Arc<Client>)
    // could NOT evict dead/half-open connections and issue #41 would persist.
    // DohClient 连接池重建自愈的实证基础：drop reqwest::Client 会关闭其连接池中
    // 的 keep-alive 连接。若不成立，重建客户端（store 新 Arc<Client>）无法驱逐
    // 死/半开连接，issue #41 将无法解决。
    // Minimal HTTP/1.1 keep-alive server: serve one request, then block reading
    // until the peer closes the connection.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test listener");
    let addr = listener.local_addr().expect("read test addr");

    let server_task = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("accept");
        let mut buf = vec![0u8; 1024];
        let _ = sock.read(&mut buf).await; // read request
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok";
        sock.write_all(resp).await.expect("write response");
        // Block until peer closes; Ok(0) = clean EOF (connection closed by client).
        loop {
            match sock.read(&mut buf).await {
                Ok(0) => return true,
                Ok(_) => continue,
                Err(_) => return false,
            }
        }
    });

    let url = format!("http://{addr}/");
    {
        // Long idle timeout so only an explicit Client drop can close the
        // connection within the test window (not the idle reaper).
        // 长 idle 超时，确保测试窗口内只有显式 drop Client 能关闭连接（而非 idle 回收）。
        let client = DohHttpClient::builder()
            .pool_idle_timeout(Duration::from_secs(60))
            .build()
            .expect("build client");
        let resp = client.get(&url).send().await.expect("send");
        assert!(resp.status().is_success());
        drop(resp.bytes().await.expect("read body")); // drain → connection returns to pool
        // client dropped at end of this block → pool torn down
    }

    // pool_idle_timeout is 60s; if the drop did not close the connection the
    // server would only observe EOF after ~60s. A 5s window therefore proves
    // the closure was caused by the drop.
    // pool_idle_timeout 为 60s；若 drop 未关闭连接，server 要等约 60s 才观察到 EOF。
    // 5s 窗口因此证明关闭由 drop 引起。
    let joined = tokio::time::timeout(Duration::from_secs(5), server_task)
        .await
        .expect("server did not observe close within 5s of drop; pool_idle_timeout=60s means only the drop could close it");
    let clean_eof = joined.expect("server task join");
    assert!(
        clean_eof,
        "server saw an error instead of clean EOF on Client drop"
    );
}

/// 上游 DoH 回 ID 0 时，DoH 客户端交回去的仍是查询自己的 ID，和其他传输一样。直接
/// 转发、回答后跳转再转发、后台刷新都经过这里；以前这里把 0 原样交出，客户端把响应
/// 当成别人的丢掉，等到超时重试才从缓存拿到答案。
/// When a DoH upstream answers with ID 0 the DoH client still hands back the query's
/// own ID, like every other transport. Direct forwards, forwards after a response jump
/// and background refreshes all go through here; it used to pass the 0 on, and the
/// client discarded the reply as someone else's until a retry was answered from cache.
#[tokio::test]
async fn doh_upstream_answering_with_id_zero_keeps_the_query_id() {
    for drop_first in [false, true] {
        // 不管收到什么 ID 都回 0 的上游（RFC 8484 允许这样做）：把查询原样回过去，ID 写成 0、
        // 标上 QR。`drop_first` 时第一个请求读完就断开、不回答，让客户端走重试那条路。
        // An upstream answering with ID 0 whatever it receives (RFC 8484 allows it): it
        // echoes the query with the ID set to 0 and QR set. With `drop_first` the first
        // request is read and its connection closed without an answer, which sends the
        // client down its retry.
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let record = Arc::clone(&seen);
        let dropped = AtomicBool::new(!drop_first);
        let (addr, _) = spawn_doh_upstream(move |_, query| {
            if !dropped.swap(true, Ordering::SeqCst) {
                return DohReply::Close;
            }
            record
                .lock()
                .unwrap()
                .push(u16::from_be_bytes([query[0], query[1]]));
            let mut answer = echo_answer(query);
            answer[..2].copy_from_slice(&[0, 0]);
            DohReply::Raw(http_ok(Some(DOH_MEDIA_TYPE), &answer))
        })
        .await;
        let upstream = format!("http://{addr}/dns-query");
        let client = DohClient::new(8, 0, Bootstrap::system()).expect("build doh client");
        for id in [0xBEEF_u16, 0xCAFE] {
            let mut query = vec![0u8; 12];
            query[..2].copy_from_slice(&id.to_be_bytes());
            query[2] = 0x01; // RD
            query[5] = 1; // QDCOUNT
            query.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
            let response = timeout(
                Duration::from_secs(10),
                client.send(&query, &upstream, Duration::from_secs(5)),
            )
            .await
            .expect("no hang")
            .expect("doh answer");

            assert_eq!(
                &response[..2],
                &id.to_be_bytes(),
                "the query's own ID comes back"
            );
            assert_eq!(response[2] & 0x80, 0x80, "the rest is the server's reply");
            assert_eq!(&response[12..], &query[12..], "the question is untouched");
        }
        // 第一个请求被断开时，重试那一次也是带着自己的 ID 出去、换回来的
        // When the first request was cut off, the retry also left with its own ID and got it back
        assert_eq!(
            *seen.lock().unwrap(),
            vec![0xBEEF, 0xCAFE],
            "queries leave with their own IDs (drop_first = {drop_first})"
        );
    }
}

/// 问 `label.test` 的 A 记录 / An A query for `label.test`
fn doh_test_query(label: &str) -> Vec<u8> {
    let mut query = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    query.push(label.len() as u8);
    query.extend_from_slice(label.as_bytes());
    query.extend_from_slice(b"\x04test\x00\x00\x01\x00\x01");
    query
}

/// 一个回答最多一条 DNS 消息那么长。此前正文有多长就收多长：服务器不停往回发时，一个查询几秒内
/// 就能占掉几个 GB，一直到超时。
/// An answer is at most one DNS message long. The body used to be taken whole:
/// with a server sending without end, one query took gigabytes within seconds,
/// until it timed out.
#[tokio::test]
async fn doh_refuses_an_answer_longer_than_a_dns_message() {
    let (addr, _) = spawn_doh_upstream(|_, query| {
        let mut answer = echo_answer(query);
        match &query[13..17] {
            b"full" => answer.resize(MAX_DNS_MESSAGE_SIZE, 0),
            b"over" => answer.resize(MAX_DNS_MESSAGE_SIZE + 1, 0),
            _ => return DohReply::Endless,
        }
        DohReply::Raw(http_ok(Some(DOH_MEDIA_TYPE), &answer))
    })
    .await;
    let upstream = format!("http://{addr}/dns-query");
    let client = DohClient::new(8, 0, Bootstrap::system()).expect("build doh client");

    // 正好一条最长的 DNS 消息：照收，分几块到也拼得回来
    // Exactly one longest DNS message: taken, put back together from its pieces
    let query = doh_test_query("full");
    let answer = client
        .send(&query, &upstream, Duration::from_secs(5))
        .await
        .expect("a 65535-byte answer is an answer");
    assert_eq!(answer.len(), MAX_DNS_MESSAGE_SIZE);
    assert_eq!(&answer[..query.len()], &echo_answer(&query)[..]);

    for label in ["over", "more"] {
        let start = tokio::time::Instant::now();
        let err = client
            .send(&doh_test_query(label), &upstream, Duration::from_secs(5))
            .await
            .expect_err("longer than a DNS message");
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "{label}: refused as soon as it is too long, not at the timeout"
        );
        assert!(
            !is_transport_error(&err),
            "{label}: the server answered, a retry would get the same: {err:#}"
        );
    }
}

/// 回答必须是 DNS 消息的媒体类型。此前强制门户或出错的代理回的网页也被当成回答交出去。
/// An answer has to carry the DNS message media type. A web page from a captive
/// portal or a broken proxy used to be handed on as an answer.
#[tokio::test]
async fn doh_refuses_an_answer_of_another_media_type() {
    let (addr, _) = spawn_doh_upstream(|_, query| {
        let media_type = match &query[13..17] {
            b"html" => Some("text/html"),
            b"none" => None,
            b"case" => Some("Application/DNS-Message"),
            _ => Some("application/dns-message; charset=binary"),
        };
        DohReply::Raw(http_ok(media_type, &echo_answer(query)))
    })
    .await;
    let upstream = format!("http://{addr}/dns-query");
    let client = DohClient::new(8, 0, Bootstrap::system()).expect("build doh client");
    for label in ["html", "none"] {
        let err = client
            .send(&doh_test_query(label), &upstream, Duration::from_secs(5))
            .await
            .expect_err("not a DNS message");
        assert!(!is_transport_error(&err), "{label}: no retry: {err:#}");
    }
    // 媒体类型不分大小写，参数不管 / Media types ignore case, and parameters do not matter
    for label in ["case", "parm"] {
        client
            .send(&doh_test_query(label), &upstream, Duration::from_secs(5))
            .await
            .unwrap_or_else(|err| panic!("{label}: a DNS message: {err:#}"));
    }
}

/// DoH 客户端不跟随跳转：服务器没有理由跳转，跟着跳可能把查询发到别处，包括明文 HTTP。
/// The DoH client follows no redirect: a server has no reason to send one, and
/// following it could take the query elsewhere, plain HTTP included.
#[tokio::test]
async fn doh_does_not_follow_redirects() {
    let (addr, paths) = spawn_doh_upstream(|path, query| {
        if path == "/dns-query" {
            DohReply::Raw(
                b"HTTP/1.1 307 Temporary Redirect\r\nlocation: /elsewhere\r\ncontent-length: 0\r\n\r\n"
                    .to_vec(),
            )
        } else {
            DohReply::Raw(http_ok(Some(DOH_MEDIA_TYPE), &echo_answer(query)))
        }
    })
    .await;
    let client = DohClient::new(8, 0, Bootstrap::system()).expect("build doh client");
    let err = client
        .send(
            &doh_test_query("move"),
            &format!("http://{addr}/dns-query"),
            Duration::from_secs(5),
        )
        .await
        .expect_err("a redirect is not an answer");
    assert!(!is_transport_error(&err), "no retry: {err:#}");
    assert_eq!(*paths.lock().unwrap(), vec!["/dns-query".to_string()]);
}

/// DoH 上一个查询只有一个回答：答的是别的问题就算失败，不交出去，也不重试。
/// Over DoH a query gets a single answer: one to another question fails the
/// query instead of being handed on, with no retry.
#[tokio::test]
async fn a_doh_answer_to_another_question_fails_the_query() {
    let (addr, paths) = spawn_doh_upstream(|_, query| {
        DohReply::Raw(http_ok(
            Some(DOH_MEDIA_TYPE),
            &udp_response_with_question(query, "other.example"),
        ))
    })
    .await;
    let client = DohClient::new(8, 0, Bootstrap::system()).expect("build doh client");
    let err = client
        .send(
            &udp_test_query("swap.example"),
            &format!("http://{addr}/dns-query"),
            Duration::from_secs(2),
        )
        .await
        .expect_err("an answer to another question");
    assert!(!is_transport_error(&err), "no retry: {err:#}");
    assert_eq!(paths.lock().unwrap().len(), 1);
}

/// Retry-After 按秒数读，收进 1 到 60 秒：0 算 1 秒，超过 60 的、大得装不下的都算 60 秒；没写、
/// 写的是 HTTP 日期或读不懂时 1 秒，也不算照 Retry-After 定的
/// Retry-After is read as seconds and brought into 1 to 60: 0 counts as 1, anything
/// above 60 or too large to hold as 60; without one, or with an HTTP date or anything
/// unreadable, 1 second, not counted as set by Retry-After
#[test]
fn a_429_pauses_for_retry_after_seconds_within_one_to_sixty() {
    let pause = |value: Option<&'static str>| {
        let throttle = throttle_after(value.map(HeaderValue::from_static).as_ref());
        (throttle.pause, throttle.from_retry_after)
    };
    let seconds = Duration::from_secs;
    assert_eq!(pause(None), (seconds(1), false));
    assert_eq!(pause(Some("30")), (seconds(30), true));
    assert_eq!(pause(Some("1")), (seconds(1), true));
    assert_eq!(pause(Some("60")), (seconds(60), true));
    assert_eq!(pause(Some("0")), (seconds(1), true));
    assert_eq!(pause(Some("61")), (seconds(60), true));
    assert_eq!(pause(Some("120")), (seconds(60), true));
    assert_eq!(pause(Some("99999999999999999999999")), (seconds(60), true));
    for unreadable in [
        "Wed, 21 Oct 2026 07:28:00 GMT",
        "soon",
        "-5",
        "2.5",
        "1e3",
        "",
    ] {
        assert_eq!(
            pause(Some(unreadable)),
            (seconds(1), false),
            "{unreadable:?}"
        );
    }
}

/// 429 不重试，也不算一次传输错误，连接池不重建；这个上游从现在起照 Retry-After 暂停。错误原文和
/// 别的错误状态一样
/// A 429 is not retried and is no transport error, so the pool is not rebuilt; the
/// upstream pauses from now for what Retry-After says. The error text is as for any
/// other error status
#[tokio::test]
async fn a_429_is_not_retried_and_pauses_its_upstream() {
    let (addr, paths) = spawn_doh_upstream(|_, _| {
        DohReply::Raw(
            b"HTTP/1.1 429 Too Many Requests\r\ncontent-type: text/html\r\nretry-after: 120\r\ncontent-length: 0\r\n\r\n"
                .to_vec(),
        )
    })
    .await;
    let upstream = format!("http://{addr}/dns-query");
    // 阈值 1：记一次传输错误就会重建 / Threshold 1: a single transport error would rebuild
    let client = DohClient::new(8, 1, Bootstrap::system()).expect("build doh client");
    assert!(!client.any_paused());
    let state = client.upstream(&upstream).expect("doh upstream state");
    let pool = Arc::as_ptr(&state.client.load_full());

    let err = client
        .send(&doh_test_query("slow"), &upstream, Duration::from_secs(5))
        .await
        .expect_err("a 429 is no answer");
    assert_eq!(format!("{err:#}"), "doh http status 429 Too Many Requests");
    assert!(!is_transport_error(&err), "no retry: {err:#}");
    assert_eq!(paths.lock().unwrap().len(), 1, "sent once");
    assert_eq!(state.consecutive_errors.load(Ordering::Acquire), 0);
    assert_eq!(
        Arc::as_ptr(&state.client.load_full()),
        pool,
        "the pool is kept"
    );

    assert_eq!(
        throttle_of(&err).map(|throttle| throttle.pause),
        Some(Duration::from_secs(60)),
        "Retry-After 120 brought down to 60"
    );
    assert!(client.any_paused());
    assert!(client.is_paused(&upstream));
    assert!(!client.is_paused("other.example/dns-query"));
    let left = state
        .paused_until
        .load(Ordering::Relaxed)
        .saturating_sub(client.millis_since_epoch());
    assert!((59_000..=60_000).contains(&left), "{left} ms left");
}

/// 几个 429 同时回来：暂停只往后推，不往前拉；只有暂停开始那一次记 warn，带上游、秒数和是不是照
/// Retry-After
/// Several 429s at once: a pause only moves later, never earlier; only its start logs a
/// warn, with the upstream, the seconds and whether Retry-After set them
#[test]
fn concurrent_429s_only_move_a_pause_later_and_warn_once() {
    let client = DohClient::new(8, 0, Bootstrap::system()).expect("build doh client");
    let upstream = "doh.example/dns-query";
    let state = client.upstream(upstream).expect("doh upstream state");
    let throttle = |seconds, from_retry_after| Throttle {
        pause: Duration::from_secs(seconds),
        from_retry_after,
    };
    let (warnings, guard) = crate::engine::test_support::Warnings::capture();
    client.pause(upstream, &state, throttle(5, true));
    let until = state.paused_until.load(Ordering::Relaxed);
    client.pause(upstream, &state, throttle(1, false));
    assert_eq!(
        state.paused_until.load(Ordering::Relaxed),
        until,
        "a shorter pause does not cut it short"
    );
    client.pause(upstream, &state, throttle(10, true));
    assert!(state.paused_until.load(Ordering::Relaxed) > until);
    drop(guard);

    let lines = warnings.lines();
    assert_eq!(lines.len(), 1, "{lines:#?}");
    for field in [
        "upstream=\"doh.example/dns-query\"",
        "pause_secs=5",
        "retry_after=true",
    ] {
        assert!(lines[0].contains(field), "{field} in {}", lines[0]);
    }
}

/// 暂停到期以后上游又能问了，`any_paused` 也清回 0，之后的检查连时钟都不读
/// Once a pause ends the upstream can be asked again, and `any_paused` clears back to 0,
/// so later checks read no clock
#[test]
fn a_pause_ends_on_time_and_the_shared_gate_clears() {
    let client = DohClient::new(8, 0, Bootstrap::system()).expect("build doh client");
    let upstream = "doh.example/dns-query";
    let state = client.upstream(upstream).expect("doh upstream state");
    client.pause(
        upstream,
        &state,
        Throttle {
            pause: Duration::from_secs(1),
            from_retry_after: false,
        },
    );
    assert!(client.any_paused());
    assert!(client.is_paused(upstream));
    std::thread::sleep(Duration::from_millis(1_100));
    assert!(!client.is_paused(upstream));
    assert!(!client.any_paused());
    assert_eq!(client.latest_pause_end.load(Ordering::Relaxed), 0);
}

#[test]
fn doh_response_gets_the_query_id_back() {
    let query = [0x12, 0x34, 0x01, 0x00];
    // 服务端回 0：换回查询的 ID，其余字节不动 / The server answered 0: the query's ID goes back, the rest is untouched
    let restored = restore_query_id(&query, Bytes::from_static(&[0x00, 0x00, 0x81, 0x80, 0x00]));
    assert_eq!(restored.as_ref(), &[0x12, 0x34, 0x81, 0x80, 0x00]);
    // 已经一致：原样返回，不复制 / Already matching: returned as is, not copied
    let echoed = Bytes::from_static(&[0x12, 0x34, 0x81, 0x80]);
    let pointer = echoed.as_ptr();
    assert_eq!(restore_query_id(&query, echoed).as_ptr(), pointer);
    // 太短的包没有 ID 可换 / A packet too short to carry an ID is left alone
    assert_eq!(
        restore_query_id(&query, Bytes::from_static(&[0x00])).as_ref(),
        &[0x00]
    );
    assert_eq!(
        restore_query_id(&[0x12], Bytes::from_static(&[0x00, 0x00])).as_ref(),
        &[0x00, 0x00]
    );
}
