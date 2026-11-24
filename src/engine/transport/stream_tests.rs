//! TCP 和 DoT 的测试 / Tests of TCP and DoT

use super::*;
use crate::engine::bootstrap::Bootstrap;
use crate::engine::transport::connect::{Aging, CONNECT_BACKOFF, Wear, build_tls_client_config};
use crate::engine::transport::test_support::*;
use bytes::Bytes;
use dashmap::DashMap;
use futures::future::join_all;
use rustc_hash::FxBuildHasher;
use socket2::{Domain, Socket, Type};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

/// 远在任何测试结束之后的期限 / A deadline far past the end of any test
fn far_off() -> tokio::time::Instant {
    tokio::time::Instant::now() + Duration::from_secs(3600)
}

/// 填满 `client` 的连接、让写入卡住，再看一个查询到时限以后怎么收尾：连接上没有动静，复位；写入任务
/// 结束、放掉写半边，对端（收到 `read_now` 后读到连接关闭为止）读得到头
/// Fills `client`'s connection so the writer is stuck, then follows a query past its
/// deadline: the connection has gone quiet, so it is reset; the writer ends and lets go of
/// the write half, and the peer (reading to the close once told by `read_now`) reaches
/// the end
async fn assert_a_stuck_write_ends_at_the_deadline<T: StreamTransport>(
    client: &StreamMuxClient<T>,
    read_now: oneshot::Sender<()>,
    peer: tokio::task::JoinHandle<()>,
) {
    client
        .connect_for_tests()
        .await
        .expect("connect to the test peer");
    // 排进比两头的缓冲加起来还多的字节，当作一个还在等的查询的帧，写入停在 await 上
    // Queue more bytes than both ends' buffers hold, as the frame of a query still waiting, so
    // the writer parks on an await
    let blob = Bytes::from(vec![0u8; 32 << 20]);
    let (tx, _waiting) = oneshot::channel();
    let queue = {
        let slot = client.wires.slot.lock();
        let live = slot.live.as_ref().expect("connected");
        client.wires.pending.insert(
            0,
            Pending {
                original_id: 0,
                generation: live.generation,
                frame: blob.clone(),
                tx,
            },
        );
        Arc::clone(&live.queue)
    };
    queue.push(0, blob);
    let err = client
        .send(&udp_test_query("stuck.example"), Duration::from_millis(500))
        .await
        .expect_err("nothing answers");
    assert!(err.to_string().contains("response timeout"), "{err:#}");
    assert!(!client.connected(), "the quiet connection is reset");
    read_now.send(()).expect("the peer waits");
    tokio::time::timeout(Duration::from_secs(10), peer)
        .await
        .expect("the writer lets go of the write half, so the peer reads to the close")
        .expect("join the peer");
}

/// 读到连接关闭为止 / Reads until the connection closes
async fn read_to_close(mut stream: impl tokio::io::AsyncRead + Unpin) {
    let mut sink = vec![0u8; 1 << 16];
    while matches!(stream.read(&mut sink).await, Ok(n) if n > 0) {}
}

/// 写不出去的连接（对端一个字节也不读）不会一直占着：查询等到时限、连接上又没有动静时复位，写入任务
/// 跟着结束。查询不再自己写（见 `WriteQueue`），以前写到一半被取消时会把半条帧留在连接上
/// A connection that cannot be written to (the peer reads not a byte) is not held on to:
/// a query waiting out its deadline on a quiet connection resets it and the writer ends.
/// Queries no longer write themselves (see `WriteQueue`); one cancelled part way through
/// its write used to leave half a frame on the connection
#[tokio::test]
async fn a_stuck_write_ends_at_the_deadline() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (read_now, told) = oneshot::channel();
    let peer = tokio::spawn(async move {
        let (held, _) = listener.accept().await.unwrap();
        let _ = told.await;
        read_to_close(held).await;
    });
    let client = TcpMuxClient::new(Arc::from(addr.to_string().as_str()));
    assert_a_stuck_write_ends_at_the_deadline(&client, read_now, peer).await;
}

/// 对端关掉自己往这边写的那一头以后，读取任务读到头、腾出连接，写入任务也跟着结束、放掉写半边，对端
/// 读得到连接关闭；不然写入任务会一直拿着这条半开的连接
/// Once the peer closes its sending side, the reader reaches the end and clears the
/// connection, and the writer ends too and lets go of the write half, so the peer reads to
/// the close; otherwise the writer would hold on to the half-open connection for good
#[tokio::test]
async fn a_closed_peer_ends_the_writer_too() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        stream.shutdown().await.unwrap();
        read_to_close(stream).await;
    });
    let client = TcpMuxClient::new(Arc::from(addr.to_string().as_str()));
    client
        .connect_for_tests()
        .await
        .expect("connect to the test peer");
    tokio::time::timeout(Duration::from_secs(5), peer)
        .await
        .expect("the writer lets go of the write half, so the peer reads to the close")
        .expect("join the peer");
    assert!(!client.connected(), "the connection is cleared");
}

/// 同一轮里排进来的帧一次写出去。一个工作线程，排帧的任务都从这个线程上起，和收到一批查询时一样；不先让
/// 一轮的话，第一个任务一叫醒写入任务，它就只写这一帧
/// The frames queued in one round go out in one write. One worker thread, with the tasks
/// queuing them started on it, as when a batch of queries arrives; without yielding a round
/// first, the first task to wake the writer would have it write that frame alone
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn a_round_of_frames_goes_out_in_one_write() {
    let queue = Arc::new(WriteQueue::default());
    let (client_io, mut server_io) = tokio::io::duplex(1 << 16);
    let writes = Arc::new(AtomicUsize::new(0));
    let writer = crate::engine::test_support::CountedWrites {
        io: client_io,
        writes: Arc::clone(&writes),
    };
    let draining = Arc::clone(&queue);
    tokio::spawn(async move { write_frames(writer, &draining, |_, _| true).await });
    // 先写一帧，写入任务写完转回去等着 / One frame first, after which the writer is back to waiting
    queue.push(9, Bytes::from_static(&[0, 1, 9]));
    server_io.read_exact(&mut [0u8; 3]).await.unwrap();
    let before = writes.load(Ordering::SeqCst);
    // 排完帧的任务接着等，和查询排完帧等回答一样 / The tasks keep waiting once their frames are
    // queued, as queries wait for their answers
    let queuing = Arc::clone(&queue);
    let waiting = tokio::spawn(async move {
        (0..8u8)
            .map(|index| {
                let queue = Arc::clone(&queuing);
                tokio::spawn(async move {
                    queue.push(u16::from(index), Bytes::copy_from_slice(&[0, 1, index]));
                    std::future::pending::<()>().await
                })
            })
            .collect::<Vec<_>>()
    })
    .await
    .unwrap();
    let mut written = [0u8; 24];
    server_io.read_exact(&mut written).await.unwrap();
    waiting.iter().for_each(tokio::task::JoinHandle::abort);
    assert_eq!(writes.load(Ordering::SeqCst) - before, 1);
    assert!(
        (0..8u8).all(|index| written.chunks(3).any(|frame| frame == [0, 1, index])),
        "every frame is written whole: {written:?}"
    );
}

/// 帧还没写出去，它的查询就放弃了（时限先到、竞速输了）：这一帧不写，上游不用白答；还在等的照写
/// A query giving up (its deadline first, a race lost) before its frame is written has the
/// frame left unwritten, so the upstream answers nothing for nobody; the frames still waited
/// for are written as ever
#[tokio::test]
async fn a_frame_whose_query_gave_up_is_not_written() {
    let client = TcpMuxClient::new(Arc::from("127.0.0.1:9"));
    let queue = Arc::new(WriteQueue::default());
    client.wires.slot.lock().live = Some(planted(Arc::clone(&queue)));
    let (ours, mut theirs) = tokio::io::duplex(1 << 16);
    TcpMuxClient::spawn_writer(
        &client.wires,
        ours,
        queue,
        Arc::new(Wear::new()),
        CancellationToken::new(),
        1,
    );
    // 两个查询在写入任务醒来之前登记好，第一个随即放弃 / Both queries register before the writer
    // wakes, and the first gives up at once
    let given_up = client
        .register(&udp_test_query("given-up.example"), far_off())
        .await
        .expect("registered");
    drop(given_up);
    let _waiting = client
        .register(&udp_test_query("waited.example"), far_off())
        .await
        .expect("registered");
    let written = read_frame(&mut theirs).await.expect("a frame written");
    assert_eq!(first_label(&written), "waited");
    assert!(
        timeout(Duration::from_millis(100), read_frame(&mut theirs))
            .await
            .is_err(),
        "nothing more is written"
    );
}

/// 让一轮就是一轮：工作线程一直有活时，写入任务也只排在眼下这些任务后面。`tokio::task::yield_now`
/// 要等手上的活干完、或者隔上几十个任务才回来，持续有负载时每一批都会晚出去
/// One round is one round: on a worker that always has work, the writer still waits only
/// behind the tasks queued now. `tokio::task::yield_now` comes back only once the work runs
/// out, or after some dozens of tasks, so under steady load every batch would leave late
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn the_writer_waits_one_round_on_a_busy_worker() {
    /// 不真写，只记下写的时候忙任务转到了第几圈 / Writes nothing, noting how many turns the busy task had made when written to
    struct NotingWrites {
        turns: Arc<AtomicUsize>,
        written_at: Arc<AtomicUsize>,
    }
    impl tokio::io::AsyncWrite for NotingWrites {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.written_at
                .store(self.turns.load(Ordering::SeqCst), Ordering::SeqCst);
            std::task::Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    let turns = Arc::new(AtomicUsize::new(0));
    let written_at = Arc::new(AtomicUsize::new(usize::MAX));
    let queue = Arc::new(WriteQueue::default());
    let writer = NotingWrites {
        turns: Arc::clone(&turns),
        written_at: Arc::clone(&written_at),
    };
    let draining = Arc::clone(&queue);
    let writing = tokio::spawn(async move { write_frames(writer, &draining, |_, _| true).await });
    // 一直有活的任务：每圈记一次数，让一轮再来 / A task that always has work: it counts each turn and yields a round
    let counting = Arc::clone(&turns);
    let busy = tokio::spawn(async move {
        loop {
            counting.fetch_add(1, Ordering::SeqCst);
            yield_one_round().await;
        }
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    for _ in 0..5 {
        let (queuing, counted) = (Arc::clone(&queue), Arc::clone(&turns));
        let pushed_at = tokio::spawn(async move {
            let at = counted.load(Ordering::SeqCst);
            queuing.push(2, Bytes::from_static(&[0, 1, 2]));
            at
        })
        .await
        .unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while written_at.load(Ordering::SeqCst) == usize::MAX {
            assert!(tokio::time::Instant::now() < deadline, "never written");
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let waited = written_at.swap(usize::MAX, Ordering::SeqCst) - pushed_at;
        assert!(waited < 8, "written {waited} turns of the busy task late");
    }
    busy.abort();
    writing.abort();
}

/// 写失败时这条连接就废了：还在等它的查询马上失败，不用等到超时；连接腾出来，下一个查询重新连
/// A failed write ends the connection: the queries still waiting on it fail at once rather
/// than at their timeout, and the slot is cleared for the next query to connect again
#[tokio::test]
async fn a_failed_write_fails_the_waiting_queries() {
    struct Broken;
    impl tokio::io::AsyncWrite for Broken {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    let client = TcpMuxClient::new(Arc::from("127.0.0.1:9"));
    let queue = Arc::new(WriteQueue::default());
    client.wires.slot.lock().live = Some(planted(Arc::clone(&queue)));
    let token = CancellationToken::new();
    // 写入任务属于摆进去的那条连接（第 1 代）/ The writer belongs to the planted connection
    // (generation 1)
    TcpMuxClient::spawn_writer(
        &client.wires,
        Broken,
        queue,
        Arc::new(Wear::new()),
        token.clone(),
        1,
    );
    let (mut waiting, _, _) = client
        .register(&udp_test_query("broken.example"), far_off())
        .await
        .expect("register while connected");
    let answer = tokio::time::timeout(Duration::from_secs(2), &mut waiting.rx)
        .await
        .expect("told at once, not at a timeout")
        .expect("the sender is used, not dropped");
    assert!(
        answer
            .expect_err("the write failed")
            .to_string()
            .contains("write failed")
    );
    assert!(!client.connected(), "the slot is cleared");
    assert!(token.is_cancelled(), "the reader ends too");
}

/// 帧排进去以后查询被取消（外层超时先到、多上游竞速输了被 abort），帧照样整条写出去，迟到的回答对不上号
/// 丢掉，连接还是对齐的：下一个查询在同一条连接上照样答对
/// A query cancelled once its frame is queued (the outer timeout first, or the loser of a
/// multi-upstream race aborted) still has its frame written whole; the late answer matches
/// nothing and is dropped, the connection stays in step, and the next query is answered
/// right on the same connection
#[tokio::test]
async fn a_query_cancelled_after_queuing_leaves_the_connection_in_step() {
    let addr = spawn_stream_upstream(None).await;
    let client = Arc::new(TcpMuxClient::new(Arc::from(addr.to_string())));
    let asking = Arc::clone(&client);
    let task = tokio::spawn(async move {
        asking
            .send(&udp_test_query("cancelled.example"), Duration::from_secs(5))
            .await
    });
    while client.wires.pending.is_empty() {
        tokio::task::yield_now().await;
    }
    task.abort();
    let _ = task.await;
    let generation = client.wires.generation.load(Ordering::Acquire);
    let answer = client
        .send(&udp_test_query("next.example"), Duration::from_secs(5))
        .await
        .expect("answered");
    assert_eq!(first_label(&answer), "next");
    assert_eq!(
        client.wires.generation.load(Ordering::Acquire),
        generation,
        "on the same connection"
    );
}

/// Listener whose accept queue is full and never drained: the kernel drops
/// further SYNs, so a connect() to it hangs until the SYN retransmits give
/// up (minutes) unless the caller bounds it.
/// accept 队列已满且从不 accept 的监听器：内核丢弃后续 SYN，connect() 会挂到
/// SYN 重传耗尽（分钟级），除非调用方自己设限。
struct BlackholedListener {
    addr: SocketAddr,
    _listener: Socket,
    _queued: Vec<std::net::TcpStream>,
}

async fn blackholed_tcp_listener() -> BlackholedListener {
    let listener = Socket::new(Domain::IPV4, Type::STREAM, None).expect("create listener");
    listener
        .bind(&"127.0.0.1:0".parse::<SocketAddr>().unwrap().into())
        .expect("bind listener");
    listener.listen(1).expect("listen with backlog 1");
    let addr = listener.local_addr().unwrap().as_socket().unwrap();
    let queued = tokio::task::spawn_blocking(move || {
        let mut held = Vec::new();
        for _ in 0..8 {
            if let Ok(stream) =
                std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(200))
            {
                held.push(stream);
            }
        }
        held
    })
    .await
    .expect("fill accept queue");
    BlackholedListener {
        addr,
        _listener: listener,
        _queued: queued,
    }
}

/// Listener that accepts and then never sends a byte, so a TLS handshake
/// against it never completes.
/// accept 后一个字节都不发的监听器：TLS 握手永远完不成。
async fn silent_tcp_listener() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind silent listener");
    let addr = listener.local_addr().expect("read silent listener address");
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    addr
}

#[tokio::test]
async fn tcp_connect_is_bounded_by_the_request_budget() {
    // ensure_connection used to call TcpStream::connect with no timeout while
    // holding the connection lock: a blackholed upstream pinned the request
    // (and every request queued behind the lock) for the kernel's SYN
    // timeout, regardless of the configured upstream timeout.
    // ensure_connection 曾在持有连接锁时无超时地 connect：上游黑洞时请求（以及排在
    // 锁后的所有请求）会等满内核 SYN 超时，配置的 upstream 超时形同虚设。
    let blackhole = blackholed_tcp_listener().await;
    let client = TcpMuxClient::new(Arc::from(blackhole.addr.to_string()));
    let started = tokio::time::Instant::now();
    let result = timeout(
        Duration::from_secs(3),
        client.send(&[0u8; 12], Duration::from_millis(300)),
    )
    .await
    .expect("send must give up within its budget, not wait for the kernel SYN timeout");
    assert!(result.is_err(), "a blackholed upstream cannot succeed");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "gave up after {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn dot_connect_and_handshake_are_bounded_by_the_request_budget() {
    // Same for DoT, where the TLS handshake is the part that can stall: an
    // upstream that accepts and stays silent must not pin the request.
    // DoT 同理，卡住的是 TLS 握手：accept 后沉默的上游不能钉死请求。
    let addr = silent_tcp_listener().await;
    let client = DotMuxClient::new(
        Arc::from(format!("dot://{addr}?sni=localhost")),
        Arc::new(build_tls_client_config().expect("tls config")),
    );
    let started = tokio::time::Instant::now();
    let result = timeout(
        Duration::from_secs(3),
        client.send(&[0u8; 12], Duration::from_millis(300)),
    )
    .await
    .expect("send must give up within its budget, not wait for a handshake that never comes");
    assert!(result.is_err(), "a silent upstream cannot succeed");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "gave up after {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn a_dot_handshake_outlives_the_query_that_started_it() {
    // 发起建连的查询在 TLS 握手做完前被取消了（竞速时别的上游先答完），握手照样做完，下一个查询直接用上，不另建
    // The query that started the connect is cancelled before the TLS handshake is through
    // (another upstream answering first in a race); the handshake goes on all the same and
    // the next query uses it, making no other
    let (server, client_tls) = localhost_tls(&[]);
    let upstream = spawn_stream_upstream(Some(server)).await;
    let (addr, accepted) =
        crate::engine::test_support::slow_front(upstream, Duration::from_millis(300)).await;
    let client = DotMuxClient::new(
        Arc::from(format!("dot://{addr}?sni=localhost")),
        Arc::new(client_tls),
    );
    let raced = timeout(
        Duration::from_millis(100),
        client.send(&udp_test_query("first.example"), Duration::from_secs(2)),
    )
    .await;
    assert!(raced.is_err(), "cancelled while the handshake goes on");
    tokio::time::sleep(Duration::from_millis(400)).await;
    client
        .send(
            &udp_test_query("second.example"),
            Duration::from_millis(100),
        )
        .await
        .expect("the connection made meanwhile answers at once");
    assert_eq!(accepted.load(Ordering::SeqCst), 1, "one connection made");
}

/// DoT 的前置：第一条连接压 300 ms 再接到 `upstream`，接通 `first_for` 以后关掉（None 是不接通、直接关掉）；之后的
/// 连接马上接通、一直通着。返回地址和接下了几条连接
/// A DoT front: the first connection is held 300 ms before it is put through to `upstream`
/// and closed after `first_for` through (None: closed without being put through); later ones
/// are put through at once and stay so. Its address, and how many connections it accepted
async fn front_closing_the_first(
    upstream: SocketAddr,
    first_for: Option<Duration>,
) -> (SocketAddr, Arc<AtomicUsize>) {
    let front = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the front");
    let addr = front.local_addr().expect("read the front address");
    let accepted = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&accepted);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = front.accept().await {
            let first = counted.fetch_add(1, Ordering::SeqCst) == 0;
            tokio::spawn(async move {
                if first {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
                let through = if first {
                    first_for
                } else {
                    Some(Duration::MAX)
                };
                let Some(through) = through else { return };
                let mut upstream = tokio::net::TcpStream::connect(upstream)
                    .await
                    .expect("reach the upstream");
                let _ = timeout(
                    through,
                    tokio::io::copy_bidirectional(&mut stream, &mut upstream),
                )
                .await;
            });
        }
    });
    (addr, accepted)
}

/// 发起建连的查询在握手做完前被取消了，连接照样建完、装上，从一开始就有人读它：上游随后把它关了，这边跟着关掉，不会
/// 停在 CLOSE_WAIT 里等下一个查询来取
/// The query that started the connect is cancelled before the handshake is through; the
/// connection is made and put in place all the same, read from the start: when the upstream
/// then closes it, this end closes too rather than sitting in CLOSE_WAIT until another query
/// comes to take it
#[tokio::test]
async fn a_connection_made_for_a_cancelled_query_closes_with_the_upstream() {
    let (server, client_tls) = localhost_tls(&[]);
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (closed_tx, closed_rx) = oneshot::channel();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        let mut tls = acceptor.accept(tcp).await.unwrap();
        tls.shutdown().await.unwrap();
        read_to_close(tls).await;
        let _ = closed_tx.send(());
    });
    let client = DotMuxClient::new(
        Arc::from(format!("dot://{addr}?sni=localhost")),
        Arc::new(client_tls),
    );
    let raced = timeout(
        Duration::from_millis(100),
        client.send(&udp_test_query("first.example"), Duration::from_secs(2)),
    )
    .await;
    assert!(raced.is_err(), "cancelled while the handshake goes on");
    timeout(Duration::from_secs(2), closed_rx)
        .await
        .expect("this end closes once the upstream has")
        .expect("the upstream noted it");
    assert!(!client.connected(), "the slot is cleared");
}

#[tokio::test]
async fn a_connection_left_waiting_and_closed_meanwhile_is_made_again() {
    // 发起建连的查询被取消了，连接照样建完、装上，上游这期间把它关了：读取任务看到就拆掉它，下一个查询重建一条再答
    // The query that started the connect is cancelled, the connection is made and put in
    // place all the same, and the upstream closes it meanwhile: its reader sees that and
    // tears it down, and the next query makes another and is answered
    let (server, client_tls) = localhost_tls(&[]);
    let upstream = spawn_stream_upstream(Some(server)).await;
    let (addr, accepted) =
        front_closing_the_first(upstream, Some(Duration::from_millis(150))).await;
    let client = DotMuxClient::new(
        Arc::from(format!("dot://{addr}?sni=localhost")),
        Arc::new(client_tls),
    );
    let raced = timeout(
        Duration::from_millis(100),
        client.send(&udp_test_query("first.example"), Duration::from_secs(2)),
    )
    .await;
    assert!(raced.is_err(), "cancelled while the handshake goes on");
    tokio::time::sleep(Duration::from_millis(800)).await;
    client
        .send(&udp_test_query("second.example"), Duration::from_secs(2))
        .await
        .expect("answered on a connection made again");
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_failure_left_waiting_past_its_backoff_does_not_fail_the_next_query() {
    // 发起建连的查询被取消了，建连随后失败；下一个查询来时，从这次失败算起的退避早已过去：重新建连再答
    // The query that started the connect is cancelled and the connect then fails; by the time
    // the next query comes the backing off counted from that failure is long over, so a
    // connect is made again before answering
    let (server, client_tls) = localhost_tls(&[]);
    let upstream = spawn_stream_upstream(Some(server)).await;
    let (addr, accepted) = front_closing_the_first(upstream, None).await;
    let client = DotMuxClient::new(
        Arc::from(format!("dot://{addr}?sni=localhost")),
        Arc::new(client_tls),
    );
    let raced = timeout(
        Duration::from_millis(100),
        client.send(&udp_test_query("first.example"), Duration::from_secs(2)),
    )
    .await;
    assert!(raced.is_err(), "cancelled while the handshake goes on");
    tokio::time::sleep(Duration::from_millis(800)).await;
    client
        .send(&udp_test_query("second.example"), Duration::from_secs(2))
        .await
        .expect("answered after connecting again");
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_failed_connect_backs_off_before_the_next() {
    // 建连失败以后退避：这期间的查询马上失败、不再去连；过了退避再连。以前上游不通时每个查询都去连一次
    // After a failed connect it backs off: the queries meanwhile fail at once without
    // connecting; past the backing off it connects again. Every query used to connect
    // with the upstream unreachable
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the refusing listener");
    let addr = listener
        .local_addr()
        .expect("read the refusing listener address");
    let accepted = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&accepted);
    tokio::spawn(async move {
        // 接下就关，TLS 握手失败 / Accepted and closed at once, failing the TLS handshake
        while listener.accept().await.is_ok() {
            counted.fetch_add(1, Ordering::Relaxed);
        }
    });
    let client = DotMuxClient::new(
        Arc::from(format!("dot://{addr}?sni=localhost")),
        Arc::new(build_tls_client_config().expect("tls config")),
    );
    let query = udp_test_query("refused.example");
    assert!(client.send(&query, Duration::from_secs(1)).await.is_err());
    let backing_off = client
        .send(&query, Duration::from_secs(1))
        .await
        .expect_err("still backing off");
    assert!(
        backing_off.to_string().contains("failed lately"),
        "{backing_off:#}"
    );
    assert_eq!(
        accepted.load(Ordering::Relaxed),
        1,
        "no connect while backing off"
    );
    tokio::time::sleep(CONNECT_BACKOFF + Duration::from_millis(50)).await;
    assert!(client.send(&query, Duration::from_secs(1)).await.is_err());
    assert_eq!(
        accepted.load(Ordering::Relaxed),
        2,
        "connects again past it"
    );
}

/// TCP upstream that answers the very first query it ever receives
/// (echoing the frame with QR set) and then swallows everything, on that
/// connection and on any later one.
/// 只应答收到的第一个查询（回显帧并置 QR 位），之后无论旧连接还是新连接一律吞掉的
/// TCP 上游。
async fn answer_once_then_stall_tcp_upstream() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stalling upstream");
    let addr = listener
        .local_addr()
        .expect("read stalling upstream address");
    let answered = Arc::new(std::sync::atomic::AtomicBool::new(false));
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let answered = Arc::clone(&answered);
            tokio::spawn(async move {
                let mut len = [0u8; 2];
                if stream.read_exact(&mut len).await.is_err() {
                    return;
                }
                let mut frame = vec![0u8; u16::from_be_bytes(len) as usize];
                if stream.read_exact(&mut frame).await.is_err() {
                    return;
                }
                if !answered.swap(true, Ordering::SeqCst) {
                    frame[2] |= 0x80;
                    let _ = stream.write_all(&len).await;
                    let _ = stream.write_all(&frame).await;
                }
                let mut sink = [0u8; 512];
                while stream.read(&mut sink).await.is_ok_and(|n| n > 0) {}
            });
        }
    });
    addr
}

#[tokio::test]
async fn tcp_retry_does_not_exceed_the_request_budget() {
    // The transparent retry over a fresh connection used to be granted a
    // 1.5 s floor even when the caller's budget was already spent, so a
    // 200 ms request took about 1.7 s on a stalled reused connection.
    // 复用连接失败后的透明重试曾无条件给 1.5 s 保底：预算 200 ms 的请求在卡住的
    // 复用连接上要跑约 1.7 s。
    let addr = answer_once_then_stall_tcp_upstream().await;
    let client = TcpMuxClient::new(Arc::from(addr.to_string()));
    let query = [0x12, 0x34, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
    client
        .send(&query, Duration::from_millis(500))
        .await
        .expect("first query on a fresh connection is answered");

    let started = tokio::time::Instant::now();
    let err = client
        .send(&query, Duration::from_millis(200))
        .await
        .expect_err("stalled upstream cannot answer the second query");
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_millis(700),
        "second query took {elapsed:?} on a 200 ms budget: {err:#}"
    );
}

/// TCP 上游：每条连接上的前 `answers` 个查询回显作答，再来一个就关掉这条连接；返回地址和接下了几条连接
/// A TCP upstream answering the first `answers` queries on each connection with an echo and
/// closing the connection on the next; its address, and how many connections it accepted
async fn closing_tcp_upstream(answers: usize) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind closing upstream");
    let addr = listener
        .local_addr()
        .expect("read closing upstream address");
    let accepted = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&accepted);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            counted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                for answered in 0.. {
                    let mut len = [0u8; 2];
                    if stream.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let mut frame = vec![0u8; u16::from_be_bytes(len) as usize];
                    if stream.read_exact(&mut frame).await.is_err() || answered == answers {
                        return;
                    }
                    frame[2] |= 0x80;
                    let _ = stream.write_all(&len).await;
                    let _ = stream.write_all(&frame).await;
                }
            });
        }
    });
    (addr, accepted)
}

#[tokio::test]
async fn a_query_on_a_connection_the_upstream_closed_is_sent_again() {
    // 连接在这次发送之前就有，上游在查询到达时把它关了（空闲久了的连接常这样）：换一条新连接重发，拿到回答
    // The connection was there before this send and the upstream closed it as the query
    // arrived (as idle connections often go): it is sent again on a fresh one and answered
    let (addr, accepted) = closing_tcp_upstream(1).await;
    let client = TcpMuxClient::new(Arc::from(addr.to_string()));
    let query = udp_test_query("again.example");
    client
        .send(&query, Duration::from_secs(1))
        .await
        .expect("answered on the first connection");
    client
        .send(&query, Duration::from_secs(1))
        .await
        .expect("sent again on a fresh connection and answered");
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_send_whose_own_connection_breaks_is_not_sent_again() {
    // 这次发送自己建的连接一收到查询就断了：不重发，再建一条多半还是断
    // The connection this send made itself breaks on receiving the query: it is not sent
    // again, as another would most likely break as well
    let (addr, accepted) = closing_tcp_upstream(0).await;
    let client = TcpMuxClient::new(Arc::from(addr.to_string()));
    let query = udp_test_query("broken.example");
    let sent = client.send(&query, Duration::from_secs(1)).await;
    assert!(sent.is_err(), "the upstream never answers");
    assert_eq!(accepted.load(Ordering::SeqCst), 1, "connected once");
}

#[tokio::test]
async fn tcp_mux_rewrite_id_no_deadlock_under_contention() {
    // Arrange: Prepare a TCP client with many pending IDs to force contention
    let client = Arc::new(TcpMuxClient::new(Arc::from("127.0.0.1:0")));
    client.wires.slot.lock().live = Some(planted(Arc::new(WriteQueue::default())));
    for id in 1u16..200u16 {
        client.wires.pending.insert(
            id,
            Pending {
                original_id: id,
                generation: 1,
                frame: Bytes::new(),
                tx: oneshot::channel().0,
            },
        );
    }

    // Act: Spawn many concurrent register_pending calls to test contention handling
    let tasks = (0..64)
        .map(|_| {
            let client = Arc::clone(&client);
            async move {
                let dummy = vec![0u8; 4];
                client.register(&dummy, far_off()).await
            }
        })
        .collect::<Vec<_>>();

    let results = timeout(Duration::from_millis(500), join_all(tasks))
        .await
        .expect("register_pending stalled under contention");

    // Assert: Verify all IDs are unique (no duplicates under contention)
    let mut ids = rustc_hash::FxHashSet::default();
    for r in results {
        let (waiting, _, _) = r.expect("register_pending failed");
        assert!(
            ids.insert(waiting.id),
            "duplicate id allocated under contention"
        );
    }
}

/// 回答到了，读取任务把条目拿走，这个 ID 随后分给了后来的查询；先前那个查询这时才放手，不能把后来的条目带走。
/// 以前放手时按 ID 无条件删：后来的查询的回答到了却找不到条目，只能等到超时
/// An answer arrives and the reader takes the entry, the ID then goes to a later query, and
/// only now does the earlier query let go: it must not take the later one's entry with it.
/// Letting go used to remove by ID whatever was there, so the later query's answer found no
/// entry and the query waited out its timeout
#[test]
fn letting_go_of_an_id_leaves_a_later_query_on_it_alone() {
    let map: Arc<DashMap<u16, Pending, FxBuildHasher>> =
        Arc::new(DashMap::with_hasher(FxBuildHasher));
    let entry = |tx| Pending {
        original_id: 1,
        generation: 1,
        frame: Bytes::new(),
        tx,
    };
    let waiting = |rx| Waiting {
        rx,
        map: Arc::clone(&map),
        id: 7,
        abandoned: |pending: &Pending| pending.tx.is_closed(),
    };
    let (earlier_tx, earlier_rx) = oneshot::channel();
    map.insert(7, entry(earlier_tx));
    let earlier = waiting(earlier_rx);
    // 回答到了：读取任务拿走条目，交出回答 / The answer arrives: the reader takes the entry
    // and hands the answer over
    let (_, taken) = map.remove(&7).expect("the earlier query's entry");
    taken.tx.send(Ok(Bytes::new())).expect("still waited for");
    // 同一个 ID 分给了后来的查询 / The same ID goes to a later query
    let (later_tx, later_rx) = oneshot::channel();
    map.insert(7, entry(later_tx));
    let later = waiting(later_rx);

    drop(earlier);
    assert!(map.contains_key(&7), "the later query's entry stays");
    // 后来的查询自己放手（超时、取消）时，它的条目跟着走 / When the later query lets go itself
    // (a timeout, a cancellation) its entry goes with it
    drop(later);
    assert!(map.is_empty(), "its own entry goes");
}

/// 登记和拆除都在槽的锁下做完：拆之前登记上的查询，拆的时候都被告知，条目也不留下
/// Registration and teardown are each done under the slot's lock: a query registered before
/// the teardown is told of it, and leaves no entry behind
#[tokio::test]
async fn a_teardown_tells_the_queries_registered_before_it() {
    let client = TcpMuxClient::new(Arc::from("127.0.0.1:9"));
    client.wires.slot.lock().live = Some(planted(Arc::new(WriteQueue::default())));
    let (mut waiting, _, _) = client
        .register(&[0u8; 4], far_off())
        .await
        .expect("registered on the planted connection");
    assert!(TcpMuxClient::close(&client.wires, 1, "reader failed"));
    assert!(client.wires.pending.is_empty());
    let result = timeout(Duration::from_millis(100), &mut waiting.rx)
        .await
        .expect("the waiter is told at once")
        .expect("the sender is used, not dropped");
    assert!(result.is_err(), "the teardown reaches the waiter");
}

/// 预热建的连接池和发送时现建的一样大，每个客户端各有自己的连接位
/// A warmed-up pool is as large as one built on first send, each client with a
/// connection slot of its own
#[test]
fn a_warmed_up_pool_has_every_client() {
    let mux = TcpMultiplexer::new(3, 0, 0, Bootstrap::system());
    mux.warm_up_pools(&["127.0.0.1:53".to_string()].into_iter().collect());
    let pool = mux
        .pools
        .get("127.0.0.1:53")
        .expect("the upstream is warmed up")
        .clone();
    assert_eq!(pool.clients.len(), 3);
    assert!(!Arc::ptr_eq(
        &pool.clients[0].wires.slot,
        &pool.clients[1].wires.slot
    ));
}

/// 同一个池的客户端各用各的连接，不同上游各有各的池：经池里两个客户端各发一个查询，上游收到两条
/// 连接
/// The clients of one pool each keep a connection of their own, and each upstream has
/// a pool of its own: a query sent through each of a pool's two clients reaches the
/// upstream over two connections
#[tokio::test]
async fn the_clients_of_one_pool_each_keep_a_connection_of_their_own() {
    use std::sync::atomic::AtomicUsize;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&accepted);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            counted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                loop {
                    let mut len = [0u8; 2];
                    if stream.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let mut frame = vec![0u8; u16::from_be_bytes(len) as usize];
                    if stream.read_exact(&mut frame).await.is_err() {
                        return;
                    }
                    frame[2] |= 0x80;
                    if stream.write_all(&len).await.is_err()
                        || stream.write_all(&frame).await.is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    let mux = TcpMultiplexer::new(2, 0, 0, Bootstrap::system());
    let pool = mux.get_or_init_pool_for_test(&addr);
    assert_eq!(pool.clients.len(), 2);
    for client in &pool.clients {
        client
            .send(&udp_test_query("a.example"), Duration::from_secs(2))
            .await
            .expect("the upstream answers");
    }
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        2,
        "one connection per client"
    );
    let other = mux.get_or_init_pool_for_test("192.0.2.53:53");
    assert!(
        !Arc::ptr_eq(&pool, &other),
        "each upstream has its own pool"
    );
}

/// 查询超时以后，它在 TCP 连接的 pending 表里的那一条已经删掉（UDP 的 inflight 表见 `udp_tests`）
/// Once a query times out, its entry is gone from the TCP connection's pending map (the UDP
/// socket's inflight map is in `udp_tests`)
#[tokio::test]
async fn a_timed_out_query_leaves_no_entry_behind() {
    // 收下查询、从不回答的本机上游 / A local upstream that takes queries and never answers
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_addr = tcp.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = tcp.accept().await {
            held.push(stream);
        }
    });

    let tcp_client = TcpMuxClient::new(Arc::from(tcp_addr.as_str()));
    let result = tcp_client
        .send(&udp_test_query("a.example"), Duration::from_millis(100))
        .await;
    assert!(result.is_err(), "the upstream never answers");
    assert!(tcp_client.wires.pending.is_empty());
}

/// 连接池大小写成 0 时按 1 算：TCP 的池里有一个客户端，DoT 用同一套（DoQ 的见 `doq_tests`）
/// A pool size of 0 counts as 1: a TCP pool gets one client, DoT sharing its code (DoQ's is in
/// `doq_tests`)
#[tokio::test]
async fn a_pool_size_of_zero_gives_one_client() {
    let tcp = TcpMultiplexer::new(0, 0, 0, Bootstrap::system());
    assert_eq!(
        tcp.get_or_init_pool_for_test("192.0.2.1:53").clients.len(),
        1
    );
}

/// TCP 和 DoT 的多路复用客户端是同一套写法，下面几条测试对两者一视同仁
/// The TCP and DoT multiplexing clients share one design, so the tests
/// below hold both to the same behaviour
/// 测试直接摆进客户端的一条连接：第 1 代，写入队列是 `queue`
/// A connection a test plants in a client: generation 1, with `queue` as its write queue
fn planted(queue: Arc<WriteQueue>) -> Live {
    Live {
        queue,
        generation: 1,
        cancel: CancellationToken::new(),
        answers: Arc::default(),
        wear: Arc::new(Wear::new()),
    }
}

trait StreamMux {
    async fn query(&self, packet: &[u8], timeout_dur: Duration) -> anyhow::Result<Bytes>;
    fn connection_generation(&self) -> u64;
    async fn drop_connection(&self);
    fn pending(&self) -> &DashMap<u16, Pending, FxBuildHasher>;
}

impl<T: StreamTransport> StreamMux for StreamMuxClient<T> {
    async fn query(&self, packet: &[u8], timeout_dur: Duration) -> anyhow::Result<Bytes> {
        self.send(packet, timeout_dur).await
    }
    fn connection_generation(&self) -> u64 {
        self.wires.generation.load(Ordering::Acquire)
    }
    async fn drop_connection(&self) {
        self.reset(self.wires.generation.load(Ordering::Acquire));
    }
    fn pending(&self) -> &DashMap<u16, Pending, FxBuildHasher> {
        &self.wires.pending
    }
}

async fn tcp_test_client() -> TcpMuxClient {
    let addr = spawn_stream_upstream(None).await;
    TcpMuxClient::new(Arc::from(addr.to_string()))
}

async fn dot_test_client() -> DotMuxClient {
    let (server, client_tls) = localhost_tls(&[]);
    let addr = spawn_stream_upstream(Some(server)).await;
    DotMuxClient::new(
        Arc::from(format!("dot://{addr}?sni=localhost")),
        Arc::new(client_tls),
    )
}

/// 一条连接上 65536 个 ID 全被等着的查询占着时，新查询立刻失败，连接照常用。此前每个新查询
/// 都要在连接锁下把 65536 个 ID 挨个试一遍，一大批这样的查询排着队，后面的远远超出时限。
/// With all 65536 IDs on a connection held by waiting queries, a new query fails
/// at once and the connection stays in use. Each new query used to try all 65536
/// IDs one by one under the connection lock, and a crowd of them queued up, the
/// later ones running far past their deadlines.
async fn a_full_id_space_fails_queries_at_once(client: &impl StreamMux) {
    client
        .query(&udp_test_query("warm.example"), Duration::from_secs(2))
        .await
        .expect("a fresh connection answers");
    let generation = client.connection_generation();
    for id in 0..=u16::MAX {
        client.pending().insert(
            id,
            Pending {
                original_id: id,
                generation: 1,
                frame: Bytes::new(),
                tx: oneshot::channel().0,
            },
        );
    }

    let started = tokio::time::Instant::now();
    let query = udp_test_query("full.example");
    let results =
        futures::future::join_all((0..2000).map(|_| client.query(&query, Duration::from_secs(1))))
            .await;
    assert!(results.iter().all(Result::is_err), "no ID is free");
    assert!(
        started.elapsed() < Duration::from_millis(900),
        "2000 queries took {:?} to fail",
        started.elapsed()
    );
    assert_eq!(client.connection_generation(), generation);

    client.pending().clear();
    client
        .query(&udp_test_query("again.example"), Duration::from_secs(2))
        .await
        .expect("the same connection answers once IDs are free");
    assert_eq!(client.connection_generation(), generation);
}

#[tokio::test]
async fn a_full_tcp_id_space_fails_queries_at_once() {
    a_full_id_space_fails_queries_at_once(&tcp_test_client().await).await;
}

#[tokio::test]
async fn a_full_dot_id_space_fails_queries_at_once() {
    a_full_id_space_fails_queries_at_once(&dot_test_client().await).await;
}

/// 同一个 ID 下回答别的问题的不收，查询接着等自己的回答，和 UDP 一样。此前只按 ID 对号：
/// 连接上 ID 转了一圈以后，之前用过这个 ID 的查询迟到的回答会被交给现在的查询，还会进缓存。
/// An answer to another question under the same ID is dropped and the query
/// keeps waiting for its own, as on UDP. Answers used to be matched by ID only:
/// once the IDs on a connection had come round, a late answer to an earlier
/// query with that ID was handed to the current one, and cached.
async fn an_answer_to_another_question_is_dropped(client: &impl StreamMux) {
    let query = udp_test_query("swap.example");
    let answer = client
        .query(&query, Duration::from_secs(2))
        .await
        .expect("the real answer follows");
    assert_eq!(answer.as_ref(), echo_answer(&query).as_slice());
}

#[tokio::test]
async fn a_tcp_answer_to_another_question_is_dropped() {
    an_answer_to_another_question_is_dropped(&tcp_test_client().await).await;
}

#[tokio::test]
async fn a_dot_answer_to_another_question_is_dropped() {
    an_answer_to_another_question_is_dropped(&dot_test_client().await).await;
}

/// 一个查询超时、这条连接上又再没有回答时，连接会被重建。此前同一条连接上还在等
/// 的查询被晾着：reader 已经取消，它们的回答再也到不了，只能等满自己的截止时间，
/// 然后各自再重置一次连接，把新连接上的查询也连累进去。
/// When a query times out and nothing else answered on the connection, the
/// connection is rebuilt. The other queries waiting on it used to be left
/// hanging: with the reader cancelled their answers could never arrive, so
/// each sat out its full deadline and then reset the connection again,
/// dragging in the queries on the new one.
async fn a_slow_answer_does_not_cost_its_neighbours_theirs(client: &impl StreamMux) {
    client
        .query(&udp_test_query("warm.example"), Duration::from_secs(2))
        .await
        .expect("a fresh connection answers");

    let started = tokio::time::Instant::now();
    let slow_query = udp_test_query("slow.example");
    let late_query = udp_test_query("late.example");
    let (slow, late) = tokio::join!(
        client.query(&slow_query, Duration::from_millis(300)),
        client.query(&late_query, Duration::from_secs(2)),
    );
    assert!(slow.is_err(), "the upstream never answers `slow`");
    assert!(
        late.is_ok(),
        "`late` is answered after 400 ms, but got {:?} after {:?}",
        late.err(),
        started.elapsed()
    );
    assert!(
        started.elapsed() < Duration::from_millis(1500),
        "`late` waited {:?} instead of retrying over a fresh connection",
        started.elapsed()
    );
}

#[tokio::test]
async fn a_slow_tcp_answer_does_not_cost_its_neighbours_theirs() {
    a_slow_answer_does_not_cost_its_neighbours_theirs(&tcp_test_client().await).await;
}

#[tokio::test]
async fn a_slow_dot_answer_does_not_cost_its_neighbours_theirs() {
    a_slow_answer_does_not_cost_its_neighbours_theirs(&dot_test_client().await).await;
}

/// 这条连接在慢查询写出之后还回答了别的查询：连接是活的，不能因为一个回答慢就重建
/// The connection answered another query after the slow one was written: it
/// is alive and must not be rebuilt over one slow answer
async fn a_slow_answer_keeps_a_live_connection(client: &impl StreamMux) {
    client
        .query(&udp_test_query("warm.example"), Duration::from_secs(2))
        .await
        .expect("a fresh connection answers");
    let generation = client.connection_generation();

    let slow_query = udp_test_query("slow.example");
    let mid_query = udp_test_query("mid.example");
    let (slow, mid) = tokio::join!(
        client.query(&slow_query, Duration::from_millis(300)),
        client.query(&mid_query, Duration::from_secs(2)),
    );
    assert!(slow.is_err(), "the upstream never answers `slow`");
    assert!(
        mid.is_ok(),
        "`mid` is answered after 100 ms: {:?}",
        mid.err()
    );
    client
        .query(&udp_test_query("after.example"), Duration::from_secs(2))
        .await
        .expect("the connection still answers");
    assert_eq!(
        client.connection_generation(),
        generation,
        "one slow answer on a connection that keeps answering must not rebuild it"
    );
}

#[tokio::test]
async fn a_slow_tcp_answer_keeps_a_live_connection() {
    a_slow_answer_keeps_a_live_connection(&tcp_test_client().await).await;
}

#[tokio::test]
async fn a_slow_dot_answer_keeps_a_live_connection() {
    a_slow_answer_keeps_a_live_connection(&dot_test_client().await).await;
}

/// reset 之后连接上再也不会有回答，等着的查询要立刻得到失败，而不是等满截止时间。
/// 连接老化（默认 5 分钟）、连续出错达到阈值都会走这里。
/// After a reset no answer can arrive on the connection, so a waiting query
/// must fail at once rather than at its deadline. Connection ageing (5
/// minutes by default) and the error threshold both come through here.
async fn a_reset_fails_waiting_queries_at_once(client: &impl StreamMux) {
    let started = tokio::time::Instant::now();
    let slow_query = udp_test_query("slow.example");
    let (result, ()) = tokio::join!(client.query(&slow_query, Duration::from_secs(3)), async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        client.drop_connection().await;
    });
    assert!(result.is_err(), "the upstream never answers `slow`");
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "the waiting query was only released after {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn a_tcp_reset_fails_waiting_queries_at_once() {
    a_reset_fails_waiting_queries_at_once(&tcp_test_client().await).await;
}

#[tokio::test]
async fn a_dot_reset_fails_waiting_queries_at_once() {
    a_reset_fails_waiting_queries_at_once(&dot_test_client().await).await;
}

/// 连接用旧了以后同时来几个查询（一次解析的 A 和 AAAA 就是这样）：旧连接只由它自己的写入任务摘下一次，新连接建一条，
/// 查询都等这同一次建连、都答上
/// With a connection worn and several queries arriving together (the A and AAAA of one lookup
/// do), the old connection is taken out once, by its own writer, one new one is made, and every
/// query waits for that one connect and is answered
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_expired_connection_is_replaced_once_for_queries_arriving_together() {
    let addr = spawn_stream_upstream(None).await;
    let client = Arc::new(TcpMuxClient::with_shared(
        Bootstrap::system(),
        Arc::from(addr.to_string()),
        Aging {
            max_age: Some(Duration::from_millis(100)),
            ..Aging::for_tests()
        },
    ));
    client
        .send(&udp_test_query("warm.example"), Duration::from_millis(50))
        .await
        .expect("a fresh connection answers");
    for round in 0..5 {
        // 用到了最长时间，期限也都过了：摘下了 / Past its max age and its deadlines: taken out
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(!client.connected(), "round {round}: worn and taken out");
        let before = client.wires.generation.load(Ordering::Acquire);
        let queries = (0..4).map(|n| {
            let client = Arc::clone(&client);
            tokio::spawn(async move {
                let query = udp_test_query(&format!("r{round}q{n}.example"));
                client.send(&query, Duration::from_millis(50)).await
            })
        });
        for answered in futures::future::join_all(queries).await {
            answered
                .expect("the query task ran")
                .unwrap_or_else(|err| panic!("round {round}: {err:#}"));
        }
        assert_eq!(
            client.wires.generation.load(Ordering::Acquire),
            before + 1,
            "round {round}: the expired connection is replaced once"
        );
    }
}

/// 连接用到了最长时间：它上面还在等的查询照样在它上面拿到回答，接着的查询走新连接；最晚的期限过了以后旧连接关掉
/// A connection reaching its max age: a query still waiting on it gets its answer there, and
/// the next query goes over a new one; past the latest deadline the old connection closes
#[tokio::test]
async fn a_query_in_flight_outlives_its_connection_reaching_max_age() {
    let (addr, mut closed) = upstream_noting_closes(None).await;
    let client = TcpMuxClient::with_shared(
        Bootstrap::system(),
        Arc::from(addr.to_string()),
        Aging {
            max_age: Some(Duration::from_millis(50)),
            ..Aging::for_tests()
        },
    );
    let mid = udp_test_query("mid.example");
    let (waited, ()) = tokio::join!(
        client.send_attempt(&mid, Duration::from_millis(500)),
        async {
            // 上游 100 毫秒后才答 `mid`，连接 50 毫秒就用到了最长时间 / The upstream answers `mid`
            // after 100 ms, and the connection reaches its max age at 50 ms
            tokio::time::sleep(Duration::from_millis(70)).await;
            let old = client.wires.generation.load(Ordering::Acquire);
            assert!(!client.connected(), "taken out at its max age");
            client
                .send_attempt(&udp_test_query("next.example"), Duration::from_secs(2))
                .await
                .expect("a new connection answers");
            assert_eq!(client.wires.generation.load(Ordering::Acquire), old + 1);
        }
    );
    waited.expect("the query on the aged connection is answered on it");
    tokio::time::timeout(Duration::from_secs(2), closed.recv())
        .await
        .expect("the aged connection closes once its last deadline has passed")
        .expect("a close noted");
}

/// 连接活了多久按单调时钟算，系统时间被往回调也照样到最长时间就摘下：这里 tokio 的钟走了 20 秒，墙上的钟几乎没动
/// How long a connection has lived counts on the monotonic clock, so it is taken out at its max
/// age however the system time is set back: here tokio's clock moves 20 seconds on while the
/// wall clock hardly moves at all
#[tokio::test]
async fn a_connection_ages_on_the_monotonic_clock() {
    let addr = spawn_stream_upstream(None).await;
    let client = TcpMuxClient::with_shared(
        Bootstrap::system(),
        Arc::from(addr.to_string()),
        Aging {
            max_age: Some(Duration::from_secs(10)),
            ..Aging::for_tests()
        },
    );
    client
        .send(&udp_test_query("warm.example"), Duration::from_secs(2))
        .await
        .expect("a fresh connection answers");
    let old = client.wires.generation.load(Ordering::Acquire);
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(20)).await;
    // 让写入任务跑一跑，到了时候它就把连接摘下 / Let the writer run: when the time has come it takes
    // the connection out
    for _ in 0..100 {
        if !client.connected() {
            break;
        }
        tokio::task::yield_now().await;
    }
    tokio::time::resume();
    client
        .send(&udp_test_query("next.example"), Duration::from_secs(2))
        .await
        .expect("a new connection answers");
    assert_eq!(client.wires.generation.load(Ordering::Acquire), old + 1);
}

/// 拆连接的决定点名一代：点的那一代已经换成新连接时，什么都不动。新连接照常用，等在它上面的查询不受影响，
/// 也没有多建一条。拆除的每条路都这样：复位、读写失败时的拆除
/// A decision to tear a connection down names a generation, and does nothing once that
/// generation has been replaced: the new connection goes on being used, a query waiting on
/// it is untouched, and no further connection is made. So for every way of tearing down: a
/// reset, the teardown after a failed read or write
#[tokio::test]
async fn a_teardown_naming_a_replaced_connection_leaves_the_new_one_alone() {
    let client = tcp_test_client().await;
    let ask = |name: &'static str| client.send(udp_test_query(name).leak(), Duration::from_secs(2));
    ask("warm.example")
        .await
        .expect("a fresh connection answers");
    let old = client.wires.generation.load(Ordering::Acquire);
    assert!(client.reset(old), "the connection it names is torn down");
    assert!(!client.reset(old), "torn down already");
    ask("again.example")
        .await
        .expect("a new connection answers");
    let new = client.wires.generation.load(Ordering::Acquire);
    assert_eq!(new, old + 1);

    // 新连接上有一个查询在等（上游 100 毫秒后才答）/ A query waits on the new connection (the
    // upstream answers after 100 ms)
    let (waiting, ()) = tokio::join!(ask("mid.example"), async {
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(!client.reset(old));
        assert!(!TcpMuxClient::close(&client.wires, old, "stale"));
        ask("next.example")
            .await
            .expect("the same connection answers");
    });
    waiting.expect("the query on the new connection is answered");
    assert_eq!(client.wires.generation.load(Ordering::Acquire), new);
}

/// `tls://[…]` 写法的上游此前根本连不上：地址被拼成 `[[…]]:853`
/// An upstream written `tls://[…]` could not connect at all: the address came
/// out as `[[…]]:853`
#[tokio::test]
async fn dot_reaches_an_ipv6_literal_upstream() {
    let (server, client_tls) = self_signed_tls(&["::1"], &[]);
    let Some(addr) = spawn_stream_upstream_on("[::1]:0", Some(server), None).await else {
        eprintln!("skipped: IPv6 loopback unavailable on this host");
        return;
    };
    let client = DotMuxClient::new(
        Arc::from(format!("dot://[::1]:{}", addr.port())),
        Arc::new(client_tls),
    );
    client
        .send(&udp_test_query("v6.example"), Duration::from_secs(2))
        .await
        .expect("an IPv6 literal DoT upstream answers");
}

/// DoT 的写入卡住时也一样收尾（见 `a_stuck_write_ends_at_the_deadline`）：TLS 流写满时会先收下明文，
/// 写入任务停在 flush 上
/// A stuck DoT write ends the same way (see `a_stuck_write_ends_at_the_deadline`): a full
/// TLS stream accepts the plaintext first and the writer parks on the flush
#[tokio::test]
async fn a_stuck_dot_write_ends_at_the_deadline() {
    let (server, client_tls) = localhost_tls(&[]);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
    let (read_now, told) = oneshot::channel();
    let peer = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let held = acceptor.accept(stream).await.expect("TLS handshake");
        let _ = told.await;
        read_to_close(held).await;
    });
    let client = DotMuxClient::new(
        Arc::from(format!("dot://{addr}?sni=localhost")),
        Arc::new(client_tls),
    );
    assert_a_stuck_write_ends_at_the_deadline(&client, read_now, peer).await;
}

/// 每条连接结束时发一个信号的本机 TCP 上游（见 [`spawn_stream_upstream`]）；`tls` 给了就是 DoT
/// A local TCP upstream (see [`spawn_stream_upstream`]) signalling whenever a
/// connection ends; DoT when `tls` is given
async fn upstream_noting_closes(
    tls: Option<rustls::ServerConfig>,
) -> (SocketAddr, tokio::sync::mpsc::UnboundedReceiver<()>) {
    let (closed_tx, closed_rx) = tokio::sync::mpsc::unbounded_channel();
    let addr = spawn_stream_upstream_on("127.0.0.1:0", tls, Some(closed_tx))
        .await
        .expect("bind the stream test upstream");
    (addr, closed_rx)
}

/// 从 `stream` 读一个带长度前缀的查询 / Reads one length-prefixed query from `stream`
async fn read_frame(stream: &mut (impl tokio::io::AsyncRead + Unpin)) -> std::io::Result<Vec<u8>> {
    let mut len = [0u8; 2];
    stream.read_exact(&mut len).await?;
    let mut query = vec![0u8; usize::from(u16::from_be_bytes(len))];
    stream.read_exact(&mut query).await?;
    Ok(query)
}

/// 往 `stream` 写 `query` 的回答（见 [`echo_answer`]），带长度前缀 / Writes the answer to `query`
/// (see [`echo_answer`]) to `stream`, length-prefixed
async fn write_answer(
    stream: &mut (impl tokio::io::AsyncWrite + Unpin),
    query: &[u8],
) -> std::io::Result<()> {
    let answer = echo_answer(query);
    stream
        .write_all(&(answer.len() as u16).to_be_bytes())
        .await?;
    stream.write_all(&answer).await?;
    stream.flush().await
}

#[tokio::test]
async fn dropping_a_tcp_pool_closes_its_connection() {
    let (addr, mut closed) = upstream_noting_closes(None).await;
    let mux = TcpMultiplexer::new(2, 300, 60, Bootstrap::system());
    mux.send(
        &udp_test_query("a.example"),
        &addr.to_string(),
        Duration::from_secs(2),
    )
    .await
    .expect("the upstream answers");
    kept_then_dropped(&mut closed, |keep| mux.retain_upstreams(|_| keep)).await;
}

#[tokio::test]
async fn dropping_a_dot_pool_closes_its_connection() {
    let (server, client_tls) = localhost_tls(&[]);
    let (addr, mut closed) = upstream_noting_closes(Some(server)).await;
    let mux = DotMultiplexer::with_shared((Arc::new(client_tls), Bootstrap::system()), 2, 300, 60);
    mux.send(
        &udp_test_query("a.example"),
        &format!("{addr}?sni=localhost"),
        Duration::from_secs(2),
    )
    .await
    .expect("the upstream answers");
    kept_then_dropped(&mut closed, |keep| mux.retain_upstreams(|_| keep)).await;
}

/// 连接池里的客户端用的是建多路复用器时给的老化设置：连接最长存活（设成 1 秒的连接到时候自己摘下、关掉，不等下一个
/// 查询来看）、空闲时长（设成 1 秒的连接不再有查询时自己关掉）
/// A pool's clients take the aging the multiplexer was built with: the longest a connection
/// may live (given 1 second, it takes itself out and closes when the time comes, with no next
/// query to look) and how long it may sit idle (given 1 second, it closes by itself once no
/// query comes)
#[tokio::test]
async fn pool_clients_take_the_configured_health_settings() {
    let query = udp_test_query("a.example");
    let mux = TcpMultiplexer::new(1, 1, 0, Bootstrap::system());
    let (addr, mut closed) = upstream_noting_closes(None).await;
    let upstream = addr.to_string();
    // 期限短一些：摘下的旧连接要等登记在它上面最晚的那个期限 / A short deadline: the old connection
    // taken out waits for the latest deadline registered on it
    mux.send(&query, &upstream, Duration::from_millis(300))
        .await
        .expect("the upstream answers");
    timeout(Duration::from_secs(3), closed.recv())
        .await
        .expect("past its max age and its deadline, it closes with no query coming");

    let mux = TcpMultiplexer::new(1, 0, 1, Bootstrap::system());
    let (addr, mut closed) = upstream_noting_closes(None).await;
    mux.send(&query, &addr.to_string(), Duration::from_millis(300))
        .await
        .expect("the upstream answers");
    timeout(Duration::from_secs(3), closed.recv())
        .await
        .expect("idle for a second past the deadline, it closes");
}

/// 连接空闲了 `tcp_connection_idle_timeout_seconds` 就自己关掉，不等哪个查询来查（RFC 7766 §6.2.3）；DoT 关的时候先发
/// close_notify（RFC 8446 §6.1）。以前要等下一个用到这个客户端的查询来查，池里排在后面、平常轮不到的连接靠 keepalive
/// 一直开着；关的时候也只断 TCP
/// A connection idle for `tcp_connection_idle_timeout_seconds` closes by itself, without
/// waiting for a query to look (RFC 7766 §6.2.3), DoT sending close_notify first (RFC 8446
/// §6.1). It used to wait for the next query using its client, so the connections far down a
/// pool, normally left alone, stayed open on their keepalive; and closing only cut the TCP
/// connection
#[tokio::test]
async fn an_idle_dot_connection_closes_by_itself_with_close_notify() {
    let (server, client_tls) = localhost_tls(&[]);
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // 答一个查询，再说一声连接结束得干不干净：读到 close_notify 是 Ok(0)，没有它就断了是错误
    // Answers one query, then says how the connection ended: close_notify reads as Ok(0), a
    // close without it as an error
    let (ended, mut how) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(stream).await.unwrap();
        let query = read_frame(&mut tls).await.unwrap();
        write_answer(&mut tls, &query).await.unwrap();
        let clean = matches!(tls.read(&mut [0u8; 1]).await, Ok(0));
        ended.send(clean).unwrap();
    });
    let client = DotMuxClient::with_shared(
        (Arc::new(client_tls), Bootstrap::system()),
        Arc::from(format!("dot://{addr}?sni=localhost")),
        Aging {
            idle: Some(Duration::from_millis(100)),
            ..Aging::for_tests()
        },
    );
    client
        .send(&udp_test_query("a.example"), Duration::from_millis(200))
        .await
        .expect("the upstream answers");
    let clean = timeout(Duration::from_secs(2), how.recv())
        .await
        .expect("the idle connection closes with no query coming")
        .expect("the upstream says how");
    assert!(clean, "closed with close_notify");
    assert!(!client.connected(), "the slot is cleared");
}

/// 新建的连接答了一些查询就被上游关掉，没答的查询换一条新连接重发（RFC 7766 §6.2.1.1）。以前只看连接是不是这次之前
/// 就有：这次新建的连接断了一律不重发，没答的查询跟着失败
/// A connection newly made that the upstream closes once it has answered some queries has the
/// ones left unanswered sent again on a fresh one (RFC 7766 §6.2.1.1). Whether the connection
/// was there before this send used to be all that counted: a new one breaking was never sent
/// again on, and the queries left unanswered failed with it
#[tokio::test]
async fn queries_a_closed_connection_left_unanswered_are_sent_again() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // 每条连接：200 毫秒里读到两个查询就只答第一个，然后关掉；只来了一个就照常答下去
    // On each connection: with two queries read within 200 ms only the first is answered and
    // the connection closed; with one alone it is answered and the connection goes on
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let Ok(first) = read_frame(&mut stream).await else {
                    return;
                };
                let second = timeout(Duration::from_millis(200), read_frame(&mut stream)).await;
                let _ = write_answer(&mut stream, &first).await;
                if second.is_ok() {
                    return;
                }
                while let Ok(query) = read_frame(&mut stream).await {
                    let _ = write_answer(&mut stream, &query).await;
                }
            });
        }
    });
    let client = TcpMuxClient::new(Arc::from(addr.to_string()));
    let (first, second) = (
        udp_test_query("first.example"),
        udp_test_query("second.example"),
    );
    let (first, second) = tokio::join!(
        client.send(&first, Duration::from_secs(2)),
        client.send(&second, Duration::from_secs(2)),
    );
    first.expect("answered before the close");
    second.expect("sent again on a fresh connection and answered there");
}

/// 重载换掉上游以后，旧上游的连接关闭；上游没变的重载不碰它
/// After a reload replaces the upstream, the old one's connection closes; a reload
/// that keeps the upstream leaves it alone
#[tokio::test]
async fn a_reload_closes_the_connections_of_upstreams_it_drops() {
    let (addr, mut closed) = upstream_noting_closes(None).await;
    let runtime = |upstream: &str| {
        let raw = serde_json::json!({
            "settings": { "default_upstream": "127.0.0.1:9", "upstream_timeout_ms": 2000 },
            "pipelines": [{ "id": "main", "rules": [{
                "name": "all", "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": upstream }]
            }] }]
        });
        let config: crate::config::PipelineConfig =
            serde_json::from_value(raw).expect("parse config");
        crate::matcher::RuntimePipelineConfig::from_config(config).expect("build runtime config")
    };
    let tcp_upstream = format!("tcp://{addr}");
    let engine =
        crate::engine::Engine::new(runtime(&tcp_upstream), "test".to_string()).expect("engine");
    let peer: SocketAddr = "192.0.2.10:53000".parse().unwrap();
    timeout(
        Duration::from_secs(5),
        engine.handle_packet(&udp_test_query("a.example"), peer),
    )
    .await
    .expect("answer in time")
    .expect("answer");

    engine.reload(runtime(&tcp_upstream));
    assert!(
        timeout(Duration::from_millis(300), closed.recv())
            .await
            .is_err(),
        "a reload that keeps the upstream keeps its connection"
    );
    engine.reload(runtime("udp://127.0.0.1:9"));
    timeout(Duration::from_secs(2), closed.recv())
        .await
        .expect("the dropped upstream's connection closes");
}
