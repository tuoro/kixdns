//! 直连 HTTP/2 的 DoH 上游（见 `doh_h2`）：共用一条连接、忙时才分到更多连接、没选 h2 时交给 reqwest、发出的请求和 reqwest 的一样、
//! 同一轮的请求一次写完、回答检查照旧、接收窗口还给对方、断了、要走了和空闲太久时重连、连续出错重建时丢掉连接
//! DoH upstreams over the direct HTTP/2 connection (see `doh_h2`): one shared connection, more
//! only when busy, reqwest when h2 is not picked, the same request as reqwest sends, one write per round of requests, the
//! answer checks as before, the receive window handed back, a new connection when the old one is
//! gone, leaving or idle too long, and the connection dropped when repeated errors rebuild

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode, Version};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use super::doh_h2::{self, proxy_configured_in};
use super::test_support::CountedWrites;
use super::transport::{BUSY_AT, DOH_MEDIA_TYPE, DohClient, throttle_of};

#[ctor::ctor]
fn init_crypto() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// 上游看到的一个请求 / One request as the upstream saw it
#[derive(Debug, Clone, PartialEq)]
struct Seen {
    version: Version,
    method: String,
    path_and_query: String,
    authority: Option<String>,
    /// 全部请求头，按收到的顺序 / Every request header, in the order received
    headers: Vec<(String, String)>,
}

/// 本机 TLS 上的 DoH 上游 / A local DoH upstream over TLS
struct TlsUpstream {
    addr: SocketAddr,
    cert: CertificateDer<'static>,
    connections: Arc<AtomicUsize>,
    seen: Arc<std::sync::Mutex<Vec<Seen>>>,
}

impl TlsUpstream {
    fn url(&self, query: &str) -> String {
        format!("https://{}/dns-query{query}", self.addr)
    }

    fn client(&self, threshold: usize) -> DohClient {
        let mut client = DohClient::new(8, threshold).expect("doh client");
        client.trust_for_tests(self.cert.clone());
        client
    }
}

/// 标上 QR 的查询本身，当作它的回答 / The query itself with QR set, as its answer
fn echo(query: &[u8]) -> Vec<u8> {
    let mut answer = query.to_vec();
    answer[2] |= 0x80;
    answer
}

fn query(id: u16) -> Vec<u8> {
    let mut query = vec![0u8; 12];
    query[..2].copy_from_slice(&id.to_be_bytes());
    query[2] = 0x01;
    query[5] = 1;
    query.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
    query
}

fn dns_ok(body: Vec<u8>) -> Response<Full<Bytes>> {
    Response::builder()
        .header("content-type", DOH_MEDIA_TYPE)
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

/// 本机地址的自签证书和用它的 TLS 接受端，握手时报 `alpn` / A self-signed certificate for the
/// local address and a TLS acceptor using it, offering `alpn` in the handshake
fn tls_acceptor(alpn: &[&[u8]]) -> (tokio_rustls::TlsAcceptor, CertificateDer<'static>) {
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params.subject_alt_names.push(rcgen::SanType::IpAddress(
        std::net::Ipv4Addr::LOCALHOST.into(),
    ));
    let pair = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&pair).unwrap();
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pair.serialize_der()));
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key)
        .unwrap();
    tls.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    (tokio_rustls::TlsAcceptor::from(Arc::new(tls)), cert_der)
}

/// 起一个 TLS DoH 上游：握手时报 `alpn`，每个请求的正文交给 `reply` 作答；`close_after` 个请求以后断开连接
/// Starts a DoH upstream over TLS: `alpn` offered in the handshake, each request's body answered
/// by `reply`; the connection is closed after `close_after` requests
async fn spawn_upstream(
    alpn: &[&[u8]],
    close_after: Option<usize>,
    reply: impl Fn(&[u8]) -> Response<Full<Bytes>> + Send + Sync + 'static,
) -> TlsUpstream {
    let (acceptor, cert_der) = tls_acceptor(alpn);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let reply = Arc::new(reply);
    {
        let (connections, seen) = (Arc::clone(&connections), Arc::clone(&seen));
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                connections.fetch_add(1, Ordering::SeqCst);
                let (acceptor, seen, reply) =
                    (acceptor.clone(), Arc::clone(&seen), Arc::clone(&reply));
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
                    let served = Arc::new(AtomicUsize::new(0));
                    let closer = Arc::new(tokio::sync::Notify::new());
                    let conn_closed = Arc::clone(&closer);
                    let svc =
                        hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                            let (seen, reply, served, conn_closed) = (
                                Arc::clone(&seen),
                                Arc::clone(&reply),
                                Arc::clone(&served),
                                conn_closed.clone(),
                            );
                            async move {
                                seen.lock().unwrap().push(Seen {
                                    version: req.version(),
                                    method: req.method().to_string(),
                                    path_and_query: req
                                        .uri()
                                        .path_and_query()
                                        .map(|p| p.to_string())
                                        .unwrap_or_default(),
                                    authority: req.uri().authority().map(|a| a.to_string()),
                                    headers: req
                                        .headers()
                                        .iter()
                                        .map(|(name, value)| {
                                            (name.to_string(), value.to_str().unwrap().to_string())
                                        })
                                        .collect(),
                                });
                                let body = req.into_body().collect().await.unwrap().to_bytes();
                                let response = reply(&body);
                                if close_after
                                    .is_some_and(|n| served.fetch_add(1, Ordering::SeqCst) + 1 >= n)
                                {
                                    conn_closed.notify_one();
                                }
                                Ok::<_, std::convert::Infallible>(response)
                            }
                        });
                    let io = hyper_util::rt::TokioIo::new(tls);
                    if h2 {
                        let conn = hyper::server::conn::http2::Builder::new(
                            hyper_util::rt::TokioExecutor::new(),
                        )
                        .serve_connection(io, svc);
                        tokio::pin!(conn);
                        tokio::select! {
                            _ = conn.as_mut() => {}
                            () = closer.notified() => {
                                // 接着驱动连接一会儿，回答写出去了再断 / Keep driving the connection a moment, so the answer is out before it closes
                                let _ = tokio::time::timeout(Duration::from_millis(100), conn.as_mut()).await;
                            }
                        }
                    } else {
                        let conn =
                            hyper::server::conn::http1::Builder::new().serve_connection(io, svc);
                        tokio::pin!(conn);
                        tokio::select! {
                            _ = conn.as_mut() => {}
                            () = closer.notified() => {
                                let _ = tokio::time::timeout(Duration::from_millis(100), conn.as_mut()).await;
                            }
                        }
                    }
                });
            }
        });
    }
    TlsUpstream {
        addr,
        cert: cert_der,
        connections,
        seen,
    }
}

/// 上游怎么回一个请求 / How the upstream answers a request
type Reply = Box<dyn Fn(&[u8]) -> Response<Full<Bytes>> + Send + Sync>;

async fn ask(client: &DohClient, upstream: &str, id: u16) -> anyhow::Result<Bytes> {
    client
        .send(&query(id), upstream, Duration::from_secs(5))
        .await
}

/// 握手时选了 h2 的上游：前后和同时发的请求都走同一条 HTTP/2 连接，每个回答带回自己查询的 ID
/// An upstream that picks h2: requests sent one after another and at once all share one HTTP/2
/// connection, and each answer carries its own query's ID
#[tokio::test]
async fn an_h2_upstream_shares_one_connection() {
    let upstream = spawn_upstream(&[b"h2", b"http/1.1"], None, |q| dns_ok(echo(q))).await;
    let client = upstream.client(3);
    let url = upstream.url("");
    for id in 0..20u16 {
        assert_eq!(ask(&client, &url, id).await.unwrap()[..2], id.to_be_bytes());
    }
    let together = (100..140u16).map(|id| {
        let (client, url) = (&client, &url);
        async move { (id, ask(client, url, id).await.unwrap()) }
    });
    for (id, answer) in futures::future::join_all(together).await {
        assert_eq!(answer[..2], id.to_be_bytes());
    }
    assert!(
        client.has_direct_connection(&url),
        "asked over the direct connection"
    );
    assert_eq!(upstream.connections.load(Ordering::SeqCst), 1);
    assert!(
        upstream
            .seen
            .lock()
            .unwrap()
            .iter()
            .all(|seen| seen.version == Version::HTTP_2)
    );
}

/// 握手时没选 h2 的上游照旧经 reqwest（HTTP/1.1）问；只试探一次，之后不再为直连多开连接
/// An upstream that does not pick h2 is asked through reqwest (HTTP/1.1) as before; it is probed
/// once, and no further connections are opened for the direct path
#[tokio::test]
async fn an_upstream_without_h2_goes_through_reqwest() {
    let upstream = spawn_upstream(&[b"http/1.1"], None, |q| dns_ok(echo(q))).await;
    let client = upstream.client(3);
    let url = upstream.url("");
    for id in 0..10u16 {
        assert_eq!(ask(&client, &url, id).await.unwrap()[..2], id.to_be_bytes());
    }
    assert!(
        upstream
            .seen
            .lock()
            .unwrap()
            .iter()
            .all(|seen| seen.version == Version::HTTP_11)
    );
    assert!(!client.has_direct_connection(&url));
    // 一条是直连试探时开的，一条是 reqwest 连接池里的 / One opened by the direct probe, one in reqwest's pool
    assert_eq!(upstream.connections.load(Ordering::SeqCst), 2);
}

/// 直连发出的请求和 reqwest 发的一样：方法、路径和查询串、:authority，全部请求头（覆盖的 Host、两个媒体类型头、
/// content-length）连同顺序
/// The direct connection sends the request reqwest sends: method, path and query, :authority,
/// and every request header (the Host override, both media type headers, content-length) in
/// the same order
#[tokio::test]
async fn the_direct_request_is_the_one_reqwest_sends() {
    let upstream = spawn_upstream(&[b"h2", b"http/1.1"], None, |q| dns_ok(echo(q))).await;
    for query_string in ["", "?host=front.example", "?ct&host=front.example&x=1"] {
        let url = upstream.url(query_string);
        let direct = upstream.client(3);
        let mut via_reqwest = upstream.client(3);
        via_reqwest.reqwest_only_for_tests();
        ask(&direct, &url, 1).await.unwrap();
        ask(&via_reqwest, &url, 2).await.unwrap();
        assert!(direct.has_direct_connection(&url), "{query_string}");
        assert!(!via_reqwest.has_direct_connection(&url), "{query_string}");
        let seen = upstream.seen.lock().unwrap().split_off(0);
        assert_eq!(seen.len(), 2, "{query_string}");
        assert_eq!(seen[0], seen[1], "{query_string}");
        assert_eq!(seen[0].version, Version::HTTP_2);
    }
}

/// 读完一个请求的正文，读到的接收窗口随手还给对方 / Reads a request body to its end, handing the receive window back as it goes
async fn read_body(mut body: h2::RecvStream) -> Vec<u8> {
    let mut read = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.unwrap();
        body.flow_control().release_capacity(chunk.len()).unwrap();
        read.extend_from_slice(&chunk);
    }
    read
}

/// 读完请求，等 `after` 以后用它的回声作答 / Reads the request, then answers with its echo after `after`
async fn answer_after(
    request: Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    after: Duration,
) {
    let query = read_body(request.into_body()).await;
    tokio::time::sleep(after).await;
    let head = Response::builder()
        .header("content-type", DOH_MEDIA_TYPE)
        .body(())
        .unwrap();
    let mut body = respond.send_response(head, false).unwrap();
    body.send_data(Bytes::from(echo(&query)), true).unwrap();
}

/// 同一轮里发起的请求连同各自的正文，一次写出去：上游不用等第二次写才收齐一个请求（hyper 的客户端总是先单独
/// 写请求头），连接也不会一个请求写一次（tokio 让刚被叫醒的连接任务插到最前面先跑）。一个工作线程，请求任务
/// 都从这个线程上起，和收到一批 UDP 查询时一样
/// The requests started in one round, each with its body, leave in one write: the upstream does
/// not wait for a second write to have a request (hyper's client always writes the head alone
/// first), and the connection does not write once per request (tokio runs the connection task it
/// was just woken for first). One worker thread, with the request tasks started on it, as when a
/// batch of UDP queries arrives
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn requests_of_one_round_go_out_in_one_write() {
    let (client_io, server_io) = tokio::io::duplex(1 << 16);
    tokio::spawn(async move {
        let mut conn = h2::server::handshake(server_io).await.unwrap();
        while let Some(accepted) = conn.accept().await {
            let (request, respond) = accepted.unwrap();
            tokio::spawn(answer_after(request, respond, Duration::ZERO));
        }
    });
    let writes = Arc::new(AtomicUsize::new(0));
    let sender = doh_h2::handshake(CountedWrites {
        io: client_io,
        writes: Arc::clone(&writes),
    })
    .await
    .unwrap();
    // 数完之前连接一直开着：发送端都没了，连接会发 GOAWAY 关掉，那也是一次写
    // The connection stays open until the count is taken: with every sender gone it would send
    // a GOAWAY and close, another write
    let keep_open = sender.clone();
    let ask = move |id: u16| {
        let request = Request::post("https://upstream.example/dns-query")
            .body(())
            .unwrap();
        let sent = doh_h2::send(sender.clone(), request, Bytes::from(query(id)));
        async move {
            let answer = sent.await.unwrap().into_body().collect().await.unwrap();
            answer.to_bytes()
        }
    };
    // 第一个请求让两边把设置和确认都交换完 / The first request lets both sides finish exchanging settings and acknowledgements
    tokio::spawn(ask(0)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let before = writes.load(Ordering::SeqCst);
    let answers = tokio::spawn(async move {
        let asked: Vec<_> = (1..=8u16).map(|id| tokio::spawn(ask(id))).collect();
        futures::future::join_all(asked).await
    })
    .await
    .unwrap();
    for (id, answer) in (1..=8u16).zip(answers) {
        assert_eq!(answer.unwrap()[..2], id.to_be_bytes());
    }
    assert_eq!(writes.load(Ordering::SeqCst) - before, 1);
    drop(keep_open);
}

/// 起一个 h2 的 TLS DoH 上游，每个请求过 `after` 再答 / Starts an h2 DoH upstream over TLS answering each request after `after`
async fn spawn_h2_upstream_answering_after(after: Duration) -> TlsUpstream {
    let (acceptor, cert) = tls_acceptor(&[b"h2"]);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = TlsUpstream {
        addr: listener.local_addr().unwrap(),
        cert,
        connections: Arc::new(AtomicUsize::new(0)),
        seen: Arc::default(),
    };
    let connections = Arc::clone(&upstream.connections);
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            connections.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let tls = acceptor.accept(tcp).await.unwrap();
                let mut conn = h2::server::handshake(tls).await.unwrap();
                while let Some(accepted) = conn.accept().await {
                    let (request, respond) = accepted.unwrap();
                    tokio::spawn(answer_after(request, respond, after));
                }
            });
        }
    });
    upstream
}

/// 同时问 `ids` 里的每一个，各自的回答都带回自己查询的 ID / Asks for each of `ids` at once; each answer carries its own query's ID
async fn ask_together(client: &DohClient, url: &str, ids: std::ops::Range<u16>) {
    let together = ids.map(|id| async move { (id, ask(client, url, id).await.unwrap()) });
    for (id, answer) in futures::future::join_all(together).await {
        assert_eq!(answer[..2], id.to_be_bytes());
    }
}

/// 平常只用一条连接：一个接一个的查询，和一阵子同时到、但没多到让连接忙起来的查询，都在第一条连接上。
/// 别的位不去连，也就不会隔太久没用、每次都要重新握手
/// Normally one connection is used: queries one after another, and a burst of them at once
/// that is not enough to make the connection busy, all go on the first. The other slots do not
/// connect, so none sits idle long enough to need a fresh handshake each time
#[tokio::test]
async fn light_load_stays_on_one_connection() {
    let upstream = spawn_h2_upstream_answering_after(Duration::from_millis(20)).await;
    let mut client = upstream.client(3);
    client.set_direct_connections_for_tests(4);
    let url = upstream.url("");
    for id in 0..10u16 {
        assert_eq!(ask(&client, &url, id).await.unwrap()[..2], id.to_be_bytes());
    }
    ask_together(&client, &url, 100..100 + BUSY_AT as u16 - 1).await;
    assert_eq!(upstream.connections.load(Ordering::SeqCst), 1);
    assert_eq!(client.direct_in_flight(&url), 0, "every request let go");
}

/// 第一条连接上同时在途的请求到了 `BUSY_AT` 个，再来的上下一条，那条也忙了再下一条
/// Once the first connection has `BUSY_AT` requests in flight, further ones go to the next,
/// and once that one is busy too, to the one after
#[tokio::test]
async fn a_busy_connection_spills_to_the_next() {
    let upstream = spawn_h2_upstream_answering_after(Duration::from_millis(200)).await;
    let mut client = upstream.client(3);
    client.set_direct_connections_for_tests(4);
    let url = upstream.url("");
    let many = 2 * BUSY_AT + BUSY_AT / 2;
    ask_together(&client, &url, 0..many as u16).await;
    assert_eq!(upstream.connections.load(Ordering::SeqCst), 3);
    assert_eq!(client.direct_in_flight(&url), 0, "every request let go");
}

/// 回答加起来超过连接的接收窗口以后照样答上：读到的窗口都还给了对方
/// Answers keep coming once they add up past the connection's receive window: what was read
/// went back to the peer
#[tokio::test]
async fn answers_keep_coming_past_the_receive_window() {
    let upstream = spawn_upstream(&[b"h2"], None, |q| {
        let mut answer = echo(q);
        answer.resize(60_000, 0);
        dns_ok(answer)
    })
    .await;
    let client = upstream.client(3);
    let url = upstream.url("");
    // 40 个 60 KB 的回答，是连接窗口的两倍多 / Forty 60 KB answers, over twice the connection window
    for id in 0..40u16 {
        let answer = ask(&client, &url, id).await.unwrap();
        assert_eq!(
            (answer.len(), &answer[..2]),
            (60_000, &id.to_be_bytes()[..])
        );
    }
    assert_eq!(upstream.connections.load(Ordering::SeqCst), 1);
}

/// 上游发来 GOAWAY 以后，新请求另连一条，不上这条要走的连接；这条连接上还没答完的请求照样答完
/// Once the upstream sends a GOAWAY, a new request opens another connection instead of the one
/// that is leaving; the request still being answered there is answered all the same
#[tokio::test]
async fn a_leaving_connection_takes_no_new_requests() {
    let (acceptor, cert) = tls_acceptor(&[b"h2"]);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = TlsUpstream {
        addr: listener.local_addr().unwrap(),
        cert,
        connections: Arc::new(AtomicUsize::new(0)),
        seen: Arc::default(),
    };
    let connections = Arc::clone(&upstream.connections);
    let leaving = Arc::new(tokio::sync::Notify::new());
    let left = Arc::clone(&leaving);
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let first = connections.fetch_add(1, Ordering::SeqCst) == 0;
            let (acceptor, left) = (acceptor.clone(), Arc::clone(&left));
            tokio::spawn(async move {
                let tls = acceptor.accept(tcp).await.unwrap();
                let mut conn = h2::server::handshake(tls).await.unwrap();
                while let Some(accepted) = conn.accept().await {
                    let (request, respond) = accepted.unwrap();
                    // 第一条连接一收到请求就发 GOAWAY，回答晚点给，所以答完之前连接一直开着
                    // The first connection sends a GOAWAY as soon as a request arrives and
                    // answers late, so it stays open until then
                    let after = if first {
                        conn.graceful_shutdown();
                        left.notify_one();
                        Duration::from_millis(500)
                    } else {
                        Duration::ZERO
                    };
                    tokio::spawn(answer_after(request, respond, after));
                }
            });
        }
    });
    let client = upstream.client(3);
    let url = upstream.url("");
    let later = async {
        // 等 GOAWAY 到了客户端再问 / Ask once the GOAWAY has reached the client
        leaving.notified().await;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while client.has_direct_connection(&url) {
            assert!(tokio::time::Instant::now() < deadline, "no GOAWAY seen");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        ask(&client, &url, 2).await
    };
    let (first, second) = tokio::join!(ask(&client, &url, 1), later);
    assert_eq!(first.unwrap()[..2], 1u16.to_be_bytes());
    assert_eq!(second.unwrap()[..2], 2u16.to_be_bytes());
    assert_eq!(upstream.connections.load(Ordering::SeqCst), 2);
}

/// 回答检查在直连上照旧：429 记下暂停，错误状态、别的媒体类型、太长的正文、答非所问都算用不了的回答，当场报出
/// 原因，不重试（太长的正文不该卡在接收窗口上等到超时）
/// The answer checks hold over the direct connection: a 429 notes the pause, and an error status,
/// another media type, a body too long and an answer to another question are unusable answers,
/// reported at once with the reason and not retried (a body too long must not stall on the
/// receive window until the timeout)
#[tokio::test]
async fn answer_checks_hold_over_the_direct_connection() {
    // 标签、错误里该有的原因、上游怎么回 / Label, the reason the error has to give, how the upstream answers
    let cases: Vec<(&str, &str, Reply)> = vec![
        (
            "429",
            "status 429",
            Box::new(|_| {
                Response::builder()
                    .status(StatusCode::TOO_MANY_REQUESTS)
                    .header("retry-after", "7")
                    .body(Full::new(Bytes::new()))
                    .unwrap()
            }),
        ),
        (
            "500",
            "status 500",
            Box::new(|_| {
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Full::new(Bytes::new()))
                    .unwrap()
            }),
        ),
        (
            "html",
            "not application/dns-message but text/html",
            Box::new(|q| {
                Response::builder()
                    .header("content-type", "text/html")
                    .body(Full::new(Bytes::from(echo(q))))
                    .unwrap()
            }),
        ),
        (
            "long",
            "longer than 65535 bytes",
            Box::new(|_| dns_ok(vec![0u8; 70_000])),
        ),
        (
            "other question",
            "does not answer the query",
            Box::new(|q| {
                let mut answer = echo(q);
                let at = answer.len() - 6;
                answer[at] = b'x';
                dns_ok(answer)
            }),
        ),
    ];
    for (label, reason, reply) in cases {
        let upstream = spawn_upstream(&[b"h2"], None, reply).await;
        let client = upstream.client(3);
        let err = ask(&client, &upstream.url(""), 1).await.expect_err(label);
        assert!(format!("{err:#}").contains(reason), "{label}: {err:#}");
        assert_eq!(
            upstream.seen.lock().unwrap().len(),
            1,
            "{label}: not retried"
        );
        assert_eq!(
            client.direct_in_flight(&upstream.url("")),
            0,
            "{label}: the failed request let go"
        );
        let throttle = throttle_of(&err);
        if label == "429" {
            assert_eq!(throttle.expect("throttle").pause, Duration::from_secs(7));
        } else {
            assert!(throttle.is_none(), "{label}");
        }
    }
}

/// 上游关掉连接以后，下一个请求连一条新的，照样答上 / Once the upstream closes the connection, the next request opens a new one and is answered
#[tokio::test]
async fn a_closed_connection_is_replaced() {
    let upstream = spawn_upstream(&[b"h2"], Some(1), |q| dns_ok(echo(q))).await;
    let client = upstream.client(3);
    let url = upstream.url("");
    ask(&client, &url, 1).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        ask(&client, &url, 2).await.unwrap()[..2],
        2u16.to_be_bytes()
    );
    assert_eq!(upstream.connections.load(Ordering::SeqCst), 2);
}

/// 空闲超过时限的连接不再用：NAT 可能早就忘了它 / A connection idle past the limit is not used again: a NAT may long have forgotten it
#[tokio::test]
async fn an_idle_connection_is_not_reused() {
    let upstream = spawn_upstream(&[b"h2"], None, |q| dns_ok(echo(q))).await;
    let mut client = upstream.client(3);
    client.set_idle_timeout_for_tests(Duration::from_millis(150));
    let url = upstream.url("");
    ask(&client, &url, 1).await.unwrap();
    ask(&client, &url, 2).await.unwrap();
    assert_eq!(upstream.connections.load(Ordering::SeqCst), 1);
    tokio::time::sleep(Duration::from_millis(300)).await;
    ask(&client, &url, 3).await.unwrap();
    assert_eq!(upstream.connections.load(Ordering::SeqCst), 2);
}

/// 连续出错到阈值重建时，直连的连接也一起丢掉，下一个请求重新连
/// When repeated errors reach the threshold and rebuild, the direct connection goes too and the
/// next request connects again
#[tokio::test]
async fn a_rebuild_drops_the_direct_connection() {
    let upstream = spawn_upstream(&[b"h2"], None, |q| dns_ok(echo(q))).await;
    let client = upstream.client(1);
    let url = upstream.url("");
    ask(&client, &url, 1).await.unwrap();
    assert!(client.record_error_of(&url), "rebuilt at the threshold");
    ask(&client, &url, 2).await.unwrap();
    assert_eq!(upstream.connections.load(Ordering::SeqCst), 2);
}

/// 设了 https 或 all 代理时不直连（reqwest 会走代理），只设 http 代理、或设成空串时照旧直连
/// With an https or all proxy set there is no direct connection (reqwest goes through the proxy);
/// with only an http proxy, or an empty value, the direct connection stays
#[test]
fn a_proxy_keeps_everything_on_reqwest() {
    let env = |pairs: &'static [(&'static str, &'static str)]| {
        move |name: &str| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| std::ffi::OsString::from(value))
        }
    };
    assert!(!proxy_configured_in(env(&[])));
    assert!(proxy_configured_in(env(&[(
        "HTTPS_PROXY",
        "http://proxy:3128"
    )])));
    assert!(proxy_configured_in(env(&[(
        "https_proxy",
        "http://proxy:3128"
    )])));
    assert!(proxy_configured_in(env(&[(
        "ALL_PROXY",
        "socks5://proxy:1080"
    )])));
    assert!(proxy_configured_in(env(&[(
        "all_proxy",
        "socks5://proxy:1080"
    )])));
    assert!(!proxy_configured_in(env(&[(
        "HTTP_PROXY",
        "http://proxy:3128"
    )])));
    assert!(!proxy_configured_in(env(&[("HTTPS_PROXY", "")])));
}
