//! 直连 HTTP/2 的 DoH 上游（见 `doh_h2`）：共用一条连接、没选 h2 时交给 reqwest、发出的请求和 reqwest 的一样、
//! 回答检查照旧、断了和空闲太久时重连、连续出错重建时丢掉连接
//! DoH upstreams over the direct HTTP/2 connection (see `doh_h2`): one shared connection, reqwest
//! when h2 is not picked, the same request as reqwest sends, the answer checks as before, a new
//! connection when the old one is gone or idle too long, and the connection dropped when repeated
//! errors rebuild

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode, Version};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use super::doh_h2::proxy_configured_in;
use super::transport::{DOH_MEDIA_TYPE, DohClient, throttle_of};

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
    host: Option<String>,
    content_type: Option<String>,
    accept: Option<String>,
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

/// 起一个 TLS DoH 上游：握手时报 `alpn`，每个请求的正文交给 `reply` 作答；`close_after` 个请求以后断开连接
/// Starts a DoH upstream over TLS: `alpn` offered in the handshake, each request's body answered
/// by `reply`; the connection is closed after `close_after` requests
async fn spawn_upstream(
    alpn: &[&[u8]],
    close_after: Option<usize>,
    reply: impl Fn(&[u8]) -> Response<Full<Bytes>> + Send + Sync + 'static,
) -> TlsUpstream {
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
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
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
                                let header = |name: &str| {
                                    req.headers()
                                        .get(name)
                                        .and_then(|v| v.to_str().ok())
                                        .map(str::to_string)
                                };
                                seen.lock().unwrap().push(Seen {
                                    version: req.version(),
                                    method: req.method().to_string(),
                                    path_and_query: req
                                        .uri()
                                        .path_and_query()
                                        .map(|p| p.to_string())
                                        .unwrap_or_default(),
                                    authority: req.uri().authority().map(|a| a.to_string()),
                                    host: header("host"),
                                    content_type: header("content-type"),
                                    accept: header("accept"),
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

/// 直连发出的请求和 reqwest 发的一样：方法、路径和查询串、:authority、覆盖的 Host、两个媒体类型头
/// The direct connection sends the request reqwest sends: method, path and query, :authority,
/// the Host override, and both media type headers
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

/// 回答检查在直连上照旧：429 记下暂停，错误状态、别的媒体类型、太长的正文、答非所问都算用不了的回答，不重试
/// The answer checks hold over the direct connection: a 429 notes the pause, and an error status,
/// another media type, a body too long and an answer to another question are unusable answers, not retried
#[tokio::test]
async fn answer_checks_hold_over_the_direct_connection() {
    let cases: Vec<(&str, Reply)> = vec![
        (
            "429",
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
            Box::new(|_| {
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Full::new(Bytes::new()))
                    .unwrap()
            }),
        ),
        (
            "html",
            Box::new(|q| {
                Response::builder()
                    .header("content-type", "text/html")
                    .body(Full::new(Bytes::from(echo(q))))
                    .unwrap()
            }),
        ),
        ("long", Box::new(|_| dns_ok(vec![0u8; 70_000]))),
        (
            "other question",
            Box::new(|q| {
                let mut answer = echo(q);
                let at = answer.len() - 6;
                answer[at] = b'x';
                dns_ok(answer)
            }),
        ),
    ];
    for (label, reply) in cases {
        let upstream = spawn_upstream(&[b"h2"], None, reply).await;
        let client = upstream.client(3);
        let err = ask(&client, &upstream.url(""), 1).await.expect_err(label);
        assert_eq!(
            upstream.seen.lock().unwrap().len(),
            1,
            "{label}: not retried"
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
