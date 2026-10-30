//! DoH (DNS over HTTPS) inbound server — RFC 8484
//!
//! 架构：TLS terminator → HTTP/1.1 handler → Engine 入口
//! 完全复用 Engine 的 `handle_packet_fast` / `handle_packet_internal_with_pre_parsed`，
//! 不重复任何 DNS 处理逻辑。
//! TLS 证书/私钥文件变更时热更新 acceptor（如 acme 续期），失败保持旧证书。

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use anyhow::Context;
use arc_swap::ArcSwap;
use bytes::Bytes;
#[cfg(test)]
use hickory_proto::op::{Message, ResponseCode};
#[cfg(test)]
use hickory_proto::serialize::binary::BinDecodable;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::Body;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::engine::{Engine, FastPathResponse, engine_helpers, write_cache_hit};
use crate::observe::ClientTransport;
use crate::watcher;

const MAX_DNS_MESSAGE: usize = 64 * 1024;

/// 客户端发送完整请求头的时限，也覆盖 keep-alive 连接上等待下一个请求的空闲期；
/// 到期由 hyper 关闭连接。RFC 7766 §6.2.3 建议 DNS 服务端对空闲连接设数秒量级
/// 的超时：10 s 足以让慢链路发完请求头，又不让只发半个请求头的连接无限期占用
/// 一个任务和一个文件描述符。
/// Time a client has to send a complete request head, which also bounds the
/// idle wait for the next request on a keep-alive connection; hyper closes the
/// connection when it expires. RFC 7766 §6.2.3 recommends a DNS server idle
/// timeout in the order of seconds: 10 s leaves a slow link room to finish a
/// request head while keeping half-sent requests from pinning a task and a
/// file descriptor indefinitely.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// POST 请求头之后，客户端最多有这么久发完正文；超时回 408、断开连接。以前只有请求头有时限，
/// 正文发到一半就停的连接会一直占着一个任务和一个文件描述符。
/// Time a client has, once a POST head is in, to send the whole body; past it the
/// server answers 408 and drops the connection. Only the head used to be bounded,
/// so a body that stopped half way held a task and a file descriptor for good.
const BODY_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// A client that connects and never finishes the TLS handshake is dropped after
/// this long, as a silent DNS-over-TCP client is; it used to hold its task and
/// descriptor for good.
/// 连上以后迟迟不完成 TLS 握手的客户端，过这么久就断开，和 DNS over TCP 上不说话的客户端一样；
/// 以前它会一直占着任务和句柄。
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// TLS acceptor shared between the accept loop and the certificate watcher:
/// wait-free snapshot per connection, swapped wholesale on reload — the same
/// hot-reload pattern as Engine's `Arc<ArcSwap<...>>` state.
type SharedTlsAcceptor = Arc<ArcSwap<TlsAcceptor>>;

/// 启动 DoH 服务器 / Start DoH server
pub async fn run_doh(
    addr: SocketAddr,
    cert_path: &str,
    key_path: &str,
    engine: Engine,
    doh_path: String,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await.context("bind doh tcp")?;
    info!(%addr, %doh_path, "DoH server listening");
    run_doh_with_listener(listener, cert_path, key_path, engine, doh_path).await
}

/// 从已绑定的 TcpListener 启动 DoH 服务器（便于测试获取实际端口）
/// Start DoH server from a pre-bound TcpListener (allows tests to discover the actual port)
pub async fn run_doh_with_listener(
    listener: TcpListener,
    cert_path: &str,
    key_path: &str,
    engine: Engine,
    doh_path: String,
) -> anyhow::Result<()> {
    let engine = engine.with_client_transport(ClientTransport::Doh);
    let acceptor: SharedTlsAcceptor = Arc::new(ArcSwap::from_pointee(build_tls_acceptor(
        cert_path, key_path,
    )?));

    // 证书文件变更时热更新 TLS acceptor；重载失败保持旧证书继续服务
    // Hot-reload the TLS acceptor on cert/key file changes; keep the previous certificate on failure
    spawn_cert_watcher(cert_path, key_path, Arc::clone(&acceptor));

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                // Never end the loop on an accept error (see accept_retry_delay)
                // 接受出错不退出循环（见 accept_retry_delay）
                warn!(error = %err, "DoH accept failed, retrying");
                tokio::time::sleep(crate::socket_utils::accept_retry_delay(&err)).await;
                continue;
            }
        };
        // Snapshot the current acceptor for this connection; in-flight
        // connections keep serving with the certificate they were established with.
        let acceptor = acceptor.load_full();
        let engine = engine.clone();
        let doh_path = doh_path.clone();
        tokio::spawn(async move {
            match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                Ok(Ok(tls_stream)) => {
                    // hyper 1.x 需要 TokioIo 适配器包装 IO
                    let io = hyper_util::rt::TokioIo::new(tls_stream);
                    let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                        let engine = engine.clone();
                        let doh_path = doh_path.clone();
                        async move { handle_doh_request(req, peer, engine, &doh_path).await }
                    });
                    // hyper 只在装了 timer 时才执行 header_read_timeout，否则静默
                    // 禁用；TokioTimer 是零大小类型，每连接无额外开销。
                    // hyper only enforces header_read_timeout when a timer is
                    // installed and silently disables it otherwise; TokioTimer is
                    // zero-sized, so this costs nothing per connection.
                    let _ = http1::Builder::new()
                        .timer(hyper_util::rt::TokioTimer::new())
                        .header_read_timeout(HEADER_READ_TIMEOUT)
                        .keep_alive(true)
                        .serve_connection(io, svc)
                        .await;
                }
                Ok(Err(e)) => {
                    warn!(error = %e, "DoH TLS handshake failed");
                }
                Err(_) => {
                    // Quiet, like a silent DNS-over-TCP client timing out: a flood of
                    // them must not flood the log as well
                    // 不出声，和 DNS over TCP 上不说话的客户端超时一样：一大批这样的连接不能把日志也刷满
                    debug!(%peer, "DoH TLS handshake timed out");
                }
            }
        });
    }
}

/// 处理单个 DoH 请求 / Handle a single DoH request
async fn handle_doh_request(
    req: Request<hyper::body::Incoming>,
    peer: SocketAddr,
    engine: Engine,
    doh_path: &str,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    // RFC 8484 §4.1: POST with application/dns-message
    // RFC 8484 §4.1.5: GET with ?dns=base64url
    let dns_wire = match (req.method(), req.uri().path()) {
        (&Method::POST, path) if path == doh_path => {
            // 先看 Content-Length：声明超限的请求一个字节都不读；再用 Limited 给
            // body 本身封顶，分块传输或与声明不符的发送方也只能让服务端缓冲
            // MAX_DNS_MESSAGE 字节。此前 body 先被整个收进内存再比较长度。
            // Check Content-Length first so a request that declares an oversized
            // body is refused without reading any of it, then cap the body itself
            // so chunked or lying senders cannot make the server buffer more than
            // MAX_DNS_MESSAGE. Previously the whole body was collected before the
            // length was compared.
            let declared = req.body().size_hint().exact();
            if declared.is_some_and(|len| len > MAX_DNS_MESSAGE as u64) {
                return Ok(error_response(StatusCode::PAYLOAD_TOO_LARGE));
            }
            let body = Limited::new(req.into_body(), MAX_DNS_MESSAGE).collect();
            match tokio::time::timeout(BODY_READ_TIMEOUT, body).await {
                Ok(Ok(collected)) => collected.to_bytes(),
                Ok(Err(err)) if err.is::<LengthLimitError>() => {
                    return Ok(error_response(StatusCode::PAYLOAD_TOO_LARGE));
                }
                Ok(Err(_)) => return Ok(error_response(StatusCode::BAD_REQUEST)),
                Err(_) => return Ok(error_response(StatusCode::REQUEST_TIMEOUT)),
            }
        }
        (&Method::GET, path) if path == doh_path => {
            match extract_get_dns_param(req.uri().query().unwrap_or("")) {
                Some(data) => data,
                None => return Ok(error_response(StatusCode::BAD_REQUEST)),
            }
        }
        _ => return Ok(error_response(StatusCode::NOT_FOUND)),
    };

    // 和 UDP、TCP 一样只回答标准查询：QR=1 的应答、问题数不是 1、opcode 不是 0 等不是查询。UDP 丢掉它们、
    // TCP 断开，DoH 回 400，和报文太短时一样
    // As over UDP and TCP, only a standard query is answered: a response with QR=1, a
    // question count other than 1, an opcode other than 0 and so on are no queries. UDP
    // drops them and TCP closes; DoH says 400, as for a message too short
    if !crate::proto_utils::is_standard_query_header(&dns_wire) {
        return Ok(error_response(StatusCode::BAD_REQUEST));
    }

    // ✅ 复用 Engine 公共入口 — 与 TCP/UDP 入站完全一致
    let resp = process_dns_wire(&dns_wire, peer, &engine).await;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/dns-message")
        .header("cache-control", "max-age=0")
        .body(Full::new(resp))
        .unwrap())
}

/// 从 GET ?dns=base64url 提取 DNS 报文 / Extract DNS wire from GET ?dns=base64url
fn extract_get_dns_param(query: &str) -> Option<Bytes> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    for pair in query.split('&') {
        if let Some(val) = pair.strip_prefix("dns=") {
            let decoded = URL_SAFE_NO_PAD.decode(val).ok()?;
            if !decoded.is_empty() {
                return Some(Bytes::from(decoded));
            }
        }
    }
    None
}

/// 处理 DNS wire 报文，返回响应 bytes
/// 完全复用 Engine 的 handle_packet_fast 快速路径 + handle_packet 完整路径
async fn process_dns_wire(packet: &[u8], peer: SocketAddr, engine: &Engine) -> Bytes {
    let pre_parsed = match engine.handle_packet_fast(packet, peer) {
        Ok(Some(FastPathResponse::Direct(bytes))) => return bytes,
        Ok(Some(FastPathResponse::CacheHit {
            cached,
            tx_id,
            inserted_at,
        })) => {
            let mut answer = bytes::BytesMut::new();
            write_cache_hit(&mut answer, &cached, tx_id, inserted_at);
            return answer.freeze();
        }
        Ok(Some(FastPathResponse::AsyncNeeded(pre_parsed))) => Some(pre_parsed),
        // 快速解析失败，回退到完整处理 / Fast parse failed, fallback to full processing
        Ok(None) => None,
        Err(error) => {
            engine.log_fast_path_error(&error);
            return empty_dns_response(packet);
        }
    };
    engine
        .answer_after_fast_path(packet, peer, pre_parsed)
        .await
        .unwrap_or_else(|| empty_dns_response(packet))
}

/// 构造空 DNS 响应（SERVFAIL） / Build empty SERVFAIL response
fn empty_dns_response(request: &[u8]) -> Bytes {
    engine_helpers::build_servfail_response_from_wire(request)
}

fn error_response(status: StatusCode) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

/// Build the TLS acceptor from PEM cert/key files. Single source of truth for
/// both startup and hot reload, so the two paths validate identically.
fn build_tls_acceptor(cert_path: &str, key_path: &str) -> anyhow::Result<TlsAcceptor> {
    let certs = load_certs(cert_path)?;
    anyhow::ensure!(!certs.is_empty(), "no certificates found in {cert_path}");
    let key = load_private_key(key_path)?;

    let tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .with_context(|| format!("build TLS server config (cert: {cert_path}, key: {key_path})"))?;
    Ok(TlsAcceptor::from(Arc::new(tls_config)))
}

/// 监听证书/私钥文件变更并热更新 TLS acceptor（阻塞线程，与 config watcher 生命周期一致）
/// Watch cert/key files and rebuild the TLS acceptor on change (blocking thread,
/// mirroring the config watcher lifecycle).
fn spawn_cert_watcher(cert_path: &str, key_path: &str, acceptor: SharedTlsAcceptor) {
    let paths = vec![PathBuf::from(cert_path), PathBuf::from(key_path)];
    let cert = cert_path.to_string();
    let key = key_path.to_string();
    thread::spawn(move || {
        let result = watcher::run_files_watcher(&paths, || {
            if let Some(new_acceptor) =
                watcher::load_with_retry("DoH TLS certificate", || build_tls_acceptor(&cert, &key))
            {
                acceptor.store(Arc::new(new_acceptor));
                info!(target = "doh", cert = %cert, key = %key, "DoH TLS certificate reloaded");
            }
        });
        if let Err(err) = result {
            error!(target = "doh", error = %err, "DoH certificate watcher exited with error");
        }
    });
}

/// 从 PEM 文件加载证书 / Load certificates from PEM file
fn load_certs(path: &str) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    CertificateDer::pem_file_iter(path)
        .context("open cert file")?
        .collect::<Result<Vec<_>, _>>()
        .context("parse PEM certificates")
}

/// 从 PEM 文件加载私钥 / Load private key from PEM file
fn load_private_key(path: &str) -> anyhow::Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_file(path).context("parse PEM private key")
}

// ============================================================================
// Tests / 单元测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    /// Install rustls crypto provider for tests that create Engine (which internally creates TLS clients).
    #[ctor::ctor]
    fn init_crypto() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

    // ---- extract_get_dns_param ----

    #[test]
    fn test_extract_get_dns_param_valid() {
        // A minimal DNS query for example.com A record
        let dns_wire = [
            0xAB, 0xCD, // TXID
            0x01, 0x00, // Flags: standard query, RD=1
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
            // Question: example.com A IN
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm',
            0, // null terminator
            0x00, 0x01, // QTYPE = A
            0x00, 0x01, // QCLASS = IN
        ];
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(dns_wire);
        let query = format!("dns={encoded}");
        let result = extract_get_dns_param(&query);
        assert!(result.is_some(), "should decode valid base64url");
        assert_eq!(result.unwrap().as_ref(), &dns_wire[..]);
    }

    #[test]
    fn test_extract_get_dns_param_missing_param() {
        assert!(extract_get_dns_param("foo=bar").is_none());
        assert!(extract_get_dns_param("").is_none());
    }

    #[test]
    fn test_extract_get_dns_param_empty_value() {
        assert!(extract_get_dns_param("dns=").is_none());
        assert!(extract_get_dns_param("dns=&foo=bar").is_none());
    }

    #[test]
    fn test_extract_get_dns_param_multiple_params() {
        let dns_wire = [0x00; 12];
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(dns_wire);
        // dns= should be found among multiple params
        let query = format!("foo=bar&dns={encoded}&baz=qux");
        let result = extract_get_dns_param(&query);
        assert!(result.is_some());
        assert_eq!(result.unwrap().as_ref(), &dns_wire[..]);
    }

    #[test]
    fn test_extract_get_dns_param_invalid_base64() {
        assert!(extract_get_dns_param("dns=!!!invalid").is_none());
    }

    #[test]
    fn test_extract_get_dns_param_standard_base64url_no_pad() {
        // RFC 8484 uses base64url without padding
        let dns_wire = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x12];
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(dns_wire);
        let result = extract_get_dns_param(&format!("dns={encoded}"));
        assert!(result.is_some());
    }

    // ---- empty_dns_response ----

    #[test]
    fn test_empty_dns_response_preserves_txid() {
        let request = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let resp = empty_dns_response(&request);
        assert_eq!(resp.len(), 12);
        assert_eq!(resp[0], 0x12, "TXID high byte preserved");
        assert_eq!(resp[1], 0x34, "TXID low byte preserved");
    }

    #[test]
    fn test_empty_dns_response_qr_and_rcode() {
        let request = [0xAB, 0xCD];
        let resp = empty_dns_response(&request);
        assert_eq!(resp.len(), 12);
        // Byte 2: QR=1, Opcode=0, AA=0, TC=0, RD=0 → 0x80
        assert_eq!(resp[2], 0x80, "QR should be 1");
        // Byte 3: RA=1, Z=0, RCODE=2 (SERVFAIL) → 0x82
        assert_eq!(resp[3], 0x82, "RA and SERVFAIL should be set");
    }

    #[test]
    fn test_empty_dns_response_short_input() {
        let resp = empty_dns_response(&[0xFF]);
        assert!(resp.is_empty(), "input < 2 bytes should return empty");
        let resp = empty_dns_response(&[]);
        assert!(resp.is_empty());
    }

    #[test]
    fn test_empty_dns_response_preserves_question() {
        let request = make_dns_query_a("question.example.com", 0x1234);
        let response = empty_dns_response(&request);
        let decoded = Message::from_bytes(&response).expect("decode SERVFAIL response");

        assert_eq!(decoded.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(decoded.queries.len(), 1);
        assert_eq!(decoded.queries[0].name().to_utf8(), "question.example.com.");
    }

    // ---- error_response ----

    #[test]
    fn test_error_response_status() {
        let resp = error_response(StatusCode::NOT_FOUND);
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let resp = error_response(StatusCode::BAD_REQUEST);
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let resp = error_response(StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    // ---- process_dns_wire (with static-response Engine) ----

    fn make_static_engine(rcode: &str) -> Engine {
        use crate::config::PipelineConfig;
        use crate::matcher::RuntimePipelineConfig;

        let raw = serde_json::json!({
            "settings": { "default_upstream": "127.0.0.1:5300" },
            "pipelines": [
                {
                    "id": "p",
                    "rules": [
                        {
                            "name": "static",
                            "matchers": [ { "type": "any" } ],
                            "actions": [ { "type": "static_response", "rcode": rcode } ]
                        }
                    ]
                }
            ]
        });
        let cfg: PipelineConfig = serde_json::from_value(raw).expect("parse config");
        let runtime = RuntimePipelineConfig::from_config(cfg).expect("build runtime");
        Engine::new(runtime, "test".to_string()).expect("initialize test engine")
    }

    fn make_dns_query_a(domain: &str, txid: u16) -> Vec<u8> {
        use hickory_proto::op::{Message, OpCode, Query};
        use hickory_proto::rr::{Name, RecordType};
        use std::str::FromStr;

        let mut msg = Message::new(txid, hickory_proto::op::MessageType::Query, OpCode::Query);
        msg.add_query(Query::query(Name::from_str(domain).unwrap(), RecordType::A));
        msg.to_vec().unwrap()
    }

    #[tokio::test]
    async fn test_process_dns_wire_static_nxdomain() {
        let engine = make_static_engine("NXDOMAIN");
        let query = make_dns_query_a("test.example.com", 0x4242);
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let resp = process_dns_wire(&query, peer, &engine).await;

        // Should be a valid DNS response
        assert!(resp.len() >= 12, "response should be >= 12 bytes");
        // TXID preserved
        assert_eq!(resp[0], 0x42, "TXID high byte preserved");
        assert_eq!(resp[1], 0x42, "TXID low byte preserved");
        // QR=1
        assert_eq!(resp[2] & 0x80, 0x80, "QR bit should be set");
        // RCODE = NXDOMAIN (3)
        assert_eq!(resp[3] & 0x0F, 0x03, "RCODE should be NXDOMAIN (3)");
    }

    #[tokio::test]
    async fn test_process_dns_wire_static_noerror() {
        let engine = make_static_engine("NOERROR");
        let query = make_dns_query_a("ok.example.com", 0x0001);
        let peer: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let resp = process_dns_wire(&query, peer, &engine).await;

        assert!(resp.len() >= 12);
        assert_eq!(resp[0], 0x00, "TXID high byte preserved");
        assert_eq!(resp[1], 0x01, "TXID low byte preserved");
        // RCODE = NOERROR (0)
        assert_eq!(resp[3] & 0x0F, 0x00, "RCODE should be NOERROR (0)");
    }

    #[tokio::test]
    async fn test_process_dns_wire_short_query_returns_servfail() {
        // Query shorter than DNS header — fast parse fails → fallback → SERVFAIL
        let engine = make_static_engine("NXDOMAIN");
        let short = [0x12, 0x34, 0x00]; // only 3 bytes, not a valid DNS message
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let resp = process_dns_wire(&short, peer, &engine).await;

        // Should return a SERVFAIL response preserving TXID
        assert_eq!(resp.len(), 12);
        assert_eq!(resp[0], 0x12, "TXID high byte preserved");
        assert_eq!(resp[1], 0x34, "TXID low byte preserved");
        assert_eq!(resp[3] & 0x0F, 0x02, "RCODE should be SERVFAIL (2)");
    }

    // ---- MAX_DNS_MESSAGE size guard ----

    #[test]
    fn test_max_dns_message_constant() {
        // RFC 1035 limits DNS messages to 65535 bytes; we cap at 64KB for safety
        assert_eq!(MAX_DNS_MESSAGE, 64 * 1024);
    }

    // ---- build_tls_acceptor ----

    #[test]
    fn test_build_tls_acceptor_rejects_empty_cert_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, "").expect("write empty cert");
        std::fs::write(&key_path, "not a pem").expect("write key");

        let Err(err) = build_tls_acceptor(cert_path.to_str().unwrap(), key_path.to_str().unwrap())
        else {
            panic!("empty cert file must be rejected");
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("no certificates"), "unexpected error: {msg}");
    }

    #[test]
    fn test_build_tls_acceptor_accepts_generated_pair() {
        use rcgen::{CertificateParams, KeyPair};

        let dir = tempfile::tempdir().expect("tempdir");
        let params = CertificateParams::new(vec!["localhost".to_string()]).expect("params");
        let key_pair = KeyPair::generate().expect("generate key pair");
        let cert = params.self_signed(&key_pair).expect("self-signed cert");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, cert.pem()).expect("write cert pem");
        std::fs::write(&key_path, key_pair.serialize_pem()).expect("write key pem");

        assert!(
            build_tls_acceptor(cert_path.to_str().unwrap(), key_path.to_str().unwrap()).is_ok(),
            "valid cert/key pair must build an acceptor"
        );
    }

    // ---- 快速路径之后 / After the fast path ----

    /// 把查询都用 UDP 转发给 `upstream` 的引擎，`settings` 覆盖在默认设置上
    /// An engine forwarding every query over UDP to `upstream`, with `settings` on top of
    /// the defaults
    fn forwarding_engine(upstream: &str, settings: serde_json::Value) -> Engine {
        let mut all = serde_json::json!({ "default_upstream": upstream });
        all.as_object_mut()
            .unwrap()
            .extend(settings.as_object().unwrap().clone());
        crate::engine::test_support::engine_from(serde_json::json!({
            "settings": all,
            "pipelines": [{
                "id": "p",
                "rules": [{
                    "name": "forward",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "forward", "upstream": upstream, "transport": "udp" }]
                }]
            }]
        }))
    }

    /// 经 DoH 问一次，读回回答 / Ask once over DoH and read the answer back
    async fn ask(engine: &Engine, query: &[u8]) -> Message {
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        Message::from_bytes(&process_dns_wire(query, peer, engine).await).expect("dns answer")
    }

    /// 缓存命中的应答带着这条查询自己的事务 ID；TTL 按应答在缓存里停留的整秒数调低（RFC 1035
    /// 第 5.2 节），停留不到一秒时原样不动
    /// A cache hit carries the query's own transaction ID, and its TTLs are lowered by the
    /// whole seconds the answer sat in the cache (RFC 1035 section 5.2), untouched under a
    /// second
    #[tokio::test]
    async fn a_cache_hit_carries_the_query_id_and_ages_its_ttls() {
        let upstream = crate::engine::test_support::answering_upstream(
            std::net::Ipv4Addr::new(192, 0, 2, 7),
            300,
        )
        .await;
        let engine = forwarding_engine(&upstream.address, serde_json::json!({}));

        // 第一次转发给上游，写进缓存 / The first goes to the upstream and into the cache
        let forwarded = ask(&engine, &make_dns_query_a("cached.test", 1)).await;
        assert_eq!((forwarded.metadata.id, forwarded.answers[0].ttl), (1, 300));

        // 停留不到一秒：只换 ID / Under a second in the cache: only the ID changes
        let hit = ask(&engine, &make_dns_query_a("cached.test", 2)).await;
        assert_eq!((hit.metadata.id, hit.answers[0].ttl), (2, 300));

        // 停留过一秒：TTL 跟着调低 / Past a second in the cache the TTL goes down too
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let aged = ask(&engine, &make_dns_query_a("cached.test", 3)).await;
        assert_eq!(aged.metadata.id, 3);
        let ttl = aged.answers[0].ttl;
        assert!((295..300).contains(&ttl), "aged TTL {ttl}");
    }

    /// 引擎在请求时限内答不上来时，到点回 SERVFAIL：不早于时限，也不等引擎自己放弃。快速解析读得了的
    /// 查询和要从头解析的一样
    /// When the engine cannot answer within the request timeout, the answer is SERVFAIL
    /// when it runs out: not before, and without waiting for the engine to give up. A query
    /// the quick parse reads and one parsed from scratch alike
    #[tokio::test]
    async fn the_answer_is_servfail_when_the_request_timeout_runs_out() {
        // 上游从不回答：引擎先用 UDP 试三分之一个时限、再试一个时限，再改用 TCP 等一个时限，加起来比
        // 请求时限长得多，所以先到点的是这里的计时
        // The upstream never answers: the engine tries UDP for a third of the timeout and
        // then a whole one, then TCP for another, far longer than the request timeout, so
        // the timer here runs out first
        const TIMEOUT: Duration = Duration::from_millis(300);
        let upstream = crate::engine::test_support::silent_upstream().await;
        let engine = forwarding_engine(
            &upstream.to_string(),
            serde_json::json!({
                "upstream_timeout_ms": TIMEOUT.as_millis() as u64,
                "request_timeout_ms": TIMEOUT.as_millis() as u64,
                "enable_tcp_fallback": true
            }),
        );
        // 第一个标签里有一个空格：快速解析读不了，要从头解析
        // A space in the first label: the quick parse cannot read it, so it is parsed
        // from scratch
        let mut parsed_from_scratch = make_dns_query_a("xslow.test", 8);
        parsed_from_scratch[13] = b' ';
        assert!(crate::proto_utils::parse_quick(&parsed_from_scratch, &mut [0u8; 256]).is_none());

        for (case, query) in [
            ("quick parse", make_dns_query_a("quick.test", 7)),
            ("full parse", parsed_from_scratch),
        ] {
            let start = std::time::Instant::now();
            let answer = ask(&engine, &query).await;
            let took = start.elapsed();
            assert_eq!(
                (answer.metadata.id, answer.metadata.response_code),
                (
                    u16::from_be_bytes([query[0], query[1]]),
                    ResponseCode::ServFail
                ),
                "{case}"
            );
            assert!(
                took >= TIMEOUT && took < TIMEOUT * 2,
                "{case} took {took:?}"
            );
        }
    }

    /// 快速路径构造不出应答（名字超长，hickory 不接受）时，回一个只有报头的 SERVFAIL
    /// When the fast path cannot build its answer (an overlong name hickory rejects), the
    /// answer is a header-only SERVFAIL
    #[tokio::test]
    async fn a_fast_path_answer_that_cannot_be_built_is_answered_servfail() {
        let engine = make_static_engine("NXDOMAIN");
        // 点分形式 256 字节：快速路径自己的解析器接受，hickory 不接受（在线格式最多 255 字节）
        // 256 bytes dotted: the fast path's own parser accepts it, hickory does not (at most
        // 255 bytes on the wire)
        let mut query = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(62),
        ] {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.extend_from_slice(&[0, 0, 1, 0, 1]); // root, QTYPE A, QCLASS IN
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        assert!(engine.handle_packet_fast(&query, peer).is_err());

        let answer = process_dns_wire(&query, peer, &engine).await;
        assert_eq!(
            &answer[..],
            [0x12, 0x34, 0x81, 0x82, 0, 0, 0, 0, 0, 0, 0, 0],
            "TXID, QR + RD, RA + SERVFAIL, no records"
        );
    }
}
