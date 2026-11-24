//! 传输的测试共用的东西：测试用的查询和回答、本机的假上游、TLS 设置
//! What the transport tests share: test queries and answers, local fake upstreams, TLS settings

use rustls::{ClientConfig, RootCertStore};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio::time::timeout;

/// reqwest + rustls 要有进程级的加密实现，明文 http 也一样
/// reqwest + rustls needs a process-level crypto provider, plain http included
#[ctor::ctor]
fn init_crypto() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// A query for `name` (A, IN) with a fixed transaction id.
pub(super) fn udp_test_query(name: &str) -> Vec<u8> {
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};
    let mut msg = Message::new(0x1234, MessageType::Query, OpCode::Query);
    msg.add_query(Query::query(
        Name::from_ascii(name).expect("parse test name"),
        RecordType::A,
    ));
    msg.to_vec().expect("encode test query")
}

/// 标上 QR 的查询本身，当作它的回答 / The query itself with QR set, as its answer
pub(super) fn echo_answer(query: &[u8]) -> Vec<u8> {
    let mut answer = query.to_vec();
    answer[2] |= 0x80;
    answer
}

/// Response to `query` whose question section names `name` instead.
pub(super) fn udp_response_with_question(query: &[u8], name: &str) -> Vec<u8> {
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};
    let id = u16::from_be_bytes([query[0], query[1]]);
    let mut msg = Message::new(id, MessageType::Response, OpCode::Query);
    msg.add_query(Query::query(
        Name::from_ascii(name).expect("parse test name"),
        RecordType::A,
    ));
    msg.to_vec().expect("encode test response")
}

/// `localhost` 的自签证书，以及只信任它的客户端配置；`alpn` 两边都用
/// A self-signed certificate for `localhost` and a client config trusting
/// only it, both sides offering `alpn`
pub(super) fn localhost_tls(alpn: &[&[u8]]) -> (rustls::ServerConfig, ClientConfig) {
    self_signed_tls(&["localhost"], alpn)
}

/// 给 `names` 签的自签证书（IP 地址成为 IP 类型的名字）和只信任它的客户端配置
/// A self-signed certificate for `names` (an IP address becomes an IP name)
/// and a client config trusting only it
pub(super) fn self_signed_tls(
    names: &[&str],
    alpn: &[&[u8]],
) -> (rustls::ServerConfig, ClientConfig) {
    use rcgen::{CertificateParams, KeyPair};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    let key_pair = KeyPair::generate().expect("generate key pair");
    let names: Vec<String> = names.iter().map(|name| name.to_string()).collect();
    let cert = CertificateParams::new(names)
        .expect("certificate params")
        .self_signed(&key_pair)
        .expect("self-signed certificate");
    let cert_der: CertificateDer<'static> = cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    let mut server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .expect("server config");
    server.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();

    let mut roots = RootCertStore::empty();
    roots.add(cert_der).expect("trust the test certificate");
    let mut client = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    (server, client)
}

/// DNS 消息里问题名的第一个标签 / First label of the question name in a DNS message
pub(super) fn first_label(message: &[u8]) -> String {
    let len = message[12] as usize;
    String::from_utf8_lossy(&message[13..13 + len]).into_owned()
}

/// 本机 TCP 测试上游；`tls` 给了就是 DoT。问题名第一个标签是 `slow` 的永不回答，
/// `late` 的 400 ms 后回答，`mid` 的 100 ms 后回答，其余立刻回答；同一条连接上的
/// 查询各自独立回答，先到先回。
/// Local TCP test upstream, DoT when `tls` is given. A question whose first
/// label is `slow` is never answered, `late` after 400 ms, `mid` after
/// 100 ms, anything else at once; queries on one connection are answered
/// independently, whichever is ready first.
pub(super) async fn spawn_stream_upstream(tls: Option<rustls::ServerConfig>) -> SocketAddr {
    spawn_stream_upstream_on("127.0.0.1:0", tls, None)
        .await
        .expect("bind the stream test upstream")
}

/// 同 [`spawn_stream_upstream`]，绑在 `bind` 上；该地址族不可用时为 None。给了 `closed`，每条
/// 连接结束时往里发一个信号
/// As [`spawn_stream_upstream`], bound to `bind`; `None` when that address
/// family is unavailable on this host. With `closed`, a signal goes there
/// whenever a connection ends
pub(super) async fn spawn_stream_upstream_on(
    bind: &str,
    tls: Option<rustls::ServerConfig>,
    closed: Option<tokio::sync::mpsc::UnboundedSender<()>>,
) -> Option<SocketAddr> {
    async fn serve<S>(stream: S)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + 'static,
    {
        let (mut reader, writer) = tokio::io::split(stream);
        let writer = Arc::new(Mutex::new(writer));
        loop {
            let mut len = [0u8; 2];
            if reader.read_exact(&mut len).await.is_err() {
                return;
            }
            let mut frame = vec![0u8; u16::from_be_bytes(len) as usize];
            if reader.read_exact(&mut frame).await.is_err() {
                return;
            }
            let writer = Arc::clone(&writer);
            tokio::spawn(async move {
                let label = first_label(&frame);
                let delay = match label.as_str() {
                    "slow" => return,
                    "late" => Duration::from_millis(400),
                    "mid" => Duration::from_millis(100),
                    _ => Duration::ZERO,
                };
                if label == "swap" {
                    // 先在同一个 ID 下回一个别的问题的回答，过一会儿再回真正的
                    // First an answer to another question under the same ID, the real one a moment later
                    let other = udp_response_with_question(&frame, "other.example");
                    let mut writer = writer.lock().await;
                    let _ = writer.write_all(&(other.len() as u16).to_be_bytes()).await;
                    let _ = writer.write_all(&other).await;
                    let _ = writer.flush().await;
                    drop(writer);
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                tokio::time::sleep(delay).await;
                frame[2] |= 0x80;
                let mut writer = writer.lock().await;
                let _ = writer.write_all(&len).await;
                let _ = writer.write_all(&frame).await;
            });
        }
    }

    let listener = tokio::net::TcpListener::bind(bind).await.ok()?;
    let addr = listener.local_addr().expect("read the stream test address");
    let acceptor = tls.map(|config| tokio_rustls::TlsAcceptor::from(Arc::new(config)));
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let (acceptor, closed) = (acceptor.clone(), closed.clone());
            tokio::spawn(async move {
                match acceptor {
                    Some(acceptor) => {
                        if let Ok(tls) = acceptor.accept(stream).await {
                            serve(tls).await;
                        }
                    }
                    None => serve(stream).await,
                }
                if let Some(closed) = closed {
                    let _ = closed.send(());
                }
            });
        }
    });
    Some(addr)
}

/// 连接池被留下时连接不断，被丢掉以后连接关闭
/// A kept pool keeps its connection; once the pool is dropped the connection closes
pub(super) async fn kept_then_dropped(
    closed: &mut tokio::sync::mpsc::UnboundedReceiver<()>,
    retain: impl Fn(bool),
) {
    retain(true);
    assert!(
        timeout(Duration::from_millis(300), closed.recv())
            .await
            .is_err(),
        "a kept upstream keeps its connection"
    );
    retain(false);
    timeout(Duration::from_secs(2), closed.recv())
        .await
        .expect("the connection closes once its pool is dropped");
}
