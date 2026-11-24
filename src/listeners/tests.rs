use super::tcp::{
    TCP_MAX_QUERIES_PER_CONN, TCP_READ_CHUNK, TCP_READ_TIMEOUT, handle_tcp_conn, run_tcp,
    serve_tcp_conn,
};
use super::*;
use crate::engine::concurrency::WAITING_TO_RUN_AT_MOST;
use crate::matcher::RuntimePipelineConfig;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use std::str::FromStr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[ctor::ctor]
fn init_crypto() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

fn static_engine() -> Engine {
    Engine::new(static_runtime(), "test".to_string()).expect("initialize engine")
}

/// `engine` 像 `run_tcp` 给每条连接的那样：标上 TCP，共享 / `engine` as `run_tcp` gives it to each
/// connection: tagged TCP and shared
fn tcp_engine(engine: Engine) -> Arc<Engine> {
    Arc::new(engine.with_client_transport(ClientTransport::Tcp))
}

fn static_runtime() -> RuntimePipelineConfig {
    use crate::config::PipelineConfig;

    let config: PipelineConfig = serde_json::from_value(serde_json::json!({
        "settings": { "default_upstream": "127.0.0.1:9" },
        "pipelines": [{
            "id": "p",
            "rules": [{
                "name": "static",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "static_ip_response", "ip": "192.0.2.1" }]
            }]
        }]
    }))
    .expect("parse config");
    RuntimePipelineConfig::from_config(config).expect("build runtime config")
}

/// 记录每个请求上报的传输 / Records the transport each request reports
#[derive(Default)]
struct TransportRecorder(std::sync::Mutex<Vec<Option<ClientTransport>>>);

impl crate::observe::EngineObserver for TransportRecorder {
    fn request_started(&self, ctx: &crate::observe::RequestContext<'_>) {
        self.0.lock().unwrap().push(ctx.transport);
    }
}

/// UDP 与 TCP 监听器为交给引擎的请求标注查询经由的传输。
/// The UDP and TCP listeners tag the requests they hand to the engine
/// with the transport the query arrived over.
#[tokio::test]
async fn listeners_report_the_transport_the_query_arrived_over() {
    let recorder = Arc::new(TransportRecorder::default());
    let engine = Engine::builder(static_runtime())
        .observer(recorder.clone())
        .build()
        .expect("initialize engine");

    let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_addr = server.local_addr().unwrap();
    let worker = tokio::spawn(run_udp_worker(0, Arc::clone(&server), engine.clone()));
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(&dns_query(), server_addr).await.unwrap();
    let mut response = [0u8; 512];
    tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut response))
        .await
        .expect("udp answer")
        .unwrap();

    let (mut client, connection) = tcp_connection(engine.clone()).await;
    tcp_exchange(&mut client, &dns_query()).await;

    assert_eq!(
        *recorder.0.lock().unwrap(),
        [Some(ClientTransport::Udp), Some(ClientTransport::Tcp)]
    );
    worker.abort();
    connection.abort();
}

fn dns_query() -> Vec<u8> {
    query("data.xiaoheihe.cn", 0xCAFE)
}

/// 一批里的每个查询都拿到自己的回答：几个客户端排着的查询比一批还多，中间夹着坏包和不是查询的报文。
/// 批量收发和一个一个收发的两种循环都这样
/// Every query in a batch gets its own answer: several clients queue more queries than one batch
/// holds, with malformed datagrams and non-queries among them. Both the batched and the one-by-one
/// receive loops do so
#[tokio::test]
async fn every_queued_query_gets_its_own_answer() {
    #[cfg(target_os = "linux")]
    every_queued_query_is_answered_by(|server, engine| {
        tokio::spawn(async move { receive_in_batches(&server, &Arc::new(engine)).await })
    })
    .await;
    every_queued_query_is_answered_by(|server, engine| {
        tokio::spawn(async move { receive_one_by_one(&server, &Arc::new(engine)).await })
    })
    .await;
}

/// 排着的报文比一批多时，接收循环收一批就让出一次线程：同一线程上别的任务（要等上游的查询、上游回答的
/// 接收）不必等排着的全收完才能跑。两种循环都这样
/// With more datagrams queued than one batch, the receive loop yields its thread after each batch:
/// other tasks on the same thread (queries waiting on an upstream, the readers of upstream answers)
/// need not wait until the whole queue is received. Both loops do so
#[tokio::test]
async fn receive_loop_yields_while_datagrams_are_queued() {
    #[cfg(target_os = "linux")]
    yields_while_datagrams_are_queued(|server, engine| {
        tokio::spawn(async move { receive_in_batches(&server, &Arc::new(engine)).await })
    })
    .await;
    yields_while_datagrams_are_queued(|server, engine| {
        tokio::spawn(async move { receive_one_by_one(&server, &Arc::new(engine)).await })
    })
    .await;
}

async fn yields_while_datagrams_are_queued(
    receive: impl FnOnce(Arc<UdpSocket>, Engine) -> tokio::task::JoinHandle<()>,
) {
    const QUEUED: usize = 4 * RECEIVED_BEFORE_YIELD;
    let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_addr = server.local_addr().unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // 循环开始前查询全排进服务端 socket；静态规则当场回答，回答在下一次让出前就到了客户端
    // Every query is queued in the server socket before the loop starts; the static rule answers on
    // the spot, so the answers reach the client before the loop next yields
    for id in 0..QUEUED as u16 {
        client
            .send_to(&query("data.xiaoheihe.cn", id), server_addr)
            .await
            .unwrap();
    }
    let worker = receive(server, static_engine());

    // 这个测试本身就是同一线程上的别的任务：每轮取走已经到的回答，记下一轮最多取到几个
    // This test is itself the other task on the thread: each turn it takes the answers that have
    // arrived, noting the most taken in one turn
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut buf = [0u8; 512];
    let (mut answered, mut most_in_one_turn) = (0, 0);
    while answered < QUEUED {
        assert!(
            tokio::time::Instant::now() < deadline,
            "only {answered} of {QUEUED} answered"
        );
        tokio::task::yield_now().await;
        let mut this_turn = 0;
        while client.try_recv_from(&mut buf).is_ok() {
            this_turn += 1;
        }
        answered += this_turn;
        most_in_one_turn = most_in_one_turn.max(this_turn);
    }
    worker.abort();
    assert!(
        most_in_one_turn <= 2 * RECEIVED_BEFORE_YIELD,
        "{most_in_one_turn} of {QUEUED} queued answers came in one turn: the receive loop kept the thread"
    );
}

/// 记录每个请求的客户端地址 / Records each request's client address
#[derive(Default)]
struct ClientRecorder(std::sync::Mutex<Vec<SocketAddr>>);

impl crate::observe::EngineObserver for ClientRecorder {
    fn request_started(&self, ctx: &crate::observe::RequestContext<'_>) {
        self.0.lock().unwrap().push(ctx.client);
    }
}

async fn every_queued_query_is_answered_by(
    receive: impl FnOnce(Arc<UdpSocket>, Engine) -> tokio::task::JoinHandle<()>,
) {
    let recorder = Arc::new(ClientRecorder::default());
    let engine = Engine::builder(static_runtime())
        .observer(recorder.clone())
        .build()
        .expect("initialize engine");
    let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_addr = server.local_addr().unwrap();
    let mut clients = Vec::new();
    for _ in 0..6 {
        clients.push(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    }
    // worker 起来之前全排进接收队列：第一次收就是满满一批，后面还有 / All queued before the
    // worker starts: the first receive is a full batch, with more behind it
    const PER_CLIENT: u16 = 12;
    for (c, client) in (0u16..).zip(&clients) {
        for q in 0..PER_CLIENT {
            let name = format!("q{q}.c{c}.example");
            client
                .send_to(&query(&name, c * 100 + q), server_addr)
                .await
                .unwrap();
        }
        client.send_to(&[0x12, 0x34], server_addr).await.unwrap();
        let mut answer_not_query = query("x.example", 0x7777);
        answer_not_query[2] |= 0x80;
        client
            .send_to(&answer_not_query, server_addr)
            .await
            .unwrap();
    }
    let worker = receive(Arc::clone(&server), engine);

    for (c, client) in (0u16..).zip(&clients) {
        let mut ids = Vec::new();
        for _ in 0..PER_CLIENT {
            let mut buf = [0u8; 512];
            let (len, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
                .await
                .expect("every query is answered")
                .unwrap();
            let response = Message::from_bytes(&buf[..len]).unwrap();
            let id = response.metadata.id;
            assert_eq!(id / 100, c, "an answer reached the wrong client");
            assert_eq!(
                response.queries[0].name().to_string(),
                format!("q{}.c{c}.example.", id % 100)
            );
            assert_eq!(response.answers.len(), 1);
            ids.push(id);
        }
        ids.sort_unstable();
        assert_eq!(
            ids,
            (0..PER_CLIENT).map(|q| c * 100 + q).collect::<Vec<_>>()
        );
        let mut buf = [0u8; 512];
        assert!(
            tokio::time::timeout(Duration::from_millis(100), client.recv_from(&mut buf))
                .await
                .is_err(),
            "malformed datagrams and non-queries get no answer"
        );
    }
    worker.abort();
    // 引擎看到的客户端就是发来这个查询的那个 / The engine sees as the client the one that sent the query
    let mut seen = recorder.0.lock().unwrap().clone();
    seen.sort_unstable();
    let mut sent = Vec::new();
    for client in &clients {
        sent.extend([client.local_addr().unwrap(); PER_CLIENT as usize]);
    }
    sent.sort_unstable();
    assert_eq!(seen, sent);
}

#[tokio::test]
async fn udp_static_fast_path_rejects_non_query_and_malformed_additional_records() {
    let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_addr = server.local_addr().unwrap();
    let worker = tokio::spawn(run_udp_worker(0, Arc::clone(&server), static_engine()));
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let mut qr_response = dns_query();
    qr_response[2] |= 0x80;

    let mut missing_additional = dns_query();
    missing_additional[11] = 1;

    let mut truncated_edns = dns_query();
    truncated_edns[11] = 1;
    truncated_edns.extend_from_slice(&[0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 4, 0, 1]);

    let mut invalid_pointer = dns_query();
    invalid_pointer[11] = 1;
    invalid_pointer.extend_from_slice(&[0xC0, 0xFF, 0, 16, 0, 1, 0, 0, 0, 0, 0, 0]);

    // 属主是 a. 的 OPT（RFC 6891 第 6.1.2 节要求根名）：记录的走法和 hickory 都不认 / An OPT owned by
    // a. (RFC 6891 section 6.1.2 asks for the root): neither the record walk nor hickory takes it
    let mut opt_off_the_root = dns_query();
    opt_off_the_root[11] = 1;
    opt_off_the_root.extend_from_slice(&[1, b'a', 0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0]);

    let mut response_buf = [0u8; 512];
    client.send_to(&qr_response, server_addr).await.unwrap();
    assert!(
        tokio::time::timeout(
            Duration::from_millis(100),
            client.recv_from(&mut response_buf),
        )
        .await
        .is_err(),
        "QR=1 gets no answer, so there is nothing to reflect"
    );
    for (case, packet) in [
        ("missing Additional RR", missing_additional),
        ("truncated EDNS RDATA", truncated_edns),
        ("invalid Additional compression pointer", invalid_pointer),
        ("OPT owned by other than the root", opt_off_the_root),
    ] {
        client.send_to(&packet, server_addr).await.unwrap();
        let (len, _) =
            tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut response_buf))
                .await
                .unwrap_or_else(|_| panic!("{case} should get FORMERR"))
                .unwrap();
        let response = Message::from_bytes(&response_buf[..len]).unwrap();
        assert_eq!(
            response.metadata.response_code,
            ResponseCode::FormErr,
            "{case}"
        );
        assert!(
            response.answers.is_empty(),
            "{case} must be rejected before static/cache fast paths"
        );
    }

    worker.abort();
}

/// 请求头是标准查询、报文读不了的回 FORMERR（RFC 6891 第 6.1.1 节），带上它的 ID、RD 和问题，不比查询长。
/// 批量收发、一个一个收发和 TCP 都这样；超过 `MAX_QUERY_LEN` 的 UDP 查询截断后也算这一类，两种接收循环一样
/// A query with a standard header that cannot be read gets FORMERR (RFC 6891 section
/// 6.1.1) with its ID, RD and question, no longer than the query. So in the batched
/// and one-by-one receive loops and over TCP; a UDP query cut off at `MAX_QUERY_LEN`
/// counts too, in both receive loops alike
#[tokio::test]
async fn a_query_that_cannot_be_read_gets_formerr() {
    #[cfg(target_os = "linux")]
    formerr_on_udp(|server, engine| {
        tokio::spawn(async move { receive_in_batches(&server, &Arc::new(engine)).await })
    })
    .await;
    formerr_on_udp(|server, engine| {
        tokio::spawn(async move { receive_one_by_one(&server, &Arc::new(engine)).await })
    })
    .await;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(run_tcp(listener, static_engine()));
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    for (case, packet) in unreadable_queries() {
        stream
            .write_all(&(packet.len() as u16).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&packet).await.unwrap();
        let mut length = [0u8; 2];
        stream.read_exact(&mut length).await.unwrap();
        let mut reply = vec![0u8; u16::from_be_bytes(length) as usize];
        stream.read_exact(&mut reply).await.unwrap();
        assert_is_formerr_for(&reply, &packet, case);
    }
    server.abort();
}

/// 操作码不是 QUERY 的请求（这里是 NOTIFY）回 NOTIMP，带着它的 ID 和操作码，只有请求头；UDP 和 TCP 都这样，
/// TCP 连接也照常接着用。以前 UDP 丢掉它、TCP 断开连接
/// A request whose opcode is not QUERY (NOTIFY here) gets NOTIMP with its ID and opcode, the
/// header alone; so over UDP and TCP, the TCP connection going on as usual. UDP used to drop
/// it and TCP to close the connection
#[tokio::test]
async fn a_request_of_another_opcode_gets_notimp() {
    let mut notify = dns_query();
    notify[2] = (notify[2] & 0x87) | (4 << 3);
    let is_notimp_for = |reply: &[u8]| {
        let reply = Message::from_bytes(reply).unwrap();
        assert_eq!(reply.metadata.response_code, ResponseCode::NotImp);
        assert_eq!(reply.metadata.message_type, MessageType::Response);
        assert_eq!(reply.metadata.op_code, OpCode::Notify);
        assert_eq!(
            reply.metadata.id,
            u16::from_be_bytes([notify[0], notify[1]])
        );
        assert!(reply.queries.is_empty() && reply.answers.is_empty());
    };

    let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_addr = server.local_addr().unwrap();
    let engine = static_engine();
    let worker = {
        let server = Arc::clone(&server);
        tokio::spawn(async move { receive_one_by_one(&server, &Arc::new(engine)).await })
    };
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(&notify, server_addr).await.unwrap();
    let mut buf = [0u8; 512];
    let (len, _) = tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf))
        .await
        .expect("NOTIMP over UDP")
        .unwrap();
    is_notimp_for(&buf[..len]);
    worker.abort();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(run_tcp(listener, static_engine()));
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    for packet in [notify.clone(), dns_query()] {
        stream
            .write_all(&(packet.len() as u16).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&packet).await.unwrap();
    }
    let mut read_reply = async || {
        let mut length = [0u8; 2];
        stream.read_exact(&mut length).await.unwrap();
        let mut reply = vec![0u8; u16::from_be_bytes(length) as usize];
        stream.read_exact(&mut reply).await.unwrap();
        reply
    };
    is_notimp_for(&read_reply().await);
    let answered = Message::from_bytes(&read_reply().await).unwrap();
    assert_eq!(
        answered.metadata.op_code,
        OpCode::Query,
        "the connection goes on"
    );
    server.abort();
}

/// 操作码是 QUERY、但问题数不是 1 或者带着回答记录的请求回 FORMERR（RFC 9619），只有请求头；UDP 和 TCP 都这样，
/// TCP 连接也照常接着用。以前 UDP 丢掉它、TCP 断开连接
/// A QUERY with a question count other than 1, or carrying answer records, gets FORMERR
/// (RFC 9619), the header alone; so over UDP and TCP, the TCP connection going on as usual.
/// UDP used to drop it and TCP to close the connection
#[tokio::test]
async fn a_query_with_a_wrong_question_count_gets_formerr() {
    let with = |change: fn(&mut Vec<u8>)| {
        let mut packet = dns_query();
        change(&mut packet);
        packet
    };
    let cases = [
        with(|packet| packet[5] = 0),
        with(|packet| packet[5] = 2),
        with(|packet| packet[7] = 1),
    ];
    let is_formerr_for = |reply: &[u8], query: &[u8]| {
        assert_eq!(reply.len(), 12, "the header alone");
        assert_eq!(reply[..2], query[..2]);
        let reply = Message::from_bytes(reply).unwrap();
        assert_eq!(reply.metadata.response_code, ResponseCode::FormErr);
        assert_eq!(reply.metadata.message_type, MessageType::Response);
    };

    let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_addr = server.local_addr().unwrap();
    let engine = static_engine();
    let worker = {
        let server = Arc::clone(&server);
        tokio::spawn(async move { receive_one_by_one(&server, &Arc::new(engine)).await })
    };
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut buf = [0u8; 512];
    for packet in &cases {
        client.send_to(packet, server_addr).await.unwrap();
        let (len, _) = tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf))
            .await
            .expect("FORMERR over UDP")
            .unwrap();
        is_formerr_for(&buf[..len], packet);
    }
    worker.abort();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(run_tcp(listener, static_engine()));
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    for packet in cases.iter().chain([&dns_query()]) {
        stream
            .write_all(&(packet.len() as u16).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(packet).await.unwrap();
    }
    for packet in &cases {
        let mut length = [0u8; 2];
        stream.read_exact(&mut length).await.unwrap();
        let mut reply = vec![0u8; u16::from_be_bytes(length) as usize];
        stream.read_exact(&mut reply).await.unwrap();
        is_formerr_for(&reply, packet);
    }
    let mut length = [0u8; 2];
    stream.read_exact(&mut length).await.unwrap();
    let mut reply = vec![0u8; u16::from_be_bytes(length) as usize];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(
        Message::from_bytes(&reply).unwrap().metadata.response_code,
        ResponseCode::NoError,
        "the connection goes on"
    );
    server.abort();
}

async fn formerr_on_udp(
    receive: impl FnOnce(Arc<UdpSocket>, Engine) -> tokio::task::JoinHandle<()>,
) {
    let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_addr = server.local_addr().unwrap();
    let worker = receive(server, static_engine());
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut too_long = dns_query();
    too_long[11] = 1;
    let padding = 4400u16;
    too_long.extend_from_slice(&[0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0]);
    too_long.extend_from_slice(&(padding + 4).to_be_bytes());
    too_long.extend_from_slice(&[0, 12]);
    too_long.extend_from_slice(&padding.to_be_bytes());
    too_long.resize(too_long.len() + padding as usize, 0);
    let mut buf = [0u8; 512];
    for (case, packet) in unreadable_queries()
        .into_iter()
        .chain([("over 4096 bytes", too_long)])
    {
        client.send_to(&packet, server_addr).await.unwrap();
        let (len, _) = tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf))
            .await
            .unwrap_or_else(|_| panic!("{case} should get FORMERR"))
            .unwrap();
        assert_is_formerr_for(&buf[..len], &packet, case);
    }
    worker.abort();
}

fn unreadable_queries() -> Vec<(&'static str, Vec<u8>)> {
    let opt = [0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0];
    let mut two_opts = dns_query();
    two_opts[11] = 2;
    two_opts.extend_from_slice(&opt);
    two_opts.extend_from_slice(&opt);
    let mut opt_after_the_end = dns_query();
    opt_after_the_end[11] = 2;
    opt_after_the_end.extend_from_slice(&opt);
    vec![
        ("two OPT records", two_opts),
        ("a record missing", opt_after_the_end),
    ]
}

fn assert_is_formerr_for(reply: &[u8], query: &[u8], case: &str) {
    let reply_message = Message::from_bytes(reply).unwrap();
    assert_eq!(
        reply_message.metadata.response_code,
        ResponseCode::FormErr,
        "{case}"
    );
    assert_eq!(
        reply_message.metadata.message_type,
        MessageType::Response,
        "{case}"
    );
    assert_eq!(reply_message.metadata.id, 0xCAFE, "{case}");
    assert!(reply_message.metadata.recursion_desired, "{case}");
    assert_eq!(
        reply_message.queries,
        Message::from_bytes(&dns_query()).unwrap().queries,
        "{case}"
    );
    assert!(reply.len() <= query.len(), "{case}: no amplification");
}

fn forwarding_engine() -> Engine {
    use crate::config::PipelineConfig;

    let config: PipelineConfig = serde_json::from_value(serde_json::json!({
        "settings": {
            "default_upstream": "127.0.0.1:9",
            "flow_control_enabled": true
        },
        "pipelines": [{
            "id": "p",
            "rules": [{
                "name": "forward",
                "matchers": [{ "type": "any" }],
                "actions": [{
                    "type": "forward",
                    "upstream": "127.0.0.1:9",
                    "transport": "udp"
                }]
            }]
        }]
    }))
    .expect("parse config");
    let runtime = RuntimePipelineConfig::from_config(config).expect("build runtime config");
    let engine = Engine::new(runtime, "test".to_string()).expect("initialize engine");
    with_busy_after(engine, Duration::ZERO)
}

fn doh_timeout_engine(upstream: &str) -> Engine {
    Engine::new(doh_timeout_config(upstream, 50), "test".to_string()).expect("initialize engine")
}

fn doh_timeout_config(upstream: &str, timeout_ms: u64) -> RuntimePipelineConfig {
    use crate::config::PipelineConfig;

    let config: PipelineConfig = serde_json::from_value(serde_json::json!({
        "settings": {
            "default_upstream": upstream,
            "upstream_timeout_ms": timeout_ms,
            "request_timeout_ms": timeout_ms
        },
        "pipelines": [{
            "id": "p",
            "rules": [{
                "name": "forward",
                "matchers": [{ "type": "any" }],
                "actions": [{
                    "type": "forward",
                    "upstream": upstream,
                    "transport": "doh"
                }]
            }]
        }]
    }))
    .expect("parse config");
    RuntimePipelineConfig::from_config(config).expect("build runtime config")
}

#[tokio::test]
async fn udp_send_datagram_surfaces_socket_errors() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let ipv6_peer: SocketAddr = "[::1]:53".parse().unwrap();
    assert!(send_udp_datagram(&socket, b"dns", ipv6_peer).await.is_err());
}

/// 查询一直算排长队、上游慢的引擎，只差内核忙不忙就会拒绝。`busy_after_ms` 是 socket 多久没收空算忙
/// An engine with queries always counting as queueing long and a slow upstream, refusing as
/// soon as the kernel is busy, `busy_after_ms` being how long a socket goes without running
/// empty before that counts as busy
async fn behind_engine_with_slow_upstream(busy_after_ms: u64) -> Engine {
    let upstream = spawn_slow_udp_upstream(Duration::from_millis(300)).await;
    let engine = with_busy_after(
        engine_forwarding_to(
            upstream,
            serde_json::json!({ "flow_control_enabled": true }),
        ),
        Duration::from_millis(busy_after_ms),
    );
    engine
        .flow_control_state
        .as_ref()
        .unwrap()
        .note_queue_delay(Duration::from_secs(3600));
    engine
}

/// 发出 `count` 个不同的查询，数被拒绝（SERVFAIL）的和答上来的
/// Sends `count` different queries and counts those refused (SERVFAIL) and those answered
async fn refused_and_answered(client: &UdpSocket, count: u16) -> (u16, u16) {
    let (mut refused, mut answered) = (0, 0);
    let mut buf = [0u8; 512];
    for _ in 0..count {
        let (len, _) = tokio::time::timeout(Duration::from_secs(3), client.recv_from(&mut buf))
            .await
            .expect("every query gets a reply")
            .unwrap();
        match Message::from_bytes(&buf[..len])
            .unwrap()
            .metadata
            .response_code
        {
            ResponseCode::ServFail => refused += 1,
            _ => answered += 1,
        }
    }
    (refused, answered)
}

/// 上游慢时，等着的查询再多也不拒绝：内核并不忙，它们都等得到回答。两种循环都这样
/// With a slow upstream, however many queries wait they are not refused: the kernel is not busy and
/// they all get their answers. Both loops do so
#[tokio::test]
async fn queries_waiting_on_a_slow_upstream_are_not_refused() {
    #[cfg(target_os = "linux")]
    not_refused_while_waiting_on_an_upstream(|server, engine| {
        tokio::spawn(async move { receive_in_batches(&server, &Arc::new(engine)).await })
    })
    .await;
    not_refused_while_waiting_on_an_upstream(|server, engine| {
        tokio::spawn(async move { receive_one_by_one(&server, &Arc::new(engine)).await })
    })
    .await;
}

/// 监听在通配地址上时，回答从查询发到的那个地址发出。一台机器有几个地址时（同一个网卡上的第二个地址、VIP、
/// 回环上的服务地址），内核自己挑的源地址可能是另一个：客户端收到一个从别的地址来的回答，不认，查询超时。
/// 当场答出的和转发回来的都从查询发到的地址发出，两种循环都这样
/// Listening on the wildcard address, a reply leaves from the address the query came to. On
/// a machine with several addresses (a second one on an interface, a VIP, a service address
/// on loopback) the source the kernel picks by itself may be another: the client gets a
/// reply from an address it did not ask, refuses it, and the query times out. Replies given
/// on the spot and those back from a forward both leave from the address the query came to,
/// in both loops
#[cfg(unix)]
#[tokio::test]
async fn a_reply_leaves_from_the_address_the_query_came_to() {
    let upstream = spawn_slow_udp_upstream(Duration::from_millis(20)).await;
    let engines = [
        ("answered on the spot", static_engine_with_flow_control()),
        (
            "back from a forward",
            Arc::new(engine_forwarding_to(upstream, serde_json::json!({}))),
        ),
    ];
    for (how, engine) in engines {
        #[cfg(target_os = "linux")]
        {
            let engine = Arc::clone(&engine);
            replies_come_from_the_address_asked(how, "batches", move |server| {
                tokio::spawn(async move { receive_in_batches(&server, &engine).await })
            })
            .await;
        }
        replies_come_from_the_address_asked(how, "one-by-one", move |server| {
            tokio::spawn(async move { receive_one_by_one(&server, &engine).await })
        })
        .await;
    }
}

/// 起一个监听在通配地址上的 worker，socket 和 `bind_udp_workers` 建的一样；客户端问它的每个本机地址（见
/// `addresses_asked`），都等到从那个地址来的回答。connect 过的客户端只收从它问的那个地址来的回答。`names`
/// 让每种循环问的名字不同，转发的不会碰上缓存
/// Starts a worker listening on the wildcard address, its socket built as `bind_udp_workers`
/// builds it; a client asks each of its local addresses (see `addresses_asked`) and waits for
/// the reply from that address. A connected client takes replies from the address it asked
/// alone. `names` keeps the names each loop asks apart, so a forward never meets the cache
#[cfg(unix)]
async fn replies_come_from_the_address_asked(
    how: &str,
    names: &str,
    receive: impl FnOnce(Arc<UdpSocket>) -> tokio::task::JoinHandle<()>,
) {
    let (wildcard, client_at, asked) = addresses_asked();
    let server = bind_udp_socket(wildcard).unwrap();
    let port = server.local_addr().unwrap().port();
    let worker = receive(Arc::new(server));
    for (id, mut to) in asked.into_iter().enumerate() {
        to.set_port(port);
        let client = UdpSocket::bind(client_at).await.unwrap();
        client.connect(to).await.unwrap();
        client
            .send(&query(&format!("n{id}.{names}.test"), id as u16))
            .await
            .unwrap();
        let mut buf = [0u8; 512];
        tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
            .await
            .unwrap_or_else(|_| panic!("{how}, {names}: no reply from {to}"))
            .unwrap();
        assert_eq!(buf[..2], (id as u16).to_be_bytes(), "{how}, {names}");
    }
    worker.abort();
}

/// 监听的通配地址、客户端绑的地址，和客户端问的本机地址（端口留 0），第一个是内核自己不会挑来当源地址的。Linux 上整个
/// 127.0.0.0/8 都在回环上，内核自己挑 127.0.0.1；macOS 和 BSD 的回环上只有 127.0.0.1，问的是回环网卡上默认有的
/// fe80::1，内核自己挑 ::1
/// The wildcard address listened on, the address the client binds, and the local addresses
/// it asks (port left 0), the first being one the kernel would not pick as a source by
/// itself. On Linux all of 127.0.0.0/8 is on loopback and the kernel picks 127.0.0.1; on
/// macOS and the BSDs loopback holds 127.0.0.1 alone, so fe80::1, on the loopback interface
/// by default, is asked, where the kernel picks ::1
#[cfg(unix)]
fn addresses_asked() -> (SocketAddr, SocketAddr, Vec<SocketAddr>) {
    #[cfg(target_os = "linux")]
    let addresses = (
        SocketAddr::from(([0, 0, 0, 0], 0)),
        SocketAddr::from(([127, 0, 0, 1], 0)),
        [[127, 0, 0, 2], [127, 0, 0, 1], [127, 9, 9, 9]]
            .map(|ip| SocketAddr::from((ip, 0)))
            .to_vec(),
    );
    #[cfg(not(target_os = "linux"))]
    let addresses = {
        use std::net::{Ipv6Addr, SocketAddrV6};
        // SAFETY: 网卡名是以 NUL 结尾的字符串 / SAFETY: the interface name is a NUL-terminated string
        let lo0 = unsafe { libc::if_nametoindex(c"lo0".as_ptr()) };
        let link_local = SocketAddrV6::new(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1), 0, 0, lo0);
        (
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
            SocketAddr::from((Ipv6Addr::LOCALHOST, 0)),
            vec![
                link_local.into(),
                SocketAddr::from((Ipv6Addr::LOCALHOST, 0)),
            ],
        )
    };
    addresses
}

/// 转发回来、排着等下一批一起发的回答（Linux 的批量循环），流控拒绝时当场发的 SERVFAIL，和直接发的回答，也从查询发到
/// 的地址发出
/// A reply back from a forward that waits for the next batch (Linux's batched loop), the
/// SERVFAIL sent at once when flow control refuses, and a reply sent directly leave from the
/// address the query came to as well
#[cfg(unix)]
#[tokio::test]
async fn queued_and_refused_replies_leave_from_the_address_the_query_came_to() {
    use crate::socket_utils::LocalAddr;

    let (wildcard, client_at, addresses) = addresses_asked();
    let server = bind_udp_socket(wildcard).unwrap();
    let mut asked = addresses[0];
    asked.set_port(server.local_addr().unwrap().port());
    let client = UdpSocket::bind(client_at).await.unwrap();
    client.connect(asked).await.unwrap();
    let local = match asked {
        SocketAddr::V4(v4) => LocalAddr::V4(*v4.ip()),
        SocketAddr::V6(v6) => LocalAddr::V6(*v6.ip(), v6.scope_id()),
    };
    let to = ReplyTo {
        peer: client.local_addr().unwrap(),
        local: Some(local),
    };
    let mut buf = [0u8; 64];
    let mut expect = async |sent: &[u8]| {
        let len = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
            .await
            .unwrap_or_else(|_| panic!("no reply from {asked} for {sent:?}"))
            .unwrap();
        assert_eq!(&buf[..len], sent);
    };

    // 排着的回答挪进一批里发 / A queued reply moved into a batch and sent
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let pending = PendingReplies::default();
        pending.queue_and_wake(&Bytes::from_static(b"queued"), to);
        let mut replies = udp_batch::Replies::default();
        pending.fill(&mut replies);
        assert_eq!(replies.send(server.as_raw_fd(), 0).unwrap(), 1);
        expect(b"queued").await;
    }

    // 流控拒绝时当场发的，不等待：tokio 要先看到 socket 可写 / What is sent at once when flow
    // control refuses, without waiting: tokio has to have seen the socket writable first
    server.writable().await.unwrap();
    to.try_send(&server, b"refused").unwrap();
    expect(b"refused").await;

    // 接收循环在等新报文时直接发的 / What goes directly while the receive loop waits
    send_udp_datagram(&server, b"direct", to).await.unwrap();
    expect(b"direct").await;
}

async fn not_refused_while_waiting_on_an_upstream(
    receive: impl FnOnce(Arc<UdpSocket>, Engine) -> tokio::task::JoinHandle<()>,
) {
    let engine = behind_engine_with_slow_upstream(2_000).await;
    let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_addr = server.local_addr().unwrap();
    let worker = receive(server, engine);
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    const QUERIES: u16 = 8;
    for id in 0..QUERIES {
        let query = query(&format!("q{id}.slow.test"), id);
        client.send_to(&query, server_addr).await.unwrap();
        // 一个一个来，socket 每次都收得空 / One at a time, so the socket runs empty each time
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(refused_and_answered(&client, QUERIES).await, (0, QUERIES));
    worker.abort();
}

/// 积压着而且在丢包时接收缓冲收小，收空了放回去。没丢包、没积压、上一段积压留下的丢包数都不算。没开流控也一样
/// While backed up and dropping the receive buffer shrinks, and running empty puts it back. No drops, no
/// backlog and the drops left from an earlier backlog do not count. The same without flow control
#[cfg(target_os = "linux")]
#[tokio::test]
async fn the_receive_buffer_shrinks_only_while_overflowing_and_comes_back() {
    let engine = Arc::new(Engine::new(static_runtime(), "test".to_string()).unwrap());
    assert!(engine.flow_control_state.is_none());
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let target = socket.local_addr().unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let size = || {
        socket2::SockRef::from(socket.as_ref())
            .recv_buffer_size()
            .unwrap()
    };
    socket2::SockRef::from(socket.as_ref())
        .set_recv_buffer_size(UDP_BUFFER_SIZE)
        .unwrap();
    let full = size();
    // 一直发到丢包为止 / Sends until it drops
    let overflow = || async {
        let before = crate::socket_utils::udp_receive_drops(&socket).unwrap();
        for _ in 0..500_000 {
            client.send_to(&[0u8; 64], target).await.unwrap();
            if crate::socket_utils::udp_receive_drops(&socket).unwrap() != before {
                return;
            }
        }
        panic!("the socket never dropped");
    };
    let pending = Arc::new(PendingReplies::default());
    let mut answering = UdpAnswering::new(&socket, &engine, &pending);
    // 看一次丢包数：处理那些查询用了一秒 / One reading of the drops: the queries took a second
    let look = |answering: &mut UdpAnswering<'_>| {
        answering.checks_since_empty = 2 * BEHIND_AFTER_CHECKS - 1;
        answering.looked_at = Instant::now() - Duration::from_secs(1);
        answering.shrink_buffer_if_overflowing();
    };

    // 积压着、队列还在涨，但没丢包 / Backed up with the queue still growing, but no drops
    look(&mut answering);
    client.send_to(&[0u8; 64], target).await.unwrap();
    look(&mut answering);
    assert!(!answering.buffer_shrunk, "no drops");
    assert_eq!(size(), full);

    overflow().await;
    answering.behind_at = Instant::now() - Duration::from_secs(3600);
    look(&mut answering);
    assert!(answering.buffer_shrunk);
    assert!(
        answering.behind_at.elapsed() < Duration::from_secs(60),
        "noted"
    );
    let shrunk = size();
    assert!(shrunk < full, "{shrunk} of {full}");

    // 这一段积压第一次看量不出速度，不动缓冲 / The first look of a backlog measures no speed and leaves the buffer
    overflow().await;
    answering.checks_since_empty = BEHIND_AFTER_CHECKS - 1;
    answering.looked_at = Instant::now() - Duration::from_millis(1);
    answering.shrink_buffer_if_overflowing();
    assert_eq!(size(), shrunk);

    // 刚才还在丢包，收空了也不放回去；又丢了就重新算 / Dropping a moment ago, running empty does not put
    // it back; new drops start the wait over
    let long_ago = || Instant::now() - CAUGHT_UP_AFTER - Duration::from_millis(1);
    answering.behind_at = Instant::now();
    answering.socket_ran_empty();
    assert!(answering.buffer_shrunk, "dropping a moment ago");
    overflow().await;
    answering.behind_at = long_ago();
    answering.note_drops_before_waiting();
    answering.socket_ran_empty();
    assert!(answering.buffer_shrunk, "new drops");
    assert_eq!(size(), shrunk);

    // 丢包停得够久才放回去 / Only with the drops stopped long enough does it go back
    answering.behind_at = long_ago();
    answering.note_drops_before_waiting();
    answering.socket_ran_empty();
    assert!(!answering.buffer_shrunk);
    assert_eq!(size(), full);

    // 没积压时丢包也不算 / Drops do not count without a backlog
    answering.shrink_buffer_if_overflowing();
    overflow().await;
    answering.shrink_buffer_if_overflowing();
    assert!(!answering.buffer_shrunk, "no backlog");

    // 上一段积压留下的丢包数不算：新的一段先记下来 / The drops left from an earlier backlog do not count:
    // a new backlog first notes the count
    look(&mut answering);
    assert!(!answering.buffer_shrunk, "old drops");

    // 每 1000 个查询读一次丢包数 / The drops are read once every 1000 queries
    overflow().await;
    let peer = SocketAddr::from(([127, 0, 0, 1], 53000));
    let mut reply = BytesMut::new();
    answering.checks_since_empty = BEHIND_AFTER_CHECKS;
    answering.looked_at = Instant::now() - Duration::from_secs(1);
    for id in 0..999 {
        answering.answer(&query("a.test", id), peer, &mut reply);
    }
    assert!(!answering.buffer_shrunk);
    answering.answer(&query("a.test", 999), peer, &mut reply);
    assert!(answering.buffer_shrunk);
}

/// 开了流控接收缓冲一直是大的，过载了、轮流时都不收小，但丢包还算没跟上；等之前的丢包不算等完才丢的
/// With flow control the receive buffer stays large, overloaded or taking turns, yet drops still
/// count as falling behind; drops from before a wait do not count as just after it
#[cfg(target_os = "linux")]
#[tokio::test]
async fn taking_turns_keeps_the_large_receive_buffer() {
    let engine = static_engine_with_flow_control();
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let target = socket.local_addr().unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let size = || {
        socket2::SockRef::from(socket.as_ref())
            .recv_buffer_size()
            .unwrap()
    };
    socket2::SockRef::from(socket.as_ref())
        .set_recv_buffer_size(UDP_BUFFER_SIZE)
        .unwrap();
    let full = size();
    let overflow = || async {
        let before = crate::socket_utils::udp_receive_drops(&socket).unwrap();
        for _ in 0..500_000 {
            client.send_to(&[0u8; 64], target).await.unwrap();
            if crate::socket_utils::udp_receive_drops(&socket).unwrap() != before {
                return;
            }
        }
        panic!("the socket never dropped");
    };
    let pending = Arc::new(PendingReplies::default());
    let mut answering = UdpAnswering::new(&socket, &engine, &pending);
    let look = |answering: &mut UdpAnswering<'_>| {
        answering.checks_since_empty = 2 * BEHIND_AFTER_CHECKS - 1;
        answering.looked_at = Instant::now() - Duration::from_secs(1);
        answering.shrink_buffer_if_overflowing();
    };
    let long_ago = || Instant::now() - CAUGHT_UP_AFTER - Duration::from_millis(1);

    look(&mut answering);
    overflow().await;
    // 开了流控，过载了（跟不上够久）也不收小：过载就按设备轮流 / With flow control even overload
    // (behind long enough) does not shrink it: overload means taking turns
    answering.behind_since = Instant::now() - BEHIND_BEFORE_TURNS - Duration::from_millis(1);
    answering.behind_at = Instant::now();
    look(&mut answering);
    assert!(answering.overloaded);
    assert!(!answering.buffer_shrunk);
    assert_eq!(size(), full);

    let _turns = answering.begin_turns();

    // 还在丢包、还过载着：轮流时也不收小，但丢包还算没跟上
    // Still dropping and still overloaded: while taking turns it is not shrunk either, yet the
    // drops still count as falling behind
    overflow().await;
    answering.behind_since = Instant::now() - BEHIND_BEFORE_TURNS - Duration::from_millis(1);
    answering.behind_at = Instant::now();
    look(&mut answering);
    assert!(
        answering.overloaded,
        "overloaded, yet taking turns keeps it large"
    );
    assert!(!answering.buffer_shrunk);
    assert_eq!(size(), full);
    assert!(answering.behind_at.elapsed() < CAUGHT_UP_AFTER, "noted");

    // 读空前丢的包也算 / Drops up to the socket being read empty count too
    overflow().await;
    answering.behind_at = long_ago();
    answering.note_drops_before_waiting();
    answering.socket_ran_empty();
    assert!(answering.taking_turns, "new drops");

    // 等了够久，等之前丢的包不算刚丢的 / After a long enough wait the drops before it are not
    // counted as just happened
    overflow().await;
    answering.note_drops_before_waiting();
    answering.behind_at = long_ago();
    answering.socket_ran_empty();
    assert!(!answering.taking_turns, "caught up");
    assert_eq!(size(), full);
}

/// 一阵阵的洪泛：跟上以后一分钟之内又跟不上，算同一阵的继续，第二阵一来就轮流。以前停一秒就从头计时，每阵不到一秒、
/// 中间停一秒多的洪泛永远开始不了轮流，每阵里别的设备都答不上
/// A flood in waves: falling behind again within a minute of catching up continues the
/// same spell, so turns begin as the second wave comes. A pause of a second used to start
/// the count over, so waves of under a second with pauses of a little over one never began
/// turns, and other devices went unanswered through every wave
#[cfg(target_os = "linux")]
#[tokio::test]
async fn waves_of_falling_behind_close_together_are_one_spell() {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let pending = Arc::new(PendingReplies::default());
    let engine = static_engine_with_flow_control();
    let mut answering = UdpAnswering::new(&socket, &engine, &pending);
    let drops = crate::socket_utils::udp_receive_drops(&socket).unwrap();
    let dropping = |answering: &mut UdpAnswering<'_>| {
        answering.drops_seen = Some(drops.wrapping_add(1));
        answering.checks_since_empty = 2 * BEHIND_AFTER_CHECKS - 1;
        answering.shrink_buffer_if_overflowing();
    };
    let back = |at: Instant, by: Duration| at.checked_sub(by).expect("the clock is far enough");

    // 运行了一阵才头一回跟不上，照样是新的一段 / Falling behind for the first time after running a
    // while is a new spell all the same
    answering.behind_since = back(answering.behind_since, Duration::from_secs(5));
    answering.behind_at = back(answering.behind_at, Duration::from_secs(5));
    // 第一阵：0.9 秒，然后停 1.1 秒 / The first wave: 0.9 s, then 1.1 s of quiet
    dropping(&mut answering);
    assert!(!answering.overloaded, "the first wave just began");
    answering.behind_since = back(answering.behind_since, Duration::from_millis(2_000));
    answering.behind_at = back(answering.behind_at, Duration::from_millis(1_100));
    answering.socket_ran_empty();

    dropping(&mut answering);
    assert!(answering.overloaded, "the second wave takes turns at once");

    // 停够一分钟以后的一阵是新的一阵 / A wave after a minute's quiet is a new spell
    answering.overloaded = false;
    answering.behind_since = back(
        Instant::now(),
        QUIET_BEFORE_A_NEW_SPELL + Duration::from_secs(10),
    );
    answering.behind_at = back(
        Instant::now(),
        QUIET_BEFORE_A_NEW_SPELL + Duration::from_secs(1),
    );
    answering.socket_ran_empty();
    dropping(&mut answering);
    assert!(!answering.overloaded, "a new spell");
    assert!(answering.behind_since.elapsed() < BEHIND_BEFORE_TURNS);
}

/// 轮流时不因为在途多拒谁：洪泛的设备占着五千个在途，它自己再来 3 个、发得少的设备一次问 4 个，都去问上游。在途多是
/// 上游慢还是名字不回答，放进来时分不出，拒的话只有一台设备时（转发器或 NAT 后面的全部用户）答得上的也一起被拒；
/// 卡住的查询另有处置（见 `Asking::wait`）
/// While taking turns nobody is refused over what is in flight: with the flooding device
/// holding five thousand in flight, 3 more of its own and a device sending little asking 4 at
/// once all go upstream. Whether many in flight means a slow upstream or names that get no
/// answer cannot be told as a query comes in, and refusing would refuse a lone device (all
/// the users behind a forwarder or NAT) what could be answered too; stuck queries are dealt
/// with elsewhere (see `Asking::wait`)
#[cfg(target_os = "linux")]
#[tokio::test]
async fn while_taking_turns_nobody_is_refused_over_what_is_in_flight() {
    let upstream = spawn_slow_udp_upstream(Duration::from_millis(300)).await;
    let (engine, heavy, light) = engine_with_two_devices(upstream);
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let pending = Arc::new(PendingReplies::default());
    let mut answering = UdpAnswering::new(&socket, &engine, &pending);
    let manager = &engine.permit_manager;
    let _held: Vec<_> = (0..5000)
        .map(|_| manager.acquire_for(manager.slot_of(heavy.ip())))
        .collect();

    let mut turns = answering.begin_turns();
    for (peer, ids) in [(heavy, 1..=3), (light, 4..=7)] {
        for id in ids {
            offer_in_turn(&mut turns, peer, id);
        }
    }
    let mut replies = udp_batch::Replies::default();
    turns.answer_in_turn(&mut answering, &mut replies);
    assert_eq!(manager.dropped_requests(), 0);
    assert_eq!(manager.inflight(), 5007, "those held and all seven");
}

/// 开着流控、转发给 `upstream` 的引擎，以及落在不同份里的两台设备 / An engine with flow control forwarding
/// to `upstream`, and two devices landing in different slots
#[cfg(target_os = "linux")]
fn engine_with_two_devices(upstream: SocketAddr) -> (Arc<Engine>, SocketAddr, SocketAddr) {
    let engine = Arc::new(engine_forwarding_to(
        upstream,
        serde_json::json!({ "flow_control_enabled": true }),
    ));
    let heavy = SocketAddr::from(([127, 0, 0, 4], 53000));
    let light = (2..=250)
        .map(|n| SocketAddr::from(([127, 0, 0, n], 53000)))
        .find(|peer| {
            engine.permit_manager.slot_of(peer.ip()).counted_in()
                != engine.permit_manager.slot_of(heavy.ip()).counted_in()
        })
        .unwrap();
    (engine, heavy, light)
}

#[cfg(target_os = "linux")]
fn offer_in_turn(turns: &mut TakingTurns, peer: SocketAddr, id: u16) {
    let packet = query(&format!("q{id}.turn.test"), id);
    turns
        .queue
        .offer(&packet, Device::of(peer.ip()), udp_batch::Peer::of(peer));
}

/// 收小以后放得下的正好是这台机器 20 ms 处理得完的查询，机器越慢缓冲越小
/// Once shrunk it holds just what this machine handles in 20 ms, so the slower the machine the smaller the buffer
#[test]
fn the_shrunk_receive_buffer_follows_the_speed() {
    // 每秒 5 万个，20 ms 是 1000 个 / At 50k a second, 20 ms is 1000
    assert_eq!(
        recv_buffer_when_behind(queries_within_target(Duration::from_millis(20))),
        1000 * RECV_BUFFER_PER_QUERY
    );
    // 每秒 1 万个，20 ms 是 200 个 / At 10k a second, 20 ms is 200
    assert_eq!(
        recv_buffer_when_behind(queries_within_target(Duration::from_millis(100))),
        200 * RECV_BUFFER_PER_QUERY
    );
    // 再慢也放得下两批 / However slow it holds two batches
    assert_eq!(
        recv_buffer_when_behind(queries_within_target(Duration::from_secs(60))),
        MIN_QUERIES_IN_RECV_BUFFER * RECV_BUFFER_PER_QUERY
    );
    // 再快也不比平时大 / However fast it is no larger than usual
    assert_eq!(
        recv_buffer_when_behind(queries_within_target(Duration::ZERO)),
        UDP_BUFFER_SIZE
    );
}

/// 开着流控、对什么查询都当场回答的引擎 / An engine with flow control answering every query on the spot
fn static_engine_with_flow_control() -> Arc<Engine> {
    use crate::config::PipelineConfig;

    let config: PipelineConfig = serde_json::from_value(serde_json::json!({
        "settings": { "default_upstream": "127.0.0.1:9", "flow_control_enabled": true },
        "pipelines": [{
            "id": "p",
            "rules": [{
                "name": "static",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "static_ip_response", "ip": "192.0.2.1" }]
            }]
        }]
    }))
    .unwrap();
    Arc::new(
        Engine::new(
            RuntimePipelineConfig::from_config(config).unwrap(),
            "test".to_string(),
        )
        .unwrap(),
    )
}

/// 跟不上持续够久、刚才还在跟不上、开着流控，三样都有才算过载；丢包和这个 worker 自己的查询被拒都算跟不上，
/// 别处的拒绝不算
/// Overload takes all three: falling behind for long enough, still so a moment ago, and flow
/// control on; drops and refusals of this worker's own queries both count as falling behind,
/// refusals elsewhere do not
#[cfg(target_os = "linux")]
#[tokio::test]
async fn overload_takes_lasting_trouble_and_flow_control() {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let pending = Arc::new(PendingReplies::default());
    let drops = crate::socket_utils::udp_receive_drops(&socket).unwrap();
    let dropping = drops.wrapping_add(1);
    let long_ago = || Instant::now() - Duration::from_secs(5);
    let look = |answering: &mut UdpAnswering<'_>, since: Instant, at: Instant, seen: u32| {
        answering.behind_since = since;
        answering.behind_at = at;
        answering.drops_seen = Some(seen);
        answering.checks_since_empty = 2 * BEHIND_AFTER_CHECKS - 1;
        answering.shrink_buffer_if_overflowing();
    };
    let with_flow = static_engine_with_flow_control();
    let mut answering = UdpAnswering::new(&socket, &with_flow, &pending);

    look(&mut answering, long_ago(), Instant::now(), dropping);
    assert!(answering.overloaded);
    look(&mut answering, Instant::now(), Instant::now(), dropping);
    assert!(!answering.overloaded, "not for long enough");
    // 停了几秒又跟不上，还是同一阵；停够一分钟才算新的一阵 / Behind again after a few seconds'
    // pause is the same spell; only a minute's quiet makes a new one
    look(&mut answering, long_ago(), long_ago(), dropping);
    assert!(answering.overloaded, "the same spell, a few seconds on");
    let quiet = Instant::now()
        .checked_sub(QUIET_BEFORE_A_NEW_SPELL + Duration::from_secs(1))
        .expect("the clock is far enough from its start");
    look(&mut answering, long_ago(), quiet, dropping);
    assert!(!answering.overloaded, "a new spell begins");
    assert!(answering.behind_since.elapsed() < BEHIND_BEFORE_TURNS);
    assert!(answering.behind_at.elapsed() < CAUGHT_UP_AFTER);
    let since = long_ago();
    look(&mut answering, since, Instant::now(), dropping);
    assert_eq!(answering.behind_since, since, "the spell goes on");
    look(&mut answering, long_ago(), Instant::now(), drops);
    assert!(answering.overloaded, "a short pause does not end it");
    look(&mut answering, long_ago(), long_ago(), drops);
    assert!(!answering.overloaded, "it is over");

    // 自己的查询被拒也算；别的 worker、TCP 和 DoH 的拒绝不算 / Its own queries refused count too;
    // refusals in another worker or over TCP and DoH do not
    with_flow
        .permit_manager
        .count_refused(crate::engine::concurrency::Defence::Capacity);
    look(&mut answering, long_ago(), long_ago(), drops);
    assert!(
        answering.behind_at.elapsed() > CAUGHT_UP_AFTER,
        "a refusal elsewhere"
    );
    answering.refused = true;
    look(&mut answering, long_ago(), long_ago(), drops);
    assert!(
        answering.behind_at.elapsed() < CAUGHT_UP_AFTER,
        "its own refusal"
    );
    let at = long_ago();
    look(&mut answering, long_ago(), at, drops);
    assert_eq!(answering.behind_at, at, "no new refusal");

    let without_flow = Arc::new(Engine::new(static_runtime(), "test".to_string()).unwrap());
    let mut answering = UdpAnswering::new(&socket, &without_flow, &pending);
    look(&mut answering, long_ago(), Instant::now(), dropping);
    assert!(!answering.overloaded, "flow control off");
}

/// 轮流时内核来不及处理，一次问 4 个的设备一个都不丢：它那 4 个和一直在发的那台轮着交出去，都在头 8 个里。一直在发的那台
/// 超出自己那一份的，排进去时就丢了。以前后面还排着别的就丢，单核上它每次并发的中间几个都没有回应
/// Taking turns with a kernel that cannot keep up, a device asking 4 at once loses none: its
/// 4 are handed over in turn with those of the one sending on and on, all within the first
/// 8. What the one sending on and on has over its share was dropped as it was offered.
/// Having more queued at all used to lose one, so on a single core the middle ones of each
/// few at once got no reply
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_device_asking_a_few_at_once_loses_none_taking_turns() {
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let engine = engine_forwarding_with_flow_control(&upstream);
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let pending = Arc::new(PendingReplies::default());
    let mut answering = UdpAnswering::new(&socket, &engine, &pending);
    let mut turns = answering.begin_turns();
    let heavy = SocketAddr::from(([192, 0, 2, 1], 53000));
    let light = SocketAddr::from(([192, 0, 2, 2], 53000));
    let room = answering.queries_within_target;
    let fit = (0..5000u16)
        .filter(|&id| {
            let packet = query(&format!("h{id}.heavy.test"), id);
            let peer = udp_batch::Peer::of(heavy);
            turns.queue.offer(&packet, Device::of(heavy.ip()), peer)
        })
        .count();
    assert_eq!(fit, room, "the rest did not fit");
    for id in 0..4 {
        let packet = query(&format!("l{id}.light.test"), id);
        let peer = udp_batch::Peer::of(light);
        assert!(turns.queue.offer(&packet, Device::of(light.ip()), peer));
    }
    engine
        .flow_control_state
        .as_ref()
        .unwrap()
        .note_queue_delay(Duration::from_secs(3600));

    let mut replies = udp_batch::Replies::default();
    turns.answer_in_turn(&mut answering, &mut replies);
    assert_eq!(engine.permit_manager.dropped_requests(), 0);
    let asked = asked_of(&upstream, udp_batch::BATCH).await;
    let of_light: Vec<_> = asked
        .iter()
        .filter(|name| name.ends_with("light.test."))
        .collect();
    assert_eq!(of_light.len(), 4, "all four of the light device: {asked:?}");
}

/// 有活等着内核干的查询够多时，当场答得上的查询也留着不取：取出来才知道它答不答得上，答不上的就得交出去
/// With enough queries having work waiting for the kernel, a query answerable on the spot
/// stays queued too: only taking it tells whether it is, and one that is not would have to
/// be handed over
#[cfg(target_os = "linux")]
#[tokio::test]
async fn nothing_is_taken_in_turn_while_the_kernel_has_enough() {
    let engine = static_engine_with_flow_control();
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let pending = Arc::new(PendingReplies::default());
    let mut answering = UdpAnswering::new(&socket, &engine, &pending);
    let mut turns = answering.begin_turns();
    let from = SocketAddr::from(([192, 0, 2, 1], 53000));
    let packet = query("a.test", 1);
    let offer = |turns: &mut TakingTurns| {
        turns
            .queue
            .offer(&packet, Device::of(from.ip()), udp_batch::Peer::of(from))
    };
    assert!(offer(&mut turns));
    let mut replies = udp_batch::Replies::default();

    // 交出去、一直没跑的任务 / Tasks handed over and never run
    let waiting = &engine.flow_control_state.as_ref().unwrap().waiting_to_run;
    let hand_over = |count: usize| -> Vec<_> {
        (0..count)
            .map(|_| {
                Box::pin(crate::engine::concurrency::WaitingToRun::counting(
                    Arc::clone(waiting),
                    std::future::pending::<()>(),
                ))
            })
            .collect()
    };
    let handed_over = hand_over(WAITING_TO_RUN_AT_MOST);
    turns.answer_in_turn(&mut answering, &mut replies);
    assert!(replies.is_empty(), "enough waiting to run");
    assert_eq!(turns.queue.devices(), 1, "still queued");

    // 少一个就接着取；任务没跑就被丢掉也不再算 / One fewer and taking goes on; a task dropped
    // before it ran counts no more either
    drop(handed_over);
    assert!(offer(&mut turns));
    let _one_short = hand_over(WAITING_TO_RUN_AT_MOST - 1);
    turns.answer_in_turn(&mut answering, &mut replies);
    assert_eq!(replies.len(), 2);
}

/// 有活等着内核干的查询只在轮流时记：不轮流时接收循环不看这个数，查询也就不必为它多花什么。任务一开始跑就不再算，它还在
/// 等上游也一样——等上游不是内核在排队
/// Queries with work waiting for the kernel are counted only while taking turns: without
/// turns the receive loops do not go by the count, so a query pays nothing for it. A task
/// counts no more as soon as it starts, still waiting on its upstream or not: waiting on
/// an upstream is not the kernel queueing
#[tokio::test]
async fn queries_handed_over_are_counted_only_while_taking_turns() {
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let engine = engine_forwarding_with_flow_control(&upstream);
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let pending = Arc::new(PendingReplies::default());
    let mut answering = UdpAnswering::new(&socket, &engine, &pending);
    let peer = SocketAddr::from(([192, 0, 2, 1], 53000));
    let mut reply = BytesMut::new();
    let waiting = |answering: &UdpAnswering<'_>| {
        let flow = answering.engine.flow_control_state.as_ref().unwrap();
        flow.waiting_to_run.count()
    };

    answering.answer(&query("a.test", 1), peer, &mut reply);
    assert_eq!(engine.permit_manager.inflight(), 1, "handed over");
    assert_eq!(waiting(&answering), 0, "not taking turns");

    answering.taking_turns = true;
    answering.answer(&query("b.test", 2), peer, &mut reply);
    assert_eq!(waiting(&answering), 1);
    asked_of(&upstream, 2).await;
    assert_eq!(waiting(&answering), 0, "started");
    assert_eq!(
        engine.permit_manager.inflight(),
        2,
        "both still waiting on the upstream"
    );
}

/// `devices` 台设备各排进 4 个各不相同的查询，名字是 `q<第几个>.d<第几台>.test`
/// Queues 4 queries, each different, from each of `devices` devices, named
/// `q<which>.d<device>.test`
fn queue_four_each<P>(queue: &mut FairQueue<P>, devices: u16, peer: impl Fn(SocketAddr) -> P) {
    for device in 0..devices {
        let [high, low] = device.to_be_bytes();
        let from = SocketAddr::from(([198, 18, high, low], 53000));
        for which in 0..4u16 {
            let packet = query(&format!("q{which}.d{device}.test"), which);
            assert!(queue.offer(&packet, Device::of(from.ip()), peer(from)));
        }
    }
}

/// 开着流控、把什么查询都转发给 `upstream` 的引擎 / An engine with flow control forwarding every
/// query to `upstream`
fn engine_forwarding_with_flow_control(upstream: &UdpSocket) -> Arc<Engine> {
    Arc::new(engine_forwarding_to(
        upstream.local_addr().unwrap(),
        serde_json::json!({ "flow_control_enabled": true }),
    ))
}

/// 等到 `upstream` 收到 `count` 个查询：交出去的那些都开始跑了，各问了上游一次。返回问到的名字
/// Waits until `upstream` has received `count` queries: those handed over have all started
/// and asked the upstream once each. Gives the names asked
async fn asked_of(upstream: &UdpSocket, count: usize) -> Vec<String> {
    let mut buf = [0u8; 512];
    let mut names = Vec::new();
    for _ in 0..count {
        let (len, _) = tokio::time::timeout(Duration::from_secs(5), upstream.recv_from(&mut buf))
            .await
            .expect("each query handed over asks the upstream")
            .unwrap();
        let asked = Message::from_bytes(&buf[..len]).unwrap();
        names.push(asked.queries[0].name().to_string());
    }
    names
}

/// 轮流时有活等着内核干的查询不超过 `WAITING_TO_RUN_AT_MOST` 个：一千台设备各排着 4 个、交出去的一个都还没开始跑时，
/// 再轮多少批也只交那么多，其余的留在各设备自己的队列里，一个不丢；交出去的开始跑了，才接着交同样多。以前内核跟不上时只丢
/// 「后面排着的不比平均少、又至少排着 4 个」的设备的查询，设备多到每台排不满 4 个时一个都不丢，接收循环按自己的速度全交
/// 出去：在途只涨不降，所有设备一起超时
/// Taking turns has at most `WAITING_TO_RUN_AT_MOST` queries with work waiting for the
/// kernel: with a thousand devices holding 4 each and none of those handed over started
/// yet, however many batches are taken only that many go, the rest staying in each device's
/// own queue with none dropped; once those have started, as many again follow. Falling behind
/// used to drop only
/// from a device with no fewer queued behind it than the average and at least 4, so with
/// devices so many that none queues 4 nothing was dropped and the receive loop handed over
/// everything at its own speed: what was in flight only grew, and every device timed out
#[cfg(target_os = "linux")]
#[tokio::test]
async fn taking_turns_hands_over_only_what_the_kernel_gets_to() {
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let engine = engine_forwarding_with_flow_control(&upstream);
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let pending = Arc::new(PendingReplies::default());
    let mut answering = UdpAnswering::new(&socket, &engine, &pending);
    let mut turns = answering.begin_turns();
    queue_four_each(&mut turns.queue, 1000, udp_batch::Peer::of);
    // 内核跟不上 / The kernel cannot keep up
    engine
        .flow_control_state
        .as_ref()
        .unwrap()
        .note_queue_delay(Duration::from_secs(3600));

    let mut replies = udp_batch::Replies::default();
    // 比排着的 4000 个还多的轮数 / More turns than the 4000 queued would take
    let batches = 4000 / udp_batch::BATCH + 1;
    for _ in 0..batches {
        turns.answer_in_turn(&mut answering, &mut replies);
    }
    assert_eq!(
        engine.permit_manager.inflight(),
        WAITING_TO_RUN_AT_MOST,
        "no more, however many turns"
    );
    assert_eq!(
        engine.permit_manager.dropped_requests(),
        0,
        "the rest stay queued"
    );

    asked_of(&upstream, WAITING_TO_RUN_AT_MOST).await;
    for _ in 0..batches {
        turns.answer_in_turn(&mut answering, &mut replies);
    }
    assert_eq!(
        engine.permit_manager.inflight(),
        2 * WAITING_TO_RUN_AT_MOST,
        "those started, as many again"
    );
    assert!(replies.is_empty(), "none answered on the spot");
}

/// 逐个收的循环轮流时也一样 / The same for the loop receiving one by one taking turns
#[tokio::test]
async fn turns_one_by_one_hand_over_only_what_the_kernel_gets_to() {
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let engine = engine_forwarding_with_flow_control(&upstream);
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let pending = Arc::new(PendingReplies::default());
    let mut answering = UdpAnswering::new(&socket, &engine, &pending);
    let mut turns = answering.begin_turns_one_by_one();
    queue_four_each(&mut turns.queue, 1000, ReplyTo::from);
    engine
        .flow_control_state
        .as_ref()
        .unwrap()
        .note_queue_delay(Duration::from_secs(3600));

    let mut reply = BytesMut::new();
    let batches = 4000 / ONE_BY_ONE_TURN + 1;
    for _ in 0..batches {
        turns.answer_in_turn(&mut answering, &mut reply).await;
    }
    assert_eq!(engine.permit_manager.inflight(), WAITING_TO_RUN_AT_MOST);
    assert_eq!(engine.permit_manager.dropped_requests(), 0);

    asked_of(&upstream, WAITING_TO_RUN_AT_MOST).await;
    for _ in 0..batches {
        turns.answer_in_turn(&mut answering, &mut reply).await;
    }
    assert_eq!(engine.permit_manager.inflight(), 2 * WAITING_TO_RUN_AT_MOST);
}

/// 排不下的丢掉并计数；不轮流的话缓冲放得下就不算跟不上，放不下才算
/// What does not fit is dropped and counted; it is falling behind only when the buffer would
/// not hold it without turns either
#[cfg(target_os = "linux")]
#[tokio::test]
async fn what_does_not_fit_counts_only_when_the_buffer_would_overflow() {
    use std::os::fd::AsRawFd;

    let engine = static_engine_with_flow_control();
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for _ in 0..7 {
        client
            .send_to(b"query", socket.local_addr().unwrap())
            .await
            .unwrap();
    }
    let pending = Arc::new(PendingReplies::default());
    let mut answering = UdpAnswering::new(&socket, &engine, &pending);
    let mut received = udp_batch::Received::default();
    let got = received.recv(socket.as_raw_fd()).unwrap();
    assert_eq!(got, 7);

    // 份额至少 4 个，排进 4 个丢 3 个 / A share of at least 4, so 4 get in and 3 are dropped
    let mut turns = TakingTurns::new(2, QUERIES_IN_RECV_BUFFER);
    answering.behind_at = Instant::now() - Duration::from_secs(5);
    turns.queue_received(&received, got, &mut answering);
    assert_eq!(engine.permit_manager.dropped_requests(), 3);
    assert!(
        answering.behind_at.elapsed() > CAUGHT_UP_AFTER,
        "the buffer would hold them"
    );

    // 积压已经满了，不轮流的话这几个内核会丢 / With the backlog full, the kernel would drop these
    // without turns
    let mut turns = TakingTurns::new(100, QUERIES_IN_RECV_BUFFER);
    turns.backlog = turns.holds;
    turns.counted_at = Instant::now() + Duration::from_secs(3600);
    turns.queue_received(&received, got, &mut answering);
    assert!(
        answering.behind_at.elapsed() < CAUGHT_UP_AFTER,
        "past the buffer"
    );
    assert_eq!(engine.permit_manager.dropped_requests(), 3, "all fit");
}

/// 不轮流时的积压：读到的加上，按量到的速度消掉，到缓冲放得下的为止
/// The backlog without turns: what is read adds to it, the measured speed works it off, and it
/// stops at what the buffer holds
#[cfg(target_os = "linux")]
#[test]
fn the_backlog_without_turns_is_worked_off_at_the_measured_speed() {
    let start = Instant::now();
    let mut turns = TakingTurns::new(10, QUERIES_IN_RECV_BUFFER);
    turns.counted_at = start;
    assert!(
        !turns.would_overflow(QUERIES_IN_RECV_BUFFER, 64, start),
        "just full"
    );
    assert!(turns.would_overflow(1, 64, start), "one more");
    assert_eq!(turns.backlog, QUERIES_IN_RECV_BUFFER);
    let later = start + QUEUE_TARGET;
    assert!(!turns.would_overflow(64, 64, later), "64 handled meanwhile");
    assert!(turns.would_overflow(1, 64, later));
    let much_later = later + Duration::from_secs(3600);
    assert!(!turns.would_overflow(0, 64, much_later));
    assert_eq!(turns.backlog, 0, "worked off");

    // 每半秒发一批、比份额多得多，平均却没到处理能力：缓冲接得住 / A batch far past the share
    // every half second, below capacity on average: the buffer catches it
    let mut at = much_later;
    for _ in 0..20 {
        at += Duration::from_millis(500);
        assert!(
            !turns.would_overflow(1000, 64, at),
            "{} held",
            turns.backlog
        );
    }
    // 平均超出处理能力：迟早放不下 / Past capacity on average: sooner or later it does not fit
    let overflowed = (0..100).any(|_| {
        at += Duration::from_millis(500);
        turns.would_overflow(2000, 64, at)
    });
    assert!(overflowed);
}

/// 洪泛停了，一台设备每次发得比自己那一份多、平均却没到处理能力：排不下的照丢，跟上了轮流就结束，不会自己一直撑着
/// The flood over, a device sending more than its share each time but below capacity on
/// average: what does not fit still goes, and turns end on catching up instead of keeping
/// themselves going
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_burst_past_the_share_does_not_keep_turns_going() {
    use std::os::fd::AsRawFd;

    let engine = static_engine_with_flow_control();
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    socket2::SockRef::from(socket.as_ref())
        .set_recv_buffer_size(UDP_BUFFER_SIZE)
        .unwrap();
    let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let pending = Arc::new(PendingReplies::default());
    let mut answering = UdpAnswering::new(&socket, &engine, &pending);
    let mut turns = answering.begin_turns();
    answering.overloaded = true;
    answering.behind_at = Instant::now() - CAUGHT_UP_AFTER - Duration::from_millis(1);
    // 内核这会儿也跟不上 / The kernel is falling behind just now, too
    engine
        .flow_control_state
        .as_ref()
        .unwrap()
        .note_queue_delay(Duration::from_secs(3600));

    let burst = 3 * answering.queries_within_target;
    let packet = query("burst.test", 1);
    for _ in 0..burst {
        client
            .send_to(&packet, socket.local_addr().unwrap())
            .unwrap();
    }
    let mut received = udp_batch::Received::default();
    let mut read = 0;
    while read < burst {
        let got = received.recv(socket.as_raw_fd()).unwrap();
        turns.queue_received(&received, got, &mut answering);
        read += got;
    }
    let mut replies = udp_batch::Replies::default();
    while !turns.queue.is_empty() {
        turns.answer_in_turn(&mut answering, &mut replies);
        replies.clear();
    }
    assert!(
        engine.permit_manager.dropped_requests() as usize > burst / 2,
        "past its share"
    );
    answering.socket_ran_empty();
    assert!(!answering.taking_turns, "caught up");
    assert!(!answering.overloaded);
}

/// 轮流时只看内存：内核跟不上也不回 SERVFAIL，该丢的已经丢了；不轮流时照常拒绝
/// Taking turns goes by memory alone: falling behind gives no SERVFAIL, as what should go
/// has gone; without turns it refuses as usual
#[tokio::test]
async fn taking_turns_goes_by_memory_alone() {
    let engine = Arc::new(behind_engine_with_slow_upstream(0).await);
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let pending = Arc::new(PendingReplies::default());
    let mut answering = UdpAnswering::new(&socket, &engine, &pending);
    let peer = UdpSocket::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let mut reply = BytesMut::new();
    // 这台设备已经有一个在途，过载时它在平均上，不轮流就拒 / This device already has one in flight,
    // so under overload it holds its share and is refused without turns
    let manager = &engine.permit_manager;
    let _held = manager.acquire_for(manager.slot_of(peer.ip()));

    answering.emptied_at = Instant::now() - Duration::from_secs(1);
    answering.answer(&query("a.queue.test", 1), peer, &mut reply);
    assert_eq!(engine.permit_manager.dropped_requests(), 1);
    assert!(answering.refused, "noted as its own refusal");

    answering.refused = false;
    answering.taking_turns = true;
    answering.answer(&query("b.queue.test", 2), peer, &mut reply);
    assert_eq!(engine.permit_manager.dropped_requests(), 1);
    assert_eq!(engine.permit_manager.inflight(), 2, "the one held and this");
    assert!(!answering.refused);

    // 快速解析读不了、从头解析的也记下 / One the quick parse cannot read, parsed from scratch, is noted too
    answering.taking_turns = false;
    answering.answer(&query_parsed_from_scratch(3), peer, &mut reply);
    assert_eq!(engine.permit_manager.dropped_requests(), 2);
    assert!(answering.refused, "noted from the full path too");
}

/// 轮流要等跟上才结束：还在跟不上时 socket 收空也继续 / Turns end only on catching up: still falling
/// behind, running empty does not end them
#[tokio::test]
async fn turns_go_on_until_caught_up() {
    let engine = static_engine_with_flow_control();
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let pending = Arc::new(PendingReplies::default());
    let mut answering = UdpAnswering::new(&socket, &engine, &pending);
    answering.taking_turns = true;
    answering.overloaded = true;
    answering.behind_at = Instant::now();
    answering.socket_ran_empty();
    assert!(answering.taking_turns, "a moment ago");
    assert!(answering.overloaded);
    answering.behind_at = Instant::now() - CAUGHT_UP_AFTER - Duration::from_millis(1);
    answering.socket_ran_empty();
    assert!(!answering.taking_turns);
    assert!(!answering.overloaded);
}

/// 一轮答一批：只有一台在排队时答它排着的，很多台时答满一批
/// A turn answers one batch: what a single device has queued, or a full batch from many
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_turn_answers_one_batch() {
    let engine = static_engine_with_flow_control();
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let pending = Arc::new(PendingReplies::default());
    let mut answering = UdpAnswering::new(&socket, &engine, &pending);
    let mut replies = udp_batch::Replies::default();
    let packet = query("a.test", 1);
    let offer = |turns: &mut TakingTurns, last: u8| {
        let ip = [192, 0, 2, last];
        let peer = udp_batch::Peer::of(SocketAddr::from((ip, 53000)));
        turns.queue.offer(&packet, Device::of(ip.into()), peer);
    };

    let mut turns = TakingTurns::new(1000, QUERIES_IN_RECV_BUFFER);
    offer(&mut turns, 1);
    turns.answer_in_turn(&mut answering, &mut replies);
    assert_eq!(replies.len(), 1);
    replies.clear();

    for last in 1..=255 {
        offer(&mut turns, last);
    }
    assert!(turns.queue.devices() > 1);
    turns.answer_in_turn(&mut answering, &mut replies);
    assert_eq!(replies.len(), udp_batch::BATCH, "one batch per turn");
}

/// 开始轮流时记下状态，队列按量到的速度算，积压按接收缓冲实际放得下的算 / Beginning turns is noted, with a
/// queue sized by the measured speed and the backlog by what the receive buffer actually holds
#[cfg(target_os = "linux")]
#[tokio::test]
async fn turns_begin_with_room_from_the_measured_speed() {
    let engine = static_engine_with_flow_control();
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let pending = Arc::new(PendingReplies::default());
    let mut answering = UdpAnswering::new(&socket, &engine, &pending);
    answering.queries_within_target = 6;
    let sock = socket2::SockRef::from(socket.as_ref());
    sock.set_recv_buffer_size(100_000).unwrap();
    let mut turns = answering.begin_turns();
    assert!(answering.taking_turns);
    let holds = sock.recv_buffer_size().unwrap() / (2 * RECV_BUFFER_PER_QUERY);
    assert_eq!(turns.holds, holds, "as much as the buffer actually holds");
    assert!(holds < QUERIES_IN_RECV_BUFFER);
    let device = Device::of([192, 0, 2, 1].into());
    let peer = udp_batch::Peer::of(SocketAddr::from(([192, 0, 2, 1], 53000)));
    for _ in 0..6 {
        assert!(turns.queue.offer(b"q", device, peer));
    }
    assert!(!turns.queue.offer(b"q", device, peer));

    // 量到的速度变了，下一轮跟着变 / The measured speed changing, the next turn follows
    answering.queries_within_target = 9;
    let mut replies = udp_batch::Replies::default();
    turns.answer_in_turn(&mut answering, &mut replies);
    for _ in 0..9 {
        assert!(turns.queue.offer(b"q", device, peer));
    }
    assert!(!turns.queue.offer(b"q", device, peer));
}

/// 内核忙、查询没在内核里排长队时，不因为在途多拒谁：占着五千个在途的设备和发得少的设备都照常去问上游
/// Busy without queries queueing long inside the kernel, nobody is refused over what is in
/// flight: the device holding five thousand in flight and one sending little both go
/// upstream as usual
#[cfg(target_os = "linux")]
#[tokio::test]
async fn busy_without_queueing_refuses_nobody_over_what_is_in_flight() {
    let upstream = spawn_slow_udp_upstream(Duration::from_millis(300)).await;
    let (engine, heavy, light) = engine_with_two_devices(upstream);
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let pending = Arc::new(PendingReplies::default());
    let mut answering = UdpAnswering::new(&socket, &engine, &pending);
    answering.emptied_at = Instant::now() - Duration::from_secs(1);
    let manager = &engine.permit_manager;
    let _held: Vec<_> = (0..5000)
        .map(|_| manager.acquire_for(manager.slot_of(heavy.ip())))
        .collect();
    let packet = |id: u16| Bytes::from(query(&format!("q{id}.busy.test"), id));
    assert!(
        spawn_udp_answer(&answering, packet(1), heavy, None),
        "the device holding most"
    );
    assert!(
        spawn_udp_answer(&answering, packet(2), light, None),
        "a device sending little"
    );
    assert_eq!(manager.dropped_requests(), 0);
    assert_eq!(manager.inflight(), 5002);
}

/// 读的时候量一个查询在接收缓冲里实际记多少，放得下的按量到的算；只往少里改
/// Reading measures what a query is actually charged in the receive buffer and what fits
/// follows it, only ever downwards
#[cfg(target_os = "linux")]
#[tokio::test]
async fn reading_measures_what_a_query_takes_in_the_receive_buffer() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let send_batch = || {
        for _ in 0..udp_batch::BATCH {
            client
                .send_to(&query("a.test", 1), socket.local_addr().unwrap())
                .unwrap();
        }
    };
    let mut received = udp_batch::Received::default();

    send_batch();
    let (queued, buffer) = crate::socket_utils::udp_receive_queue(&socket).unwrap();
    let charge = queued as usize / udp_batch::BATCH;
    assert!(charge > query("a.test", 1).len(), "{charge}");
    let mut turns = TakingTurns::new(10, usize::MAX);
    socket.readable().await.unwrap();
    assert_eq!(
        turns.read(&socket, &mut received).unwrap(),
        udp_batch::BATCH
    );
    assert_eq!(
        turns.holds,
        buffer as usize / charge,
        "as many as actually fit"
    );
    assert_eq!(
        turns.reading.samples_left,
        CHARGE_SAMPLES - 1,
        "one batch measured"
    );

    send_batch();
    let mut turns = TakingTurns::new(10, MIN_QUERIES_IN_RECV_BUFFER);
    socket.readable().await.unwrap();
    turns.read(&socket, &mut received).unwrap();
    assert_eq!(
        turns.holds, MIN_QUERIES_IN_RECV_BUFFER,
        "never more than reckoned"
    );

    // 量够了就不再量 / Once measured enough it measures no more
    turns.reading.samples_left = 0;
    turns.holds = usize::MAX;
    send_batch();
    socket.readable().await.unwrap();
    turns.read(&socket, &mut received).unwrap();
    assert_eq!(turns.holds, usize::MAX);
}

/// 答一批之前最多读这么多批 / At most this many batches are read before one is answered
#[cfg(target_os = "linux")]
#[test]
fn reads_before_a_turn_have_a_limit() {
    let mut turns = TakingTurns::new(100, QUERIES_IN_RECV_BUFFER);
    let allowed = (0..100).take_while(|_| turns.may_read_more()).count();
    assert_eq!(allowed, READS_PER_TURN - 1);
}

/// `fd` 这个 socket 的接收缓冲是不是已经排到四分之三；读不到（socket 已经关了）是 `None`
/// Whether the receive buffer of socket `fd` is three quarters full already; `None` when it
/// cannot be read, the socket being closed
#[cfg(target_os = "linux")]
fn receive_buffer_mostly_full(fd: std::os::fd::RawFd) -> Option<bool> {
    let mut info = [0u32; libc::SK_MEMINFO_RCVBUF as usize + 1];
    let mut len = std::mem::size_of_val(&info) as libc::socklen_t;
    // SAFETY: the buffer and its length are valid for the call, which only writes within them
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MEMINFO,
            info.as_mut_ptr().cast(),
            &mut len,
        )
    };
    let queued = info[libc::SK_MEMINFO_RMEM_ALLOC as usize] as usize;
    (ret == 0).then(|| 4 * queued >= 3 * info[libc::SK_MEMINFO_RCVBUF as usize] as usize)
}

/// 洪泛怎么发：只管发 / How the flood sends: as fast as it can
#[cfg(target_os = "linux")]
const FLOOD_FREELY: u8 = 0;
/// 请它别挤满接收缓冲 / Asked to leave the receive buffer short of full
#[cfg(target_os = "linux")]
const FLOOD_ASKED_GENTLE: u8 = 1;
/// 它看到了，从此每发一个先看缓冲 / It has seen that, and from then on looks at the buffer before each send
#[cfg(target_os = "linux")]
const FLOOD_GENTLE: u8 = 2;

/// 一直发直到 `stop`，发的是当场能答的查询。`mode` 改成 `FLOOD_ASKED_GENTLE` 以后它回一个 `FLOOD_GENTLE`，从此
/// `server` 的接收缓冲排到四分之三就先等一等：洪泛照样远超处理能力，只是缓冲满不了。轮流读得比洪泛快时本来就是这样，
/// 可测试里读和发是两个线程，谁快一时半会说不准，读慢了一下缓冲就满，内核会把别的设备的包和洪泛一起丢掉
/// Keeps sending queries answered on the spot until `stop`. Once `mode` is set to
/// `FLOOD_ASKED_GENTLE` it answers with `FLOOD_GENTLE`, and from then on waits whenever
/// `server`'s receive buffer is three quarters full: the flood still goes far past what can be
/// handled, only the buffer never fills. That is how taking turns goes while it reads faster
/// than the flood, but in a test reading and sending are two threads and either may be ahead
/// for a moment; with reading behind for a moment the buffer fills and the kernel drops
/// another device's datagram along with the flood
#[cfg(target_os = "linux")]
fn flood_from(
    source: [u8; 4],
    server: &UdpSocket,
    stop: Arc<std::sync::atomic::AtomicBool>,
    mode: Arc<std::sync::atomic::AtomicU8>,
) -> std::thread::JoinHandle<()> {
    use std::os::fd::AsRawFd;
    use std::sync::atomic::Ordering;

    let socket = std::net::UdpSocket::bind(SocketAddr::from((source, 0))).unwrap();
    let (target, fd) = (server.local_addr().unwrap(), server.as_raw_fd());
    let packet = query("flood.test", 1);
    std::thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            let _ = mode.compare_exchange(
                FLOOD_ASKED_GENTLE,
                FLOOD_GENTLE,
                Ordering::SeqCst,
                Ordering::SeqCst,
            );
            if mode.load(Ordering::SeqCst) == FLOOD_GENTLE {
                // 测试先失败了，socket 已经关掉 / The test failed first and closed the socket
                let Some(mostly_full) = receive_buffer_mostly_full(fd) else {
                    return;
                };
                if mostly_full {
                    std::thread::yield_now();
                    continue;
                }
            }
            let _ = socket.send_to(&packet, target);
        }
    })
}

/// 逐个收的循环（没有 recvmmsg 的系统用的那个）也按设备轮流：一台设备把 CPU 占满时，另一台一个一个地问也都答得上。以前
/// 只有 Linux 的批量循环会轮流，逐个收的循环在洪泛下一个都不拒，别的设备和不开流控时一样答不上
/// The loop receiving one by one (the one for systems without recvmmsg) takes devices in turn
/// too: with one device taking all the CPU another asking one at a time is answered every time.
/// Only Linux's batched loop used to take turns, and the loop receiving one by one refused
/// nothing under a flood, leaving other devices as unanswered as without flow control
#[cfg(target_os = "linux")]
#[tokio::test]
async fn the_loop_receiving_one_by_one_takes_turns_too() {
    flood_the_loop_receiving_one_by_one(true).await;
}

/// 读不到丢包数时也一样：FreeBSD、Windows 上就是这样 / The same without drops to read, as on
/// FreeBSD and Windows
#[cfg(target_os = "linux")]
#[tokio::test]
async fn the_loop_receiving_one_by_one_takes_turns_without_drops_to_read() {
    flood_the_loop_receiving_one_by_one(false).await;
}

#[cfg(target_os = "linux")]
async fn flood_the_loop_receiving_one_by_one(reads_drops: bool) {
    use std::os::fd::AsRawFd;

    let engine = static_engine_with_flow_control();
    let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let target = server.local_addr().unwrap();
    let worker = {
        let (server, engine) = (Arc::clone(&server), Arc::clone(&engine));
        tokio::spawn(async move {
            receive_one_by_one_reading_drops(&server, &engine, reads_drops).await
        })
    };
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mode = Arc::new(std::sync::atomic::AtomicU8::new(FLOOD_FREELY));
    let flood = flood_from(
        [127, 0, 0, 2],
        &server,
        Arc::clone(&stop),
        Arc::clone(&mode),
    );
    let client = UdpSocket::bind("127.0.0.3:0").await.unwrap();
    let mut buf = [0u8; 512];

    // 轮流时排不下的才计入被拒绝，这里没有别的拒绝 / Only what does not fit while taking turns is
    // counted as refused, and nothing else gets refused here
    let started = Instant::now();
    while engine.permit_manager.dropped_requests() == 0 {
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "turns never began"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // 洪泛从这里起不挤满缓冲，内核一个包都不丢，没答上的只能是轮流没轮到它 / From here the flood
    // leaves the buffer short of full and the kernel drops nothing, so one left unanswered could
    // only be one taking turns passed over
    mode.store(FLOOD_ASKED_GENTLE, std::sync::atomic::Ordering::SeqCst);
    let started = Instant::now();
    while mode.load(std::sync::atomic::Ordering::SeqCst) != FLOOD_GENTLE
        || receive_buffer_mostly_full(server.as_raw_fd()).unwrap()
    {
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "the flood never eased"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let cut = engine.permit_manager.dropped_requests();
    for id in 0..20 {
        client
            .send_to(&query("light.test", id), target)
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf))
            .await
            .unwrap_or_else(|_| panic!("query {id} unanswered"))
            .unwrap();
    }
    assert!(
        engine.permit_manager.dropped_requests() > cut,
        "the flood is still being cut"
    );
    // 洪泛停了、跟上了：轮流结束，一阵突发不因排不下被丢 / The flood over and caught up: turns end,
    // and a burst is not dropped for not fitting
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    flood.join().unwrap();
    tokio::time::sleep(CAUGHT_UP_AFTER + Duration::from_millis(200)).await;
    let refused = engine.permit_manager.dropped_requests();
    let packet = query("light.test", 3);
    let sender = std::net::UdpSocket::bind("127.0.0.4:0").unwrap();
    let sending = std::thread::spawn(move || {
        for _ in 0..3000 {
            sender.send_to(&packet, target).unwrap();
        }
    });
    sending.join().unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        engine.permit_manager.dropped_requests(),
        refused,
        "caught up, nothing is dropped for not fitting"
    );
    worker.abort();
}

/// 读不到丢包数的系统上，不在轮流时 socket 连续 `BUSY_AFTER` 没收空就算在丢，跟不上够久就过载；轮流时不这样算，看的是轮流
/// 自己算的积压
/// On systems that cannot read drops, a socket going `BUSY_AFTER` without running empty counts
/// as dropping when not taking turns, and lasting long enough is overload; taking turns it does
/// not count, the backlog the turns work out being what tells
#[tokio::test]
async fn without_drops_to_read_a_socket_never_running_empty_counts_as_dropping() {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let pending = Arc::new(PendingReplies::default());
    let engine = static_engine_with_flow_control();
    let mut answering = UdpAnswering::new(&socket, &engine, &pending);
    answering.reads_drops = false;
    let look = |answering: &mut UdpAnswering<'_>| {
        answering.checks_since_empty = 2 * BEHIND_AFTER_CHECKS - 1;
        answering.shrink_buffer_if_overflowing();
    };

    answering.emptied_at = Instant::now();
    look(&mut answering);
    assert!(!answering.behind, "it ran empty just now");
    answering.emptied_at =
        Instant::now() - crate::engine::concurrency::BUSY_AFTER - Duration::from_millis(1);
    look(&mut answering);
    assert!(answering.behind, "it has not run empty for long");
    answering.behind_since = Instant::now() - BEHIND_BEFORE_TURNS - Duration::from_millis(1);
    look(&mut answering);
    assert!(answering.overloaded);

    let at = Instant::now() - Duration::from_secs(5);
    answering.behind_at = at;
    answering.taking_turns = true;
    look(&mut answering);
    assert_eq!(answering.behind_at, at, "taking turns it does not count");
}

/// 一台设备把 CPU 占满时，另一台偶尔才问一次的设备照样答得上：过载就轮流，不等第二台设备露面；跟上以后不再按设备
/// 轮流，一阵突发不因排不下被丢
/// With one device taking all the CPU another asking only now and then is still answered:
/// overload means taking turns, with no waiting for a second device to show; once caught up
/// devices no longer take turns and a burst is not dropped for not fitting
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_device_asking_rarely_is_answered_while_another_floods() {
    use std::os::fd::AsRawFd;

    let engine = static_engine_with_flow_control();
    let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let target = server.local_addr().unwrap();
    let worker = {
        let (server, engine) = (Arc::clone(&server), Arc::clone(&engine));
        tokio::spawn(async move { receive_in_batches(&server, &engine).await })
    };
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mode = Arc::new(std::sync::atomic::AtomicU8::new(FLOOD_FREELY));
    let flood = flood_from(
        [127, 0, 0, 2],
        &server,
        Arc::clone(&stop),
        Arc::clone(&mode),
    );
    let client = UdpSocket::bind("127.0.0.3:0").await.unwrap();
    let mut buf = [0u8; 512];

    // 只有洪泛的那台也开始轮流：轮流时排不下的才计入被拒绝，这里没有别的拒绝
    // Turns begin with the flooding device alone: only then is what does not fit counted as
    // refused, and nothing else gets refused here
    let started = Instant::now();
    while engine.permit_manager.dropped_requests() == 0 {
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "turns never began"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // 另一台头一次问就答得上，之后一个一个地问也都答得上。洪泛从这里起不挤满缓冲，内核一个包都不丢，没答上的只能是
    // 轮流没轮到它；还在削洪泛，就是还在轮流
    // The other is answered on its very first query, and asking one at a time after that too.
    // From here the flood leaves the buffer short of full and the kernel drops nothing, so one
    // left unanswered could only be one taking turns passed over; the flood still being cut
    // means turns go on
    mode.store(FLOOD_ASKED_GENTLE, std::sync::atomic::Ordering::SeqCst);
    let started = Instant::now();
    while mode.load(std::sync::atomic::Ordering::SeqCst) != FLOOD_GENTLE
        || receive_buffer_mostly_full(server.as_raw_fd()).unwrap()
    {
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "the flood never eased"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let drops = crate::socket_utils::udp_receive_drops(&server).unwrap();
    let cut = engine.permit_manager.dropped_requests();
    for id in 0..20 {
        client
            .send_to(&query("light.test", id), target)
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf))
            .await
            .unwrap_or_else(|_| panic!("query {id} unanswered"))
            .unwrap();
    }
    assert_eq!(
        crate::socket_utils::udp_receive_drops(&server).unwrap(),
        drops,
        "nothing dropped in the kernel"
    );
    assert!(
        engine.permit_manager.dropped_requests() > cut,
        "the flood is still being cut"
    );

    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    flood.join().unwrap();
    tokio::time::sleep(CAUGHT_UP_AFTER + Duration::from_millis(200)).await;
    let refused = engine.permit_manager.dropped_requests();
    let packet = query("light.test", 3);
    let sender = std::net::UdpSocket::bind("127.0.0.4:0").unwrap();
    let sending = std::thread::spawn(move || {
        for _ in 0..3000 {
            sender.send_to(&packet, target).unwrap();
        }
    });
    sending.join().unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        engine.permit_manager.dropped_requests(),
        refused,
        "caught up, nothing is dropped for not fitting"
    );
    worker.abort();
}

/// 空闲了很久以后来的查询不算内核忙：等新报文的时间不算没收空。两种循环都这样
/// Queries after a long quiet spell do not find the kernel busy: waiting for datagrams does not count as
/// not running empty. Both loops do so
#[tokio::test]
async fn a_quiet_spell_does_not_count_as_busy() {
    #[cfg(target_os = "linux")]
    not_refused_after_a_quiet_spell(|server, engine| {
        tokio::spawn(async move { receive_in_batches(&server, &Arc::new(engine)).await })
    })
    .await;
    not_refused_after_a_quiet_spell(|server, engine| {
        tokio::spawn(async move { receive_one_by_one(&server, &Arc::new(engine)).await })
    })
    .await;
}

async fn not_refused_after_a_quiet_spell(
    receive: impl FnOnce(Arc<UdpSocket>, Engine) -> tokio::task::JoinHandle<()>,
) {
    let engine = behind_engine_with_slow_upstream(500).await;
    let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_addr = server.local_addr().unwrap();
    let worker = receive(server, engine);
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    tokio::time::sleep(Duration::from_millis(1_000)).await;
    const QUERIES: u16 = 2;
    for id in 0..QUERIES {
        let query = query(&format!("q{id}.quiet.test"), id);
        client.send_to(&query, server_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(refused_and_answered(&client, QUERIES).await, (0, QUERIES));
    worker.abort();
}

/// 内核忙、查询又在排长队时，两种接收循环都回 SERVFAIL。这里一开始就算忙、排队一直算过长，每个查询都该被拒。
/// 只拒一部分的那种情况看时机，CI 上一次线程抢占就能翻，不在这里测；不忙就不拒由
/// `queries_waiting_on_a_slow_upstream_are_not_refused` 和 `a_quiet_spell_does_not_count_as_busy` 测着
/// With the kernel busy and queries queueing long, both receive loops answer SERVFAIL. Here it is
/// busy from the start and queueing always runs long, so every query is refused. Refusing only some
/// turns on timing that one preempted thread on CI can flip, so it is not tested here; that nothing
/// is refused while not busy is what `queries_waiting_on_a_slow_upstream_are_not_refused` and
/// `a_quiet_spell_does_not_count_as_busy` test
#[tokio::test]
async fn a_busy_kernel_queueing_long_refuses_in_both_loops() {
    #[cfg(target_os = "linux")]
    refused_when_busy(|server, engine| {
        tokio::spawn(async move { receive_in_batches(&server, &Arc::new(engine)).await })
    })
    .await;
    refused_when_busy(|server, engine| {
        tokio::spawn(async move { receive_one_by_one(&server, &Arc::new(engine)).await })
    })
    .await;
}

async fn refused_when_busy(
    receive: impl FnOnce(Arc<UdpSocket>, Engine) -> tokio::task::JoinHandle<()>,
) {
    let engine = behind_engine_with_slow_upstream(0).await;
    let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_addr = server.local_addr().unwrap();
    let worker = receive(server, engine);
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    const QUERIES: u16 = 50;
    for id in 0..QUERIES {
        let query = query(&format!("q{id}.busy.test"), id);
        client.send_to(&query, server_addr).await.unwrap();
    }
    // 头一个进去，那时什么都没在途；它在慢上游上等着的时候，同一台设备的其余都在平均上，都拒
    // The first goes in, nothing being in flight then; while it waits on the slow upstream the
    // rest from the same device hold its share and are all refused
    assert_eq!(
        refused_and_answered(&client, QUERIES).await,
        (QUERIES - 1, 1)
    );
    worker.abort();
}

/// 查询从排进去到开始跑等得超过目标，内核就算跟不上，下一个查询被拒绝；等得不久就不会
/// A query waiting past the target from being queued until it runs means the kernel is
/// behind, and the next query is refused; a short wait does not
#[tokio::test]
async fn queueing_past_the_target_refuses_queries() {
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let engine = Arc::new(with_busy_after(
        engine_forwarding_to(
            upstream.local_addr().unwrap(),
            serde_json::json!({
                "flow_control_enabled": true,
                "upstream_timeout_ms": 5000,
                "enable_tcp_fallback": false,
            }),
        ),
        Duration::ZERO,
    ));
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let pending = Arc::new(PendingReplies::default());
    let mut answering = UdpAnswering::new(&socket, &engine, &pending);
    let peer = UdpSocket::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let mut reply = BytesMut::new();
    let mut ask = |id: u16| {
        let query = query(&format!("q{id}.queue.test"), id);
        answering.answer(&query, peer, &mut reply);
    };

    // 这个测试和查询的任务在同一线程上，它不让出，任务就跑不了
    // This test and the query's task share a thread, so the task cannot run until it yields
    ask(1);
    tokio::task::yield_now().await;
    ask(2);
    assert_eq!(engine.permit_manager.dropped_requests(), 0, "a short wait");

    ask(3);
    std::thread::sleep(Duration::from_millis(300));
    tokio::task::yield_now().await;
    ask(4);
    assert_eq!(engine.permit_manager.dropped_requests(), 1, "a long wait");
}

/// 开着流控的引擎，转发给一个不应答的上游，在途已有 1000 个查询，内存剩多少看 `available`
/// An engine with flow control forwarding to a silent upstream, with 1000 queries in
/// flight and `available` bytes of memory left
fn engine_short_of_memory(
    silent_upstream: SocketAddr,
    available: Arc<std::sync::atomic::AtomicU64>,
) -> (Engine, Vec<crate::engine::concurrency::PermitGuard>) {
    use crate::config::PipelineConfig;
    use crate::engine::memory_watermark::{MemoryLeft, MemoryReading, MemoryWatermark};

    let config: PipelineConfig = serde_json::from_value(serde_json::json!({
        "settings": {
            "default_upstream": silent_upstream.to_string(),
            "upstream_timeout_ms": 3000,
            "enable_tcp_fallback": false,
            "flow_control_enabled": true
        },
        "pipelines": [{ "id": "main", "rules": [{
            "name": "all",
            "matchers": [{ "type": "any" }],
            "actions": [{ "type": "forward", "upstream": silent_upstream.to_string() }]
        }]}]
    }))
    .unwrap();
    let mut engine = Engine::new(
        crate::matcher::RuntimePipelineConfig::from_config(config).unwrap(),
        "test".to_string(),
    )
    .unwrap();
    let flow = Arc::get_mut(engine.flow_control_state.as_mut().unwrap()).unwrap();
    flow.memory = MemoryWatermark::reading(move || MemoryReading {
        own: 0,
        limits: vec![MemoryLeft {
            total: 1 << 30,
            available: available.load(std::sync::atomic::Ordering::Relaxed),
        }],
    });
    let in_flight = (0..1000).map(|_| engine.permit_manager.acquire()).collect();
    (engine, in_flight)
}

/// 测试不必等：内存不够以前问过的设备都算老设备 / A test need not wait: a device that asked before memory
/// ran short counts as known
#[cfg(target_os = "linux")]
fn known_at_once(engine: &mut Engine) {
    Arc::get_mut(engine.flow_control_state.as_mut().unwrap())
        .unwrap()
        .known_before = Duration::ZERO;
}

/// 内存剩这么多字节 / This many bytes of memory left
fn memory_left(bytes: u64) -> Arc<std::sync::atomic::AtomicU64> {
    Arc::new(std::sync::atomic::AtomicU64::new(bytes))
}

/// 一个 TCP 服务端，返回它的地址 / A TCP server, giving its address
async fn tcp_server(engine: &Engine) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let engine = engine.clone();
    (
        address,
        tokio::spawn(async move { run_tcp(listener, engine).await }),
    )
}

async fn send_tcp_query(stream: &mut TcpStream) {
    let query = dns_query();
    stream
        .write_all(&(query.len() as u16).to_be_bytes())
        .await
        .unwrap();
    stream.write_all(&query).await.unwrap();
}

/// 等到在途数量到 `count` / Until `count` are in flight
async fn in_flight_reaches(engine: &Engine, count: usize) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while engine.permit_manager.inflight() != count {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{} in flight", engine.permit_manager.inflight()));
}

/// TCP 进来的查询也看内存：不够时当场回 SERVFAIL，不问上游，连接还在
/// A query from TCP goes by memory too: with too little it gets SERVFAIL at once, the
/// upstream is not asked and the connection stays
#[tokio::test]
async fn a_tcp_query_is_refused_when_memory_runs_short() {
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let available = memory_left(1 << 30);
    let (engine, _in_flight) =
        engine_short_of_memory(upstream.local_addr().unwrap(), Arc::clone(&available));
    let (address, server) = tcp_server(&engine).await;
    let mut stream = TcpStream::connect(address).await.unwrap();
    in_flight_reaches(&engine, 1001).await;

    // 看够了次数，下一次读到内存不够 / Enough looks for the next read to find memory short
    available.store(0, std::sync::atomic::Ordering::Relaxed);
    for _ in 0..3000 {
        drop(engine.query_permit(None, std::net::Ipv4Addr::LOCALHOST.into()));
    }
    send_tcp_query(&mut stream).await;
    let mut length = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut length))
        .await
        .expect("refused at once")
        .unwrap();
    let mut reply = vec![0u8; u16::from_be_bytes(length) as usize];
    stream.read_exact(&mut reply).await.unwrap();
    let reply = Message::from_bytes(&reply).unwrap();
    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
    let mut buf = [0u8; 512];
    assert!(
        tokio::time::timeout(Duration::from_millis(100), upstream.recv_from(&mut buf))
            .await
            .is_err(),
        "the upstream is not asked"
    );
    assert_eq!(
        engine.permit_manager.inflight(),
        1001,
        "only the connection counts"
    );
    server.abort();
}

/// 内存够时 TCP 的连接和查询都算在途，查询照常问上游
/// With enough memory a TCP connection and query both count as in flight, and the query
/// asks the upstream as usual
#[tokio::test]
async fn a_tcp_connection_and_query_count_as_in_flight() {
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (engine, _in_flight) =
        engine_short_of_memory(upstream.local_addr().unwrap(), memory_left(1 << 30));
    let (address, server) = tcp_server(&engine).await;
    let mut stream = TcpStream::connect(address).await.unwrap();
    in_flight_reaches(&engine, 1001).await;
    send_tcp_query(&mut stream).await;
    let mut buf = [0u8; 512];
    tokio::time::timeout(Duration::from_secs(1), upstream.recv_from(&mut buf))
        .await
        .expect("the upstream is asked")
        .unwrap();
    in_flight_reaches(&engine, 1002).await;
    drop(stream);
    server.abort();
}

/// 内存不够时不接新连接：连接本身也占内存，只拒绝查询挡不住光连不发的客户端
/// With too little memory no new connection is taken: a connection holds memory too, and
/// refusing queries alone would not stop clients that connect and send nothing
#[tokio::test]
async fn a_new_tcp_connection_is_closed_when_memory_is_short() {
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (engine, _in_flight) =
        engine_short_of_memory(upstream.local_addr().unwrap(), memory_left(0));
    let (address, server) = tcp_server(&engine).await;

    let mut stream = TcpStream::connect(address).await.unwrap();
    let mut buf = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut buf))
        .await
        .expect("closed at once");
    assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
    assert_eq!(engine.permit_manager.dropped_requests(), 1);
    assert_eq!(engine.permit_manager.inflight(), 1000, "it holds nothing");
    server.abort();
}

/// 从 `local` 连 `to`。只有 Linux 的回环上整个 127.0.0.0/8 都绑得上，macOS 和 BSD 默认只有 127.0.0.1，用它的测试只在
/// Linux 上跑
/// Connects to `to` from `local`. Only Linux's loopback takes all of 127.0.0.0/8; macOS and the
/// BSDs hold 127.0.0.1 alone by default, so the tests using it run on Linux only
#[cfg(target_os = "linux")]
async fn connect_from(local: std::net::IpAddr, to: SocketAddr) -> TcpStream {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind(SocketAddr::new(local, 0)).unwrap();
    socket.connect(to).await.unwrap()
}

/// 内存紧张时，在途占满的那台设备的查询和新连接被拒，别的设备照常；UDP 和 TCP 都按真实的对端地址算
/// With memory tight, the device holding everything in flight has its queries and new
/// connections refused while another goes on; UDP and TCP both go by the real peer address
#[cfg(target_os = "linux")]
#[tokio::test]
async fn tight_memory_refuses_only_the_device_holding_the_queries() {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::Ordering::Relaxed;

    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let available = memory_left(1 << 30);
    let (mut engine, plain) =
        engine_short_of_memory(upstream.local_addr().unwrap(), Arc::clone(&available));
    known_at_once(&mut engine);
    drop(plain);
    let manager = &engine.permit_manager;
    let heavy = IpAddr::from(Ipv4Addr::new(127, 0, 0, 4));
    // 和它不在同一份的另一台：份是按每次启动都不同的哈希分的 / Another device, not in the same
    // slot: slots go by a hash that differs at each start
    let light = (2..=250)
        .map(|n| IpAddr::from(Ipv4Addr::new(127, 0, 0, n)))
        .find(|ip| manager.slot_of(*ip).counted_in() != manager.slot_of(heavy).counted_in())
        .unwrap();
    // 它在内存不够以前就在用 / It was in use before memory ran short
    drop(engine.query_permit(None, light));
    let held: Vec<_> = (0..1000)
        .map(|_| engine.query_permit(None, heavy).expect("plenty of memory"))
        .collect();
    // 内存还够时它先连上一条 TCP / While memory is plenty it opens a TCP connection first
    let (address, tcp) = tcp_server(&engine).await;
    let mut heavy_connected = connect_from(heavy, address).await;
    in_flight_reaches(&engine, 1001).await;
    // 余量 64 MiB、两倍 128 MiB，剩 100 MiB 算紧张；看够了次数，下一次读到它
    // A 64 MiB margin, twice that 128 MiB: 100 MiB left is tight; enough looks for the next read to find it
    available.store(100 << 20, Relaxed);
    for _ in 0..3000 {
        drop(engine.query_permit(None, heavy));
    }
    assert!(engine.query_permit(None, heavy).is_none(), "tight now");

    let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_addr = server.local_addr().unwrap();
    let worker = tokio::spawn(run_udp_worker(0, Arc::clone(&server), engine.clone()));
    let mut buf = [0u8; 512];
    let light_client = UdpSocket::bind(SocketAddr::new(light, 0)).await.unwrap();
    light_client
        .send_to(&dns_query(), server_addr)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), upstream.recv_from(&mut buf))
        .await
        .expect("the light device's query is asked of the upstream")
        .unwrap();
    in_flight_reaches(&engine, 1002).await;

    let heavy_client = UdpSocket::bind(SocketAddr::new(heavy, 0)).await.unwrap();
    heavy_client
        .send_to(&dns_query(), server_addr)
        .await
        .unwrap();
    let (len, _) = tokio::time::timeout(Duration::from_secs(1), heavy_client.recv_from(&mut buf))
        .await
        .expect("the heavy device is refused at once")
        .unwrap();
    // 1 秒内就回 SERVFAIL 就是被拒了：放行的要等这个不回答的上游超时，至少 3 秒。上游收没收到不在这里看，
    // 发得少的那个查询还挂在它上面，可能重发 / SERVFAIL within a second means refused: one let through waits
    // for this silent upstream to time out, 3 s at least. What the upstream receives is not looked at here, as
    // the light device's query still hangs on it and may be sent again
    let reply = Message::from_bytes(&buf[..len]).unwrap();
    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);

    // 它在已有的连接上发的查询也被拒，当场回 SERVFAIL / Its query on the connection it has is refused
    // too, with SERVFAIL at once
    send_tcp_query(&mut heavy_connected).await;
    let mut length = [0u8; 2];
    tokio::time::timeout(
        Duration::from_secs(1),
        heavy_connected.read_exact(&mut length),
    )
    .await
    .expect("refused at once")
    .unwrap();
    let mut reply = vec![0u8; u16::from_be_bytes(length) as usize];
    heavy_connected.read_exact(&mut reply).await.unwrap();
    let reply = Message::from_bytes(&reply).unwrap();
    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);

    let mut heavy_stream = connect_from(heavy, address).await;
    let read = tokio::time::timeout(Duration::from_secs(1), heavy_stream.read(&mut buf))
        .await
        .expect("its new connection is closed at once");
    assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
    let before = engine.permit_manager.inflight();
    let light_stream = connect_from(light, address).await;
    in_flight_reaches(&engine, before + 1).await;

    drop((held, light_stream, heavy_connected));
    worker.abort();
    tcp.abort();
}

/// 内存紧张时，一台只开着一条 TCP 连接的设备，在这条连接上问的未命中查询照常转发：连接不算查询的份。以前连接和
/// 查询记在一起，别的设备各占一个查询时它这条连接也算占了一份，查询当场被拒
/// With memory tight, a device holding just one TCP connection has a miss it asks on that
/// connection forwarded as usual: a connection is no share of queries. Connections and
/// queries used to be counted together, so with every other device holding one query its
/// connection counted as a share and the query was refused at once
#[cfg(target_os = "linux")]
#[tokio::test]
async fn tight_memory_does_not_count_a_connection_as_a_share_of_queries() {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::Ordering::Relaxed;

    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let available = memory_left(1 << 30);
    let (mut engine, plain) =
        engine_short_of_memory(upstream.local_addr().unwrap(), Arc::clone(&available));
    known_at_once(&mut engine);
    drop(plain);
    let manager = &engine.permit_manager;
    // 1000 台设备各占一个查询，数设备时各算一台 / 1000 devices holding one query each, each
    // counting as one when devices are counted
    let mut slots = std::collections::HashSet::new();
    let holders: Vec<IpAddr> = (0..=255u8)
        .flat_map(|b| (1..=254u8).map(move |c| IpAddr::from(Ipv4Addr::new(127, 1, b, c))))
        .filter(|ip| slots.insert(manager.slot_of(*ip).counted_in()))
        .take(1000)
        .collect();
    let client = (2..=254)
        .map(|n| IpAddr::from(Ipv4Addr::new(127, 0, 0, n)))
        .find(|ip| !slots.contains(&manager.slot_of(*ip).counted_in()))
        .unwrap();
    // 它在内存不够以前就在用 / It was in use before memory ran short
    drop(engine.query_permit(None, client));
    let held: Vec<_> = holders
        .iter()
        .map(|ip| engine.query_permit(None, *ip).expect("plenty of memory"))
        .collect();
    let (address, tcp) = tcp_server(&engine).await;
    let mut connected = connect_from(client, address).await;
    in_flight_reaches(&engine, 1001).await;
    // 剩 100 MiB 算紧张；看够了次数，下一次读到它 / 100 MiB left is tight; enough looks for the next read to find it
    available.store(100 << 20, Relaxed);
    for _ in 0..3000 {
        drop(engine.query_permit(None, holders[0]));
    }
    assert!(
        engine.query_permit(None, holders[0]).is_none(),
        "tight now, and a device holding a query is at the average"
    );

    send_tcp_query(&mut connected).await;
    let mut buf = [0u8; 512];
    tokio::time::timeout(Duration::from_secs(1), upstream.recv_from(&mut buf))
        .await
        .expect("the query on the only connection is asked of the upstream")
        .unwrap();

    drop((held, connected));
    tcp.abort();
}

/// 过载拒绝时回 SERVFAIL，照线上格式拼、不解析查询，快速解析读不了的也一样；以前 UDP 对它们不回，TCP 和 DoH 却回，只有不足
/// 12 字节的报文和应答（QR=1）不回
/// A refusal under overload answers SERVFAIL, put together on the wire with no parse, also to
/// a query the quick parse cannot read, which UDP used to leave unanswered while TCP and DoH
/// answered it; only a message under 12 bytes and a response (QR=1) get nothing
#[tokio::test]
async fn udp_permit_exhaustion_returns_servfail_but_a_short_packet_is_silent() {
    let engine = forwarding_engine();
    engine
        .flow_control_state
        .as_ref()
        .unwrap()
        .note_queue_delay(Duration::from_secs(3600));

    let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_addr = server.local_addr().unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // 客户端这台设备已经有一个在途，过载时它在平均上 / The client's device already has one in
    // flight, so under overload it holds its share
    let manager = Arc::clone(&engine.permit_manager);
    let _held = manager.acquire_for(manager.slot_of(client.local_addr().unwrap().ip()));
    let worker = tokio::spawn(run_udp_worker(0, Arc::clone(&server), engine));

    client.send_to(&dns_query(), server_addr).await.unwrap();
    let mut response_buf = [0u8; 512];
    let (response_len, _) =
        tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut response_buf))
            .await
            .expect("valid query should receive a response")
            .unwrap();
    let response = Message::from_bytes(&response_buf[..response_len]).unwrap();
    assert_eq!(response.metadata.id, 0xCAFE);
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(response.queries.len(), 1);
    // 过载时的 SERVFAIL 照查询带回 RD 位和问题 / The overload SERVFAIL carries the query's RD bit and question
    assert!(response.metadata.recursion_desired);
    assert_eq!(
        response.queries,
        Message::from_bytes(&dns_query()).unwrap().queries
    );

    // 问题名照客户端的写法，查询带 OPT 应答也带：开着 0x20 的解析器认大小写，问题名被改成小写的应答它当作不匹配丢掉
    // The question name as the client wrote it, and an OPT back for a query with one: a
    // resolver using 0x20 checks the case and drops a reply whose name was lowercased
    let mut asked = Message::new(0xBEEF, MessageType::Query, OpCode::Query);
    asked.metadata.recursion_desired = true;
    asked.add_query(Query::query(
        Name::from_str("data.xiaoheihe.cn.").unwrap(),
        RecordType::A,
    ));
    asked.edns = Some(hickory_proto::op::Edns::new());
    let mut asked = asked.to_vec().unwrap();
    // 编码时名字会变成小写，所以直接改字节：DaTa.XiaoHeiHe / Encoding lowercases the name, so the
    // bytes are changed directly: DaTa.XiaoHeiHe
    for at in [13, 15, 18, 22, 25] {
        asked[at] = asked[at].to_ascii_uppercase();
    }
    assert_eq!(&asked[13..17], b"DaTa");
    client.send_to(&asked, server_addr).await.unwrap();
    let (response_len, _) =
        tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut response_buf))
            .await
            .expect("valid query should receive a response")
            .unwrap();
    let mut name_end = 12;
    while asked[name_end] != 0 {
        name_end += 1 + usize::from(asked[name_end]);
    }
    let question_end = name_end + 1 + 4;
    assert_eq!(
        &response_buf[12..question_end],
        &asked[12..question_end],
        "the question as asked"
    );
    let response = Message::from_bytes(&response_buf[..response_len]).unwrap();
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    assert!(response.edns.is_some(), "an OPT for a query with one");

    client.send_to(&[0x12, 0x34], server_addr).await.unwrap();
    assert!(
        tokio::time::timeout(
            Duration::from_millis(100),
            client.recv_from(&mut response_buf),
        )
        .await
        .is_err(),
        "malformed UDP packets must not receive a reflected response"
    );

    // 过了请求头检查、快速解析读不了（末尾多一个字节）的查询也到这里，同样回 SERVFAIL、带回问题
    // A query past the header check that the quick parse cannot read (one byte too many at
    // the end) gets here too, and the same SERVFAIL with its question
    let mut trailing = dns_query();
    trailing.extend_from_slice(&[0x00]);
    client.send_to(&trailing, server_addr).await.unwrap();
    let (response_len, _) =
        tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut response_buf))
            .await
            .expect("the refused query is answered")
            .unwrap();
    let response = Message::from_bytes(&response_buf[..response_len]).unwrap();
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(
        response.queries,
        Message::from_bytes(&dns_query()).unwrap().queries
    );

    worker.abort();
}

#[tokio::test]
async fn udp_hanging_doh_returns_servfail() {
    let upstream = format!("https://{}/dns-query", spawn_silent_upstream().await);
    let engine = doh_timeout_engine(&upstream);
    let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_addr = server.local_addr().unwrap();
    let worker = tokio::spawn(run_udp_worker(0, Arc::clone(&server), engine));
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    client.send_to(&dns_query(), server_addr).await.unwrap();
    let mut response_buf = [0u8; 512];
    let (response_len, _) =
        tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut response_buf))
            .await
            .expect("timed-out query should receive SERVFAIL")
            .unwrap();
    let response = Message::from_bytes(&response_buf[..response_len]).unwrap();
    assert_eq!(response.metadata.id, 0xCAFE);
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(response.queries.len(), 1);

    worker.abort();
}

/// 只连接不发数据的客户端此前可以永久占用一个任务和一个文件描述符；
/// 现在服务端在空闲超时后关闭连接。
/// A client that connects without sending used to pin a task and a file
/// descriptor forever; the server now closes the connection when the idle
/// timeout expires.
#[tokio::test]
async fn tcp_idle_connection_is_closed_after_the_read_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        handle_tcp_conn(stream, peer, tcp_engine(static_engine())).await
    });

    let mut client = TcpStream::connect(addr).await.unwrap();
    let mut buf = [0u8; 1];
    // 实际等待一次 TCP_READ_TIMEOUT：这条路径没有可注入的时钟。
    // Waits one real TCP_READ_TIMEOUT; this path has no injectable clock.
    let read = tokio::time::timeout(TCP_READ_TIMEOUT * 3, client.read(&mut buf))
        .await
        .expect("server must close the idle connection instead of waiting forever")
        .expect("read after close");
    assert_eq!(read, 0, "an idle connection must be closed by the server");
    server.await.expect("connection handler");
}

/// 长连接上的查询必须跟着热重载后的 request_timeout 走。此前超时值在进入
/// 循环前只读一次，运维调大超时之后，已有连接上的查询继续按旧值失败，
/// 直到客户端自己重连。RFC 7766 的客户端正是长期复用一条连接。
/// Queries on a long-lived connection must follow the request_timeout a
/// reload installed. The value used to be read once before the loop, so
/// after an operator raised the timeout the queries on an existing
/// connection kept failing on the old budget until the client reconnected.
/// An RFC 7766 client reuses one connection for exactly that long.
#[tokio::test]
async fn tcp_request_timeout_follows_a_reload_on_an_open_connection() {
    // 只接不答的上游，让每条查询都跑满整体请求超时
    // An upstream that accepts and never answers, so every query runs the
    // whole request timeout
    let upstream = format!("https://{}/dns-query", spawn_silent_upstream().await);
    const BEFORE_MS: u64 = 120;
    const AFTER_MS: u64 = 900;
    let engine = Engine::new(doh_timeout_config(&upstream, BEFORE_MS), "test".to_string())
        .expect("initialize engine");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(listener_addr).await.unwrap();
    let (server_stream, peer) = listener.accept().await.unwrap();
    let server_task = tokio::spawn(handle_tcp_conn(
        server_stream,
        peer,
        tcp_engine(engine.clone()),
    ));

    let first = time_one_tcp_query(&mut client).await;
    assert!(
        first < Duration::from_millis(AFTER_MS / 2),
        "the first query must use the configured {BEFORE_MS} ms budget, took {first:?}"
    );

    engine.reload(doh_timeout_config(&upstream, AFTER_MS));

    // 同一条连接上的第二次查询 / A second query on the same connection
    let second = time_one_tcp_query(&mut client).await;
    assert!(
        second >= Duration::from_millis(AFTER_MS / 2),
        "a query after the reload must use the new {AFTER_MS} ms budget, took {second:?}"
    );

    server_task.abort();
}

/// 在一条已建立的连接上发一次查询并读回完整应答，返回耗时
/// Send one query on an established connection, read the whole answer back
/// and return how long it took
async fn time_one_tcp_query(client: &mut TcpStream) -> Duration {
    let (message, elapsed) = tcp_exchange(client, &dns_query()).await;
    assert_eq!(message.metadata.response_code, ResponseCode::ServFail);
    elapsed
}

/// 本机 UDP 上游：每个查询隔 `delay` 才回（标上 QR 的查询本身）
/// Local UDP upstream answering every query after `delay` (the query itself with QR set)
async fn spawn_slow_udp_upstream(delay: Duration) -> SocketAddr {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
            let mut answer = buf[..n].to_vec();
            answer[2] |= 0x80;
            let socket = Arc::clone(&socket);
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                let _ = socket.send_to(&answer, peer).await;
            });
        }
    });
    addr
}

/// slow.test 转发给 `upstream`，fast.test 静态回答 / slow.test forwards to `upstream`, fast.test answers statically
fn slow_and_fast_engine(upstream: SocketAddr) -> Engine {
    let config: crate::config::PipelineConfig = serde_json::from_value(serde_json::json!({
        "settings": {
            "default_upstream": "127.0.0.1:9",
            "upstream_timeout_ms": 2000,
            "request_timeout_ms": 4000
        },
        "pipelines": [{ "id": "main", "rules": [
            {
                "name": "slow",
                "matchers": [{ "type": "domain_suffix", "value": "slow.test" }],
                "actions": [{ "type": "forward", "upstream": upstream.to_string() }]
            },
            {
                "name": "fast",
                "matchers": [{ "type": "domain_suffix", "value": "fast.test" }],
                "actions": [{ "type": "static_ip_response", "ip": "192.0.2.1" }]
            }
        ]}]
    }))
    .expect("parse config");
    Engine::new(
        RuntimePipelineConfig::from_config(config).expect("runtime config"),
        "test".to_string(),
    )
    .expect("initialize engine")
}

/// `name` 的 A 查询，ID 为 `id`，带长度前缀 / An A query for `name` with ID `id`, length-prefixed
fn tcp_frame(name: &str, id: u16) -> Vec<u8> {
    framed(&query(name, id))
}

/// `packet` 带上长度前缀 / `packet` with its length prefix
fn framed(packet: &[u8]) -> Vec<u8> {
    [&(packet.len() as u16).to_be_bytes()[..], packet].concat()
}

/// 不带 OPT 的 `packet` 补上一条只有填充选项的 OPT，正好 `len` 字节，照样当场答得上
/// `packet`, carrying no OPT, with one holding a padding option alone added, exactly `len`
/// bytes long and answered on the spot all the same
fn padded_to(mut packet: Vec<u8>, len: usize) -> Vec<u8> {
    // OPT 的名字、类型、载荷、TTL 和 RDLENGTH 共 11 字节，填充选项的代码和长度 4 字节
    // The OPT's name, type, payload, TTL and RDLENGTH take 11 bytes, the padding option's code
    // and length 4
    let pad = (len - packet.len() - 15) as u16;
    packet[11] = 1;
    packet.extend_from_slice(&[0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0]);
    packet.extend_from_slice(&(4 + pad).to_be_bytes());
    packet.extend_from_slice(&[0, 12]);
    packet.extend_from_slice(&pad.to_be_bytes());
    packet.resize(len, 0);
    packet
}

/// 从连接上读一个回答，返回它的 ID / Reads one answer off the connection and returns its ID
async fn read_answer_id(client: &mut TcpStream) -> u16 {
    let answer = read_tcp_answer(client).await;
    u16::from_be_bytes([answer[0], answer[1]])
}

/// 从连接上读一个回答 / Reads one answer off the connection
async fn read_tcp_answer(client: &mut TcpStream) -> Vec<u8> {
    let mut len_buf = [0u8; 2];
    client
        .read_exact(&mut len_buf)
        .await
        .expect("length prefix");
    let mut answer = vec![0u8; u16::from_be_bytes(len_buf) as usize];
    client.read_exact(&mut answer).await.expect("dns frame");
    answer
}

/// 连在 `engine` 上的一条入站 TCP 连接，和处理它的任务 / An inbound TCP connection to `engine` and the task handling it
async fn tcp_connection(engine: Engine) -> (TcpStream, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (stream, peer) = listener.accept().await.unwrap();
    (
        client,
        tokio::spawn(handle_tcp_conn(stream, peer, tcp_engine(engine))),
    )
}

/// 一次写进来的一串查询都答上，各带自己的 ID；当场答的攒在一起写回
/// A run of queries written in one go is answered in full, each with its own ID; the answers
/// made on the spot are written back together
#[tokio::test]
async fn queries_written_together_are_all_answered() {
    let (mut client, _server) = tcp_connection(static_engine()).await;
    let frames: Vec<u8> = (0..200u16)
        .flat_map(|id| tcp_frame(&format!("q{id}.example."), id))
        .collect();
    client.write_all(&frames).await.unwrap();
    let mut ids = Vec::new();
    for _ in 0..200 {
        let answer = read_tcp_answer(&mut client).await;
        let message = Message::from_bytes(&answer).unwrap();
        assert_eq!(
            message.queries[0].name().to_string(),
            format!("q{}.example.", message.metadata.id)
        );
        ids.push(message.metadata.id);
    }
    ids.sort_unstable();
    assert_eq!(ids, (0..200).collect::<Vec<_>>());
}

/// 消息拆成几段到，长度前缀也拆开，照样答；拆开的段之间不超时
/// A message arriving in pieces, its length prefix split too, is still answered; the pieces
/// do not time out between them
#[tokio::test]
async fn a_message_in_pieces_is_answered() {
    let (mut client, _server) = tcp_connection(static_engine()).await;
    let frame = tcp_frame("pieces.example.", 7);
    for piece in [&frame[..1], &frame[1..2], &frame[2..9], &frame[9..]] {
        client.write_all(piece).await.unwrap();
        client.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(read_answer_id(&mut client).await, 7);
    // 下一个消息只差最后一个字节，跟在这个后面一起到 / The next message, all but its last byte, comes along with this one
    let next = [tcp_frame("a.example.", 8), tcp_frame("b.example.", 9)].concat();
    client.write_all(&next[..next.len() - 1]).await.unwrap();
    assert_eq!(read_answer_id(&mut client).await, 8);
    client.write_all(&next[next.len() - 1..]).await.unwrap();
    assert_eq!(read_answer_id(&mut client).await, 9);
}

/// 比一次读的大小还长的消息照样读完，后面的查询照样答：最长的查询带上长度前缀就比一次读的多
/// A message longer than one read is still read whole, and the query after it is answered:
/// the longest query with its length prefix is more than one read
#[tokio::test]
async fn a_message_longer_than_one_read_is_read_whole() {
    let (mut client, _server) = tcp_connection(static_engine()).await;
    let mut long = query("long.example.", 1);
    long.resize(crate::proto_utils::MAX_QUERY_LEN, 0);
    assert!(2 + long.len() > TCP_READ_CHUNK);
    let frames = [framed(&long), tcp_frame("after.example.", 2)].concat();
    client.write_all(&frames).await.unwrap();
    // 多出来的字节让完整解析出错：回 SERVFAIL 或不回都行，后面那个一定要答
    // The extra bytes make the full parse fail: a SERVFAIL or no answer is fine, the one after must be answered
    loop {
        let answer = read_tcp_answer(&mut client).await;
        if u16::from_be_bytes([answer[0], answer[1]]) == 2 {
            break;
        }
    }
}

/// 连接上的处理名额用满时，同一批里已经当场答好的不陪着等名额，先写回去
/// With every slot on the connection taken, what the same batch already answered on the spot
/// does not wait for a slot along with the rest and is written back first
#[tokio::test]
async fn answers_made_on_the_spot_do_not_wait_for_a_slot() {
    const DELAY: Duration = Duration::from_millis(400);
    let upstream = spawn_slow_udp_upstream(DELAY).await;
    let (mut client, _server) = tcp_connection(slow_and_fast_engine(upstream)).await;
    let slow = |i: usize| tcp_frame(&format!("q{i}.slow.test."), i as u16);
    let mut frames: Vec<u8> = (0..TCP_MAX_QUERIES_PER_CONN).flat_map(slow).collect();
    frames.extend(tcp_frame("a.fast.test.", 9999));
    frames.extend(slow(TCP_MAX_QUERIES_PER_CONN));
    let started = std::time::Instant::now();
    client.write_all(&frames).await.unwrap();
    assert_eq!(read_answer_id(&mut client).await, 9999);
    assert!(
        started.elapsed() < DELAY / 2,
        "took {:?}",
        started.elapsed()
    );
}

/// 测试里的读超时，比 TCP_READ_TIMEOUT 短，几次超时一会儿就跑完 / The read timeout in tests,
/// shorter than TCP_READ_TIMEOUT, so several timeouts take little time
const SHORT_READ_TIMEOUT: Duration = Duration::from_secs(1);

/// 连在 `engine` 上、读超时是 SHORT_READ_TIMEOUT 的一条入站 TCP 连接 / An inbound TCP connection
/// to `engine` with SHORT_READ_TIMEOUT as its read timeout
async fn tcp_connection_timing_out(engine: Engine) -> (TcpStream, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (stream, peer) = listener.accept().await.unwrap();
    let server = tokio::spawn(serve_tcp_conn(
        stream,
        peer,
        tcp_engine(engine),
        SHORT_READ_TIMEOUT,
    ));
    (client, server)
}

/// 还有查询在等上游回答时，连接不算空闲：读超时过了以后再发来的查询照样读、照样答；都答完以后，空闲一个读超时才关。
/// 以前空闲计时不看有没有在途的查询，上游慢时，等回答的那段时间里再来的查询躺在接收缓冲里没人读，答完一关连接就丢了
/// A connection with queries still waiting on an upstream is not idle: a query sent after the
/// read timeout is read and answered all the same, and with both answered it closes after one
/// read timeout idle. The idle clock used to ignore queries in flight, and with a slow upstream
/// a query sent meanwhile lay unread in the receive buffer, lost as the connection closed
#[tokio::test]
async fn a_connection_waiting_on_an_answer_keeps_reading() {
    let upstream = spawn_slow_udp_upstream(SHORT_READ_TIMEOUT + Duration::from_millis(500)).await;
    let (mut client, server) = tcp_connection_timing_out(slow_and_fast_engine(upstream)).await;
    client
        .write_all(&tcp_frame("a.slow.test.", 1))
        .await
        .unwrap();
    tokio::time::sleep(SHORT_READ_TIMEOUT + Duration::from_millis(200)).await;
    client
        .write_all(&tcp_frame("b.fast.test.", 2))
        .await
        .unwrap();
    let mut ids = [
        read_answer_id(&mut client).await,
        read_answer_id(&mut client).await,
    ];
    ids.sort_unstable();
    assert_eq!(ids, [1, 2], "both answered");
    let mut rest = [0u8; 1];
    assert_eq!(client.read(&mut rest).await.unwrap(), 0, "closed once idle");
    server.await.expect("connection handler");
}

/// 声明的长度超过 MAX_QUERY_LEN 的消息不答：不等它发完，连接当场关掉，之前的查询照样答；之前最长的查询把读缓冲撑大、它整个
/// 一次读进来时也一样。只发一个长度前缀的连接于是占不住 64 KiB 的读缓冲和一个读超时，几千条那样的连接占不满路由器的内存
/// A message declaring more than MAX_QUERY_LEN goes unanswered: it is not waited for, the
/// connection closing there and then with the queries before it still answered, and so too
/// when the longest query before it has grown the read buffer and it comes in whole in one
/// read. A connection sending a length prefix alone thus holds neither 64 KiB of read buffer
/// nor a read timeout, and a few thousand such connections cannot fill a router's memory
#[tokio::test]
async fn a_message_longer_than_any_query_closes_the_connection() {
    const { assert!(2 + MAX_QUERY_LEN > TCP_READ_CHUNK) };
    let too_long = framed(&padded_to(query("too-long.example.", 9), MAX_QUERY_LEN + 1));
    // 先只发它的长度前缀；再在最长的查询之后整个发：最长的查询一次读不完，读缓冲为它涨过
    // First its length prefix alone; then the whole of it after the longest query, which takes
    // more than one read and grows the read buffer
    let before = [
        (tcp_frame("before.example.", 7), &too_long[..2]),
        (
            framed(&padded_to(query("before.example.", 7), MAX_QUERY_LEN)),
            &too_long[..],
        ),
    ];
    for (before, sent) in before {
        let (mut client, server) = tcp_connection_timing_out(static_engine()).await;
        client.write_all(&before).await.unwrap();
        assert_eq!(read_answer_id(&mut client).await, 7);
        let started = std::time::Instant::now();
        client.write_all(sent).await.unwrap();
        let mut rest = [0u8; 1];
        assert_eq!(
            client.read(&mut rest).await.unwrap(),
            0,
            "closed, unanswered"
        );
        assert!(
            started.elapsed() < SHORT_READ_TIMEOUT,
            "{:?}",
            started.elapsed()
        );
        server.await.expect("connection handler");
    }
}

/// 半截消息一点点地发也不能一直挂着：正文从开始等起总共一个读超时，中途到的字节不重新计时
/// A half-sent message trickled in bit by bit cannot hang on either: the body gets one read
/// timeout from when it was first waited for, and bytes arriving meanwhile do not restart it
#[tokio::test]
async fn a_trickled_message_still_times_out() {
    let (client, server) = tcp_connection_timing_out(static_engine()).await;
    let (_read, mut write) = client.into_split();
    let frame = tcp_frame("trickle.example.", 1);
    let started = std::time::Instant::now();
    write.write_all(&frame[..4]).await.unwrap();
    let trickle = tokio::spawn(async move {
        for byte in &frame[4..frame.len() - 1] {
            tokio::time::sleep(SHORT_READ_TIMEOUT / 4).await;
            if write.write_all(std::slice::from_ref(byte)).await.is_err() {
                break;
            }
        }
    });
    tokio::time::timeout(SHORT_READ_TIMEOUT * 3, server)
        .await
        .expect("the connection is closed")
        .unwrap();
    let took = started.elapsed();
    trickle.abort();
    assert!(
        took >= SHORT_READ_TIMEOUT && took < SHORT_READ_TIMEOUT + SHORT_READ_TIMEOUT / 4,
        "took {took:?}"
    );
}

/// 读超时管的是每次等：一直有查询进来的连接不会因为连了很久就被关掉，空下来以后才在一个读超时后关
/// The read timeout bounds each wait: a connection that keeps sending queries is not closed for
/// having lasted long, and closes one read timeout after it goes quiet
#[tokio::test]
async fn a_busy_connection_outlives_the_read_timeout() {
    let (mut client, server) = tcp_connection_timing_out(static_engine()).await;
    let started = std::time::Instant::now();
    for id in 0..4 {
        client
            .write_all(&tcp_frame("busy.example.", id))
            .await
            .unwrap();
        assert_eq!(read_answer_id(&mut client).await, id);
        tokio::time::sleep(SHORT_READ_TIMEOUT * 3 / 5).await;
    }
    let quiet = started.elapsed();
    assert!(quiet > SHORT_READ_TIMEOUT * 2, "took {quiet:?}");
    tokio::time::timeout(SHORT_READ_TIMEOUT * 2, server)
        .await
        .expect("the quiet connection is closed")
        .unwrap();
}

/// 长度为 0 的消息结束连接，但它前面一起到的查询照样拿到回答
/// A zero-length message ends the connection, yet the queries that came before it in the same
/// read still get their answers
#[tokio::test]
async fn a_zero_length_message_ends_the_connection_after_the_answers_before_it() {
    let (mut client, server) = tcp_connection(static_engine()).await;
    let frames = [
        tcp_frame("a.example.", 1),
        tcp_frame("b.example.", 2),
        vec![0, 0],
    ]
    .concat();
    client.write_all(&frames).await.unwrap();
    assert_eq!(read_answer_id(&mut client).await, 1);
    assert_eq!(read_answer_id(&mut client).await, 2);
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut rest))
        .await
        .expect("the connection closes")
        .unwrap();
    assert!(rest.is_empty());
    server.await.unwrap();
}

/// 同一条连接上，快查询不等它前面的慢查询，答完就回（RFC 7766 第 6.2.1.1 节）。此前一个接一个地
/// 处理，快查询要陪着慢查询等。
/// On one connection a fast query does not wait for the slow one before it and is
/// answered when done (RFC 7766 section 6.2.1.1). Queries used to be handled one after
/// another, the fast one waiting out the slow one.
#[tokio::test]
async fn a_fast_tcp_query_is_not_held_behind_a_slow_one() {
    let upstream = spawn_slow_udp_upstream(Duration::from_millis(800)).await;
    let (mut client, _server) = tcp_connection(slow_and_fast_engine(upstream)).await;
    let started = std::time::Instant::now();
    client
        .write_all(&[tcp_frame("a.slow.test.", 1), tcp_frame("a.fast.test.", 2)].concat())
        .await
        .unwrap();
    assert_eq!(
        read_answer_id(&mut client).await,
        2,
        "the fast answer comes first"
    );
    assert!(
        started.elapsed() < Duration::from_millis(300),
        "the fast answer took {:?}",
        started.elapsed()
    );
    assert_eq!(read_answer_id(&mut client).await, 1, "then the slow one");
}

/// 客户端发完查询就关掉发送方向，还在处理的查询照样把回答写回去，然后连接关闭
/// A client that shuts its sending side after its query still gets the answers being
/// worked on, and then the connection closes
#[tokio::test]
async fn a_half_closed_tcp_client_gets_its_pending_answers() {
    let upstream = spawn_slow_udp_upstream(Duration::from_millis(300)).await;
    let (mut client, server) = tcp_connection(slow_and_fast_engine(upstream)).await;
    client
        .write_all(&tcp_frame("b.slow.test.", 7))
        .await
        .unwrap();
    client.shutdown().await.unwrap();
    assert_eq!(read_answer_id(&mut client).await, 7);
    let mut rest = Vec::new();
    client.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty(), "the connection closes after the answer");
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("the handler ends")
        .unwrap();
}

/// 一条连接上同时处理的查询有上限：一次发来 100 个慢查询，全都答了，前 64 个一起答完，剩下的接着
/// 一起答完——并发了，也没有一下子开 100 个任务。
/// The queries handled at once on one connection are capped: 100 slow queries sent in one
/// go are all answered, the first 64 together and the rest together after them, so they
/// run concurrently without 100 tasks starting at once.
#[tokio::test]
async fn tcp_queries_run_concurrently_up_to_the_per_connection_cap() {
    // UDP 转发每次尝试等上游超时的三分之一，延迟要短于它，一次就答上
    // A UDP forward waits a third of the upstream timeout per attempt; the delay stays
    // below that so one attempt answers
    const DELAY: Duration = Duration::from_millis(400);
    let upstream = spawn_slow_udp_upstream(DELAY).await;
    let (mut client, _server) = tcp_connection(slow_and_fast_engine(upstream)).await;
    let frames: Vec<u8> = (0..100)
        .flat_map(|i| tcp_frame(&format!("q{i}.slow.test."), i))
        .collect();
    let started = std::time::Instant::now();
    client.write_all(&frames).await.unwrap();
    let mut ids = Vec::new();
    for _ in 0..100 {
        ids.push(read_answer_id(&mut client).await);
    }
    let took = started.elapsed();
    ids.sort_unstable();
    assert_eq!(ids, (0..100).collect::<Vec<u16>>());
    assert!(
        took >= DELAY * 2 && took < DELAY * 2 + Duration::from_millis(600),
        "two rounds of {DELAY:?} expected, took {took:?}"
    );
}

/// 不读回答的客户端：写回在时限内写不完就关掉写端，处理这条连接的任务能结束，而不是永远卡在写上
/// A client that never reads its answers: a write not done within the limit shuts the
/// write side, and the task handling the connection ends instead of hanging on the write
#[tokio::test]
async fn a_tcp_client_that_never_reads_does_not_hold_the_handler() {
    let upstream = spawn_slow_udp_upstream(Duration::from_millis(10)).await;
    let (mut client, server) = tcp_connection(slow_and_fast_engine(upstream)).await;
    // 一直发、从不读，直到发不出去：服务端的写回早就堵住了
    // Keep sending, never reading, until sending stalls: the server's writes are long blocked
    let frame = tcp_frame("c.fast.test.", 9);
    let burst: Vec<u8> = frame
        .iter()
        .copied()
        .cycle()
        .take(frame.len() * 4096)
        .collect();
    while tokio::time::timeout(Duration::from_millis(500), client.write_all(&burst))
        .await
        .is_ok()
    {}
    tokio::time::timeout(TCP_READ_TIMEOUT * 4, server)
        .await
        .expect("the handler ends once its blocked write times out")
        .unwrap();
}

/// 写端坏了以后客户端还一直发：处理这条连接的任务照样马上结束，不再读、不再问上游。以前只关写端，读循环接着解析、
/// 问上游，客户端隔一会儿发一个，它就一直不空闲、一直不结束
/// The client keeps sending after the write side broke: the task handling the connection ends
/// at once all the same, reading and asking upstreams no more. Only the write side used to be
/// shut, the read loop parsing and asking upstreams on, never idle and never ending while the
/// client sent one every now and then
#[tokio::test]
async fn a_broken_tcp_write_side_ends_the_handler_though_the_client_keeps_sending() {
    let upstream = spawn_slow_udp_upstream(Duration::from_millis(10)).await;
    let (mut client, server) = tcp_connection(slow_and_fast_engine(upstream)).await;
    let frame = tcp_frame("c.fast.test.", 9);
    // 一帧接一帧地发、从不读，写不出去才停：服务端堵在写上时这里也堵着，服务端一读就接着发。每帧都完整写完，不会
    // 半截留在流里
    // Frame after frame, never reading, stopping only once it cannot be sent: blocked while
    // the server is stuck writing, sending on as soon as it reads. Each frame is written
    // whole, none left halfway in the stream
    tokio::spawn(async move { while client.write_all(&frame).await.is_ok() {} });
    tokio::time::timeout(TCP_READ_TIMEOUT * 2, server)
        .await
        .expect("the handler ends once its write side breaks")
        .unwrap();
}

#[tokio::test]
async fn tcp_hanging_doh_returns_complete_servfail_frame() {
    let upstream = format!("https://{}/dns-query", spawn_silent_upstream().await);
    let engine = doh_timeout_engine(&upstream);
    let (mut client, server_task) = tcp_connection(engine).await;
    let (response, _) = tokio::time::timeout(
        Duration::from_secs(1),
        tcp_exchange(&mut client, &dns_query()),
    )
    .await
    .expect("TCP query should receive the complete DNS frame");
    assert_eq!(response.metadata.id, 0xCAFE);
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(response.queries.len(), 1);

    server_task.abort();
}

#[tokio::test]
async fn udp_response_truncates_oversized_payload() {
    use hickory_proto::rr::{RData, Record, rdata::TXT};

    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server.local_addr().unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // 客户端无 EDNS → 512 字节限制 / Client without EDNS → 512-byte limit
    let request = dns_query();
    // 构造 >512 字节的大 TXT 响应 / Build a large TXT response (>512 bytes)
    let name = Name::from_str("data.xiaoheihe.cn.").unwrap();
    let mut big = Message::new(0xCAFE, MessageType::Response, OpCode::Query);
    big.metadata.recursion_desired = true;
    big.metadata.recursion_available = true;
    big.add_query(Query::query(name.clone(), RecordType::TXT));
    for i in 0..20 {
        let text = format!("verification-{i:02}-{}", "x".repeat(180));
        big.add_answer(Record::from_rdata(
            name.clone(),
            300,
            RData::TXT(TXT::new(vec![text])),
        ));
    }
    let big_response = big.to_vec().unwrap();
    assert!(big_response.len() > 512);

    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        let (len, peer) = server.recv_from(&mut buf).await.unwrap();
        let reply = udp_reply(&buf[..len], Bytes::from(big_response));
        send_udp_datagram(&server, &reply, peer).await.unwrap();
    });

    client.send_to(&request, server_addr).await.unwrap();
    let mut buf = [0u8; 4096];
    let (len, _) = tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf))
        .await
        .expect("client should receive a truncated response")
        .unwrap();
    let resp = Message::from_bytes(&buf[..len]).unwrap();
    assert!(len <= 512, "response must fit the 512-byte UDP limit");
    assert!(resp.metadata.truncation, "TC bit must be set");
    assert_eq!(resp.queries.len(), 1);
    assert_eq!(resp.metadata.id, 0xCAFE);
}

/// 名字为 `name`、ID 为 `id`、带 RD 的 A 查询 / An A query for `name` with ID `id` and RD set
fn query(name: &str, id: u16) -> Vec<u8> {
    let mut request = Message::new(id, MessageType::Query, OpCode::Query);
    request.metadata.recursion_desired = true;
    request.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
    request.to_vec().unwrap()
}

/// 快速解析读不了、要从头解析的查询：第一个标签里有一个空格
/// A query the quick parse cannot read and the full parse can: a space in its first label
fn query_parsed_from_scratch(id: u16) -> Vec<u8> {
    let mut packet = query("xslow.test", id);
    // 12 字节的报头之后是第一个标签的长度，再往后是它的第一个字节
    // The 12-byte header is followed by the first label's length, then its first byte
    packet[13] = b' ';
    assert!(crate::proto_utils::parse_quick(&packet, &mut [0u8; 256]).is_none());
    assert!(Message::from_bytes(&packet).is_ok());
    packet
}

/// 本机 UDP 上游：每个查询回一条 TTL 300 的 A 记录
/// A local UDP upstream answering every query with one A record of TTL 300
async fn spawn_answering_udp_upstream() -> SocketAddr {
    use hickory_proto::rr::{RData, Record, rdata::A};

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
            let Ok(query) = Message::from_bytes(&buf[..n]) else {
                continue;
            };
            let mut answer = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
            answer.metadata.recursion_desired = query.metadata.recursion_desired;
            answer.metadata.recursion_available = true;
            for question in query.queries {
                answer.add_answer(Record::from_rdata(
                    question.name().clone(),
                    300,
                    RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 7))),
                ));
                answer.add_query(question);
            }
            let _ = socket.send_to(&answer.to_vec().unwrap(), peer).await;
        }
    });
    addr
}

/// 要转发的查询在接收循环忙着时答完：回答排进队列、和下一批一起发出，每个客户端收到的正好是自己那些
/// 查询的回答。批量收发和一个一个收发的两种循环、单线程和多线程的运行时都这样
/// Forwarded queries answered while the receive loop is busy: the replies queue up and go out
/// with the next batch, and each client gets the answers to exactly its own queries. So with the
/// batched and the one-by-one loop, on a current-thread and a multi-thread runtime alike
#[tokio::test]
async fn forwarded_answers_reach_their_clients_while_the_loop_is_busy() {
    forwarded_answers_reach_their_clients().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forwarded_answers_reach_their_clients_on_several_threads() {
    forwarded_answers_reach_their_clients().await;
}

async fn forwarded_answers_reach_their_clients() {
    #[cfg(target_os = "linux")]
    forwarded_answers_reach_their_clients_by(|server, engine| {
        tokio::spawn(async move { receive_in_batches(&server, &Arc::new(engine)).await })
    })
    .await;
    forwarded_answers_reach_their_clients_by(|server, engine| {
        tokio::spawn(async move { receive_one_by_one(&server, &Arc::new(engine)).await })
    })
    .await;
}

async fn forwarded_answers_reach_their_clients_by(
    receive: impl FnOnce(Arc<UdpSocket>, Engine) -> tokio::task::JoinHandle<()>,
) {
    const CLIENTS: u16 = 4;
    const PER_CLIENT: u16 = 100;
    // 每个客户端最多同时等这么多个回答：几个客户端加起来装得进默认的接收缓冲，不会被内核丢掉，又足够让
    // 接收循环一直有事做
    // Each client waits for at most this many answers at once: all clients together fit in the
    // default receive buffer, so the kernel drops none, and still keep the receive loop busy
    const WINDOW: u16 = 16;
    let upstream = spawn_answering_udp_upstream().await;
    let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_addr = server.local_addr().unwrap();
    let worker = receive(
        server,
        engine_forwarding_to(upstream, serde_json::json!({})),
    );
    let clients: Vec<_> = (0..CLIENTS)
        .map(|c| {
            tokio::spawn(async move {
                let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                // 名字各不相同：每个都要转发，不会命中缓存或者合并成一个 / Every name differs: each is
                // forwarded, none hits the cache or merges with another
                let ask = |id: u16| query(&format!("q{id}-c{c}.forwarded.test"), id);
                for id in 0..WINDOW {
                    client.send_to(&ask(id), server_addr).await.unwrap();
                }
                let (mut sent, mut ids) = (WINDOW, Vec::new());
                let mut buf = [0u8; 512];
                while ids.len() < PER_CLIENT as usize {
                    let (len, _) =
                        tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf))
                            .await
                            .unwrap_or_else(|_| panic!("client {c} got only {} answers", ids.len()))
                            .unwrap();
                    let answer = Message::from_bytes(&buf[..len]).expect("an answer");
                    assert_eq!(
                        answer.queries[0].name().to_string(),
                        format!("q{}-c{c}.forwarded.test.", answer.metadata.id),
                        "client {c} got an answer to someone else's query"
                    );
                    assert_eq!(answer.answers.len(), 1, "the upstream's answer comes back");
                    ids.push(answer.metadata.id);
                    if sent < PER_CLIENT {
                        client.send_to(&ask(sent), server_addr).await.unwrap();
                        sent += 1;
                    }
                }
                ids.sort_unstable();
                assert_eq!(ids, (0..PER_CLIENT).collect::<Vec<_>>(), "client {c}");
            })
        })
        .collect();
    for client in clients {
        client.await.unwrap();
    }
    worker.abort();
}

/// 接收循环在等新报文时（其他平台一直如此）不收回答，由转发完的任务直接发
/// While the receive loop waits for datagrams (on other platforms, always) it takes no reply,
/// and the task done forwarding sends it directly
#[test]
fn a_waiting_loop_takes_no_replies() {
    let pending = PendingReplies::default();
    assert!(!pending.try_queue(
        &Bytes::from_static(b"reply"),
        "127.0.0.1:9".parse::<SocketAddr>().unwrap()
    ));
    assert!(pending.queue.lock().is_empty());
}

/// 循环忙着时放进来的回答让它不睡：说完在等以后看一眼队列，还有回答就接着发
/// A reply queued while the loop is busy keeps it awake: once it has said it waits it looks at
/// the queue, and goes on sending while a reply is there
#[test]
fn a_reply_queued_while_the_loop_is_busy_keeps_it_awake() {
    let pending = PendingReplies::default();
    pending
        .idle
        .store(false, std::sync::atomic::Ordering::SeqCst);
    assert!(pending.try_queue(
        &Bytes::from_static(b"reply"),
        "127.0.0.1:9".parse::<SocketAddr>().unwrap()
    ));
    assert!(
        !pending.begin_wait(),
        "the loop must not sleep on a queued reply"
    );
}

/// 循环刚说完在等，转发完的任务才放进回答（它看的时候循环还忙着）：这个回答叫醒循环
/// The loop has just said it waits when a task queues a reply (the loop was busy when the task
/// looked): that reply wakes the loop
#[tokio::test]
async fn a_reply_queued_as_the_loop_turns_to_waiting_wakes_it() {
    let pending = PendingReplies::default();
    pending
        .idle
        .store(false, std::sync::atomic::Ordering::SeqCst);
    assert!(
        pending.begin_wait(),
        "nothing queued yet: the loop may sleep"
    );
    pending.queue_and_wake(
        &Bytes::from_static(b"reply"),
        "127.0.0.1:9".parse::<SocketAddr>().unwrap(),
    );
    tokio::time::timeout(Duration::from_millis(500), pending.wake.notified())
        .await
        .expect("the queued reply wakes the loop");
}

/// 接收循环转去等待之前，把排着的回答都发出去 / Before the receive loop turns to waiting, it
/// sends every queued reply
#[cfg(target_os = "linux")]
#[tokio::test]
async fn the_loop_sends_what_is_queued_before_it_waits() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let pending = PendingReplies::default();
    pending
        .idle
        .store(false, std::sync::atomic::Ordering::SeqCst);
    assert!(pending.try_queue(
        &Bytes::from_static(b"queued reply"),
        client.local_addr().unwrap()
    ));
    let mut replies = crate::socket_utils::udp_batch::Replies::default();
    // 没有新报文，这个等待不会自己结束 / With no datagram this wait never ends of itself
    let _ = tokio::time::timeout(
        Duration::from_millis(200),
        pending.wait(&server, &mut replies),
    )
    .await;
    let mut buf = [0u8; 64];
    let (len, _) = tokio::time::timeout(Duration::from_millis(500), client.recv_from(&mut buf))
        .await
        .expect("the queued reply went out before the wait")
        .unwrap();
    assert_eq!(&buf[..len], b"queued reply");
}

/// 一次只问一个：接收循环在等新报文时回答直接发，正在转去等待时放进队列的回答也不会卡住
/// One query at a time: while the receive loop waits for datagrams the reply goes directly, and
/// a reply queued just as it turns to waiting does not get stuck
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lone_forwarded_answer_never_waits_in_the_queue() {
    let upstream = spawn_answering_udp_upstream().await;
    let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_addr = server.local_addr().unwrap();
    let engine = Arc::new(engine_forwarding_to(upstream, serde_json::json!({})));
    #[cfg(target_os = "linux")]
    let worker = tokio::spawn(async move { receive_in_batches(&server, &engine).await });
    #[cfg(not(target_os = "linux"))]
    let worker = tokio::spawn(async move { receive_one_by_one(&server, &engine).await });
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut buf = [0u8; 512];
    for id in 0..200u16 {
        let name = format!("lone{id}.forwarded.test");
        client
            .send_to(&query(&name, id), server_addr)
            .await
            .unwrap();
        let (len, _) = tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf))
            .await
            .unwrap_or_else(|_| panic!("query {id} got no answer within a second"))
            .unwrap();
        assert_eq!(Message::from_bytes(&buf[..len]).unwrap().metadata.id, id);
    }
    worker.abort();
}

/// 本机上游，UDP 和 TCP 占同一个端口：收下查询、接下连接，从不回答
/// A local upstream on one port for UDP and TCP: it takes queries and connections and
/// never answers
async fn spawn_silent_upstream() -> SocketAddr {
    // 先拿 UDP 端口，再在同号上绑 TCP：TCP 挑临时端口时不看 UDP 的占用，反过来更容易撞上别的
    // 测试占着的 UDP 端口。同号的 TCP 端口正被占着时换一对，最多试 20 次
    // The UDP port first, then TCP on the same number: the TCP ephemeral allocator
    // does not look at UDP, so the other order runs into UDP ports other tests hold
    // more often. Another pair when that TCP port is taken, at most 20 tries
    let mut tries = 0;
    let (tcp, udp) = loop {
        tries += 1;
        assert!(
            tries <= 20,
            "port conflict: no port free for both UDP and TCP in 20 tries"
        );
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        match TcpListener::bind(udp.local_addr().unwrap()).await {
            Ok(tcp) => break (tcp, udp),
            Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => continue,
            Err(err) => panic!("bind tcp on the udp port: {err}"),
        }
    };
    let addr = tcp.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        let mut buf = [0u8; 512];
        loop {
            tokio::select! {
                Ok((stream, _)) = tcp.accept() => held.push(stream),
                Ok(_) = udp.recv_from(&mut buf) => {}
                else => break,
            }
        }
    });
    addr
}

/// 把查询都用 UDP 转发给 `upstream` 的引擎，`settings` 覆盖在默认设置上
/// An engine forwarding every query over UDP to `upstream`, with `settings` on top of
/// the defaults
fn engine_forwarding_to(upstream: SocketAddr, settings: serde_json::Value) -> Engine {
    let mut all = serde_json::json!({ "default_upstream": upstream.to_string() });
    all.as_object_mut()
        .unwrap()
        .extend(settings.as_object().unwrap().clone());
    let config: crate::config::PipelineConfig = serde_json::from_value(serde_json::json!({
        "settings": all,
        "pipelines": [{
            "id": "p",
            "rules": [{
                "name": "forward",
                "matchers": [{ "type": "any" }],
                "actions": [{
                    "type": "forward",
                    "upstream": upstream.to_string(),
                    "transport": "udp"
                }]
            }]
        }]
    }))
    .expect("parse config");
    let runtime = RuntimePipelineConfig::from_config(config).expect("build runtime config");
    Engine::new(runtime, "test".to_string()).expect("initialize engine")
}

/// 换掉引擎判断「socket 多久没收空算忙」的时长。生产里它就是 `BUSY_AFTER`，配置改不了，测试要别的值只能这样换
/// Changes how long a socket goes without running empty before the engine counts as busy. In
/// production that is `BUSY_AFTER`, which no configuration changes, so a test wanting another value swaps it here
fn with_busy_after(mut engine: Engine, busy_after: Duration) -> Engine {
    let flow = engine
        .flow_control_state
        .take()
        .expect("flow control is on");
    let mut flow = Arc::into_inner(flow).expect("nothing else holds it yet");
    flow.busy_after = busy_after;
    engine.flow_control_state = Some(Arc::new(flow));
    engine
}

/// 智能流控替代了旧参数：配置里写的 `flow_control_latency_threshold_ms` 不起作用，忙不忙始终按 `BUSY_AFTER` 判断
/// Smart flow control replaced the old numbers: a `flow_control_latency_threshold_ms` in the
/// configuration has no effect, and busy is always judged by `BUSY_AFTER`
#[tokio::test]
async fn an_old_busy_threshold_in_the_configuration_has_no_effect() {
    for threshold in [0, 1, 100, 60_000] {
        let engine = engine_forwarding_to(
            "127.0.0.1:9".parse().unwrap(),
            serde_json::json!({
                "flow_control_enabled": true,
                "flow_control_latency_threshold_ms": threshold,
            }),
        );
        let flow = engine
            .flow_control_state
            .as_ref()
            .expect("flow control is on");
        assert_eq!(
            flow.busy_after,
            crate::engine::concurrency::BUSY_AFTER,
            "{threshold}"
        );
    }
}

/// 发一个 UDP 查询、读回回答，连同用时一起返回
/// Send one UDP query, read the answer back, and return it with the time it took
async fn udp_exchange(client: &UdpSocket, server: SocketAddr, query: &[u8]) -> (Message, Duration) {
    let start = std::time::Instant::now();
    client.send_to(query, server).await.unwrap();
    let mut buf = [0u8; 512];
    let (n, _) = tokio::time::timeout(Duration::from_secs(3), client.recv_from(&mut buf))
        .await
        .expect("udp answer")
        .unwrap();
    (Message::from_bytes(&buf[..n]).unwrap(), start.elapsed())
}

/// 在一条连接上发一个查询、读回回答，连同用时一起返回
/// Send one query on a connection, read the answer back, and return it with the time
/// it took
async fn tcp_exchange(client: &mut TcpStream, query: &[u8]) -> (Message, Duration) {
    let start = std::time::Instant::now();
    client.write_all(&framed(query)).await.unwrap();
    let answer = read_tcp_answer(client).await;
    (Message::from_bytes(&answer).unwrap(), start.elapsed())
}

/// 缓存命中的应答带着这条查询自己的事务 ID；TTL 按应答在缓存里停留的整秒数调低（RFC 1035
/// 第 5.2 节），停留不到一秒时原样不动。UDP 和 TCP 一样
/// A cache hit carries the query's own transaction ID, and its TTLs are lowered by the
/// whole seconds the answer sat in the cache (RFC 1035 section 5.2), untouched under a
/// second. The same over UDP and over TCP
#[tokio::test]
async fn a_cache_hit_carries_the_query_id_and_ages_its_ttls() {
    let engine = engine_forwarding_to(spawn_answering_udp_upstream().await, serde_json::json!({}));
    let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_addr = server.local_addr().unwrap();
    let worker = tokio::spawn(run_udp_worker(0, Arc::clone(&server), engine.clone()));
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (mut tcp, connection) = tcp_connection(engine).await;

    // 第一次转发给上游，写进缓存 / The first goes to the upstream and into the cache
    let (forwarded, _) = udp_exchange(&client, server_addr, &query("cached.test", 1)).await;
    assert_eq!((forwarded.metadata.id, forwarded.answers[0].ttl), (1, 300));

    // 停留不到一秒：只换 ID / Under a second in the cache: only the ID changes
    let (udp_hit, _) = udp_exchange(&client, server_addr, &query("cached.test", 2)).await;
    let (tcp_hit, _) = tcp_exchange(&mut tcp, &query("cached.test", 3)).await;
    assert_eq!((udp_hit.metadata.id, udp_hit.answers[0].ttl), (2, 300));
    assert_eq!((tcp_hit.metadata.id, tcp_hit.answers[0].ttl), (3, 300));

    // 停留过一秒：TTL 跟着调低 / Past a second in the cache the TTL goes down too
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let (udp_aged, _) = udp_exchange(&client, server_addr, &query("cached.test", 4)).await;
    let (tcp_aged, _) = tcp_exchange(&mut tcp, &query("cached.test", 5)).await;
    assert_eq!(udp_aged.metadata.id, 4);
    assert_eq!(tcp_aged.metadata.id, 5);
    for aged in [&udp_aged, &tcp_aged] {
        let ttl = aged.answers[0].ttl;
        assert!((295..300).contains(&ttl), "aged TTL {ttl}");
    }

    worker.abort();
    connection.abort();
}

/// 引擎在请求时限内答不上来时，监听器到点回 SERVFAIL：不早于时限，也不等引擎自己放弃。快速解析
/// 读得了的查询和要从头解析的一样，UDP 和 TCP 一样。每次超时记的告警说是哪个监听器、哪个查询、哪个客户端
/// When the engine cannot answer within the request timeout, the listener answers
/// SERVFAIL when it runs out: not before, and without waiting for the engine to give up.
/// A query the quick parse reads and one parsed from scratch alike, over UDP as over TCP.
/// The warning each timeout logs names the listener, the query and the client
#[tokio::test]
async fn listeners_answer_servfail_when_the_request_timeout_runs_out() {
    let (warnings, guard) = crate::engine::test_support::Warnings::capture();
    // 上游从不回答：引擎先用 UDP 试三分之一个时限、再试一个时限，再改用 TCP 等一个时限，加起来比
    // 请求时限长得多，所以先到点的是监听器自己的计时
    // The upstream never answers: the engine tries UDP for a third of the timeout and
    // then a whole one, then TCP for another, far longer than the request timeout, so
    // the listener's own timer runs out first
    const TIMEOUT: Duration = Duration::from_millis(300);
    let engine = engine_forwarding_to(
        spawn_silent_upstream().await,
        serde_json::json!({
            "upstream_timeout_ms": TIMEOUT.as_millis() as u64,
            "request_timeout_ms": TIMEOUT.as_millis() as u64,
            "enable_tcp_fallback": true
        }),
    );
    let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_addr = server.local_addr().unwrap();
    let worker = tokio::spawn(run_udp_worker(0, Arc::clone(&server), engine.clone()));
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (mut tcp_client, connection) = tcp_connection(engine).await;

    for (case, packet) in [
        ("quick parse", query("quick.test", 7)),
        ("full parse", query_parsed_from_scratch(8)),
    ] {
        let id = u16::from_be_bytes([packet[0], packet[1]]);
        let udp = udp_exchange(&client, server_addr, &packet).await;
        let tcp = tcp_exchange(&mut tcp_client, &packet).await;
        for (transport, (answer, took)) in [("UDP", udp), ("TCP", tcp)] {
            assert_eq!(
                (answer.metadata.id, answer.metadata.response_code),
                (id, ResponseCode::ServFail),
                "{case} over {transport}"
            );
            assert!(
                took >= TIMEOUT && took < TIMEOUT * 2,
                "{case} over {transport} took {took:?}"
            );
        }
    }
    drop(guard);
    let lines = warnings.lines();
    for listener in ["UDP", "TCP"] {
        for qname in ["quick.test", r"\032slow.test"] {
            let named = |line: &&String| {
                line.contains(&format!("{listener} request timeout"))
                    && line.contains(&format!("qname={qname} "))
                    && line.contains("client_ip=127.0.0.1")
            };
            assert_eq!(
                lines.iter().filter(named).count(),
                1,
                "{listener} {qname}: {lines:#?}"
            );
        }
    }

    worker.abort();
    connection.abort();
}

/// 要绑的地址：IPv4 地址本身；IPv6 地址本身，`[::]` 之前还有同伴 `0.0.0.0`，端口相同
/// The addresses bound: an IPv4 address itself; an IPv6 address itself, `[::]` preceded by its
/// twin `0.0.0.0` on the same port
#[test]
fn the_listen_addresses_split_any_into_both_families() {
    let addr = |text: &str| text.parse::<SocketAddr>().unwrap();
    let addrs = |text: &str| listen_addrs(addr(text)).collect::<Vec<_>>();
    assert_eq!(addrs("192.0.2.1:53"), [(addr("192.0.2.1:53"), "IPv4")]);
    assert_eq!(
        addrs("[::]:53"),
        [(addr("0.0.0.0:53"), "IPv4"), (addr("[::]:53"), "IPv6")]
    );
    assert_eq!(addrs("[::1]:53"), [(addr("[::1]:53"), "IPv6")]);
}

/// 入站 DoH 监听 `[::]` 时和 TCP 一样开两个监听口：IPv4 的 `0.0.0.0` 和只收 IPv6 的 `[::]`。以前 DoH 只绑一个 `[::]`，
/// 收不收 IPv4 要看系统的默认：FreeBSD 等 BSD 上 IPv4 客户端连不上。这台机器没有 IPv6 就不测
/// Inbound DoH on `[::]` opens two listeners as TCP does: `0.0.0.0` for IPv4 and an IPv6-only
/// `[::]`. DoH used to bind `[::]` alone, whether that took IPv4 being up to the system's
/// default: on FreeBSD and the other BSDs IPv4 clients could not connect. Skipped on a machine
/// without IPv6
#[tokio::test]
async fn doh_on_the_any_address_listens_on_both_families_as_tcp_does() {
    // 两个地址族都空着的端口：IPv6 socket 在 Linux、macOS 上默认两边都占 / A port free in both
    // families: on Linux and macOS an IPv6 socket takes both by default
    let Ok(probe) = std::net::TcpListener::bind("[::]:0") else {
        return;
    };
    let any = probe.local_addr().unwrap();
    drop(probe);
    let dir = tempfile::tempdir().unwrap();
    let (tls_cert, tls_key) = crate::engine::test_support::write_certificate(dir.path());
    let bound = BoundListeners::bind(
        ListenerConfig {
            udp: "127.0.0.1:0".parse().unwrap(),
            tcp: "127.0.0.1:0".parse().unwrap(),
            doh: Some(crate::config::DohListenerConfig {
                bind: any,
                tls_cert,
                tls_key,
                path: "/dns-query".to_string(),
            }),
        },
        1,
    )
    .unwrap();

    let doh = bound.doh.expect("DoH is bound");
    let listening: Vec<SocketAddr> = doh
        .listeners
        .iter()
        .map(|listener| listener.local_addr().unwrap())
        .collect();
    assert_eq!(
        listening,
        [SocketAddr::from(([0, 0, 0, 0], any.port())), any],
        "IPv4 apart, then IPv6"
    );
    assert!(
        socket2::SockRef::from(&doh.listeners[1]).only_v6().unwrap(),
        "the IPv6 listener takes IPv6 alone"
    );
}

/// 端口被别的程序占着时 UDP 绑不上，启动失败：以前设着 SO_REUSEADDR 和 SO_REUSEPORT，悄悄和占着端口的程序共用（默认的
/// 5353 上就是 mDNSResponder、avahi），查询进了别人那里。占端口的这个和它们一样设 SO_REUSEADDR；Linux 上 SO_REUSEPORT
/// 只在同一个用户的 socket 之间共用，avahi 是另一个用户，这里同一个用户就只设 SO_REUSEADDR，内核不分报文的系统上再像
/// mDNSResponder 那样设 SO_REUSEPORT
/// A UDP port taken by another program cannot be bound, and starting fails: SO_REUSEADDR and
/// SO_REUSEPORT used to be set, quietly sharing the port with the program holding it
/// (mDNSResponder or avahi on the default 5353), the queries going there. The one holding it
/// here sets SO_REUSEADDR as they do; on Linux SO_REUSEPORT is shared only between one user's
/// sockets and avahi runs as another, so being the same user it sets SO_REUSEADDR alone there,
/// and SO_REUSEPORT as mDNSResponder does where the kernel does not spread datagrams
#[cfg(unix)]
#[tokio::test]
async fn a_udp_port_taken_by_another_program_cannot_be_bound() {
    use std::os::fd::AsRawFd;
    let taken = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None).unwrap();
    taken.set_reuse_address(true).unwrap();
    if !crate::socket_utils::SPREADS_DATAGRAMS {
        let on: libc::c_int = 1;
        // SAFETY: the option value is a valid c_int for the call, which only reads it
        let set = unsafe {
            libc::setsockopt(
                taken.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_REUSEPORT,
                (&on as *const libc::c_int).cast(),
                std::mem::size_of_val(&on) as libc::socklen_t,
            )
        };
        assert_eq!(set, 0);
    }
    taken
        .bind(&SocketAddr::from(([127, 0, 0, 1], 0)).into())
        .unwrap();
    let addr = taken.local_addr().unwrap().as_socket().unwrap();

    let Err(err) = bind_udp_workers(addr, "IPv4", 2) else {
        panic!("{addr} is shared with the program holding it");
    };
    assert!(format!("{err:#}").contains("in use"), "{err:#}");
}

/// 内核不分报文的系统上（macOS、OpenBSD、NetBSD、Windows）worker 共用一个 socket，分得开的系统上每个一个。以前各绑
/// 一个，报文都进其中一个，别的 worker 白等着
/// Where the kernel does not spread datagrams (macOS, OpenBSD, NetBSD, Windows) the workers
/// share one socket, and where it does each has its own. Each used to bind one, every datagram
/// going to one of them and the other workers waiting for nothing
#[tokio::test]
async fn udp_workers_share_a_socket_where_the_kernel_does_not_spread_datagrams() {
    let bound = bind_udp_workers(SocketAddr::from(([127, 0, 0, 1], 0)), "IPv4", 3).unwrap();
    let shared = bound
        .sockets
        .iter()
        .all(|socket| Arc::ptr_eq(socket, &bound.sockets[0]));
    assert_eq!(bound.sockets.len(), 3);
    assert_eq!(shared, !crate::socket_utils::SPREADS_DATAGRAMS);
}

/// TCP 上放不进一个消息的回答（超过 65535 字节，长度前缀只有两个字节）换成只带问题的 SERVFAIL：以前不发，客户端一直等到超时
/// An answer over TCP too long for one message (over 65535 bytes, the length prefix having two
/// bytes) gives way to a SERVFAIL with the question: it used to go unsent, the client waiting
/// until it timed out
#[tokio::test]
async fn a_tcp_answer_too_long_for_a_message_is_servfail() {
    // 5000 条 A 记录，每条 16 字节 / 5000 A records of 16 bytes each
    let addresses: Vec<String> = (0..5000u32)
        .map(|n| std::net::Ipv4Addr::from(0x0A00_0000 + n).to_string())
        .collect();
    let config: crate::config::PipelineConfig = serde_json::from_value(serde_json::json!({
        "settings": { "default_upstream": "127.0.0.1:9" },
        "pipelines": [{
            "id": "p",
            "rules": [{
                "name": "many",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "static_ip_response", "ip": addresses.join(",") }]
            }]
        }]
    }))
    .expect("parse config");
    let engine = Engine::new(
        RuntimePipelineConfig::from_config(config).expect("build runtime config"),
        "test".to_string(),
    )
    .expect("initialize engine");
    let (mut tcp, connection) = tcp_connection(engine).await;

    let (answer, _) = tokio::time::timeout(
        Duration::from_secs(2),
        tcp_exchange(&mut tcp, &query("many.test", 7)),
    )
    .await
    .expect("an answer");
    assert_eq!(answer.metadata.id, 7);
    assert_eq!(answer.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(answer.queries.len(), 1);
    assert!(answer.answers.is_empty());
    connection.abort();
}

/// 装不进一条记录的静态 TXT（一段超过 255 字节，或者总长超过 65535），UDP 和 TCP 都收到
/// SERVFAIL，不带 TC。以前总长超长时两边收到的都是 NOERROR、TC 置位、没有答案的应答
/// A static TXT that does not fit a record (a segment over 255 bytes, or a total over
/// 65535) is SERVFAIL over UDP and TCP alike, without TC. A total that was too long
/// used to give both a NOERROR answer with TC set and no records
#[tokio::test]
async fn a_static_txt_that_does_not_fit_a_record_is_servfail_over_udp_and_tcp() {
    let config: crate::config::PipelineConfig = serde_json::from_value(serde_json::json!({
        "settings": { "default_upstream": "127.0.0.1:9" },
        "pipelines": [{
            "id": "p",
            "rules": [
                {
                    "name": "segment",
                    "matchers": [{ "type": "domain_suffix", "value": "segment.test" }],
                    "actions": [{ "type": "static_txt_response", "text": ["x".repeat(256)] }]
                },
                {
                    "name": "total",
                    "matchers": [{ "type": "any" }],
                    "actions": [{
                        "type": "static_txt_response",
                        "text": vec!["y".repeat(250); 300]
                    }]
                }
            ]
        }]
    }))
    .expect("parse config");
    let engine = Engine::new(
        RuntimePipelineConfig::from_config(config).expect("build runtime config"),
        "test".to_string(),
    )
    .expect("initialize engine");
    let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_addr = server.local_addr().unwrap();
    let worker = tokio::spawn(run_udp_worker(0, Arc::clone(&server), engine.clone()));
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (mut tcp, connection) = tcp_connection(engine).await;

    for (id, qname) in [(1, "segment.test"), (2, "total.test")] {
        let (udp, _) = udp_exchange(&client, server_addr, &query(qname, id)).await;
        let (tcp, _) = tcp_exchange(&mut tcp, &query(qname, id)).await;
        for (transport, answer) in [("UDP", udp), ("TCP", tcp)] {
            assert_eq!(
                (answer.metadata.response_code, answer.metadata.truncation),
                (ResponseCode::ServFail, false),
                "{qname} over {transport}"
            );
        }
    }

    worker.abort();
    connection.abort();
}
