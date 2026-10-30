//! 引擎测试共用的部分：本机假上游、按配置建引擎，以及像监听器那样问。
//! What the engine tests share: a local fake upstream, an engine built from a config,
//! and asking as a listener does.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::Bytes;
use hickory_proto::op::{Message, MessageType, OpCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, Record};
use hickory_proto::serialize::binary::BinDecodable;
use parking_lot::Mutex;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::engine::transport::DOH_MEDIA_TYPE;
use crate::engine::{Engine, FastPathResponse};
use crate::matcher::RuntimePipelineConfig;

/// 假上游对一个查询发出的应答：每个在多久之后发、发什么
/// What the fake upstream sends for one query: each reply, and how long after it
pub(super) type Replies = Vec<(Duration, Vec<u8>)>;

/// 假上游 / A fake upstream
pub(crate) struct Upstream {
    pub(crate) address: String,
    /// 收到的每个查询 / Every query it received
    received: Arc<Mutex<Vec<Vec<u8>>>>,
    /// 置位后照样收、照样记，只是不再应答 / Once set, it still receives and records but no
    /// longer answers
    silent: Arc<AtomicBool>,
}

impl Upstream {
    /// 收到的查询个数 / How many queries it received
    pub(super) fn queries(&self) -> usize {
        self.received.lock().len()
    }

    /// 收到的每个查询 / Every query it received
    pub(super) fn received(&self) -> Vec<Message> {
        self.received
            .lock()
            .iter()
            .map(|query| Message::from_bytes(query).expect("parse query"))
            .collect()
    }

    /// 停止或恢复应答 / Stop or resume answering
    pub(super) fn silence(&self, silent: bool) {
        self.silent.store(silent, Ordering::SeqCst);
    }
}

/// 按 `replies` 对每个查询作答的本机 UDP 上游 / A local UDP upstream answering each query as `replies` says
pub(crate) async fn upstream(replies: impl Fn(&Message) -> Replies + Send + 'static) -> Upstream {
    let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let address = sock.local_addr().unwrap().to_string();
    let received = Arc::new(Mutex::new(Vec::new()));
    let silent = Arc::new(AtomicBool::new(false));
    let (recorded, muted) = (received.clone(), silent.clone());
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            let Ok(query) = Message::from_bytes(&buf[..n]) else {
                continue;
            };
            recorded.lock().push(buf[..n].to_vec());
            if muted.load(Ordering::SeqCst) {
                continue;
            }
            for (delay, reply) in replies(&query) {
                let sock = sock.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let _ = sock.send_to(&reply, peer).await;
                });
            }
        }
    });
    Upstream {
        address,
        received,
        silent,
    }
}

/// 每个查询回一条 TTL 为 `ttl` 的 A 记录 `address` 的本机 UDP 上游
/// A local UDP upstream answering every query with one A record `address` of TTL `ttl`
pub(crate) async fn answering_upstream(address: Ipv4Addr, ttl: u32) -> Upstream {
    answering_upstream_after(address, ttl, Duration::ZERO).await
}

/// 同 [`answering_upstream`]，但每个应答晚 `delay` 才发出
/// The same as [`answering_upstream`], with every answer sent `delay` late
pub(crate) async fn answering_upstream_after(
    address: Ipv4Addr,
    ttl: u32,
    delay: Duration,
) -> Upstream {
    upstream(move |query| {
        let Some(question) = query.queries.first() else {
            return Vec::new();
        };
        let mut reply = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
        reply.metadata.recursion_desired = query.metadata.recursion_desired;
        reply.add_query(question.clone());
        reply.add_answer(Record::from_rdata(
            question.name().clone(),
            ttl,
            RData::A(A(address)),
        ));
        vec![(delay, reply.to_vec().unwrap())]
    })
    .await
}

/// UDP 和 TCP 占同一个端口的本机上游：收下查询、接下连接，从不回答
/// A local upstream on one port for UDP and TCP: it takes queries and connections and
/// never answers
pub(crate) async fn silent_upstream() -> SocketAddr {
    // 先拿 UDP 端口，再在同号上绑 TCP（顺序的道理见 upstream.rs 测试里的
    // `bind_udp_and_tcp_on_one_port`）；同号的 TCP 端口正被占着时换一对，最多试 20 次
    // The UDP port first, then TCP on the same number (see `bind_udp_and_tcp_on_one_port`
    // in the upstream.rs tests for the order); another pair when that TCP port is
    // taken, at most 20 tries
    let mut tries = 0;
    let (tcp, udp) = loop {
        tries += 1;
        assert!(
            tries <= 20,
            "port conflict: no port free for both UDP and TCP in 20 tries"
        );
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        match tokio::net::TcpListener::bind(udp.local_addr().unwrap()).await {
            Ok(tcp) => break (tcp, udp),
            Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => continue,
            Err(err) => panic!("bind tcp on the udp port: {err}"),
        }
    };
    let address = tcp.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        let mut buf = [0u8; 1500];
        loop {
            tokio::select! {
                Ok((stream, _)) = tcp.accept() => held.push(stream),
                Ok(_) = udp.recv_from(&mut buf) => {}
                else => break,
            }
        }
    });
    address
}

/// 照 `config` 建的引擎 / An engine built from `config`
pub(crate) fn engine_from(config: Value) -> Engine {
    let config: crate::config::PipelineConfig =
        serde_json::from_value(config).expect("parse config");
    Engine::new(
        RuntimePipelineConfig::from_config(config).expect("build runtime config"),
        "test".to_string(),
    )
    .expect("engine")
}

/// 和「等在别人的条目上」有关的观察者事件，按先后记下：哪个客户端的请求开始了、发出了转发、拿到了上游的
/// 结果、挂到了别人的条目上
/// The observer events that bear on waiting on another request's entry, in order: which
/// client's request started, forwarded, got an upstream's result, or joined another's entry
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Step {
    Started(SocketAddr),
    Forwarded(SocketAddr, String),
    Answered(SocketAddr, String),
    Joined(SocketAddr),
}

/// 按先后记下 [`Step`] 的观察者 / An observer recording [`Step`]s in order
#[derive(Default)]
pub(crate) struct Steps(Mutex<Vec<Step>>);

impl Steps {
    fn position(&self, step: &Step) -> Option<usize> {
        self.0.lock().iter().position(|taken| taken == step)
    }

    /// `client` 的请求挂到了别人的条目上 / `client`'s request joined another's entry
    pub(crate) fn joined(&self, client: &str) -> bool {
        self.position(&Step::Joined(client.parse().unwrap()))
            .is_some()
    }

    /// `later` 发往 `later_upstream` 的转发，在 `leader` 发往 `upstream` 的转发拿到结果之前就发出了：
    /// 两个请求同时在等，`later` 查 inflight 表时 `leader` 的条目还在，它自己转发而没有等
    /// `later`'s forward to `later_upstream` went out before `leader`'s forward to `upstream`
    /// got its result: both waited at once, so `leader`'s entry was there when `later` looked
    /// in the inflight map, and it forwarded itself instead of waiting
    pub(crate) fn forwarded_while_waiting(
        &self,
        (leader, upstream): (&str, &str),
        (later, later_upstream): (&str, &str),
    ) -> bool {
        let (leader, later) = (leader.parse().unwrap(), later.parse().unwrap());
        let steps = self.0.lock();
        let at = |step: &Step| steps.iter().position(|taken| taken == step);
        match (
            at(&Step::Forwarded(leader, upstream.to_string())),
            at(&Step::Forwarded(later, later_upstream.to_string())),
            at(&Step::Answered(leader, upstream.to_string())),
        ) {
            (Some(first), Some(second), Some(answered)) => first < second && second < answered,
            _ => false,
        }
    }

    /// `later` 等在了 `leader` 发往 `upstream` 的那次转发的条目上：那次转发还在等结果时，`later` 已经
    /// 走到了（记下了别的事件），却没有同时发往 `upstream`；它自己发往那里的转发在那次转发拿到结果之后
    /// `later` waited on the entry of `leader`'s forward to `upstream`: while that forward
    /// still waited for its result `later` had got there (recorded other steps) without
    /// forwarding to `upstream` as well, and its own forward there came after that result
    pub(crate) fn waited_on(&self, leader: &str, upstream: &str, later: &str) -> bool {
        let (leader, later): (SocketAddr, SocketAddr) =
            (leader.parse().unwrap(), later.parse().unwrap());
        let steps = self.0.lock();
        let at = |step: &Step| steps.iter().position(|taken| taken == step);
        let (Some(forwarded), Some(answered)) = (
            at(&Step::Forwarded(leader, upstream.to_string())),
            at(&Step::Answered(leader, upstream.to_string())),
        ) else {
            return false;
        };
        let of_later = |step: &Step| match step {
            Step::Started(client) | Step::Joined(client) => *client == later,
            Step::Forwarded(client, _) | Step::Answered(client, _) => *client == later,
        };
        let meanwhile = &steps[forwarded + 1..answered];
        meanwhile.iter().any(of_later)
            && !meanwhile.contains(&Step::Forwarded(later, upstream.to_string()))
            && steps[answered..].contains(&Step::Forwarded(later, upstream.to_string()))
    }

    /// 两个请求发往 `upstream` 的转发同时在等：后发出的那个，在先发出的那个拿到结果之前就发出了。谁先到那一步不定
    /// The two requests' forwards to `upstream` waited at once: the later one went out before
    /// the earlier one got its result. Which got there first may go either way
    pub(crate) fn forwarded_together(&self, upstream: &str, [a, b]: [&str; 2]) -> bool {
        self.forwarded_while_waiting((a, upstream), (b, upstream))
            || self.forwarded_while_waiting((b, upstream), (a, upstream))
    }

    /// 两个请求里有一个等在了另一个发往 `upstream` 的那次转发的条目上（见 [`Self::waited_on`]）。谁先到那一步不定
    /// One of the two requests waited on the entry of the other's forward to `upstream` (see
    /// [`Self::waited_on`]). Which got there first may go either way
    pub(crate) fn one_waited_on_the_other(&self, upstream: &str, [a, b]: [&str; 2]) -> bool {
        self.waited_on(a, upstream, b) || self.waited_on(b, upstream, a)
    }

    /// 记下的全部事件，断言失败时看 / Every step recorded, for a failing assertion
    pub(crate) fn taken(&self) -> Vec<Step> {
        self.0.lock().clone()
    }
}

impl crate::observe::EngineObserver for Steps {
    fn request_started(&self, ctx: &crate::observe::RequestContext<'_>) {
        if !ctx.background_refresh {
            self.0.lock().push(Step::Started(ctx.client));
        }
    }

    fn upstream_attempt(
        &self,
        ctx: &crate::observe::RequestContext<'_>,
        event: &crate::observe::UpstreamAttempt<'_>,
    ) {
        self.0
            .lock()
            .push(Step::Forwarded(ctx.client, event.upstream.to_string()));
    }

    fn upstream_result(
        &self,
        ctx: &crate::observe::RequestContext<'_>,
        event: &crate::observe::UpstreamResult<'_>,
    ) {
        self.0
            .lock()
            .push(Step::Answered(ctx.client, event.upstream.to_string()));
    }

    fn inflight_joined(&self, ctx: &crate::observe::RequestContext<'_>) {
        self.0.lock().push(Step::Joined(ctx.client));
    }
}

/// 照 `config` 建的、由 [`Steps`] 观察的引擎 / An engine built from `config`, observed by
/// [`Steps`]
pub(crate) fn engine_with_steps(config: Value) -> (Engine, Arc<Steps>) {
    let config: crate::config::PipelineConfig =
        serde_json::from_value(config).expect("parse config");
    runtime_with_steps(RuntimePipelineConfig::from_config(config).expect("build runtime config"))
}

/// 同 [`engine_with_steps`]，从建好的运行时配置建 / As [`engine_with_steps`], from a built
/// runtime configuration
pub(crate) fn runtime_with_steps(runtime: RuntimePipelineConfig) -> (Engine, Arc<Steps>) {
    let steps = Arc::new(Steps::default());
    let engine = Engine::builder(runtime)
        .listener_label("test".to_string())
        .observer(steps.clone())
        .build()
        .expect("engine");
    (engine, steps)
}

/// 数上游查询的测试用的设置，`extra` 覆盖在上面 / Settings for tests that count upstream
/// queries, with `extra` on top
pub(super) fn counting_settings(extra: Value) -> Value {
    let mut all = json!({
        "default_upstream": "127.0.0.1:9",
        // A UDP query is sent again after a third of this (`upstream::hedge_timeout`). The
        // tests count upstream queries, and on a busy machine 1 s let an answer arrive
        // after that point now and then; tests that wait on a silent upstream set less.
        // UDP 查询过了这个时间的三分之一会再发一次（`upstream::hedge_timeout`）。这些测试数上游
        // 收到的查询，机器忙时 1 秒偶尔会让应答晚过这个点；要等上游不应答的测试自己设得更短。
        "upstream_timeout_ms": 3000,
        "enable_tcp_fallback": false
    });
    all.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    all
}

/// 静态规则给的地址 / The address the static rule answers
pub(super) const STATIC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 80);

/// 名字以 `matched.test` 结尾的请求得到静态的 [`STATIC`]，以 `text.test` 结尾的得到静态 TXT（它不能
/// 预先算好，第一次走完整路径，之后从规则缓存作答），其余转发给 `upstream`
/// A name ending in `matched.test` gets the static [`STATIC`], one ending in `text.test` a
/// static TXT (which cannot be computed ahead, so the full path answers it first and the
/// rule cache afterwards), and the rest go to `upstream`
pub(super) fn static_or_forward(upstream: &str) -> Engine {
    engine_from(json!({
        "settings": counting_settings(json!({})),
        "pipelines": [{ "id": "main", "rules": [
            {
                "name": "static",
                "matchers": [{ "type": "domain_suffix", "value": "matched.test" }],
                "actions": [{ "type": "static_ip_response", "ip": STATIC.to_string() }]
            },
            {
                "name": "text",
                "matchers": [{ "type": "domain_suffix", "value": "text.test" }],
                "actions": [{ "type": "static_txt_response", "text": ["hello"] }]
            },
            {
                "name": "all",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": upstream }]
            }
        ]}]
    }))
}

pub(super) fn peer() -> SocketAddr {
    "127.0.0.1:53000".parse().unwrap()
}

/// 应答里的第一个 A 记录 / The first A record in a reply
pub(super) fn first_a(reply: &[u8]) -> Option<Ipv4Addr> {
    match Message::from_bytes(reply)
        .expect("parse reply")
        .answers
        .first()
        .map(|record| &record.data)
    {
        Some(RData::A(address)) => Some(address.0),
        _ => None,
    }
}

/// 走完整路径 / Through the full path
pub(super) async fn ask(engine: &Engine, packet: &[u8], peer: SocketAddr) -> Bytes {
    tokio::time::timeout(Duration::from_secs(5), engine.handle_packet(packet, peer))
        .await
        .expect("answer in time")
        .expect("answer")
}

/// 像监听器那样先走快速路径，要等上游的再带着预解析的数据走异步路径；快速路径读不了这个查询时
/// 为 None
/// The fast path first as a listener does, then the async path with the pre-parsed data
/// when an upstream has to answer; None when the fast path cannot read the query
pub(super) async fn ask_fast_path_first(
    engine: &Engine,
    packet: &[u8],
    peer: SocketAddr,
) -> Option<Bytes> {
    Some(
        match engine
            .handle_packet_fast(packet, peer)
            .expect("fast path")?
        {
            FastPathResponse::Direct(reply) => reply,
            FastPathResponse::CacheHit { cached, .. } => cached,
            FastPathResponse::AsyncNeeded(pre_parsed) => tokio::time::timeout(
                Duration::from_secs(5),
                engine.handle_packet_internal_with_pre_parsed(packet, peer, false, pre_parsed),
            )
            .await
            .expect("answer in time")
            .expect("answer"),
        },
    )
}

/// 像监听器那样问：快速路径读不了的查询，和监听器一样交给完整路径
/// Ask as a listener does: a query the fast path cannot read goes to the full path,
/// as a listener sends it
pub(super) async fn ask_like_a_listener(engine: &Engine, packet: &[u8], peer: SocketAddr) -> Bytes {
    match ask_fast_path_first(engine, packet, peer).await {
        Some(reply) => reply,
        None => ask(engine, packet, peer).await,
    }
}

/// 每个请求都回 429 的本机 DoH 上游，像常见的限速网关那样带一页 HTML
/// A local DoH upstream answering every request with a 429 and an HTML page, as a common
/// rate-limiting gateway does
pub(crate) struct Throttling {
    /// 写进配置的样子 / As written in the configuration
    pub(crate) url: String,
    /// 观察者事件里的样子：去掉前缀的地址 / As in observer events: the address without its prefix
    pub(crate) address: String,
    asked: Arc<std::sync::Mutex<Vec<String>>>,
}

impl Throttling {
    /// `retry_after` 是 Retry-After 头的值，None 就不带 / `retry_after` is the Retry-After
    /// header's value, none for None
    pub(crate) async fn spawn(retry_after: Option<&'static str>) -> Self {
        let (addr, asked) = spawn_doh_upstream(move |_, _| {
            let body = "<html><body>429 Too Many Requests</body></html>";
            let retry_after =
                retry_after.map_or_else(String::new, |value| format!("retry-after: {value}\r\n"));
            DohReply::Raw(
                format!(
                    "HTTP/1.1 429 Too Many Requests\r\ncontent-type: text/html\r\n{retry_after}content-length: {}\r\n\r\n{body}",
                    body.len()
                )
                .into_bytes(),
            )
        })
        .await;
        Self {
            url: format!("https://{addr}/dns-query"),
            address: format!("{addr}/dns-query"),
            asked,
        }
    }

    /// 收到过几个请求 / How many requests it got
    pub(crate) fn asked(&self) -> usize {
        self.asked.lock().unwrap().len()
    }
}

/// 本机 DoH 测试上游怎么回一个请求 / How the local DoH test upstream answers one request
pub(crate) enum DohReply {
    /// 把这些字节当作整个 HTTP 响应写回去 / Write these bytes back as the whole HTTP response
    Raw(Vec<u8>),
    /// 200，分块的正文永远发不完 / A 200 whose chunked body never ends
    Endless,
    /// 读完请求就断开，不回答 / Read the request and close the connection unanswered
    Close,
}

/// 本机明文 DoH 上游：每个请求按 `reply(路径, 正文)` 回答。返回监听地址和它被请求过的路径（按先后）
/// Local plain-HTTP DoH upstream: each request is answered by `reply(path, body)`.
/// Returns its address and the paths it was asked for, in order
pub(crate) async fn spawn_doh_upstream(
    reply: impl Fn(&str, &[u8]) -> DohReply + Send + Sync + 'static,
) -> (SocketAddr, Arc<std::sync::Mutex<Vec<String>>>) {
    let reply = Arc::new(reply);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind DoH stub");
    let addr = listener.local_addr().expect("DoH stub address");
    let paths = Arc::new(std::sync::Mutex::new(Vec::new()));
    let record = Arc::clone(&paths);
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let record = Arc::clone(&record);
            let reply = Arc::clone(&reply);
            tokio::spawn(async move {
                let mut buf = Vec::new();
                while let Some((head, body)) = next_http_request(&mut socket, &mut buf).await {
                    let path = head
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or_default()
                        .to_string();
                    record.lock().unwrap().push(path.clone());
                    match reply(&path, &body) {
                        DohReply::Raw(response) => {
                            if socket.write_all(&response).await.is_err() {
                                return;
                            }
                        }
                        DohReply::Endless => {
                            let head = format!(
                                "HTTP/1.1 200 OK\r\ncontent-type: {DOH_MEDIA_TYPE}\r\ntransfer-encoding: chunked\r\n\r\n"
                            );
                            let piece = [0u8; 16 * 1024];
                            let chunk =
                                [format!("{:x}\r\n", piece.len()).as_bytes(), &piece, b"\r\n"]
                                    .concat();
                            if socket.write_all(head.as_bytes()).await.is_ok() {
                                while socket.write_all(&chunk).await.is_ok() {}
                            }
                            return;
                        }
                        DohReply::Close => return,
                    }
                }
            });
        }
    });
    (addr, paths)
}

/// 200 应答，带给定的媒体类型（None 就不带）和正文 / A 200 with the given media type (none for None) and body
pub(crate) fn http_ok(media_type: Option<&str>, body: &[u8]) -> Vec<u8> {
    let mut head = String::from("HTTP/1.1 200 OK\r\n");
    if let Some(media_type) = media_type {
        head.push_str(&format!("content-type: {media_type}\r\n"));
    }
    head.push_str(&format!("content-length: {}\r\n\r\n", body.len()));
    [head.as_bytes(), body].concat()
}

/// `socket` 上的下一个 HTTP/1.1 请求：请求头（转成小写）和正文。`buf` 存着上一个请求之后多读的字节；
/// 客户端走了就是 None
/// The next HTTP/1.1 request on `socket`: its head (lower-cased) and body. `buf`
/// holds the bytes read past the previous request; `None` once the client is gone
async fn next_http_request(
    socket: &mut tokio::net::TcpStream,
    buf: &mut Vec<u8>,
) -> Option<(String, Vec<u8>)> {
    let mut chunk = [0u8; 2048];
    let header_end = loop {
        if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        match socket.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_ascii_lowercase();
    let length = head
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    while buf.len() < header_end + length {
        match socket.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    let body = buf[header_end..header_end + length].to_vec();
    buf.drain(..header_end + length);
    Some((head, body))
}

/// 测试期间记下的 warn 及以上的日志 / The warn-and-above log lines written during a test
#[derive(Clone, Default)]
pub(crate) struct Warnings(Arc<Mutex<Vec<u8>>>);

impl Warnings {
    /// 从现在起记下这个线程上的 warn 及以上的日志，直到返回的守卫被丢掉；`#[tokio::test]` 默认的单线程
    /// 运行时里，引擎派生的任务也在这个线程上
    /// Records this thread's warn-and-above lines from now until the returned guard is
    /// dropped; on the single-threaded runtime `#[tokio::test]` uses by default, the
    /// tasks the engine spawns run on this thread too
    pub(crate) fn capture() -> (Self, tracing::subscriber::DefaultGuard) {
        // 只登记着一个订阅者时，tracing 按碰到回调点的那个线程自己的订阅者缓存回调点要不要记：别的测试
        // 线程（没装订阅者）先碰到引擎里的某个 warn，这里就再也收不到它。全局放一个什么都不收的订阅者，
        // 抓日志时登记的就总有两个，回调点改成每次都问当前线程的订阅者
        // With a single subscriber registered, tracing caches whether a callsite is wanted by
        // asking the subscriber of whichever thread hits it first: another test thread (with
        // none installed) hitting one of the engine's warns first would hide it from here for
        // good. A global subscriber that takes nothing keeps two registered while a test
        // captures, so callsites ask the current thread's subscriber every time
        static GLOBAL: std::sync::Once = std::sync::Once::new();
        GLOBAL.call_once(|| {
            let _ =
                tracing::subscriber::set_global_default(tracing::subscriber::NoSubscriber::new());
        });
        let warnings = Self::default();
        let writer = warnings.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .without_time()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        (warnings, tracing::subscriber::set_default(subscriber))
    }

    /// 记下的各行 / The lines recorded
    pub(crate) fn lines(&self) -> Vec<String> {
        String::from_utf8_lossy(&self.0.lock())
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

impl std::io::Write for Warnings {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
