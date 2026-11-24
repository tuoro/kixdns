//! DoQ（RFC 9250）：每个上游一池 QUIC 连接，一个查询一个流；可以用 0-RTT，被拒绝以后不再用
//! DoQ (RFC 9250): a pool of QUIC connections per upstream, a stream per query; 0-RTT is used
//! where allowed and dropped once rejected

use super::address::{DoqTarget, parse_doq_target};
use super::connect::{
    Aging, Connect, ConnectionPool, InFlight, UpstreamPools, Wear, build_tls_client_config, forget,
    staggered,
};
use super::{MAX_DNS_MESSAGE_SIZE, retry_budget};
use crate::engine::bootstrap::Bootstrap;
use crate::engine::doh_h2;
use anyhow::Context;
use arc_swap::ArcSwapOption;
use bytes::Bytes;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{
    Connection as QuicConnection, Endpoint as QuicEndpoint, TransportConfig as QuicTransportConfig,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

struct DoqRuntime {
    endpoint_v4: QuicEndpoint,
    endpoint_v6: QuicEndpoint,
    /// 连接怎样老化：最长 [`DOQ_MAX_AGE`]，空闲 `doq_connection_idle_timeout_seconds` / How connections
    /// age: [`DOQ_MAX_AGE`] at most, idle for `doq_connection_idle_timeout_seconds`
    aging: Aging,
    /// 上游的主机名怎样解析（见 [`Bootstrap`]）/ How upstream host names are resolved (see [`Bootstrap`])
    bootstrap: Arc<Bootstrap>,
    enable_0rtt: bool,
    /// 0-RTT 的安全提示只在真正用上 0-RTT 时打印一次
    /// Prints the 0-RTT security notice once, and only if 0-RTT is really used
    zero_rtt_notice: std::sync::Once,
}

/// DoQ (DNS over QUIC) 连接池
/// DoQ (DNS over QUIC) connection pool
///
/// 参考 RFC 9250 (DNS over Dedicated QUIC Connections) 实现
/// Implements RFC 9250 (DNS over Dedicated QUIC Connections)
pub type DoqConnectionPool = ConnectionPool<DoqMuxClient>;

/// DoQ 一次尝试的失败原因，按类型保留 quinn 的原始错误
/// Why one DoQ attempt failed, keeping quinn's own error by type
///
/// 每一步都包进 `.context()` 的话，`anyhow::Error::to_string()` 只给出最外层那一句，判定 0-RTT 是否被拒绝时看不到 quinn
/// 说了什么。原始错误原样带出来，判定就落在类型上
/// With every step wrapped in `.context()`, `anyhow::Error::to_string()` would render only the
/// outermost one, and the check for a rejected 0-RTT attempt would never see quinn's own words.
/// Carried out untouched, the error lets the decision rest on types
#[derive(Debug)]
enum DoqFailure {
    /// `open_bi` 失败：连接已经不可用 / the connection is already unusable
    OpenStream(quinn::ConnectionError),
    /// 写查询失败 / writing the query failed
    Write(quinn::WriteError),
    /// 读应答失败 / reading the answer failed
    Read(quinn::ReadToEndError),
    /// 应答本身不合协议，与 0-RTT 无关 / the answer itself is malformed
    Protocol(String),
}

impl std::fmt::Display for DoqFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OpenStream(err) => write!(f, "doq open stream failed: {err}"),
            Self::Write(err) => write!(f, "doq send query failed: {err}"),
            Self::Read(err) => write!(f, "doq read response failed: {err}"),
            Self::Protocol(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for DoqFailure {
    /// 保住 quinn 的 source 链：类型化到这里就被拍平成字符串的话，日志里就只
    /// 剩 Display 那一行了。
    /// Keeps quinn's source chain: flattening to a string at this boundary
    /// would leave the log with nothing but the Display line.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::OpenStream(err) => Some(err),
            Self::Write(err) => Some(err),
            Self::Read(err) => Some(err),
            Self::Protocol(_) => None,
        }
    }
}

/// DoQ (DNS over QUIC) 客户端，管理多个上游的 QUIC 连接池
/// DoQ (DNS over QUIC) client, managing QUIC connection pools for multiple upstreams
///
/// 参考 RFC 9250 (DNS over Dedicated QUIC Connections) 实现
/// Implements RFC 9250 (DNS over Dedicated QUIC Connections)
pub struct DoqClient {
    pools: UpstreamPools<DoqMuxClient>,
    /// 每个池几个客户端，至少一个 / How many clients a pool has, at least one
    pool_size: usize,
    runtime: Arc<DoqRuntime>,
}

/// DoQ (DNS over QUIC) 多路复用客户端，管理单个上游的 QUIC 连接
/// DoQ (DNS over QUIC) multiplexing client, managing QUIC connection for a single upstream
///
/// 参考 RFC 9250 (DNS over Dedicated QUIC Connections) 实现
/// Implements RFC 9250 (DNS over Dedicated QUIC Connections)
pub struct DoqMuxClient {
    upstream: Arc<str>,
    /// 解析好的上游地址，第一个查询时算 / The upstream address parsed, worked out at the first query
    target: std::sync::OnceLock<DoqTarget>,
    /// 池里的连接。读它不加锁，建连的任务建好了把连接放进来 / The pooled connection, read without a
    /// lock; the connecting task puts the connection here once made
    pooled: Arc<ArcSwapOption<DoqConn>>,
    /// 在建的连接、建连失败以后的退避（见 [`Connect`]）；等它算在各个查询自己的预算里 / The
    /// connection being made and the backing off after a failed connect (see [`Connect`]); waiting
    /// for it counts against each query's own budget
    connecting: parking_lot::Mutex<Connect>,
    /// 这个客户端上还没答完的查询数（见 [`least_busy`]）/ Queries on this client not yet answered (see [`least_busy`])
    in_flight: AtomicUsize,
    runtime: Arc<DoqRuntime>,
    /// 客户端被丢掉时取消：它的连接马上关掉（见 [`DoqMuxClient::watch`]）/ Cancelled when the client is
    /// dropped: its connection closes at once (see [`DoqMuxClient::watch`])
    stop: CancellationToken,
    /// Track whether 0-RTT has been rejected by the server for auto-fallback
    /// 跟踪服务器是否拒绝了 0-RTT，用于自动回退
    /// Once rejected, 0-RTT will be skipped for subsequent connections
    /// 一旦被拒绝，后续连接将跳过 0-RTT
    ///
    /// 同一个上游连接池里的所有连接共用这个标记：一条连接学到的事，其余连接不必再各
    /// 失败一次、各等满一次超时
    /// Shared by every connection in the upstream's pool: what one connection
    /// learned, the others need not each fail and sit out a timeout to learn again
    zero_rtt_rejected: Arc<AtomicBool>,
}

/// 新建的一条 DoQ 连接，和它有没有用 0-RTT / A DoQ connection newly made, and whether it used 0-RTT
struct NewDoqConn {
    conn: QuicConnection,
    used_0rtt: bool,
}

/// 发查询用的连接，和它是怎么来的 / The connection to send on, and how it came
struct DoqConnected {
    pooled: Arc<DoqConn>,
    used_0rtt: bool,
    /// 取自池里，而不是为这次查询新建的 / Taken from the pool rather than made for this query
    reused: bool,
}

/// 池里的一条 QUIC 连接 / One pooled QUIC connection
struct DoqConn {
    conn: QuicConnection,
    /// 建它时用了 0-RTT / Made with 0-RTT
    used_0rtt: bool,
    /// 用它的查询都记上自己的期限，它的看守任务按它老化（见 [`DoqMuxClient::watch`]）/ Every query using it
    /// notes its deadline here, and its watching task ages it by this (see [`DoqMuxClient::watch`])
    wear: Wear,
    /// 在它上面读到过几个回答。查询超时时看这期间涨没涨：涨了说明连接照常在回答，慢的只是这一个，不换连接
    /// Answers read on it. A query timing out looks whether this grew meanwhile: if so the
    /// connection kept answering and only this one is slow, so it is not replaced
    answers: AtomicU64,
}

/// DoQ 连接的传输参数。查询都是我们开的流，一个流问一个（RFC 9250 第 4.2 节），所以：
/// - 上游能开给我们的流是 0。quinn 的 `max_concurrent_bidi/uni_streams` 限的是对端开过来的流，我们从不去接，给了的话
///   上游开过来的流和发来的数据会一直缓冲着；
/// - 每个流的接收窗口正好装下最长的回答（65535 字节加两字节长度前缀），连接的窗口和 DoH 的 HTTP/2 连接一样（见
///   `doh_h2::CONNECTION_WINDOW`）。照 quinn 默认的每个流 1.25 MB、连接不设上限，一个恶意上游能让一条连接缓冲上百 MB；
/// - 不收 QUIC datagram，DoQ 用不着。
///
/// 初始 RTT 定 100 ms，好让拥塞控制一开始估得准一些；`keepalive_interval_ms`、`idle_timeout_secs` 为 0 时不设
/// The transport parameters of a DoQ connection. Every query is a stream we open, one query
/// a stream (RFC 9250 section 4.2), so:
/// - the upstream may open no stream to us. quinn's `max_concurrent_bidi/uni_streams` bound the
///   streams the peer opens, which we never accept, so streams an upstream opened and the data
///   it sent on them would stay buffered;
/// - each stream's receive window holds just the longest answer (65535 bytes and its two-byte
///   length prefix), and the connection's is that of an HTTP/2 DoH connection (see
///   `doh_h2::CONNECTION_WINDOW`). quinn's defaults are 1.25 MB a stream and no bound on the
///   connection, which let a malicious upstream have one connection buffer hundreds of MB;
/// - no QUIC datagram is taken, DoQ has no use for them.
///
/// The initial RTT is 100 ms, for congestion control to start from a better estimate;
/// `keepalive_interval_ms` and `idle_timeout_secs` at 0 leave theirs unset
fn doq_transport(
    keepalive_interval_ms: u64,
    idle_timeout_secs: u64,
) -> anyhow::Result<QuicTransportConfig> {
    let mut transport = QuicTransportConfig::default();
    transport
        .initial_rtt(Duration::from_millis(100))
        .max_concurrent_bidi_streams(0u32.into())
        .max_concurrent_uni_streams(0u32.into())
        .stream_receive_window(quinn::VarInt::from_u32(MAX_DNS_MESSAGE_SIZE as u32 + 2))
        .receive_window(doh_h2::CONNECTION_WINDOW.into())
        .datagram_receive_buffer_size(None);
    if keepalive_interval_ms > 0 {
        transport.keep_alive_interval(Some(Duration::from_millis(keepalive_interval_ms)));
    }
    if idle_timeout_secs > 0 {
        let idle_timeout = Duration::from_secs(idle_timeout_secs)
            .try_into()
            .context("invalid doq idle timeout")?;
        transport.max_idle_timeout(Some(idle_timeout));
    }
    Ok(transport)
}

/// DoQ 连接最长用多久：30 分钟 / How long a DoQ connection may live: 30 minutes
const DOQ_MAX_AGE: Duration = Duration::from_secs(30 * 60);

impl DoqClient {
    /// 只留下 `keep` 认可的上游的连接池（见 [`UpstreamPools::retain`]）/ Keeps only the pools of the
    /// upstreams `keep` accepts (see [`UpstreamPools::retain`])
    pub(crate) fn retain_upstreams(&self, keep: impl Fn(&str) -> bool) {
        self.pools.retain(keep);
    }

    pub fn new(
        pool_size: usize,
        idle_timeout_secs: u64,
        keepalive_interval_ms: u64,
        enable_0rtt: bool,
        bootstrap: Arc<Bootstrap>,
    ) -> anyhow::Result<Self> {
        let mut tls = build_tls_client_config()?;
        tls.alpn_protocols = vec![b"doq".to_vec()];
        tls.enable_early_data = enable_0rtt;

        let quic_crypto = QuicClientConfig::try_from(tls).context("build quic client config")?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));
        client_config.transport_config(Arc::new(doq_transport(
            keepalive_interval_ms,
            idle_timeout_secs,
        )?));

        let mut endpoint_v4 = QuicEndpoint::client("0.0.0.0:0".parse()?)?;
        endpoint_v4.set_default_client_config(client_config.clone());

        let endpoint_v6 = match QuicEndpoint::client("[::]:0".parse()?) {
            Ok(mut ep) => {
                ep.set_default_client_config(client_config);
                ep
            }
            Err(e) => {
                warn!(error = %e, "Failed to bind IPv6 QUIC endpoint, falling back to IPv4 only");
                endpoint_v4.clone()
            }
        };

        let runtime = Arc::new(DoqRuntime {
            endpoint_v4,
            endpoint_v6,
            aging: Aging::new(DOQ_MAX_AGE, Duration::from_secs(idle_timeout_secs)),
            bootstrap,
            enable_0rtt,
            zero_rtt_notice: std::sync::Once::new(),
        });

        Ok(Self {
            pools: UpstreamPools::new(),
            pool_size: pool_size.max(1),
            runtime,
        })
    }

    pub async fn send(
        &self,
        packet: &[u8],
        upstream: &str,
        timeout_dur: Duration,
    ) -> anyhow::Result<Bytes> {
        let pool = self.pools.get_or_create(upstream, |upstream| {
            // 一个池的连接共用对 0-RTT 的了解 / A pool's connections share what they learn about 0-RTT
            let zero_rtt_rejected = Arc::new(AtomicBool::new(false));
            (0..self.pool_size)
                .map(|_| {
                    Arc::new(DoqMuxClient::new(
                        upstream.clone(),
                        Arc::clone(&self.runtime),
                        Arc::clone(&zero_rtt_rejected),
                    ))
                })
                .collect()
        });
        pool.least_busy(|client| client.in_flight.load(Ordering::Relaxed))
            .send(packet, timeout_dur)
            .await
    }
}

/// 客户端被丢掉（它的上游在重载后不在配置里了）时，它的连接马上关掉 / When the client is dropped (its
/// upstream left the configuration on a reload), its connection closes at once
impl Drop for DoqMuxClient {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

impl DoqMuxClient {
    fn new(
        upstream: Arc<str>,
        runtime: Arc<DoqRuntime>,
        zero_rtt_rejected: Arc<AtomicBool>,
    ) -> Self {
        Self {
            upstream,
            target: std::sync::OnceLock::new(),
            pooled: Arc::default(),
            connecting: parking_lot::Mutex::default(),
            in_flight: AtomicUsize::new(0),
            runtime,
            stop: CancellationToken::new(),
            zero_rtt_rejected,
        }
    }

    /// 解析好的上游地址 / The upstream address, parsed
    fn target(&self) -> anyhow::Result<&DoqTarget> {
        if let Some(target) = self.target.get() {
            return Ok(target);
        }
        let target = parse_doq_target(&self.upstream)?;
        anyhow::ensure!(
            !target.host.is_empty(),
            "invalid doq upstream: {}",
            self.upstream
        );
        Ok(self.target.get_or_init(|| target))
    }

    pub async fn send(&self, packet: &[u8], timeout_dur: Duration) -> anyhow::Result<Bytes> {
        let target = self.target()?;
        let _in_flight = InFlight::enter(&self.in_flight);
        self.send_with_retry(target, packet, timeout_dur).await
    }

    async fn send_with_retry(
        &self,
        target: &DoqTarget,
        packet: &[u8],
        timeout_dur: Duration,
    ) -> anyhow::Result<Bytes> {
        // RFC 9250 §4.2.1: DNS Message ID over DoQ MUST be set to 0.
        // We preserve original ID for local correlation and restore it in the final response.
        // RFC 9250 §4.2.1：DoQ 上的 DNS Message ID 必须为 0。
        // 我们保留原始 ID 用于本地关联，并在最终响应中恢复。
        if packet.len() < 2 {
            anyhow::bail!("dns packet too short for doq");
        }
        let original_id = u16::from_be_bytes([packet[0], packet[1]]);

        // 一次查询最多重试一次 / A query is retried at most once
        let mut allow_retry = true;
        let mut timeout_dur = timeout_dur;

        loop {
            let start = tokio::time::Instant::now();
            // 等别的查询连好、解析上游名字、握手和等回答共用这一份预算
            // Waiting for another query's connect, resolving the upstream name, the handshake and
            // the answer share this one budget
            let DoqConnected {
                pooled,
                used_0rtt,
                reused,
            } = match timeout(timeout_dur, self.get_or_connect(target)).await {
                Ok(connected) => connected?,
                Err(_) => {
                    anyhow::bail!("doq connect timeout after {}ms", timeout_dur.as_millis())
                }
            };
            let query_budget = timeout_dur.saturating_sub(start.elapsed());
            if query_budget.is_zero() {
                anyhow::bail!("doq timeout before sending the query");
            }
            pooled.wear.note(start + timeout_dur);
            let answers_before = pooled.answers.load(Ordering::Acquire);

            match timeout(query_budget, Self::ask(&pooled.conn, packet, original_id)).await {
                Ok(Ok(bytes)) => {
                    pooled.answers.fetch_add(1, Ordering::AcqRel);
                    return Ok(bytes);
                }
                Ok(Err(failure)) => {
                    // 连接没了才换；流被重置、回答不合协议是这一个查询的事，连接照用
                    // Only a connection that is gone is replaced; a stream reset or a malformed
                    // answer is this one query's matter, and the connection stays in use
                    let gone = Self::connection_gone(&failure);
                    if gone {
                        forget(&self.pooled, &pooled);
                    }
                    let retry = if !allow_retry {
                        false
                    } else if Self::early_data_refused(&failure)
                        || (used_0rtt
                            && self.zero_rtt_retry_allowed(target)
                            && Self::zero_rtt_likely_rejected(&failure))
                    {
                        self.disable_zero_rtt();
                        warn!(
                            upstream = %self.upstream,
                            error = %failure,
                            "DoQ 0-RTT likely rejected, retrying without 0-RTT"
                        );
                        true
                    } else if reused && gone {
                        // 池里的连接在两次查询之间断了（服务器的空闲超时可能比保活间隔还短），
                        // 这次查询本身没问题：换一条新连接再发一次
                        // The pooled connection died between two queries (a server's
                        // idle timeout can be shorter than our keep-alive interval);
                        // the query itself is fine, so send it again on a fresh one
                        debug!(
                            upstream = %self.upstream,
                            error = %failure,
                            "DoQ pooled connection is gone, retrying on a fresh connection"
                        );
                        true
                    } else {
                        false
                    };
                    if retry && let Some(remaining) = retry_budget(timeout_dur, start) {
                        allow_retry = false;
                        timeout_dur = remaining;
                        continue;
                    }
                    return Err(anyhow::Error::new(failure));
                }
                Err(_) => {
                    // 用了 0-RTT 的连接上超时，算 0-RTT 的嫌疑，往后不再用；普通连接上的超时只是这次回答慢。预算已经
                    // 用完，不再重试
                    // A timeout on a connection that used 0-RTT puts 0-RTT under suspicion, and it
                    // is not used from then on; on a normal connection it is just a slow answer.
                    // The budget is spent, so there is no retry
                    if used_0rtt {
                        self.disable_zero_rtt();
                    }
                    // 这期间连接上没读到过别的回答（多半死了或者卡住了）才换：从池里拿掉、关掉它，和 TCP、DoT 复位连接
                    // 一样。它上面别的查询马上失败，取自池里的按连接没了换一条新连接重发，不用干等到各自的期限
                    // Replaced only when no other answer was read on it meanwhile (it is most likely
                    // dead or stalled): taken out of the pool and closed, as TCP and DoT reset a
                    // connection. The other queries on it fail at once, those that took it from the
                    // pool sent again on a fresh one as for a connection gone, rather than sitting
                    // out their deadlines
                    if pooled.answers.load(Ordering::Acquire) == answers_before {
                        forget(&self.pooled, &pooled);
                        pooled.conn.close(DOQ_NO_ERROR, b"");
                    }
                    return Err(anyhow::anyhow!("doq timeout"));
                }
            }
        }
    }

    /// 在 `conn` 上开一个流问一次（RFC 9250 §4.2）。返回带类型的失败而不是 anyhow：每一步都被 context 包过之后，
    /// anyhow 的 to_string 只剩最外层那一句，quinn 的原始错误到不了判定处
    /// Asks once on a stream of its own on `conn` (RFC 9250 §4.2). It gives a typed failure
    /// rather than anyhow: once every step is wrapped in context, anyhow's to_string leaves only
    /// the outermost sentence and quinn's own error never reaches the decision
    async fn ask(
        conn: &QuicConnection,
        packet: &[u8],
        original_id: u16,
    ) -> Result<Bytes, DoqFailure> {
        let (send, recv) = conn.open_bi().await.map_err(DoqFailure::OpenStream)?;
        let mut stream = DoqStream {
            send,
            recv,
            answered: false,
        };
        let DoqStream {
            send,
            recv,
            answered,
        } = &mut stream;

        // RFC 9250 §4.2: DNS messages sent over QUIC streams MUST be prefixed
        // with a 2-octet length field, followed by the DNS message content.
        // Each query uses a separate bidirectional stream; the message boundary
        // is signalled by FIN.
        // RFC 9250 §4.2: QUIC 流上的 DNS 消息必须使用 2 字节长度前缀，
        // 后跟 DNS 消息内容。每个查询使用单独的双向流；消息边界由 FIN 信号标识。
        //
        // RFC 9250 §4.2.1: DNS Message ID MUST be 0 over DoQ.
        // Build complete wire frame in one allocation, no intermediate copy.
        // RFC 9250 §4.2.1: DoQ 上 DNS Message ID 必须为 0。
        // 单次分配构建完整 wire frame，无中间拷贝。
        let mut frame = Vec::with_capacity(2 + packet.len());
        frame.extend_from_slice(&(packet.len() as u16).to_be_bytes());
        frame.extend_from_slice(packet);
        frame[2] = 0; // Message ID = 0 (RFC 9250 §4.2.1) / 消息 ID = 0
        frame[3] = 0;

        send.write_all(&frame).await.map_err(DoqFailure::Write)?;
        let _ = send.finish();

        // Read response: 2-byte length prefix followed by DNS message
        // 读取响应：2 字节长度前缀，后跟 DNS 消息
        // Note: The server sends the response and closes the stream with FIN
        // We need to read all data until FIN, then parse the length prefix
        // 注意：服务器发送响应后用 FIN 关闭流
        // 我们需要读取所有数据直到 FIN，然后解析长度前缀
        let mut all_data = recv
            .read_to_end(MAX_DNS_MESSAGE_SIZE + 2)
            .await
            .map_err(DoqFailure::Read)?;
        // 上游已经把流结束了：之后不论应答对不对，都不算放弃 / The upstream has ended the stream: whatever
        // the answer, from here on it is no abandoning
        *answered = true;

        if all_data.is_empty() {
            return Err(DoqFailure::Protocol(
                "doq received empty response (server closed stream without sending data)"
                    .to_string(),
            ));
        }

        if all_data.len() < 2 {
            return Err(DoqFailure::Protocol(format!(
                "doq response too short: {} bytes",
                all_data.len()
            )));
        }

        let msg_len = u16::from_be_bytes([all_data[0], all_data[1]]) as usize;

        // idoq-style length validation: response length must match length prefix
        // idoq 风格的长度验证：响应长度必须匹配长度前缀
        if all_data.len() != 2 + msg_len {
            return Err(DoqFailure::Protocol(format!(
                "doq length mismatch: expected {} bytes (2 + {}), got {} bytes. \
                This may indicate data corruption or server protocol violation.",
                2 + msg_len,
                msg_len,
                all_data.len()
            )));
        }

        let buf = &all_data[2..2 + msg_len];
        if buf.len() < 2 {
            // DNS message must be at least 2 bytes for TXID restoration.
            // Also prevents all_data[2..4] index out of bounds when msg_len < 2.
            // DNS 消息必须至少 2 字节才能恢复 TXID。
            // 同时防止 msg_len < 2 时 all_data[2..4] 越界。
            return Err(DoqFailure::Protocol(format!(
                "doq DNS message too short: {msg_len} bytes"
            )));
        }
        // RFC 5452 §9.1, as on the other transports: the answer has to be
        // for this question
        // RFC 5452 §9.1，和别的传输一样：回答必须是这个问题的
        if !crate::proto_utils::answers_query(packet, buf) {
            return Err(DoqFailure::Protocol(
                "doq reply does not answer the query".to_string(),
            ));
        }
        // Restore original DNS Message ID in-place (Vec<u8> is mutable).
        // Bytes::from(Vec) takes ownership of the heap allocation (zero-copy).
        // slice(2..) returns a view past the length prefix (zero-copy, shares allocation).
        // 原地恢复原始 DNS Message ID（Vec<u8> 可变）。
        // Bytes::from(Vec) 接管堆分配（零拷贝）。
        // slice(2..) 返回跳过长度前缀的视图（零拷贝，共享分配）。
        all_data[2..4].copy_from_slice(&original_id.to_be_bytes());
        Ok::<Bytes, DoqFailure>(Bytes::from(all_data).slice(2..))
    }

    /// 池里的连接还能用（没被关掉）就给出来；用旧了的看守任务已经把它从池里拿掉了（见 [`Self::watch`]）
    /// The pooled connection when still usable (not closed); one worn out has been taken out of
    /// the pool by its watching task already (see [`Self::watch`])
    fn usable(&self) -> Option<Arc<DoqConn>> {
        let pooled = self.pooled.load_full()?;
        if let Some(reason) = pooled.conn.close_reason() {
            debug!(upstream = %self.upstream, reason = %reason, "DoQ pooled connection already closed, reconnecting");
            return None;
        }
        Some(pooled)
    }

    /// 发查询用的连接：池里的能用就用，不能用就等一条新的（见 [`Connect::get_or_make`]）：建连的任务建好了放进池里，这个
    /// 查询再取用。等来的连接在取用之前就没了时不再等下一条。等来的连接不算取自池里，用没用 0-RTT 照建它时的
    /// The connection to send on: the pooled one when usable, otherwise a new one waited for (see
    /// [`Connect::get_or_make`]): the connecting task pools it once made, and this query takes it
    /// from there. A connection waited for and gone before it could be taken is not followed by a
    /// wait for another. A connection waited for does not count as taken from the pool, and used
    /// 0-RTT as it was made
    async fn get_or_connect(&self, target: &DoqTarget) -> anyhow::Result<DoqConnected> {
        let connected = |pooled: Arc<DoqConn>, waited: bool| DoqConnected {
            used_0rtt: waited && pooled.used_0rtt,
            reused: !waited,
            pooled,
        };
        if let Some(pooled) = self.usable() {
            return Ok(connected(pooled, false));
        }
        let make = |deadline| {
            let (pool, upstream) = (Arc::clone(&self.pooled), Arc::clone(&self.upstream));
            let (aging, stop) = (self.runtime.aging, self.stop.clone());
            let made = Self::connect_new(
                Arc::clone(&self.runtime),
                Arc::clone(&self.upstream),
                target.clone(),
                self.zero_rtt_retry_allowed(target),
                deadline,
            );
            async move {
                let NewDoqConn { conn, used_0rtt } = made.await?;
                let pooled = Arc::new(DoqConn {
                    conn,
                    used_0rtt,
                    wear: Wear::new(),
                    answers: AtomicU64::new(0),
                });
                pool.store(Some(Arc::clone(&pooled)));
                tokio::spawn(Self::watch(pooled, pool, aging, stop, upstream));
                Ok(())
            }
        };
        let (pooled, waited) =
            Connect::get_or_make(&self.connecting, |connect| connect, |_| self.usable(), make)
                .await?
                .context("doq connection closed as soon as it was made")?;
        Ok(connected(pooled, waited))
    }

    /// 看着池里的一条连接直到它走：关了（上游关的，或者查询判它卡住了关的）就从池里拿掉；用旧了（见 [`Aging`]）也拿掉，
    /// 接着来的查询另建一条，它上面的查询都过了期限再关；客户端被丢掉时马上关。keepalive 让上游看它一直在用，不由这里关的话，
    /// 没人用的连接会一直开着
    /// Watches a pooled connection until it goes: closed (by the upstream, or by a query that
    /// found it stalled), it is taken out of the pool; worn (see [`Aging`]), it is taken out too,
    /// queries coming next make another, and it closes once the queries on it are past their
    /// deadlines; with the client dropped it closes at once. Its keepalive has the upstream see it
    /// in use all along, so a connection nobody uses would stay open were it not closed here
    async fn watch(
        pooled: Arc<DoqConn>,
        pool: Arc<ArcSwapOption<DoqConn>>,
        aging: Aging,
        stop: CancellationToken,
        upstream: Arc<str>,
    ) {
        let worn = tokio::select! {
            () = stop.cancelled() => None,
            _ = pooled.conn.closed() => None,
            why = aging.worn(&pooled.wear) => Some(why),
        };
        forget(&pool, &pooled);
        if let Some(why) = worn {
            info!(upstream = %upstream, why, "DoQ connection worn, closing it once its queries are done");
            tokio::select! {
                () = stop.cancelled() => {}
                _ = pooled.conn.closed() => {}
                () = pooled.wear.settled() => {}
            }
        }
        pooled.conn.close(DOQ_NO_ERROR, b"");
    }

    /// 这次失败是否像 0-RTT 被拒绝，值得关掉 0-RTT 再试一次
    /// Whether this failure looks like a rejected 0-RTT attempt and is worth one
    /// retry with 0-RTT off
    ///
    /// 两类算数：quinn 明确报告 `ZeroRttRejected`；或者连接被对端关闭、重置、
    /// 丢失——服务器拒绝 0-RTT 数据时常常直接关连接，而不是报那个专门的错误。
    /// 本地关闭、超时、协议层面的问题都不算，它们和 0-RTT 无关。
    ///
    /// 纯函数，不吃 `&self`，所以测试可以直接拿 quinn 的错误值驱动它。
    /// Two things count: quinn saying `ZeroRttRejected` outright, and the
    /// connection being closed, reset or lost by the peer, since a server that
    /// refuses 0-RTT data often just closes instead of raising that specific
    /// error. A local close, a timeout and any protocol-level problem do not,
    /// having nothing to do with 0-RTT. It takes no `&self`, so a test can drive
    /// it with real quinn error values.
    fn zero_rtt_likely_rejected(failure: &DoqFailure) -> bool {
        fn peer_ended_it(err: &quinn::ConnectionError) -> bool {
            matches!(
                err,
                quinn::ConnectionError::ApplicationClosed(_)
                    | quinn::ConnectionError::ConnectionClosed(_)
                    | quinn::ConnectionError::Reset
            )
        }

        match failure {
            DoqFailure::OpenStream(err) => peer_ended_it(err),
            DoqFailure::Write(quinn::WriteError::ZeroRttRejected) => true,
            DoqFailure::Write(quinn::WriteError::ConnectionLost(err)) => peer_ended_it(err),
            DoqFailure::Read(quinn::ReadToEndError::Read(err)) => match err {
                quinn::ReadError::ZeroRttRejected => true,
                quinn::ReadError::ConnectionLost(err) => peer_ended_it(err),
                _ => false,
            },
            _ => false,
        }
    }

    /// quinn 明说这个查询发出去的是早期数据、被上游拒收了。只有 0-RTT 期间开的流才会报这个，所以不管这条连接是不是
    /// 这个查询自己建的，它都该换一条不带 0-RTT 的连接再发一次，搭在别的查询建的连接上的也一样
    /// quinn says outright that what this query sent was early data the upstream refused. Only
    /// a stream opened during 0-RTT is told so, and whether or not this query made the
    /// connection it is to be sent again on one without 0-RTT, one riding a connection another
    /// query made included
    fn early_data_refused(failure: &DoqFailure) -> bool {
        matches!(
            failure,
            DoqFailure::Write(quinn::WriteError::ZeroRttRejected)
                | DoqFailure::Read(quinn::ReadToEndError::Read(
                    quinn::ReadError::ZeroRttRejected
                ))
        )
    }

    /// 这次失败是否说明连接本身已经没了（而不是这一次查询出了问题）
    /// Whether this failure means the connection itself is gone, rather than
    /// something being wrong with this one query
    ///
    /// 开流失败、写或读的时候连接丢了，都算；流被对端重置、应答不合协议都不算，
    /// 换连接重发也不会更好。
    /// A failed stream open and a connection lost during the write or the read
    /// count. A stream reset by the peer or a malformed answer do not, as
    /// sending again on another connection would not help.
    fn connection_gone(failure: &DoqFailure) -> bool {
        matches!(
            failure,
            DoqFailure::OpenStream(_)
                | DoqFailure::Write(quinn::WriteError::ConnectionLost(_))
                | DoqFailure::Read(quinn::ReadToEndError::Read(
                    quinn::ReadError::ConnectionLost(_)
                ))
        )
    }

    /// 在这条连接上是否还允许关掉 0-RTT 重试：配置开着、且还没被标记过拒绝
    /// Whether a 0-RTT retry is still allowed here: enabled by configuration and
    /// not already marked as rejected
    fn zero_rtt_retry_allowed(&self, target: &DoqTarget) -> bool {
        target.enable_0rtt.unwrap_or(self.runtime.enable_0rtt)
            && !self.zero_rtt_rejected.load(Ordering::Relaxed)
    }

    /// 给这个上游关掉 0-RTT；查和改是同一步，同时来的几个里只有一个记 warn
    /// Switch 0-RTT off for this upstream; checking and setting is one step, so of
    /// several arriving at once only one logs the warn
    fn disable_zero_rtt(&self) {
        if !self.zero_rtt_rejected.swap(true, Ordering::Relaxed) {
            warn!(
                upstream = %self.upstream,
                "DoQ 0-RTT rejected or unstable, disabling 0-RTT for this upstream until restart"
            );
        }
    }
    /// 建一条到 `target` 的连接，`zero_rtt` 时先试 0-RTT，最晚到建连的期限 `deadline`；连接和用没用 0-RTT。几个地址
    /// 错开着连（见 [`staggered`]），握手失败了马上连下一个 / Connects to `target`, trying 0-RTT first when
    /// `zero_rtt`, by the connect's `deadline`; the connection and whether 0-RTT was used. Several
    /// addresses are connected to staggered (see [`staggered`]), a failed handshake moving on to
    /// the next at once
    async fn connect_new(
        runtime: Arc<DoqRuntime>,
        upstream: Arc<str>,
        target: DoqTarget,
        zero_rtt: bool,
        deadline: tokio::time::Instant,
    ) -> anyhow::Result<NewDoqConn> {
        let mut addresses = runtime
            .bootstrap
            .addresses(&target.host, target.port)
            .await
            .context("doq resolve failed")?;

        // 优先使用 IPv4 地址，避免 IPv6 连接问题
        // Prefer IPv4 addresses to avoid IPv6 connection issues
        // 某些网络的 IPv6 连接不稳定或 MTU 限制导致 QUIC Initial 数据包发送失败
        // Some networks have unstable IPv6 or MTU limits causing QUIC Initial packet send failures
        addresses.sort_by_key(SocketAddr::is_ipv6);
        staggered(addresses, deadline, |address| {
            Self::connect_to(&runtime, &upstream, &target, address, zero_rtt)
        })
        .await
    }

    /// 在 `address` 上建一条到 `target` 的连接（见 [`Self::connect_new`]）/ Connects to `target` at
    /// `address` (see [`Self::connect_new`])
    async fn connect_to(
        runtime: &DoqRuntime,
        upstream: &str,
        target: &DoqTarget,
        address: SocketAddr,
        zero_rtt: bool,
    ) -> anyhow::Result<NewDoqConn> {
        let endpoint = if address.is_ipv6() {
            &runtime.endpoint_v6
        } else {
            &runtime.endpoint_v4
        };
        let connecting = endpoint
            .connect(address, target.sni.as_ref())
            .context("doq connect failed")?;

        // 0-RTT：上游设置优先于全局设置，之前被拒绝过就跳过（见 `zero_rtt_retry_allowed`）
        // 0-RTT: the upstream's setting before the global one, skipped once it was
        // rejected (see `zero_rtt_retry_allowed`)
        let connecting = if zero_rtt {
            // Security warning: 0-RTT (early data) is vulnerable to replay attacks
            // per RFC 8446 §8 and RFC 9001 §5.4. DNS queries are idempotent, so
            // replay impact is limited to redundant lookups and potential cache
            // timing side-channels. Only enable 0-RTT in trusted network environments.
            // The client is built for every configuration, so the notice waits for
            // the first connection that actually offers early data.
            // 安全警告：0-RTT（早期数据）容易受到重放攻击（RFC 8446 §8, RFC 9001 §5.4）。
            // DNS 查询是幂等的，因此重放影响仅限于冗余查询和潜在的缓存时序侧信道。
            // 仅在可信网络环境中启用 0-RTT。客户端在任何配置下都会构造，因此提示
            // 推迟到第一个真正发送早期数据的连接。
            runtime.zero_rtt_notice.call_once(|| {
                tracing::warn!(
                    upstream = %target.host,
                    "DoQ 0-RTT enabled: vulnerable to replay attacks (RFC 8446 §8). \
                     DNS queries are idempotent but an attacker can observe timing patterns. \
                     Disable 0-RTT in untrusted environments."
                );
            });
            match connecting.into_0rtt() {
                Ok((conn, _zero_rtt_accepted)) => {
                    // 0-RTT connection established
                    // Note: Some DoQ servers (e.g., Alibaba DNS) may reject 0-RTT data
                    // If you see timeouts, the system will automatically disable 0-RTT for this upstream
                    // 0-RTT 连接已建立
                    // 注意：某些 DoQ 服务器（如阿里 DNS）可能拒绝 0-RTT 数据
                    // 如果遇到超时，系统将自动为此上游禁用 0-RTT
                    debug!(
                        upstream = %upstream,
                        "DoQ 0-RTT connection established"
                    );
                    return Ok(NewDoqConn {
                        conn,
                        used_0rtt: true,
                    });
                }
                // 0-RTT not available (no previous session), fall back to normal connect
                // 0-RTT 不可用（无先前会话），回退到正常连接
                Err(connecting) => connecting,
            }
        } else {
            connecting
        };

        let connection = connecting.await.context("doq handshake failed")?;

        Ok(NewDoqConn {
            conn: connection,
            used_0rtt: false,
        })
    }
}

/// RFC 9250 第 4.4 节的 DOQ_NO_ERROR：自己关掉连接、没出什么错 / RFC 9250 section 4.4's DOQ_NO_ERROR:
/// the connection closed of our own accord, nothing wrong
const DOQ_NO_ERROR: quinn::VarInt = quinn::VarInt::from_u32(0x0);

/// RFC 9250 第 4.3 节的 DOQ_REQUEST_CANCELLED：客户端不要这个查询的回答了 / RFC 9250 section
/// 4.3's DOQ_REQUEST_CANCELLED: the client no longer wants this query's answer
const DOQ_REQUEST_CANCELLED: quinn::VarInt = quinn::VarInt::from_u32(0x3);

/// 一个 DoQ 查询的那一对流。没等到上游把回答发完就被丢掉（时限到了、几个上游竞速它输了）时，按 RFC 9250
/// 第 4.3.1 节用 [`DOQ_REQUEST_CANCELLED`] 停止接收、重置发送：交给 quinn 丢掉流的话，发出的错误码是 0，
/// 也就是 DOQ_NO_ERROR，上游会当它正常结束
/// The pair of streams of one DoQ query. Dropped before the upstream has finished sending the
/// answer (a deadline that came first, a race between upstreams lost), it stops receiving and
/// resets sending with [`DOQ_REQUEST_CANCELLED`], as RFC 9250 section 4.3.1 asks: streams left
/// for quinn to drop would carry error code 0, DOQ_NO_ERROR, which the upstream takes for a
/// normal end
struct DoqStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    /// 上游已经把回答发完 / The upstream has finished sending the answer
    answered: bool,
}

impl Drop for DoqStream {
    fn drop(&mut self) {
        if !self.answered {
            let _ = self.send.reset(DOQ_REQUEST_CANCELLED);
            let _ = self.recv.stop(DOQ_REQUEST_CANCELLED);
        }
    }
}

#[cfg(test)]
#[path = "doq_tests.rs"]
mod tests;
