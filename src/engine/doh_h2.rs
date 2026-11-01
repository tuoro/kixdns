//! DoH 上游的 HTTP/2 连接：握手时选了 h2 的上游，所有请求共用一条连接，直接经 hyper 发出，不过 reqwest
//! 的那几层（请求构造、URL 和 URI 的来回转换、中间件、连接池检出）。连接断了、空闲太久或连续出错重建时，
//! 下一个请求重新连。没选 h2 的上游由调用方照旧交给 reqwest。
//! An HTTP/2 connection to a DoH upstream: an upstream that picked h2 in the handshake has all
//! requests share one connection, sent straight through hyper without reqwest's layers (request
//! building, URL and URI conversions, middleware, pool checkout). When the connection is gone, idle
//! too long or rebuilt after repeated errors, the next request connects again. An upstream that did
//! not pick h2 is handed to reqwest by the caller as before.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::Context;
use arc_swap::ArcSwapOption;
use bytes::Bytes;
use http_body_util::Full;
use hyper::client::conn::http2;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tower_service::Service;
use url::{Host, Url};

/// 请求的发送端 / The sending half requests go through
pub(crate) type H2Sender = http2::SendRequest<Full<Bytes>>;

/// 连接空闲这么久就不再用，和 reqwest 连接池的空闲时限（`pool_idle_timeout`）一样：家用路由器的 NAT 会
/// 悄悄忘掉空闲久了的 TCP 连接，在那样的连接上发的请求只会等到超时
/// A connection idle this long is not used again, the same limit as the reqwest pool's
/// (`pool_idle_timeout`): a home router's NAT quietly forgets TCP connections idle that long,
/// and a request sent on one would only wait for its timeout
pub(crate) const DOH_IDLE_TIMEOUT: Duration = Duration::from_secs(90);

/// 一条打开的连接 / One open connection
struct H2Conn {
    sender: H2Sender,
    /// 最后一次用它时离 `H2Link::epoch` 多少毫秒 / When it was last used, in milliseconds since `H2Link::epoch`
    last_used_ms: AtomicU64,
}

/// 一个 DoH 上游的 HTTP/2 连接 / One DoH upstream's HTTP/2 connection
pub(crate) struct H2Link {
    conn: ArcSwapOption<H2Conn>,
    /// 同一时刻只有一个请求去连，其余的等它连好 / One request connects at a time and the others wait for it
    connecting: tokio::sync::Mutex<()>,
    /// 这个上游握手时没选 h2：之后的请求都交给 reqwest / This upstream did not pick h2 in the handshake: later requests all go to reqwest
    no_h2: AtomicBool,
    epoch: Instant,
    idle_timeout: Duration,
}

impl H2Link {
    pub(crate) fn new(idle_timeout: Duration) -> Self {
        Self {
            conn: ArcSwapOption::empty(),
            connecting: tokio::sync::Mutex::new(()),
            no_h2: AtomicBool::new(false),
            epoch: Instant::now(),
            idle_timeout,
        }
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// 还能用的现有连接：没关、也没空闲太久 / The current connection if it is still usable: not closed and not idle too long
    fn usable(&self, now: u64) -> Option<H2Sender> {
        let conn = self.conn.load_full()?;
        let idle =
            Duration::from_millis(now.saturating_sub(conn.last_used_ms.load(Ordering::Relaxed)));
        if conn.sender.is_closed() || idle >= self.idle_timeout {
            return None;
        }
        conn.last_used_ms.store(now, Ordering::Relaxed);
        Some(conn.sender.clone())
    }

    /// 发请求用的发送端：有能用的连接就用它，没有就连一条。上游没选 h2 时是 None，交给 reqwest
    /// The sender for a request: the current connection when usable, a new one otherwise. None
    /// when the upstream did not pick h2, for reqwest to handle
    pub(crate) async fn sender(
        &self,
        url: &Url,
        tls: &Arc<ClientConfig>,
        connector: &HttpConnector,
    ) -> anyhow::Result<Option<H2Sender>> {
        if self.no_h2.load(Ordering::Relaxed) {
            return Ok(None);
        }
        if let Some(sender) = self.usable(self.now_ms()) {
            return Ok(Some(sender));
        }
        let _connecting = self.connecting.lock().await;
        // 等锁的时候别的请求可能已经连好了 / Another request may have connected while this one waited for the lock
        if let Some(sender) = self.usable(self.now_ms()) {
            return Ok(Some(sender));
        }
        match connect(url, tls, connector).await? {
            Some(sender) => {
                self.conn.store(Some(Arc::new(H2Conn {
                    sender: sender.clone(),
                    last_used_ms: AtomicU64::new(self.now_ms()),
                })));
                Ok(Some(sender))
            }
            None => {
                self.no_h2.store(true, Ordering::Relaxed);
                Ok(None)
            }
        }
    }

    /// 现在有没有一条直连的连接 / Whether a direct connection is open now
    #[cfg(test)]
    pub(crate) fn is_connected(&self) -> bool {
        self.conn
            .load()
            .as_ref()
            .is_some_and(|conn| !conn.sender.is_closed())
    }

    /// 丢掉现有连接：下一个请求重新连，也重新看对方选不选 h2（连续出错重建连接池时用）
    /// Drops the current connection: the next request connects again and looks again whether
    /// the peer picks h2 (used when repeated errors rebuild the pool)
    pub(crate) fn reset(&self) {
        self.conn.store(None);
        self.no_h2.store(false, Ordering::Relaxed);
    }
}

/// 连上 `url`：TCP 走 reqwest 用的同一个连接器（解析域名、IPv6 连不上时退回 IPv4），TLS 握手报 h2 和
/// http/1.1。对方选了 h2 就做 HTTP/2 握手，把连接交给后台任务；没选时是 None
/// Connects to `url`: TCP through the same connector reqwest uses (name resolution, falling
/// back to IPv4 when IPv6 does not connect), a TLS handshake offering h2 and http/1.1. When the
/// peer picks h2 the HTTP/2 handshake follows and a background task drives the connection;
/// otherwise None
async fn connect(
    url: &Url,
    tls: &Arc<ClientConfig>,
    connector: &HttpConnector,
) -> anyhow::Result<Option<H2Sender>> {
    let server_name = match url.host().context("doh url has no host")? {
        Host::Domain(name) => ServerName::try_from(name.to_string()).context("doh server name")?,
        Host::Ipv4(ip) => ServerName::IpAddress(std::net::IpAddr::V4(ip).into()),
        Host::Ipv6(ip) => ServerName::IpAddress(std::net::IpAddr::V6(ip).into()),
    };
    let uri: hyper::Uri = url.as_str().parse().context("doh url as uri")?;
    let tcp = connector
        .clone()
        .call(uri)
        .await
        .map_err(|err| anyhow::anyhow!(err))
        .context("doh connect failed")?
        .into_inner();
    let stream = tokio_rustls::TlsConnector::from(Arc::clone(tls))
        .connect(server_name, tcp)
        .await
        .context("doh tls handshake failed")?;
    if stream.get_ref().1.alpn_protocol() != Some(b"h2") {
        return Ok(None);
    }
    let (sender, conn) = http2::Builder::new(TokioExecutor::new())
        .timer(TokioTimer::new())
        .adaptive_window(true)
        .handshake(TokioIo::new(stream))
        .await
        .context("doh http2 handshake failed")?;
    tokio::spawn(async move {
        if let Err(err) = conn.await {
            tracing::debug!(error = %err, "DoH HTTP/2 connection ended");
        }
    });
    Ok(Some(sender))
}

/// 和 reqwest 默认一样的 TCP 连接器：关 Nagle，不限 http（TLS 由这里接着做），TCP keepalive 15 秒起、
/// 每 15 秒一次、3 次没回就断
/// A TCP connector set up as reqwest's default: Nagle off, any scheme allowed (TLS follows
/// here), TCP keepalive from 15 seconds, every 15 seconds, given up after 3 unanswered
pub(crate) fn tcp_connector() -> HttpConnector {
    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    connector.set_nodelay(true);
    connector.set_keepalive(Some(Duration::from_secs(15)));
    connector.set_keepalive_interval(Some(Duration::from_secs(15)));
    connector.set_keepalive_retries(Some(3));
    connector
}

/// 设了代理环境变量时，reqwest 会让 https 请求走代理（它默认读这些变量）。这里的直连不认代理，所以那时
/// 全部照旧交给 reqwest
/// With a proxy environment variable set, reqwest sends https requests through the proxy (it
/// reads these by default). The direct connection here knows no proxies, so then everything
/// goes to reqwest as before
pub(crate) fn proxy_configured() -> bool {
    proxy_configured_in(|name| std::env::var_os(name))
}

/// [`proxy_configured`]，环境变量从 `var` 读 / [`proxy_configured`] with the environment read through `var`
pub(crate) fn proxy_configured_in(var: impl Fn(&str) -> Option<std::ffi::OsString>) -> bool {
    ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"]
        .iter()
        .any(|name| var(name).is_some_and(|value| !value.is_empty()))
}
