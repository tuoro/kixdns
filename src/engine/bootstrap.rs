//! 写成主机名的上游（TCP、DoT、DoH、DoQ）怎样解析成地址。设了 `bootstrap` 时问这些明文 DNS 服务器，用引擎自己的
//! UDP 发送，问到的地址按 TTL 留着；没设时交给系统的解析器。系统的解析器要是 KixDNS 自己，解析上游的名字就绕回来问
//! KixDNS，而它正要问的就是这个上游，所以没设时第一次经系统解析名字就记一条 warn。写成 IP 的上游不用解析
//! How the host names upstreams are written with (TCP, DoT, DoH, DoQ) become addresses. With
//! `bootstrap` set they are asked of those plain DNS servers through the engine's own UDP sending,
//! the addresses kept for their TTL; without it the system resolver has them. Should the system
//! resolver be KixDNS itself, resolving an upstream's name comes back round to KixDNS, which is
//! about to ask that very upstream, so without it the first name the system resolves logs a warn.
//! An upstream written as an IP needs no resolving

use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::Context;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use parking_lot::Mutex;
use rustc_hash::FxHashMap;
use tokio::net::TcpStream;
use tokio::time::Instant;
use tracing::{debug, warn};

use super::transport::UdpClient;

/// 上游主机名的解析：经 `bootstrap` 的服务器，或者系统的解析器 / Resolving upstream host names: through the
/// `bootstrap` servers, or by the system resolver
pub struct Bootstrap {
    /// 设了 `bootstrap` 时问的服务器；None 时交给系统的解析器 / The servers asked with `bootstrap` set;
    /// None leaves it to the system resolver
    through: Option<Through>,
    /// 经系统解析的提示只记一次，等到真有名字要经系统解析时才记 / The notice about the system resolver is
    /// logged once, and only when a name really goes to it
    system_notice: std::sync::Once,
}

/// `bootstrap` 的服务器和从它们问到的地址 / The `bootstrap` servers and the addresses asked of them
struct Through {
    /// `IP:端口`，至少一个 / `IP:port`, one at least
    servers: Box<[Box<str>]>,
    udp: Arc<UdpClient>,
    /// 一次解析最多等多久（`upstream_timeout_ms`）/ How long one resolving waits at most (`upstream_timeout_ms`)
    timeout: Duration,
    /// 每个名字最近一次问到的地址 / The addresses each name was last given
    known: Mutex<FxHashMap<Box<str>, Known>>,
}

/// 一个名字问到的地址，TTL 到 `until` 为止 / The addresses a name was given, their TTL lasting until `until`
#[derive(Clone)]
struct Known {
    /// IPv4 在前 / IPv4 first
    addresses: Arc<[IpAddr]>,
    until: Instant,
}

impl Bootstrap {
    /// `servers` 是 `bootstrap` 的写法：逗号分隔的 `IP:端口`，空的就交给系统的解析器
    /// `servers` as `bootstrap` writes them: comma-separated `IP:port`, none leaving it to the
    /// system resolver
    pub(crate) fn new(servers: &str, udp: Arc<UdpClient>, timeout: Duration) -> Arc<Self> {
        let servers: Box<[Box<str>]> = servers
            .split(',')
            .map(str::trim)
            .filter(|server| !server.is_empty())
            .map(Box::from)
            .collect();
        Arc::new(Self {
            through: (!servers.is_empty()).then(|| Through {
                servers,
                udp,
                timeout,
                known: Mutex::default(),
            }),
            system_notice: std::sync::Once::new(),
        })
    }

    /// 交给系统的解析器的 Bootstrap / A Bootstrap leaving it to the system resolver
    #[cfg(test)]
    pub(crate) fn system() -> Arc<Self> {
        Arc::new(Self {
            through: None,
            system_notice: std::sync::Once::new(),
        })
    }

    /// `host` 在端口 `port` 上的地址；`host` 是 IP 时就是它本身
    /// The addresses of `host` at port `port`; `host` itself when it is an IP
    pub(crate) async fn addresses(&self, host: &str, port: u16) -> anyhow::Result<Vec<SocketAddr>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
        let Some(through) = &self.through else {
            self.system_notice.call_once(|| {
                warn!(
                    host,
                    "upstream host names are resolved by the system resolver; should that be KixDNS itself, resolving one comes back round to KixDNS and the upstream cannot be reached: set bootstrap to plain DNS servers written as IP:port"
                );
            });
            return Ok(tokio::net::lookup_host((host, port))
                .await
                .with_context(|| format!("resolve {host}"))?
                .collect());
        };
        Ok(through
            .lookup(host)
            .await?
            .iter()
            .map(|&ip| SocketAddr::new(ip, port))
            .collect())
    }

    /// 连上写成 `主机:端口` 的地址，几个地址依次试 / Connects to an address written as `host:port`,
    /// trying its addresses in turn
    pub(crate) async fn connect(&self, address: &str) -> anyhow::Result<TcpStream> {
        let addresses = match address.parse::<SocketAddr>() {
            Ok(address) => vec![address],
            Err(_) => {
                let (host, port) = address
                    .rsplit_once(':')
                    .context("expected a host and a port")?;
                self.addresses(host, port.parse().context("invalid port")?)
                    .await?
            }
        };
        Ok(TcpStream::connect(&addresses[..]).await?)
    }
}

impl Through {
    /// `host` 的地址：TTL 没过就用留着的；问不到时用上次问到的，上游的地址很少变，bootstrap 一时答不上来不该连带
    /// 上游连不上
    /// The addresses of `host`: those kept while their TTL lasts; when none can be asked, those
    /// last given, as an upstream's address rarely changes and bootstrap failing to answer for a
    /// moment should not leave the upstream unreachable with it
    async fn lookup(&self, host: &str) -> anyhow::Result<Arc<[IpAddr]>> {
        let known = self.known.lock().get(host).cloned();
        if let Some(known) = &known
            && Instant::now() < known.until
        {
            return Ok(Arc::clone(&known.addresses));
        }
        match self.ask(host).await {
            Ok((addresses, ttl)) => {
                self.known.lock().insert(
                    host.into(),
                    Known {
                        addresses: Arc::clone(&addresses),
                        until: Instant::now() + ttl,
                    },
                );
                Ok(addresses)
            }
            Err(error) => {
                let known = known.ok_or(error)?;
                debug!(
                    host,
                    "bootstrap gave no answer, using the addresses it last gave"
                );
                Ok(known.addresses)
            }
        }
    }

    /// 同时问每个服务器，取先答出地址的那个：地址和它们里最短的 TTL / Asks every server at once and
    /// takes the first to answer with addresses: those and the shortest TTL among them
    async fn ask(&self, host: &str) -> anyhow::Result<(Arc<[IpAddr]>, Duration)> {
        let name = Name::from_ascii(host).with_context(|| format!("invalid host name {host}"))?;
        let query = |record_type| {
            let mut query = Message::new(0, MessageType::Query, OpCode::Query);
            query.metadata.recursion_desired = true;
            query.add_query(Query::query(name.clone(), record_type));
            query.to_vec()
        };
        let (a, aaaa) = (query(RecordType::A)?, query(RecordType::AAAA)?);
        let asked = self
            .servers
            .iter()
            .map(|server| Box::pin(self.ask_server(server, host, &a, &aaaa)));
        let (answer, _) = tokio::time::timeout(self.timeout, futures::future::select_ok(asked))
            .await
            .with_context(|| format!("bootstrap gave no answer for {host} in time"))??;
        Ok(answer)
    }

    /// 向 `server` 问 `host` 的 A 和 AAAA 记录（`a`、`aaaa` 是这两个查询）/ Asks `server` for the A and
    /// AAAA records of `host` (`a` and `aaaa` being those two queries)
    async fn ask_server(
        &self,
        server: &str,
        host: &str,
        a: &[u8],
        aaaa: &[u8],
    ) -> anyhow::Result<(Arc<[IpAddr]>, Duration)> {
        let reply = |query| async move { self.udp.begin(query, server).await?.reply().await };
        let (a, aaaa) = tokio::join!(reply(a), reply(aaaa));
        let mut addresses = Vec::new();
        let mut ttl = u32::MAX;
        for reply in [a?, aaaa?] {
            for record in Message::from_vec(&reply)?.answers {
                let address = match record.data {
                    RData::A(address) => IpAddr::V4(address.0),
                    RData::AAAA(address) => IpAddr::V6(address.0),
                    _ => continue,
                };
                addresses.push(address);
                ttl = ttl.min(crate::proto_utils::received_ttl(record.ttl));
            }
        }
        anyhow::ensure!(!addresses.is_empty(), "{server} gave no address for {host}");
        Ok((addresses.into(), Duration::from_secs(u64::from(ttl))))
    }
}

/// DoH 的两条路各要一种解析器：直连的 TCP 连接器（hyper-util）和 reqwest 接口不同，都交给 [`Bootstrap`]。端口由
/// 它们按 URL 补上
/// The resolver each of DoH's two ways asks for: the direct connection's TCP connector
/// (hyper-util) and reqwest differ in interface, and both go to [`Bootstrap`]. They fill in the
/// port from the URL
#[derive(Clone)]
pub(crate) struct Resolver(pub(crate) Arc<Bootstrap>);

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// `host` 的地址，端口留 0 / The addresses of `host`, the port left at 0
async fn addresses_of(
    bootstrap: Arc<Bootstrap>,
    host: String,
) -> Result<std::vec::IntoIter<SocketAddr>, BoxError> {
    Ok(bootstrap.addresses(&host, 0).await?.into_iter())
}

impl tower_service::Service<hyper_util::client::legacy::connect::dns::Name> for Resolver {
    type Response = std::vec::IntoIter<SocketAddr>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, BoxError>> + Send>>;

    fn poll_ready(&mut self, _: &mut TaskContext<'_>) -> Poll<Result<(), BoxError>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: hyper_util::client::legacy::connect::dns::Name) -> Self::Future {
        Box::pin(addresses_of(Arc::clone(&self.0), name.as_str().to_owned()))
    }
}

impl reqwest::dns::Resolve for Resolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let resolving = addresses_of(Arc::clone(&self.0), name.as_str().to_owned());
        Box::pin(async move { Ok(Box::new(resolving.await?) as reqwest::dns::Addrs) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::test_support::loopback_bootstrap;

    /// 经本机 bootstrap 服务器 `server` 解析的 Bootstrap，一次最多等 300 毫秒 / A Bootstrap resolving
    /// through the local bootstrap server `server`, waiting 300 milliseconds at most each time
    fn through(server: &str) -> Arc<Bootstrap> {
        Bootstrap::new(
            server,
            Arc::new(UdpClient::new(1).expect("UDP client")),
            Duration::from_millis(300),
        )
    }

    /// 问到的地址 IPv4 在前，TTL 没过就不再问；TTL 是 0 的每次都问。写成 IP 的不用问
    /// The addresses given come IPv4 first and are not asked again while their TTL lasts; with a
    /// TTL of 0 each time asks. One written as an IP needs no asking
    #[tokio::test]
    async fn addresses_are_kept_for_their_ttl() {
        let expected = vec![
            "127.0.0.1:853".parse::<SocketAddr>().unwrap(),
            "[::1]:853".parse().unwrap(),
        ];
        for (ttl, queries) in [(300, 2), (0, 4)] {
            let server = loopback_bootstrap(ttl).await;
            let bootstrap = through(&server.address);
            for _ in 0..2 {
                let addresses = bootstrap.addresses("upstream.test", 853).await.unwrap();
                assert_eq!(addresses, expected, "TTL {ttl}");
            }
            assert_eq!(
                server.queries(),
                queries,
                "TTL {ttl}: A and AAAA each time asked"
            );
            assert_eq!(
                bootstrap.addresses("192.0.2.1", 53).await.unwrap(),
                ["192.0.2.1:53".parse().unwrap()]
            );
            assert_eq!(server.queries(), queries, "an IP is not asked about");
        }
    }

    /// bootstrap 不回答时用上次问到的地址，哪怕 TTL 已经过了；从没问到过的名字解析失败
    /// With bootstrap not answering the addresses last given stand in, their TTL past or not; a
    /// name never given any fails to resolve
    #[tokio::test]
    async fn the_last_addresses_stand_in_while_bootstrap_does_not_answer() {
        let server = loopback_bootstrap(0).await;
        let bootstrap = through(&server.address);
        let given = bootstrap.addresses("upstream.test", 853).await.unwrap();
        server.silence(true);
        assert_eq!(
            bootstrap.addresses("upstream.test", 853).await.unwrap(),
            given
        );
        assert!(bootstrap.addresses("other.test", 853).await.is_err());
    }
}
