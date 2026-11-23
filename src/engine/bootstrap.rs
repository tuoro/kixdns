//! 写成主机名的上游（TCP、DoT、DoH、DoQ）怎样解析成地址。设了 `bootstrap` 时问这些明文 DNS 服务器，用引擎自己的
//! UDP 发送；没设时交给系统的解析器，系统的解析器要是 KixDNS 自己，解析上游的名字就绕回来问 KixDNS，而它正要问的就是
//! 这个上游，所以这时配置的 warnings 里说一声（见 `config::warnings`）。问到过的地址马上就用，TTL 过了也照用、同时在
//! 后台再问；只有从没问到过的名字要等。写成 IP 的上游不用解析
//! How the host names upstreams are written with (TCP, DoT, DoH, DoQ) become addresses. With
//! `bootstrap` set they are asked of those plain DNS servers through the engine's own UDP
//! sending; without it the system resolver has them, and should that be KixDNS itself, resolving
//! an upstream's name comes back round to KixDNS, which is about to ask that very upstream, so
//! then the configuration's warnings say so (see `config::warnings`). Addresses once given are
//! used at once, past their TTL too while they are asked again in the background; only a name
//! never given any waits. An upstream written as an IP needs no resolving

use std::net::{IpAddr, SocketAddr};
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::Context;
use futures::FutureExt;
use futures::future::{BoxFuture, Shared};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use parking_lot::Mutex;
use rustc_hash::FxHashMap;
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout};
use tracing::debug;

use super::transport::UdpClient;

/// 问一次 bootstrap 最多等多久。从没问到过的名字，建连要等它问完，而建连一共只有 `transport::CONNECT_BUDGET`
/// （5 秒），剩下的留给 TCP 和 TLS 握手。以前等的是 `upstream_timeout_ms`（默认 9 秒），比整个建连还长：bootstrap
/// 不答时还没轮到用上次的地址，建连就超时了
/// How long one asking of bootstrap waits at most. For a name never given any addresses the
/// connect waits for the asking, and a connect has `transport::CONNECT_BUDGET` (5 seconds) in
/// all, the rest of which the TCP and TLS handshakes need. It used to wait `upstream_timeout_ms`
/// (9 seconds by default), longer than the whole connect: with bootstrap not answering, the
/// connect timed out before the last addresses could stand in
const ASK_BUDGET: Duration = Duration::from_secs(2);

/// A 和 AAAA 有一种先答出了地址，另一种最多再等多久（RFC 8305 §3 的 Resolution Delay）
/// With A or AAAA answered with addresses first, how long the other is waited for at most (the
/// Resolution Delay of RFC 8305 §3)
const RESOLUTION_DELAY: Duration = Duration::from_millis(50);

/// 上游主机名的解析：经 `bootstrap` 的服务器，或者系统的解析器 / Resolving upstream host names: through the
/// `bootstrap` servers, or by the system resolver
pub struct Bootstrap {
    /// 设了 `bootstrap` 时问的服务器；None 时交给系统的解析器 / The servers asked with `bootstrap` set;
    /// None leaves it to the system resolver
    through: Option<Arc<Through>>,
}

/// `bootstrap` 的服务器和从它们问到的地址 / The `bootstrap` servers and the addresses asked of them
struct Through {
    /// `IP:端口`，至少一个 / `IP:port`, one at least
    servers: Box<[Box<str>]>,
    udp: Arc<UdpClient>,
    /// 每个名字问到的地址和正在问的那一次 / Each name's addresses given and its asking under way
    hosts: Mutex<FxHashMap<Box<str>, Host>>,
}

/// 一个名字最近一次问到的地址，和正在问的那一次 / The addresses one name was last given, and its
/// asking under way
#[derive(Default)]
struct Host {
    known: Option<Known>,
    asking: Option<Asking>,
}

/// 一个名字问到的地址，TTL 到 `until` 为止 / The addresses a name was given, their TTL lasting until `until`
struct Known {
    /// IPv4 在前 / IPv4 first
    addresses: Arc<[IpAddr]>,
    until: Instant,
}

/// 问一次的结果，等着它的各拿一份 / One asking's outcome, a copy for each that waits on it
type Asking = Shared<BoxFuture<'static, Result<Arc<[IpAddr]>, Arc<str>>>>;

impl Bootstrap {
    /// `servers` 是 `bootstrap` 的写法：逗号分隔的 `IP:端口`，空的就交给系统的解析器
    /// `servers` as `bootstrap` writes them: comma-separated `IP:port`, none leaving it to the
    /// system resolver
    pub(crate) fn new(servers: &str, udp: Arc<UdpClient>) -> Arc<Self> {
        let servers: Box<[Box<str>]> = servers
            .split(',')
            .map(str::trim)
            .filter(|server| !server.is_empty())
            .map(Box::from)
            .collect();
        Arc::new(Self {
            through: (!servers.is_empty()).then(|| {
                Arc::new(Through {
                    servers,
                    udp,
                    hosts: Mutex::default(),
                })
            }),
        })
    }

    /// 交给系统的解析器的 Bootstrap / A Bootstrap leaving it to the system resolver
    #[cfg(test)]
    pub(crate) fn system() -> Arc<Self> {
        Arc::new(Self { through: None })
    }

    /// `host` 在端口 `port` 上的地址；`host` 是 IP 时就是它本身
    /// The addresses of `host` at port `port`; `host` itself when it is an IP
    pub(crate) async fn addresses(&self, host: &str, port: u16) -> anyhow::Result<Vec<SocketAddr>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
        let Some(through) = &self.through else {
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
    /// `host` 的地址。问到过就马上给：TTL 过了也照给，同时在后台再问一次，问不到就一直用着上次的，上游的地址很少变，
    /// 用不着为它等，bootstrap 一时答不上来也不该连带上游连不上。从没问到过的名字才等，最多 [`ASK_BUDGET`]。一个名字
    /// 同时只问一次，同时要它的都等这一次
    /// The addresses of `host`. Once given they come at once: past their TTL too, while they are
    /// asked again in the background, and the last ones stay in use for as long as no asking
    /// gives others; an upstream's address rarely changes and is not worth a wait, and bootstrap
    /// failing to answer for a moment should not leave the upstream unreachable with it. Only a
    /// name never given any waits, [`ASK_BUDGET`] at most. A name is asked once at a time, and
    /// whatever wants it meanwhile waits on that asking
    async fn lookup(self: &Arc<Self>, host: &str) -> anyhow::Result<Arc<[IpAddr]>> {
        let asking = {
            let mut hosts = self.hosts.lock();
            let entry = hosts.entry(host.into()).or_default();
            match &entry.known {
                Some(known) => {
                    if Instant::now() >= known.until && entry.asking.is_none() {
                        entry.asking = Some(self.ask(host));
                    }
                    return Ok(Arc::clone(&known.addresses));
                }
                None => entry.asking.get_or_insert_with(|| self.ask(host)).clone(),
            }
        };
        asking.await.map_err(anyhow::Error::msg)
    }

    /// 问一次 `host`：在自己的任务里问完，等它的走了也一样，问到的地址记下来（见 [`Host`]）
    /// Asks about `host` once, in a task of its own that finishes whether or not anything still
    /// waits, the addresses given noted down (see [`Host`])
    fn ask(self: &Arc<Self>, host: &str) -> Asking {
        let (through, host) = (Arc::clone(self), Box::<str>::from(host));
        let asking: Asking = async move {
            let asked = timeout(ASK_BUDGET, through.ask_servers(&host))
                .await
                .unwrap_or_else(|_| Err(anyhow::anyhow!("no answer in time")))
                .map_err(|error| {
                    Arc::<str>::from(format!("bootstrap gave no address for {host}: {error:#}"))
                });
            if let Err(error) = &asked {
                debug!(%error, "bootstrap asking failed");
            }
            let mut hosts = through.hosts.lock();
            let entry = hosts.entry(host).or_default();
            entry.asking = None;
            let (addresses, ttl) = asked?;
            entry.known = Some(Known {
                addresses: Arc::clone(&addresses),
                until: Instant::now() + ttl,
            });
            Ok(addresses)
        }
        .boxed()
        .shared();
        tokio::spawn(asking.clone());
        asking
    }

    /// 同时问每个服务器，取先答出地址的那个：地址（IPv4 在前）和它们里最短的 TTL / Asks every server at
    /// once and takes the first to answer with addresses: those (IPv4 first) and the shortest
    /// TTL among them
    async fn ask_servers(&self, host: &str) -> anyhow::Result<(Arc<[IpAddr]>, Duration)> {
        let name = Name::from_ascii(host).context("invalid host name")?;
        let query = |record_type| {
            let mut query = Message::new(0, MessageType::Query, OpCode::Query);
            query.metadata.recursion_desired = true;
            query.add_query(Query::query(name.clone(), record_type));
            query.to_vec()
        };
        let queries = [query(RecordType::A)?, query(RecordType::AAAA)?];
        let asked = self
            .servers
            .iter()
            .map(|server| Box::pin(self.ask_server(server, &queries)));
        let (mut given, _) = futures::future::select_ok(asked).await?;
        given.sort_by_key(|(address, _)| address.is_ipv6());
        let ttl = given
            .iter()
            .fold(u32::MAX, |ttl, &(_, record)| ttl.min(record));
        Ok((
            given.into_iter().map(|(address, _)| address).collect(),
            Duration::from_secs(u64::from(ttl)),
        ))
    }

    /// 向 `server` 问 A 和 AAAA 记录（`queries` 是这两个查询），给出地址和各自的 TTL。一种先答出了地址，
    /// 另一种只是添头：最多再等 [`RESOLUTION_DELAY`]，没答上来、出了错都不要了。以前两种都要答，丢了一个 AAAA 就
    /// 等满整个时限，答了的 A 也一起丢掉
    /// Asks `server` for the A and AAAA records (`queries` being those two queries),
    /// giving the addresses with their TTLs. With one answered with addresses first, the other is
    /// a bonus: waited for [`RESOLUTION_DELAY`] at most, and left out unanswered or failed. Both
    /// used to be needed, so a lost AAAA waited out the whole time limit and threw the A answered
    /// away with it
    async fn ask_server(
        &self,
        server: &str,
        [a, aaaa]: &[Vec<u8>; 2],
    ) -> anyhow::Result<Vec<(IpAddr, u32)>> {
        let (a, aaaa) = (
            pin!(self.records(server, a)),
            pin!(self.records(server, aaaa)),
        );
        let (first, other) = futures::future::select(a, aaaa).await.factor_first();
        let mut given = first?;
        let other = other.into_inner();
        if given.is_empty() {
            given = other.await?;
        } else if let Ok(Ok(more)) = timeout(RESOLUTION_DELAY, other).await {
            given.extend(more);
        }
        anyhow::ensure!(!given.is_empty(), "{server} answered no A or AAAA record");
        Ok(given)
    }

    /// `server` 对 `query` 答的地址和各自的 TTL / The addresses `server` answers `query` with, and their TTLs
    async fn records(&self, server: &str, query: &[u8]) -> anyhow::Result<Vec<(IpAddr, u32)>> {
        let reply = self.udp.begin(query, server).await?.reply().await?;
        Ok(Message::from_vec(&reply)?
            .answers
            .into_iter()
            .filter_map(|record| {
                let address = match record.data {
                    RData::A(address) => IpAddr::V4(address.0),
                    RData::AAAA(address) => IpAddr::V6(address.0),
                    _ => return None,
                };
                Some((address, crate::proto_utils::received_ttl(record.ttl)))
            })
            .collect())
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
    use crate::engine::test_support::{loopback_addresses, loopback_bootstrap, upstream};

    /// 经本机 bootstrap 服务器 `server` 解析的 Bootstrap / A Bootstrap resolving through the
    /// local bootstrap server `server`
    fn through(server: &str) -> Arc<Bootstrap> {
        Bootstrap::new(server, Arc::new(UdpClient::new(1).expect("UDP client")))
    }

    /// 问到的地址 IPv4 在前，TTL 没过就不再问。写成 IP 的不用问
    /// The addresses given come IPv4 first and are not asked again while their TTL lasts. One
    /// written as an IP needs no asking
    #[tokio::test]
    async fn addresses_are_kept_for_their_ttl() {
        let expected = vec![
            "127.0.0.1:853".parse::<SocketAddr>().unwrap(),
            "[::1]:853".parse().unwrap(),
        ];
        let server = loopback_bootstrap(300).await;
        let bootstrap = through(&server.address);
        for _ in 0..2 {
            let addresses = bootstrap.addresses("upstream.test", 853).await.unwrap();
            assert_eq!(addresses, expected);
        }
        assert_eq!(server.queries(), 2, "A and AAAA asked once");
        assert_eq!(
            bootstrap.addresses("192.0.2.1", 53).await.unwrap(),
            ["192.0.2.1:53".parse().unwrap()]
        );
        assert_eq!(server.queries(), 2, "an IP is not asked about");
    }

    /// TTL 过了，上次问到的地址照样马上给，后台再问一次，这期间再来要的不再另问。以前要等这一次问完，bootstrap 不答时
    /// 要等满整个时限
    /// Past their TTL the addresses last given still come at once while they are asked again in
    /// the background, and whatever wants them meanwhile asks nothing more. That asking used to
    /// be waited for, the whole time limit with bootstrap not answering
    #[tokio::test]
    async fn the_last_addresses_come_at_once_while_asked_again() {
        let server = loopback_bootstrap(0).await;
        let bootstrap = through(&server.address);
        let given = bootstrap.addresses("upstream.test", 853).await.unwrap();
        for _ in 0..3 {
            let now = bootstrap.addresses("upstream.test", 853).now_or_never();
            assert_eq!(now.expect("at once").unwrap(), given);
        }
        // 一个新名字的两个查询在后台那次之后发出，答回来时前面的查询都已经到了 / A new name's two queries go
        // after the one in the background, so by the time they are answered every earlier query has arrived
        bootstrap.addresses("other.test", 853).await.unwrap();
        assert_eq!(server.queries(), 6, "asked again once in the background");
    }

    /// bootstrap 不回答时一直用上次问到的地址；从没问到过的名字解析失败
    /// With bootstrap not answering the addresses last given stay in use; a name never given any
    /// fails to resolve
    #[tokio::test]
    async fn the_last_addresses_stand_in_while_bootstrap_does_not_answer() {
        let server = loopback_bootstrap(0).await;
        let bootstrap = through(&server.address);
        let given = bootstrap.addresses("upstream.test", 853).await.unwrap();
        server.silence(true);
        for _ in 0..2 {
            assert_eq!(
                bootstrap.addresses("upstream.test", 853).await.unwrap(),
                given
            );
        }
        assert!(bootstrap.addresses("other.test", 853).await.is_err());
    }

    /// 同时要一个从没问到过的名字，只问一次，都等这一次。以前各问各的
    /// A name never given any, wanted by several at once, is asked once and all wait on that
    /// asking. Each used to ask on its own
    #[tokio::test]
    async fn a_name_wanted_together_is_asked_once() {
        let server = loopback_bootstrap(300).await;
        let bootstrap = through(&server.address);
        let lookups = (0..5).map(|_| bootstrap.addresses("upstream.test", 853));
        for addresses in futures::future::join_all(lookups).await {
            assert_eq!(addresses.unwrap().len(), 2);
        }
        assert_eq!(server.queries(), 2, "A and AAAA asked once");
    }

    /// 只答 A、不答 AAAA 的服务器（或者反过来）给的地址照用，不等丢了的那个。以前两种都要答，等满整个时限后失败
    /// From a server answering A and never AAAA (or the other way round) the addresses it gives
    /// are used without waiting for the one lost. Both used to be needed, failing once the whole
    /// time limit was out
    #[tokio::test]
    async fn one_family_answered_is_enough() {
        for (answered, expected) in [
            (RecordType::A, "127.0.0.1:853"),
            (RecordType::AAAA, "[::1]:853"),
        ] {
            let server = upstream(move |query| {
                if query.queries[0].query_type() == answered {
                    loopback_addresses(query, 300)
                } else {
                    Vec::new()
                }
            })
            .await;
            let addresses = timeout(
                Duration::from_secs(1),
                through(&server.address).addresses("upstream.test", 853),
            )
            .await
            .expect("well within the time limit");
            assert_eq!(
                addresses.unwrap(),
                [expected.parse().unwrap()],
                "{answered} answered"
            );
        }
    }
}
