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
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use futures::FutureExt;
use futures::future::{BoxFuture, Shared};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use parking_lot::Mutex;
use rustc_hash::FxHashMap;
use tokio::time::{Instant, timeout, timeout_at};
use tracing::debug;

use super::transport::{UdpClient, UdpExchange};

/// 解析一个名字最多等多久：问 bootstrap 时 A 和 AAAA 同时问，各自最多等这么久；系统的解析器也最多等这么久，到时报
/// `resolve 名字: no answer in 2000ms`。建连要等名字解析完（经 bootstrap 的只有从没问到过的名字要等），而建连一共只有
/// `transport::CONNECT_BUDGET`（5 秒），剩下的留给 TCP 和 TLS 握手
/// How long resolving one name waits at most: asking bootstrap, A and AAAA are asked at once,
/// each waited for this long at most; the system resolver is waited for this long at most too,
/// `resolve name: no answer in 2000ms` coming then. A connect waits for its name to be resolved
/// (through bootstrap only a name never given any addresses waits), and a connect has
/// `transport::CONNECT_BUDGET` (5 seconds) in all, the rest of which the TCP and TLS handshakes
/// need
const ASK_BUDGET: Duration = Duration::from_secs(2);

/// 一族地址（A 或 AAAA）这次没问到时，多久之后再问（见 [`Known::new`]）。这时这一族要么没有地址（头一回问），要么是上回
/// 问到的；在只连得上一族的主机上（比如 IPv6 只有 ULA），少了能连的那一族上游就连不上，所以要短。也不必更短：解析器把一次
/// 失败至少记 1 秒（RFC 9520 3.2），它举的例子从 5 秒起退避，再早问多半拿回同一个失败。再问在后台，最多 [`ASK_BUDGET`]，
/// 谁也不等它，有建连要地址时才问，一个名字每 10 秒至多问一次：A、AAAA 各问每个服务器，每个至多发三份（见
/// [`Through::records`]），也就是至多 6 × 服务器数个查询，所以不退避：一族一直问不到（AAAA 查询被丢掉的网络）也就这点开销。
/// 问到过地址的名字后来一个地址也问不到（比如两族都答 NXDOMAIN）时也一样，留着上回的地址，这么久以后再问
/// How long until a family of addresses (A or AAAA) not given this time is asked again (see
/// [`Known::new`]). Until then that family has no addresses (asked the first time) or those last
/// given; on a host reaching one family only (IPv6 with ULA only, say), the upstream cannot be
/// reached without the family it can reach, so this is short. Nor is shorter any use: a resolver
/// holds a failure for 1 second at least (RFC 9520 3.2), its example backing off from 5 seconds,
/// and asking sooner would mostly get the same failure back. Asking again is in the background,
/// [`ASK_BUDGET`] at most, nothing waiting on it, and only when a connect wants addresses, once
/// per name per 10 seconds at most: A and AAAA asked of every server, three copies each at most
/// (see [`Through::records`]), so 6 × the servers' number of queries at most, and there is no
/// backing off: a family never given (a network dropping AAAA queries) costs no more than that.
/// A name once given addresses that later gets none at all (both families answering NXDOMAIN,
/// say) is no different, keeping the last addresses and asked again after this long
const ASK_AGAIN_AFTER: Duration = Duration::from_secs(10);

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

/// 一个名字问到的地址，到 `until` 再问 / The addresses a name was given, asked again at `until`
struct Known {
    /// IPv4 在前 / IPv4 first
    addresses: Arc<[IpAddr]>,
    until: Instant,
}

impl Known {
    /// 这次问到的两族（`asked`，A 在前）。没问到的那一族沿用 `last` 里这一族的地址，[`ASK_AGAIN_AFTER`] 之后再问；
    /// 问到了的那一族（没有这一族的记录也算问到）用这次的地址，按它们里最短的 TTL。这样凑不出一个地址时（两族都没有记录，
    /// 或者没问到的那一族上回也没有地址），整张沿用 `last`，同样 [`ASK_AGAIN_AFTER`] 之后再问。头一回问和后台再问都是这一条：
    /// 头一回没有 `last`，没问到的那一族就先没有地址，一个地址也没有时是 Err
    /// What this asking gave of the two families (`asked`, A first). A family not given keeps the
    /// addresses `last` has of it, asked again after [`ASK_AGAIN_AFTER`]; a family given (no
    /// record of it counting as given) takes this asking's addresses, by the shortest TTL among
    /// them. Coming to no address so (neither family having records, or the one not given having
    /// none last time either), all of `last` is kept, asked again after [`ASK_AGAIN_AFTER`] too.
    /// Asking the first time and asking again in the background are the one rule: the first time
    /// has no `last`, a family not given then having no addresses for now, and no address at all
    /// is an Err
    fn new(asked: [Family; 2], last: Option<&Known>) -> anyhow::Result<Self> {
        let (mut addresses, mut ttl, mut failures) = (Vec::new(), Duration::MAX, Vec::new());
        for (family, ipv6) in asked.into_iter().zip([false, true]) {
            match family {
                Ok(given) => {
                    for (address, record) in given {
                        addresses.push(address);
                        ttl = ttl.min(Duration::from_secs(u64::from(record)));
                    }
                }
                Err(error) => {
                    let last = last.map_or(&[][..], |last| &last.addresses[..]);
                    addresses.extend(last.iter().filter(|address| address.is_ipv6() == ipv6));
                    ttl = ttl.min(ASK_AGAIN_AFTER);
                    failures.push(format!("{error:#}"));
                }
            }
        }
        if addresses.is_empty() {
            if let Some(last) = last {
                return Ok(Self {
                    addresses: Arc::clone(&last.addresses),
                    until: Instant::now() + ASK_AGAIN_AFTER,
                });
            }
            let why = match failures.is_empty() {
                true => "no A or AAAA record".to_owned(),
                false => failures.join("; "),
            };
            anyhow::bail!(why);
        }
        // 有地址时 ttl 已不是 Duration::MAX：地址要么来自一条记录，要么来自没问到的一族 / With addresses ttl is no
        // longer Duration::MAX: each comes from a record or from a family not given
        Ok(Self {
            addresses: addresses.into(),
            until: Instant::now() + ttl,
        })
    }
}

/// 一族地址这次问到的样子：地址和各自的 TTL（空的是没有这一族的记录）；Err 是没问到：每个服务器都出了错、答了失败应答
/// （见 `upstream::is_failure_reply`）、到时没答上或者查询发不出去
/// What one family of addresses came to this time: the addresses with their TTLs (none being no
/// record of the family); Err when not given: every server failing, answering with a failure
/// reply (see `upstream::is_failure_reply`), not answering in time or never sent the query
type Family = anyhow::Result<Vec<(IpAddr, u32)>>;

/// 问一次的结果，等着它的各拿一份 / One asking's outcome, a copy for each that waits on it
type Asking = Shared<BoxFuture<'static, Result<Arc<[IpAddr]>, NoAddress>>>;

/// bootstrap 没给出一个名字的地址：为什么，和是不是 DNS 里就没有它的地址 / Bootstrap giving no address
/// for a name: why, and whether DNS has no address for it at all
#[derive(Clone, Debug)]
struct NoAddress {
    why: Arc<str>,
    /// 两族都答了、都没有记录（比如 NXDOMAIN），而不是没问到（见 [`Family`]）/ Both families answered with no
    /// record (NXDOMAIN, say), rather than not given (see [`Family`])
    not_in_dns: bool,
}

impl std::fmt::Display for NoAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.why)
    }
}

impl std::error::Error for NoAddress {}

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
            return system_addresses(host, port).await;
        };
        Ok(through
            .lookup(host)
            .await?
            .iter()
            .map(|&ip| SocketAddr::new(ip, port))
            .collect())
    }
}

/// 系统的解析器给的 `host` 在端口 `port` 上的地址，最多等 [`ASK_BUDGET`] / The addresses of `host`
/// at port `port` from the system resolver, waited for [`ASK_BUDGET`] at most
async fn system_addresses(host: &str, port: u16) -> anyhow::Result<Vec<SocketAddr>> {
    let resolved = timeout(ASK_BUDGET, tokio::net::lookup_host((host, port)))
        .await
        .map_err(|_| {
            anyhow::anyhow!("resolve {host}: no answer in {}ms", ASK_BUDGET.as_millis())
        })?;
    Ok(resolved
        .with_context(|| format!("resolve {host}"))?
        .collect())
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
        asking.await.map_err(anyhow::Error::new)
    }

    /// 问一次 `host`：在自己的任务里问完，等它的走了也一样，问到的地址记下来（见 [`Host`]）
    /// Asks about `host` once, in a task of its own that finishes whether or not anything still
    /// waits, the addresses given noted down (see [`Host`])
    fn ask(self: &Arc<Self>, host: &str) -> Asking {
        let (through, host) = (Arc::clone(self), Box::<str>::from(host));
        let asking: Asking = async move {
            let asked = through.ask_servers(&host).await;
            let not_in_dns =
                matches!(&asked, Ok([Ok(a), Ok(aaaa)]) if a.is_empty() && aaaa.is_empty());
            let mut hosts = through.hosts.lock();
            let entry = hosts.entry(host.clone()).or_default();
            entry.asking = None;
            let known = asked
                .and_then(|asked| Known::new(asked, entry.known.as_ref()))
                .map_err(|error| NoAddress {
                    why: format!("bootstrap gave no address for {host}: {error:#}").into(),
                    not_in_dns,
                })?;
            let addresses = Arc::clone(&known.addresses);
            entry.known = Some(known);
            Ok(addresses)
        }
        .boxed()
        .shared();
        tokio::spawn(asking.clone());
        asking
    }

    /// 问 `host` 的两族地址（A 在前）：两族同时问、都等到答上，晚答上的照样记下；每族同时问每个服务器，取先答上的那个，
    /// 各自最多等 [`ASK_BUDGET`]。一族没问到不连累另一族（见 [`Family`]），记一条 debug
    /// Asks for the two families of addresses of `host` (A first): both are asked at once and each
    /// is waited for until answered, one answered late kept all the same; each family is asked of
    /// every server at once, the first to answer taken, [`ASK_BUDGET`] at most each. A family not
    /// given never costs the other (see [`Family`]), and is logged at debug
    async fn ask_servers(&self, host: &str) -> anyhow::Result<[Family; 2]> {
        let name = Name::from_ascii(host).context("invalid host name")?;
        let family = |record_type| {
            let name = name.clone();
            async move {
                let mut query = Message::new(0, MessageType::Query, OpCode::Query);
                query.metadata.recursion_desired = true;
                query.add_query(Query::query(name, record_type));
                let given = self
                    .first_answer(&query.to_vec()?)
                    .await
                    .with_context(|| record_type.to_string());
                if let Err(error) = &given {
                    debug!(host, error = %format_args!("{error:#}"), "bootstrap asking failed");
                }
                given
            }
        };
        let (a, aaaa) =
            futures::future::join(family(RecordType::A), family(RecordType::AAAA)).await;
        Ok([a, aaaa])
    }

    /// 同时向每个服务器问 `query`，先答上的那个的回答（见 [`Self::records`]，各自最多 [`ASK_BUDGET`]）。都没答上时
    /// 按先后列出每个服务器为什么没答上
    /// `query` asked of every server at once, the answer of the first to answer (see
    /// [`Self::records`], [`ASK_BUDGET`] at most each). With none answering, why each did not is
    /// listed, in the order they failed
    async fn first_answer(&self, query: &[u8]) -> anyhow::Result<Vec<(IpAddr, u32)>> {
        use futures::StreamExt;
        let mut asked: futures::stream::FuturesUnordered<_> = self
            .servers
            .iter()
            .map(|server| self.records(server, query))
            .collect();
        let mut failed = Vec::new();
        while let Some(answer) = asked.next().await {
            match answer {
                Ok(given) => return Ok(given),
                Err(error) => failed.push(format!("{error:#}")),
            }
        }
        anyhow::bail!("{}", failed.join(", "))
    }

    /// `server` 对 `query` 答的地址和各自的 TTL；答了失败应答（见 `upstream::is_failure_reply`）是 Err，和答了没有这种
    /// 记录（空的）分开。一份查询过了这次问的时限（[`ASK_BUDGET`]）的三分之一还没有回答就再发一份，和还没答过的上游一样
    /// （见 `upstream::hedge_timeout`）；前面发的照样等着，谁的回答先到用谁的（见 [`UdpExchange`]）：丢了一个包的查询
    /// 不用等满整个时限。一份发不出去也不让这次问失败，记下来，到了再发的时候照样再发，直到时限。UDP 转发（见
    /// `upstream::forward_udp_smart`）不一样：它一共只发两份，第一份发不出去就马上发第二份；这里一直按间隔再发，发不出去
    /// 时马上再发只会空转。到了时限还没有回答：发出去过的报 `no answer in 2000ms`，一份也没发出去的报最后一次为什么没发出去
    /// （`query not sent: …`），比如没有到这个服务器的路由
    /// The addresses `server` answers `query` with, and their TTLs; Err for a failure reply (see
    /// `upstream::is_failure_reply`), told apart from an answer with no such record (none). A copy
    /// left unanswered for a third of the asking's time limit ([`ASK_BUDGET`]) has another sent,
    /// as for an upstream yet to answer (see `upstream::hedge_timeout`); the earlier ones are
    /// still waited for, the first reply to come being used (see [`UdpExchange`]): a query with a
    /// packet lost does not wait out the whole limit. Nor does a copy that cannot be sent fail the
    /// asking: it is logged, and another goes when the time to send again comes, up to the time
    /// limit. UDP forwarding (see `upstream::forward_udp_smart`) differs: it sends two copies in
    /// all, the second at once when the first cannot be sent; here copies keep going at the
    /// interval, and sending again at once while sending fails would only spin. With no answer by
    /// the time limit, one with a copy sent reports `no answer in 2000ms`, and one with none sent
    /// why the latest could not go (`query not sent: …`), no route to the server, say
    async fn records(&self, server: &str, query: &[u8]) -> anyhow::Result<Vec<(IpAddr, u32)>> {
        let deadline = Instant::now() + ASK_BUDGET;
        let resend_after = super::upstream::hedge_timeout(ASK_BUDGET);
        let mut exchange = UdpExchange::new(&self.udp, query, server);
        // 发出去过一份没有，和最后一次发不出去的原因 / Whether any copy went out, and why the latest
        // could not
        let (mut sent, mut not_sent) = (false, None);
        let reply = loop {
            match exchange.send(()).await {
                Ok(()) => sent = true,
                Err(error) => {
                    debug!(server, %error, "bootstrap query not sent, sending again later");
                    not_sent = Some(error);
                }
            }
            let resend_at = (Instant::now() + resend_after).min(deadline);
            match timeout_at(resend_at, exchange.reply()).await {
                Ok(Some((reply, ()))) => break reply?,
                // 一份也没在等（都没发出去）：到了时候再发 / No copy waited for (none went out): another goes
                // when the time comes
                Ok(None) => tokio::time::sleep_until(resend_at).await,
                Err(_) => {}
            }
            if Instant::now() >= deadline {
                return Err(match not_sent {
                    Some(error) if !sent => anyhow::anyhow!("{server}: query not sent: {error:#}"),
                    _ => anyhow::anyhow!("{server}: no answer in {}ms", ASK_BUDGET.as_millis()),
                });
            }
        };
        let reply = Message::from_vec(&reply)?;
        let rcode = reply.metadata.response_code;
        anyhow::ensure!(
            !super::upstream::is_failure_reply(rcode),
            "{server} answered {}",
            crate::observe::rcode_name(rcode.into())
        );
        Ok(reply
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

/// reqwest 用的解析器，端口由 reqwest 按 URL 补上：上游的主机名交给 [`Bootstrap`]，代理的主机名（`proxies`）见
/// [`proxy_addresses`]。reqwest 经代理连上游时只在本机解析代理（上游的名字在 CONNECT 里由代理解析）；NO_PROXY 里的上游
/// reqwest 直连，照常经 [`Bootstrap`] 解析
/// The resolver reqwest uses, the port filled in by reqwest from the URL: upstream host names go
/// to [`Bootstrap`], and for the proxies' host names (`proxies`) see [`proxy_addresses`].
/// Connecting through a proxy, reqwest resolves only the proxy here (the upstream's name, in the
/// CONNECT, the proxy resolves); an upstream in NO_PROXY reqwest connects to directly, resolved
/// through [`Bootstrap`] as usual
#[derive(Clone)]
pub(crate) struct Resolver {
    /// 上游的主机名怎样解析，直连的 DoH 也用它 / How upstream host names are resolved, by direct DoH too
    pub(crate) bootstrap: Arc<Bootstrap>,
    /// 代理环境变量里写的代理主机名（见 `doh_h2::proxy_hosts`）/ The proxies' host names the proxy
    /// environment variables write (see `doh_h2::proxy_hosts`)
    proxies: Arc<[Box<str>]>,
}

impl Resolver {
    pub(crate) fn new(bootstrap: Arc<Bootstrap>, proxies: impl Into<Arc<[Box<str>]>>) -> Self {
        Self {
            bootstrap,
            proxies: proxies.into(),
        }
    }
}

impl reqwest::dns::Resolve for Resolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_owned();
        let proxy = self
            .proxies
            .iter()
            .any(|proxy| proxy.eq_ignore_ascii_case(&host));
        let bootstrap = Arc::clone(&self.bootstrap);
        Box::pin(async move {
            let addresses = match proxy {
                true => proxy_addresses(&bootstrap, &host).await?,
                false => bootstrap.addresses(&host, 0).await?,
            };
            Ok(Box::new(addresses.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// 代理 `host` 的地址（端口由 reqwest 补上）。和上游的名字一样经 `bootstrap`：系统的解析器是 KixDNS 自己、KixDNS 又要经
/// 这个代理才问得到它的地址时，问系统就绕回来，每条新连接都要等满 [`ASK_BUDGET`] 才失败。bootstrap 的服务器答了 DNS 里没有
/// 它的地址时（见 [`NoAddress`]），它是本机或局域网自己的名字：hosts 文件里的、mDNS 的、局域网 DNS 的，或者靠搜索域补全的
/// 单个标签，只有系统的解析器认得，交给它。没问到（到时没答上、只答了失败应答）照样是错误，不转给系统的解析器：它可能就是
/// KixDNS 自己。没设 bootstrap 时 `bootstrap` 本来就交给系统的解析器
/// The addresses of the proxy `host` (the port filled in by reqwest). They go through `bootstrap`
/// as upstream names do: with the system resolver KixDNS itself and KixDNS reaching that proxy's
/// address only through the proxy, asking the system comes back round, and every new connection
/// fails only once it has waited out [`ASK_BUDGET`]. With the bootstrap servers answering that
/// DNS has no address for it (see [`NoAddress`]), it is a name of the host's or the LAN's own: one
/// from the hosts file, mDNS or the LAN's DNS, or a single label completed by the search domains,
/// which only the system resolver knows, and it goes there. Not given (unanswered in time, or
/// answered with failure replies alone), it is an error all the same, not passed on to the system
/// resolver, which may be KixDNS itself. With bootstrap unset, `bootstrap` leaves it to the system
/// resolver anyway
async fn proxy_addresses(bootstrap: &Bootstrap, host: &str) -> anyhow::Result<Vec<SocketAddr>> {
    match bootstrap.addresses(host, 0).await {
        Err(error)
            if error
                .downcast_ref::<NoAddress>()
                .is_some_and(|no| no.not_in_dns) =>
        {
            system_addresses(host, 0).await
        }
        given => given,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::test_support::{Replies, loopback_addresses, loopback_bootstrap, upstream};
    use hickory_proto::op::ResponseCode;

    /// 经本机 bootstrap 服务器 `server` 解析的 Bootstrap / A Bootstrap resolving through the
    /// local bootstrap server `server`
    fn through(server: &str) -> Arc<Bootstrap> {
        Bootstrap::new(server, Arc::new(UdpClient::new(1).expect("UDP client")))
    }

    /// `host` 正在问的那一次 / The asking of `host` under way
    fn asking(bootstrap: &Bootstrap, host: &str) -> Option<Asking> {
        let through = bootstrap
            .through
            .as_ref()
            .expect("through bootstrap servers");
        through.hosts.lock().get(host)?.asking.clone()
    }

    /// 对 `query` 答 `rcode`、不带记录；NOERROR 就是有这个名字、没有这种记录
    /// Answers `query` with `rcode` and no records; with NOERROR the name is there, with no
    /// record of this type
    fn no_records(query: &Message, rcode: ResponseCode) -> Replies {
        let mut reply = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
        reply.metadata.response_code = rcode;
        reply.add_query(query.queries[0].clone());
        vec![(Duration::ZERO, reply.to_vec().unwrap())]
    }

    /// 时间往前拨 `by` / Moves the clock on by `by`
    async fn later_by(by: Duration) {
        tokio::time::pause();
        tokio::time::advance(by).await;
        tokio::time::resume();
    }

    /// reqwest 经代理连上游时只在本机解析代理，代理的主机名和上游的一样问 bootstrap：系统的解析器是 KixDNS 自己、KixDNS
    /// 又要经这个代理才问得到它时，问系统会绕回来。`proxy.test` 是代理（大小写不论），只有本机的 bootstrap 服务器认得，
    /// 它给的环回地址就是代理的地址。以前代理的名字一律交给系统的解析器
    /// Through a proxy reqwest resolves only the proxy here, and the proxy's host name is asked of
    /// bootstrap as an upstream's is: with the system resolver KixDNS itself and KixDNS reaching
    /// the proxy only through it, asking the system comes back round. `proxy.test` being the proxy
    /// (in any case), known to the local bootstrap server alone, the loopback addresses it gives
    /// are the proxy's. The proxy's name used to go to the system resolver whatever happened
    #[tokio::test]
    async fn a_proxy_is_resolved_through_bootstrap() {
        use reqwest::dns::Resolve;
        let server = loopback_bootstrap(300).await;
        let resolver = Resolver::new(through(&server.address), vec![Box::from("proxy.test")]);
        let resolve = |name: &str| resolver.resolve(name.parse().expect("a host name"));
        let loopback: Vec<SocketAddr> =
            vec!["127.0.0.1:0".parse().unwrap(), "[::1]:0".parse().unwrap()];
        for name in ["Proxy.Test", "upstream.test"] {
            let addresses: Vec<SocketAddr> = resolve(name)
                .await
                .unwrap_or_else(|error| panic!("{name}: {error}"))
                .collect();
            assert_eq!(addresses, loopback, "{name}");
        }
        assert_eq!(server.queries(), 4, "A and AAAA of each asked of bootstrap");
    }

    /// bootstrap 答了 DNS 里没有代理的地址（NXDOMAIN、两族都没有记录）时，它是本机或局域网自己的名字，交给系统的解析器：
    /// `localhost` 由系统解析出环回地址。没问到（只答了 SERVFAIL）照样失败，不转给系统的解析器，它可能就是 KixDNS 自己
    /// With bootstrap answering that DNS has no address for the proxy (NXDOMAIN, or no record of
    /// either family), it is a name of the host's or the LAN's own and goes to the system
    /// resolver: `localhost` gets loopback addresses from the system. Not given (SERVFAIL alone),
    /// it fails all the same, not passed on to the system resolver, which may be KixDNS itself
    #[tokio::test]
    async fn a_proxy_not_in_dns_is_left_to_the_system_resolver() {
        use reqwest::dns::Resolve;
        for rcode in [
            ResponseCode::NXDomain,
            ResponseCode::NoError,
            ResponseCode::ServFail,
        ] {
            let server = upstream(move |query| no_records(query, rcode)).await;
            let resolver = Resolver::new(through(&server.address), vec![Box::from("localhost")]);
            let resolved = resolver.resolve("localhost".parse().unwrap()).await;
            assert_eq!(
                server.queries(),
                2,
                "{rcode}: A and AAAA asked of bootstrap"
            );
            match rcode {
                ResponseCode::ServFail => {
                    let error = resolved.err().expect("not given by bootstrap");
                    assert!(
                        error
                            .to_string()
                            .starts_with("bootstrap gave no address for localhost"),
                        "{error}"
                    );
                }
                _ => {
                    let addresses: Vec<SocketAddr> = resolved
                        .unwrap_or_else(|error| panic!("{rcode}: {error}"))
                        .collect();
                    assert!(
                        !addresses.is_empty()
                            && addresses.iter().all(|address| address.ip().is_loopback()),
                        "{rcode}: {addresses:?}"
                    );
                }
            }
        }
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

    /// 只有 IPv4 的名字，服务器没收到第一份 A 查询（包丢在了路上）：过了时限的三分之一再发一份，照样问到，用不着等满
    /// 整个时限
    /// A name with IPv4 only whose first A query never reached the server (the packet lost on the
    /// way): another copy goes after a third of the time limit and is answered, well within the
    /// whole limit
    #[tokio::test]
    async fn a_query_lost_on_the_way_is_sent_again() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let asked_a = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&asked_a);
        let server = upstream(move |query| {
            if query.queries[0].query_type() != RecordType::A {
                return no_records(query, ResponseCode::NoError);
            }
            if counted.fetch_add(1, Ordering::SeqCst) == 0 {
                return Vec::new();
            }
            loopback_addresses(query, 300)
        })
        .await;
        let addresses = timeout(
            Duration::from_millis(1500),
            through(&server.address).addresses("upstream.test", 853),
        )
        .await
        .expect("well within the time limit");
        assert_eq!(addresses.unwrap(), ["127.0.0.1:853".parse().unwrap()]);
        assert_eq!(asked_a.load(Ordering::SeqCst), 2, "sent once more");
    }

    /// 一份查询发不出去（这里是 socket 的 ID 一时都被占着）不让这次问失败：到了再发的时候照样再发一份，问到地址
    /// A query that cannot be sent (every ID of the socket taken for a moment, here) does not fail
    /// the asking: another copy goes when the time to send again comes, and is answered
    #[tokio::test]
    async fn a_query_that_cannot_be_sent_is_sent_again_later() {
        let server = loopback_bootstrap(300).await;
        let udp = Arc::new(UdpClient::new(1).expect("UDP client"));
        let bootstrap = Bootstrap::new(&server.address, Arc::clone(&udp));
        udp.hold_every_id_for_tests();
        let asking = tokio::spawn(async move { bootstrap.addresses("upstream.test", 853).await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        udp.free_ids_for_tests();
        let addresses = timeout(Duration::from_millis(1500), asking)
            .await
            .expect("well within the time limit")
            .expect("the asking task");
        assert_eq!(addresses.unwrap().len(), 2);
    }

    /// 到了时限还没有回答的服务器，和查询根本没发出去的分开报：发出去过的是「no answer in 2000ms」，一份也没发出去的说
    /// 最后一次为什么没发出去（这里是 socket 的 ID 都被占着；常见的是 IPv6 的 bootstrap 服务器在没有 IPv6 路由的机器上）
    /// A server with no answer by the time limit is told from one never sent the query: one with a
    /// copy sent is "no answer in 2000ms", one with none sent says why the latest could not go
    /// (every ID of the socket taken, here; an IPv6 bootstrap server on a host with no IPv6 route,
    /// commonly)
    #[tokio::test]
    async fn a_server_not_answering_is_told_from_one_never_asked() {
        let silent = upstream(|_| Vec::new()).await;
        let unasked = loopback_bootstrap(300).await;
        let udp = Arc::new(UdpClient::new(1).expect("UDP client"));
        udp.hold_every_id_for_tests();
        let (silent_err, unasked_err) = futures::future::join(
            through(&silent.address).addresses("upstream.test", 853),
            Bootstrap::new(&unasked.address, udp).addresses("upstream.test", 853),
        )
        .await;
        let silent_err = format!("{:#}", silent_err.expect_err("no answer"));
        let no_answer = format!("{}: no answer in 2000ms", silent.address);
        assert_eq!(silent_err.matches(&no_answer).count(), 2, "{silent_err}");
        let unasked_err = format!("{:#}", unasked_err.expect_err("never asked"));
        let not_sent = format!("{}: query not sent: udp pool exhausted", unasked.address);
        assert_eq!(unasked_err.matches(&not_sent).count(), 2, "{unasked_err}");
        assert_eq!(unasked.queries(), 0, "nothing reached the server");
    }

    /// 只答 A、不答 AAAA 的服务器（或者反过来）给的地址照用：不答的那种等到时限就不等了，这次问不因它失败
    /// From a server answering A and never AAAA (or the other way round) the addresses it gives
    /// are used: the one unanswered is given up on at the time limit, and the asking does not
    /// fail for it
    #[tokio::test]
    async fn one_family_answered_is_enough() {
        let cases = [
            (RecordType::A, "127.0.0.1:853"),
            (RecordType::AAAA, "[::1]:853"),
        ]
        .map(|(answered, expected)| async move {
            let server = upstream(move |query| {
                if query.queries[0].query_type() == answered {
                    loopback_addresses(query, 300)
                } else {
                    Vec::new()
                }
            })
            .await;
            let addresses = timeout(
                ASK_BUDGET + Duration::from_secs(1),
                through(&server.address).addresses("upstream.test", 853),
            )
            .await
            .expect("given by the time limit");
            assert_eq!(
                addresses.unwrap(),
                [expected.parse().unwrap()],
                "{answered} answered"
            );
        });
        futures::future::join_all(cases).await;
    }

    /// AAAA 当场答、A 过了一阵才答：晚答上的那一族照样记下，建连连上 A 给的地址。AAAA 给的地址上没有人听，就像只有 ULA
    /// 的主机连公网 IPv6 地址，马上失败
    /// AAAA answered at once and A a while later: the family answered late is kept all the same,
    /// and the connect reaches the address A gives. Nothing listens at the address AAAA gives, as
    /// on a host with ULA only dialling a global IPv6 address, which fails at once
    #[tokio::test]
    async fn a_family_answered_late_is_kept() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = upstream(|query| {
            let mut replies = loopback_addresses(query, 300);
            if query.queries[0].query_type() == RecordType::A {
                replies[0].0 = Duration::from_millis(200);
            }
            replies
        })
        .await;
        let bootstrap = through(&server.address);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        super::super::transport::connect_tcp(
            &bootstrap,
            &format!("upstream.test:{port}"),
            deadline,
            |stream| async { Ok(stream) },
        )
        .await
        .expect("connected to the address A gives");
        assert_eq!(
            bootstrap.addresses("upstream.test", port).await.unwrap(),
            [
                SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port)),
                SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port)),
            ],
            "both families kept"
        );
        assert_eq!(server.queries(), 2, "A and AAAA asked once");
    }

    /// 头一回问，A 答了 SERVFAIL、AAAA 答上：先只用 AAAA 的地址，[`ASK_AGAIN_AFTER`] 之后就再问，问到 A 的地址。只有
    /// IPv6 的名字（A 答了没有记录）两族都算问到，TTL 内不再问
    /// Asked the first time, A answering SERVFAIL and AAAA answered: AAAA's address is used alone
    /// for now, asked again after [`ASK_AGAIN_AFTER`], which gives A's address. A name with IPv6
    /// only (A answered with no record) has both families given, and is not asked again while its
    /// TTL lasts
    #[tokio::test]
    async fn a_family_not_given_is_asked_again_soon() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let failing = Arc::new(AtomicBool::new(true));
        let server = upstream({
            let failing = Arc::clone(&failing);
            move |query| match query.queries[0].query_type() {
                RecordType::A if query.queries[0].name().to_ascii().starts_with("ipv6only.") => {
                    no_records(query, ResponseCode::NoError)
                }
                RecordType::A if failing.load(Ordering::SeqCst) => {
                    no_records(query, ResponseCode::ServFail)
                }
                _ => loopback_addresses(query, 300),
            }
        })
        .await;
        let bootstrap = through(&server.address);
        let ipv6 = vec!["[::1]:853".parse::<SocketAddr>().unwrap()];
        for host in ["upstream.test", "ipv6only.test"] {
            assert_eq!(
                bootstrap.addresses(host, 853).await.unwrap(),
                ipv6,
                "{host}"
            );
        }
        failing.store(false, Ordering::SeqCst);
        later_by(ASK_AGAIN_AFTER).await;
        for host in ["upstream.test", "ipv6only.test"] {
            let now = bootstrap.addresses(host, 853).now_or_never();
            assert_eq!(now.expect("at once").unwrap(), ipv6, "{host}");
        }
        assert!(
            asking(&bootstrap, "ipv6only.test").is_none(),
            "within its TTL"
        );
        let asked = asking(&bootstrap, "upstream.test").expect("asked again");
        assert_eq!(
            asked.await.unwrap()[..],
            [
                IpAddr::from(std::net::Ipv4Addr::LOCALHOST),
                IpAddr::from(std::net::Ipv6Addr::LOCALHOST)
            ]
        );
        assert_eq!(server.queries(), 6, "only upstream.test asked again");
    }

    /// 每个服务器都没答上时，原因里每一族列出每个服务器为什么没答上。以前每一族只留最后一个服务器的
    /// With no server answering, the cause lists for each family why each server did not. Each
    /// family used to keep the last server's alone
    #[tokio::test]
    async fn every_server_is_named_when_none_answers() {
        use crate::engine::test_support::answering_rcode;
        let servfail = answering_rcode(ResponseCode::ServFail).await.address;
        let refused = answering_rcode(ResponseCode::Refused).await.address;
        let err = through(&format!("{servfail}, {refused}"))
            .addresses("upstream.test", 853)
            .await
            .expect_err("no server answers");
        let err = format!("{err:#}");
        for failure in [
            format!("{servfail} answered SERVFAIL"),
            format!("{refused} answered REFUSED"),
        ] {
            assert_eq!(err.matches(&failure).count(), 2, "{failure} in {err}");
        }
    }

    /// 问到过地址的名字后来两族都答 NXDOMAIN：上回的地址照用，[`ASK_AGAIN_AFTER`] 之后再问，这期间要地址的不另问
    /// A name once given addresses that later has both families answer NXDOMAIN: the last
    /// addresses stay in use, asked again after [`ASK_AGAIN_AFTER`], nothing wanting them
    /// meanwhile asking again
    #[tokio::test]
    async fn a_name_given_no_address_any_more_keeps_its_last_ones_for_a_while() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let gone = Arc::new(AtomicBool::new(false));
        let server = upstream({
            let gone = Arc::clone(&gone);
            move |query| match gone.load(Ordering::SeqCst) {
                true => no_records(query, ResponseCode::NXDomain),
                // TTL 为 0：下一次要时就在后台再问 / TTL 0: asked again in the background when next wanted
                false => loopback_addresses(query, 0),
            }
        })
        .await;
        let bootstrap = through(&server.address);
        let given = bootstrap.addresses("upstream.test", 853).await.unwrap();
        gone.store(true, Ordering::SeqCst);
        let now = bootstrap.addresses("upstream.test", 853).now_or_never();
        assert_eq!(now.expect("at once").unwrap(), given);
        let asked = asking(&bootstrap, "upstream.test").expect("asked again");
        assert_eq!(asked.await.expect("the last addresses kept").len(), 2);
        let queries = server.queries();
        for _ in 0..3 {
            let now = bootstrap.addresses("upstream.test", 853).now_or_never();
            assert_eq!(now.expect("at once").unwrap(), given);
        }
        assert!(
            asking(&bootstrap, "upstream.test").is_none(),
            "not asked again yet"
        );
        assert_eq!(server.queries(), queries);
        later_by(ASK_AGAIN_AFTER).await;
        let now = bootstrap.addresses("upstream.test", 853).now_or_never();
        assert_eq!(now.expect("at once").unwrap(), given);
        assert!(
            asking(&bootstrap, "upstream.test").is_some(),
            "asked again by now"
        );
    }

    /// 后台再问时 A 答了 SERVFAIL：A 上回问到的 127.0.0.1 留着，不换成只有 AAAA 的那半张
    /// A answering SERVFAIL when asked again in the background: the 127.0.0.1 A gave last time
    /// stays, not traded for the half that is AAAA's alone
    #[tokio::test]
    async fn a_family_not_given_again_keeps_its_last_addresses() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let failing = Arc::new(AtomicBool::new(false));
        let server = upstream({
            let failing = Arc::clone(&failing);
            move |query| match query.queries[0].query_type() {
                RecordType::A if failing.load(Ordering::SeqCst) => {
                    no_records(query, ResponseCode::ServFail)
                }
                // TTL 为 0：每次要都在后台再问 / TTL 0: asked again in the background each time wanted
                _ => loopback_addresses(query, 0),
            }
        })
        .await;
        let bootstrap = through(&server.address);
        let given = bootstrap.addresses("upstream.test", 853).await.unwrap();
        assert_eq!(given.len(), 2, "both families given");
        failing.store(true, Ordering::SeqCst);
        let now = bootstrap.addresses("upstream.test", 853).now_or_never();
        assert_eq!(now.expect("at once").unwrap(), given);
        let asked = asking(&bootstrap, "upstream.test").expect("asked again");
        asked.await.unwrap();
        let now = bootstrap.addresses("upstream.test", 853).now_or_never();
        assert_eq!(now.expect("at once").unwrap(), given, "127.0.0.1 kept");
    }
}
