//! 上游地址的读法：各传输怎样从配置里写的地址得出要连的主机、端口和 TLS 服务器名；检查配置时也照这样读
//! How upstream addresses are read: how each transport gets from an address as configured to the
//! host, port and TLS server name it connects to; the configuration is checked reading them so

use anyhow::Context;
use rustls::pki_types::ServerName;
use std::net::SocketAddr;
use std::sync::Arc;
use url::Url;

/// DoH 上游 `upstream` 的 URL 和覆盖的 Host（`host` 查询参数，不发给上游）。`upstream` 是去掉前缀的地址
/// （`dns.example/dns-query`，见 `config::parse_upstream_addr`），一律走 https；后面又写了一个前缀的（`doh://http://…`）
/// 不认，不然它就悄悄走了明文。没写路径时用 `/dns-query`
/// The URL of the DoH upstream `upstream` and the Host override (the `host` query parameter,
/// not sent on). `upstream` is the address short of its prefix (`dns.example/dns-query`, see
/// `config::parse_upstream_addr`), always over https; one with a second prefix after the first
/// (`doh://http://…`) is not taken, as it would otherwise go over plain http unseen. With no path
/// written it is `/dns-query`
pub(super) fn build_doh_url(upstream: &str) -> anyhow::Result<(Url, Option<String>)> {
    if let Some((scheme, _)) = crate::config::split_scheme(upstream) {
        anyhow::bail!(
            "a second prefix \"{scheme}://\" after the first; a DoH upstream always goes over https"
        );
    }
    let mut url = Url::parse(&format!("https://{upstream}")).context("invalid doh url")?;

    // Default path for DoH if not provided
    if url.path().is_empty() || url.path() == "/" {
        url.set_path("/dns-query");
    }

    let mut host_override: Option<String> = None;
    if url.query().is_some() {
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        for (k, v) in url.query_pairs() {
            if k.eq_ignore_ascii_case("host") {
                if !v.is_empty() {
                    host_override = Some(v.to_string());
                }
            } else {
                serializer.append_pair(&k, &v);
            }
        }
        let new_query = serializer.finish();
        if new_query.is_empty() {
            url.set_query(None);
        } else {
            url.set_query(Some(&new_query));
        }
    }

    Ok((url, host_override))
}

#[derive(Clone)]
pub(super) struct DotTarget {
    pub(super) connect_addr: Arc<str>,
    pub(super) sni: Arc<str>,
}

pub(super) fn build_server_name(name: &str) -> anyhow::Result<ServerName<'static>> {
    if let Ok(ip) = name.parse::<std::net::IpAddr>() {
        let ip = rustls::pki_types::IpAddr::from(ip);
        Ok(ServerName::IpAddress(ip))
    } else {
        ServerName::try_from(name.to_string()).context("invalid tls server name")
    }
}

/// URL 里的主机，IPv6 地址不带方括号。`Url::host_str` 会把方括号原样带上，拼地址时
/// 就成了 `[[…]]:853`，拿去当证书名或判断是不是 IP 也都对不上。
/// The URL's host, an IPv6 address without its brackets. `Url::host_str` keeps
/// the brackets, which turned into `[[…]]:853` once joined with the port and
/// matched neither a certificate name nor an IP check.
fn url_host(url: &Url) -> Option<String> {
    Some(match url.host()? {
        url::Host::Domain(domain) => domain.to_string(),
        url::Host::Ipv4(addr) => addr.to_string(),
        url::Host::Ipv6(addr) => addr.to_string(),
    })
}

/// `主机:端口`，IPv6 地址加上方括号 / `host:port`, with brackets around an IPv6 address
fn host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// 一个上游地址（不带前缀）用 `transport` 读不读得懂，读法和各个客户端连接时一样
/// Whether `transport` can read one upstream address (prefix removed), read the
/// way each client reads it when it connects
pub(crate) fn check_upstream_address(
    address: &str,
    transport: crate::config::Transport,
) -> anyhow::Result<()> {
    use crate::config::Transport;

    // UDP 只认 IP 和端口（见 UdpClient::send）；TCP 也认主机名，由 Bootstrap 解析
    // UDP takes an IP and a port only (see UdpClient::send); TCP takes a host name too,
    // which Bootstrap resolves
    let socket_address = |address: &str| -> anyhow::Result<()> {
        let parsed: SocketAddr = address
            .parse()
            .context("expected an IP address and a port")?;
        anyhow::ensure!(parsed.port() != 0, "port 0");
        Ok(())
    };
    match transport {
        Transport::Udp | Transport::TcpUdp => socket_address(address),
        Transport::Tcp => {
            if socket_address(address).is_ok() {
                return Ok(());
            }
            let (host, port) = address
                .rsplit_once(':')
                .context("expected a host and a port")?;
            let port: u16 = port.parse().context("invalid port")?;
            anyhow::ensure!(port != 0, "port 0");
            anyhow::ensure!(
                !host.is_empty()
                    && host
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.'),
                "invalid host \"{host}\""
            );
            Ok(())
        }
        Transport::Doh => build_doh_url(address).map(drop),
        // 建连时拿 SNI 做 TLS 服务器名，做不成的名字（`%20`、`.`）每次建连都会失败
        // A connect makes the TLS server name from the SNI, so a name that makes none
        // (`%20`, `.`) would fail every connect
        Transport::Dot => build_server_name(&parse_dot_target(address)?.sni).map(drop),
        Transport::Doq => build_server_name(&parse_doq_target(address)?.sni).map(drop),
    }
}

/// 用 `transport` 连一个上游地址（不带前缀）之前要解析的主机名，读法和各个客户端连接时一样；写成 IP 的没有，UDP 只认 IP
/// The host name to resolve before `transport` connects to one upstream address (prefix
/// removed), read the way each client reads it when it connects; none for one written as an IP,
/// and UDP takes IPs only
pub(crate) fn host_name(address: &str, transport: crate::config::Transport) -> Option<String> {
    use crate::config::Transport;

    let host = match transport {
        Transport::Udp | Transport::TcpUdp => return None,
        Transport::Tcp if address.parse::<SocketAddr>().is_ok() => return None,
        Transport::Tcp => address.rsplit_once(':')?.0.to_owned(),
        Transport::Dot | Transport::Doq => parse_tls_upstream(address, transport).ok()?.host,
        Transport::Doh => url_host(&build_doh_url(address).ok()?.0)?,
    };
    host.parse::<std::net::IpAddr>().is_err().then_some(host)
}

/// DoT、DoQ 上游地址读出来的样子：主机，端口（默认 853），`sni`/`servername` 参数（空的不算，多个时取最后一个），
/// DoQ 的 `0rtt`/`enable_0rtt` 参数
/// What a DoT or DoQ upstream address reads as: the host, the port (853 by default), the
/// `sni`/`servername` parameter (an empty one does not count, the last of several wins), and
/// DoQ's `0rtt`/`enable_0rtt` parameter
struct TlsUpstream {
    host: String,
    port: u16,
    sni: Option<String>,
    enable_0rtt: Option<bool>,
}

/// 读一个 DoT 或 DoQ（`transport`）上游去掉前缀的地址（见 `config::parse_upstream_addr`），见 [`TlsUpstream`]。不许
/// 带路径；后面又写了一个前缀的（`dot://tcp://…`）不认，和 DoH 一样（见 [`build_doh_url`]）；参数只认这一种传输读的
/// （DoT 是 `sni`、`servername`，DoQ 再加 `0rtt`、`enable_0rtt`），别的参数和读不懂的 `0rtt` 值都是错，配置检查报出来，
/// 不悄悄忽略。错误文字里的协议名就是这种传输的
/// Reads the address of a DoT or DoQ (`transport`) upstream short of its prefix (see
/// `config::parse_upstream_addr`), see [`TlsUpstream`]. It may carry no path; one with a second
/// prefix after the first (`dot://tcp://…`) is not taken, as for DoH (see [`build_doh_url`]);
/// only the parameters this transport reads are (`sni` and `servername` for DoT, `0rtt` and
/// `enable_0rtt` too for DoQ), any other and a `0rtt` value it cannot read being errors the
/// configuration check reports rather than ignored unseen. The errors name the transport
fn parse_tls_upstream(
    upstream: &str,
    transport: crate::config::Transport,
) -> anyhow::Result<TlsUpstream> {
    let scheme = transport.label();
    if let Some((second, _)) = crate::config::split_scheme(upstream) {
        anyhow::bail!("a second prefix \"{second}://\" after the first");
    }
    let url = Url::parse(&format!("{scheme}://{upstream}"))
        .with_context(|| format!("invalid {scheme} upstream url"))?;
    let host = url_host(&url).with_context(|| format!("{scheme} upstream missing host"))?;
    if !url.path().is_empty() && url.path() != "/" {
        anyhow::bail!("{scheme} upstream should not contain path");
    }
    let (mut sni, mut enable_0rtt) = (None, None);
    for (key, value) in url.query_pairs() {
        let is = |name: &str| key.eq_ignore_ascii_case(name);
        if is("sni") || is("servername") {
            if !value.is_empty() {
                sni = Some(value.into_owned());
            }
        } else if transport == crate::config::Transport::Doq && (is("0rtt") || is("enable_0rtt")) {
            enable_0rtt = Some(match value.to_ascii_lowercase().as_str() {
                "true" | "1" | "yes" | "on" => true,
                "false" | "0" | "no" | "off" => false,
                _ => anyhow::bail!(
                    "invalid {key} \"{value}\", expected true, false, 1, 0, yes, no, on or off"
                ),
            });
        } else {
            anyhow::bail!("{scheme} upstream does not take the parameter \"{key}\"");
        }
    }
    Ok(TlsUpstream {
        host,
        port: url.port().unwrap_or(853),
        sni,
        enable_0rtt,
    })
}

pub(super) fn parse_dot_target(upstream: &str) -> anyhow::Result<DotTarget> {
    let TlsUpstream {
        host, port, sni, ..
    } = parse_tls_upstream(upstream, crate::config::Transport::Dot)?;

    let connect_addr = host_port(&host, port);
    let sni_value = sni.unwrap_or(host);

    Ok(DotTarget {
        connect_addr: Arc::from(connect_addr.as_str()),
        sni: Arc::from(sni_value.as_str()),
    })
}

#[derive(Clone)]
pub(super) struct DoqTarget {
    pub(super) host: Arc<str>,
    pub(super) port: u16,
    pub(super) sni: Arc<str>,
    /// Enable 0-RTT for this specific upstream (overrides global setting)
    /// 为此特定上游启用 0-RTT（覆盖全局设置）
    /// None = use global setting, Some(true) = force enable, Some(false) = force disable
    /// None = 使用全局设置，Some(true) = 强制启用，Some(false) = 强制禁用
    pub(super) enable_0rtt: Option<bool>,
}

pub(super) fn parse_doq_target(upstream: &str) -> anyhow::Result<DoqTarget> {
    let TlsUpstream {
        host,
        port,
        sni,
        enable_0rtt,
    } = parse_tls_upstream(upstream, crate::config::Transport::Doq)?;

    let is_ip = host.parse::<std::net::IpAddr>().is_ok();
    if sni.is_none() && is_ip {
        anyhow::bail!(
            "doq upstream with IP address requires explicit sni (e.g. doq://223.5.5.5:853?sni=alidns.com)"
        );
    }

    let sni_value = sni.unwrap_or_else(|| host.clone());

    Ok(DoqTarget {
        host: Arc::from(host),
        port,
        sni: Arc::from(sni_value.as_str()),
        enable_0rtt,
    })
}

#[cfg(test)]
#[path = "address_tests.rs"]
mod tests;
