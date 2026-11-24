//! 上游地址的读法：各传输怎样从配置里写的地址得出要连的主机、端口和 TLS 服务器名；检查配置时也照这样读
//! How upstream addresses are read: how each transport gets from an address as configured to the
//! host, port and TLS server name it connects to; the configuration is checked reading them so

use anyhow::Context;
use rustls::pki_types::ServerName;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::warn;
use url::Url;

pub(super) fn build_doh_url(upstream: &str) -> anyhow::Result<(Url, Option<String>)> {
    let url_str = if upstream.starts_with("http://") || upstream.starts_with("https://") {
        upstream.to_string()
    } else if let Some(stripped) = upstream.strip_prefix("doh://") {
        format!("https://{}", stripped)
    } else {
        format!("https://{}", upstream)
    };

    let mut url = Url::parse(&url_str).context("invalid doh url")?;

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
        Transport::Dot => parse_tls_upstream(address, "dot").ok()?.1,
        Transport::Doq => parse_tls_upstream(address, "doq").ok()?.1,
        Transport::Doh => url_host(&build_doh_url(address).ok()?.0)?,
    };
    host.parse::<std::net::IpAddr>().is_err().then_some(host)
}

/// DoT、DoQ 上游地址共有的部分：没写协议时补上 `scheme`，主机，端口（默认 853），不许带路径，
/// `sni`/`servername` 参数（空的不算，多个时取最后一个）。错误文字里的协议名就是 `scheme`
/// What DoT and DoQ upstream addresses share: `scheme` added when none is written, the
/// host, the port (853 by default), no path, and the `sni`/`servername` parameter (an
/// empty one does not count, the last of several wins). The errors name `scheme`
fn parse_tls_upstream(
    upstream: &str,
    scheme: &str,
) -> anyhow::Result<(Url, String, u16, Option<String>)> {
    let url = if upstream.contains("://") {
        Url::parse(upstream)
    } else {
        Url::parse(&format!("{scheme}://{upstream}"))
    }
    .with_context(|| format!("invalid {scheme} upstream url"))?;

    let host = url_host(&url).with_context(|| format!("{scheme} upstream missing host"))?;
    let port = url.port().unwrap_or(853);

    if !url.path().is_empty() && url.path() != "/" {
        anyhow::bail!("{scheme} upstream should not contain path");
    }

    let sni = url
        .query_pairs()
        .filter(|(k, v)| {
            (k.eq_ignore_ascii_case("sni") || k.eq_ignore_ascii_case("servername")) && !v.is_empty()
        })
        .last()
        .map(|(_, v)| v.to_string());
    Ok((url, host, port, sni))
}

pub(super) fn parse_dot_target(upstream: &str) -> anyhow::Result<DotTarget> {
    let (_, host, port, sni) = parse_tls_upstream(upstream, "dot")?;

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
    let (url, host, port, sni) = parse_tls_upstream(upstream, "doq")?;

    let mut enable_0rtt: Option<bool> = None;
    for (k, v) in url.query_pairs() {
        if k.eq_ignore_ascii_case("0rtt") || k.eq_ignore_ascii_case("enable_0rtt") {
            // Parse 0rtt parameter: true/false/1/0
            // 解析 0rtt 参数：true/false/1/0
            enable_0rtt = match v.to_lowercase().as_str() {
                "true" | "1" | "yes" | "on" => Some(true),
                "false" | "0" | "no" | "off" => Some(false),
                _ => {
                    warn!("invalid doq 0rtt value: {}, ignoring", v);
                    None
                }
            };
        }
    }

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
