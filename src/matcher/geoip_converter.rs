//! GeoIP 数据文件（V2Ray .dat 或 JSON）转成 MaxMind MMDB 国家库
//!
//! 解析和运行时读数据文件是同一份（见 `GeoIpManager::parse_matching`）：地址里的主机位清掉，超过位宽的
//! 前缀按单个地址算，同一个国家的网段合并以后拆成恰好盖住它们的最少的 CIDR。只转两个字母的国家代码：MMDB
//! 里一个地址只有一个国家，运行时也只有这样的标签查 MMDB（见 `is_country_tag`）。PRIVATE、CLOUDFLARE 这类
//! 标签和国家的网段重叠，以前也照样写进去，盖掉了那些地址原来的国家，`geoip:us` 就匹配不上 Cloudflare 的
//! 地址；这类标签运行时直接从数据文件里匹配。
//!
//! Converts a GeoIP data file (V2Ray .dat or JSON) into a MaxMind MMDB country database.
//!
//! It is parsed exactly as the runtime reads the data file (see
//! `GeoIpManager::parse_matching`): host bits in an address are cleared, a prefix wider than
//! the address is one address, and a country's networks are merged and then cut into the
//! fewest CIDRs covering exactly them. Only two-letter country codes are converted: an MMDB
//! holds one country per address, and only such tags are looked up in an MMDB at runtime
//! (see `is_country_tag`). Tags like PRIVATE or CLOUDFLARE overlap countries' networks; they
//! used to be written all the same, overwriting those addresses' countries, so `geoip:us`
//! stopped matching Cloudflare's addresses. Such tags are matched from the data file itself
//! at runtime.

use anyhow::{Context, Result};
use ipnet::IpNet;
use maxminddb_writer::paths::IpAddrWithMask;
use rustc_hash::FxHashSet as HashSet;
use serde::Serialize;
use std::fs::File;
use std::io::BufWriter;
use std::path::Path;
use tracing::info;

use super::geoip::{GeoIpManager, ParsedGeoIp, is_country_tag};

/// MMDB 输出数据结构
/// MMDB output data structure
#[derive(Debug, Clone, Serialize)]
struct MmdbCountryData {
    #[serde(rename = "country")]
    country: MmdbCountry,
}

#[derive(Debug, Clone, Serialize)]
struct MmdbCountry {
    #[serde(rename = "iso_code")]
    iso_code: String,
}

/// 转换统计信息
/// Conversion statistics
#[derive(Debug, Clone)]
pub struct ConversionStats {
    pub source_file_size: u64,
    pub output_file_size: u64,
    pub countries_count: usize,
    pub ipv4_ranges_count: usize,
    pub ipv6_ranges_count: usize,
}

impl std::fmt::Display for ConversionStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Conversion Statistics:")?;
        writeln!(f, "  Source file size: {} bytes", self.source_file_size)?;
        writeln!(f, "  Output file size: {} bytes", self.output_file_size)?;
        writeln!(f, "  Countries: {}", self.countries_count)?;
        writeln!(f, "  IPv4 ranges: {}", self.ipv4_ranges_count)?;
        writeln!(f, "  IPv6 ranges: {}", self.ipv6_ranges_count)?;
        Ok(())
    }
}

/// 把 `source` 里的国家转成 MMDB 写到 `output`；`filter` 给了（不空）就只转这几个国家（两个字母的代码，不分
/// 大小写），写了别的标签是错误
/// Converts the countries of `source` into an MMDB written to `output`; with a `filter`
/// (not empty) only those countries are converted (two-letter codes, ignoring case), any
/// other tag in it being an error
pub fn convert_dat_to_mmdb(
    source: &Path,
    output: &Path,
    filter: Option<&[String]>,
) -> Result<ConversionStats> {
    info!(
        "Starting conversion: {} -> {}",
        source.display(),
        output.display()
    );
    let filter: Option<HashSet<String>> = filter
        .filter(|codes| !codes.is_empty())
        .map(|codes| codes.iter().map(|code| code.to_ascii_uppercase()).collect());
    if let Some(tag) = filter.iter().flatten().find(|code| !is_country_tag(code)) {
        anyhow::bail!(
            "{tag} is not a two-letter country code: an MMDB holds countries only, and other \
             tags are matched from the data file itself (geoip_dat_path)"
        );
    }
    let wanted = |code: &str| {
        is_country_tag(code) && filter.as_ref().is_none_or(|filter| filter.contains(code))
    };
    let parsed = GeoIpManager::parse_matching(source, &wanted)?;
    let stats = write_mmdb(&parsed, source, output)?;
    info!("Conversion completed:\n{}", stats);
    Ok(stats)
}

/// 把 `parsed` 的国家写成 MMDB / Writes the countries of `parsed` as an MMDB
fn write_mmdb(parsed: &ParsedGeoIp, source: &Path, output: &Path) -> Result<ConversionStats> {
    use maxminddb_writer::{Database, metadata::IpVersion};
    use std::io::Write;

    let mut db = Database::default();

    // 标准字段：libmaxminddb 要求 binary_format_major_version 与 build_epoch 非零，
    // 否则报 "Is this a valid MaxMind DB file?"
    // Standard fields: libmaxminddb needs binary_format_major_version and build_epoch
    // non-zero, or it reports "Is this a valid MaxMind DB file?"
    db.metadata.database_type = "KixDNS GeoIP".to_string();
    db.metadata.description.insert(
        "en".to_string(),
        "GeoIP database converted from V2Ray .dat format".to_string(),
    );
    db.metadata.ip_version = IpVersion::V6;
    db.metadata.binary_format_major_version = 2;
    db.metadata.binary_format_minor_version = 0;
    db.metadata.build_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(1);
    db.metadata.languages = vec!["en".to_string()];

    let (mut ipv4_count, mut ipv6_count) = (0, 0);
    // 收集所有插入项后按前缀升序插入（父网段先插），规避 maxminddb-writer 的 NodeTree::insert 先子后父
    // 覆盖丢失子网的 bug
    // Everything is collected and inserted by ascending prefix (parents first), working round
    // maxminddb-writer's NodeTree::insert losing a child inserted before its parent
    let mut inserts = Vec::new();
    for (country, networks) in parsed.networks_by_tag() {
        let data = MmdbCountryData {
            country: MmdbCountry {
                iso_code: country.to_string(),
            },
        };
        let data_ref = db
            .insert_value(&data)
            .with_context(|| format!("Failed to insert data for country: {country}"))?;
        for net in networks {
            match net {
                IpNet::V4(_) => ipv4_count += 1,
                IpNet::V6(_) => ipv6_count += 1,
            }
            let path = ip_net_to_mmdb_path(&net);
            inserts.push((path.mask, data_ref, path));
        }
    }
    // 一个网段都没有时不写：这样的 MMDB 没有查找树，maxminddb 打开时就拒绝
    // Nothing is written without a single network: such an MMDB has no search tree, which
    // maxminddb refuses to open
    if inserts.is_empty() {
        anyhow::bail!(
            "{} has no network of the countries to convert, and an MMDB without networks cannot be read",
            source.display()
        );
    }
    inserts.sort_by_key(|(mask, _, _)| *mask);
    for (_, data_ref, path) in inserts {
        db.insert_node(path, data_ref);
    }

    let file = File::create(output)
        .with_context(|| format!("Failed to create output file: {}", output.display()))?;
    let mut writer = BufWriter::new(file);
    db.write_to(&mut writer)
        .context("Failed to write MMDB database")?;
    writer.flush().context("Failed to flush output")?;

    Ok(ConversionStats {
        source_file_size: std::fs::metadata(source).map(|m| m.len()).unwrap_or(0),
        output_file_size: std::fs::metadata(output)
            .map(|m| m.len())
            .with_context(|| format!("Failed to get output file size: {}", output.display()))?,
        countries_count: parsed.tag_count(),
        ipv4_ranges_count: ipv4_count,
        ipv6_ranges_count: ipv6_count,
    })
}

/// 将 IP 网段转换为 MMDB 插入路径
/// Convert an IP network to an MMDB insertion path
///
/// IPv4 必须嵌入 `::/96`（前 96 位全 0 的 IPv6 地址），因为所有 maxminddb
/// reader（Rust / libmaxminddb / Python）查询 IPv4 时都从树第 96 位（::/96
/// 子树根）开始。maxminddb-writer 0.1.1 本身不处理嵌入，直接插树根会导致
/// IPv4 网段全部落空。
/// IPv4 has to be embedded in `::/96` (IPv6 addresses whose first 96 bits are zero), as
/// every maxminddb reader (Rust, libmaxminddb, Python) looks IPv4 up from bit 96 of the tree,
/// the root of the `::/96` subtree. maxminddb-writer 0.1.1 does no embedding itself, and
/// inserted at the root the IPv4 networks would all be missed.
fn ip_net_to_mmdb_path(net: &IpNet) -> IpAddrWithMask {
    match net {
        IpNet::V4(v4) => IpAddrWithMask::new(
            std::net::IpAddr::V6(v4.addr().to_ipv6_compatible()),
            v4.prefix_len() + 96,
        ),
        IpNet::V6(v6) => IpAddrWithMask::new(std::net::IpAddr::V6(v6.addr()), v6.prefix_len()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matcher::geoip_proto::{Cidr, GeoIP, GeoIPList};
    use prost::Message;
    use serde::Deserialize;

    #[derive(Deserialize, Debug)]
    struct CountryRec {
        country: Option<CountryIso>,
    }
    #[derive(Deserialize, Debug)]
    struct CountryIso {
        iso_code: Option<String>,
    }

    fn cidr(ip: &str, prefix: u32) -> Cidr {
        let ip = match ip.parse::<std::net::IpAddr>().unwrap() {
            std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
            std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
        };
        Cidr { ip, prefix }
    }

    /// 写一个 .dat：每项是一个标签和它的网段 / Writes a .dat, each entry a tag and its networks
    fn dat(dir: &Path, entries: Vec<(&str, Vec<Cidr>)>) -> std::path::PathBuf {
        let list = GeoIPList {
            entry: entries
                .into_iter()
                .map(|(code, cidr)| GeoIP {
                    country_code: code.to_string(),
                    cidr,
                })
                .collect(),
        };
        let path = dir.join("geoip.dat");
        std::fs::write(&path, list.encode_to_vec()).unwrap();
        path
    }

    fn country_of(reader: &maxminddb::Reader<Vec<u8>>, ip: &str) -> Option<String> {
        reader
            .lookup(ip.parse().unwrap())
            .unwrap()
            .decode::<CountryRec>()
            .unwrap()
            .and_then(|rec| rec.country?.iso_code)
    }

    /// 转出来的 MMDB 和运行时读数据文件一样：主机位清掉，超过位宽的前缀按单个地址算，同一个国家的网段合并；
    /// 只有国家，和国家重叠的 CLOUDFLARE、PRIVATE 这类标签不写进去，不盖掉那些地址的国家。以前前缀照
    /// `as u8` 截断（280 成了 24），标签照样写进去
    /// The MMDB converted reads as the runtime reads the data file: host bits cleared, a
    /// prefix wider than the address one address, a country's networks merged; countries
    /// only, tags like CLOUDFLARE and PRIVATE overlapping them left out rather than
    /// overwriting those addresses' countries. Prefixes used to be cut `as u8` (280 becoming
    /// 24), and the tags written all the same
    #[test]
    fn an_mmdb_holds_the_countries_as_the_runtime_reads_them() {
        let dir = tempfile::tempdir().unwrap();
        let source = dat(
            dir.path(),
            vec![
                (
                    "cn",
                    vec![
                        cidr("1.2.3.4", 24),
                        cidr("1.2.2.0", 24),
                        cidr("5.6.7.8", 280),
                    ],
                ),
                ("US", vec![cidr("2001:db8::", 32), cidr("104.16.0.0", 12)]),
                ("CLOUDFLARE", vec![cidr("104.16.0.0", 13)]),
                ("PRIVATE", vec![cidr("10.0.0.0", 8)]),
            ],
        );
        let output = dir.path().join("out.mmdb");
        let stats = convert_dat_to_mmdb(&source, &output, None).unwrap();
        assert_eq!(stats.countries_count, 2, "CN and US");
        // CN 的两个 /24 合成一个 /23，5.6.7.8 是单个地址 / CN's two /24s merge into a /23, 5.6.7.8 is one address
        assert_eq!((stats.ipv4_ranges_count, stats.ipv6_ranges_count), (3, 1));

        let reader = maxminddb::Reader::from_source(std::fs::read(&output).unwrap()).unwrap();
        assert_eq!(reader.metadata().binary_format_major_version, 2);
        assert!(reader.metadata().build_epoch > 0);
        assert_eq!(reader.metadata().ip_version, 6);
        for (ip, country) in [
            ("1.2.3.200", Some("CN")),
            ("1.2.2.1", Some("CN")),
            ("5.6.7.8", Some("CN")),
            ("5.6.7.9", None),
            ("104.16.1.1", Some("US")),
            ("2001:db8::1", Some("US")),
            ("10.1.1.1", None),
            ("9.9.9.9", None),
        ] {
            assert_eq!(country_of(&reader, ip).as_deref(), country, "{ip}");
        }
    }

    /// 只转过滤条件里的国家，不分大小写；写了不是国家的标签就报错，不转出一个没有它的库
    /// Only the countries in the filter are converted, ignoring case; a tag in it that is no
    /// country is an error, rather than a database without it
    #[test]
    fn a_filter_keeps_its_countries_and_refuses_other_tags() {
        let dir = tempfile::tempdir().unwrap();
        let source = dat(
            dir.path(),
            vec![
                ("CN", vec![cidr("1.2.3.0", 24)]),
                ("US", vec![cidr("8.8.8.0", 24)]),
            ],
        );
        let output = dir.path().join("out.mmdb");
        let stats = convert_dat_to_mmdb(&source, &output, Some(&["cn".to_string()])).unwrap();
        assert_eq!(stats.countries_count, 1);
        let reader = maxminddb::Reader::from_source(std::fs::read(&output).unwrap()).unwrap();
        assert_eq!(country_of(&reader, "1.2.3.4").as_deref(), Some("CN"));
        assert_eq!(country_of(&reader, "8.8.8.8"), None);

        let refused = convert_dat_to_mmdb(&source, &output, Some(&["CN".into(), "private".into()]))
            .unwrap_err();
        assert!(
            refused.to_string().starts_with("PRIVATE is not"),
            "{refused}"
        );
    }

    /// 过滤条件里的国家一个都不在数据里时报错，不写出 MMDB：没有网段的 MMDB 读不了。以前照样写出一个没有查找树的库，
    /// maxminddb 0.29 起打不开它，内核加载时只能报读不了
    /// With none of the filter's countries in the data it is an error and no MMDB is written: an
    /// MMDB without networks cannot be read. One without a search tree used to be written all
    /// the same, which maxminddb cannot open since 0.29, the kernel only able to say so as it loads
    #[test]
    fn converting_no_network_writes_no_mmdb() {
        let dir = tempfile::tempdir().unwrap();
        let source = dat(dir.path(), vec![("CN", vec![cidr("1.2.3.0", 24)])]);
        let output = dir.path().join("out.mmdb");
        let refused = convert_dat_to_mmdb(&source, &output, Some(&["US".to_string()])).unwrap_err();
        assert!(
            refused
                .to_string()
                .contains("no network of the countries to convert"),
            "{refused}"
        );
        assert!(!output.exists());
    }
}
