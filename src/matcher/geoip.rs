use std::fs::File;
use std::io::{BufReader, Read};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use prost::Message;
use rustc_hash::{FxHashMap, FxHashSet};
use serde::Deserialize;

// Re-export from geoip_converter module
// Note: geoip_converter is a sibling module at the crate root level
pub use crate::lock::RwLock;
pub use crate::matcher::geoip_converter::{ConversionStats, convert_dat_to_mmdb};

/// MaxMind GeoLite2-Country 数据库结构，字符串直接借用数据库里的字节
/// MaxMind GeoLite2-Country database structure, its strings borrowed from the database's bytes
#[derive(Deserialize)]
struct MaxMindCountryRecord<'a> {
    #[serde(borrow)]
    country: Option<MaxMindCountry<'a>>,
    #[serde(borrow)]
    registered_country: Option<MaxMindCountry<'a>>,
    #[serde(borrow)]
    represented_country: Option<MaxMindCountry<'a>>,
}

#[derive(Deserialize)]
struct MaxMindCountry<'a> {
    iso_code: Option<&'a str>,
}

/// V2Ray GeoIP .dat 文件格式 / V2Ray GeoIP .dat file format
#[derive(Debug, Clone, Deserialize)]
pub struct V2RayGeoIP {
    /// 国家代码 / Country code
    pub country_code: String,
    /// IP 地址列表 / IP address list
    pub ips: Vec<String>,
}

/// V2Ray GeoIP 列表格式 / V2Ray GeoIP list format
#[derive(Debug, Clone, Deserialize)]
pub struct V2RayGeoIPList {
    /// GeoIP 条目列表 / GeoIP entries
    pub entries: Vec<V2RayGeoIP>,
}

/// IP 段（用于快速匹配）/ IP range for fast matching
#[derive(Debug, Clone)]
pub struct IpRange {
    /// 起始 IP 地址 / Start IP address
    pub start: u32,
    /// 结束 IP 地址 / End IP address
    pub end: u32,
    /// 国家代码 / Country code
    pub country_code: String,
}

impl IpRange {
    /// 检查 IP 是否在范围内 / Check if IP is in range
    #[inline]
    pub fn contains(&self, ip: u32) -> bool {
        ip >= self.start && ip <= self.end
    }
}

/// IPv6 段（用于快速匹配）/ IPv6 range for fast matching
#[derive(Debug, Clone)]
pub struct IpRangeV6 {
    /// 起始 IP 地址（u128 大端序）/ Start IP address (u128 big-endian)
    pub start: u128,
    /// 结束 IP 地址（u128 大端序）/ End IP address (u128 big-endian)
    pub end: u128,
    /// 国家代码 / Country code
    pub country_code: String,
}

impl IpRangeV6 {
    /// 检查 IPv6 是否在范围内 / Check if IPv6 is in range
    #[inline]
    pub fn contains(&self, ip: u128) -> bool {
        ip >= self.start && ip <= self.end
    }
}

#[derive(Debug, Clone, Copy)]
struct Ipv4Range {
    start: u32,
    end: u32,
}

#[derive(Debug, Clone, Copy)]
struct Ipv6Range {
    start: u128,
    end: u128,
}

#[derive(Debug, Default)]
struct GeoIpTagIndex {
    ipv4_ranges: Vec<Ipv4Range>,
    ipv6_ranges: Vec<Ipv6Range>,
    raw_ipv4_ranges: Vec<Ipv4Range>,
    raw_ipv6_ranges: Vec<Ipv6Range>,
}

impl GeoIpTagIndex {
    fn finalize(&mut self) {
        self.raw_ipv4_ranges = self.ipv4_ranges.clone();
        self.raw_ipv4_ranges
            .sort_unstable_by_key(|range| range.start);
        self.raw_ipv6_ranges = self.ipv6_ranges.clone();
        self.raw_ipv6_ranges
            .sort_unstable_by_key(|range| range.start);
        merge_ipv4_ranges(&mut self.ipv4_ranges);
        merge_ipv6_ranges(&mut self.ipv6_ranges);
    }

    #[inline]
    fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => {
                let ip = u32::from(ip);
                let index = self.ipv4_ranges.partition_point(|range| range.start <= ip);
                index > 0 && self.ipv4_ranges[index - 1].end >= ip
            }
            IpAddr::V6(ip) => {
                let ip = u128::from(ip);
                let index = self.ipv6_ranges.partition_point(|range| range.start <= ip);
                index > 0 && self.ipv6_ranges[index - 1].end >= ip
            }
        }
    }

    fn matching_range(&self, ip: IpAddr) -> Option<(u128, u128)> {
        match ip {
            IpAddr::V4(ip) => {
                let ip = u32::from(ip);
                most_specific_ipv4(&self.raw_ipv4_ranges, ip)
                    .map(|range| (u128::from(range.start), u128::from(range.end)))
            }
            IpAddr::V6(ip) => most_specific_ipv6(&self.raw_ipv6_ranges, u128::from(ip))
                .map(|range| (range.start, range.end)),
        }
    }

    #[inline]
    fn range_count(&self) -> usize {
        self.ipv4_ranges.len() + self.ipv6_ranges.len()
    }
}

/// V2Ray .dat 文件使用 protobuf 格式
/// MaxMind GeoIP 数据库管理器 / MaxMind GeoIP database manager
/// 一个数据文件解析出的 GeoIP 索引，已 finalize，尚未进入管理器
/// GeoIP indexes parsed out of one data file, already finalised and not yet
/// applied to a manager
pub struct ParsedGeoIp {
    tag_indexes: FxHashMap<Arc<str>, GeoIpTagIndex>,
    count: usize,
    ipv4_count: usize,
    ipv6_count: usize,
    /// 只用于日志，区分 .dat 与 JSON / For the log line only, .dat versus JSON
    source: &'static str,
}

pub struct GeoIpManager {
    /// MaxMind DB 和它每条数据记录的国家代码 / The MaxMind DB and the country code of each of its data records
    mmdb: Option<Mmdb>,
    /// MMDB 文件路径（用于延迟加载）/ MMDB file path (for lazy loading)
    /// Note: Reserved for future hot-reload functionality
    #[allow(dead_code)]
    db_path: Option<String>,
    /// 按标签分组的 IP 范围索引（从 .dat/JSON 文件加载）
    /// IP range indexes grouped by tag (loaded from .dat/JSON files)
    tag_indexes: FxHashMap<Arc<str>, GeoIpTagIndex>,
}

/// MaxMind 数据库，加上每条数据记录的国家代码。同一个国家的网段指向同一条记录（GeoLite2-Country
/// 一百多万个网段只有六千来条记录），所以加载时每条记录解一次，查询只走查找树再查一次表，约
/// 105 ns。此前每次查询解一整条记录约 800 ns，前面按 IP 挡一层缓存，命中要 240 ns，未命中连插入
/// 近 2 µs，缓存还随问到的不同地址涨到上百 MiB。
/// The MaxMind database, plus the country code of each of its data records. All networks of a
/// country point at the same record (GeoLite2-Country has some six thousand records for over a
/// million networks), so each record is decoded once when loading, and a query walks the search
/// tree and looks the table up, in about 105 ns. Each query used to decode a whole record, in
/// about 800 ns, behind a per-IP cache that took 240 ns on a hit, nearly 2 µs on a miss with
/// its insert, and grew past a hundred MiB with the distinct addresses asked about.
struct Mmdb {
    reader: maxminddb::Reader<Vec<u8>>,
    /// 数据记录在文件里的位置 → 国家代码 / A data record's offset in the file → its country code
    countries: FxHashMap<usize, Option<Arc<str>>>,
}

impl Mmdb {
    fn open(path: &str) -> Result<Self, maxminddb::MaxMindDbError> {
        let reader = maxminddb::Reader::open_readfile(path)?;
        let mut countries = FxHashMap::default();
        if let Err(e) = Self::index(&reader, &mut countries) {
            // 没解到的记录查询时当场解，结果不变 / Records left out are decoded when asked about, with the same result
            tracing::warn!(geoip_db = %path, error = %e, "could not index every GeoIP database record, the rest are decoded per query");
        }
        Ok(Self { reader, countries })
    }

    /// 把每条数据记录的国家代码（大写）记进 `countries`，同一个代码共用一份
    /// Records the country code (uppercase) of every data record in `countries`, records of
    /// the same code sharing one string
    fn index(
        reader: &maxminddb::Reader<Vec<u8>>,
        countries: &mut FxHashMap<usize, Option<Arc<str>>>,
    ) -> Result<(), maxminddb::MaxMindDbError> {
        let mut interned: FxHashMap<String, Arc<str>> = FxHashMap::default();
        for network in reader.networks(Default::default())? {
            let found = network?;
            let Some(offset) = found.offset() else {
                continue;
            };
            if countries.contains_key(&offset) {
                continue;
            }
            let code = record_country(&found).map(|code| {
                let code = code.to_ascii_uppercase();
                Arc::clone(
                    interned
                        .entry(code)
                        .or_insert_with_key(|code| Arc::from(code.as_str())),
                )
            });
            countries.insert(offset, code);
        }
        Ok(())
    }

    /// `ip` 的国家代码，按数据库里的写法，比较时不分大小写
    /// The country code of `ip` as the database writes it; compare it ignoring case
    #[inline]
    fn country(&self, ip: IpAddr) -> Option<&str> {
        let found = self.reader.lookup(ip).ok()?;
        match self.countries.get(&found.offset()?) {
            Some(code) => code.as_deref(),
            // 加载时每条记录都解过，到不了这里；真到了就当场解
            // Every record was decoded when loading, so this is not reached; if it is, the
            // record is decoded here
            None => record_country(&found),
        }
    }
}

/// 一条记录的国家代码：先看 country，没有再看 registered_country、represented_country；解不出来
/// 当作没有
/// A record's country code: country first, then registered_country, then represented_country;
/// a record that cannot be decoded has none
fn record_country<'a>(found: &maxminddb::LookupResult<'a, Vec<u8>>) -> Option<&'a str> {
    let record = found.decode::<MaxMindCountryRecord<'a>>().ok()??;
    record
        .country
        .or(record.registered_country)
        .or(record.represented_country)
        .and_then(|country| country.iso_code)
}

/// GeoIP 查询结果 / GeoIP query result
#[derive(Debug, Clone)]
pub struct GeoIpResult {
    /// ISO 3166-1 alpha-2 国家代码（如 "CN", "US"） / ISO 3166-1 alpha-2 country code (e.g., "CN", "US")
    /// 使用 Arc<str> 实现零拷贝 clone / Use Arc<str> for zero-copy clone
    pub country_code: Option<Arc<str>>,
    /// 是否为私有 IP 地址 / Whether it's a private IP address
    pub is_private: bool,
}

impl GeoIpManager {
    /// 创建新的 GeoIP 管理器 / Create new GeoIP manager
    ///
    /// # 参数 / Parameters
    /// - `db_path`: MMDB 文件路径（可选）/ MMDB file path (optional)
    ///
    /// 此方法会立即加载 MMDB 文件（如果配置了路径），不再使用懒加载。
    /// This method loads the MMDB file immediately (if path is configured), no longer using lazy loading.
    pub fn new(db_path: Option<String>) -> anyhow::Result<Self> {
        // 立即加载 MMDB 文件（如果配置了）/ Load MMDB file immediately (if configured)
        let mmdb = if let Some(ref path) = db_path {
            if std::path::Path::new(path).exists() {
                match Mmdb::open(path) {
                    Ok(mmdb) => {
                        tracing::info!(geoip_db = %path, records = mmdb.countries.len(), "GeoIP database loaded successfully");
                        Some(mmdb)
                    }
                    Err(e) => {
                        tracing::warn!(geoip_db = %path, error = %e, "Failed to open GeoIP database");
                        None
                    }
                }
            } else {
                tracing::warn!(geoip_db = %path, "GeoIP database file not found");
                None
            }
        } else {
            None
        };

        Ok(Self {
            mmdb,
            db_path,
            tag_indexes: FxHashMap::default(),
        })
    }

    /// MMDB 是否已加载；加载了，两个字母的国家代码就只按它判断
    /// Whether an MMDB is loaded; when one is, two-letter country codes are judged by it alone
    #[inline]
    pub fn has_mmdb(&self) -> bool {
        self.mmdb.is_some()
    }

    /// 查询 IP 的 GeoIP 信息 / Lookup GeoIP information for an IP address
    ///
    /// # 参数 / Parameters
    /// - `ip`: 要查询的 IP 地址 / IP address to lookup
    ///
    /// # 返回 / Returns
    /// GeoIP 查询结果（包含国家代码和私有 IP 标志） / GeoIP result (with country code and private IP flag)
    pub fn lookup(&self, ip: IpAddr) -> GeoIpResult {
        let country_code = match &self.mmdb {
            Some(mmdb) => mmdb
                .country(ip)
                .map(|code| Arc::from(code.to_ascii_uppercase())),
            // 使用 .dat/JSON 文件中的国家标签 / Use country tags from .dat/JSON files
            None if !self.tag_indexes.is_empty() => self.lookup_dat_country(ip),
            // 没有 MMDB 文件，只检测私有 IP / No MMDB file, only check private IP
            None => None,
        };
        GeoIpResult {
            country_code,
            is_private: is_private_ip(ip),
        }
    }

    /// 检查 IP 是否属于指定标签 / Check whether an IP belongs to a tag.
    #[inline]
    pub fn matches_tag(&self, ip: IpAddr, tag: &str) -> bool {
        let normalized;
        let tag = if tag.bytes().all(|b| !b.is_ascii_lowercase()) {
            tag
        } else {
            normalized = tag.to_ascii_uppercase();
            &normalized
        };

        if let Some(mmdb) = &self.mmdb
            && is_country_tag(tag)
        {
            return mmdb
                .country(ip)
                .is_some_and(|code| code.eq_ignore_ascii_case(tag));
        }

        self.tag_indexes
            .get(tag)
            .is_some_and(|index| index.contains(ip))
    }

    /// 检查 IP 是否属于任一指定标签 / Check whether an IP belongs to any requested tag.
    #[inline]
    pub fn matches_any_tag(&self, ip: IpAddr, tags: &[Arc<str>]) -> bool {
        // 用到国家代码时才查 MMDB，只查一次 / The MMDB is asked once, and only when a country code needs it
        let mut mmdb_country: Option<Option<&str>> = None;

        for tag in tags {
            let normalized;
            let tag = if tag.bytes().all(|b| !b.is_ascii_lowercase()) {
                tag.as_ref()
            } else {
                normalized = tag.to_ascii_uppercase();
                &normalized
            };

            if let Some(mmdb) = &self.mmdb
                && is_country_tag(tag)
            {
                if mmdb_country
                    .get_or_insert_with(|| mmdb.country(ip))
                    .is_some_and(|country_code| country_code.eq_ignore_ascii_case(tag))
                {
                    return true;
                }
                continue;
            }

            if self
                .tag_indexes
                .get(tag)
                .is_some_and(|index| index.contains(ip))
            {
                return true;
            }
        }
        false
    }

    /// 返回 IP 命中的全部标签，主要用于诊断和管理接口。
    /// Return all tags matching an IP, primarily for diagnostics and management APIs.
    pub fn lookup_tags(&self, ip: IpAddr) -> Vec<Arc<str>> {
        let has_mmdb = self.has_mmdb();
        let mut tags: Vec<_> = self.lookup(ip).country_code.into_iter().collect();
        tags.extend(
            self.tag_indexes
                .iter()
                .filter(|(tag, index)| index.contains(ip) && (!has_mmdb || !is_country_tag(tag)))
                .map(|(tag, _)| Arc::clone(tag)),
        );
        tags.sort_unstable_by(|a, b| a.as_ref().cmp(b.as_ref()));
        tags.dedup();
        tags
    }

    /// 从 .dat/JSON 数据中查询传统单标签结果，优先返回两位国家代码。
    /// Lookup the legacy single-tag result, preferring a two-letter country code.
    fn lookup_dat_country(&self, ip: IpAddr) -> Option<Arc<str>> {
        let mut country_match = None;
        let mut named_match = None;

        for (tag, index) in &self.tag_indexes {
            let Some((start, end)) = index.matching_range(ip) else {
                continue;
            };

            let target = if is_country_tag(tag) {
                &mut country_match
            } else {
                &mut named_match
            };
            if is_more_specific(target, tag, start, end) {
                *target = Some((Arc::clone(tag), start, end));
            }
        }

        country_match.or(named_match).map(|(tag, _, _)| tag)
    }

    /// 重新加载 MMDB 数据库 / Reload MMDB database
    ///
    /// # 参数 / Parameters
    /// - `db_path`: 新的 MMDB 文件路径 / New MMDB file path
    pub fn reload(&mut self, db_path: Option<String>) -> anyhow::Result<()> {
        if let Some(path) = db_path {
            match Mmdb::open(&path) {
                Ok(mmdb) => {
                    self.mmdb = Some(mmdb);
                    tracing::info!(
                        geoip_db = %path,
                        "GeoIP database reloaded successfully"
                    );
                    Ok(())
                }
                Err(e) => {
                    tracing::warn!(
                        geoip_db = %path,
                        error = %e,
                        "Failed to reload GeoIP database"
                    );
                    Err(e.into())
                }
            }
        } else {
            tracing::debug!("No GeoIP database path to reload");
            Ok(())
        }
    }

    /// 检查 GeoIP 数据是否已加载 / Check whether any GeoIP data is loaded.
    #[inline]
    pub fn is_loaded(&self) -> bool {
        self.mmdb.is_some() || !self.tag_indexes.is_empty()
    }

    /// 获取去重合并后的 IP 范围数量（仅用于调试）。
    /// Get the deduplicated and merged IP range count (debug only).
    #[inline]
    pub fn ip_range_count(&self) -> usize {
        self.tag_indexes
            .values()
            .map(GeoIpTagIndex::range_count)
            .sum()
    }

    /// 从 V2Ray .dat 文件加载 GeoIP 数据 / Load GeoIP data from V2Ray .dat file
    ///
    /// 文件格式 / File format:
    /// - Header: 4 bytes magic (0x0D 0x0A 0x0D 0x0A)
    /// - Index section: country_code_count (2 bytes) + entries
    /// - Data section: IP ranges for each country
    ///
    /// 从 V2Ray .dat 文件加载 GeoIP 数据
    ///
    /// V2Ray .dat 文件使用 protobuf 编码，包含国家代码和 IP 范围
    /// V2Ray .dat files use protobuf encoding, containing country codes and IP ranges
    /// V2Ray .dat 文件使用 protobuf 编码，包含国家代码和 IP 范围
    /// V2Ray .dat files use protobuf encoding, containing country codes and IP ranges
    pub fn load_from_dat_file(&mut self, path: &Path) -> anyhow::Result<usize> {
        let parsed = Self::parse_dat_file(path)?;
        Ok(self.apply_parsed(parsed))
    }

    /// 解析 .dat 文件，不触碰管理器状态
    /// Parse a .dat file without touching manager state
    ///
    /// 读取、解码、建索引、finalize 全在这里完成，与 [`Self::apply_parsed`]
    /// 配合：调用方在锁外解析，只在替换数据时短暂持写锁。finalize 必须留在
    /// 这一侧——它要排序并合并每个 tag 的全部网段，是整个重载里最重的一段，
    /// 只把读取和解码搬出去拿不到多少。
    /// Reading, decoding, building the indexes and finalising all happen here.
    /// It pairs with [`Self::apply_parsed`]: callers parse outside the lock and
    /// hold the write lock only while swapping data in. Finalising has to stay
    /// on this side, since sorting and merging every tag's ranges is the
    /// heaviest part of a reload and moving only the read and the decode would
    /// leave most of it behind.
    pub fn parse_dat_file(path: &Path) -> anyhow::Result<ParsedGeoIp> {
        Self::parse_dat_entries(path, &|_| true)
    }

    /// 解析 .dat 文件里 `wanted` 认可的条目（参数是大写的国家代码或标签）。按条目顺序读，不把整个
    /// 文件读进内存：每个条目先只解国家代码，要的条目才整个解，一百多万个网段里规则只用到几个标签时，
    /// 别的标签既不解也不留。
    /// 使用 Google 标准 protobuf 库 (prost) 解码条目，与 dae pkg/geodata 对齐：手写 wire 解析假设
    /// 字段顺序固定、无未知字段，任何 .dat 格式变体都会产生静默错位或错误网段。
    /// Parses the entries of a .dat file that `wanted` accepts (given the uppercase country code
    /// or tag). The file is read entry by entry rather than into memory whole: each entry's
    /// country code is decoded first and only wanted entries are decoded whole, so when rules use
    /// a few tags out of over a million networks the other tags are neither decoded nor kept.
    /// Entries are decoded with Google's standard protobuf library (prost), in line with dae's
    /// pkg/geodata: hand-written wire parsing assumes a fixed field order and no unknown fields,
    /// and any .dat variant would silently shift fields or yield wrong networks.
    fn parse_dat_entries(
        path: &Path,
        wanted: &dyn Fn(&str) -> bool,
    ) -> anyhow::Result<ParsedGeoIp> {
        let file = File::open(path)?;
        let mut remaining = file.metadata()?.len();
        let mut file = BufReader::with_capacity(64 * 1024, file);
        // 一个条目的内容，各条目轮流使用 / One entry's bytes, reused for every entry
        let mut entry = Vec::new();
        let mut tag_indexes: FxHashMap<Arc<str>, GeoIpTagIndex> = FxHashMap::default();
        let mut count = 0;
        let mut ipv4_count = 0;
        let mut ipv6_count = 0;

        // GeoIPList 顶层只有 `repeated GeoIP entry = 1`，别的字段跳过
        // GeoIPList holds only `repeated GeoIP entry = 1` at the top; other fields are skipped
        while remaining > 0 {
            let key = read_varint(&mut file, &mut remaining)?;
            let (field, wire_type) = (key >> 3, key & 0x7);
            let len = match wire_type {
                0 => {
                    read_varint(&mut file, &mut remaining)?;
                    continue;
                }
                1 => 8,
                2 => read_varint(&mut file, &mut remaining)?,
                5 => 4,
                other => anyhow::bail!("invalid wire type {other} in .dat file"),
            };
            anyhow::ensure!(
                field != 1 || wire_type == 2,
                "invalid wire type {wire_type} for a GeoIP entry"
            );
            anyhow::ensure!(
                len <= remaining,
                "truncated .dat file: a field needs {len} bytes, {remaining} left"
            );
            remaining -= len;
            if field != 1 {
                file.seek_relative(i64::try_from(len)?)?;
                continue;
            }
            entry.clear();
            entry.resize(usize::try_from(len)?, 0);
            file.read_exact(&mut entry)?;

            // 先只解国家代码（其余字段跳过不解），要的条目才整个解
            // Decode the country code alone first (other fields are skipped undecoded), and
            // the whole entry only when it is wanted
            let country_code = super::geoip_proto::GeoIPCode::decode(entry.as_slice())
                .context("failed to decode a geoip.dat entry")?
                .country_code
                .to_ascii_uppercase();
            if country_code.is_empty() || !wanted(&country_code) {
                continue;
            }
            let geoip = super::geoip_proto::GeoIP::decode(entry.as_slice())
                .context("failed to decode a geoip.dat entry")?;
            for cidr in geoip.cidr {
                match cidr.ip.len() {
                    4 => {
                        let mut ip_bytes = [0u8; 4];
                        ip_bytes.copy_from_slice(&cidr.ip);
                        let start = u32::from_be_bytes(ip_bytes);
                        let end = if cidr.prefix >= 32 {
                            // /32 或异常前缀按单 IP 处理
                            start
                        } else if cidr.prefix == 0 {
                            // /0 表示整个 IPv4 空间
                            u32::MAX
                        } else {
                            let host_count = 1u32.wrapping_shl(32 - cidr.prefix);
                            start.saturating_add(host_count).saturating_sub(1)
                        };
                        get_or_insert_tag_index(&mut tag_indexes, &country_code)
                            .ipv4_ranges
                            .push(Ipv4Range { start, end });
                        count += 1;
                        ipv4_count += 1;
                    }
                    16 => {
                        let mut ip_bytes = [0u8; 16];
                        ip_bytes.copy_from_slice(&cidr.ip);
                        let start = u128::from_be_bytes(ip_bytes);
                        let end = if cidr.prefix >= 128 {
                            start
                        } else if cidr.prefix == 0 {
                            u128::MAX
                        } else {
                            let host_count = 1u128.wrapping_shl(128 - cidr.prefix);
                            start.saturating_add(host_count).saturating_sub(1)
                        };
                        get_or_insert_tag_index(&mut tag_indexes, &country_code)
                            .ipv6_ranges
                            .push(Ipv6Range { start, end });
                        count += 1;
                        ipv6_count += 1;
                    }
                    len => {
                        tracing::debug!(
                            target = "geoip",
                            len,
                            "skipping CIDR with unsupported IP length"
                        );
                    }
                }
            }
        }

        for index in tag_indexes.values_mut() {
            index.finalize();
        }

        Ok(ParsedGeoIp {
            tag_indexes,
            count,
            ipv4_count,
            ipv6_count,
            source: ".dat file",
        })
    }

    /// 用解析结果整体替换索引
    /// Replace the indexes wholesale with a parsed result
    ///
    /// GeoIP 只有一个数据文件（`geoip_dat_path` 是单值），所以这里不需要
    /// geosite 那套按来源记账：两个 loader 本来就是整体替换，解析失败时
    /// 管理器保持原样，失败原子性已经成立。
    /// GeoIP has a single data file, `geoip_dat_path` being one value, so none
    /// of geosite's per-source bookkeeping applies here: both loaders already
    /// replace wholesale and a failed parse leaves the manager untouched, so
    /// failure atomicity was never the gap.
    pub fn apply_parsed(&mut self, parsed: ParsedGeoIp) -> usize {
        self.tag_indexes = parsed.tag_indexes;

        tracing::info!(
            geoip_entries = parsed.count,
            geoip_tags = self.tag_indexes.len(),
            ipv4_entries = parsed.ipv4_count,
            ipv6_entries = parsed.ipv6_count,
            merged_ranges = self.ip_range_count(),
            source = parsed.source,
            "loaded GeoIP tag indexes"
        );

        parsed.count
    }

    pub fn load_from_v2ray_file(&mut self, path: &Path) -> anyhow::Result<usize> {
        let parsed = Self::parse_v2ray_file(path)?;
        Ok(self.apply_parsed(parsed))
    }

    /// 按扩展名解析数据文件里 `tags` 这几个标签（不分大小写），其余条目不解，不触碰管理器状态：
    /// `.dat` 按条目读（见 [`Self::parse_dat_file`]），其余按 JSON 读（[`Self::parse_v2ray_file`]）。
    /// 文件里没有的标签记一条告警，用它的规则不会命中。
    /// Parses the `tags` of a data file (ignoring case) by its extension, leaving the other
    /// entries undecoded and the manager untouched: `.dat` is read entry by entry (see
    /// [`Self::parse_dat_file`]) and anything else as JSON ([`Self::parse_v2ray_file`]). Tags
    /// the file lacks are logged as a warning, since rules using them never match.
    pub fn parse_file(path: &Path, tags: &[String]) -> anyhow::Result<ParsedGeoIp> {
        let wanted: FxHashSet<String> = tags.iter().map(|tag| tag.to_ascii_uppercase()).collect();
        let is_wanted = |code: &str| wanted.contains(code);
        let is_dat = path
            .extension()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s.eq_ignore_ascii_case("dat"));
        let parsed = if is_dat {
            Self::parse_dat_entries(path, &is_wanted)
        } else {
            Self::parse_v2ray_entries(path, &is_wanted)
        }?;

        let mut missing: Vec<&str> = wanted
            .iter()
            .map(String::as_str)
            .filter(|tag| !parsed.tag_indexes.contains_key(*tag))
            .collect();
        if !missing.is_empty() {
            missing.sort_unstable();
            tracing::warn!(target = "geoip", path = %path.display(), tags = ?missing, "GeoIP tags used by rules are not in the data file and never match");
        }
        Ok(parsed)
    }

    /// 解析 JSON 格式的数据文件，不触碰管理器状态
    /// Parse a JSON data file without touching manager state
    pub fn parse_v2ray_file(path: &Path) -> anyhow::Result<ParsedGeoIp> {
        Self::parse_v2ray_entries(path, &|_| true)
    }

    /// 解析 JSON 数据文件里 `wanted` 认可的条目（参数是大写的国家代码或标签）
    /// Parses the entries of a JSON data file that `wanted` accepts (given the uppercase
    /// country code or tag)
    fn parse_v2ray_entries(
        path: &Path,
        wanted: &dyn Fn(&str) -> bool,
    ) -> anyhow::Result<ParsedGeoIp> {
        let data = std::fs::read_to_string(path)?;
        let list: V2RayGeoIPList = serde_json::from_str(&data)?;
        let mut tag_indexes: FxHashMap<Arc<str>, GeoIpTagIndex> = FxHashMap::default();
        let mut count = 0;
        let mut ipv4_count = 0;
        let mut ipv6_count = 0;

        for geoip in list.entries {
            let tag = geoip.country_code.to_ascii_uppercase();
            if tag.is_empty() || !wanted(&tag) {
                continue;
            }
            let index = get_or_insert_tag_index(&mut tag_indexes, &tag);

            for ip_str in &geoip.ips {
                match ip_str.parse::<ipnet::IpNet>() {
                    Ok(ipnet::IpNet::V4(v4net)) => {
                        index.ipv4_ranges.push(Ipv4Range {
                            start: u32::from(v4net.network()),
                            end: u32::from(v4net.broadcast()),
                        });
                        count += 1;
                        ipv4_count += 1;
                    }
                    Ok(ipnet::IpNet::V6(v6net)) => {
                        index.ipv6_ranges.push(Ipv6Range {
                            start: u128::from(v6net.network()),
                            end: u128::from(v6net.broadcast()),
                        });
                        count += 1;
                        ipv6_count += 1;
                    }
                    Err(_) => continue,
                }
            }
        }

        for index in tag_indexes.values_mut() {
            index.finalize();
        }

        Ok(ParsedGeoIp {
            tag_indexes,
            count,
            ipv4_count,
            ipv6_count,
            source: "JSON file",
        })
    }

    /// 转换 .dat 为 MMDB 格式
    /// Convert .dat to MMDB format
    ///
    /// # 参数 / Parameters
    /// - `dat_path`: V2Ray .dat 文件路径 / V2Ray .dat file path
    /// - `mmdb_path`: 输出 MMDB 文件路径 / Output MMDB file path
    /// - `filter_countries`: 可选的国家代码过滤列表 / Optional country code filter list
    pub fn convert_dat_to_mmdb(
        dat_path: &Path,
        mmdb_path: &Path,
        filter_countries: Option<&[String]>,
    ) -> anyhow::Result<ConversionStats> {
        convert_dat_to_mmdb(dat_path, mmdb_path, filter_countries)
    }

    /// 自动转换并加载
    /// Auto-convert and load
    ///
    /// 如果 MMDB 文件不存在但 .dat 文件存在，自动转换并加载
    /// If MMDB file doesn't exist but .dat file exists, auto-convert and load
    ///
    /// # 参数 / Parameters
    /// - `dat_path`: V2Ray .dat 文件路径 / V2Ray .dat file path
    /// - `mmdb_path`: 输出 MMDB 文件路径 / Output MMDB file path
    pub fn auto_convert_and_load(dat_path: &Path, mmdb_path: &Path) -> anyhow::Result<Self> {
        // Check if MMDB already exists
        if mmdb_path.exists() {
            tracing::info!(
                mmdb = %mmdb_path.display(),
                "MMDB file already exists, loading directly"
            );
            return Self::new(Some(mmdb_path.to_string_lossy().to_string()));
        }

        // Check if .dat file exists
        if !dat_path.exists() {
            anyhow::bail!(
                "Neither MMDB nor .dat file exists: mmdb={}, dat={}",
                mmdb_path.display(),
                dat_path.display()
            );
        }

        tracing::info!(
            dat = %dat_path.display(),
            mmdb = %mmdb_path.display(),
            "MMDB not found, converting from .dat file"
        );

        // Perform conversion
        let stats = Self::convert_dat_to_mmdb(dat_path, mmdb_path, None)?;

        tracing::info!(
            "Conversion successful: {} countries, {} IPv4 ranges, {} IPv6 ranges",
            stats.countries_count,
            stats.ipv4_ranges_count,
            stats.ipv6_ranges_count
        );

        // Load the converted MMDB
        Self::new(Some(mmdb_path.to_string_lossy().to_string()))
    }
}

/// 从 `file` 读一个 protobuf 变长整数，`remaining` 是文件里还剩的字节数
/// Reads a protobuf varint from `file`, `remaining` being the bytes left in the file
fn read_varint(file: &mut impl Read, remaining: &mut u64) -> anyhow::Result<u64> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        anyhow::ensure!(
            *remaining > 0,
            "truncated .dat file: a varint runs past the end"
        );
        let mut byte = [0u8];
        file.read_exact(&mut byte)?;
        *remaining -= 1;
        value |= u64::from(byte[0] & 0x7F) << shift;
        if byte[0] & 0x80 == 0 {
            return Ok(value);
        }
    }
    anyhow::bail!("invalid varint in .dat file")
}

fn get_or_insert_tag_index<'a>(
    indexes: &'a mut FxHashMap<Arc<str>, GeoIpTagIndex>,
    tag: &str,
) -> &'a mut GeoIpTagIndex {
    if !indexes.contains_key(tag) {
        indexes.insert(Arc::from(tag), GeoIpTagIndex::default());
    }
    indexes
        .get_mut(tag)
        .expect("GeoIP tag index must exist after insertion")
}

fn merge_ipv4_ranges(ranges: &mut Vec<Ipv4Range>) {
    ranges.sort_unstable_by_key(|range| range.start);
    let mut merged: Vec<Ipv4Range> = Vec::with_capacity(ranges.len());
    for range in ranges.drain(..) {
        if let Some(last) = merged.last_mut()
            && range.start <= last.end.saturating_add(1)
        {
            last.end = last.end.max(range.end);
            continue;
        }
        merged.push(range);
    }
    *ranges = merged;
}

fn merge_ipv6_ranges(ranges: &mut Vec<Ipv6Range>) {
    ranges.sort_unstable_by_key(|range| range.start);
    let mut merged: Vec<Ipv6Range> = Vec::with_capacity(ranges.len());
    for range in ranges.drain(..) {
        if let Some(last) = merged.last_mut()
            && range.start <= last.end.saturating_add(1)
        {
            last.end = last.end.max(range.end);
            continue;
        }
        merged.push(range);
    }
    *ranges = merged;
}

fn most_specific_ipv4(ranges: &[Ipv4Range], ip: u32) -> Option<Ipv4Range> {
    let index = ranges.partition_point(|range| range.start <= ip);
    ranges[..index]
        .iter()
        .filter(|range| range.end >= ip)
        .min_by_key(|range| (range.end - range.start, std::cmp::Reverse(range.start)))
        .copied()
}

fn most_specific_ipv6(ranges: &[Ipv6Range], ip: u128) -> Option<Ipv6Range> {
    let index = ranges.partition_point(|range| range.start <= ip);
    ranges[..index]
        .iter()
        .filter(|range| range.end >= ip)
        .min_by_key(|range| (range.end - range.start, std::cmp::Reverse(range.start)))
        .copied()
}

/// 是否两个字母的国家代码；有 MMDB 时只有这样的标签查 MMDB
/// Whether a tag is a two-letter country code; with an MMDB only such tags are looked up there
#[inline]
pub(crate) fn is_country_tag(tag: &str) -> bool {
    tag.len() == 2 && tag.bytes().all(|byte| byte.is_ascii_alphabetic())
}

fn is_more_specific(
    current: &Option<(Arc<str>, u128, u128)>,
    tag: &str,
    start: u128,
    end: u128,
) -> bool {
    match current {
        None => true,
        Some((current_tag, current_start, current_end)) => {
            let span = end - start;
            let current_span = *current_end - *current_start;
            span < current_span
                || (span == current_span && start > *current_start)
                || (span == current_span && start == *current_start && tag < current_tag.as_ref())
        }
    }
}

/// 检测 IP 是否为私有地址 / Detect if IP is private address
#[inline]
pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_loopback() || ipv4.is_private() || ipv4.is_link_local() || ipv4.is_broadcast()
        }
        IpAddr::V6(ipv6) => {
            let seg0 = ipv6.segments()[0];
            ipv6.is_loopback()
                || ipv6.is_unspecified()
                || (seg0 & 0xffc0) == 0xfe80  // Link-local addresses (fe80::/10)
                || (seg0 & 0xfe00) == 0xfc00 // Unique Local Addresses (fc00::/7)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造 V2Ray .dat 格式的 protobuf 字节（含 v4 和/或 v6 CIDR）
    /// Build V2Ray .dat protobuf bytes (with v4 and/or v6 CIDRs)
    fn build_dat(country: &str, v4: Option<([u8; 4], u8)>, v6: Option<([u8; 16], u8)>) -> Vec<u8> {
        let mut entry = Vec::new();
        // country_code (field 1, tag 0x0A)
        entry.push(0x0A);
        entry.push(country.len() as u8);
        entry.extend_from_slice(country.as_bytes());
        // cidr (field 2, tag 0x12) —— 每个 CIDR 一个独立 message (repeated, 与真实 .dat 一致)
        let mut push_cidr = |ip_bytes: &[u8], prefix: u8| {
            let mut msg = Vec::new();
            msg.push(0x0A); // field 1: ip (bytes)
            msg.push(ip_bytes.len() as u8);
            msg.extend_from_slice(ip_bytes);
            msg.push(0x10); // field 2: prefix (varint)
            msg.push(prefix);
            entry.push(0x12);
            entry.push(msg.len() as u8);
            entry.extend_from_slice(&msg);
        };
        if let Some((ip, prefix)) = v4 {
            push_cidr(&ip, prefix);
        }
        if let Some((ip, prefix)) = v6 {
            push_cidr(&ip, prefix);
        }

        let mut dat = Vec::new();
        dat.push(0x0A); // outer field: GeoIP entry
        dat.push(entry.len() as u8);
        dat.extend_from_slice(&entry);
        dat
    }

    #[test]
    fn test_load_dat_includes_ipv6() {
        // 2001:db8::/32 (v6) + 1.2.3.0/24 (v4)
        let v6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let v4: [u8; 4] = [1, 2, 3, 0];
        let dat = build_dat("CN", Some((v4, 24)), Some((v6, 32)));

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("geoip_test_v6.dat");
        std::fs::write(&path, &dat).unwrap();

        let mut mgr = GeoIpManager::new(None).unwrap();
        let count = mgr.load_from_dat_file(&path).unwrap();
        assert_eq!(count, 2, "应加载 2 条（v4 + v6）");
        assert_eq!(mgr.ip_range_count(), 2, "IPv4 和 IPv6 段都应保留");

        // IPv6 查询应匹配国家 / IPv6 lookup should match the country
        let ip: std::net::IpAddr = "2001:db8::1".parse().unwrap();
        let res = mgr.lookup(ip);
        assert_eq!(res.country_code.as_deref(), Some("CN"));

        // 不在段内的 IPv6 不应误匹配 / IPv6 outside the range must not match
        let miss: std::net::IpAddr = "2001:db9::1".parse().unwrap();
        assert_eq!(mgr.lookup(miss).country_code, None);

        // IPv4 查询仍然正常 / IPv4 lookup still works
        let v4ip: std::net::IpAddr = "1.2.3.5".parse().unwrap();
        assert_eq!(mgr.lookup(v4ip).country_code.as_deref(), Some("CN"));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_load_json_includes_ipv6() {
        let json = r#"{
            "entries": [
                {
                    "country_code": "JP",
                    "ips": ["2001:db8:1::/48", "198.51.100.0/24"]
                }
            ]
        }"#;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("geoip_test_v6.json");
        std::fs::write(&path, json).unwrap();

        let mut mgr = GeoIpManager::new(None).unwrap();
        let count = mgr.load_from_v2ray_file(&path).unwrap();
        assert_eq!(count, 2, "JSON 应加载 v4 + v6");
        assert_eq!(mgr.ip_range_count(), 2, "JSON IPv4 和 IPv6 段都应保留");

        let ip: std::net::IpAddr = "2001:db8:1::1234".parse().unwrap();
        let res = mgr.lookup(ip);
        assert_eq!(res.country_code.as_deref(), Some("JP"));

        let _ = std::fs::remove_file(&path);
    }

    /// 解析与应用分开之后，解析失败必须完全不碰管理器：它拿不到 &mut self，
    /// 没有机会写进去。原先整个重载在一个方法里，坏文件解析到一半才返回错误。
    /// With parsing split from applying, a failed parse cannot touch the manager
    /// at all, because it never receives &mut self. The whole reload used to sit
    /// in one method, where a bad file failed part way through.
    #[test]
    fn a_failed_parse_cannot_touch_the_manager() {
        let dir = tempfile::tempdir().unwrap();
        let good = dir.path().join("good.dat");
        let bad = dir.path().join("bad.dat");
        std::fs::write(&good, build_dat("CN", Some(([10, 0, 0, 0], 8)), None)).unwrap();
        std::fs::write(&bad, b"not a protobuf at all").unwrap();

        let mut manager = GeoIpManager::new(None).unwrap();
        manager.load_from_dat_file(&good).unwrap();
        assert!(manager.matches_tag("10.1.2.3".parse().unwrap(), "cn"));

        assert!(
            GeoIpManager::parse_dat_file(&bad).is_err(),
            "a corrupt .dat must fail to parse"
        );

        assert!(
            manager.matches_tag("10.1.2.3".parse().unwrap(), "cn"),
            "a failed parse must leave the loaded data alone"
        );
    }

    /// 构造嵌套重叠的 .dat(CN /8 大网段内嵌 US /24,IPv4+IPv6)
    /// Build a .dat with nested overlapping networks (CN /8 containing US /24)
    fn build_nested_dat() -> Vec<u8> {
        use prost::Message;
        let v6_cn: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let v6_us: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let list = super::super::geoip_proto::GeoIPList {
            entry: vec![
                super::super::geoip_proto::GeoIP {
                    country_code: "CN".to_string(),
                    cidr: vec![
                        super::super::geoip_proto::Cidr {
                            ip: vec![10, 0, 0, 0],
                            prefix: 8,
                        },
                        super::super::geoip_proto::Cidr {
                            ip: v6_cn.to_vec(),
                            prefix: 32,
                        },
                    ],
                },
                super::super::geoip_proto::GeoIP {
                    country_code: "US".to_string(),
                    cidr: vec![
                        super::super::geoip_proto::Cidr {
                            ip: vec![10, 1, 2, 0],
                            prefix: 24,
                        },
                        super::super::geoip_proto::Cidr {
                            ip: v6_us.to_vec(),
                            prefix: 48,
                        },
                    ],
                },
            ],
        };
        list.encode_to_vec()
    }

    #[test]
    fn test_most_specific_handles_crossing_overlaps() {
        let ipv4_ranges = [
            Ipv4Range { start: 40, end: 55 },
            Ipv4Range { start: 45, end: 70 },
        ];
        let ipv4_match = most_specific_ipv4(&ipv4_ranges, 50).unwrap();
        assert_eq!((ipv4_match.start, ipv4_match.end), (40, 55));

        let ipv6_ranges = [
            Ipv6Range { start: 40, end: 55 },
            Ipv6Range { start: 45, end: 70 },
        ];
        let ipv6_match = most_specific_ipv6(&ipv6_ranges, 50).unwrap();
        assert_eq!((ipv6_match.start, ipv6_match.end), (40, 55));
    }

    #[test]
    fn test_lookup_nested_overlap_most_specific() {
        let dat = build_nested_dat();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("geoip_test_nested.dat");
        std::fs::write(&path, &dat).unwrap();

        let mut mgr = GeoIpManager::new(None).unwrap();
        mgr.load_from_dat_file(&path).unwrap();

        let us: IpAddr = "10.1.2.5".parse().unwrap();
        assert_eq!(mgr.lookup(us).country_code.as_deref(), Some("US"));
        let b1: IpAddr = "10.1.2.255".parse().unwrap();
        assert_eq!(mgr.lookup(b1).country_code.as_deref(), Some("US"));
        let cn: IpAddr = "10.1.3.5".parse().unwrap();
        assert_eq!(mgr.lookup(cn).country_code.as_deref(), Some("CN"));
        let b2: IpAddr = "10.1.3.0".parse().unwrap();
        assert_eq!(mgr.lookup(b2).country_code.as_deref(), Some("CN"));
        let cn2: IpAddr = "10.200.1.1".parse().unwrap();
        assert_eq!(mgr.lookup(cn2).country_code.as_deref(), Some("CN"));

        let us6: IpAddr = "2001:db8:1::1".parse().unwrap();
        assert_eq!(mgr.lookup(us6).country_code.as_deref(), Some("US"));
        let cn6: IpAddr = "2001:db8:2::1".parse().unwrap();
        assert_eq!(mgr.lookup(cn6).country_code.as_deref(), Some("CN"));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_lookup_preserves_same_tag_nested_specificity() {
        let json = r#"{
            "entries": [
                {
                    "country_code": "CN",
                    "ips": ["10.0.0.0/8", "10.1.0.0/16", "2001:db8::/32", "2001:db8:1::/48"]
                },
                {
                    "country_code": "US",
                    "ips": ["10.0.0.0/12", "2001:db8::/40"]
                }
            ]
        }"#;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("geoip_test_same_tag_nested.json");
        std::fs::write(&path, json).unwrap();

        let mut mgr = GeoIpManager::new(None).unwrap();
        assert_eq!(mgr.load_from_v2ray_file(&path).unwrap(), 6);

        let cn4: IpAddr = "10.1.1.1".parse().unwrap();
        assert!(mgr.matches_tag(cn4, "CN"));
        assert!(mgr.matches_tag(cn4, "US"));
        assert_eq!(mgr.lookup(cn4).country_code.as_deref(), Some("CN"));
        let us4: IpAddr = "10.2.1.1".parse().unwrap();
        assert_eq!(mgr.lookup(us4).country_code.as_deref(), Some("US"));

        let cn6: IpAddr = "2001:db8:1::1".parse().unwrap();
        assert!(mgr.matches_tag(cn6, "CN"));
        assert!(mgr.matches_tag(cn6, "US"));
        assert_eq!(mgr.lookup(cn6).country_code.as_deref(), Some("CN"));
        let us6: IpAddr = "2001:db8:2::1".parse().unwrap();
        assert_eq!(mgr.lookup(us6).country_code.as_deref(), Some("US"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_overlapping_dat_tags_match_independently() {
        let mut dat = build_dat("AU", Some(([1, 1, 1, 0], 24)), None);
        dat.extend(build_dat("cloudflare", Some(([1, 1, 1, 0], 24)), None));

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("geoip_test_overlapping_tags.dat");
        std::fs::write(&path, &dat).unwrap();

        let mut mgr = GeoIpManager::new(None).unwrap();
        assert_eq!(mgr.load_from_dat_file(&path).unwrap(), 2);

        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        assert!(mgr.matches_tag(ip, "AU"));
        assert!(mgr.matches_tag(ip, "cloudflare"));
        assert!(!mgr.matches_tag(ip, "netflix"));
        assert!(mgr.matches_any_tag(ip, &[Arc::from("NETFLIX"), Arc::from("CLOUDFLARE")]));
        assert_eq!(mgr.lookup(ip).country_code.as_deref(), Some("AU"));
        assert_eq!(
            mgr.lookup_tags(ip),
            vec![Arc::from("AU"), Arc::from("CLOUDFLARE")]
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_lookup_preserves_named_tag_only_dat_behavior() {
        let dat = build_dat("cloudflare", Some(([1, 1, 1, 0], 24)), None);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("geoip_test_named_tag_only.dat");
        std::fs::write(&path, &dat).unwrap();

        let mut mgr = GeoIpManager::new(None).unwrap();
        mgr.load_from_dat_file(&path).unwrap();

        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        assert_eq!(mgr.lookup(ip).country_code.as_deref(), Some("CLOUDFLARE"));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_mmdb_country_precedence_keeps_named_dat_tags() {
        let network = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mmdb_source = build_dat("US", None, Some((network, 32)));
        let mut dat = build_dat("CN", None, Some((network, 16)));
        dat.extend(build_dat("CLOUDFLARE", None, Some((network, 16))));
        let temp_dir = tempfile::tempdir().unwrap();
        let mmdb_source_path = temp_dir.path().join("geoip_test_mmdb_source.dat");
        let dat_path = temp_dir.path().join("geoip_test_mmdb_precedence.dat");
        let mmdb_path = temp_dir.path().join("geoip_test_mmdb_precedence.mmdb");
        std::fs::write(&mmdb_source_path, mmdb_source).unwrap();
        std::fs::write(&dat_path, dat).unwrap();
        GeoIpManager::convert_dat_to_mmdb(&mmdb_source_path, &mmdb_path, None).unwrap();

        let mut mgr = GeoIpManager::new(Some(mmdb_path.to_string_lossy().into_owned())).unwrap();
        mgr.load_from_dat_file(&dat_path).unwrap();

        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(mgr.matches_tag(ip, "US"));
        assert!(!mgr.matches_tag(ip, "CN"));
        assert!(mgr.matches_tag(ip, "CLOUDFLARE"));
        assert!(mgr.matches_any_tag(ip, &[Arc::from("CN"), Arc::from("CLOUDFLARE")]));
        assert_eq!(
            mgr.lookup_tags(ip),
            vec![Arc::from("CLOUDFLARE"), Arc::from("US")]
        );

        let mmdb_miss: IpAddr = "2001:db9::1".parse().unwrap();
        assert!(!mgr.matches_tag(mmdb_miss, "CN"));
        assert!(mgr.matches_tag(mmdb_miss, "CLOUDFLARE"));
        assert_eq!(mgr.lookup(mmdb_miss).country_code, None);
        assert_eq!(mgr.lookup_tags(mmdb_miss), vec![Arc::from("CLOUDFLARE")]);

        drop(mgr);
        let _ = std::fs::remove_file(mmdb_source_path);
        let _ = std::fs::remove_file(dat_path);
        let _ = std::fs::remove_file(mmdb_path);
    }

    fn tags(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| name.to_string()).collect()
    }

    /// 只解析规则用到的标签，请求不分大小写；别的条目不留，文件里没有的标签不算错
    /// Only the tags rules use are parsed, requested in any case; other entries are not kept,
    /// and a tag the file lacks is not an error
    #[test]
    fn parse_file_keeps_only_the_wanted_dat_tags() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("geoip.dat");
        let mut dat = build_dat("CN", Some(([10, 0, 0, 0], 8)), None);
        dat.extend(build_dat("US", Some(([20, 0, 0, 0], 8)), None));
        dat.extend(build_dat("private", Some(([192, 168, 0, 0], 16)), None));
        std::fs::write(&path, &dat).unwrap();

        let mut manager = GeoIpManager::new(None).unwrap();
        let parsed = GeoIpManager::parse_file(&path, &tags(&["cn", "PRIVATE", "XX"])).unwrap();
        assert_eq!(manager.apply_parsed(parsed), 2);
        assert!(manager.matches_tag("10.1.2.3".parse().unwrap(), "CN"));
        assert!(manager.matches_tag("192.168.1.1".parse().unwrap(), "private"));
        assert!(
            !manager.matches_tag("20.1.2.3".parse().unwrap(), "US"),
            "a tag rules do not use must not be loaded"
        );
        assert_eq!(manager.ip_range_count(), 2);
    }

    /// JSON 数据文件同样只留用到的标签 / A JSON data file keeps only the tags used too
    #[test]
    fn parse_file_keeps_only_the_wanted_json_tags() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("geoip.json");
        std::fs::write(
            &path,
            r#"{"entries":[
                {"country_code":"JP","ips":["198.51.100.0/24"]},
                {"country_code":"US","ips":["203.0.113.0/24"]}
            ]}"#,
        )
        .unwrap();

        let mut manager = GeoIpManager::new(None).unwrap();
        manager.apply_parsed(GeoIpManager::parse_file(&path, &tags(&["jp"])).unwrap());
        assert!(manager.matches_tag("198.51.100.7".parse().unwrap(), "JP"));
        assert!(!manager.matches_tag("203.0.113.7".parse().unwrap(), "US"));
        assert_eq!(manager.ip_range_count(), 1);
    }

    /// 条目里的字段不论先后，国家代码写在网段后面也认得出来；文件顶层不认识的字段跳过
    /// An entry's fields come in any order, so a country code written after the networks is
    /// still recognised; unknown fields at the top of the file are skipped
    #[test]
    fn parse_file_reads_entries_whatever_their_field_order() {
        // CIDR { ip = 10.0.0.0, prefix = 8 }, then reverse_match = true (field 3), then
        // country_code = "CN"
        let cidr = [0x0A, 4, 10, 0, 0, 0, 0x10, 8];
        let mut entry = vec![0x12, cidr.len() as u8];
        entry.extend(cidr);
        entry.extend([0x18, 0x01]);
        entry.extend([0x0A, 2, b'C', b'N']);
        // 不认识的顶层字段：2 号变长整数、3 号字节串、4 号 32 位、5 号 64 位
        // Unknown top-level fields: field 2 a varint, field 3 bytes, field 4 32-bit, field 5 64-bit
        let mut dat = vec![0x10, 0x01, 0x1A, 3, 1, 2, 3, 0x25, 1, 2, 3, 4];
        dat.extend([0x29, 1, 2, 3, 4, 5, 6, 7, 8]);
        dat.extend([0x0A, entry.len() as u8]);
        dat.extend(&entry);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("geoip.dat");
        std::fs::write(&path, &dat).unwrap();

        let mut manager = GeoIpManager::new(None).unwrap();
        manager.apply_parsed(GeoIpManager::parse_file(&path, &tags(&["CN"])).unwrap());
        assert!(manager.matches_tag("10.1.2.3".parse().unwrap(), "CN"));
    }

    /// 国家代码写了不止一次时和 protobuf 一样以最后一次为准
    /// A country code written more than once counts by its last value, as in protobuf
    #[test]
    fn the_last_country_code_of_an_entry_counts() {
        let cidr = [0x0A, 4, 10, 0, 0, 0, 0x10, 8];
        let mut entry = vec![0x0A, 2, b'U', b'S', 0x12, cidr.len() as u8];
        entry.extend(cidr);
        entry.extend([0x0A, 2, b'C', b'N']);
        let mut dat = vec![0x0A, entry.len() as u8];
        dat.extend(&entry);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("geoip.dat");
        std::fs::write(&path, &dat).unwrap();

        let only_us = GeoIpManager::parse_file(&path, &tags(&["US"])).unwrap();
        assert_eq!(only_us.count, 0, "the entry is CN, not US");
        let mut manager = GeoIpManager::new(None).unwrap();
        manager.apply_parsed(GeoIpManager::parse_file(&path, &tags(&["CN"])).unwrap());
        assert!(manager.matches_tag("10.1.2.3".parse().unwrap(), "CN"));
    }

    /// 截断的文件整份拒绝，不论读全部还是只读部分标签
    /// A truncated file is rejected whole, whether every tag or only some are read
    #[test]
    fn a_truncated_dat_fails_to_parse() {
        let dat = build_dat("CN", Some(([10, 0, 0, 0], 8)), None);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("geoip.dat");
        std::fs::write(&path, &dat[..dat.len() - 2]).unwrap();

        assert!(GeoIpManager::parse_dat_file(&path).is_err());
        assert!(GeoIpManager::parse_file(&path, &tags(&["CN"])).is_err());
    }

    /// MMDB 的每条数据记录加载时都进了表，查表和逐条解码得到同样的国家代码
    /// Every MMDB data record is in the table after loading, and the table gives the same
    /// country code as decoding the record
    #[test]
    fn every_mmdb_record_is_in_the_country_table() {
        let mut source = build_dat("CN", Some(([10, 0, 0, 0], 8)), None);
        source.extend(build_dat(
            "US",
            Some(([20, 0, 0, 0], 8)),
            Some((
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                32,
            )),
        ));
        let dir = tempfile::tempdir().unwrap();
        let source_path = dir.path().join("source.dat");
        let mmdb_path = dir.path().join("test.mmdb");
        std::fs::write(&source_path, source).unwrap();
        GeoIpManager::convert_dat_to_mmdb(&source_path, &mmdb_path, None).unwrap();

        let mmdb = Mmdb::open(mmdb_path.to_str().unwrap()).unwrap();
        for (ip, want) in [
            ("10.1.2.3", Some("CN")),
            ("20.1.2.3", Some("US")),
            ("2001:db8::1", Some("US")),
            ("30.1.2.3", None),
        ] {
            let ip: IpAddr = ip.parse().unwrap();
            let found = mmdb.reader.lookup(ip).unwrap();
            if let Some(offset) = found.offset() {
                assert!(
                    mmdb.countries.contains_key(&offset),
                    "{ip}: record not indexed"
                );
            }
            assert_eq!(record_country(&found), want, "{ip}");
            assert_eq!(mmdb.country(ip), want, "{ip}");
        }
    }
}
