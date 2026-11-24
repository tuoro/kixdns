use std::hash::{DefaultHasher, Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::Context;
use prost::Message;
use rustc_hash::{FxHashMap, FxHashSet};
use serde::Deserialize;

use super::dat_reader::DatReader;

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

/// 一段连续的地址，两端都含：u32 是 IPv4，u128 是 IPv6
/// A run of addresses, both ends included: u32 for IPv4, u128 for IPv6
#[derive(Debug, Clone, Copy, Hash)]
struct AddrRange<T> {
    start: T,
    end: T,
}

/// 区间的端点：IPv4 的 u32 和 IPv6 的 u128 / A range bound: IPv4's u32 and IPv6's u128
trait Bound: Copy + Ord {
    /// 下一个地址，到顶就不再加 / The next address, saturating at the top
    fn next(self) -> Self;
}

impl Bound for u32 {
    fn next(self) -> Self {
        self.saturating_add(1)
    }
}

impl Bound for u128 {
    fn next(self) -> Self {
        self.saturating_add(1)
    }
}

impl<T: Bound> AddrRange<T> {
    /// 按起点排好，合并重叠和相邻的区间 / Sort by start and merge overlapping and adjacent ranges
    fn merge(ranges: &mut Vec<Self>) {
        ranges.sort_unstable_by_key(|range| range.start);
        let mut merged: Vec<Self> = Vec::with_capacity(ranges.len());
        for range in ranges.drain(..) {
            if let Some(last) = merged.last_mut()
                && range.start <= last.end.next()
            {
                last.end = last.end.max(range.end);
                continue;
            }
            merged.push(range);
        }
        *ranges = merged;
    }

    /// 排好、合并过的 `ranges` 里有没有含 `ip` 的 / Whether sorted, merged `ranges` hold `ip`
    #[inline]
    fn any_contains(ranges: &[Self], ip: T) -> bool {
        let index = ranges.partition_point(|range| range.start <= ip);
        index > 0 && ranges[index - 1].end >= ip
    }
}

#[derive(Debug, Default)]
struct GeoIpTagIndex {
    ipv4_ranges: Vec<AddrRange<u32>>,
    ipv6_ranges: Vec<AddrRange<u128>>,
    /// 合并好的网段的指纹，[`Self::finalize`] 时算出：同样的网段不论怎么写、按什么先后写都是这个数（见
    /// [`GeoIpManager::fingerprints`]）
    /// The fingerprint of the merged ranges, worked out by [`Self::finalize`]: the same networks
    /// give this number however and in whatever order they are written (see
    /// [`GeoIpManager::fingerprints`])
    fingerprint: u64,
}

impl GeoIpTagIndex {
    fn finalize(&mut self) {
        AddrRange::merge(&mut self.ipv4_ranges);
        AddrRange::merge(&mut self.ipv6_ranges);
        let mut hasher = DefaultHasher::new();
        (&self.ipv4_ranges, &self.ipv6_ranges).hash(&mut hasher);
        self.fingerprint = hasher.finish();
    }

    #[inline]
    fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => AddrRange::any_contains(&self.ipv4_ranges, u32::from(ip)),
            IpAddr::V6(ip) => AddrRange::any_contains(&self.ipv6_ranges, u128::from(ip)),
        }
    }

    #[inline]
    fn range_count(&self) -> usize {
        self.ipv4_ranges.len() + self.ipv6_ranges.len()
    }
}

/// 一个数据文件解析出的 GeoIP 索引，尚未进入管理器。读取、解码、建索引、finalize 都在解析时、管理器的锁外做完，
/// 调用方只在把它换进去时短暂持写锁（见 [`GeoIpManager::apply_parsed`]）。finalize 是整个重载里最重的一段：要排序
/// 并合并每个标签的全部网段
/// GeoIP indexes parsed out of one data file, not yet applied to a manager. Reading,
/// decoding, building the indexes and finalising are all done while parsing, outside the
/// manager's lock, and callers hold the write lock only while swapping them in (see
/// [`GeoIpManager::apply_parsed`]). Finalising is the heaviest part of a reload: it sorts and
/// merges every tag's networks
pub struct ParsedGeoIp {
    tag_indexes: FxHashMap<Arc<str>, GeoIpTagIndex>,
    count: usize,
    ipv4_count: usize,
    ipv6_count: usize,
    /// 只用于日志，区分 .dat 与 JSON / For the log line only, .dat versus JSON
    source: &'static str,
}

impl ParsedGeoIp {
    /// 解析出的标签数（只解析了规则用到的那些）/ How many tags were parsed (only those rules use are)
    pub fn tag_count(&self) -> usize {
        self.tag_indexes.len()
    }

    /// 每个标签和它的网段：合并过的区间拆成恰好盖住它们的最少的 CIDR
    /// Each tag with its networks: the merged ranges cut into the fewest CIDRs covering exactly them
    pub(super) fn networks_by_tag(
        &self,
    ) -> impl Iterator<Item = (&str, impl Iterator<Item = ipnet::IpNet> + '_)> {
        self.tag_indexes.iter().map(|(tag, index)| {
            let v4 = index.ipv4_ranges.iter().flat_map(|range| {
                ipnet::Ipv4Subnets::new(range.start.into(), range.end.into(), 0)
                    .map(ipnet::IpNet::V4)
            });
            let v6 = index.ipv6_ranges.iter().flat_map(|range| {
                ipnet::Ipv6Subnets::new(range.start.into(), range.end.into(), 0)
                    .map(ipnet::IpNet::V6)
            });
            (&**tag, v4.chain(v6))
        })
    }
}

/// 一个 GeoIP 管理器里的数据的指纹：每个标签的网段的，和 MMDB 的（见 [`GeoIpManager::fingerprints`]）
/// The fingerprints of the data in a GeoIP manager: each tag's networks', and the MMDB's (see
/// [`GeoIpManager::fingerprints`])
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GeoIpFingerprints {
    /// 每个标签（大写）的网段的 / Each tag's (uppercase) networks'
    pub tags: FxHashMap<Arc<str>, u64>,
    /// MMDB 的，没有 MMDB 时是 None / The MMDB's, None without one
    pub mmdb: Option<u64>,
}

/// 默认的管理器没有 MMDB、也没有标签 / The default manager has no MMDB and no tags
#[derive(Default)]
pub struct GeoIpManager {
    /// MaxMind DB 和它每条数据记录的国家代码；重载时文件没变就和在用的那份共用（见 [`Self::use_mmdb`]）
    /// The MaxMind DB and the country code of each of its data records, shared with the one in
    /// use on a reload while the file stays as it was (see [`Self::use_mmdb`])
    mmdb: Option<Arc<Mmdb>>,
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
    /// 文件内容的指纹：同样的库再读一遍还是这个数（见 [`GeoIpManager::fingerprints`]）/ The
    /// fingerprint of the file's content, the same number for the same database read again (see
    /// [`GeoIpManager::fingerprints`])
    fingerprint: u64,
    /// 数据记录在文件里的位置 → 国家代码 / A data record's offset in the file → its country code
    countries: FxHashMap<usize, Option<Arc<str>>>,
    /// 读的是哪个文件、读的时候那个文件什么样 / Which file was read, and what it was like then
    file: FileStamp,
}

/// 一个文件的路径、长度和修改时间：三样都没变，就当内容没变 / A file's path, length and modification
/// time: with all three unchanged, its content counts as unchanged
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct FileStamp {
    path: PathBuf,
    len: u64,
    modified: Option<SystemTime>,
}

impl FileStamp {
    pub(crate) fn of(path: &Path) -> std::io::Result<Self> {
        let meta = std::fs::metadata(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            len: meta.len(),
            modified: meta.modified().ok(),
        })
    }
}

impl Mmdb {
    fn open(path: &str, file: FileStamp) -> Result<Self, maxminddb::MaxMindDbError> {
        let content = std::fs::read(path)?;
        let mut hasher = DefaultHasher::new();
        content.hash(&mut hasher);
        let fingerprint = hasher.finish();
        let reader = maxminddb::Reader::from_source(content)?;
        let mut countries = FxHashMap::default();
        if let Err(e) = Self::index(&reader, &mut countries) {
            // 没解到的记录查询时当场解，结果不变 / Records left out are decoded when asked about, with the same result
            tracing::warn!(geoip_db = %path, error = %e, "could not index every GeoIP database record, the rest are decoded per query");
        }
        Ok(Self {
            reader,
            fingerprint,
            countries,
            file,
        })
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

impl GeoIpManager {
    /// 用 `path` 的 MMDB。`current` 在用的正是这个文件、文件也没变（路径、长度、修改时间都一样）时共用它那份，不再
    /// 读一遍：以前只改了规则用的标签也要把整个库（约 10 MB）再读一遍、每个网段再走一遍，旧库还占着内存。读不了
    /// （不存在、正被替换、写坏了）时，`current` 用的是同一个路径就留着它那份，返回读不了的原因；文件换了样子以后的
    /// 热重载再读它（见 `engine::geo` 的 `Loaded`）。以前换进去的是没有 MMDB 的管理器，文件又在，之后国家代码就一直
    /// 不按 MMDB 判断，直到重启
    /// Uses the MMDB at `path`. When `current` uses that very file and the file is unchanged
    /// (same path, length and modification time) its data is shared rather than read again: a
    /// change to nothing but the tags rules use used to read the whole database (some 10 MB) and
    /// walk every network again while the old one still held memory. When it cannot be read
    /// (missing, being replaced, broken) the data `current` has from the same path stays, and
    /// it gives why; the hot reload after the file looks otherwise reads it again (see
    /// `Loaded` in `engine::geo`). A manager with no MMDB used to be swapped in, and with the
    /// file still there country codes were no longer judged by the MMDB until a restart
    pub fn use_mmdb(&mut self, path: &str, current: &Self) -> anyhow::Result<()> {
        let file = FileStamp::of(Path::new(path));
        let in_use = current.mmdb.as_ref();
        if let (Ok(file), Some(in_use)) = (&file, in_use)
            && *file == in_use.file
        {
            self.mmdb = Some(Arc::clone(in_use));
            return Ok(());
        }
        let opened = file
            .map_err(anyhow::Error::new)
            .and_then(|file| Mmdb::open(path, file).map_err(anyhow::Error::new));
        match opened {
            Ok(mmdb) => {
                tracing::info!(geoip_db = %path, records = mmdb.countries.len(), "GeoIP database loaded successfully");
                self.mmdb = Some(Arc::new(mmdb));
                Ok(())
            }
            Err(e) => {
                self.mmdb = in_use
                    .filter(|in_use| in_use.file.path == Path::new(path))
                    .cloned();
                Err(e)
            }
        }
    }

    /// 和这个管理器用同一份 MMDB、还没有标签的管理器：监视到数据文件变了时，新的标签在它上面、锁外装好，写锁下只把整个
    /// 管理器换进去（见 `engine::geo` 的 `reload_geoip_file`）
    /// A manager with this one's very MMDB and no tags yet: when a watched data file changes, the
    /// new tags go into it outside the lock, and the write lock is held only to swap the whole
    /// manager in (see `reload_geoip_file` in `engine::geo`)
    pub fn sharing_mmdb(&self) -> Self {
        Self {
            mmdb: self.mmdb.clone(),
            tag_indexes: FxHashMap::default(),
        }
    }

    /// 眼下的数据的指纹：数据真换了样子才变，读它的 pipeline 跟着换缓存命名空间（见 `engine::geo::GeoGeneration`）
    /// The fingerprints of the data right now, changing only once the data really changes, and
    /// the pipelines reading it move to a new cache namespace with them (see
    /// `engine::geo::GeoGeneration`)
    pub fn fingerprints(&self) -> GeoIpFingerprints {
        GeoIpFingerprints {
            tags: self
                .tag_indexes
                .iter()
                .map(|(tag, index)| (Arc::clone(tag), index.fingerprint))
                .collect(),
            mmdb: self.mmdb.as_ref().map(|mmdb| mmdb.fingerprint),
        }
    }

    /// MMDB 是否已加载；加载了，两个字母的国家代码就只按它判断
    /// Whether an MMDB is loaded; when one is, two-letter country codes are judged by it alone
    #[inline]
    pub fn has_mmdb(&self) -> bool {
        self.mmdb.is_some()
    }

    /// IP 是否属于一个标签（不分大小写）：测试用的 [`Self::matches_any_tag`] 简写
    /// Whether an IP belongs to one tag (in any case): the tests' shorthand for
    /// [`Self::matches_any_tag`]
    #[cfg(test)]
    pub fn matches_tag(&self, ip: IpAddr, tag: &str) -> bool {
        self.matches_any_tag(ip, &[Arc::from(tag.to_ascii_uppercase())])
    }

    /// IP 是否属于 `tags` 里的哪个标签。`tags` 已是大写：规则写的国家代码和标签编译时就转了大写（见
    /// `matcher::normalize_geoip_country_codes`），数据文件里的读进来时转
    /// Whether an IP belongs to any of `tags`. `tags` are uppercase already: the country codes and
    /// tags rules write are uppercased as they compile (see
    /// `matcher::normalize_geoip_country_codes`), and those of data files as they are read
    #[inline]
    pub fn matches_any_tag(&self, ip: IpAddr, tags: &[Arc<str>]) -> bool {
        // 用到国家代码时才查 MMDB，只查一次 / The MMDB is asked once, and only when a country code needs it
        let mut mmdb_country: Option<Option<&str>> = None;

        for tag in tags {
            let tag = tag.as_ref();
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

    /// 获取去重合并后的 IP 范围数量（仅用于调试）。
    /// Get the deduplicated and merged IP range count (debug only).
    #[inline]
    pub fn ip_range_count(&self) -> usize {
        self.tag_indexes
            .values()
            .map(GeoIpTagIndex::range_count)
            .sum()
    }

    /// 从 V2Ray .dat 文件加载每个标签（protobuf 编码的 GeoIPList，见 [`Self::parse_dat_file`]），测试用
    /// Loads every tag of a V2Ray .dat file (a protobuf-encoded GeoIPList, see
    /// [`Self::parse_dat_file`]), for tests
    #[cfg(test)]
    pub fn load_from_dat_file(&mut self, path: &Path) -> anyhow::Result<usize> {
        let parsed = Self::parse_dat_file(path)?;
        Ok(self.apply_parsed(parsed))
    }

    /// 解析 .dat 文件里的每个标签，测试用；运行时只解析规则用到的（见 [`Self::parse_file`]）
    /// Parse every tag of a .dat file, for tests; at run time only the tags rules use are
    /// parsed (see [`Self::parse_file`])
    #[cfg(test)]
    pub fn parse_dat_file(path: &Path) -> anyhow::Result<ParsedGeoIp> {
        Self::parse_dat_entries(path, &|_| true)
    }

    /// 解析 .dat 文件里 `wanted` 认可的条目（参数是大写的国家代码或标签）。顶层在这里一个个条目读，不把整个文件读进
    /// 内存：每个条目先只解国家代码，要的条目才整个解，一百多万个网段里规则只用到几个标签时，别的标签既不解也不留。
    /// 条目交给 prost 按 protobuf 的规矩解（见 `geoip_proto`）
    /// Parses the entries of a .dat file that `wanted` accepts (given the uppercase country code
    /// or tag). The top level is read here entry by entry rather than into memory whole: each
    /// entry's country code is decoded first and only wanted entries are decoded whole, so when
    /// rules use a few tags out of over a million networks the other tags are neither decoded
    /// nor kept. Entries are decoded by protobuf's rules with prost (see `geoip_proto`)
    fn parse_dat_entries(
        path: &Path,
        wanted: &dyn Fn(&str) -> bool,
    ) -> anyhow::Result<ParsedGeoIp> {
        let mut file = DatReader::open(path)?;
        // 一个条目的内容，各条目轮流使用 / One entry's bytes, reused for every entry
        let mut entry = Vec::new();
        let mut tag_indexes: FxHashMap<Arc<str>, GeoIpTagIndex> = FxHashMap::default();
        let mut count = 0;
        let mut ipv4_count = 0;
        let mut ipv6_count = 0;

        // GeoIPList 顶层只有 `repeated GeoIP entry = 1`，别的字段跳过。条目越出文件时整份文件拒绝（见
        // `DatReader::next_field`）
        // GeoIPList holds only `repeated GeoIP entry = 1` at the top; other fields are skipped.
        // An entry running past the file gets the whole file rejected (see
        // `DatReader::next_field`)
        while let Some(len) = file.next_field(1, file.end())? {
            file.read(&mut entry, len)?;

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
            let mut skipped = Skipped::default();
            for cidr in geoip.cidr {
                match cidr.ip.len() {
                    4 => {
                        let mut ip_bytes = [0u8; 4];
                        ip_bytes.copy_from_slice(&cidr.ip);
                        // 地址里的主机位清掉（1.2.3.4/24 就是 1.2.3.0/24）；超过 32 的前缀按单个
                        // 地址算，/0 是整个 IPv4 空间
                        // Host bits in the address are cleared (1.2.3.4/24 is 1.2.3.0/24); a
                        // prefix over 32 is one address, /0 the whole IPv4 space
                        let mask = u32::MAX.checked_shl(32 - cidr.prefix.min(32)).unwrap_or(0);
                        let start = u32::from_be_bytes(ip_bytes) & mask;
                        let end = start | !mask;
                        get_or_insert_tag_index(&mut tag_indexes, &country_code)
                            .ipv4_ranges
                            .push(AddrRange { start, end });
                        count += 1;
                        ipv4_count += 1;
                    }
                    16 => {
                        let mut ip_bytes = [0u8; 16];
                        ip_bytes.copy_from_slice(&cidr.ip);
                        // 同上 / As above
                        let mask = u128::MAX
                            .checked_shl(128 - cidr.prefix.min(128))
                            .unwrap_or(0);
                        let start = u128::from_be_bytes(ip_bytes) & mask;
                        let end = start | !mask;
                        get_or_insert_tag_index(&mut tag_indexes, &country_code)
                            .ipv6_ranges
                            .push(AddrRange { start, end });
                        count += 1;
                        ipv6_count += 1;
                    }
                    len => skipped.add(|| format!("an address of {len} bytes")),
                }
            }
            skipped.warn(&country_code, ".dat file");
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

    /// 数据文件给出的标签（只有规则用到的那些）/ The tags the data file gives (only those rules use)
    pub fn tags(&self) -> Vec<String> {
        self.tag_indexes.keys().map(|tag| tag.to_string()).collect()
    }

    /// 把 `in_use` 里属于 `tags`（不分大小写）的标签连同数据搬过来，给出搬过来的标签。重新读数据文件什么都没读出来
    /// 时，用它把在用的数据带进新建的管理器（见 `engine::geo` 的 `load_geoip`）；`in_use` 之后只该被换掉
    /// Moves the tags among `tags` (ignoring case) over from `in_use`, data and all, giving the
    /// tags moved. When reading the data file again gives nothing, this carries the data in use
    /// into the manager being built (see `load_geoip` in `engine::geo`); `in_use` is only to be
    /// replaced afterwards
    pub fn keep_tags_of(&mut self, in_use: &mut GeoIpManager, tags: &[String]) -> Vec<String> {
        let kept: Vec<Arc<str>> = in_use
            .tag_indexes
            .keys()
            .filter(|tag| tags.iter().any(|wanted| wanted.eq_ignore_ascii_case(tag)))
            .cloned()
            .collect();
        for tag in &kept {
            if let Some(index) = in_use.tag_indexes.remove(tag) {
                self.tag_indexes.insert(Arc::clone(tag), index);
            }
        }
        kept.iter().map(|tag| tag.to_string()).collect()
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

    /// 从 JSON 数据文件加载每个标签，测试用 / Loads every tag of a JSON data file, for tests
    #[cfg(test)]
    pub fn load_from_v2ray_file(&mut self, path: &Path) -> anyhow::Result<usize> {
        let parsed = Self::parse_v2ray_file(path)?;
        Ok(self.apply_parsed(parsed))
    }

    /// 按扩展名解析数据文件里 `tags` 这几个标签（不分大小写），其余条目不解，不触碰管理器状态：
    /// `.dat` 按条目读（见 `parse_dat_entries`），其余按 JSON 读（`parse_v2ray_entries`）。文件里没有的标签见
    /// [`Self::missing_tags`]
    /// Parses the `tags` of a data file (ignoring case) by its extension, leaving the other
    /// entries undecoded and the manager untouched: `.dat` is read entry by entry (see
    /// `parse_dat_entries`) and anything else as JSON (`parse_v2ray_entries`). For the tags the
    /// file lacks see [`Self::missing_tags`]
    pub fn parse_file(path: &Path, tags: &[String]) -> anyhow::Result<ParsedGeoIp> {
        let wanted: FxHashSet<String> = tags.iter().map(|tag| tag.to_ascii_uppercase()).collect();
        Self::parse_matching(path, &|code| wanted.contains(code))
    }

    /// `tags`（规则用到的，大写）里哪些既不是 MMDB 答得了的国家代码、也没有数据文件提供：用它们的规则不会命中
    /// The tags among `tags` (the ones rules use, uppercase) that are neither country codes the
    /// MMDB answers nor provided by the data file: rules using them never match
    pub fn missing_tags(&self, tags: &[String]) -> Vec<String> {
        tags.iter()
            .filter(|tag| {
                !(self.has_mmdb() && is_country_tag(tag))
                    && !self.tag_indexes.contains_key(tag.as_str())
            })
            .cloned()
            .collect()
    }

    /// 按扩展名解析数据文件里 `wanted` 认可的条目（参数是大写的国家代码或标签）：`.dat` 按条目读，其余按 JSON 读
    /// Parses the entries of a data file that `wanted` accepts (given the uppercase country
    /// code or tag) by its extension: `.dat` entry by entry, anything else as JSON
    pub(super) fn parse_matching(
        path: &Path,
        wanted: &dyn Fn(&str) -> bool,
    ) -> anyhow::Result<ParsedGeoIp> {
        let is_dat = path
            .extension()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s.eq_ignore_ascii_case("dat"));
        if is_dat {
            Self::parse_dat_entries(path, wanted)
        } else {
            Self::parse_v2ray_entries(path, wanted)
        }
    }

    /// 解析 JSON 数据文件里的每个标签，不触碰管理器状态；测试用，运行时只解析规则用到的（见 [`Self::parse_file`]）
    /// Parse every tag of a JSON data file without touching manager state; for tests, as at run
    /// time only the tags rules use are parsed (see [`Self::parse_file`])
    #[cfg(test)]
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
            let mut skipped = Skipped::default();
            for ip_str in &geoip.ips {
                let Some(net) = json_network(ip_str) else {
                    skipped.add(|| ip_str.clone());
                    continue;
                };
                // 标签的索引在读出第一个网段时才建，和 .dat 一样：一个网段都读不出来的标签不算文件提供了
                // A tag's index is made with its first network read, as for .dat: a tag none of
                // whose networks can be read does not count as provided by the file
                let index = get_or_insert_tag_index(&mut tag_indexes, &tag);
                match net {
                    ipnet::IpNet::V4(v4net) => {
                        index.ipv4_ranges.push(AddrRange {
                            start: u32::from(v4net.network()),
                            end: u32::from(v4net.broadcast()),
                        });
                        ipv4_count += 1;
                    }
                    ipnet::IpNet::V6(v6net) => {
                        index.ipv6_ranges.push(AddrRange {
                            start: u128::from(v6net.network()),
                            end: u128::from(v6net.broadcast()),
                        });
                        ipv6_count += 1;
                    }
                }
                count += 1;
            }
            skipped.warn(&tag, "JSON file");
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
}

/// JSON 数据里的一项：带前缀长度的网段（`1.1.1.0/24`），或者不带前缀长度的单个地址（`1.1.1.1` 就是 `1.1.1.1/32`，
/// IPv6 是 /128），和 .dat 里超过位宽的前缀按单个地址算一样。网段列表里写一个地址只有这一个意思，以前它读不出来，
/// 悄悄丢掉，文件里明明列着的地址规则却匹配不上
/// One item of JSON data: a network with its prefix length (`1.1.1.0/24`), or a single
/// address without one (`1.1.1.1` is `1.1.1.1/32`, /128 for IPv6), as a .dat prefix wider than
/// the address is one address. An address in a list of networks can mean nothing else; it used
/// not to parse and was dropped in silence, so rules missed an address the file plainly lists
fn json_network(text: &str) -> Option<ipnet::IpNet> {
    text.parse()
        .ok()
        .or_else(|| text.parse::<IpAddr>().ok().map(ipnet::IpNet::from))
}

/// 一个条目里读不出来、跳过的网段：几条，第一条是什么。跳过的记一条告警，不然标签照样在，用它的规则却悄悄地少了这些
/// 网段，和 GeoSite 一样（见 `GeoSiteManager::convert_v2ray_to_entries`）
/// The networks of one entry that cannot be read and are skipped: how many, and what the
/// first was. Those skipped make one warning, or the tag stays with the rules using it quietly
/// missing them, as for GeoSite (see `GeoSiteManager::convert_v2ray_to_entries`)
#[derive(Default)]
struct Skipped {
    count: usize,
    first: Option<String>,
}

impl Skipped {
    fn add(&mut self, network: impl FnOnce() -> String) {
        self.count += 1;
        self.first.get_or_insert_with(network);
    }

    /// 有跳过的就记一条告警 / Logs a warning when any were skipped
    fn warn(self, tag: &str, source: &str) {
        if let Some(example) = self.first {
            tracing::warn!(tag, skipped = self.count, example = %example, source,
                "skipped GeoIP networks that cannot be read");
        }
    }
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

/// 是否两个字母的国家代码；有 MMDB 时只有这样的标签查 MMDB
/// Whether a tag is a two-letter country code; with an MMDB only such tags are looked up there
#[inline]
pub(crate) fn is_country_tag(tag: &str) -> bool {
    tag.len() == 2 && tag.bytes().all(|byte| byte.is_ascii_alphabetic())
}

/// `geoip_private`、`response_answer_ip_geoip_private` 和 ECS 都算作内网的地址，只有这一份（ECS 另外再算一个转换前缀和基准测试
/// 网段，见 `ecs::is_private_ip`）。连过去到的是本机、本地网络或运营商的内部网络，或者哪儿也到不了的地址：
/// - IPv4：RFC 1918 私有网段，运营商级 NAT 的共享地址 100.64.0.0/10（RFC 6598，Tailscale 也用它），回环，链路本地，
///   「本网络」0.0.0.0/8，IETF 协议分配 192.0.0.0/24（RFC 6890，DS-Lite 等的内部地址），受限广播 255.255.255.255。
///   0.0.0.0/8 和 `::` 一样不是哪台主机的地址（RFC 791），连 0.0.0.0 在 Linux、macOS 上连的是本机，回答它和回答
///   127.0.0.1 一样能拿来重绑定
/// - IPv6：回环，未指定地址，ULA（fc00::/7），链路本地（fe80::/10），已废弃、仍有内网在用的站点本地（fec0::/10，
///   RFC 3879），丢弃前缀 100::/64（RFC 6666）
/// - NAT64 地址（64:ff9b::/96，RFC 6052；本地用的 64:ff9b:1::/48，RFC 8215）按它末 32 位嵌着的 IPv4 地址判断（/96
///   的写法）：连过去，转换网关连的就是那个 IPv4 地址，嵌着内网地址的照样能拿来重绑定，嵌着公网地址的是 DNS64 的
///   寻常回答
///
/// 基准测试的 198.18.0.0/15（RFC 2544）不算（ECS 另外排除它）：它是 Clash、mihomo 等 fake-ip 的默认网段，算进去的话，
/// 转给 fake-ip 上游的查询，回答都会被防重绑定的规则拦下。文档用的网段（192.0.2.0/24 这些）也不算：不可全球路由，却也不在哪个内网里
/// The addresses `geoip_private`, `response_answer_ip_geoip_private` and ECS count as local
/// network ones, this one list alone (ECS counts one translation prefix and the benchmarking
/// range more, see `ecs::is_private_ip`). Connecting to them reaches this machine, the local network or the
/// operator's internal network, or nowhere at all:
/// - IPv4: the RFC 1918 private networks, carrier-grade NAT's shared space 100.64.0.0/10
///   (RFC 6598, which Tailscale uses too), loopback, link-local, "this network" 0.0.0.0/8,
///   the IETF protocol assignments 192.0.0.0/24 (RFC 6890, internal addresses of DS-Lite and
///   the like), and limited broadcast 255.255.255.255. Like `::`, 0.0.0.0/8 is no host's
///   address (RFC 791), and connecting to 0.0.0.0 reaches this machine on Linux and macOS, so
///   an answer of it rebinds as one of 127.0.0.1 does
/// - IPv6: loopback, the unspecified address, ULA (fc00::/7), link-local (fe80::/10),
///   site-local (fec0::/10, RFC 3879), deprecated yet still used on internal networks, and the
///   discard-only prefix 100::/64 (RFC 6666)
/// - NAT64 addresses (64:ff9b::/96, RFC 6052; the local-use 64:ff9b:1::/48, RFC 8215) count
///   by the IPv4 address their last 32 bits embed (the /96 format): connecting to one, the
///   translator connects to that IPv4 address, so one embedding a local address rebinds all
///   the same, while one embedding a public address is an ordinary DNS64 answer
///
/// Benchmarking's 198.18.0.0/15 (RFC 2544) does not count (ECS leaves it out separately): it
/// is the default fake-ip range of Clash, mihomo and the like, and counted, every answer to a query forwarded to a fake-ip
/// upstream would be stopped by anti-rebinding rules. Nor do the documentation networks
/// (192.0.2.0/24 and the like): not globally routable, yet not on any local network either
#[inline]
pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_v4(v4),
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                || segments[0] & 0xffc0 == 0xfec0
                || segments[..4] == [0x0100, 0, 0, 0]
                || nat64_ipv4(v6).is_some_and(is_private_v4)
        }
    }
}

/// [`is_private_ip`] 的 IPv4 部分 / The IPv4 part of [`is_private_ip`]
fn is_private_v4(v4: Ipv4Addr) -> bool {
    let [a, b, c, _] = v4.octets();
    v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_broadcast()
        || a == 0
        || (a == 100 && b & 0xc0 == 64)
        || (a == 192 && b == 0 && c == 0)
}

/// NAT64 地址（64:ff9b::/96、64:ff9b:1::/48）末 32 位嵌着的 IPv4 地址 / The IPv4 address the last 32
/// bits of a NAT64 address (64:ff9b::/96, 64:ff9b:1::/48) embed
fn nat64_ipv4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    let segments = v6.segments();
    (segments[..6] == [0x64, 0xff9b, 0, 0, 0, 0] || segments[..3] == [0x64, 0xff9b, 1])
        .then(|| Ipv4Addr::from_bits(v6.to_bits() as u32))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 内网地址只有一份：私有网段、运营商级 NAT 和 Tailscale 的 100.64.0.0/10、192.0.0.0/24、回环、链路本地、0.0.0.0/8、
    /// 广播，IPv6 的 ULA、链路本地、站点本地 fec0::/10、丢弃前缀 100::/64；NAT64 地址按末 32 位嵌着的 IPv4 地址判断。
    /// 各网段两边的边界都看。fake-ip 的 198.18.0.0/15 不算。以前 100.64.0.0/10、192.0.0.0/24、100::/64 只有 ECS 算，
    /// fec0::/10 和嵌着内网地址的 NAT64 地址哪边都不算，防重绑定的规则放过了 Tailscale 和运营商级 NAT 的地址
    /// One list of local network addresses: the private networks, carrier-grade NAT's and
    /// Tailscale's 100.64.0.0/10, 192.0.0.0/24, loopback, link-local, 0.0.0.0/8 and broadcast,
    /// and in IPv6 ULA, link-local, site-local fec0::/10 and the discard-only 100::/64; a NAT64
    /// address counts by the IPv4 address its last 32 bits embed. Each range is checked at both
    /// of its edges. fake-ip's 198.18.0.0/15 does not count. 100.64.0.0/10, 192.0.0.0/24 and
    /// 100::/64 used to count for ECS alone, and fec0::/10 and NAT64 addresses embedding a local
    /// one for neither, so anti-rebinding rules let Tailscale and carrier-grade NAT addresses
    /// through
    #[test]
    fn local_network_addresses_are_one_list() {
        for (address, local) in [
            ("10.1.2.3", true),
            ("172.31.255.255", true),
            ("192.168.1.1", true),
            ("127.0.0.1", true),
            ("169.254.1.1", true),
            ("0.1.2.3", true),
            ("255.255.255.255", true),
            ("100.64.0.0", true),
            ("100.100.100.100", true),
            ("100.127.255.255", true),
            ("100.63.255.255", false),
            ("100.128.0.0", false),
            ("192.0.0.8", true),
            ("192.0.1.0", false),
            ("198.18.0.1", false),
            ("198.19.255.255", false),
            ("192.0.2.1", false),
            ("203.0.113.1", false),
            ("8.8.8.8", false),
            ("::", true),
            ("::1", true),
            ("fd00::1", true),
            ("fe80::1", true),
            ("fec0::1", true),
            ("feff:ffff::1", true),
            ("ff02::1", false),
            ("100::1", true),
            ("100:0:0:1::1", false),
            ("64:ff9b::c0a8:101", true),
            ("64:ff9b::7f00:1", true),
            ("64:ff9b::808:808", false),
            ("64:ff9b:1::a00:1", true),
            ("64:ff9b:1:ab::6440:1", true),
            ("64:ff9b:1::808:808", false),
            ("64:ff9b:0:0:0:1:a00:1", false),
            ("64:ff9b:2::a00:1", false),
            ("2001:db8::1", false),
            ("2606:4700::1111", false),
        ] {
            assert_eq!(is_private_ip(address.parse().unwrap()), local, "{address}");
        }
    }

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

        let mut mgr = GeoIpManager::default();
        let count = mgr.load_from_dat_file(&path).unwrap();
        assert_eq!(count, 2, "应加载 2 条（v4 + v6）");
        assert_eq!(mgr.ip_range_count(), 2, "IPv4 和 IPv6 段都应保留");

        // IPv6 查询应匹配国家 / IPv6 lookup should match the country
        let ip: std::net::IpAddr = "2001:db8::1".parse().unwrap();
        assert!(mgr.matches_tag(ip, "CN"));

        // 不在段内的 IPv6 不应误匹配 / IPv6 outside the range must not match
        let miss: std::net::IpAddr = "2001:db9::1".parse().unwrap();
        assert!(!mgr.matches_tag(miss, "CN"));

        // IPv4 查询仍然正常 / IPv4 lookup still works
        let v4ip: std::net::IpAddr = "1.2.3.5".parse().unwrap();
        assert!(mgr.matches_tag(v4ip, "CN"));

        let _ = std::fs::remove_file(&path);
    }

    /// .dat 里带主机位的网段（1.2.3.4/24）按它所在的整个网段算：主机位清掉，不往后错位
    /// A .dat CIDR with host bits set (1.2.3.4/24) stands for its whole network: the host
    /// bits are cleared rather than shifting the range
    #[test]
    fn a_dat_cidr_with_host_bits_covers_its_network() {
        let mut v6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        v6[15] = 1;
        let dat = build_dat("CN", Some(([1, 2, 3, 4], 24)), Some((v6, 32)));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("geoip.dat");
        std::fs::write(&path, &dat).unwrap();
        let mut mgr = GeoIpManager::default();
        mgr.load_from_dat_file(&path).unwrap();

        for inside in [
            "1.2.3.0",
            "1.2.3.1",
            "1.2.3.255",
            "2001:db8::",
            "2001:db8:ffff::1",
        ] {
            assert!(mgr.matches_tag(inside.parse().unwrap(), "CN"), "{inside}");
        }
        for outside in ["1.2.2.255", "1.2.4.0", "1.2.4.3", "2001:db9::"] {
            assert!(
                !mgr.matches_tag(outside.parse().unwrap(), "CN"),
                "{outside}"
            );
        }
    }

    /// JSON 里写成小写的国家代码，转换成 MMDB 时照样认得过滤条件里的大写代码
    /// A country code the JSON writes in lowercase still meets the filter's uppercase code
    /// when converting to MMDB
    #[test]
    fn a_lowercase_json_country_passes_the_conversion_filter() {
        let json = r#"{ "entries": [
            { "country_code": "cn", "ips": ["198.51.100.0/24"] },
            { "country_code": "jp", "ips": ["203.0.113.0/24"] }
        ] }"#;
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("geoip.json");
        let mmdb = dir.path().join("geoip.mmdb");
        std::fs::write(&source, json).unwrap();
        let stats = crate::matcher::geoip_converter::convert_dat_to_mmdb(
            &source,
            &mmdb,
            Some(&["CN".to_string()]),
        )
        .unwrap();
        assert_eq!(stats.countries_count, 1);

        let mut mgr = GeoIpManager::default();
        mgr.use_mmdb(&mmdb.to_string_lossy(), &GeoIpManager::default())
            .unwrap();
        assert!(mgr.matches_tag("198.51.100.7".parse().unwrap(), "CN"));
        assert!(!mgr.matches_tag("203.0.113.7".parse().unwrap(), "JP"));
    }

    /// 重载时文件没变就共用在用的那份 MMDB，不再读第二遍；文件读不了（写坏了）时留着在用的那份、报读不上，修好以后
    /// 读进新的。以前每次都重读整个库，读不了就换成没有 MMDB 的管理器，国家代码一直不按 MMDB 判断，直到重启
    /// On a reload an unchanged file shares the MMDB in use instead of reading it twice; a file
    /// that cannot be read (broken) keeps the one in use and reports it was not read, and once
    /// fixed it is read anew. The whole database used to be read every time, a failed read
    /// swapping in a manager with no MMDB, country codes no longer judged by it until a restart
    #[test]
    fn a_reload_shares_an_unchanged_mmdb_and_keeps_it_when_the_file_breaks() {
        let dir = tempfile::tempdir().unwrap();
        let mmdb = dir.path().join("geoip.mmdb");
        let path = mmdb.to_string_lossy().into_owned();
        let convert = |json: &str| {
            let source = dir.path().join("geoip.json");
            std::fs::write(&source, json).unwrap();
            crate::matcher::geoip_converter::convert_dat_to_mmdb(&source, &mmdb, None).unwrap();
        };
        convert(r#"{ "entries": [{ "country_code": "CN", "ips": ["198.51.100.0/24"] }] }"#);
        let mut first = GeoIpManager::default();
        first.use_mmdb(&path, &GeoIpManager::default()).unwrap();

        let mut unchanged = GeoIpManager::default();
        unchanged.use_mmdb(&path, &first).unwrap();
        assert!(Arc::ptr_eq(
            unchanged.mmdb.as_ref().unwrap(),
            first.mmdb.as_ref().unwrap()
        ));

        std::fs::write(&mmdb, b"not a database").unwrap();
        let mut broken = GeoIpManager::default();
        assert!(broken.use_mmdb(&path, &first).is_err(), "it was not read");
        assert!(broken.matches_tag("198.51.100.7".parse().unwrap(), "CN"));

        convert(r#"{ "entries": [{ "country_code": "JP", "ips": ["198.51.100.0/24"] }] }"#);
        // 和第一份一样长；修改时间按内核时钟的节拍走，紧接着写的可能和第一份一样（OpenWrt 虚拟机上就是），
        // 所以写明它晚一秒，像隔了一阵才换上的那样
        // As long as the first; modification times go by the kernel clock's tick, so one
        // written right after may match the first's (as on an OpenWrt VM), and it is set a
        // second later, as for a file replaced a while on
        let later = std::fs::metadata(&mmdb).unwrap().modified().unwrap()
            + std::time::Duration::from_secs(1);
        std::fs::File::options()
            .write(true)
            .open(&mmdb)
            .unwrap()
            .set_modified(later)
            .unwrap();
        let mut fixed = GeoIpManager::default();
        fixed.use_mmdb(&path, &broken).unwrap();
        assert!(fixed.matches_tag("198.51.100.7".parse().unwrap(), "JP"));
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

        let mut mgr = GeoIpManager::default();
        let count = mgr.load_from_v2ray_file(&path).unwrap();
        assert_eq!(count, 2, "JSON 应加载 v4 + v6");
        assert_eq!(mgr.ip_range_count(), 2, "JSON IPv4 和 IPv6 段都应保留");

        let ip: std::net::IpAddr = "2001:db8:1::1234".parse().unwrap();
        assert!(mgr.matches_tag(ip, "JP"));

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

        let mut manager = GeoIpManager::default();
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

    /// 相邻的网段（前一段的末尾紧挨着后一段的开头）合并成一段，隔开一个地址的不合并；IPv4、IPv6
    /// 一样，到顶的那一段也不越界
    /// Adjacent ranges (one ending right before the next begins) merge into one, ranges
    /// one address apart do not; the same for IPv4 and IPv6, and a range reaching the top
    /// does not wrap
    #[test]
    fn adjacent_ranges_merge_and_ones_apart_stay_apart() {
        let mut index = GeoIpTagIndex {
            ipv4_ranges: vec![
                AddrRange { start: 20, end: 29 },
                AddrRange { start: 10, end: 19 },
                AddrRange { start: 31, end: 40 },
                AddrRange {
                    start: u32::MAX - 5,
                    end: u32::MAX,
                },
                AddrRange {
                    start: u32::MAX - 9,
                    end: u32::MAX - 6,
                },
            ],
            ipv6_ranges: vec![
                AddrRange { start: 20, end: 29 },
                AddrRange { start: 10, end: 19 },
                AddrRange { start: 31, end: 40 },
                AddrRange {
                    start: u128::MAX - 5,
                    end: u128::MAX,
                },
                AddrRange {
                    start: u128::MAX - 9,
                    end: u128::MAX - 6,
                },
            ],
            fingerprint: 0,
        };
        index.finalize();
        assert_eq!(
            index
                .ipv4_ranges
                .iter()
                .map(|range| (range.start, range.end))
                .collect::<Vec<_>>(),
            [(10, 29), (31, 40), (u32::MAX - 9, u32::MAX)]
        );
        assert_eq!(
            index
                .ipv6_ranges
                .iter()
                .map(|range| (range.start, range.end))
                .collect::<Vec<_>>(),
            [(10, 29), (31, 40), (u128::MAX - 9, u128::MAX)]
        );
    }

    /// 交叉重叠的网段合并以后，两段里的地址都算在内，两段之外的不算
    /// Crossing ranges merged still hold every address of both, and nothing beyond them
    #[test]
    fn crossing_ranges_merge_into_one() {
        let mut index = GeoIpTagIndex {
            ipv4_ranges: vec![
                AddrRange { start: 45, end: 70 },
                AddrRange { start: 40, end: 55 },
            ],
            ipv6_ranges: vec![
                AddrRange { start: 45, end: 70 },
                AddrRange { start: 40, end: 55 },
            ],
            fingerprint: 0,
        };
        index.finalize();
        assert_eq!(index.range_count(), 2);
        for (ip, inside) in [(39, false), (40, true), (50, true), (70, true), (71, false)] {
            assert_eq!(
                index.contains(IpAddr::from(std::net::Ipv4Addr::from(ip))),
                inside,
                "v4 {ip}"
            );
            assert_eq!(
                index.contains(IpAddr::from(std::net::Ipv6Addr::from(u128::from(ip)))),
                inside,
                "v6 {ip}"
            );
        }
    }

    /// 嵌套的网段各管各的：US 的 /24 在 CN 的 /8 里面，里面的地址两个标签都算，/24 外面只算 CN
    /// Nested networks each keep their own: US's /24 sits inside CN's /8, so an address in it
    /// is under both tags and one outside the /24 under CN alone
    #[test]
    fn nested_networks_match_each_tag() {
        let dat = build_nested_dat();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("geoip_test_nested.dat");
        std::fs::write(&path, &dat).unwrap();

        let mut mgr = GeoIpManager::default();
        mgr.load_from_dat_file(&path).unwrap();

        for (ip, us) in [
            ("10.1.2.5", true),
            ("10.1.2.255", true),
            ("10.1.3.5", false),
            ("10.1.3.0", false),
            ("10.200.1.1", false),
            ("2001:db8:1::1", true),
            ("2001:db8:2::1", false),
        ] {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(mgr.matches_tag(ip, "CN"), "{ip}");
            assert_eq!(mgr.matches_tag(ip, "US"), us, "{ip}");
        }

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn same_tag_nested_networks_match() {
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

        let mut mgr = GeoIpManager::default();
        assert_eq!(mgr.load_from_v2ray_file(&path).unwrap(), 6);

        let cn4: IpAddr = "10.1.1.1".parse().unwrap();
        assert!(mgr.matches_tag(cn4, "CN"));
        assert!(mgr.matches_tag(cn4, "US"));
        let us4: IpAddr = "10.2.1.1".parse().unwrap();
        assert!(mgr.matches_tag(us4, "US"));
        assert!(mgr.matches_tag(us4, "CN"));
        let cn_only4: IpAddr = "10.200.1.1".parse().unwrap();
        assert!(mgr.matches_tag(cn_only4, "CN"));
        assert!(!mgr.matches_tag(cn_only4, "US"));

        let cn6: IpAddr = "2001:db8:1::1".parse().unwrap();
        assert!(mgr.matches_tag(cn6, "CN"));
        assert!(mgr.matches_tag(cn6, "US"));
        let us6: IpAddr = "2001:db8:2::1".parse().unwrap();
        assert!(mgr.matches_tag(us6, "US"));
        assert!(mgr.matches_tag(us6, "CN"));
        let cn_only6: IpAddr = "2001:db9::1".parse().unwrap();
        assert!(!mgr.matches_tag(cn_only6, "CN"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_overlapping_dat_tags_match_independently() {
        let mut dat = build_dat("AU", Some(([1, 1, 1, 0], 24)), None);
        dat.extend(build_dat("cloudflare", Some(([1, 1, 1, 0], 24)), None));

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("geoip_test_overlapping_tags.dat");
        std::fs::write(&path, &dat).unwrap();

        let mut mgr = GeoIpManager::default();
        assert_eq!(mgr.load_from_dat_file(&path).unwrap(), 2);

        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        assert!(mgr.matches_tag(ip, "AU"));
        assert!(mgr.matches_tag(ip, "cloudflare"));
        assert!(!mgr.matches_tag(ip, "netflix"));
        assert!(mgr.matches_any_tag(ip, &[Arc::from("NETFLIX"), Arc::from("CLOUDFLARE")]));
        let outside: IpAddr = "1.1.2.1".parse().unwrap();
        assert!(!mgr.matches_any_tag(outside, &[Arc::from("AU"), Arc::from("CLOUDFLARE")]));

        let _ = std::fs::remove_file(&path);
    }

    /// 只有命名标签（不是国家代码）的数据照样按标签匹配，不分大小写
    /// Data holding a named tag alone (no country code) matches by that tag, ignoring case
    #[test]
    fn a_named_tag_alone_matches() {
        let dat = build_dat("cloudflare", Some(([1, 1, 1, 0], 24)), None);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("geoip_test_named_tag_only.dat");
        std::fs::write(&path, &dat).unwrap();

        let mut mgr = GeoIpManager::default();
        mgr.load_from_dat_file(&path).unwrap();

        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        assert!(mgr.matches_tag(ip, "CLOUDFLARE"));
        assert!(mgr.matches_tag(ip, "cloudflare"));
        assert!(!mgr.matches_tag("1.1.2.1".parse().unwrap(), "CLOUDFLARE"));

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
        crate::matcher::geoip_converter::convert_dat_to_mmdb(&mmdb_source_path, &mmdb_path, None)
            .unwrap();

        let mut mgr = GeoIpManager::default();
        mgr.use_mmdb(&mmdb_path.to_string_lossy(), &GeoIpManager::default())
            .unwrap();
        mgr.load_from_dat_file(&dat_path).unwrap();

        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(mgr.matches_tag(ip, "US"));
        assert!(!mgr.matches_tag(ip, "CN"));
        assert!(mgr.matches_tag(ip, "CLOUDFLARE"));
        assert!(mgr.matches_any_tag(ip, &[Arc::from("CN"), Arc::from("CLOUDFLARE")]));

        let mmdb_miss: IpAddr = "2001:db9::1".parse().unwrap();
        assert!(!mgr.matches_tag(mmdb_miss, "CN"));
        assert!(mgr.matches_tag(mmdb_miss, "CLOUDFLARE"));
        assert!(!mgr.matches_tag(mmdb_miss, "US"));

        drop(mgr);
        let _ = std::fs::remove_file(mmdb_source_path);
        let _ = std::fs::remove_file(dat_path);
        let _ = std::fs::remove_file(mmdb_path);
    }

    fn tags(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| name.to_string()).collect()
    }

    /// JSON 里不带前缀长度的地址按单个地址算：`198.51.100.7` 是 /32，`2001:db8::7` 是 /128，旁边的地址不算。以前它们
    /// 读不出来，悄悄丢掉
    /// An address in JSON without a prefix length is that one address: `198.51.100.7` is a /32
    /// and `2001:db8::7` a /128, the addresses next to them not included. They used not to
    /// parse and were dropped in silence
    #[test]
    fn a_json_address_without_a_prefix_is_that_one_address() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts.json");
        std::fs::write(
            &path,
            r#"{"entries":[{"country_code":"HOSTS","ips":["198.51.100.7","2001:db8::7"]}]}"#,
        )
        .unwrap();
        let mut manager = GeoIpManager::default();
        manager.apply_parsed(GeoIpManager::parse_file(&path, &tags(&["hosts"])).unwrap());
        let hosts = [Arc::from("HOSTS")];
        for (ip, expected) in [
            ("198.51.100.7", true),
            ("198.51.100.8", false),
            ("2001:db8::7", true),
            ("2001:db8::8", false),
        ] {
            assert_eq!(
                manager.matches_any_tag(ip.parse().unwrap(), &hosts),
                expected,
                "{ip}"
            );
        }
    }

    /// 读不出来的网段跳过，按条目各记一条告警，说跳过了几条、第一条是什么，别的网段照常：JSON 里前缀超过位宽的、写错的、
    /// 带空格的，.dat 里地址不是 4 或 16 字节的。一个网段都读不出来的标签不算文件提供了，用它的规则什么都不匹配，
    /// 和文件里没有这个标签一样
    /// Networks that cannot be read are skipped with one warning for each entry, saying how many
    /// and what the first was, the other networks loading as usual: in JSON one whose prefix is
    /// wider than the address, one written wrong, one with a space; in a .dat an address that is
    /// not 4 or 16 bytes. A tag none of whose networks can be read does not count as provided by
    /// the file, so rules using it match nothing, as when the file lacks the tag
    #[test]
    fn networks_that_cannot_be_read_are_warned_about() {
        use prost::Message;
        let dir = tempfile::tempdir().unwrap();
        let json = dir.path().join("geoip.json");
        std::fs::write(
            &json,
            r#"{"entries":[
                {"country_code":"SOME","ips":["192.0.2.0/24","198.51.100.0/33"," 203.0.113.0/24"]},
                {"country_code":"NONE","ips":["10.0.0.0/8x","bogus"]}
            ]}"#,
        )
        .unwrap();
        let dat = dir.path().join("geoip.dat");
        let cidr = |ip: Vec<u8>, prefix| super::super::geoip_proto::Cidr { ip, prefix };
        let list = super::super::geoip_proto::GeoIPList {
            entry: vec![super::super::geoip_proto::GeoIP {
                country_code: "SOME".to_string(),
                cidr: vec![
                    cidr(vec![192, 0, 2, 0], 24),
                    cidr(vec![198, 51, 100, 0, 0], 24),
                ],
            }],
        };
        std::fs::write(&dat, list.encode_to_vec()).unwrap();

        let (warnings, guard) = crate::engine::test_support::Warnings::capture();
        let from_json = GeoIpManager::parse_file(&json, &tags(&["some", "none"])).unwrap();
        let from_dat = GeoIpManager::parse_file(&dat, &tags(&["some"])).unwrap();
        drop(guard);
        for parsed in [from_json, from_dat] {
            assert_eq!(parsed.tag_count(), 1);
            let mut manager = GeoIpManager::default();
            manager.apply_parsed(parsed);
            assert!(manager.matches_tag("192.0.2.1".parse().unwrap(), "SOME"));
            assert!(!manager.matches_tag("203.0.113.1".parse().unwrap(), "SOME"));
        }
        let lines = warnings.lines();
        let skipped: Vec<&String> = lines
            .iter()
            .filter(|line| line.contains("skipped GeoIP networks that cannot be read"))
            .collect();
        assert_eq!(skipped.len(), 3, "{lines:#?}");
        for (line, (tag, count, example)) in skipped.iter().zip([
            ("SOME", 2, "198.51.100.0/33"),
            ("NONE", 2, "10.0.0.0/8x"),
            ("SOME", 1, "an address of 5 bytes"),
        ]) {
            assert!(
                line.contains(tag)
                    && line.contains(&format!("skipped={count}"))
                    && line.contains(example),
                "{line}"
            );
        }
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

        let mut manager = GeoIpManager::default();
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

        let mut manager = GeoIpManager::default();
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

        let mut manager = GeoIpManager::default();
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
        let mut manager = GeoIpManager::default();
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
        crate::matcher::geoip_converter::convert_dat_to_mmdb(&source_path, &mmdb_path, None)
            .unwrap();

        let mmdb = Mmdb::open(
            mmdb_path.to_str().unwrap(),
            FileStamp::of(&mmdb_path).unwrap(),
        )
        .unwrap();
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
