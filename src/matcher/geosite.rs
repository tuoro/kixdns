// GeoSite 域名分类匹配器 / GeoSite domain category matcher
// 支持基于域名分类的路由决策 / Supports routing decisions based on domain categorization

use std::fs;
use std::path::{Path, PathBuf};

use std::hash::BuildHasher;
use std::io::Read;

use anyhow::Context;
use hashbrown::HashTable;
use prost::Message;
use regex::{Regex, RegexSet, RegexSetBuilder};
use rustc_hash::{FxBuildHasher, FxHashMap};
use serde::Deserialize;
use tracing::{debug, info, warn};

use super::{MAX_REGEX_LEN, REGEX_SIZE_LIMIT, ascii_regex_pattern, domain_suffix_matches};

/// 域名匹配器类型 / Domain matcher type
#[derive(Debug, Clone)]
pub enum DomainMatcher {
    /// 完全匹配 / Full domain match
    Full(String),
    /// 后缀匹配：域名本身及其所有子域名，按整段比较；开头的点不计
    /// Suffix match: the domain itself and every subdomain, by whole labels; a leading dot is ignored
    Suffix(String),
    /// 关键词匹配 / Keyword match
    Keyword(String),
    /// 正则匹配 / Regex match
    Regex(Regex),
}

impl DomainMatcher {
    /// 检查域名是否匹配 / Check if domain matches
    pub fn matches(&self, domain: &str) -> bool {
        match self {
            DomainMatcher::Full(pattern) => domain.eq_ignore_ascii_case(pattern),
            DomainMatcher::Suffix(suffix) => {
                // 开头的点不计：.github.com 和 github.com 一样匹配 github.com 及其子域名。按整段比较，
                // 所以 github.com 不匹配 notgithub.com。
                // A leading dot is ignored: .github.com, like github.com, matches github.com and its
                // subdomains. Labels compare whole, so github.com does not match notgithub.com.
                let suffix = suffix.strip_prefix('.').unwrap_or(suffix);
                if suffix.is_empty() {
                    // 空值匹配不到任何域名，而不是全部 / An empty value matches no domain, not every one
                    return false;
                }
                if domain
                    .bytes()
                    .chain(suffix.bytes())
                    .any(|b| b.is_ascii_uppercase())
                {
                    domain_suffix_matches(
                        &domain.to_ascii_lowercase(),
                        &suffix.to_ascii_lowercase(),
                    )
                } else {
                    domain_suffix_matches(domain, suffix)
                }
            }
            DomainMatcher::Keyword(keyword) => {
                // 两边都没有大写时零分配比较，否则都转小写，和 Suffix 一样
                // With no capitals on either side compare without allocating, otherwise
                // lowercase both, as for Suffix
                if domain
                    .bytes()
                    .chain(keyword.bytes())
                    .any(|b| b.is_ascii_uppercase())
                {
                    domain
                        .to_ascii_lowercase()
                        .contains(&keyword.to_ascii_lowercase())
                } else {
                    domain.contains(keyword.as_str())
                }
            }
            DomainMatcher::Regex(regex) => regex.is_match(domain),
        }
    }
}

/// GeoSite 条目 / GeoSite entry
#[derive(Debug, Clone)]
pub struct GeoSiteEntry {
    pub tag: String,
    pub matchers: Vec<DomainMatcher>,
}

/// 一组小写域名，存在一整块内存里：名字首尾相接，各自前面两个字节记长度，哈希表只记每个名字的起点。
/// 几十万条名字只占两块大内存。每条单独分配时，几十万个小块和加载时的临时内存交错在一起，临时内存
/// 释放后整页还不回去：三个常用的 tag（约 33 万条）存的数据只有 13 MiB，进程却为它们多占 24 MiB。
/// A set of lowercase names kept in one block of memory: the names back to back, each preceded
/// by two bytes holding its length, and a hash table recording only where each name starts.
/// Hundreds of thousands of names take two large blocks. Allocated one by one, they were hundreds
/// of thousands of small blocks interleaved with the temporary memory of loading, and the pages
/// could not be returned once that was freed: three common tags (about 330,000 names) held 13 MiB
/// of data while the process took 24 MiB more for them.
#[derive(Default)]
struct NameSet {
    /// 每个名字是两个字节的长度（小端）加上名字本身 / Each name is a two-byte length (little-endian) followed by the name
    bytes: Vec<u8>,
    /// 每个名字在 `bytes` 里的起点 / Where each name starts in `bytes`
    starts: HashTable<u32>,
}

impl NameSet {
    /// 能放下 `names` 个、总长 `total` 字节的名字 / Room for `names` names of `total` bytes together
    fn with_capacity(names: usize, total: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(total + 2 * names),
            starts: HashTable::with_capacity(names),
        }
    }

    fn hash(name: &[u8]) -> u64 {
        FxBuildHasher.hash_one(name)
    }

    /// 从 `start` 开始的那个名字 / The name starting at `start`
    fn name_at(bytes: &[u8], start: u32) -> &[u8] {
        let start = start as usize;
        let len = u16::from_le_bytes([bytes[start], bytes[start + 1]]) as usize;
        &bytes[start + 2..start + 2 + len]
    }

    /// 加入 `name` 的小写形式，已经有了就不变。名字长到两个字节记不下（超过 65535 字节），或这块
    /// 内存超过 4 GiB 时放不进来，返回 false。
    /// Adds `name` lowercased; nothing changes when it is there already. Returns false when it
    /// cannot go in: a name too long for two bytes to hold (over 65535 bytes), or this block
    /// past 4 GiB.
    fn insert(&mut self, name: &str) -> bool {
        let (Ok(len), Ok(start)) = (u16::try_from(name.len()), u32::try_from(self.bytes.len()))
        else {
            return false;
        };
        let Self { bytes, starts } = self;
        // 先写进去，按写好的小写形式算哈希、找重复；重复就撤回
        // Written first, so the hash and the duplicate check use the lowercased form; withdrawn
        // when it is a duplicate
        bytes.extend_from_slice(&len.to_le_bytes());
        bytes.extend(name.bytes().map(|b| b.to_ascii_lowercase()));
        let written = Self::name_at(bytes, start);
        let hash = Self::hash(written);
        if starts
            .find(hash, |&other| Self::name_at(bytes, other) == written)
            .is_some()
        {
            bytes.truncate(start as usize);
        } else {
            starts.insert_unique(hash, start, |&other| {
                Self::hash(Self::name_at(bytes, other))
            });
        }
        true
    }

    /// 去掉多余的容量：边加边建时按需翻倍增长，最后可能空着将近一半
    /// Drops spare capacity: grown by doubling while built entry by entry, it may end almost half
    /// empty
    fn shrink_to_fit(&mut self) {
        let Self { bytes, starts } = self;
        bytes.shrink_to_fit();
        starts.shrink_to_fit(|&start| Self::hash(Self::name_at(bytes, start)));
    }

    /// 有没有 `name` 这个名字（调用方已转成小写） / Whether `name` is one of the names (the caller lowercased it)
    fn contains(&self, name: &str) -> bool {
        !self.starts.is_empty()
            && self
                .starts
                .find(Self::hash(name.as_bytes()), |&start| {
                    Self::name_at(&self.bytes, start) == name.as_bytes()
                })
                .is_some()
    }

    fn len(&self) -> usize {
        self.starts.len()
    }

    fn is_empty(&self) -> bool {
        self.starts.is_empty()
    }

    /// 所有名字（测试用，顺序不保留） / Every name (for tests; order is not kept)
    #[cfg(test)]
    fn iter(&self) -> impl Iterator<Item = &str> {
        self.starts.iter().map(|&start| {
            std::str::from_utf8(Self::name_at(&self.bytes, start))
                .expect("names go in as str and are lowercased by ASCII only")
        })
    }
}

impl std::fmt::Debug for NameSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NameSet")
            .field("names", &self.len())
            .field("bytes", &self.bytes.len())
            .finish()
    }
}

/// 一个 tag 的匹配器，按查找方式分开存放。完整域名和后缀放进哈希集合，查找时从整个域名开始、
/// 每次去掉最左边一段去查，次数只取决于域名有几段，和这个 tag 有多少条无关；正则合成一组，
/// 一遍扫完；关键词和少见的写法仍逐条比较。结果和对每一条调用 [`DomainMatcher::matches`] 完全相同。
/// One tag's matchers, stored by how they are looked up. Full names and suffixes go into
/// hash sets, found by starting from the whole name and dropping the leftmost label each
/// step, so the cost depends on how many labels the name has, not on how many entries the
/// tag has; regexes are combined into one set and scanned in a single pass; keywords and
/// rare spellings are still tried one by one. The result is exactly that of calling
/// [`DomainMatcher::matches`] on every entry.
#[derive(Debug, Default)]
pub struct TagMatchers {
    /// `Full` 条目，小写 / `Full` entries, lowercased
    full: NameSet,
    /// `Suffix` 条目去掉开头一个点后的值，小写 / `Suffix` entries with one leading dot removed, lowercased
    suffixes: NameSet,
    /// `Regex` 条目 / `Regex` entries
    regexes: Regexes,
    /// 其余条目（关键词、两个点开头的后缀），按加载顺序 / Every other entry (keywords, suffixes with two leading dots), in load order
    others: Vec<DomainMatcher>,
}

/// 一个 tag 的正则条目，合成一个个 [`RegexSet`]：每 [`Regexes::SET_SIZE`] 条一组（写法合起来不超过一条正则的上限，见
/// [`Regexes::groups`]），一遍扫描就知道一组里有没有哪条命中：`geolocation-!cn` 这样带上百条正则的 tag，逐条比较要几微秒，
/// 合起来不到一微秒。编译后合起来也不超过一条正则的上限，超出的组对半分开再合（见 [`Regexes::combine`]）
/// One tag's regex entries, combined into [`RegexSet`]s: [`Regexes::SET_SIZE`] of them to a group
/// (no longer together than one regex may be, see [`Regexes::groups`]), so a single scan tells
/// whether any in that group matches: a tag like `geolocation-!cn` with over a hundred regexes
/// takes microseconds one by one and well under one combined. Compiled, a group is no larger
/// than one regex may be either, and one that is gets halved and combined again (see
/// [`Regexes::combine`])
#[derive(Debug, Default)]
struct Regexes(Vec<RegexSet>);

impl Regexes {
    /// 一个集合最多合这么多条。集合在匹配时边走边建状态，存在一块有上限的缓存里；条数多了状态装不下，
    /// 缓存一次次清空以后就退回慢上千倍的做法。拦截列表里常见的通配符正则，一千多条合成一个集合时，
    /// 每个没命中的名字要比 2 毫秒左右（1500 条时单核每秒只答得了四百多个查询）；分成每组 256 条，
    /// 和只有七百条时一样快。
    /// The most regexes one set combines. A set builds its states while matching and keeps them in
    /// a cache of bounded size; with too many regexes the states do not fit, and once the cache has
    /// been cleared over and over matching falls back to a way a thousand times slower. Over a
    /// thousand of the wildcard regexes common in blocklists, combined into one set, took about two
    /// milliseconds for every name none of them matched (with 1500 one core answered some four
    /// hundred queries a second); in groups of 256 they match as fast as seven hundred did.
    const SET_SIZE: usize = 256;

    /// 由各条正则的写法建成，每条只编译这一次 / Built from the regexes' patterns, each compiled
    /// this once
    fn new(patterns: Vec<String>) -> Self {
        let mut sets = Vec::new();
        for group in Self::groups(&patterns) {
            Self::combine(group, &mut sets);
        }
        Self(sets)
    }

    /// 把 `group` 合成集合放进 `sets`，编译后最多 [`REGEX_SIZE_LIMIT`]，和一条正则一样。集合里装着每一条，单独编译就
    /// 超出上限的那条放在集合里也超出，所以合起来不放宽每条的上限。超出时对半分开各自再合，只剩一条还超出就跳过它，什么
    /// 名字都不匹配，和单独编译时一样；别的组不受影响。以前集合的上限是每条的上限乘以条数：单独编译不出的正则放进大集合
    /// 照样编进去，同一条正则在小 tag 里跳过、在大 tag 里命中；一组合不成，整个 tag 的正则都改成逐条比较
    /// Combines `group` into sets put in `sets`, each at most [`REGEX_SIZE_LIMIT`] compiled, as one
    /// regex may be. A set holds every one of its regexes, so one over the limit compiled alone is
    /// over it inside a set too, and combining keeps each regex's limit. A group over it is halved
    /// and each half combined again, and a single regex still over it is skipped, matching no
    /// name, as compiled alone; the other groups are not affected. A set's limit used to be the
    /// per-regex limit times the number of regexes: a regex that would not compile alone went into
    /// a large set all the same, so one regex was skipped in a small tag and matched in a large
    /// one; and when one group could not combine, the whole tag's regexes were tried one by one
    fn combine(group: &[String], sets: &mut Vec<RegexSet>) {
        match RegexSetBuilder::new(group)
            .size_limit(REGEX_SIZE_LIMIT)
            .build()
        {
            Ok(set) => sets.push(set),
            Err(err) => match group {
                [pattern] => {
                    warn!(pattern = %pattern, error = %err,
                        "GeoSite regex pattern does not compile, skipping it");
                }
                _ => {
                    let (first, second) = group.split_at(group.len() / 2);
                    Self::combine(first, sets);
                    Self::combine(second, sets);
                }
            },
        }
    }

    /// 按顺序分组：每组最多 [`Self::SET_SIZE`] 条，写法合起来最多 [`MAX_REGEX_LEN`] 字节，一条就比这长的（改写成 Go
    /// 的字符类会变长）自成一组。合成集合时一组的正则同时解析成语法树、都留到编译完，合起来不该比一条最长的正则更占
    /// 内存：数据里 64 条 16 KiB 的 `\pL` 以前合成一组，要 2 GB。真实数据里的正则短，照样每 256 条一组
    /// In order, in groups of at most [`Self::SET_SIZE`] whose patterns come to at most
    /// [`MAX_REGEX_LEN`] bytes together, one longer than that by itself (rewriting the Go way
    /// lengthens it) making a group alone. Combining a group into a set parses all its regexes
    /// into syntax trees at once and keeps them until compiled, so together they should take no
    /// more than the longest regex may: 64 regexes of 16 KiB of `\pL` in the data used to
    /// combine into one group, taking 2 GB. The regexes of real data are short and still go 256
    /// to a group
    fn groups(patterns: &[String]) -> impl Iterator<Item = &[String]> {
        let mut rest = patterns;
        std::iter::from_fn(move || {
            if rest.is_empty() {
                return None;
            }
            let mut bytes = 0;
            let end = rest
                .iter()
                .take(Self::SET_SIZE)
                .position(|pattern| {
                    bytes += pattern.len();
                    bytes > MAX_REGEX_LEN
                })
                .unwrap_or(rest.len().min(Self::SET_SIZE))
                .max(1);
            let (group, after) = rest.split_at(end);
            rest = after;
            Some(group)
        })
    }

    fn is_match(&self, domain: &str) -> bool {
        self.0.iter().any(|set| set.is_match(domain))
    }

    fn len(&self) -> usize {
        self.0.iter().map(RegexSet::len).sum()
    }

    /// 正则重新展开成一条条（测试用） / The regexes one by one again (for tests)
    #[cfg(test)]
    fn to_regexes(&self) -> Vec<Regex> {
        self.0
            .iter()
            .flat_map(RegexSet::patterns)
            .filter_map(|pattern| super::limited_regex(pattern).ok())
            .collect()
    }
}

/// 一边加条目一边建的 [`TagMatchers`]。解析数据文件时每读出一条就加进来，不必先把整个 tag 的条目收齐：
/// 收齐再建时，几十万条的临时字符串和数组用完以后，有好几 MiB 留在分配器里还不回去（只加载 `cn` 时进程
/// 多占 9 MiB，其中 tag 本身的数据只有 2.5 MiB）。
/// A [`TagMatchers`] built as entries are added. Parsing a data file adds each entry as it is
/// read instead of first collecting the whole tag: collected first, the hundreds of thousands of
/// temporary strings and the arrays holding them left several MiB in the allocator once freed
/// (with only `cn` loaded the process took 9 MiB more, of which the tag's own data was 2.5 MiB).
#[derive(Default)]
struct TagBuilder {
    tag: TagMatchers,
    /// 正则的写法，到 `finish` 才合成编译 / The regexes' patterns, combined and compiled in `finish`
    regexes: Vec<String>,
}

impl TagBuilder {
    /// 能放下 `full` 和 `suffixes`（各是条数和总长）的 builder / A builder with room for `full` and
    /// `suffixes` (each a count and a total length)
    fn with_capacity(full: (usize, usize), suffixes: (usize, usize)) -> Self {
        Self {
            tag: TagMatchers {
                full: NameSet::with_capacity(full.0, full.1),
                suffixes: NameSet::with_capacity(suffixes.0, suffixes.1),
                ..TagMatchers::default()
            },
            regexes: Vec::new(),
        }
    }

    fn add(&mut self, matcher: DomainMatcher) {
        let tag = &mut self.tag;
        match &matcher {
            DomainMatcher::Full(name) => {
                if !tag.full.insert(name) {
                    // 放不进去的（长得不像域名）照原样逐条比较 / One that does not fit (no real name is that long) is tried as it is
                    tag.others.push(matcher);
                }
            }
            DomainMatcher::Suffix(suffix) => {
                let value = suffix.strip_prefix('.').unwrap_or(suffix);
                if value.is_empty() {
                    // 匹配不到任何域名（见 `DomainMatcher::matches`）/ Matches no domain (see `DomainMatcher::matches`)
                    return;
                }
                if value.starts_with('.') {
                    // 两个点开头的值按字符串结尾比较，不按整段，所以逐条比
                    // A value with two leading dots compares by string ending, not by label,
                    // so it is tried as it is
                    tag.others.push(matcher);
                    return;
                }
                if !tag.suffixes.insert(value) {
                    // 同上 / As above
                    tag.others.push(matcher);
                }
            }
            DomainMatcher::Regex(regex) => self.regexes.push(regex.as_str().to_owned()),
            // 请求名是小写的，keyword 也存成小写，数据文件里写成大写的才命中得了
            // Request names are lowercase, so the keyword is stored lowercase too, or one
            // the data file writes in capitals never matches
            DomainMatcher::Keyword(keyword) => tag
                .others
                .push(DomainMatcher::Keyword(keyword.to_ascii_lowercase())),
        }
    }

    /// 加入数据文件里读出的一条 / Adds one entry read from a data file
    fn add_entry(&mut self, entry: DatEntry) {
        match entry {
            DatEntry::Matcher(matcher) => self.add(matcher),
            // 写错的正则跳过，什么名字都不匹配，和 JSON 数据里一样。以前换成 `^$` 顶替，而根域名的名字正是空的
            // A regex written wrong is skipped and matches no name, as in JSON data. It used to be
            // replaced with `^$`, and the root name is the empty one
            DatEntry::Regex(pattern) => match ascii_regex_pattern(&pattern) {
                Ok(pattern) => self.regexes.push(pattern),
                Err(err) => {
                    warn!(pattern = %pattern, error = %err,
                         "invalid GeoSite regex pattern, skipping it");
                }
            },
        }
    }

    fn finish(self) -> TagMatchers {
        let mut tag = self.tag;
        tag.regexes = Regexes::new(self.regexes);
        tag.full.shrink_to_fit();
        tag.suffixes.shrink_to_fit();
        tag
    }
}

impl TagMatchers {
    /// 由一个 tag 的条目建成。名字和关键词存成小写（见 [`TagBuilder::add`]），条目不必先转
    /// Built from a tag's entries. Names and keywords are stored lowercased (see
    /// [`TagBuilder::add`]), so entries need no lowering first
    fn new(entries: Vec<DatEntry>) -> Self {
        // 先数好条数和总长，两组名字各一次分配到位 / Count first, so each set of names is allocated once
        let (mut full, mut suffixes) = ((0, 0), (0, 0));
        for entry in &entries {
            match entry {
                DatEntry::Matcher(DomainMatcher::Full(name)) => {
                    (full.0, full.1) = (full.0 + 1, full.1 + name.len())
                }
                DatEntry::Matcher(DomainMatcher::Suffix(suffix)) => {
                    (suffixes.0, suffixes.1) = (suffixes.0 + 1, suffixes.1 + suffix.len())
                }
                _ => {}
            }
        }
        let mut builder = TagBuilder::with_capacity(full, suffixes);
        for entry in entries {
            builder.add_entry(entry);
        }
        builder.finish()
    }

    fn matches(&self, domain: &str) -> bool {
        let lowered;
        let name = if domain.bytes().any(|b| b.is_ascii_uppercase()) {
            lowered = domain.to_ascii_lowercase();
            lowered.as_str()
        } else {
            domain
        };
        self.full.contains(name)
            || self.suffix_matches(name)
            || self.regexes.is_match(domain)
            || self.others.iter().any(|matcher| matcher.matches(domain))
    }

    /// 域名本身，或它某个点之后的部分，是不是一个后缀条目：正是 [`domain_suffix_matches`]
    /// 对不带开头点的后缀的判断
    /// Whether the name itself, or what follows one of its dots, is a suffix entry: exactly
    /// what [`domain_suffix_matches`] decides for a suffix without a leading dot
    fn suffix_matches(&self, name: &str) -> bool {
        !self.suffixes.is_empty()
            && (self.suffixes.contains(name)
                || name
                    .match_indices('.')
                    .any(|(dot, _)| self.suffixes.contains(&name[dot + 1..])))
    }

    fn len(&self) -> usize {
        self.full.len() + self.suffixes.len() + self.regexes.len() + self.others.len()
    }

    /// 条目重新展开成匹配器列表（测试用，顺序不保留）
    /// The entries as a list of matchers again (for tests; order is not kept)
    #[cfg(test)]
    fn to_matchers(&self) -> Vec<DomainMatcher> {
        self.full
            .iter()
            .map(|name| DomainMatcher::Full(name.to_owned()))
            .chain(
                self.suffixes
                    .iter()
                    .map(|suffix| DomainMatcher::Suffix(suffix.to_owned())),
            )
            .chain(
                self.regexes
                    .to_regexes()
                    .into_iter()
                    .map(DomainMatcher::Regex),
            )
            .chain(self.others.iter().cloned())
            .collect()
    }
}

/// 数据换进管理器以后、放掉写锁才做的事：记下换完以后的规模，放掉换下来的数据（见 [`GeoSiteManager::swap_source`]）。
/// 以前两样都在写锁里做：日志要格式化、写出去，释放一个大 tag 的索引和建它差不多费时，为此还在锁里起一个线程，这期间
/// 所有按 GeoSite 匹配的查询都停着
/// What is left once data is swapped into a manager, done after the write lock is released:
/// logging the size the swap left, and freeing the data swapped out (see
/// [`GeoSiteManager::swap_source`]). Both used to happen under the write lock: a log line is
/// formatted and written out, freeing a large tag's index takes about as long as building it
/// and a thread was started for that under the lock, and every GeoSite match stalled meanwhile
#[must_use = "finish it once the manager's write lock is released"]
pub struct Swapped {
    /// 这个文件换进来几个 tag / How many tags the file swapped in
    loaded: usize,
    /// 换完以后的 tag 数和条目总数 / The tags and all their entries after the swap
    totals: (usize, usize),
    /// 换下来的数据 / The data swapped out
    retired: Vec<TagMatchers>,
}

impl Swapped {
    /// 记下规模、放掉换下来的数据，给出这个文件换进来几个 tag / Logs the size and frees the data
    /// swapped out, giving how many tags the file swapped in
    pub fn finish(self) -> usize {
        let (tags, domains) = self.totals;
        info!(
            geosite_tags = tags,
            total_domains = domains,
            "GeoSite data loaded"
        );
        drop(self.retired);
        self.loaded
    }
}

/// GeoSite 数据库管理器 / GeoSite database manager
/// 使用 FxHashMap 实现高性能查找（由外层 RwLock 保护线程安全）/ Uses FxHashMap for high-performance lookup (thread-safety protected by outer RwLock)
pub struct GeoSiteManager {
    // Tag -> its matchers, indexed (see `TagMatchers`). Matching needs no cache in front: it is
    // a few hash lookups plus one regex-set scan, cheaper than a cache lookup and insert, and a
    // cache keyed by every name ever asked grew to hundreds of megabytes on unique names
    // 匹配不再经过缓存：几次哈希查找加一遍正则集合扫描，比查一次缓存、写一条缓存还快；按问过的每个
    // 名字存结果的缓存，在全是新名字时会涨到几百兆
    database: FxHashMap<String, TagMatchers>,
    // 每个数据文件贡献的 tag，重载时据此只替换该文件的条目。按文件头一次读进来的先后排，也就是配置里写的
    // 先后；重载不改变位置。几个文件声明同一个 tag 时，排在后面的文件说了算，`database` 里放的是它的数据
    // Tags contributed by each data file, so a reload replaces only that file's entries. In the
    // order the files were first read, which is the order the configuration writes them in; a
    // reload keeps a file's place. Of several files declaring one tag the later file decides,
    // and `database` holds its data
    sources: Vec<(PathBuf, Vec<String>)>,
}

/// 一个数据文件解析出的 tag 与域名匹配器，尚未进入管理器
/// Tags and matchers parsed out of one data file, not yet applied to a manager.
/// They come indexed already (see [`TagMatchers`]): the index is built while
/// parsing, outside the manager's write lock, so applying them only swaps them in.
/// 已经建好索引（见 [`TagMatchers`]）：索引在解析时、管理器的写锁之外建好，应用时只是换进去。
pub type ParsedGeoSite = Vec<(String, TagMatchers)>;

/// 一个数据文件不再提供、要由前面的文件顶上的 tag，按顶上的文件分组（见 [`GeoSiteManager::handovers`]）
/// The tags a data file no longer provides that earlier files are to take over, grouped by
/// the file taking them (see [`GeoSiteManager::handovers`])
pub type Handovers = FxHashMap<PathBuf, Vec<String>>;

impl Default for GeoSiteManager {
    fn default() -> Self {
        Self::new()
    }
}

impl GeoSiteManager {
    /// 创建新的 GeoSite 管理器 / Create new GeoSite manager
    pub fn new() -> Self {
        Self {
            database: FxHashMap::default(),
            sources: Vec::new(),
        }
    }

    /// 添加 GeoSite 条目 / Add GeoSite entry
    #[cfg(test)]
    pub fn add_entry(&mut self, entry: GeoSiteEntry) {
        let entries = entry.matchers.into_iter().map(DatEntry::Matcher).collect();
        self.database.insert(entry.tag, TagMatchers::new(entries));
    }

    /// 域名在不在标签 `tag`（如 `cn`、`google`、`category-ads`）里。`tag` 是小写的：规则写的标签编译时就转了小写（见
    /// `matcher::geosite_tag`），数据文件里的读进来时转
    /// Whether the name is in tag `tag` (such as `cn`, `google` or `category-ads`). `tag` is
    /// lowercase: the tags rules write are lowercased as they compile (see
    /// `matcher::geosite_tag`), and those of data files as they are read
    #[inline]
    pub fn matches(&self, tag: &str, domain: &str) -> bool {
        self.database
            .get(tag)
            .is_some_and(|matchers| matchers.matches(domain))
    }

    /// 标签是否已加载，测试用 / Whether a tag is loaded, for tests
    #[cfg(test)]
    pub fn has_tag(&self, tag: &str) -> bool {
        self.database.contains_key(tag)
    }

    /// `tags`（规则用到的，小写）里哪些没有一个数据文件提供：用它们的规则永远不会命中
    /// The tags among `tags` (the ones rules use, lowercase) that no data file provides: rules
    /// using them never match
    pub fn missing_tags(&self, tags: &[String]) -> Vec<String> {
        tags.iter()
            .filter(|tag| !self.database.contains_key(*tag))
            .cloned()
            .collect()
    }

    /// 把数据文件 `path` 眼下说了算的标签里、属于 `tags`（不分大小写）的拿出来，连同它们的数据。重新读这个文件
    /// 什么都没读出来时，用它把在用的数据带进新建的管理器（见 `engine::geo` 的 `load_geosite`）。拿走以后
    /// 这个管理器不再完整，只该被换掉
    /// Takes out, data and all, the tags among `tags` (ignoring case) that data file `path`
    /// decides right now. When reading the file again gives nothing, this carries the data in
    /// use into the manager being built (see `load_geosite` in `engine::geo`). The manager is
    /// left incomplete and is only to be replaced
    pub fn take_source(&mut self, path: &Path, tags: &[String]) -> ParsedGeoSite {
        let key = Self::source_key(path);
        let Some(place) = self.sources.iter().position(|(source, _)| *source == key) else {
            return Vec::new();
        };
        let mut taken = Vec::new();
        for tag in std::mem::take(&mut self.sources[place].1) {
            if is_one_of(&tag, tags)
                && !self.later_source_provides(place, &tag)
                && let Some(matchers) = self.database.remove(&tag)
            {
                taken.push((tag, matchers));
            }
        }
        taken
    }

    /// 标签的所有域名匹配器，测试用 / Every domain matcher of a tag, for tests
    #[cfg(test)]
    pub fn get_tag_matchers(&self, tag: &str) -> Option<Vec<DomainMatcher>> {
        self.database.get(tag).map(TagMatchers::to_matchers)
    }
}

/// 解析出的这份数据有没有 `tags`（规则用到的，不分大小写）里的标签
/// Whether this parsed data has any of `tags` (the ones rules use, ignoring case)
pub fn parsed_provides_any(parsed: &ParsedGeoSite, tags: &[String]) -> bool {
    parsed.iter().any(|(tag, _)| is_one_of(tag, tags))
}

/// `tag`（已是小写）是不是 `tags` 里的一个，不分大小写 / Whether `tag` (lowercase already) is one of `tags`, ignoring case
fn is_one_of(tag: &str, tags: &[String]) -> bool {
    tags.iter().any(|wanted| wanted.eq_ignore_ascii_case(tag))
}

/// V2Ray GeoSite 数据格式 / V2Ray GeoSite data format
#[derive(Debug, Clone, Deserialize)]
pub struct V2RayGeoSite {
    /// Tag 名称 / Tag name
    pub tag: String,
    /// 域名列表 / Domain list
    pub domains: Vec<String>,
}

/// V2Ray GeoSite 列表格式 / V2Ray GeoSite list format
#[derive(Debug, Clone, Deserialize)]
pub struct V2RayGeoSiteList {
    /// GeoSite 条目列表 / GeoSite entries
    pub entries: Vec<V2RayGeoSite>,
}

/// GeoSite 标签在每个 `@` 处拆开，得到分类名和要求的属性：`category-games@cn@ads` 拆成 `category-games` 和
/// `cn`、`ads` 两个属性，`category-games` 就是它自己、不要求属性。分类名或哪个属性是空的（`tag@`、`@cn`、
/// `a@@b`）时不拆，整个就是分类名。以前只在第一个 `@` 处拆开，`a@cn@ads` 要的是一个叫 `cn@ads` 的属性，什么都
/// 选不出
/// Splits a GeoSite tag at every `@` into the list name and the attributes it asks for:
/// `category-games@cn@ads` is `category-games` with the attributes `cn` and `ads`, and
/// `category-games` is itself, asking for none. With the name or any attribute empty (`tag@`, `@cn`, `a@@b`)
/// nothing is split and the whole is the name. Only the first `@` used to split, so
/// `a@cn@ads` asked for one attribute named `cn@ads` and selected nothing
fn split_tag_attrs(tag: &str) -> (&str, Vec<&str>) {
    match tag.split_once('@') {
        Some((base, attrs)) if !base.is_empty() && !attrs.split('@').any(str::is_empty) => {
            (base, attrs.split('@').collect())
        }
        _ => (tag, Vec::new()),
    }
}

/// 一个域名的属性 `attrs` 里有没有 `wanted` 的每一个：和 V2Ray 一样都要有，按字面的键比较，两边都已是小写（见
/// `Domain::into_entry`、`matcher::geosite_tag`），所以 `!cn` 要的是键 `!cn`（domain-list-community 自己就用这个键），
/// 不是取反
/// Whether a domain's attributes `attrs` hold every one of `wanted`: all are required, as in
/// V2Ray, each compared as a literal key, both sides lowercase already (see
/// `Domain::into_entry` and `matcher::geosite_tag`), so `!cn` asks for the key `!cn`
/// (domain-list-community uses that key itself), not for a negation
///
/// The domains of a tag that lack an attribute are two matchers:
/// `geosite: google` together with `geosite_not: google@cn`.
fn has_attrs(attrs: &[String], wanted: &[String]) -> bool {
    wanted.iter().all(|key| attrs.contains(key))
}

/// 数据文件（.dat 或 JSON）里读出的一条。正则只留写法，等整个 tag 读完合成集合时才编译，只编译这一次（见
/// [`Regexes::new`]）
/// One entry read from a data file (.dat or JSON). A regex keeps only its pattern, compiled once
/// the whole tag is read and combined into sets, and only then (see [`Regexes::new`])
#[derive(Clone)]
enum DatEntry {
    Matcher(DomainMatcher),
    Regex(String),
}

/// V2Ray 数据里的一条域名（`Domain`），只留这里用到的字段，用 prost 按 protobuf 的规矩解：字段头和长度都是
/// 变长整数，字段不论先后，不认识的字段按线上类型跳过，长度越出消息就是坏数据，和 GeoIP 一样（见
/// `geoip_proto`）。proto3 不写取默认值的字段：没有类型时是 0（Plain，即关键词），v2ray 数据里的关键词条目正是
/// 这样写的；值为空时同样不写，这样的条目没有值
/// One domain (`Domain`) of V2Ray data with just the fields used here, decoded by protobuf's
/// rules with prost: keys and lengths are varints, fields come in any order, unknown fields
/// are skipped by wire type, and a length running past the message means broken data, as for
/// GeoIP (see `geoip_proto`). proto3 leaves out fields holding their default: without a type
/// it is 0 (Plain, that is a keyword), which is exactly how keyword entries are written in
/// v2ray data; an empty value is left out the same way, and such an entry has no value
#[derive(Clone, PartialEq, prost::Message)]
struct Domain {
    /// `type`
    #[prost(int32, tag = "1")]
    kind: i32,
    #[prost(string, tag = "2")]
    value: String,
    #[prost(message, repeated, tag = "3")]
    attribute: Vec<Attribute>,
}

impl Domain {
    /// 这条域名的条目和各个属性的 key（小写，供 `@attr` 筛选）；没有值时是 None
    /// This domain's entry and the key of each attribute (lowercase, for `@attr` filtering);
    /// None without a value
    fn into_entry(self) -> Option<(DatEntry, Vec<String>)> {
        if self.value.is_empty() {
            return None;
        }
        let value = self.value;
        // 根据 V2Ray Domain.Type 创建匹配器 / Create matcher based on V2Ray Domain.Type
        let entry = match self.kind {
            0 => DatEntry::Matcher(DomainMatcher::Keyword(value)), // Plain
            1 => DatEntry::Regex(value),                           // Regex
            2 => {
                // RootDomain - 转换为 Suffix 匹配器 / Convert to Suffix matcher
                DatEntry::Matcher(DomainMatcher::Suffix(format!(".{value}")))
            }
            3 => DatEntry::Matcher(DomainMatcher::Full(value)), // Full
            kind => {
                warn!(type = kind,
                     "unknown V2Ray domain type, using full matcher");
                DatEntry::Matcher(DomainMatcher::Full(value))
            }
        };
        let attrs = self
            .attribute
            .into_iter()
            .map(|attribute| attribute.key.to_ascii_lowercase())
            .collect();
        Some((entry, attrs))
    }
}

/// `Domain.Attribute` 的 key；`typed_value` 用不到，跳过不解 / The key of a `Domain.Attribute`;
/// its `typed_value` is not used and skipped undecoded
#[derive(Clone, PartialEq, prost::Message)]
struct Attribute {
    #[prost(string, tag = "1")]
    key: String,
}

/// .dat 文件的顺序读取：按需读出字段、跳过不要的部分，不把整个文件读进内存
/// Sequential reading of a .dat file: fields are read as needed and the rest skipped, without
/// reading the whole file into memory
struct DatReader {
    file: std::io::BufReader<fs::File>,
    /// 当前在文件里的位置 / The current position in the file
    pos: usize,
    /// 打开时的文件长度 / The file's length when opened
    len: usize,
}

impl DatReader {
    fn open(path: &Path) -> anyhow::Result<Self> {
        let file = fs::File::open(path)?;
        let len = usize::try_from(file.metadata()?.len())?;
        Ok(Self {
            file: std::io::BufReader::with_capacity(64 * 1024, file),
            pos: 0,
            len,
        })
    }

    /// 下一个字节，必须有 / The next byte, which must be there
    fn next_byte(&mut self) -> anyhow::Result<u8> {
        anyhow::ensure!(self.pos < self.len, "unexpected end of file");
        let mut byte = [0u8];
        self.file.read_exact(&mut byte)?;
        self.pos += 1;
        Ok(byte[0])
    }

    /// 读一个变长整数：最多 10 个字节，多了就是坏文件 / Reads a varint: 10 bytes at most,
    /// more means a broken file
    fn varint(&mut self) -> anyhow::Result<usize> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = self.next_byte()?;
            value |= u64::from(byte & 0x7F) << shift;
            if byte & 0x80 == 0 {
                return varint_len(value);
            }
        }
        anyhow::bail!("invalid varint in .dat file")
    }

    /// 从当前位置往后读到 `end` 为止，找下一个字段号是 `number` 的字段，给出它的值有多长，读的位置停在值的开头；
    /// 别的字段按线上类型跳过。字段头和长度都是变长整数。找的字段不是带长度的、哪个字段越出 `end`、线上类型不认识，
    /// 都是坏文件：越出的字段以前让条目到此为止，余下的域名悄悄丢掉。读到 `end` 也没找到时是 None
    /// Reads on from the current position up to `end` for the next field numbered `number`,
    /// giving the length of its value with the position left where the value starts; other
    /// fields are skipped by wire type. Keys and lengths are varints. The field not being
    /// length-delimited, any field running past `end`, or a wire type not known means a
    /// broken file: a field running past used to end its entry there, quietly dropping the
    /// domains left. None when `end` is reached without finding it
    fn next_field(&mut self, number: usize, end: usize) -> anyhow::Result<Option<usize>> {
        while self.pos < end {
            let key = self.varint()?;
            let (field, wire_type) = (key >> 3, key & 0x07);
            let len = match wire_type {
                0 => {
                    self.varint()?;
                    0
                }
                1 => 8,
                2 => self.varint()?,
                5 => 4,
                other => anyhow::bail!("invalid wire type {other} in .dat file"),
            };
            if runs_past(self.pos, len, end) {
                anyhow::bail!(
                    "truncated .dat file: field {field} at offset {} needs {len} bytes, past the end of its message at {end}",
                    self.pos
                );
            }
            if field == number {
                anyhow::ensure!(
                    wire_type == 2,
                    "invalid wire type {wire_type} for field {number} in .dat file"
                );
                return Ok(Some(len));
            }
            self.seek_to(self.pos + len)?;
        }
        Ok(None)
    }

    /// 接下来的 `len` 个字节，读进 `buf` / The next `len` bytes, read into `buf`
    fn read(&mut self, buf: &mut Vec<u8>, len: usize) -> anyhow::Result<()> {
        buf.clear();
        buf.resize(len, 0);
        self.file.read_exact(buf)?;
        self.pos += len;
        Ok(())
    }

    /// 移到文件里的 `pos` / Moves to `pos` in the file
    fn seek_to(&mut self, pos: usize) -> anyhow::Result<()> {
        let offset = i64::try_from(pos)? - i64::try_from(self.pos)?;
        self.file.seek_relative(offset)?;
        self.pos = pos;
        Ok(())
    }
}

/// 变长整数当作长度或位置用 / A varint used as a length or position
fn varint_len(value: u64) -> anyhow::Result<usize> {
    usize::try_from(value).context("varint in .dat file too large")
}

/// 从 `pos` 起的 `len` 个字节是否越出 `end`。`len` 是文件里读出来的，可以接近 u64::MAX：
/// 加起来溢出也算越出，不能让回绕成的小数通过检查、把读的位置退回前面
/// Whether `len` bytes from `pos` run past `end`. `len` is read from the file and may come
/// close to u64::MAX: a sum that overflows runs past too, rather than wrapping to a small
/// number that passes the check and moves the reading position back
fn runs_past(pos: usize, len: usize, end: usize) -> bool {
    pos.checked_add(len).is_none_or(|stop| stop > end)
}

impl GeoSiteManager {
    /// 加载数据文件里的每个标签，给出加载了几个，测试用；运行时只加载规则用到的（见 [`Self::parse_file`]）
    /// Loads every tag of a data file, giving how many, for tests; at run time only the tags
    /// rules use are loaded (see [`Self::parse_file`])
    #[cfg(test)]
    pub fn load_from_v2ray_file<P: AsRef<Path>>(&mut self, path: P) -> anyhow::Result<usize> {
        let path = path.as_ref();
        let parsed = Self::parse_file(path, &[])?;
        Ok(self.apply_source(path, parsed))
    }

    /// 解析 JSON 格式的数据文件里 `tags` 点名的标签（不分大小写；不点名时每个标签都要），不触碰管理器状态。
    /// 没点名的条目，域名原样跳过：借着文件内容（`RawValue`），不解析也不分配。一份几十万个域名的文件，
    /// 只为规则用到的几个标签建匹配器。以前每个标签都解析、都建匹配器，规则用不到的也一直占着内存
    /// Parse the `tags` a JSON data file names (ignoring case; every tag when none is named)
    /// without touching manager state. An entry not named has its domains skipped as they are,
    /// borrowed from the file's content (`RawValue`), neither parsed nor allocated: a file of
    /// hundreds of thousands of domains builds matchers only for the few tags rules use. Every
    /// tag used to be parsed and given matchers, those no rule uses holding memory all along
    ///
    /// 与 [`Self::parse_dat_file_selective`] 对称，同样与 [`Self::apply_source`] 配合：
    /// 调用方在锁外解析，只在替换数据时短暂持写锁。
    /// The counterpart of [`Self::parse_dat_file_selective`], pairing with
    /// [`Self::apply_source`] the same way: callers parse outside the lock and
    /// hold the write lock only while swapping data in.
    pub fn parse_json_file<P: AsRef<Path>>(
        path: P,
        tags: &[String],
    ) -> anyhow::Result<ParsedGeoSite> {
        #[derive(Deserialize)]
        struct Entry<'a> {
            tag: String,
            #[serde(borrow)]
            domains: &'a serde_json::value::RawValue,
        }
        #[derive(Deserialize)]
        struct List<'a> {
            #[serde(borrow)]
            entries: Vec<Entry<'a>>,
        }
        let path = path.as_ref();
        let content = fs::read_to_string(path)
            .with_context(|| format!("read geosite file: {}", path.display()))?;
        let list: List<'_> =
            serde_json::from_str(&content).with_context(|| "parse V2Ray GeoSite JSON format")?;
        let entries = list
            .entries
            .into_iter()
            .filter(|entry| tags.is_empty() || is_one_of(&entry.tag, tags))
            .map(|entry| {
                Ok(V2RayGeoSite {
                    domains: serde_json::from_str(entry.domains.get())?,
                    tag: entry.tag,
                })
            })
            .collect::<serde_json::Result<_>>()
            .with_context(|| "parse V2Ray GeoSite JSON format")?;
        Ok(Self::convert_v2ray_to_entries(V2RayGeoSiteList { entries }))
    }

    /// 按扩展名选择解析器解析一个数据文件，不触碰管理器状态
    /// Parse a data file with the parser its extension selects, without
    /// touching manager state
    ///
    /// `.dat` 走 V2Ray 二进制解析器，其余按 JSON 读；两种都只解出 `tags` 点名的标签，不点名时每个都解。
    /// 格式分派集中在这里：登记进 `sources` 的文件后续会被 `read_handovers` 再次读取，
    /// 两处必须用同一套判定，否则会拿错解析器。
    /// `.dat` uses the V2Ray binary parser and anything else is read as JSON; both
    /// decode just the tags `tags` names, or every tag when it names none.
    /// Keeping the dispatch in one place matters because a file registered in
    /// `sources` is read again later by `read_handovers`, and both have to agree on
    /// which parser a path needs.
    pub fn parse_file<P: AsRef<Path>>(path: P, tags: &[String]) -> anyhow::Result<ParsedGeoSite> {
        let path = path.as_ref();
        let is_dat = path
            .extension()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s.eq_ignore_ascii_case("dat"));
        if !is_dat {
            return Self::parse_json_file(path, tags);
        }
        if tags.is_empty() {
            Self::parse_dat_file_every_tag(path)
        } else {
            Self::parse_dat_file_selective(path, tags)
        }
    }

    /// 用一个数据文件的解析结果替换该文件此前贡献的 tag
    /// Replace the tags a data file contributed with its freshly parsed content
    ///
    /// 文件里删掉的 tag 随之消失，其它文件贡献的 tag 保持不变
    /// （`geosite_data_paths` 接受多个文件）。要由前面的文件顶上的 tag 当场从那些文件里读出来
    /// （见 [`Self::handovers`]），所以只用在别人读不到的管理器上；共享的管理器分三步换（见
    /// `engine::geo` 的 `reload_geosite_file`）
    /// Tags dropped from the file disappear with it while tags from other files
    /// stay (`geosite_data_paths` accepts several files). The tags earlier files are to
    /// take over are read from those files on the spot (see [`Self::handovers`]), so this
    /// is only for a manager nobody else reads; a shared one is swapped in three steps (see
    /// `reload_geosite_file` in `engine::geo`)
    pub fn apply_source<P: AsRef<Path>>(&mut self, path: P, parsed: ParsedGeoSite) -> usize {
        let path = path.as_ref();
        let handed_over = Self::read_handovers(self.handovers(path, &parsed));
        self.swap_source(path, parsed, handed_over, false).finish()
    }

    /// 数据文件 `path` 换成 `parsed` 时它不再提供、此前由它说了算、前面还有文件提供的 tag，按其中排得最后的那个文件
    /// 分组：那个文件把它们顶上，和全部重新读一遍的结果一样，不然名义上 tag 还在，命中的却是已经被删掉的数据。只读
    /// 管理器，共享的管理器在读锁下算
    /// The tags data file `path` no longer provides once it is `parsed`, that it decided
    /// until now and that earlier files still provide, grouped by the latest of those files:
    /// that file takes them over, as a full load would have it, or else the tag survives but
    /// matches data that was deleted. It only reads the manager, so a shared one works it
    /// out under the read lock
    pub fn handovers(&self, path: &Path, parsed: &ParsedGeoSite) -> Handovers {
        let key = Self::source_key(path);
        let mut handovers = Handovers::default();
        let Some(place) = self.sources.iter().position(|(source, _)| *source == key) else {
            return handovers;
        };
        for tag in &self.sources[place].1 {
            if parsed.iter().any(|(provided, _)| provided == tag)
                || self.later_source_provides(place, tag)
            {
                continue;
            }
            if let Some(other) = self.earlier_source_providing(place, tag) {
                handovers
                    .entry(other.to_path_buf())
                    .or_default()
                    .push(tag.clone());
            }
        }
        handovers
    }

    /// 从各个文件里读出 `handovers` 要它们顶上的 tag，不触碰管理器状态，调用方在锁外读：读文件、建索引要几十毫秒，
    /// 而写锁是整个匹配器共享的，以前在写锁里读，这期间所有查询都停着。一个文件不论顶上多少个 tag 都只解析一次。
    /// 读不出来、或者文件里已经没有的 tag 不在结果里，它正在用的数据留着，等那个文件自己重载时纠正，总好过留下一个空 tag
    /// Reads from each file the tags `handovers` gives it to take over, without touching
    /// manager state, so callers read outside the lock: reading a file and building its
    /// index takes tens of milliseconds, and the write lock is shared with matching, so
    /// reading under it, as was done before, stalled every query meanwhile. A file is
    /// parsed once however many tags it takes over. A tag that cannot be read, or that the
    /// file no longer has, is left out and keeps the data in use until that file's own
    /// reload fixes it, which beats leaving the tag empty
    pub fn read_handovers(handovers: Handovers) -> ParsedGeoSite {
        let mut handed_over = Vec::new();
        for (path, wanted) in handovers {
            match Self::parse_file(&path, &wanted) {
                Ok(parsed) => {
                    if parsed.len() < wanted.len() {
                        warn!(
                            path = %path.display(), wanted = wanted.len(), taken = parsed.len(),
                            "data file no longer contains every tag it was recorded as providing"
                        );
                    }
                    handed_over.extend(parsed);
                }
                Err(e) => {
                    warn!(
                        path = %path.display(), tags = wanted.len(), error = %e,
                        "failed to re-read shared tags, keeping the current entries"
                    );
                }
            }
        }
        handed_over
    }

    /// 把数据文件 `path` 新解析出的 `parsed` 换进来，替换它此前贡献的 tag；它不再提供、前面的文件顶上的 tag 换成
    /// `handed_over`（见 [`Self::read_handovers`]）里的数据。只换数据、不读文件，共享的管理器在写锁下调用，放锁以后
    /// 再把它交回的 [`Swapped`] 做完。它不再提供、也没有别的文件提供的 tag 随之消失；`keep_unprovided` 时留着正在用的
    /// 数据，仍算它提供的
    /// Swaps in `parsed`, data file `path`'s new content, in place of the tags it
    /// contributed; the tags it no longer provides that earlier files take over get the
    /// data in `handed_over` (see [`Self::read_handovers`]). It swaps data and reads no
    /// file, so a shared manager calls it under the write lock and finishes the [`Swapped`]
    /// it gives back once the lock is released. The tags it no longer provides that no other
    /// file provides disappear with it; with `keep_unprovided` they keep the data in use and
    /// still count as provided by it
    pub fn swap_source(
        &mut self,
        path: &Path,
        parsed: ParsedGeoSite,
        handed_over: ParsedGeoSite,
        keep_unprovided: bool,
    ) -> Swapped {
        let key = Self::source_key(path);
        // 这个文件排第几：读过的留在原位，头一次读的排到最后 / The file's place: one read before
        // keeps it, one read for the first time goes last
        let place = self
            .sources
            .iter()
            .position(|(source, _)| *source == key)
            .unwrap_or_else(|| {
                self.sources.push((key.clone(), Vec::new()));
                self.sources.len() - 1
            });
        let previous = std::mem::take(&mut self.sources[place].1);

        let mut tags = Vec::with_capacity(parsed.len());
        let mut retired = Vec::new();
        for (tag, matchers) in parsed {
            // 排在后面的文件也声明了这个 tag：那个文件说了算，索引里留着它的数据，这一份不进去
            // A later file declares the tag too: that file decides and its data stays in the
            // index, so this copy does not go in
            if self.later_source_provides(place, &tag) {
                retired.push(matchers);
            } else {
                retired.extend(self.database.insert(tag.clone(), matchers));
            }
            tags.push(tag);
        }
        let loaded_count = tags.len();
        for (tag, matchers) in handed_over {
            retired.extend(self.database.insert(tag, matchers));
        }

        // 这个文件不再提供的 tag：排在后面的文件还提供着，索引里本来就是那个文件的数据；前面的文件还提供着，刚换成了
        // 它的数据（读不出来时留着正在用的）。都没有时，索引里是本文件的旧条目，随之删掉
        // For tags this file no longer provides: with a later file still providing one the
        // index holds that file's data already; with an earlier file providing it, it just
        // got that file's data (or keeps the data in use when it could not be read). With
        // neither, the index holds this file's stale entries, which go with it
        for tag in previous {
            if tags.contains(&tag)
                || self.later_source_provides(place, &tag)
                || self.earlier_source_providing(place, &tag).is_some()
            {
                continue;
            }
            if keep_unprovided {
                tags.push(tag);
            } else {
                retired.extend(self.database.remove(&tag));
            }
        }
        self.sources[place].1 = tags;

        Swapped {
            loaded: loaded_count,
            totals: (
                self.database.len(),
                self.database.values().map(TagMatchers::len).sum(),
            ),
            retired,
        }
    }

    /// 排在第 `place` 个文件后面的文件里，有没有提供这个 tag 的
    /// Whether a file after the one at `place` provides this tag
    fn later_source_provides(&self, place: usize, tag: &str) -> bool {
        self.sources[place + 1..]
            .iter()
            .any(|(_, provided)| provided.iter().any(|name| name == tag))
    }

    /// 排在第 `place` 个文件前面、仍在提供这个 tag 的文件里排得最后的那个
    /// The latest of the files before the one at `place` that still provide this tag
    fn earlier_source_providing(&self, place: usize, tag: &str) -> Option<&Path> {
        self.sources[..place]
            .iter()
            .rev()
            .find(|(_, provided)| provided.iter().any(|name| name == tag))
            .map(|(path, _)| path.as_path())
    }

    /// 数据文件的身份：尽量用规范化后的绝对路径，这样配置里写的相对路径与
    /// 监视器事件带来的绝对路径指向同一条记录；无法规范化（文件刚被删掉等）时
    /// 退回原路径。
    /// Identity of a data file: the canonical absolute path where possible, so a
    /// relative path from the configuration and the absolute path a watcher
    /// event carries refer to the same entry; falls back to the path as given
    /// when it cannot be canonicalised (the file was just removed, say).
    fn source_key(path: &Path) -> PathBuf {
        std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
    }

    /// 从 .dat 文件加载 `tags` 这几个标签，给出加载了几个，测试用 / Loads the tags `tags` from a .dat
    /// file, giving how many, for tests
    #[cfg(test)]
    pub fn load_from_dat_file_selective<P: AsRef<Path>>(
        &mut self,
        path: P,
        tags: &[String],
    ) -> anyhow::Result<usize> {
        let path = path.as_ref();
        let parsed = Self::parse_dat_file_selective(path, tags)?;
        Ok(self.apply_source(path, parsed))
    }

    /// 按需解析 .dat 文件，不触碰管理器状态
    /// Parse the requested tags out of a .dat file without touching manager state
    ///
    /// 与 [`Self::apply_source`] 配合使用：调用方可以在锁外解析，只在替换数据时短暂持有写锁；
    /// 解析失败时管理器保持原样。
    /// Pairs with [`Self::apply_source`]: callers parse outside the lock and hold the
    /// write lock only while swapping data in, and a failed parse leaves the manager
    /// untouched.
    pub fn parse_dat_file_selective<P: AsRef<Path>>(
        path: P,
        tags: &[String],
    ) -> anyhow::Result<ParsedGeoSite> {
        if tags.is_empty() {
            return Ok(Vec::new());
        }
        Self::parse_dat_entries(path.as_ref(), Some(tags))
    }

    /// 解析 .dat 文件里的每一个 tag，不触碰管理器状态；[`Self::parse_file`] 不点名 tag 时走这里。
    /// 和按需解析是同一套读法（见 `parse_dat_entries` 里读 tag 字段的那段注释）
    /// Parse every tag of a .dat file without touching manager state; [`Self::parse_file`]
    /// comes here when no tag is named. It reads the file the same way as selective
    /// parsing (see the comment on reading the tag field in `parse_dat_entries`)
    fn parse_dat_file_every_tag(path: &Path) -> anyhow::Result<ParsedGeoSite> {
        Self::parse_dat_entries(path, None)
    }

    /// 按条目读 .dat 文件，留下要的 tag：`tags` 是点名的那些（小写，可以带一个或几个 `@属性`），None 时每个 tag 都要
    /// Read a .dat file entry by entry, keeping the wanted tags: the named `tags` (lowercase,
    /// and they may carry `@attribute`s), or every tag with None
    fn parse_dat_entries(path: &Path, tags: Option<&[String]>) -> anyhow::Result<ParsedGeoSite> {
        // Pre-process tags: split `tag@attr@…` syntax into (base, attributes)
        // Map: base_tag → Vec<(store_tag, attributes)>
        let mut tag_requests: FxHashMap<&str, Vec<(String, Vec<String>)>> = FxHashMap::default();
        for tag in tags.unwrap_or_default() {
            let (base, attrs) = split_tag_attrs(tag);
            tag_requests
                .entry(base)
                .or_default()
                .push((tag.clone(), attrs.into_iter().map(str::to_owned).collect()));
        }

        if let Some(tags) = tags {
            info!(requested_tags = ?tags,
                 "loading GeoSite data selectively from .dat file");
        }

        // 按条目顺序读，不把整个文件读进内存：一次读进 11 MB 的文件，释放以后约有 6 MiB 留在分配器里
        // 还不回去
        // Read entry by entry instead of reading the whole file into memory: an 11 MB file read
        // at once left about 6 MiB in the allocator after it was freed
        let mut file =
            DatReader::open(path).with_context(|| format!("read .dat file: {}", path.display()))?;
        // 一个字段的内容，各字段轮流使用 / One field's content, reused for every field
        let mut field = Vec::new();
        let mut parsed: ParsedGeoSite = Vec::new();

        // GeoSiteList 顶层只有 `repeated GeoSite entry = 1`，别的字段跳过。条目越出文件（写入中断或读到写了一半的
        // 覆盖）时整份文件拒绝，否则调用方会把读到的那部分当成完整版本，文件里其余的 tag 就被删掉了（见
        // `DatReader::next_field`）
        // GeoSiteList holds only `repeated GeoSite entry = 1` at the top; other fields are
        // skipped. An entry running past the file (an interrupted write, or a half-written
        // overwrite caught in the act) gets the whole file rejected: otherwise the caller
        // takes the part that was read as the complete file and drops every tag the rest of
        // it holds (see `DatReader::next_field`)
        while let Some(entry_len) = file.next_field(1, file.len)? {
            let entry_start = file.pos;
            let entry_end = entry_start + entry_len;

            // 先只读 tag（字段 1），判断这个条目要不要。只看第一个 tag 字段：protobuf 规定同一个字段写了几次时
            // 取最后一个，可那样每个条目都得把字段走完，不要的条目就没法读到 tag 就整段跳过；真实数据里每个条目
            // 只有一个 tag
            // The tag (field 1) first, to tell whether the entry is wanted. Only the first tag
            // field counts: protobuf takes the last when a field is written more than once,
            // but then every entry's fields would have to be walked and an unwanted entry could
            // not be skipped whole once its tag is read; real data has one tag per entry
            let requests = match file.next_field(1, entry_end)? {
                Some(len) => {
                    file.read(&mut field, len)?;
                    let tag = std::str::from_utf8(&field)
                        .context("GeoSite tag in .dat file is not UTF-8")?
                        .to_ascii_lowercase();
                    debug!(tag = %tag, "read GeoSite tag");
                    // Match against base tags (supports `@attr` split); with no tag named,
                    // every non-empty tag is wanted
                    match tags {
                        Some(_) => tag_requests.get(tag.as_str()).cloned(),
                        None => (!tag.is_empty()).then(|| vec![(tag, Vec::new())]),
                    }
                }
                None => None,
            };
            let Some(requests) = requests else {
                file.seek_to(entry_end)?;
                continue;
            };

            // 先数一遍要存的名字，builder 一次分配到位（见 `count_names`）
            // Count the names to store first, so each builder is allocated once (see `count_names`)
            file.seek_to(entry_start)?;
            let (full, suffixes) = Self::count_names(&mut file, &mut field, entry_end)?;

            // 再读一遍，每读出一条就交给各个请求的 builder，不先收齐整个 tag（见 `TagBuilder`）
            // Read again, handing each entry to every request's builder as it is read rather
            // than collecting the whole tag first (see `TagBuilder`)
            file.seek_to(entry_start)?;
            let mut builders: Vec<(TagBuilder, usize)> = requests
                .iter()
                .map(|_| (TagBuilder::with_capacity(full, suffixes), 0))
                .collect();

            // 读不出来的一条让整份文件被拒绝，和越出的字段一样；以前跳过它照样往下读
            // A domain that cannot be read gets the whole file rejected, as a field running past
            // does; it used to be skipped and reading went on
            while let Some(len) = file.next_field(2, entry_end)? {
                file.read(&mut field, len)?;
                let Some((entry, attrs)) = Domain::decode(field.as_slice())?.into_entry() else {
                    continue;
                };
                for ((builder, count), (_, wanted)) in builders.iter_mut().zip(&requests) {
                    if has_attrs(&attrs, wanted) {
                        builder.add_entry(entry.clone());
                        *count += 1;
                    }
                }
            }

            // Store each request's tag under its original name
            // 每个请求的 tag 按原来的名字存放
            for ((builder, count), (store_tag, attr_filter)) in builders.into_iter().zip(&requests)
            {
                if count > 0 {
                    info!(tag = %store_tag,
                          domain_count = count,
                          attr_filter = ?attr_filter,
                          "loaded GeoSite tag with domains");
                    parsed.push((store_tag.clone(), builder.finish()));
                } else if tags.is_none() {
                    warn!(tag = %store_tag,
                          "GeoSite tag has no valid domains, skipping");
                } else {
                    warn!(tag = %store_tag,
                          attr_filter = ?attr_filter,
                          "no GeoSite domains matched the attribute filter");
                }
            }
        }

        match tags {
            Some(tags) => info!(
                loaded_count = parsed.len(),
                requested_count = tags.len(),
                "selectively loaded GeoSite data from .dat file"
            ),
            None => info!(
                loaded_count = parsed.len(),
                "loaded GeoSite data from V2Ray .dat file"
            ),
        }

        Ok(parsed)
    }

    /// 一个 GeoSite 条目里（从 `file` 当前位置到 `entry_end`）完整域名和后缀各有几条、共多长，好一次
    /// 分配到位；只读类型和值的长度，属性筛选不计，所以带 `@` 的 tag 只会多留一些容量（见
    /// [`TagBuilder::finish`]）
    /// How many full names and suffixes one GeoSite entry (from `file`'s position to `entry_end`)
    /// holds, and their total length, so the builder is allocated once; only types and value
    /// lengths are read and attribute filters are not applied, so a tag with `@` merely reserves
    /// some extra room (see [`TagBuilder::finish`])
    fn count_names(
        file: &mut DatReader,
        field: &mut Vec<u8>,
        entry_end: usize,
    ) -> anyhow::Result<((usize, usize), (usize, usize))> {
        let (mut full, mut suffixes) = ((0, 0), (0, 0));
        while let Some(len) = file.next_field(2, entry_end)? {
            file.read(field, len)?;
            let domain = Domain::decode(field.as_slice())?;
            match (domain.kind, domain.value.len()) {
                // 和 `Domain::into_entry` 一样：没有值的不算一条，0 和 1（关键词、正则）不存成名字，2 是后缀，
                // 3 和不认识的类型按完整域名
                // As in `Domain::into_entry`: one without a value is no entry, 0 and 1 (keywords,
                // regexes) are not stored as names, 2 is a suffix, and 3 and unknown types are
                // full names
                (_, 0) | (0 | 1, _) => {}
                (2, len) => (suffixes.0, suffixes.1) = (suffixes.0 + 1, suffixes.1 + len),
                (_, len) => (full.0, full.1) = (full.0 + 1, full.1 + len),
            }
        }
        Ok((full, suffixes))
    }

    /// 加载 V2Ray JSON 格式的字符串，保留已有的数据，给出条目数，测试用 / Loads a string in V2Ray's
    /// JSON format, keeping the data already there, giving the number of entries, for tests
    #[cfg(test)]
    pub fn load_from_v2ray_string(&mut self, json_str: &str) -> anyhow::Result<usize> {
        let v2ray_data: V2RayGeoSiteList =
            serde_json::from_str(json_str).with_context(|| "parse V2Ray GeoSite JSON format")?;

        let count = v2ray_data.entries.len();

        // 逐个添加条目，保留现有数据 / Add entries one by one, preserving existing data
        self.database
            .extend(Self::convert_v2ray_to_entries(v2ray_data));

        Ok(count)
    }

    /// V2Ray 格式的每个 tag 建成匹配器 / Each tag of the V2Ray format built into matchers
    ///
    /// 写法与 V2Ray 一致：`domain:` 和不带前缀的值匹配域名本身及其所有子域名，`full:` 只匹配域名本身，
    /// `keyword:` 按关键词、`regexp:` 按正则匹配；不带前缀且含 `*` 的值按通配符转成正则。
    /// 前缀不认识、没有值的条目会跳过并告警，正则无效的也是（见 [`TagBuilder::add_entry`]），不再留下永远匹配不到
    /// （空值则匹配一切）的条目。
    /// Entries are written as in V2Ray: `domain:` and unprefixed values match the domain and every
    /// subdomain, `full:` the domain only, `keyword:` a keyword and `regexp:` a regular expression; an
    /// unprefixed value containing `*` becomes a wildcard regex. An entry with an unknown prefix or
    /// no value is skipped with a warning, and so is an invalid regex (see
    /// [`TagBuilder::add_entry`]), instead of staying as an entry that never matches (or, when
    /// empty, matches everything).
    fn convert_v2ray_to_entries(v2ray_data: V2RayGeoSiteList) -> ParsedGeoSite {
        v2ray_data
            .entries
            .into_iter()
            .map(|v2ray_entry| {
                // 分类名转小写，和 .dat 一样：查找时按小写查 / Tags are lower-cased, as for .dat:
                // lookups use the lower-cased tag
                let tag = v2ray_entry.tag.to_ascii_lowercase();
                let mut skipped = 0usize;
                let mut first_skipped = None;
                let entries = v2ray_entry
                    .domains
                    .into_iter()
                    .filter_map(|domain| {
                        let entry = Self::v2ray_json_entry(&domain);
                        if entry.is_none() {
                            skipped += 1;
                            first_skipped.get_or_insert(domain);
                        }
                        entry
                    })
                    .collect();
                if let Some(example) = first_skipped {
                    warn!(
                        tag = %tag,
                        skipped,
                        example = %example,
                        "skipped GeoSite JSON entries that cannot match: unknown prefix or no value"
                    );
                }

                (tag, TagMatchers::new(entries))
            })
            .collect()
    }

    /// 一条 V2Ray JSON 域名对应的条目；前缀不认识、没有值时为 `None`。正则和 .dat 里的一样只留写法，合成集合时才
    /// 编译（以前这里先单独编译一遍，合成集合时又编译一遍）。通配符在转成正则之前转小写：别的值存进去时转（见
    /// [`TagBuilder::add`]），正则里的转不了
    /// The entry for one V2Ray JSON domain; `None` for an unknown prefix or no value. A regex
    /// keeps only its pattern, as in a .dat, compiled when combined into sets (it used to be
    /// compiled alone here first, and again in the set). A wildcard is lower-cased before it
    /// becomes a regex: the other values are lowered as they are stored (see
    /// [`TagBuilder::add`]), which cannot reach into a regex
    fn v2ray_json_entry(entry: &str) -> Option<DatEntry> {
        let (prefix, value) = match entry.split_once(':') {
            Some((prefix, value)) => (Some(prefix), value),
            None => (None, entry),
        };
        if value.is_empty() {
            return None;
        }
        let value = value.to_string();
        Some(match prefix {
            Some("domain") => DatEntry::Matcher(DomainMatcher::Suffix(value)),
            Some("full") => DatEntry::Matcher(DomainMatcher::Full(value)),
            Some("keyword") => DatEntry::Matcher(DomainMatcher::Keyword(value)),
            Some("regexp") => DatEntry::Regex(value),
            Some(_) => return None,
            None if value.contains('*') => {
                let pattern = value
                    .to_ascii_lowercase()
                    .replace('.', r"\.")
                    .replace('*', ".*");
                DatEntry::Regex(format!("^{pattern}$"))
            }
            None => DatEntry::Matcher(DomainMatcher::Suffix(value)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matcher::limited_regex;

    /// 由匹配器建成的索引 / The index built from matchers
    fn indexed(matchers: Vec<DomainMatcher>) -> TagMatchers {
        TagMatchers::new(matchers.into_iter().map(DatEntry::Matcher).collect())
    }

    fn encode_varint(mut value: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        loop {
            let byte = (value & 0x7F) as u8;
            value >>= 7;
            if value == 0 {
                bytes.push(byte);
                break;
            }
            bytes.push(byte | 0x80);
        }
        bytes
    }

    fn encode_varint_field(field_number: u8, value: usize) -> Vec<u8> {
        // wire_type 0 (varint): (field_number << 3) | wire_type
        let mut result = vec![field_number << 3];
        result.extend(encode_varint(value));
        result
    }

    fn encode_ld(field_number: u8, data: &[u8]) -> Vec<u8> {
        let mut result = vec![(field_number << 3) | 2];
        result.extend(encode_varint(data.len()));
        result.extend_from_slice(data);
        result
    }

    fn encode_str(field_number: u8, s: &str) -> Vec<u8> {
        encode_ld(field_number, s.as_bytes())
    }

    /// Build a Domain protobuf message
    fn build_domain(domain_type: usize, value: &str, attrs: &[&str]) -> Vec<u8> {
        let mut msg = encode_varint_field(1, domain_type);
        msg.extend(encode_str(2, value));
        for attr in attrs {
            let attr_msg = encode_str(1, attr); // Attribute.key
            msg.extend(encode_ld(3, &attr_msg)); // repeated attribute
        }
        msg
    }

    /// Build a GeoSite entry
    fn build_geosite(tag: &str, domains: &[Vec<u8>]) -> Vec<u8> {
        let mut msg = encode_str(1, tag);
        for d in domains {
            msg.extend(encode_ld(2, d));
        }
        msg
    }

    /// Build a GeoSiteList (.dat file content)
    fn build_dat(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut result = Vec::new();
        for entry in entries {
            result.extend(encode_ld(1, entry));
        }
        result
    }

    fn write_dat(dir: &tempfile::TempDir, entries: &[Vec<u8>]) -> PathBuf {
        let path = dir.path().join("geosite.dat");
        std::fs::write(&path, build_dat(entries)).unwrap();
        path
    }

    /// proto3 不写取默认值的字段：v2ray 数据里的关键词条目没有类型字段，只有值，照样是关键词；字段不论先后。
    /// 按需加载和全部加载都是这样。
    /// proto3 leaves out fields holding their default: a keyword entry in v2ray data has no type
    /// field, only its value, and is a keyword all the same; fields come in any order. Both
    /// selective and full loading read it so.
    /// 没有值的 Domain 条目（proto3 不写空字符串，值就不在）不算一条域名：它不匹配任何名字，只有这种
    /// 条目的 tag 也不存下来。按需加载和全部加载都是这样
    /// A Domain entry without a value (proto3 leaves an empty string out, so the value is
    /// missing) is no entry: it matches no name, and a tag of only such entries is not
    /// stored either. Both selective and full loading do so
    #[test]
    fn a_domain_without_a_value_is_no_entry() {
        let dir = tempfile::tempdir().unwrap();
        // 一条只写了类型 full，一条什么都没写（类型 0 是关键词）
        // One with only its type (full) written, one with nothing written (type 0 is a keyword)
        let valueless = [encode_varint_field(1, 3), Vec::new()];
        let path = write_dat(
            &dir,
            &[
                build_geosite(
                    "V",
                    &[&valueless[..], &[build_domain(3, "a.example", &[])]].concat(),
                ),
                build_geosite("E", &valueless),
            ],
        );

        let parsed =
            GeoSiteManager::parse_dat_file_selective(&path, &["v".to_string(), "e".to_string()])
                .unwrap();
        assert_eq!(
            parsed
                .iter()
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>(),
            ["v"]
        );
        let (_, tag) = &parsed[0];
        assert!(tag.matches("a.example"));
        assert!(!tag.matches("b.example"));

        let mut manager = GeoSiteManager::new();
        manager.load_from_v2ray_file(&path).unwrap();
        assert!(manager.matches("v", "a.example"));
        assert!(!manager.matches("v", "b.example"));
        assert!(!manager.has_tag("e"));
    }

    #[test]
    fn a_keyword_without_a_type_field_is_still_a_keyword() {
        let dir = tempfile::tempdir().unwrap();
        let mut value_first = encode_str(2, "only.test");
        value_first.extend(encode_varint_field(1, 3));
        let path = write_dat(
            &dir,
            &[build_geosite("G", &[encode_str(2, "google"), value_first])],
        );

        let parsed = GeoSiteManager::parse_dat_file_selective(&path, &["g".to_string()]).unwrap();
        let (_, tag) = &parsed[0];
        assert!(tag.matches("www.google.com"));
        assert!(tag.matches("only.test"));
        assert!(!tag.matches("www.only.test"));

        let mut manager = GeoSiteManager::new();
        manager.load_from_v2ray_file(&path).unwrap();
        assert!(manager.matches("g", "www.google.com"));
        assert!(manager.matches("g", "only.test"));
    }

    /// 数据文件里的正则读完一个 tag 才合成编译；写错的一条跳过，什么名字都不匹配，也不连累同一个 tag 的其他
    /// 正则。按需加载和全部加载都是这样。以前写错的一条换成只匹配空名字的正则，而根域名的名字正是空的：带着
    /// 一条坏正则的 tag 就把对根域名的查询也算了进去。
    /// A data file's regexes compile once the tag is read; one written wrong is skipped, matching
    /// no name at all, and spoils none of the tag's others. Both selective and full loading do
    /// so. One written wrong used to become a regex matching only the empty name, and the root
    /// name is the empty one: a tag with one broken regex took in queries for the root.
    #[test]
    fn a_broken_regex_in_a_data_file_spoils_none_of_the_others() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_dat(
            &dir,
            &[build_geosite(
                "R",
                &[
                    build_domain(1, "(unclosed", &[]),
                    build_domain(1, r"^cdn\d\.example\.com$", &[]),
                    build_domain(1, r"^a\.", &[]),
                ],
            )],
        );

        let parsed = GeoSiteManager::parse_dat_file_selective(&path, &["r".to_string()]).unwrap();
        let (_, tag) = &parsed[0];
        assert_eq!(tag.regexes.0.len(), 1);
        assert!(tag.matches("cdn7.example.com"));
        assert!(tag.matches("a.test"));
        assert!(!tag.matches(""));
        assert!(!tag.matches("cdnx.example.com"));

        let mut manager = GeoSiteManager::new();
        manager.load_from_v2ray_file(&path).unwrap();
        assert!(manager.matches("r", "cdn7.example.com"));
        assert!(!manager.matches("r", "b.test"));
        assert!(!manager.matches("r", ""));
    }

    #[test]
    fn dat_reload_drops_tags_removed_from_the_file() {
        // The .dat loaders used to insert into the live table without clearing
        // it, so a tag deleted from the file kept matching after a reload.
        // .dat 加载器曾直接往现有表里插入而不清空：文件里删掉的 tag 重载后仍然命中。
        let dir = tempfile::tempdir().unwrap();
        let path = write_dat(
            &dir,
            &[
                build_geosite("CN", &[build_domain(2, "baidu.com", &[])]),
                build_geosite("ADS", &[build_domain(2, "doubleclick.net", &[])]),
            ],
        );
        let mut manager = GeoSiteManager::new();
        manager.load_from_v2ray_file(&path).unwrap();
        assert!(manager.matches("ads", "www.doubleclick.net"));

        write_dat(
            &dir,
            &[build_geosite("CN", &[build_domain(2, "qq.com", &[])])],
        );
        manager.load_from_v2ray_file(&path).unwrap();

        assert!(
            !manager.matches("ads", "www.doubleclick.net"),
            "a tag removed from the file must stop matching"
        );
        assert!(!manager.matches("cn", "www.baidu.com"));
        assert!(manager.matches("cn", "www.qq.com"));
    }

    #[test]
    fn corrupt_dat_reload_keeps_previous_data_intact() {
        // A file that fails to parse must leave the previous data untouched:
        // no entries from the bad file, nothing from the old data lost.
        // 解析失败的文件不能动现有数据：坏文件里的条目一个都不进来，旧数据一个都不丢。
        let dir = tempfile::tempdir().unwrap();
        let path = write_dat(
            &dir,
            &[build_geosite("OLD", &[build_domain(2, "old.example", &[])])],
        );
        let mut manager = GeoSiteManager::new();
        manager.load_from_v2ray_file(&path).unwrap();

        // One good entry followed by an unterminated varint.
        let mut corrupt =
            build_dat(&[build_geosite("NEW", &[build_domain(2, "new.example", &[])])]);
        corrupt.extend_from_slice(&[0x0A, 0xFF]);
        std::fs::write(&path, corrupt).unwrap();

        manager
            .load_from_v2ray_file(&path)
            .expect_err("corrupt file must be rejected");
        assert!(
            manager.matches("old", "www.old.example"),
            "previous data must survive a failed reload"
        );
        assert!(
            !manager.matches("new", "www.new.example"),
            "nothing from the failed file may leak into the live table"
        );
    }

    /// 配置里写相对路径、监视器事件给绝对路径，两者必须指向同一条记录，
    /// 否则删除动作永远打不中启动时那次加载。
    /// A relative path from the configuration and the absolute path a watcher
    /// event carries must refer to the same entry, or the removal never matches
    /// the load that happened at startup.
    #[test]
    fn dat_reload_matches_the_same_file_through_a_different_path_spelling() {
        let dir = tempfile::tempdir().unwrap();
        let absolute = write_dat(
            &dir,
            &[
                build_geosite("CN", &[build_domain(2, "baidu.com", &[])]),
                build_geosite("ADS", &[build_domain(2, "doubleclick.net", &[])]),
            ],
        );
        // 同一个文件的另一种写法：绕一层子目录再退回来。Rust 的 Path 比较会规范化
        // 掉 "."，但不会规范化 ".."，正好模拟配置里的相对路径与监视器给出的绝对
        // 路径指向同一个文件却不相等的情况。
        // Another spelling of the same file, via a subdirectory and back. Rust's
        // Path comparison normalises "." away but not "..", which reproduces a
        // relative path from the configuration and the absolute path a watcher
        // reports pointing at one file without comparing equal.
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        let indirect = dir.path().join("sub").join("..").join("geosite.dat");

        let mut manager = GeoSiteManager::new();
        manager.load_from_v2ray_file(&indirect).unwrap();
        assert!(manager.matches("ads", "www.doubleclick.net"));

        write_dat(
            &dir,
            &[build_geosite("CN", &[build_domain(2, "qq.com", &[])])],
        );
        manager.load_from_v2ray_file(&absolute).unwrap();

        assert!(
            !manager.matches("ads", "www.doubleclick.net"),
            "the same file under another spelling must count as the same source"
        );
        assert!(manager.matches("cn", "www.qq.com"));
    }

    /// 同时配置 .dat 和 .json 时，重载 JSON 不能清掉 .dat 贡献的 tag。此前
    /// JSON 走的是整库重载，会把数据表和来源记录一起清空——tag 消失之外，来源
    /// 记录也没了，下一次 .dat 重载连"删掉已移除 tag"的能力都失效。
    /// With a .dat and a .json configured together, reloading the JSON must not
    /// wipe the tags the .dat contributed. The JSON path used to reload the
    /// whole database, clearing both the table and the source records, so the
    /// tag vanished and the next .dat reload also lost its ability to drop tags
    /// the file had removed.
    #[test]
    fn reloading_a_json_file_keeps_the_tags_a_dat_file_provides() {
        let dir = tempfile::tempdir().unwrap();
        let dat = dir.path().join("a.dat");
        let json = dir.path().join("b.json");
        std::fs::write(
            &dat,
            build_dat(&[build_geosite("CN", &[build_domain(2, "baidu.com", &[])])]),
        )
        .unwrap();
        let json_body = |domain: &str| {
            format!(r#"{{"entries":[{{"tag":"ads","domains":["domain:{domain}"]}}]}}"#)
        };
        std::fs::write(&json, json_body("doubleclick.net")).unwrap();

        let mut manager = GeoSiteManager::new();
        manager.load_from_v2ray_file(&dat).unwrap();
        manager.load_from_v2ray_file(&json).unwrap();
        assert!(manager.matches("cn", "www.baidu.com"));
        assert!(manager.matches("ads", "doubleclick.net"));

        // 只有 JSON 变了 / only the JSON changed
        std::fs::write(&json, json_body("ads.example")).unwrap();
        manager.load_from_v2ray_file(&json).unwrap();

        assert!(
            manager.matches("cn", "www.baidu.com"),
            "a JSON reload must not take the .dat file's tags with it"
        );
        assert!(manager.matches("ads", "ads.example"));
        assert!(
            !manager.matches("ads", "doubleclick.net"),
            "the JSON file's own removed domain must be gone"
        );

        // 来源记录还在，所以 .dat 仍然能删掉自己移除的 tag
        // The source record survives, so the .dat can still drop a tag it removed
        std::fs::write(&dat, build_dat(&[])).unwrap();
        manager.load_from_v2ray_file(&dat).unwrap();
        assert!(
            !manager.has_tag("cn"),
            "the .dat source record must survive a JSON reload"
        );
    }

    /// 两个文件都声明同一个 tag 时，重载其中一个不能把另一个的数据带走。
    /// When two files declare the same tag, reloading one must not take the
    /// other file's data with it.
    #[test]
    fn reloading_one_file_keeps_a_tag_another_file_still_provides() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.dat");
        let b = dir.path().join("b.dat");
        std::fs::write(
            &a,
            build_dat(&[
                build_geosite("ADS", &[build_domain(2, "doubleclick.net", &[])]),
                build_geosite("ONLY-A", &[build_domain(2, "only-a.example", &[])]),
            ]),
        )
        .unwrap();
        std::fs::write(
            &b,
            build_dat(&[build_geosite("ADS", &[build_domain(2, "ads.example", &[])])]),
        )
        .unwrap();

        let mut manager = GeoSiteManager::new();
        manager.load_from_v2ray_file(&a).unwrap();
        manager.load_from_v2ray_file(&b).unwrap();

        // a.dat 去掉 ads，b.dat 原封不动 / ads leaves a.dat, b.dat is untouched
        std::fs::write(
            &a,
            build_dat(&[build_geosite(
                "ONLY-A",
                &[build_domain(2, "only-a.example", &[])],
            )]),
        )
        .unwrap();
        manager.load_from_v2ray_file(&a).unwrap();

        assert!(
            manager.has_tag("ads"),
            "a tag another file still provides must survive"
        );
        assert!(manager.matches("only-a", "www.only-a.example"));
    }

    /// 写一个只有 tag `ADS`、里面只有域名 `domain` 的数据文件
    /// Writes a data file with the one tag `ADS` holding the one name `domain`
    fn write_ads(path: &Path, domain: &str) {
        std::fs::write(
            path,
            build_dat(&[build_geosite("ADS", &[build_domain(2, domain, &[])])]),
        )
        .unwrap();
    }

    /// 两个文件声明同一个 tag 时，排在后面的文件说了算，和各自什么时候读进来无关：前面的文件变了、重新读进来
    /// 以后，这个 tag 用的还是后面那个文件的数据。以前是谁后读进来谁说了算，前面的文件一变，这个 tag 就换成
    /// 了它的数据，直到后面的文件也变一次
    /// Of two files declaring one tag the later file decides, whenever each was read: once the
    /// earlier file changes and is read again, the tag still has the later file's data. Whichever
    /// was read last used to decide, so a change to the earlier file gave the tag its data until
    /// the later file changed too
    #[test]
    fn the_later_file_keeps_a_shared_tag_when_an_earlier_one_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("a.dat"), dir.path().join("b.dat"));
        write_ads(&a, "from-a.example");
        write_ads(&b, "from-b.example");
        let mut manager = GeoSiteManager::new();
        manager.load_from_v2ray_file(&a).unwrap();
        manager.load_from_v2ray_file(&b).unwrap();
        assert!(manager.matches("ads", "www.from-b.example"));
        assert!(!manager.matches("ads", "www.from-a.example"));

        write_ads(&a, "again-from-a.example");
        manager.load_from_v2ray_file(&a).unwrap();
        assert!(manager.matches("ads", "www.from-b.example"));
        assert!(!manager.matches("ads", "www.again-from-a.example"));

        // 后面的文件不再声明它，才轮到前面那个现在的数据 / Only once the later file drops it does
        // the earlier one's present data have its turn
        std::fs::write(&b, build_dat(&[])).unwrap();
        manager.load_from_v2ray_file(&b).unwrap();
        assert!(manager.matches("ads", "www.again-from-a.example"));
        assert!(!manager.matches("ads", "www.from-b.example"));
    }

    /// 排在最后的文件不再声明这个 tag 时，换成剩下的文件里排得最后的那一个，和全部重新读一遍的结果一样。以前
    /// 换成路径最小的那一个
    /// When the last file stops declaring a tag, the latest of the files left provides it, as a
    /// full load would have it. The one with the smallest path used to
    #[test]
    fn a_dropped_shared_tag_falls_back_to_the_latest_file_still_providing_it() {
        let dir = tempfile::tempdir().unwrap();
        let [first, second, last] = ["a.dat", "z.dat", "c.dat"].map(|name| dir.path().join(name));
        write_ads(&first, "from-first.example");
        write_ads(&second, "from-second.example");
        write_ads(&last, "from-last.example");
        let mut manager = GeoSiteManager::new();
        for path in [&first, &second, &last] {
            manager.load_from_v2ray_file(path).unwrap();
        }
        assert!(manager.matches("ads", "www.from-last.example"));

        std::fs::write(&last, build_dat(&[])).unwrap();
        manager.load_from_v2ray_file(&last).unwrap();
        assert!(manager.matches("ads", "www.from-second.example"));
        assert!(!manager.matches("ads", "www.from-first.example"));
        assert!(!manager.matches("ads", "www.from-last.example"));
    }

    /// 后加载的文件删掉共享 tag 之后，索引里必须换成仍在声明它的那个文件的数据，
    /// 而不是留着被删掉的那份。
    /// When the file that loaded last drops a shared tag, the index must fall
    /// back to the data of the file still declaring it instead of keeping the
    /// entries that were just deleted.
    #[test]
    fn dropping_a_shared_tag_falls_back_to_the_file_still_providing_it() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.dat");
        let b = dir.path().join("b.dat");
        std::fs::write(
            &a,
            build_dat(&[build_geosite(
                "ADS",
                &[build_domain(2, "doubleclick.net", &[])],
            )]),
        )
        .unwrap();
        std::fs::write(
            &b,
            build_dat(&[build_geosite("ADS", &[build_domain(2, "ads.example", &[])])]),
        )
        .unwrap();

        let mut manager = GeoSiteManager::new();
        manager.load_from_v2ray_file(&a).unwrap();
        // b.dat 后加载，此刻 ads 命中的是 b.dat 的数据
        // b.dat loads last, so ads matches b.dat's data at this point
        manager.load_from_v2ray_file(&b).unwrap();
        assert!(manager.matches("ads", "www.ads.example"));

        // b.dat 去掉 ads，只剩 a.dat 在提供 / ads leaves b.dat, only a.dat provides it
        std::fs::write(&b, build_dat(&[])).unwrap();
        manager.load_from_v2ray_file(&b).unwrap();

        assert!(
            manager.matches("ads", "www.doubleclick.net"),
            "the remaining file's data must be the one serving the tag"
        );
        assert!(
            !manager.matches("ads", "www.ads.example"),
            "entries from the file that dropped the tag must not survive"
        );
    }

    /// 顶替共享 tag 时必须按扩展名选解析器。JSON 登记进来源表之后，写死的
    /// .dat 解析器会把它读成"截断的 .dat"，落进"保留现有条目"的告警分支——
    /// 被删掉的那份数据继续命中，比彻底丢掉这个 tag 更糟。
    /// Taking a shared tag over has to pick the parser by extension. Once JSON
    /// files are registered as sources, a hardcoded .dat parser reads one as a
    /// truncated .dat and lands in the "keep the current entries" warning, so
    /// the data that was just deleted goes on matching, which is worse than
    /// losing the tag outright.
    #[test]
    fn a_json_file_can_take_a_shared_tag_over_from_a_dat_file() {
        let dir = tempfile::tempdir().unwrap();
        let json = dir.path().join("a.json");
        let dat = dir.path().join("b.dat");
        std::fs::write(
            &json,
            r#"{"entries":[{"tag":"cn","domains":["domain:json.example"]}]}"#,
        )
        .unwrap();
        std::fs::write(
            &dat,
            build_dat(&[build_geosite("CN", &[build_domain(2, "baidu.com", &[])])]),
        )
        .unwrap();

        let mut manager = GeoSiteManager::new();
        manager.load_from_v2ray_file(&json).unwrap();
        manager.load_from_v2ray_file(&dat).unwrap();
        assert!(manager.matches("cn", "www.baidu.com"));

        // .dat 交出 cn，只剩 JSON 在提供 / the .dat drops cn, only the JSON provides it
        std::fs::write(&dat, build_dat(&[])).unwrap();
        manager.load_from_v2ray_file(&dat).unwrap();

        assert!(
            manager.matches("cn", "json.example"),
            "the JSON file's data must take the tag over"
        );
        assert!(
            !manager.matches("cn", "www.baidu.com"),
            "the entries the .dat just dropped must not survive"
        );
    }

    /// 两个 JSON 共享一个 tag 是更常见的布局，同样不能用 .dat 解析器去顶替。
    /// Two JSON files sharing a tag is the more common layout and must not go
    /// through the .dat parser either.
    #[test]
    fn a_json_file_can_take_a_shared_tag_over_from_another_json_file() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("a.json");
        let second = dir.path().join("b.json");
        std::fs::write(
            &first,
            r#"{"entries":[{"tag":"ads","domains":["domain:first.example"]}]}"#,
        )
        .unwrap();
        std::fs::write(
            &second,
            r#"{"entries":[{"tag":"ads","domains":["domain:second.example"]}]}"#,
        )
        .unwrap();

        let mut manager = GeoSiteManager::new();
        manager.load_from_v2ray_file(&first).unwrap();
        manager.load_from_v2ray_file(&second).unwrap();
        assert!(manager.matches("ads", "second.example"));

        std::fs::write(&second, r#"{"entries":[]}"#).unwrap();
        manager.load_from_v2ray_file(&second).unwrap();

        assert!(
            manager.matches("ads", "first.example"),
            "the remaining JSON file's data must take the tag over"
        );
        assert!(
            !manager.matches("ads", "second.example"),
            "the entries the other JSON just dropped must not survive"
        );
    }

    /// 一次删掉多个共享 tag 时，顶上来的数据必须逐个正确——分组重读不能把
    /// 某个 tag 漏掉或串到别的 tag 上。
    /// When several shared tags are dropped at once, every one of them must come
    /// back with the right data: grouping the re-read must not skip a tag or mix
    /// one tag's entries into another.
    #[test]
    fn dropping_several_shared_tags_reloads_each_of_them() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.dat");
        let b = dir.path().join("b.dat");
        std::fs::write(
            &a,
            build_dat(&[
                build_geosite("ADS", &[build_domain(2, "doubleclick.net", &[])]),
                build_geosite("TRACK", &[build_domain(2, "scorecard.net", &[])]),
            ]),
        )
        .unwrap();
        std::fs::write(
            &b,
            build_dat(&[
                build_geosite("ADS", &[build_domain(2, "ads.example", &[])]),
                build_geosite("TRACK", &[build_domain(2, "track.example", &[])]),
                build_geosite("ONLY-B", &[build_domain(2, "only-b.example", &[])]),
            ]),
        )
        .unwrap();

        let mut manager = GeoSiteManager::new();
        manager.load_from_v2ray_file(&a).unwrap();
        manager.load_from_v2ray_file(&b).unwrap();
        assert!(manager.matches("ads", "www.ads.example"));
        assert!(manager.matches("track", "www.track.example"));

        // b.dat 一次去掉两个共享 tag / both shared tags leave b.dat at once
        std::fs::write(
            &b,
            build_dat(&[build_geosite(
                "ONLY-B",
                &[build_domain(2, "only-b.example", &[])],
            )]),
        )
        .unwrap();
        manager.load_from_v2ray_file(&b).unwrap();

        assert!(
            manager.matches("ads", "www.doubleclick.net"),
            "ads must come back from a.dat"
        );
        assert!(
            manager.matches("track", "www.scorecard.net"),
            "track must come back from a.dat too"
        );
        assert!(!manager.matches("ads", "www.ads.example"));
        assert!(!manager.matches("track", "www.track.example"));
        assert!(manager.matches("only-b", "www.only-b.example"));
    }

    /// 整个 GeoSiteList，测试里拿 prost 一次解出整份文件作对照 / A whole GeoSiteList: tests decode
    /// a whole file at once with prost for reference
    #[derive(Clone, PartialEq, prost::Message)]
    struct GeoSiteList {
        #[prost(message, repeated, tag = "1")]
        entry: Vec<GeoSite>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    struct GeoSite {
        #[prost(string, tag = "1")]
        country_code: String,
        #[prost(message, repeated, tag = "2")]
        domain: Vec<Domain>,
    }

    /// 不点名 tag 时（`parse_file` 拿到空的 tags），按条目读出的标签和条目与 prost 一次解出整份文件的结果一致：
    /// 标签的名字和先后、每个标签里的条目、匹配的结果。数据里有重复的 tag、空 tag、只有空值的 tag、
    /// 域名写在 tag 前面的条目，还有一个不是 GeoSite 条目的外层字段
    /// With no tag named (`parse_file` given empty tags), the tags and entries read entry by
    /// entry agree with what prost decodes from the whole file at once: the tag names and
    /// their order, each tag's entries, and what they match. The data has a repeated tag, an
    /// empty tag, a tag of only valueless entries, an entry with its domains before its
    /// tag, and an outer field that is no GeoSite entry
    #[test]
    fn every_tag_parsing_reads_what_protobuf_reads() {
        let dir = tempfile::tempdir().unwrap();
        let mut domains_first = encode_ld(2, &build_domain(3, "first.example", &[]));
        domains_first.extend(encode_str(1, "Late"));
        let path = write_dat(
            &dir,
            &[
                build_geosite(
                    "CN",
                    &[
                        build_domain(2, "baidu.com", &["cn"]),
                        build_domain(3, "qq.com", &[]),
                        build_domain(0, "taobao", &[]),
                        build_domain(1, r"^jd\.", &[]),
                    ],
                ),
                build_geosite("Ads", &[build_domain(2, "doubleclick.net", &["ads"])]),
                build_geosite("", &[build_domain(3, "nameless.example", &[])]),
                build_geosite("NONE", &[encode_varint_field(1, 3)]),
                build_geosite("CN", &[build_domain(2, "sina.com", &[])]),
                domains_first,
            ],
        );
        let mut data = std::fs::read(&path).unwrap();
        data.extend(encode_ld(2, b"junk"));
        std::fs::write(&path, data).unwrap();

        let every = GeoSiteManager::parse_file(&path, &[]).unwrap();
        // 有 tag、也有带值的域名的条目，和按条目读时一样 / The entries with a tag and a domain
        // holding a value, as reading entry by entry keeps
        let full: ParsedGeoSite = GeoSiteList::decode(std::fs::read(&path).unwrap().as_slice())
            .unwrap()
            .entry
            .into_iter()
            .filter_map(|site| {
                let mut builder = TagBuilder::default();
                let mut count = 0;
                for (entry, _) in site.domain.into_iter().filter_map(Domain::into_entry) {
                    builder.add_entry(entry);
                    count += 1;
                }
                (!site.country_code.is_empty() && count > 0)
                    .then(|| (site.country_code.to_ascii_lowercase(), builder.finish()))
            })
            .collect();
        let entries = |parsed: &ParsedGeoSite| {
            parsed
                .iter()
                .map(|(tag, matchers)| {
                    let mut entries: Vec<String> = matchers
                        .to_matchers()
                        .iter()
                        .map(|matcher| format!("{matcher:?}"))
                        .collect();
                    entries.sort();
                    (tag.clone(), entries)
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(entries(&every), entries(&full));
        assert_eq!(
            every
                .iter()
                .map(|(tag, _)| tag.as_str())
                .collect::<Vec<_>>(),
            ["cn", "ads", "cn", "late"]
        );
        for name in [
            "baidu.com",
            "www.baidu.com",
            "qq.com",
            "www.qq.com",
            "taobao.com",
            "jd.com",
            "sina.com",
            "doubleclick.net",
            "first.example",
            "nameless.example",
            "example.com",
        ] {
            for ((tag, a), (_, b)) in every.iter().zip(&full) {
                assert_eq!(a.matches(name), b.matches(name), "{tag} {name}");
            }
        }
    }

    /// 字段头和长度都按变长整数读，字段号从 16 起字段头就有两个字节。不认识的字段按线上类型跳过（varint、8 字节、
    /// 4 字节、带长度），在文件顶层、条目里和 Domain、Attribute 消息里都一样，之后的字段照常读出。以前字段头只读
    /// 一个字节，遇到字段号大的字段就错了位；文件顶层和条目里的字段一律当成带长度的读，varint 的值被当成了长度
    /// Keys and lengths are read as varints, and from field 16 on a key takes two bytes.
    /// Unknown fields are skipped by wire type (varint, 8 bytes, 4 bytes, length-delimited) at
    /// the top of the file, inside an entry and inside Domain and Attribute messages alike,
    /// and the fields after them read as usual. A key used to be read as one byte, so a field
    /// with a large number threw everything after it out of place; at the top of the file and
    /// inside an entry every field was read as length-delimited, a varint's value taken for a
    /// length
    #[test]
    fn unknown_fields_are_skipped_by_their_wire_type() {
        // 每种线上类型一个不认识的字段，两个用两字节的字段头 / One unknown field of every wire
        // type, two of them with two-byte keys
        let mut unknown = encode_varint_field(4, 150);
        unknown.extend(encode_varint((20 << 3) | 1));
        unknown.extend([1, 2, 3, 4, 5, 6, 7, 8]);
        unknown.extend([(6 << 3) | 5, 1, 2, 3, 4]);
        unknown.extend(encode_varint((300 << 3) | 2));
        unknown.extend(encode_varint(7));
        unknown.extend(b"skip me");

        let mut attribute = unknown.clone();
        attribute.extend(encode_str(1, "CN"));
        let mut domain = unknown.clone();
        domain.extend(build_domain(3, "a.example", &[]));
        domain.extend(encode_ld(3, &attribute));
        let mut entry = unknown.clone();
        entry.extend(build_geosite(
            "Test",
            &[domain, build_domain(2, "b.example", &[])],
        ));
        entry.extend(&unknown);
        let mut data = unknown.clone();
        data.extend(encode_ld(1, &entry));
        data.extend(&unknown);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("geosite.dat");
        std::fs::write(&path, data).unwrap();

        let tags = ["test".to_string(), "test@cn".to_string()];
        let selective = GeoSiteManager::parse_dat_file_selective(&path, &tags).unwrap();
        let every = GeoSiteManager::parse_file(&path, &[]).unwrap();
        let matching = |parsed: &ParsedGeoSite, name: &str| {
            parsed
                .iter()
                .filter(|(_, matchers)| matchers.matches(name))
                .map(|(tag, _)| tag.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(matching(&selective, "a.example"), ["test", "test@cn"]);
        assert_eq!(matching(&selective, "www.b.example"), ["test"]);
        assert_eq!(matching(&every, "a.example"), ["test"]);
        assert_eq!(matching(&every, "www.b.example"), ["test"]);

        // 线上类型 3（已废弃的 group）不认识，整份文件拒绝 / Wire type 3 (the deprecated group)
        // is not known, and the whole file is refused
        assert_refused(
            build_dat(&[[vec![(4 << 3) | 3], encode_str(1, "CN")].concat()]),
            "group",
        );
    }

    /// 在另一个线程里跑 `parse`，5 秒内要有结果：坏的长度既不能让解析 panic，也不能让它原地打转
    /// Runs `parse` on another thread and wants its result within 5 s: a bad length may
    /// neither make parsing panic nor leave it going round in circles
    fn within_five_seconds<T: Send + 'static>(parse: impl FnOnce() -> T + Send + 'static) -> T {
        let (done, result) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = done.send(parse());
        });
        result
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("parsing must neither panic nor hang")
    }

    /// 按需和全部两种解析都拒绝 `data`，而且都不 panic、不原地打转 / Both selective and every-tag
    /// parsing refuse `data`, neither panicking nor going round in circles
    fn assert_refused(data: Vec<u8>, what: &str) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("geosite.dat");
        std::fs::write(&path, data).unwrap();
        let tags = vec!["cn".to_string(), "ads".to_string()];
        for every in [false, true] {
            let (path, tags) = (path.clone(), tags.clone());
            let parsed = within_five_seconds(move || {
                if every {
                    GeoSiteManager::parse_file(&path, &[]).map(|_| ())
                } else {
                    GeoSiteManager::parse_dat_file_selective(&path, &tags).map(|_| ())
                }
            });
            assert!(parsed.is_err(), "{what}, every tag {every}");
        }
    }

    /// 文件里读出的长度大到「位置 + 长度」溢出时（u64::MAX，或者刚好回绕到 0），不论在文件顶层、条目里，还是在
    /// Domain、Attribute 消息里，整份文件都被拒绝，不 panic、不原地打转。只有损坏或特意构造的数据文件会碰到
    /// A length read from the file so large that position plus length overflows (u64::MAX,
    /// or one that wraps to exactly 0) gets the whole file refused, whether at the top of the
    /// file, inside an entry, or inside a Domain or Attribute message, without panicking or
    /// going round in circles. Only a broken or deliberately crafted data file gets here
    #[test]
    fn a_length_that_overflows_the_position_is_refused() {
        let good = build_geosite("CN", &[build_domain(3, "good.example", &[])]);
        // 长度 varint 之后的位置是 11（1 字节字段头加 10 字节 varint），所以 2^64 - 11 刚好回绕到 0
        // The position after the length varint is 11 (a 1-byte key and a 10-byte varint),
        // so 2^64 - 11 wraps to exactly 0
        for huge in [usize::MAX, usize::MAX - 10] {
            let huge_field = |key: u8| [vec![key], encode_varint(huge)].concat();
            assert_refused(huge_field(0x0A), "outer");
            assert_refused(
                [encode_ld(1, &good), huge_field(0x0A)].concat(),
                "outer after a good entry",
            );
            // 条目里的字段，放在 tag 前面和一条好域名后面 / A field inside an entry, before the
            // tag and after a good domain
            assert_refused(
                build_dat(&[[huge_field(0x12), encode_str(1, "CN")].concat()]),
                "inner before the tag",
            );
            assert_refused(
                build_dat(&[[good.clone(), huge_field(0x12)].concat()]),
                "inner after a good domain",
            );
            // Domain 消息里的值、属性和未知字段，Attribute 消息里的 key 和未知字段 / A Domain's
            // value, attribute and unknown field, an Attribute's key and unknown field
            for key in [(2 << 3) | 2, (3 << 3) | 2, (7 << 3) | 2] {
                assert_refused(
                    build_dat(&[build_geosite("CN", &[huge_field(key)])]),
                    &format!("domain field {key:#x}, {huge}"),
                );
            }
            for key in [(1 << 3) | 2, (7 << 3) | 2] {
                let domain = [
                    encode_str(2, "good.example"),
                    encode_ld(3, &huge_field(key)),
                ]
                .concat();
                assert_refused(
                    build_dat(&[build_geosite("CN", &[domain])]),
                    &format!("attribute field {key:#x}, {huge}"),
                );
            }
        }
    }

    /// 长度越出所在消息的字段让整份文件被拒绝，和越出文件的条目一样：条目里放在 tag 前面或一条好域名后面的
    /// 字段、Domain 消息里的值、Attribute 消息里的 key 都是。以前越出条目的字段让条目到此为止（放在 tag 前面时
    /// 整个条目不见了，放在后面时余下的域名不见了），读不出的 Domain 跳过，读不出的 Attribute 不算，文件照样
    /// 当成完好的读进来，规则悄悄少了一部分名单
    /// A field whose length runs past the message holding it gets the whole file refused, as
    /// an entry running past the file does: a field in an entry before its tag or after a
    /// good domain, a Domain's value and an Attribute's key alike. A field running past its
    /// entry used to end the entry there (before the tag the whole entry vanished, after a
    /// domain the domains left did), a Domain that could not be read was skipped and an
    /// Attribute that could not be read did not count, and the file was taken as whole, the
    /// rules quietly missing part of their list
    #[test]
    fn a_length_past_its_message_refuses_the_file() {
        let good = build_domain(3, "good.example", &[]);
        // 说要 9 个字节、后面只有 3 个的字段 / A field saying 9 bytes with only 3 after it
        let short = |key: u8| [vec![key, 9], b"abc".to_vec()].concat();
        let bad_attribute = [
            encode_str(2, "a.example"),
            encode_ld(3, &short((1 << 3) | 2)),
        ]
        .concat();
        for (what, entry) in [
            (
                "field after a good domain",
                [encode_str(1, "CN"), encode_ld(2, &good), short(0x12)].concat(),
            ),
            (
                "field before the tag",
                [short(0x12), encode_str(1, "CN")].concat(),
            ),
            (
                "domain value",
                build_geosite("CN", &[good.clone(), short((2 << 3) | 2)]),
            ),
            ("attribute key", build_geosite("CN", &[bad_attribute])),
        ] {
            // 后面还有一个好条目，所以不是截断的文件 / A good entry follows, so the file is not
            // a truncated one
            assert_refused(
                build_dat(&[entry, build_geosite("ADS", std::slice::from_ref(&good))]),
                what,
            );
        }
    }

    /// 截断的文件（写入中断）必须整份拒绝，而不是把读到的部分当成完整版本。
    /// A truncated file must be rejected outright rather than taken as complete.
    #[test]
    fn truncated_dat_is_rejected_instead_of_dropping_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_dat(
            &dir,
            &[
                build_geosite("CN", &[build_domain(2, "baidu.com", &[])]),
                build_geosite("ADS", &[build_domain(2, "doubleclick.net", &[])]),
            ],
        );
        let mut manager = GeoSiteManager::new();
        manager.load_from_v2ray_file(&path).unwrap();

        // 只写出前半段，模拟覆盖写到一半 / Write only the first half
        let full = std::fs::read(&path).unwrap();
        std::fs::write(&path, &full[..full.len() * 2 / 3]).unwrap();
        manager
            .load_from_v2ray_file(&path)
            .expect_err("a truncated file must be rejected");

        assert!(
            manager.matches("ads", "www.doubleclick.net"),
            "a rejected file must leave the previous data in place"
        );
        assert!(manager.matches("cn", "www.baidu.com"));

        // 按需解析（生产代码走的这一路）同样整份拒绝 / Selective parsing, the way production
        // code reads, rejects it whole as well
        std::fs::write(&path, &full).unwrap();
        let tags = ["cn".to_string(), "ads".to_string()];
        let mut selective = GeoSiteManager::new();
        selective
            .load_from_dat_file_selective(&path, &tags)
            .unwrap();
        std::fs::write(&path, &full[..full.len() * 2 / 3]).unwrap();
        selective
            .load_from_dat_file_selective(&path, &tags)
            .expect_err("a truncated file must be rejected");
        assert!(
            selective.matches("ads", "www.doubleclick.net"),
            "a rejected file must leave the previous data in place"
        );
        assert!(selective.matches("cn", "www.baidu.com"));
    }

    #[test]
    fn test_split_tag_attrs() {
        assert_eq!(
            split_tag_attrs("category-games"),
            ("category-games", vec![])
        );
        assert_eq!(
            split_tag_attrs("category-games@cn"),
            ("category-games", vec!["cn"])
        );
        assert_eq!(
            split_tag_attrs("category-games@!cn"),
            ("category-games", vec!["!cn"])
        );
        assert_eq!(
            split_tag_attrs("category-games@cn@ads"),
            ("category-games", vec!["cn", "ads"])
        );
        // Edge: empty parts → no split
        for tag in ["tag@", "@cn", "tag@cn@", "tag@@cn"] {
            assert_eq!(split_tag_attrs(tag), (tag, vec![]));
        }
    }

    #[test]
    fn test_has_attrs() {
        let keys = |keys: &[&str]| keys.iter().map(|key| key.to_string()).collect::<Vec<_>>();
        let cn = keys(&["cn"]);
        assert!(has_attrs(&cn, &cn));
        assert!(!has_attrs(&[], &cn));
        // Nothing asked for: every domain
        assert!(has_attrs(&[], &[]));
        // `!cn` is the literal key, as in V2Ray: neither `cn` nor no attribute
        assert!(!has_attrs(&cn, &keys(&["!cn"])));
        assert!(!has_attrs(&[], &keys(&["!cn"])));
        assert!(has_attrs(&keys(&["!cn"]), &keys(&["!cn"])));
        assert!(!has_attrs(&keys(&["!cn"]), &cn));
        // Every attribute asked for is required, in any order
        assert!(has_attrs(&keys(&["cn", "ads"]), &keys(&["ads", "cn"])));
        assert!(!has_attrs(&cn, &keys(&["cn", "ads"])));
    }

    /// 标签里写了几个属性时，选出的是每个属性都带的域名，和 V2Ray 一样。以前只在第一个 `@` 处拆开，`test@cn@ads`
    /// 要的是一个叫 `cn@ads` 的属性，一个域名都选不出
    /// A tag naming several attributes selects the domains carrying every one of them, as in
    /// V2Ray. Only the first `@` used to split, so `test@cn@ads` asked for one attribute named
    /// `cn@ads` and selected no domain at all
    #[test]
    fn a_tag_with_several_attributes_selects_the_domains_carrying_all_of_them() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_dat(
            &dir,
            &[build_geosite(
                "TEST",
                &[
                    build_domain(3, "both.example", &["cn", "ads"]),
                    build_domain(3, "cn.example", &["cn"]),
                    build_domain(3, "ads.example", &["ads"]),
                    build_domain(3, "none.example", &[]),
                ],
            )],
        );
        let tag = "test@cn@ads".to_string();
        let mut manager = GeoSiteManager::new();
        manager
            .load_from_dat_file_selective(&path, std::slice::from_ref(&tag))
            .unwrap();
        assert!(manager.matches(&tag, "both.example"));
        for name in ["cn.example", "ads.example", "none.example"] {
            assert!(!manager.matches(&tag, name), "{name}");
        }
    }

    /// 属性只取 key，转成小写；`typed_value` 跳过 / An attribute gives just its key, lowercased;
    /// its `typed_value` is skipped
    #[test]
    fn attribute_keys_are_read_without_their_values() {
        let mut attribute = encode_str(1, "GeoLocation");
        attribute.extend(encode_varint_field(2, 1)); // bool_value = true
        let mut domain = build_domain(3, "a.example", &["cn"]);
        domain.extend(encode_ld(3, &attribute));
        let (_, attrs) = Domain::decode(domain.as_slice())
            .unwrap()
            .into_entry()
            .unwrap();
        assert_eq!(attrs, ["cn", "geolocation"]);
    }

    #[test]
    fn test_geosite_attr_filter_end_to_end() {
        let domains = vec![
            build_domain(3, "example.com", &["cn"]), // Full match, has @cn
            build_domain(3, "other.com", &[]),       // Full match, no attrs
            build_domain(3, "foreign.com", &["!cn"]), // Full match, has the key `!cn`
        ];
        let entry = build_geosite("TEST", &domains);
        let dat = build_dat(&[entry]);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kixdns_test_attr.dat");
        std::fs::write(&path, &dat).unwrap();

        // @cn: only example.com
        let mut m1 = GeoSiteManager::new();
        m1.load_from_dat_file_selective(&path, &["test@cn".to_string()])
            .unwrap();
        assert!(m1.matches("test@cn", "example.com"));
        assert!(!m1.matches("test@cn", "other.com"));
        assert!(!m1.matches("test@cn", "foreign.com"));

        // no filter: all three
        let mut m2 = GeoSiteManager::new();
        m2.load_from_dat_file_selective(&path, &["test".to_string()])
            .unwrap();
        assert!(m2.matches("test", "example.com"));
        assert!(m2.matches("test", "other.com"));
        assert!(m2.matches("test", "foreign.com"));

        // @!cn: the domains carrying the key `!cn`, as in V2Ray; not a negation
        let mut m3 = GeoSiteManager::new();
        m3.load_from_dat_file_selective(&path, &["test@!cn".to_string()])
            .unwrap();
        assert!(!m3.matches("test@!cn", "example.com"));
        assert!(!m3.matches("test@!cn", "other.com"));
        assert!(m3.matches("test@!cn", "foreign.com"));

        // Without `cn` is the tag minus `@cn`, the two matchers a rule combines
        let mut m4 = GeoSiteManager::new();
        m4.load_from_dat_file_selective(&path, &["test".to_string(), "test@cn".to_string()])
            .unwrap();
        let without_cn =
            |domain: &str| m4.matches("test", domain) && !m4.matches("test@cn", domain);
        assert!(!without_cn("example.com"));
        assert!(without_cn("other.com"));
        assert!(without_cn("foreign.com"));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_geosite_attr_and_plain_same_base() {
        // Request both `test` and `test@cn` — both should load from same .dat entry
        let domains = vec![
            build_domain(3, "a.com", &["cn"]),
            build_domain(3, "b.com", &[]),
        ];
        let entry = build_geosite("DUAL", &domains);
        let dat = build_dat(&[entry]);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kixdns_test_dual.dat");
        std::fs::write(&path, &dat).unwrap();

        let mut m = GeoSiteManager::new();
        let count = m
            .load_from_dat_file_selective(&path, &["dual".to_string(), "dual@cn".to_string()])
            .unwrap();
        assert_eq!(count, 2); // both loaded

        assert!(m.matches("dual", "a.com"));
        assert!(m.matches("dual", "b.com"));
        assert!(m.matches("dual@cn", "a.com"));
        assert!(!m.matches("dual@cn", "b.com"));

        let _ = std::fs::remove_file(&path);
    }

    const V2RAY_JSON_ENTRIES: &str = r#"{"entries":[{"tag":"t","domains":[
        "github.com", "domain:example.org", "full:exact.net", ".dotted.io",
        "Upper.Case", "keyword:kw", "keyword:UP", "regexp:^re\\.x$", "*.wild.dev", "*.Mixed.dev"
    ]}]}"#;

    fn assert_v2ray_json_entries(manager: &GeoSiteManager) {
        let cases = [
            ("github.com", true),
            ("www.github.com", true),
            ("WWW.GitHub.com", true),
            ("notgithub.com", false),
            ("example.org", true),
            ("a.example.org", true),
            ("notexample.org", false),
            ("exact.net", true),
            ("www.exact.net", false),
            ("dotted.io", true),
            ("a.dotted.io", true),
            ("notdotted.io", false),
            ("upper.case", true),
            ("a.upper.case", true),
            ("akwb.com", true),
            ("xupx.com", true),
            ("re.x", true),
            ("a.wild.dev", true),
            ("wild.dev", false),
            ("a.mixed.dev", true),
            ("unrelated.com", false),
        ];
        for (domain, expected) in cases {
            assert_eq!(manager.matches("t", domain), expected, "{domain}");
        }
    }

    /// JSON 条目按 V2Ray 的写法匹配：`domain:` 和不带前缀的值含子域名并按整段比较，`full:` 只匹配本身，
    /// 不区分大小写。字符串和配置文件（parse_json_file）两条加载路径都测。
    /// JSON entries follow V2Ray: `domain:` and unprefixed values take in subdomains by whole labels,
    /// `full:` the name only, ignoring case. Both the string loader and the configured-file path
    /// (parse_json_file) are checked.
    #[test]
    fn json_entries_follow_v2ray_and_match_whole_labels() {
        let mut from_string = GeoSiteManager::new();
        from_string
            .load_from_v2ray_string(V2RAY_JSON_ENTRIES)
            .unwrap();
        assert_v2ray_json_entries(&from_string);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("geosite.json");
        std::fs::write(&path, V2RAY_JSON_ENTRIES).unwrap();
        let mut from_file = GeoSiteManager::new();
        let parsed = GeoSiteManager::parse_json_file(&path, &[]).unwrap();
        from_file.apply_source(&path, parsed);
        assert_v2ray_json_entries(&from_file);
    }

    /// JSON 数据文件和 .dat 一样只解出点名的标签，不分大小写：没点名的条目连域名都不解，写坏了也不碍事。
    /// 以前每个标签都解析、都建匹配器
    /// A JSON data file, like a .dat, decodes only the tags named, ignoring case: an entry not
    /// named does not have even its domains parsed, so a broken one does no harm. Every tag
    /// used to be parsed and given matchers
    #[test]
    fn a_json_file_decodes_only_the_tags_named() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("geosite.json");
        std::fs::write(
            &path,
            r#"{"entries":[
                {"tag":"ADS","domains":["domain:ads.example"]},
                {"tag":"unused","domains":5},
                {"tag":"cn","domains":["full:baidu.com"]}
            ]}"#,
        )
        .unwrap();
        let parsed = GeoSiteManager::parse_file(&path, &["ads".to_string()]).unwrap();
        let tags: Vec<&str> = parsed.iter().map(|(tag, _)| tag.as_str()).collect();
        assert_eq!(tags, ["ads"]);
        assert!(
            GeoSiteManager::parse_file(&path, &[]).is_err(),
            "every tag wanted, the broken one is parsed too"
        );
    }

    /// 前缀不认识、没有值或正则无效的条目跳过，其余照常加载；空值不会让整个分类匹配一切。
    /// Entries with an unknown prefix, no value or an invalid regex are skipped and the rest load;
    /// an empty value does not make the whole tag match everything.
    #[test]
    fn json_entries_that_cannot_match_are_skipped() {
        let mut manager = GeoSiteManager::new();
        manager
            .load_from_v2ray_string(
                r#"{"entries":[{"tag":"t","domains":[
                    "include:other", "ext:file:tag", "", "domain:", "full:",
                    "keyword:", "regexp:", "regexp:(", "ok.com"
                ]}]}"#,
            )
            .unwrap();
        assert_eq!(manager.get_tag_matchers("t").map(|m| m.len()), Some(1));
        assert!(manager.matches("t", "ok.com"));
        assert!(!manager.matches("t", "anything.example"));
    }

    /// .dat 里的根域名（V2Ray 的 `domain:`）同样按整段比较；空值匹配不到任何域名。
    /// Root domains in a .dat file (V2Ray's `domain:`) compare whole labels too; an empty value
    /// matches no domain.
    #[test]
    fn dat_root_domains_match_whole_labels() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_dat(
            &dir,
            &[
                build_geosite("t", &[build_domain(2, "github.com", &[])]),
                build_geosite("empty", &[build_domain(2, "", &[])]),
            ],
        );
        let mut manager = GeoSiteManager::new();
        manager.load_from_v2ray_file(&path).unwrap();
        assert!(manager.matches("t", "github.com"));
        assert!(manager.matches("t", "api.github.com"));
        assert!(!manager.matches("t", "notgithub.com"));
        assert!(!manager.matches("empty", "github.com"));

        // 按需解析（生产代码走的这一路）一样 / The same with selective parsing, the way
        // production code reads
        let mut selective = GeoSiteManager::new();
        selective
            .load_from_dat_file_selective(&path, &["t".to_string(), "empty".to_string()])
            .unwrap();
        assert!(selective.matches("t", "github.com"));
        assert!(selective.matches("t", "api.github.com"));
        assert!(!selective.matches("t", "notgithub.com"));
        assert!(!selective.matches("empty", "github.com"));
    }

    /// JSON 的分类名和 .dat 一样读进来转成小写；原来写成大写的分类永远查不到。
    /// JSON tags are lowercased as they are read, as .dat tags are; a tag written in capitals
    /// used to be unreachable.
    #[test]
    fn json_tags_ignore_case() {
        let json = r#"{"entries":[{"tag":"Ads","domains":["ads.example"]}]}"#;
        let mut from_string = GeoSiteManager::new();
        from_string.load_from_v2ray_string(json).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("geosite.json");
        std::fs::write(&path, json).unwrap();
        let mut from_file = GeoSiteManager::new();
        let parsed = GeoSiteManager::parse_json_file(&path, &[]).unwrap();
        from_file.apply_source(&path, parsed);
        for manager in [&from_string, &from_file] {
            assert!(manager.matches("ads", "ads.example"));
        }
    }

    #[test]
    fn domain_matcher_suffix_compares_whole_labels_ignoring_case() {
        let suffix = DomainMatcher::Suffix("GitHub.com".to_string());
        assert!(suffix.matches("github.com"));
        assert!(suffix.matches("WWW.GITHUB.COM"));
        assert!(!suffix.matches("notgithub.com"));
        assert!(DomainMatcher::Suffix(".github.com".to_string()).matches("github.com"));
        assert!(!DomainMatcher::Suffix(String::new()).matches("github.com"));
        assert!(!DomainMatcher::Suffix(".".to_string()).matches("github.com"));
    }

    /// 索引查找和逐条比较的结果完全相同：随机生成条目和域名，包括大小写、开头的点、两个点、
    /// 空值、结尾的点、关键词和正则
    /// The index gives exactly what trying every entry gives: random entries and names,
    /// with mixed case, leading dots, double dots, empty values, trailing dots, keywords
    /// and regexes
    #[test]
    fn the_index_matches_exactly_as_every_entry_would() {
        const LABELS: [&str; 8] = ["a", "B", "ex", "Ex", "cn", "com", "", "xn--p1ai"];
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move |bound: usize| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state % bound as u64) as usize
        };
        let name = |next: &mut dyn FnMut(usize) -> usize| {
            let labels = 1 + next(4);
            let mut out = (0..labels)
                .map(|_| LABELS[next(LABELS.len())])
                .collect::<Vec<_>>()
                .join(".");
            match next(8) {
                0 => out.insert(0, '.'),
                1 => out.push('.'),
                _ => {}
            }
            out
        };
        let regexes = ["^a\\.", "Ex", "cn$", "^$"];
        for round in 0..400 {
            let mut matchers = Vec::new();
            for _ in 0..next(12) {
                let value = name(&mut next);
                matchers.push(match next(6) {
                    0 => DomainMatcher::Full(value),
                    1 => DomainMatcher::Suffix(format!(".{value}")),
                    2 => DomainMatcher::Suffix(format!("..{value}")),
                    3 => DomainMatcher::Keyword(LABELS[next(LABELS.len())].to_string()),
                    4 => DomainMatcher::Regex(Regex::new(regexes[next(regexes.len())]).unwrap()),
                    _ => DomainMatcher::Suffix(value),
                });
            }
            let indexed = indexed(matchers.clone());
            for _ in 0..60 {
                let domain = name(&mut next);
                assert_eq!(
                    indexed.matches(&domain),
                    matchers.iter().any(|matcher| matcher.matches(&domain)),
                    "round {round}: {domain:?} against {matchers:?}"
                );
            }
        }
    }

    /// GeoSite 正则只留 ASCII：只含 ASCII 的名字结果和按 Unicode 编译时相同，`\w` 不认非 ASCII 字母，和 v2ray 一样；
    /// `\pL{20}` 编出来和 `[A-Za-z]{20}` 一样小；写错的照旧是错
    /// GeoSite regexes are kept to ASCII: names of ASCII alone match as compiled for Unicode, and
    /// `\w` takes no non-ASCII letter, as in v2ray; `\pL{20}` compiles as small as `[A-Za-z]{20}`;
    /// one written wrong is still wrong
    /// 数据里的一条正则照数据文件读它时的样子编译：字符类只留 ASCII 的部分（见 [`ascii_regex_pattern`]）
    /// One regex of the data compiled as reading a data file makes it, every class kept to its
    /// ASCII part (see [`ascii_regex_pattern`])
    fn compile_geosite_regex(pattern: &str) -> anyhow::Result<Regex> {
        Ok(limited_regex(&ascii_regex_pattern(pattern)?)?)
    }

    #[test]
    fn geosite_regexes_are_kept_to_ascii() {
        let word = r"^r+[0-9]+(---|\.)sn-(2x3|ni5|j5o)\w{5}\.googlevideo\.com$";
        let go = compile_geosite_regex(word).unwrap();
        let unicode = Regex::new(word).unwrap();
        for name in [
            "r1---sn-2x3abcde.googlevideo.com",
            "rr22.sn-ni5x_y9z.googlevideo.com",
            "r1---sn-2x3abcd.googlevideo.com",
        ] {
            assert_eq!(go.is_match(name), unicode.is_match(name), "{name}");
        }
        assert!(!go.is_match("r1---sn-2x3abcdé.googlevideo.com"));
        assert!(unicode.is_match("r1---sn-2x3abcdé.googlevideo.com"));

        let within_64_kib = |pattern: &str| {
            regex::RegexBuilder::new(pattern)
                .size_limit(64 * 1024)
                .build()
                .is_ok()
        };
        let letters = r"^\pL{20}\.example\.com$";
        assert!(!within_64_kib(letters), "as written, as Unicode");
        assert!(within_64_kib(&ascii_regex_pattern(letters).unwrap()));
        assert!(
            compile_geosite_regex(letters)
                .unwrap()
                .is_match("abcdefghijklmnopqrst.example.com")
        );
        assert!(compile_geosite_regex("(unclosed").is_err());
        assert!(
            compile_geosite_regex(r"[\w-a]").is_err(),
            "a class cannot end a range"
        );
    }

    /// 名字集合按小写存一份：大小写不同的同一个名字只存一次，重复加入什么都不变；查找时调用方
    /// 已经转成小写
    /// A name set keeps one lowercase copy: the same name in another case is stored once, adding
    /// it again changes nothing, and lookups come lowercased from the caller
    #[test]
    fn a_name_set_keeps_each_lowercase_name_once() {
        let mut set = NameSet::with_capacity(3, 31);
        assert!(set.insert("Example.COM"));
        assert!(set.insert("example.com"));
        assert!(set.insert("other.test"));
        assert_eq!(set.len(), 2);
        assert!(set.contains("example.com"));
        assert!(set.contains("other.test"));
        assert!(!set.contains("Example.COM"));
        assert!(!set.contains("example.co"));
        assert!(!set.contains("xample.com"));
        let mut names = set.iter().collect::<Vec<_>>();
        names.sort_unstable();
        assert_eq!(names, ["example.com", "other.test"]);
    }

    /// 长度两个字节记不下的值放不进名字集合，就按原样逐条比较，命中与否不变
    /// A value whose length two bytes cannot hold does not go into a name set and is tried as
    /// it is, matching just the same
    #[test]
    fn a_value_too_long_for_a_name_set_still_matches_as_written() {
        let long = format!("{}.test", "a".repeat(70_000));
        let indexed = indexed(vec![
            DomainMatcher::Full(long.to_ascii_uppercase()),
            DomainMatcher::Suffix(format!("x.{long}")),
        ]);
        assert!(indexed.full.is_empty() && indexed.suffixes.is_empty());
        assert!(indexed.matches(&long));
        assert!(indexed.matches(&format!("www.x.{long}")));
        assert!(!indexed.matches(&format!("y.{long}")));
        assert!(!indexed.matches("a.test"));
    }

    /// 后缀条目按整段命中，开头的点不计，大小写不计；完整域名只命中它自己
    /// Suffix entries match by whole labels, ignoring one leading dot and case; a full
    /// name matches itself only
    #[test]
    fn the_index_matches_suffixes_by_label_and_full_names_exactly() {
        let indexed = indexed(vec![
            DomainMatcher::Suffix(".Example.com".to_string()),
            DomainMatcher::Full("only.test".to_string()),
            DomainMatcher::Keyword("ads".to_string()),
        ]);
        for (domain, expected) in [
            ("example.com", true),
            ("WWW.example.COM", true),
            ("a.b.example.com", true),
            ("notexample.com", false),
            ("example.com.cn", false),
            ("only.test", true),
            ("ONLY.test", true),
            ("www.only.test", false),
            ("myads.net", true),
            ("net", false),
        ] {
            assert_eq!(indexed.matches(domain), expected, "{domain}");
        }
    }

    /// 数据文件里的正则和配置里的一样最长 16384 字节，在解析之前查：长一个字节的跳过，什么名字都不匹配，同一个
    /// tag 的其他条目照常；刚好 16384 字节、内容寻常的照常编译。.dat 和 JSON 都是。正则先整条解析成语法树才看
    /// 编译后的大小，`\pL` 在树里是几 KB 的 Unicode 区间：以前数据里一条 1 MiB 的 `\pL` 要 2 GB 内存。
    /// A data file's regex is at most 16384 bytes, as a configuration's is, checked before it is
    /// parsed: one a byte longer is skipped, matching no name, and the tag's other entries load
    /// as usual; one of exactly 16384 bytes with ordinary content compiles. So for .dat and JSON
    /// alike. A regex is parsed whole into its syntax tree before its compiled size is looked at,
    /// and `\pL` is several KB of Unicode ranges there: one regex of 1 MiB of `\pL` in the data
    /// used to take 2 GB.
    #[test]
    fn a_data_regex_longer_than_16_kib_is_skipped() {
        use crate::matcher::{MAX_REGEX_LEN, tests::names_regex};
        let at_limit = names_regex(r"at-limit\.example", MAX_REGEX_LEN);
        let over = names_regex(r"over\.example", MAX_REGEX_LEN + 1);
        let check = |tag: &TagMatchers| {
            assert_eq!(tag.regexes.len(), 2);
            assert!(tag.matches("at-limit.example"));
            assert!(tag.matches("cdn7.example.com"));
            assert!(tag.matches("ok.com"));
            assert!(!tag.matches("over.example"));
        };

        let dir = tempfile::tempdir().unwrap();
        let path = write_dat(
            &dir,
            &[build_geosite(
                "t",
                &[
                    build_domain(1, &over, &[]),
                    build_domain(1, &at_limit, &[]),
                    build_domain(1, r"^cdn\d\.example\.com$", &[]),
                    build_domain(3, "ok.com", &[]),
                ],
            )],
        );
        let parsed = GeoSiteManager::parse_dat_file_selective(&path, &["t".to_string()]).unwrap();
        check(&parsed[0].1);

        let json = serde_json::json!({ "entries": [{ "tag": "t", "domains": [
            format!("regexp:{over}"),
            format!("regexp:{at_limit}"),
            r"regexp:^cdn\d\.example\.com$",
            "full:ok.com",
        ] }] });
        let path = dir.path().join("geosite.json");
        std::fs::write(&path, json.to_string()).unwrap();
        let parsed = GeoSiteManager::parse_json_file(&path, &[]).unwrap();
        check(&parsed[0].1);
    }

    /// 合成一个集合的正则同时解析成语法树、都留到编译完，所以一组的写法合起来也不超过一条正则的上限：数据里 64 条
    /// 16 KiB 的 `\pL` 以前合成一组，要 2 GB 内存。刚好到上限的合在一组；一条就比上限长的（改写成 Go 的字符类会
    /// 变长）自成一组。真实数据里的正则短（最多的 tag 合起来 4 KB 左右），照旧每 256 条一组
    /// The regexes combined into one set are parsed into syntax trees together and all kept until
    /// compiled, so a group's patterns together are no longer than one regex may be either: 64
    /// regexes of 16 KiB of `\pL` in the data used to combine into one group, taking 2 GB. Those
    /// exactly reaching the limit share a group; one longer than the limit by itself (rewriting the
    /// Go way lengthens it) makes a group alone. The regexes of real data are short (some 4 KB
    /// together for the tag with most), and still go 256 to a group
    #[test]
    fn a_group_of_regexes_is_no_longer_than_one_regex_may_be() {
        use crate::matcher::{MAX_REGEX_LEN, tests::names_regex};
        let half = |i: usize| names_regex(&format!(r"half{i}\.example"), MAX_REGEX_LEN / 2);
        let longer = names_regex(r"longer\.example", MAX_REGEX_LEN + 100);
        let patterns = vec![half(0), half(1), half(2), longer, half(3), half(4)];
        let regexes = Regexes::new(patterns);
        let Regexes(sets) = &regexes;
        assert_eq!(
            sets.iter().map(RegexSet::len).collect::<Vec<_>>(),
            [2, 1, 1, 2]
        );
        for name in [
            "half0.example",
            "half1.example",
            "half2.example",
            "longer.example",
            "half3.example",
            "half4.example",
        ] {
            assert!(regexes.is_match(name), "{name}");
        }
        assert!(!regexes.is_match("half5.example"));
    }

    /// 多条正则合成一组以后，命中与否和逐条比较完全一样
    /// Combined into one set, regexes match exactly as they do one by one
    #[test]
    fn combined_regexes_match_exactly_as_each_one_does() {
        let patterns = [
            "^a\\.",
            "Ex",
            "cn$",
            "^$",
            "(^|\\.)google\\.[a-z]{2,3}$",
            "^www\\d+\\.",
        ];
        let each: Vec<Regex> = patterns.iter().map(|p| Regex::new(p).unwrap()).collect();
        let combined = Regexes::new(patterns.iter().map(|p| p.to_string()).collect());
        assert_eq!(combined.0.len(), 1, "several regexes combine into one set");
        for domain in [
            "a.example",
            "A.example",
            "Example.org",
            "example.org",
            "www.163.cn",
            "",
            "mail.google.com",
            "google.community",
            "www12.site.net",
            "site.net",
        ] {
            let expected = each.iter().any(|regex| regex.is_match(domain));
            assert_eq!(combined.is_match(domain), expected, "{domain:?}");
        }
        assert_eq!(combined.len(), patterns.len());
        let listed: Vec<String> = combined
            .to_regexes()
            .iter()
            .map(|regex| regex.as_str().to_owned())
            .collect();
        assert_eq!(listed, patterns);
    }

    /// 合成集合的正则守着每条的上限：单独编译超出上限的那条放在集合里也跳过，同一组别的正则照常命中，别的组不受影响，
    /// 还是一个集合。以前集合的上限是每条的上限乘以条数，这样的正则在大 tag 里照样编进集合、照样命中，单独编译（tag 里
    /// 只有它一条，或者整个 tag 退回逐条比较）时却跳过
    /// Regexes combined into sets keep each one's limit: one over the limit compiled alone is
    /// skipped inside a set too, the other regexes of its group match as usual, and the other
    /// groups are not affected, one set still. A set's limit used to be the per-regex limit
    /// times the number of regexes, so such a regex was compiled into a set and matched in a large
    /// tag, yet was skipped compiled alone (the only regex of its tag, or the whole tag falling
    /// back to one by one)
    #[test]
    fn a_regex_over_the_limit_alone_is_skipped_inside_a_set_too() {
        let oversized = ascii_regex_pattern(r"^(?:\w{30000})?oversized\.example$").unwrap();
        assert!(limited_regex(&oversized).is_err(), "over the limit alone");
        let count = Regexes::SET_SIZE * 2;
        let mut patterns: Vec<String> = (0..count).map(|i| format!(r"^ad{i}\.example$")).collect();
        patterns[7] = oversized;
        let regexes = Regexes::new(patterns);
        assert!(!regexes.is_match("oversized.example"));
        assert_eq!(regexes.len(), count - 1);
        for i in (0..count).filter(|&i| i != 7) {
            assert!(regexes.is_match(&format!("ad{i}.example")), "{i}");
        }
        assert_eq!(
            regexes.0.last().map(RegexSet::len),
            Some(Regexes::SET_SIZE),
            "the second group combines whole"
        );
    }

    /// 正则多于一组时分成几个集合，命中与否和逐条比较完全一样；分组前后的条目都能命中
    /// More regexes than one group holds split into several sets and match exactly as they do one
    /// by one; entries before and after a group boundary all match
    #[test]
    fn many_regexes_split_into_groups_and_match_as_each_one_does() {
        let count = Regexes::SET_SIZE * 2 + 1;
        let patterns: Vec<String> = (0..count)
            .map(|i| format!(r"^(?:.*\.)?ad{i}x\.example\.com$"))
            .collect();
        let regexes = Regexes::new(patterns);
        assert_eq!(regexes.0.len(), 3, "{count} regexes make three groups");
        assert_eq!(regexes.len(), count);
        assert_eq!(regexes.to_regexes().len(), count);
        // 每个名字只有一条正则命中，所以每一组都得问到 / Each name matches one regex only, so
        // every group must be asked
        for i in [0, Regexes::SET_SIZE - 1, Regexes::SET_SIZE, count - 1] {
            assert!(regexes.is_match(&format!("cdn.ad{i}x.example.com")), "{i}");
        }
        assert!(!regexes.is_match(&format!("cdn.ad{count}x.example.com")));
    }

    /// 数据文件里写成大写的 keyword 照样命中：请求名是小写的，keyword 也得是小写。按需加载和全部加载
    /// 都是这样。
    /// A keyword the data file writes in capitals still matches: request names are lowercase,
    /// so the keyword has to be too. Both selective and full loading read it so.
    #[test]
    fn a_keyword_written_in_capitals_matches() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_dat(&dir, &[build_geosite("K", &[encode_str(2, "GooGle")])]);

        let parsed = GeoSiteManager::parse_dat_file_selective(&path, &["k".to_string()]).unwrap();
        assert!(parsed[0].1.matches("www.google.com"));

        let mut manager = GeoSiteManager::new();
        manager.load_from_v2ray_file(&path).unwrap();
        assert!(manager.matches("k", "www.google.com"));
        assert!(!manager.matches("k", "www.example.com"));
    }

    /// 超过 10 个字节的变长整数是坏文件，按需加载和全部加载都报错，不读出一个错位的长度
    /// A varint longer than 10 bytes means a broken file: both selective and full loading
    /// refuse it rather than read a length out of it
    #[test]
    fn a_varint_too_long_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("geosite.dat");
        let mut data = vec![0x0A];
        data.extend([0xFF; 11]);
        data.push(0x01);
        std::fs::write(&path, data).unwrap();
        assert!(GeoSiteManager::parse_file(&path, &[]).is_err());
        assert!(GeoSiteManager::parse_dat_file_selective(&path, &["x".to_string()]).is_err());
    }
}
