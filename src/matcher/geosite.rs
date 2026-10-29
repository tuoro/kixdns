// GeoSite 域名分类匹配器 / GeoSite domain category matcher
// 支持基于域名分类的路由决策 / Supports routing decisions based on domain categorization

use std::fs;
use std::path::{Path, PathBuf};
use std::thread;

use std::hash::BuildHasher;
use std::io::Read;

use anyhow::Context;
use hashbrown::HashTable;
use regex::{Regex, RegexBuilder, RegexSet, RegexSetBuilder};
use rustc_hash::{FxBuildHasher, FxHashMap};
use serde::Deserialize;
use tracing::{debug, info, warn};

use super::domain_suffix_matches;

/// 编译 GeoSite 数据里的一条正则。数据是给 v2ray 写的，v2ray 用 Go 的正则，那里 `\w`、`\d`、`\s`、`\b` 只认
/// ASCII；Rust 的正则默认按 Unicode 理解，`\w{5}` 要展开整张 Unicode 字母表，`cn` 里这样的正则让进程多占好几 MiB。
/// 所以先把这几类写法改成 Go 的 ASCII 写法（见 [`go_classes`]），其余照旧；改写后编译不了（不该发生）就按原样编译。
/// 只含 ASCII 的名字两种写法结果相同，含其他字符的名字按 v2ray 的理解。
/// Compiles one regex of GeoSite data. The data is written for v2ray, whose Go regexes treat
/// `\w`, `\d`, `\s` and `\b` as ASCII only; Rust regexes default to Unicode, where `\w{5}` spells
/// out the whole Unicode alphabet, and such regexes in `cn` cost the process several MiB. So these
/// classes are first rewritten the Go way (see [`go_classes`]) and the rest is left as it is; a
/// rewrite that does not compile (it should not happen) compiles as written instead. Names of
/// ASCII alone match the same either way; names with other characters match as v2ray reads the
/// pattern.
fn compile_geosite_regex(pattern: &str) -> Result<Regex, regex::Error> {
    // 原样的写法也不对时，按原样编译拿到正则自己的报错 / When the pattern as written is wrong too,
    // compiling it as written gives the regex's own error
    Regexes::compile(&geosite_regex_pattern(pattern).unwrap_or_else(|_| pattern.to_owned()))
}

/// 一条 GeoSite 正则实际要编译的写法：按 Go 的含义改写过字符类的（见 [`go_classes`]），改写后语法不对（不该发生）
/// 就用原样，原样也不对时返回语法错误。只检查语法、不编译：数据文件里一个 tag 的正则读完以后合成一个集合，只编译
/// 这一次（见 [`Regexes::new`]）；以前每条先单独编译一次，`geolocation-!cn` 的 151 条因此多占好几 MiB。
/// The pattern a GeoSite regex actually compiles as: with its classes rewritten the Go way (see
/// [`go_classes`]), as written when the rewrite does not parse (it should not happen), and a
/// syntax error when that does not parse either. Only the syntax is checked, nothing compiles:
/// a data file's regexes for one tag are combined into one set once read, which is the only
/// compile (see [`Regexes::new`]); compiling each one first as well cost several MiB for the
/// 151 regexes of `geolocation-!cn`.
fn geosite_regex_pattern(pattern: &str) -> Result<String, Box<regex_syntax::Error>> {
    let check = |pattern: &str| {
        regex_syntax::Parser::new()
            .parse(pattern)
            .map(drop)
            .map_err(Box::new)
    };
    if let std::borrow::Cow::Owned(rewritten) = go_classes(pattern)
        && check(&rewritten).is_ok()
    {
        return Ok(rewritten);
    }
    check(pattern).map(|()| pattern.to_owned())
}

/// 只匹配空名字的正则，写错的正则用它顶替 / A regex matching only the empty name, standing in for
/// one written wrong
const EMPTY_NAME: &str = "^$";

/// `pattern` 里的 `\w`、`\d`、`\s`、`\b` 及其大写的取反形式改成 Go 正则的 ASCII 含义：字符类外写成一个字符类
/// （`\b` 写成 `(?-u:\b)`），字符类里展开成范围（取反的写成嵌套的字符类）。转义的反斜杠和别的转义原样保留。
/// `\w`, `\d`, `\s` and `\b` in `pattern`, and their negated capitals, rewritten to their ASCII
/// meaning in Go regexes: outside a class each becomes a class (`\b` becomes `(?-u:\b)`), inside a
/// class it becomes ranges (a negated one a nested class). Escaped backslashes and other escapes
/// stay as they are.
fn go_classes(pattern: &str) -> std::borrow::Cow<'_, str> {
    const WORD: &str = "0-9A-Za-z_";
    const DIGIT: &str = "0-9";
    const SPACE: &str = r"\t\n\f\r ";
    if !pattern.contains('\\') {
        return std::borrow::Cow::Borrowed(pattern);
    }
    let mut out = String::with_capacity(pattern.len() + 16);
    let mut changed = false;
    // 字符类嵌套的层数，和刚开始一个字符类（这时的 `]` 是字面字符）
    // How deep in character classes, and whether one just began (where `]` is a literal)
    let (mut depth, mut class_start) = (0usize, false);
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        let starting = std::mem::take(&mut class_start);
        match c {
            '\\' => {
                let Some(next) = chars.next() else {
                    out.push(c);
                    break;
                };
                let class = match next.to_ascii_lowercase() {
                    'w' => Some(WORD),
                    'd' => Some(DIGIT),
                    's' => Some(SPACE),
                    _ => None,
                };
                match (class, next.is_ascii_uppercase(), depth > 0) {
                    (Some(class), false, true) => out.push_str(class),
                    (Some(class), negated, _) => {
                        out.push_str(if negated { "[^" } else { "[" });
                        out.push_str(class);
                        out.push(']');
                    }
                    (None, _, false) if matches!(next, 'b' | 'B') => {
                        out.push_str("(?-u:\\");
                        out.push(next);
                        out.push(')');
                    }
                    _ => {
                        out.push(c);
                        out.push(next);
                        continue;
                    }
                }
                changed = true;
            }
            '[' => {
                depth += 1;
                class_start = true;
                out.push(c);
            }
            '^' if starting => {
                class_start = true;
                out.push(c);
            }
            ']' if depth > 0 && !starting => {
                depth -= 1;
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    if changed {
        std::borrow::Cow::Owned(out)
    } else {
        std::borrow::Cow::Borrowed(pattern)
    }
}

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

impl GeoSiteEntry {
    /// 标准化：将所有匹配器转换为小写（配置加载时调用）
    /// Normalization: convert all matchers to lowercase (called during config loading)
    #[inline]
    pub fn normalized(mut self) -> Self {
        for matcher in &mut self.matchers {
            match matcher {
                DomainMatcher::Full(domain) => *domain = domain.to_ascii_lowercase(),
                DomainMatcher::Suffix(suffix) => *suffix = suffix.to_ascii_lowercase(),
                DomainMatcher::Keyword(keyword) => *keyword = keyword.to_ascii_lowercase(),
                DomainMatcher::Regex(_) => {} // 正则不转换 / Regex not converted
            }
        }
        self
    }
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

    /// 所有名字（调试用，顺序不保留） / Every name (for debugging; order is not kept)
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

/// 一个 tag 的正则条目。每 [`Regexes::SET_SIZE`] 条合成一个 [`RegexSet`]，一遍扫描就知道一组里
/// 有没有哪条命中：`geolocation-!cn` 这样带上百条正则的 tag，逐条比较要几微秒，合起来不到一微秒。
/// 合不成（超出大小上限）时退回逐条比较。
/// One tag's regex entries. Every [`Regexes::SET_SIZE`] of them combine into one [`RegexSet`], so
/// a single scan tells whether any in that group matches: a tag like `geolocation-!cn` with over a
/// hundred regexes takes microseconds one by one and well under one combined. When they cannot be
/// combined (over the size limit) they are tried one by one instead.
#[derive(Debug, Default)]
enum Regexes {
    #[default]
    None,
    Sets(Vec<RegexSet>),
    Each(Vec<Regex>),
}

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

    /// 每条正则编译后的大小上限；合成的集合是它乘以条数，合起来不会比逐条编译时更宽
    /// The compiled size limit of each regex; a combined set gets it times the number of
    /// regexes, so combining allows no more than compiling them one by one
    const SIZE_LIMIT_EACH: usize = 1_000_000;

    /// 编译一条正则，用每条的上限 / Compiles one regex within the per-regex limit
    fn compile(pattern: &str) -> Result<Regex, regex::Error> {
        RegexBuilder::new(pattern)
            .size_limit(Self::SIZE_LIMIT_EACH)
            .dfa_size_limit(Self::SIZE_LIMIT_EACH)
            .build()
    }

    /// 由各条正则的写法建成：多条分组合成集合，只编译这一次
    /// Built from the regexes' patterns: several combine into sets, compiled this once
    fn new(patterns: Vec<String>) -> Self {
        Self::with_size_limit(patterns, Self::SIZE_LIMIT_EACH)
    }

    /// 同上，集合的上限按每条 `limit_each` 计（测试用来逼出合不成的情形）
    /// The same with the set's limit counted as `limit_each` per regex (tests use it to force a
    /// set that cannot combine)
    fn with_size_limit(patterns: Vec<String>, limit_each: usize) -> Self {
        match patterns.len() {
            0 => Self::None,
            1 => Self::Each(Self::compile_each(&patterns)),
            count => match patterns
                .chunks(Self::SET_SIZE)
                .map(|group| {
                    RegexSetBuilder::new(group)
                        .size_limit(limit_each.saturating_mul(group.len()))
                        .build()
                })
                .collect()
            {
                Ok(sets) => Self::Sets(sets),
                Err(err) => {
                    warn!(target = "geosite", regexes = count, error = %err,
                        "GeoSite regexes too large to combine, matching them one by one");
                    Self::Each(Self::compile_each(&patterns))
                }
            },
        }
    }

    /// 逐条编译；编译不了的（超出上限）照旧只匹配空名字 / Compiles one by one; one that does not
    /// compile (over the limit) matches only the empty name, as before
    fn compile_each(patterns: &[String]) -> Vec<Regex> {
        patterns
            .iter()
            .map(|pattern| {
                Self::compile(pattern).unwrap_or_else(|err| {
                    warn!(target = "geosite", pattern = %pattern, error = %err,
                         "invalid regex pattern, using empty regex");
                    Regex::new(EMPTY_NAME).expect("a valid regex")
                })
            })
            .collect()
    }

    fn is_match(&self, domain: &str) -> bool {
        match self {
            Self::None => false,
            Self::Sets(sets) => sets.iter().any(|set| set.is_match(domain)),
            Self::Each(each) => each.iter().any(|regex| regex.is_match(domain)),
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::None => 0,
            Self::Sets(sets) => sets.iter().map(RegexSet::len).sum(),
            Self::Each(each) => each.len(),
        }
    }

    /// 正则重新展开成一条条（调试用） / The regexes one by one again (for debugging)
    fn to_regexes(&self) -> Vec<Regex> {
        match self {
            Self::None => Vec::new(),
            // 集合里的每一条单独编译时都没超过上限，这里照样编译得出来
            // Every pattern in a set compiled within the limit on its own, so it compiles here again
            Self::Sets(sets) => sets
                .iter()
                .flat_map(RegexSet::patterns)
                .filter_map(|pattern| Self::compile(pattern).ok())
                .collect(),
            Self::Each(each) => each.clone(),
        }
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
            DatEntry::Regex(pattern) => {
                let pattern = geosite_regex_pattern(&pattern).unwrap_or_else(|err| {
                    warn!(target = "geosite", pattern = %pattern, error = %err,
                         "invalid regex pattern, using empty regex");
                    EMPTY_NAME.to_owned()
                });
                self.regexes.push(pattern);
            }
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
    fn new(matchers: Vec<DomainMatcher>) -> Self {
        // 先数好条数和总长，两组名字各一次分配到位 / Count first, so each set of names is allocated once
        let (mut full, mut suffixes) = ((0, 0), (0, 0));
        for matcher in &matchers {
            match matcher {
                DomainMatcher::Full(name) => (full.0, full.1) = (full.0 + 1, full.1 + name.len()),
                DomainMatcher::Suffix(suffix) => {
                    (suffixes.0, suffixes.1) = (suffixes.0 + 1, suffixes.1 + suffix.len())
                }
                _ => {}
            }
        }
        let mut builder = TagBuilder::with_capacity(full, suffixes);
        for matcher in matchers {
            builder.add(matcher);
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

    /// 条目重新展开成匹配器列表（调试用，顺序不保留）
    /// The entries as a list of matchers again (for debugging; order is not kept)
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

/// 被替换下来的 tag 交给另一个线程释放：释放一个大 tag 的索引和建它差不多费时，而调用方这时
/// 正持有管理器的写锁。起不了线程时就在这里释放。
/// Frees replaced tags on another thread: freeing a large tag's index takes about as
/// long as building it, and the caller holds the manager's write lock meanwhile.
/// When no thread can be started they are freed here.
fn retire(retired: Vec<TagMatchers>) {
    if retired.is_empty() {
        return;
    }
    // On failure the closure, and `retired` with it, is dropped right here
    // 失败时闭包连同 `retired` 就在这里释放
    let _ = thread::Builder::new()
        .name("geosite-retire".to_string())
        .spawn(move || drop(retired));
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
    // 每个数据文件贡献的 tag，重载时据此只替换该文件的条目
    // Tags contributed by each data file, so a reload replaces only that file's entries
    sources: FxHashMap<PathBuf, Vec<String>>,
}

/// 一个数据文件解析出的 tag 与域名匹配器，尚未进入管理器
/// Tags and matchers parsed out of one data file, not yet applied to a manager.
/// They come indexed already (see [`TagMatchers`]): the index is built while
/// parsing, outside the manager's write lock, so applying them only swaps them in.
/// 已经建好索引（见 [`TagMatchers`]）：索引在解析时、管理器的写锁之外建好，应用时只是换进去。
pub type ParsedGeoSite = Vec<(String, TagMatchers)>;

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
            sources: FxHashMap::default(),
        }
    }

    /// 记下加载后的规模（加载完数据后调用）/ Log the size after loading (call after loading data)
    fn log_totals(&self) {
        let total_domains: usize = self.database.values().map(TagMatchers::len).sum();
        tracing::info!(
            geosite_tags = self.database.len(),
            total_domains = total_domains,
            "GeoSite data loaded"
        );
    }

    /// 添加 GeoSite 条目 / Add GeoSite entry
    pub fn add_entry(&mut self, entry: GeoSiteEntry) {
        // 在添加时自动标准化 / Auto-normalize on add
        let normalized = entry.normalized();
        self.database
            .insert(normalized.tag, TagMatchers::new(normalized.matchers));
    }

    /// 检查域名是否匹配指定的 GeoSite 标签 / Check if domain matches specified GeoSite tag
    ///
    /// # 参数 / Parameters
    /// - `tag`: GeoSite 标签（如 "cn", "google", "category-ads"）/ GeoSite tag
    /// - `domain`: 要检查的域名 / Domain to check
    ///
    /// # 返回 / Returns
    /// - `true`: 域名匹配该标签 / Domain matches the tag
    /// - `false`: 域名不匹配该标签 / Domain does not match the tag
    #[inline]
    pub fn matches(&self, tag: &str, domain: &str) -> bool {
        // 不区分大小写：按小写的 tag 查找；配置里的 tag 一般已是小写，就不另分配一份
        // Case insensitive: looked up by the lowercased tag; tags in a config are usually lowercase
        // already, and then no lowercased copy is made
        let lowered;
        let tag = if tag.bytes().any(|b| b.is_ascii_uppercase()) {
            lowered = tag.to_ascii_lowercase();
            lowered.as_str()
        } else {
            tag
        };
        self.database
            .get(tag)
            .is_some_and(|matchers| matchers.matches(domain))
    }

    /// 检查标签是否已加载 / Check if tag is loaded
    #[inline]
    pub fn has_tag(&self, tag: &str) -> bool {
        self.database.contains_key(tag)
    }

    /// `tags`（规则用到的，不分大小写）里哪些没有一个数据文件提供：用它们的规则永远不会命中
    /// The tags among `tags` (the ones rules use, ignoring case) that no data file provides:
    /// rules using them never match
    pub fn missing_tags(&self, tags: &[String]) -> Vec<String> {
        let mut missing: Vec<String> = tags
            .iter()
            .map(|tag| tag.to_ascii_lowercase())
            .filter(|tag| !self.database.contains_key(tag))
            .collect();
        missing.sort_unstable();
        missing.dedup();
        missing
    }

    /// 数据文件 `path` 眼下有没有提供 `tags`（不分大小写）里的标签
    /// Whether data file `path` provides any of `tags` (ignoring case) right now
    pub fn source_provides_any(&self, path: &Path, tags: &[String]) -> bool {
        self.sources
            .get(&Self::source_key(path))
            .is_some_and(|provided| provided.iter().any(|tag| is_one_of(tag, tags)))
    }

    /// 获取标签的所有域名匹配器（仅用于调试）/ Get all domain matchers for a tag (debug only)
    #[inline]
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

/// Split a GeoSite tag with optional `@attr` filter into (base, Option<attr>)
/// `category-games@cn` → (`category-games`, Some(`cn`))
/// `category-games`    → (`category-games`, None)
fn split_tag_attr(tag: &str) -> (&str, Option<&str>) {
    match tag.split_once('@') {
        Some((base, attr)) if !base.is_empty() && !attr.is_empty() => (base, Some(attr)),
        _ => (tag, None),
    }
}

/// Check if a domain's attributes satisfy the `@attr` filter
/// The filter is an attribute key, compared without case, as in V2Ray:
/// `cn`   → domain has attribute `cn`
/// `!cn`  → domain has attribute `!cn`, a key domain-list-community uses
///          itself, so it is not a negation
///
/// The domains of a tag that lack an attribute are two matchers:
/// `geosite: google` together with `geosite_not: google@cn`.
fn attr_filter_matches(attrs: &[String], filter: &str) -> bool {
    attrs.iter().any(|a| a.eq_ignore_ascii_case(filter))
}

/// 数据文件里读出的一条。正则只留写法，等整个 tag 读完合成一个集合时才编译（见 [`Regexes::new`]）
/// One entry read from a data file. A regex keeps only its pattern, compiled when the whole tag
/// is read and combined into one set (see [`Regexes::new`])
#[derive(Clone)]
enum DatEntry {
    Matcher(DomainMatcher),
    Regex(String),
}

/// 一条 V2Ray Domain 消息里用到的字段（见 [`GeoSiteManager::read_domain`]）
/// The fields of a V2Ray Domain message used here (see [`GeoSiteManager::read_domain`])
struct V2rayDomain<'a> {
    /// `type`，没写时是 0（关键词） / `type`, 0 (keyword) when left out
    kind: usize,
    /// `value`，没写时没有 / `value`, absent when left out
    value: Option<&'a [u8]>,
    /// 各个 `attribute` 的 key / The key of each `attribute`
    attrs: Vec<String>,
}

/// 跳过 `data` 里 `pos` 处一个线上类型为 `wire_type` 的字段值（字段头已经读过）。值越出 `data`、
/// 或者线上类型不认识时为 Err
/// Skips the value of one field of wire type `wire_type` at `pos` in `data` (its key
/// already read). Err when the value runs past `data` or the wire type is unknown
fn skip_field(data: &[u8], pos: &mut usize, wire_type: u8) -> anyhow::Result<()> {
    match wire_type {
        0 => {
            parse_varint(data, pos)?;
        }
        1 => {
            if runs_past(*pos, 8, data.len()) {
                anyhow::bail!("invalid domain data: incomplete fixed64");
            }
            *pos += 8;
        }
        5 => {
            if runs_past(*pos, 4, data.len()) {
                anyhow::bail!("invalid domain data: incomplete fixed32");
            }
            *pos += 4;
        }
        2 => {
            let len = parse_varint(data, pos)?;
            if runs_past(*pos, len, data.len()) {
                anyhow::bail!("invalid domain data: incomplete length-delimited");
            }
            *pos += len;
        }
        _ => anyhow::bail!("unknown wire type: {}", wire_type),
    }
    Ok(())
}

/// Parse a V2Ray Domain.Attribute protobuf message to extract the key field
/// Attribute { string key = 1; oneof typed_value { ... } }
fn parse_attribute_key(data: &[u8]) -> Option<String> {
    let mut pos = 0;
    while pos < data.len() {
        let field_tag = data[pos] >> 3;
        let wire_type = data[pos] & 0x07;
        pos += 1;

        match field_tag {
            1 => {
                let len = parse_varint(data, &mut pos).ok()?;
                if runs_past(pos, len, data.len()) {
                    return None;
                }
                return std::str::from_utf8(&data[pos..pos + len])
                    .ok()
                    .map(|s| s.to_ascii_lowercase());
            }
            // 跳过越出 `data` 时，原来也是走出循环、得到 None / A skip past `data` left the loop
            // with None before as well
            _ => skip_field(data, &mut pos, wire_type).ok()?,
        }
    }
    None
}

/// 解析 varint / Parse varint
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

    /// 下一个字节，文件读完了是 None / The next byte, or None at the end of the file
    fn byte(&mut self) -> anyhow::Result<Option<u8>> {
        if self.pos >= self.len {
            return Ok(None);
        }
        let mut byte = [0u8];
        self.file.read_exact(&mut byte)?;
        self.pos += 1;
        Ok(Some(byte[0]))
    }

    /// 下一个字节，必须有 / The next byte, which must be there
    fn next_byte(&mut self) -> anyhow::Result<u8> {
        self.byte()?
            .ok_or_else(|| anyhow::anyhow!("unexpected end of file"))
    }

    /// 和 [`parse_varint`] 一样读一个变长整数 / Reads a varint as [`parse_varint`] does
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

/// 读一个变长整数：最多 10 个字节，多了就是坏文件 / Reads a varint: 10 bytes at most,
/// more means a broken file
fn parse_varint(data: &[u8], pos: &mut usize) -> anyhow::Result<usize> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        if *pos >= data.len() {
            anyhow::bail!("unexpected end of file");
        }
        let byte = data[*pos];
        *pos += 1;
        value |= u64::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            return varint_len(value);
        }
    }
    anyhow::bail!("invalid varint in .dat file")
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
    /// 从 V2Ray 格式文件加载 GeoSite 数据 / Load GeoSite data from V2Ray format file
    ///
    /// # 参数 / Parameters
    /// - `path`: 文件路径 / File path
    ///
    /// # 返回 / Returns
    /// 返回加载的条目数量 / Returns the number of loaded entries
    ///
    /// # 错误 / Errors
    /// 如果文件不存在或格式错误，返回错误 / Returns error if file doesn't exist or format is invalid
    ///
    /// # 示例 / Example
    /// ```no_run
    /// use kixdns::matcher::geosite::GeoSiteManager;
    /// let mut manager = GeoSiteManager::new();
    /// let count = manager.load_from_v2ray_file("geosite.json").unwrap();
    /// println!("Loaded {} GeoSite entries", count);
    /// ```
    pub fn load_from_v2ray_file<P: AsRef<Path>>(&mut self, path: P) -> anyhow::Result<usize> {
        let path = path.as_ref();
        let parsed = Self::parse_file(path, &[])?;
        Ok(self.apply_source(path, parsed))
    }

    /// 用完整解析器（见 [`Self::parse_dat_file`]）加载 .dat 文件里的每一个 tag，只给测试用
    /// Load every tag of a .dat file with the full parser (see [`Self::parse_dat_file`]),
    /// for tests only
    #[cfg(test)]
    pub fn load_from_dat_file<P: AsRef<Path>>(&mut self, path: P) -> anyhow::Result<usize> {
        let path = path.as_ref();
        let parsed = Self::parse_dat_file(path)?;
        Ok(self.apply_source(path, parsed))
    }

    /// 完整解析器：一次读进整个 .dat 文件，解出每一个 tag，只给测试用。生产代码只用按需解析
    /// （[`Self::parse_dat_file_selective`]，不点名 tag 时是 `parse_dat_file_every_tag`）；这一份是
    /// 另写的实现，留作测试里的独立对照。
    /// The full parser: reads a whole .dat file at once and decodes every tag, for tests
    /// only. Production code only parses selectively ([`Self::parse_dat_file_selective`],
    /// or `parse_dat_file_every_tag` when no tag is named); this separately written one
    /// stays as an independent reference in tests.
    #[cfg(test)]
    pub fn parse_dat_file<P: AsRef<Path>>(path: P) -> anyhow::Result<ParsedGeoSite> {
        let path = path.as_ref();

        // 读取文件内容 / Read file content
        let content =
            fs::read(path).with_context(|| format!("read .dat file: {}", path.display()))?;

        // V2Ray .dat 文件格式分析 / V2Ray .dat file format analysis
        // 外层结构：repeated GeoSite 条目 / Outer structure: repeated GeoSite entries
        // 每个 GeoSite 条目包含 / Each GeoSite entry contains:
        //   - tag (string, field tag 0x0A)
        //   - domains (repeated message, field tag 0x12)
        //     每个域名包含 / Each domain contains:
        //       - type (uint64, field tag 0x08)
        //       - value (string, field tag 0x12)

        let mut pos = 0;
        let mut parsed: ParsedGeoSite = Vec::new();

        while pos < content.len() {
            // 读取外层字段标签 / Read outer field tag
            let field_tag = content[pos];
            pos += 1;

            // 解析 varint 长度 / Parse varint length
            let entry_len = parse_varint(&content, &mut pos)?;

            // 文件被截断（写入中断或读到写了一半的覆盖）：拒绝整份文件，
            // 否则调用方会把读到的那部分当成完整版本，文件里其余的 tag 就被删掉了。
            // A truncated file (an interrupted write, or a half-written overwrite
            // caught in the act) is rejected outright: otherwise the caller takes
            // the part that was read as the complete file and drops every tag the
            // rest of it holds.
            if runs_past(pos, entry_len, content.len()) {
                anyhow::bail!(
                    "truncated .dat file: entry at offset {pos} needs {entry_len} bytes, {} left",
                    content.len() - pos
                );
            }

            let entry_end = pos + entry_len;

            // field_tag = 0x0A 表示 GeoSite 条目 (field 1, wire type 2: string)
            // field_tag = 0x0A indicates GeoSite entry (field 1, wire type 2: string)
            if field_tag == 0x0A {
                let mut tag = String::new();
                // 这个条目的匹配器和条数 / This entry's matchers and how many
                let (mut builder, mut domain_count) = (TagBuilder::default(), 0);

                // 解析 GeoSite 条目内容 / Parse GeoSite entry content
                while pos < entry_end {
                    let inner_tag = content[pos];
                    pos += 1;

                    let inner_len = parse_varint(&content, &mut pos)?;

                    if runs_past(pos, inner_len, entry_end) {
                        break;
                    }

                    match inner_tag {
                        // 0x0A: country_code (string, field 1)
                        0x0A => {
                            if let Ok(tag_str) = std::str::from_utf8(&content[pos..pos + inner_len])
                            {
                                tag = tag_str.to_string();
                                tracing::debug!(target = "geosite", tag = %tag_str, "parsed GeoSite country_code");
                            }
                            pos += inner_len;
                        }
                        // 0x12: domain (repeated Domain message, field 2)
                        0x12 => {
                            // V2Ray 的 domain 字段是 repeated Domain 消息
                            // V2Ray's domain field is repeated Domain messages
                            // 每个 Domain 消息包含: type (field 1) 和 value (field 2)
                            // Each Domain message contains: type (field 1) and value (field 2)
                            let domains_data = &content[pos..pos + inner_len];
                            match Self::parse_v2ray_domains(domains_data) {
                                Ok(parsed) => {
                                    let count = usize::from(parsed.is_some());
                                    if let Some((entry, _)) = parsed {
                                        builder.add_entry(entry);
                                    }
                                    domain_count += count;
                                    tracing::debug!(target = "geosite", tag = %tag,
                                                 count = count,
                                                 "parsed domains from V2Ray protobuf format");
                                }
                                Err(err) => {
                                    tracing::warn!(target = "geosite", tag = %tag, error = %err,
                                                  "failed to parse V2Ray domains, skipping tag");
                                }
                            }
                            pos += inner_len;
                        }
                        _ => {
                            // 跳过未知字段 / Skip unknown field
                            pos += inner_len;
                        }
                    }
                }

                // 使用解析好的 matchers / Use parsed matchers
                if !tag.is_empty() && domain_count > 0 {
                    tracing::info!(target = "geosite", tag = %tag,
                                domain_count = domain_count,
                                "loaded GeoSite tag with domains");
                    // 将 tag 转换为小写以支持大小写不敏感的匹配 / Convert tag to lowercase for case-insensitive matching
                    let tag_lower = tag.to_lowercase();
                    tracing::debug!(target = "geosite", original_tag = %tag, tag_lower = %tag_lower,
                                 "inserting tag into database");
                    parsed.push((tag_lower, builder.finish()));
                } else if !tag.is_empty() {
                    tracing::warn!(target = "geosite", tag = %tag,
                                  "tag has no valid domains, skipping");
                }
            } else {
                // 跳过未知字段 / Skip unknown field
                pos = entry_end;
            }
        }

        // 根据实际加载的条数重建缓存
        info!(
            target = "geosite",
            loaded_count = parsed.len(),
            "loaded GeoSite data from V2Ray .dat file"
        );
        Ok(parsed)
    }

    /// 解析 JSON 格式的数据文件，不触碰管理器状态
    /// Parse a JSON data file without touching manager state
    ///
    /// 与 [`Self::parse_dat_file_selective`] 对称，同样与 [`Self::apply_source`] 配合：
    /// 调用方在锁外解析，只在替换数据时短暂持写锁。
    /// The counterpart of [`Self::parse_dat_file_selective`], pairing with
    /// [`Self::apply_source`] the same way: callers parse outside the lock and
    /// hold the write lock only while swapping data in.
    pub fn parse_json_file<P: AsRef<Path>>(path: P) -> anyhow::Result<ParsedGeoSite> {
        let path = path.as_ref();
        let content = fs::read_to_string(path)
            .with_context(|| format!("read geosite file: {}", path.display()))?;
        let v2ray_data: V2RayGeoSiteList =
            serde_json::from_str(&content).with_context(|| "parse V2Ray GeoSite JSON format")?;
        Ok(Self::convert_v2ray_to_entries(v2ray_data)
            .into_iter()
            .map(|entry| {
                let normalized = entry.normalized();
                (normalized.tag, TagMatchers::new(normalized.matchers))
            })
            .collect())
    }

    /// 按扩展名选择解析器解析一个数据文件，不触碰管理器状态
    /// Parse a data file with the parser its extension selects, without
    /// touching manager state
    ///
    /// `.dat` 走 V2Ray 二进制解析器，其余按 JSON 读。`tags` 只对 `.dat` 有意义
    /// （二进制格式可以只解出需要的 tag）；JSON 一次读完整份，由调用方挑选。
    /// 格式分派集中在这里：登记进 `sources` 的文件后续会被 `apply_source` 和
    /// `reload_tags_from` 再次读取，三处必须用同一套判定，否则会拿错解析器。
    /// `.dat` uses the V2Ray binary parser and anything else is read as JSON.
    /// `tags` only means something for `.dat`, where the binary format allows
    /// decoding just the wanted tags; JSON is read whole and the caller picks.
    /// Keeping the dispatch in one place matters because a file registered in
    /// `sources` is read again later by `apply_source` and `reload_tags_from`,
    /// and all of them have to agree on which parser a path needs.
    pub fn parse_file<P: AsRef<Path>>(path: P, tags: &[String]) -> anyhow::Result<ParsedGeoSite> {
        let path = path.as_ref();
        let is_dat = path
            .extension()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s.eq_ignore_ascii_case("dat"));
        if !is_dat {
            return Self::parse_json_file(path);
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
    /// （`geosite_data_paths` 接受多个文件）。
    /// Tags dropped from the file disappear with it while tags from other files
    /// stay (`geosite_data_paths` accepts several files).
    pub fn apply_source<P: AsRef<Path>>(&mut self, path: P, parsed: ParsedGeoSite) -> usize {
        let key = Self::source_key(path.as_ref());
        let previous = self.sources.remove(&key).unwrap_or_default();

        let mut tags = Vec::with_capacity(parsed.len());
        let mut retired = Vec::new();
        for (tag, matchers) in parsed {
            retired.extend(self.database.insert(tag.clone(), matchers));
            tags.push(tag);
        }

        // 这个文件不再提供的 tag：没有别的文件提供就删掉；还有别的文件提供，
        // 就从那个文件里重新读出来顶上——否则索引里留着的仍是本文件的旧条目，
        // 名义上 tag 还在，命中的却是已经被删掉的数据。多个文件声明同一个 tag
        // 时最后加载的一份生效（与全量加载一致）。
        // For tags this file no longer provides: drop them when no other file
        // provides them, and re-read them from a file that still does otherwise.
        // Without that the index keeps this file's own stale entries, so the tag
        // survives but matches data that was deleted. When several files declare
        // the same tag the last load wins, as with a full load.
        // 先按提供者分组再读：同一个文件顶上多少个 tag 都只解析一次，代价与被删
        // 的 tag 数无关。写锁是整个匹配器共享的，这里多读一遍就是多停顿一次查询。
        // Group by provider before reading: one parse per file however many tags
        // it takes over, so the cost no longer scales with the number of dropped
        // tags. The write lock is shared with matching, so every extra read here
        // is another stall for queries.
        let mut takeovers: FxHashMap<PathBuf, Vec<String>> = FxHashMap::default();
        for tag in previous {
            if tags.contains(&tag) {
                continue;
            }
            match self.other_source_providing(&key, &tag) {
                Some(other) => takeovers.entry(other).or_default().push(tag),
                None => {
                    retired.extend(self.database.remove(&tag));
                }
            }
        }
        for (path, wanted) in takeovers {
            self.reload_tags_from(&path, &wanted, &mut retired);
        }

        let loaded_count = tags.len();
        self.sources.insert(key, tags);

        self.log_totals();
        retire(retired);
        loaded_count
    }

    /// 找一个仍在提供这个 tag 的其它数据文件；多个候选时取路径最小的一个，
    /// 让结果与哈希表的遍历顺序无关。
    /// Find another data file still providing this tag; with several candidates
    /// the smallest path wins, so the result does not depend on hash order.
    fn other_source_providing(&self, skip: &Path, tag: &str) -> Option<PathBuf> {
        self.sources
            .iter()
            .filter(|(path, provided)| {
                path.as_path() != skip && provided.iter().any(|name| name == tag)
            })
            .map(|(path, _)| path.clone())
            .min()
    }

    /// 从另一个数据文件里重新读出单个 tag；读不出来就保持原样，等那个文件自己
    /// 重载时纠正，总好过留下一个空 tag。
    /// Re-read a single tag from another data file; leave the index as it is when
    /// that fails and let the other file's own reload fix it, which beats leaving
    /// the tag empty.
    fn reload_tags_from(&mut self, path: &Path, wanted: &[String], retired: &mut Vec<TagMatchers>) {
        match Self::parse_file(path, wanted) {
            Ok(parsed) => {
                let mut taken = 0usize;
                for (tag, matchers) in parsed {
                    if wanted.contains(&tag) {
                        retired.extend(self.database.insert(tag, matchers));
                        taken += 1;
                    }
                }
                if taken < wanted.len() {
                    warn!(
                        target = "geosite",
                        path = %path.display(), wanted = wanted.len(), taken,
                        "data file no longer contains every tag it was recorded as providing"
                    );
                }
            }
            Err(e) => {
                warn!(
                    target = "geosite",
                    path = %path.display(), tags = wanted.len(), error = %e,
                    "failed to re-read shared tags, keeping the current entries"
                );
            }
        }
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

    /// 从 .dat 文件按需加载指定的 GeoSite tags / Load specified GeoSite tags from .dat file on-demand
    ///
    /// # 参数 / Parameters
    /// - `path`: .dat 文件路径 / .dat file path
    /// - `tags`: 需要加载的 tag 列表 / List of tags to load
    ///
    /// # 返回 / Returns
    /// 返回实际加载的条目数量 / Returns the number of entries actually loaded
    ///
    /// # 错误 / Errors
    /// 如果文件不存在或格式错误，返回错误 / Returns error if file doesn't exist or format is invalid
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

    /// 按条目读 .dat 文件，留下要的 tag：`tags` 是点名的那些（可以带 `@属性`），None 时每个 tag 都要
    /// Read a .dat file entry by entry, keeping the wanted tags: the named `tags` (which may
    /// carry `@attribute`), or every tag with None
    fn parse_dat_entries(path: &Path, tags: Option<&[String]>) -> anyhow::Result<ParsedGeoSite> {
        // Pre-process tags: split `tag@attr` syntax into (base, attr_filter)
        // Map: base_tag_lower → Vec<(store_tag_lower, Option<attr_filter>)>
        let mut tag_requests: FxHashMap<String, Vec<(String, Option<String>)>> =
            FxHashMap::default();
        for tag in tags.unwrap_or_default() {
            let (base, attr) = split_tag_attr(tag);
            tag_requests
                .entry(base.to_lowercase())
                .or_default()
                .push((tag.to_lowercase(), attr.map(|a| a.to_lowercase())));
        }

        if let Some(tags) = tags {
            info!(target = "geosite", requested_tags = ?tags,
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

        while let Some(field_tag) = file.byte()? {
            let entry_len = file.varint()?;
            let pos = file.pos;

            // 文件被截断（写入中断或读到写了一半的覆盖）：拒绝整份文件，
            // 否则调用方会把读到的那部分当成完整版本，文件里其余的 tag 就被删掉了。
            // A truncated file (an interrupted write, or a half-written overwrite
            // caught in the act) is rejected outright: otherwise the caller takes
            // the part that was read as the complete file and drops every tag the
            // rest of it holds.
            if runs_past(pos, entry_len, file.len) {
                anyhow::bail!(
                    "truncated .dat file: entry at offset {pos} needs {entry_len} bytes, {} left",
                    file.len - pos
                );
            }

            let entry_start = pos;
            let entry_end = pos + entry_len;

            // field_tag = 0x0A 表示 GeoSite 条目 / 0x0A is a GeoSite entry
            if field_tag != 0x0A {
                file.seek_to(entry_end)?;
                continue;
            }
            let mut tag = String::new();

            // 先解析 tag，判断是否需要加载 / Parse tag first to check if we need to load it
            // Clone matching requests out of the map to release the borrow before mutating self
            let matching_requests: Option<Vec<(String, Option<String>)>> = loop {
                if file.pos >= entry_end {
                    break None;
                }
                let inner_tag = file.next_byte()?;
                let inner_len = file.varint()?;
                if runs_past(file.pos, inner_len, entry_end) {
                    break None;
                }
                // 0x0A: tag/country_code (string, field 1)
                // 只看第一个 tag 字段：protobuf 规定同一个字段写了几次时取最后一个，可那样每个条目都得
                // 把字段走完，不要的条目就没法读到 tag 就整段跳过；真实数据里每个条目只有一个 tag
                // Only the first tag field counts: protobuf takes the last when a field is
                // written more than once, but then every entry's fields would have to be walked
                // and an unwanted entry could not be skipped whole once its tag is read; real
                // data has one tag per entry
                if inner_tag == 0x0A {
                    file.read(&mut field, inner_len)?;
                    if let Ok(tag_str) = std::str::from_utf8(&field) {
                        tag = tag_str.to_string();
                        let tag_lower = tag.to_lowercase();
                        // Match against base tags (supports `@attr` split); with no tag named,
                        // every non-empty tag is wanted
                        let reqs = match tags {
                            Some(_) => tag_requests.get(&tag_lower).cloned(),
                            None => (!tag_lower.is_empty()).then(|| vec![(tag_lower, None)]),
                        };
                        if let Some(reqs) = reqs {
                            debug!(target = "geosite", tag = %tag_str,
                                  "loading requested tag");
                            break Some(reqs);
                        } else {
                            debug!(target = "geosite", tag = %tag_str,
                                   "skipping unwanted tag");
                        }
                    }
                    break None;
                }
                file.seek_to(file.pos + inner_len)?;
            };

            let Some(requests) = matching_requests else {
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

            while file.pos < entry_end {
                let inner_tag = file.next_byte()?;
                let inner_len = file.varint()?;
                if runs_past(file.pos, inner_len, entry_end) {
                    break;
                }
                if inner_tag != 0x12 {
                    file.seek_to(file.pos + inner_len)?;
                    continue;
                }
                file.read(&mut field, inner_len)?;
                match Self::parse_v2ray_domains(&field) {
                    Ok(domains) => {
                        if let Some((entry, attrs)) = domains {
                            for ((builder, count), (_, attr_filter)) in
                                builders.iter_mut().zip(&requests)
                            {
                                if attr_filter
                                    .as_deref()
                                    .is_none_or(|f| attr_filter_matches(&attrs, f))
                                {
                                    builder.add_entry(entry.clone());
                                    *count += 1;
                                }
                            }
                        }
                    }
                    Err(err) => {
                        warn!(target = "geosite", tag = %tag, error = %err,
                             "failed to parse V2Ray domains, skipping domain entry");
                    }
                }
            }
            file.seek_to(entry_end)?;

            // Store each request's tag under its original name
            // 每个请求的 tag 按原来的名字存放
            for ((builder, count), (store_tag, attr_filter)) in builders.into_iter().zip(&requests)
            {
                if count > 0 {
                    info!(target = "geosite", tag = %store_tag,
                          domain_count = count,
                          attr_filter = ?attr_filter,
                          "loaded GeoSite tag with domains");
                    parsed.push((store_tag.clone(), builder.finish()));
                } else if tags.is_none() {
                    warn!(target = "geosite", tag = %store_tag,
                          "tag has no valid domains, skipping");
                } else {
                    warn!(target = "geosite", tag = %store_tag,
                          attr_filter = ?attr_filter,
                          "no domains matched attribute filter");
                }
            }
        }

        match tags {
            Some(tags) => info!(
                target = "geosite",
                loaded_count = parsed.len(),
                requested_count = tags.len(),
                "selectively loaded GeoSite data from .dat file"
            ),
            None => info!(
                target = "geosite",
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
        while file.pos < entry_end {
            let inner_tag = file.next_byte()?;
            let inner_len = file.varint()?;
            if runs_past(file.pos, inner_len, entry_end) {
                break;
            }
            if inner_tag != 0x12 {
                file.seek_to(file.pos + inner_len)?;
                continue;
            }
            file.read(field, inner_len)?;
            match Self::domain_type_and_len(field) {
                // 和 `parse_v2ray_domains` 一样：2 是后缀，3 和不认识的类型按完整域名
                // As in `parse_v2ray_domains`: 2 is a suffix, 3 and unknown types are full names
                Some((2, len)) => (suffixes.0, suffixes.1) = (suffixes.0 + 1, suffixes.1 + len),
                Some((kind, len)) if kind >= 3 => (full.0, full.1) = (full.0 + 1, full.1 + len),
                _ => {}
            }
        }
        Ok((full, suffixes))
    }

    /// 一条 Domain 消息的类型和值的长度（见 [`Self::read_domain`]），给 [`Self::count_names`] 用
    /// One Domain message's type and value length (see [`Self::read_domain`]), for
    /// [`Self::count_names`]
    fn domain_type_and_len(data: &[u8]) -> Option<(usize, usize)> {
        let domain = Self::read_domain(data, false).ok()?;
        Some((domain.kind, domain.value?.len()))
    }

    /// 读出一条 V2Ray Domain 消息的类型（字段 1）、值（字段 2）和属性（字段 3，`with_attrs` 时才取），字段不论先后。
    /// proto3 不写取默认值的字段：没有字段 1 时类型是 0（Plain，即关键词），v2ray 数据里的关键词条目正是这样写的；
    /// 值为空时同样不写，这样的条目没有值。
    /// Reads one V2Ray Domain message's type (field 1), value (field 2) and attributes (field 3,
    /// taken only `with_attrs`), in whatever order they come. proto3 leaves out fields holding
    /// their default: without field 1 the type is 0 (Plain, that is a keyword), which is exactly
    /// how keyword entries are written in v2ray data; an empty value is left out the same way, and
    /// such an entry has no value.
    fn read_domain(data: &[u8], with_attrs: bool) -> anyhow::Result<V2rayDomain<'_>> {
        let mut domain = V2rayDomain {
            kind: 0,
            value: None,
            attrs: Vec::new(),
        };
        let mut pos = 0;
        while pos < data.len() {
            // 读取 field tag 和 wire type / Read field tag and wire type
            let field_tag = data[pos] >> 3;
            let wire_type = data[pos] & 0x07;
            pos += 1;

            match field_tag {
                1 => {
                    // field 1: type (varint, wire_type 0)
                    if wire_type != 0 {
                        anyhow::bail!("invalid wire type for type field");
                    }
                    domain.kind = parse_varint(data, &mut pos)?;
                }
                2 => {
                    // field 2: value (string, wire_type 2)
                    if wire_type != 2 {
                        anyhow::bail!("invalid wire type for value field");
                    }
                    let value_len = parse_varint(data, &mut pos)?;
                    if runs_past(pos, value_len, data.len()) {
                        anyhow::bail!("invalid domain data: incomplete value string");
                    }
                    domain.value = Some(&data[pos..pos + value_len]);
                    pos += value_len;
                }
                3 => {
                    // field 3: attribute (repeated Attribute message, wire_type 2)
                    // Domain.Attribute { string key = 1; oneof typed_value { ... } }
                    if wire_type != 2 {
                        anyhow::bail!("invalid wire type for attribute field");
                    }
                    let attr_len = parse_varint(data, &mut pos)?;
                    if runs_past(pos, attr_len, data.len()) {
                        anyhow::bail!("invalid domain data: incomplete attribute");
                    }
                    if with_attrs && let Some(key) = parse_attribute_key(&data[pos..pos + attr_len])
                    {
                        domain.attrs.push(key);
                    }
                    pos += attr_len;
                }
                // 跳过未知字段 / Skip unknown field
                _ => skip_field(data, &mut pos, wire_type)?,
            }
        }
        Ok(domain)
    }

    /// 解析 V2Ray protobuf 格式的 Domain 消息列表 / Parse V2Ray protobuf format Domain message list
    ///
    /// V2Ray .dat 文件中的 domains 字段是 repeated Domain 消息
    /// The domains field in V2Ray .dat file is repeated Domain messages
    /// 每个 Domain 消息包含: type (field 1, varint) 和 value (field 2, string)
    /// Each Domain message contains: type (field 1, varint) and value (field 2, string)
    /// Returns the entry and its attribute keys, which enable `@attr` filtering; None for a
    /// domain without a value
    fn parse_v2ray_domains(data: &[u8]) -> anyhow::Result<Option<(DatEntry, Vec<String>)>> {
        tracing::debug!(
            target = "geosite",
            data_len = data.len(),
            "starting to parse V2Ray domains"
        );

        let domain = Self::read_domain(data, true)?;
        let Some(value) = domain.value else {
            return Ok(None);
        };
        let domain_value = String::from_utf8_lossy(value).into_owned();

        // 根据 V2Ray Domain.Type 创建匹配器 / Create matcher based on V2Ray Domain.Type
        let entry = match domain.kind {
            0 => DatEntry::Matcher(DomainMatcher::Keyword(domain_value)), // Plain
            1 => DatEntry::Regex(domain_value),                           // Regex
            2 => {
                // RootDomain - 转换为 Suffix 匹配器 / Convert to Suffix matcher
                DatEntry::Matcher(DomainMatcher::Suffix(format!(".{}", domain_value)))
            }
            3 => DatEntry::Matcher(DomainMatcher::Full(domain_value)), // Full
            kind => {
                warn!(target = "geosite", type = kind,
                     "unknown V2Ray domain type, using full matcher");
                DatEntry::Matcher(DomainMatcher::Full(domain_value))
            }
        };

        tracing::debug!(target = "geosite", "parsed V2Ray domains");

        Ok(Some((entry, domain.attrs)))
    }

    /// 从 V2Ray 格式字符串加载 GeoSite 数据 / Load GeoSite data from V2Ray format string
    ///
    /// # 参数 / Parameters
    /// - `json_str`: JSON 字符串 / JSON string
    ///
    /// # 返回 / Returns
    /// 返回加载的条目数量 / Returns the number of loaded entries
    ///
    /// # 错误 / Errors
    /// 如果 JSON 格式错误，返回错误 / Returns error if JSON format is invalid
    pub fn load_from_v2ray_string(&mut self, json_str: &str) -> anyhow::Result<usize> {
        let v2ray_data: V2RayGeoSiteList =
            serde_json::from_str(json_str).with_context(|| "parse V2Ray GeoSite JSON format")?;

        let count = v2ray_data.entries.len();

        let entries = Self::convert_v2ray_to_entries(v2ray_data);

        // 逐个添加条目，保留现有数据 / Add entries one by one, preserving existing data
        for entry in entries {
            self.add_entry(entry);
        }

        self.log_totals();

        Ok(count)
    }

    /// 转换 V2Ray 格式为 GeoSiteEntry 列表 / Convert V2Ray format to GeoSiteEntry list
    ///
    /// 写法与 V2Ray 一致：`domain:` 和不带前缀的值匹配域名本身及其所有子域名，`full:` 只匹配域名本身，
    /// `keyword:` 按关键词、`regexp:` 按正则匹配；不带前缀且含 `*` 的值按通配符转成正则。
    /// 前缀不认识、没有值或正则无效的条目会跳过并告警，不再留下永远匹配不到（空值则匹配一切）的条目。
    /// Entries are written as in V2Ray: `domain:` and unprefixed values match the domain and every
    /// subdomain, `full:` the domain only, `keyword:` a keyword and `regexp:` a regular expression; an
    /// unprefixed value containing `*` becomes a wildcard regex. An entry with an unknown prefix, no
    /// value or an invalid regex is skipped with a warning, instead of staying as an entry that never
    /// matches (or, when empty, matches everything).
    fn convert_v2ray_to_entries(v2ray_data: V2RayGeoSiteList) -> Vec<GeoSiteEntry> {
        v2ray_data
            .entries
            .into_iter()
            .map(|v2ray_entry| {
                // 分类名转小写，和 .dat 一样：查找时按小写查 / Tags are lower-cased, as for .dat:
                // lookups use the lower-cased tag
                let tag = v2ray_entry.tag.to_ascii_lowercase();
                let mut skipped = 0usize;
                let mut first_skipped = None;
                let matchers = v2ray_entry
                    .domains
                    .into_iter()
                    .filter_map(|domain| {
                        let matcher = Self::v2ray_json_matcher(&domain);
                        if matcher.is_none() {
                            skipped += 1;
                            first_skipped.get_or_insert(domain);
                        }
                        matcher
                    })
                    .collect();
                if let Some(example) = first_skipped {
                    warn!(
                        target = "geosite",
                        tag = %tag,
                        skipped,
                        example = %example,
                        "skipped GeoSite JSON entries that cannot match: unknown prefix, no value or invalid regex"
                    );
                }

                GeoSiteEntry { tag, matchers }
            })
            .collect()
    }

    /// 一条 V2Ray JSON 域名对应的匹配器；前缀不认识、没有值或正则无效时为 `None`。
    /// 通配符在转成正则之前转小写：其余的值由 `GeoSiteEntry::normalized` 转，正则它转不了。
    /// The matcher for one V2Ray JSON domain entry; `None` for an unknown prefix, no value or an
    /// invalid regex. A wildcard is lower-cased before it becomes a regex: `GeoSiteEntry::normalized`
    /// lower-cases the other values but cannot reach into a regex.
    fn v2ray_json_matcher(entry: &str) -> Option<DomainMatcher> {
        let (prefix, value) = match entry.split_once(':') {
            Some((prefix, value)) => (Some(prefix), value),
            None => (None, entry),
        };
        if value.is_empty() {
            return None;
        }
        let build_regex = |pattern: &str| {
            compile_geosite_regex(pattern)
                .ok()
                .map(DomainMatcher::Regex)
        };
        match prefix {
            Some("domain") => Some(DomainMatcher::Suffix(value.to_string())),
            Some("full") => Some(DomainMatcher::Full(value.to_string())),
            Some("keyword") => Some(DomainMatcher::Keyword(value.to_string())),
            Some("regexp") => build_regex(value),
            Some(_) => None,
            None if value.contains('*') => {
                let pattern = value
                    .to_ascii_lowercase()
                    .replace('.', r"\.")
                    .replace('*', ".*");
                build_regex(&format!("^{}$", pattern))
            }
            None => Some(DomainMatcher::Suffix(value.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        manager.load_from_dat_file(&path).unwrap();
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
        manager.load_from_dat_file(&path).unwrap();
        assert!(manager.matches("g", "www.google.com"));
        assert!(manager.matches("g", "only.test"));
    }

    /// 数据文件里的正则读完一个 tag 才合成编译；写错的一条照旧换成只匹配空名字的正则，不连累同一个 tag
    /// 的其他正则。按需加载和全部加载都是这样。
    /// A data file's regexes compile once the tag is read; one written wrong still stands as a
    /// regex matching only the empty name and spoils none of the tag's others. Both selective and
    /// full loading do so.
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
        assert!(matches!(tag.regexes, Regexes::Sets(_)));
        assert!(tag.matches("cdn7.example.com"));
        assert!(tag.matches("a.test"));
        assert!(tag.matches(""));
        assert!(!tag.matches("cdnx.example.com"));

        let mut manager = GeoSiteManager::new();
        manager.load_from_dat_file(&path).unwrap();
        assert!(manager.matches("r", "cdn7.example.com"));
        assert!(!manager.matches("r", "b.test"));
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
        manager.load_from_dat_file(&path).unwrap();
        assert!(manager.matches("ads", "www.doubleclick.net"));

        write_dat(
            &dir,
            &[build_geosite("CN", &[build_domain(2, "qq.com", &[])])],
        );
        manager.load_from_dat_file(&path).unwrap();

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
        manager.load_from_dat_file(&path).unwrap();

        // One good entry followed by an unterminated varint.
        let mut corrupt =
            build_dat(&[build_geosite("NEW", &[build_domain(2, "new.example", &[])])]);
        corrupt.extend_from_slice(&[0x0A, 0xFF]);
        std::fs::write(&path, corrupt).unwrap();

        manager
            .load_from_dat_file(&path)
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
        manager.load_from_dat_file(&indirect).unwrap();
        assert!(manager.matches("ads", "www.doubleclick.net"));

        write_dat(
            &dir,
            &[build_geosite("CN", &[build_domain(2, "qq.com", &[])])],
        );
        manager.load_from_dat_file(&absolute).unwrap();

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
        manager.load_from_dat_file(&a).unwrap();
        manager.load_from_dat_file(&b).unwrap();

        // a.dat 去掉 ads，b.dat 原封不动 / ads leaves a.dat, b.dat is untouched
        std::fs::write(
            &a,
            build_dat(&[build_geosite(
                "ONLY-A",
                &[build_domain(2, "only-a.example", &[])],
            )]),
        )
        .unwrap();
        manager.load_from_dat_file(&a).unwrap();

        assert!(
            manager.has_tag("ads"),
            "a tag another file still provides must survive"
        );
        assert!(manager.matches("only-a", "www.only-a.example"));
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
        manager.load_from_dat_file(&a).unwrap();
        // b.dat 后加载，此刻 ads 命中的是 b.dat 的数据
        // b.dat loads last, so ads matches b.dat's data at this point
        manager.load_from_dat_file(&b).unwrap();
        assert!(manager.matches("ads", "www.ads.example"));

        // b.dat 去掉 ads，只剩 a.dat 在提供 / ads leaves b.dat, only a.dat provides it
        std::fs::write(&b, build_dat(&[])).unwrap();
        manager.load_from_dat_file(&b).unwrap();

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
        manager.load_from_dat_file(&a).unwrap();
        manager.load_from_dat_file(&b).unwrap();
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
        manager.load_from_dat_file(&b).unwrap();

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

    /// 不点名 tag 时（`parse_file` 拿到空的 tags），读出的标签和条目与完整解析器对同一份数据读出的一致：
    /// 标签的名字和先后、每个标签里的条目、匹配的结果。数据里有重复的 tag、空 tag、只有空值的 tag、
    /// 域名写在 tag 前面的条目，还有一个不是 GeoSite 条目的外层字段
    /// With no tag named (`parse_file` given empty tags), the tags and entries read agree
    /// with what the full parser reads from the same data: the tag names and their
    /// order, each tag's entries, and what they match. The data has a repeated tag, an
    /// empty tag, a tag of only valueless entries, an entry with its domains before its
    /// tag, and an outer field that is no GeoSite entry
    #[test]
    fn every_tag_parsing_reads_what_the_full_parser_reads() {
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
        let full = GeoSiteManager::parse_dat_file(&path).unwrap();
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

    /// Domain 和 Attribute 消息里不认识的字段按线上类型跳过（varint、8 字节、4 字节、带长度），之后的
    /// 字段照常读出；跳过的部分越出消息、或者线上类型不认识时，Domain 读不出，Attribute 没有 key
    /// Unknown fields in Domain and Attribute messages are skipped by wire type (varint,
    /// 8 bytes, 4 bytes, length-delimited) and the fields after them read as usual; when
    /// the skipped part runs past the message, or the wire type is unknown, the Domain
    /// cannot be read and the Attribute has no key
    #[test]
    fn unknown_fields_are_skipped_by_their_wire_type() {
        let mut unknown = vec![(4 << 3), 0x96, 0x01];
        unknown.extend([(5 << 3) | 1, 1, 2, 3, 4, 5, 6, 7, 8]);
        unknown.extend([(6 << 3) | 5, 1, 2, 3, 4]);
        unknown.extend(encode_ld(7, b"skip me"));

        let mut domain = unknown.clone();
        domain.extend(build_domain(3, "a.example", &["cn"]));
        let read = GeoSiteManager::read_domain(&domain, true).unwrap();
        assert_eq!(read.kind, 3);
        assert_eq!(read.value, Some(&b"a.example"[..]));
        assert_eq!(read.attrs, ["cn"]);

        let mut attribute = unknown.clone();
        attribute.extend(encode_str(1, "Ads"));
        assert_eq!(parse_attribute_key(&attribute).as_deref(), Some("ads"));

        for cut in [
            vec![(5 << 3) | 1, 1, 2, 3],
            vec![(6 << 3) | 5, 1, 2],
            vec![(7 << 3) | 2, 9, 1, 2],
            vec![(4 << 3) | 3, 1],
        ] {
            assert!(GeoSiteManager::read_domain(&cut, true).is_err(), "{cut:?}");
            assert_eq!(parse_attribute_key(&cut), None, "{cut:?}");
        }

        // 线上类型 3（已废弃的 group）不认识：后面的字段即使完好也不读 / Wire type 3 (the
        // deprecated group) is not known: the fields after it are not read even when whole
        let mut domain = vec![(4 << 3) | 3];
        domain.extend(build_domain(3, "a.example", &[]));
        assert!(GeoSiteManager::read_domain(&domain, true).is_err());
        let mut attribute = vec![(4 << 3) | 3];
        attribute.extend(encode_str(1, "ads"));
        assert_eq!(parse_attribute_key(&attribute), None);
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

    /// 文件里读出的长度大到「位置 + 长度」溢出时（u64::MAX，或者刚好回绕到 0）：外层条目的长度让整份
    /// 文件被拒绝；条目里某个字段的长度让这个条目到此为止，和别的越出条目的字段一样；Domain、
    /// Attribute 消息里的长度让它读不出。都不 panic、不原地打转。按需、全部和完整三种解析都验。
    /// 只有损坏或特意构造的数据文件会碰到
    /// A length read from the file so large that position plus length overflows (u64::MAX,
    /// or one that wraps to exactly 0): an outer entry's length gets the whole file
    /// refused; a field's length inside an entry ends that entry there, like any other
    /// field running past its entry; a length inside a Domain or Attribute message leaves
    /// it unreadable. None panics or goes round in circles. Selective, every-tag and full
    /// parsing are all checked. Only a broken or deliberately crafted data file gets here
    #[test]
    fn a_length_that_overflows_the_position_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let good = build_geosite("CN", &[build_domain(3, "good.example", &[])]);
        // 长度 varint 之后的位置是 11（1 字节字段头加 10 字节 varint），所以 2^64 - 11 刚好回绕到 0
        // The position after the length varint is 11 (a 1-byte key and a 10-byte varint),
        // so 2^64 - 11 wraps to exactly 0
        for huge in [usize::MAX, usize::MAX - 10] {
            for before in [Vec::new(), encode_ld(1, &good)] {
                let mut data = before.clone();
                data.push(0x0A);
                data.extend(encode_varint(huge));
                let path = dir.path().join("outer.dat");
                std::fs::write(&path, data).unwrap();
                let tags = vec!["cn".to_string()];
                for every in [false, true] {
                    let (path, tags) = (path.clone(), tags.clone());
                    let parsed = within_five_seconds(move || {
                        if every {
                            GeoSiteManager::parse_file(&path, &[]).map(|_| ())
                        } else {
                            GeoSiteManager::parse_dat_file_selective(&path, &tags).map(|_| ())
                        }
                    });
                    assert!(parsed.is_err(), "outer {huge}, every tag {every}");
                }
                let full =
                    within_five_seconds(move || GeoSiteManager::parse_dat_file(&path).map(|_| ()));
                assert!(full.is_err(), "outer {huge}, full");
            }

            // 条目里的字段：放在 tag 前面时整个条目不要，放在一条好域名后面时只留下那条
            // A field inside an entry: before the tag it drops the whole entry, after a good
            // domain only that domain stays
            let mut bad_field = vec![0x12];
            bad_field.extend(encode_varint(huge));
            let mut tag_first = encode_str(1, "CN");
            tag_first.extend(encode_ld(2, &build_domain(3, "good.example", &[])));
            tag_first.extend(&bad_field);
            let mut field_first = bad_field.clone();
            field_first.extend(encode_str(1, "CN"));
            for (entry, kept) in [(tag_first, true), (field_first, false)] {
                let path = dir.path().join("inner.dat");
                std::fs::write(&path, build_dat(&[entry])).unwrap();
                let tags = vec!["cn".to_string()];
                let (selective, every, full) = within_five_seconds(move || {
                    let found = |parsed: anyhow::Result<ParsedGeoSite>| {
                        parsed
                            .unwrap()
                            .iter()
                            .any(|(tag, matchers)| tag == "cn" && matchers.matches("good.example"))
                    };
                    (
                        found(GeoSiteManager::parse_dat_file_selective(&path, &tags)),
                        found(GeoSiteManager::parse_file(&path, &[])),
                        found(GeoSiteManager::parse_dat_file(&path)),
                    )
                });
                assert_eq!(
                    [selective, every, full],
                    [kept; 3],
                    "inner {huge}, kept {kept}"
                );
            }

            // Domain、Attribute 消息里的值、属性和未知字段 / Values, attributes and unknown
            // fields in Domain and Attribute messages
            for key in [(2 << 3) | 2, (3 << 3) | 2, (7 << 3) | 2] {
                let mut message = vec![key];
                message.extend(encode_varint(huge));
                assert!(
                    within_five_seconds({
                        let message = message.clone();
                        move || GeoSiteManager::read_domain(&message, true).is_err()
                    }),
                    "domain field {key:#x}, {huge}"
                );
            }
            for key in [(1 << 3) | 2, (7 << 3) | 2] {
                let mut message = vec![key];
                message.extend(encode_varint(huge));
                assert_eq!(
                    within_five_seconds(move || parse_attribute_key(&message)),
                    None,
                    "attribute field {key:#x}, {huge}"
                );
            }
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
        manager.load_from_dat_file(&path).unwrap();

        // 只写出前半段，模拟覆盖写到一半 / Write only the first half
        let full = std::fs::read(&path).unwrap();
        std::fs::write(&path, &full[..full.len() * 2 / 3]).unwrap();
        manager
            .load_from_dat_file(&path)
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
    fn test_split_tag_attr() {
        assert_eq!(split_tag_attr("category-games"), ("category-games", None));
        assert_eq!(
            split_tag_attr("category-games@cn"),
            ("category-games", Some("cn"))
        );
        assert_eq!(
            split_tag_attr("category-games@!cn"),
            ("category-games", Some("!cn"))
        );
        // Edge: empty parts → no split
        assert_eq!(split_tag_attr("tag@"), ("tag@", None));
        assert_eq!(split_tag_attr("@cn"), ("@cn", None));
    }

    #[test]
    fn test_attr_filter_matches() {
        let cn = vec!["cn".to_string()];
        assert!(attr_filter_matches(&cn, "cn"));
        assert!(!attr_filter_matches(&[], "cn"));
        // `!cn` is the literal key, as in V2Ray: neither `cn` nor no attribute
        assert!(!attr_filter_matches(&cn, "!cn"));
        assert!(!attr_filter_matches(&[], "!cn"));
        assert!(attr_filter_matches(&["!cn".to_string()], "!cn"));
        assert!(!attr_filter_matches(&["!cn".to_string()], "cn"));
        // case insensitive
        assert!(attr_filter_matches(&["CN".to_string()], "cn"));
        assert!(attr_filter_matches(&["!CN".to_string()], "!cn"));
    }

    #[test]
    fn test_parse_attribute_key() {
        // Attribute { key = "cn" }
        let attr = encode_str(1, "cn");
        assert_eq!(parse_attribute_key(&attr), Some("cn".to_string()));

        // Attribute with extra fields (bool_value)
        let mut attr = encode_str(1, "geolocation");
        attr.extend(encode_varint_field(2, 1)); // bool_value = true
        assert_eq!(parse_attribute_key(&attr), Some("geolocation".to_string()));

        // Empty message
        assert_eq!(parse_attribute_key(&[]), None);
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
        let parsed = GeoSiteManager::parse_json_file(&path).unwrap();
        from_file.apply_source(&path, parsed);
        assert_v2ray_json_entries(&from_file);
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
        manager.load_from_dat_file(&path).unwrap();
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

    /// JSON 的分类名和 .dat 一样不区分大小写；原来写成大写的分类永远查不到。
    /// JSON tags ignore case as .dat tags do; a tag written in capitals used to be unreachable.
    #[test]
    fn json_tags_ignore_case() {
        let json = r#"{"entries":[{"tag":"Ads","domains":["ads.example"]}]}"#;
        let mut from_string = GeoSiteManager::new();
        from_string.load_from_v2ray_string(json).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("geosite.json");
        std::fs::write(&path, json).unwrap();
        let mut from_file = GeoSiteManager::new();
        let parsed = GeoSiteManager::parse_json_file(&path).unwrap();
        from_file.apply_source(&path, parsed);
        for manager in [&from_string, &from_file] {
            assert!(manager.matches("ads", "ads.example"));
            assert!(manager.matches("ADS", "ads.example"));
            assert!(manager.matches("Ads", "ads.example"));
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
            let indexed = TagMatchers::new(matchers.clone());
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

    /// GeoSite 正则里的 `\w`、`\d`、`\s`、`\b` 按 Go（v2ray）的 ASCII 含义改写，字符类里外各有写法，别的转义
    /// 和转义的反斜杠不动
    /// `\w`, `\d`, `\s` and `\b` in GeoSite regexes take their Go (v2ray) ASCII meaning, written
    /// one way outside a class and another inside, while other escapes and escaped backslashes
    /// stay
    #[test]
    fn geosite_regex_classes_are_rewritten_the_go_way() {
        for (pattern, rewritten) in [
            (r"cdn\d-x", r"cdn[0-9]-x"),
            (r"^\w{5}\.com$", r"^[0-9A-Za-z_]{5}\.com$"),
            (r"a\Sb\Dc\Wd", r"a[^\t\n\f\r ]b[^0-9]c[^0-9A-Za-z_]d"),
            (r"[\w-]+", r"[0-9A-Za-z_-]+"),
            (r"[^\d.]", r"[^0-9.]"),
            (r"[a\W]", r"[a[^0-9A-Za-z_]]"),
            (r"[]\d]", r"[]0-9]"),
            (r"[[:alpha:]\d]x\d", r"[[:alpha:]0-9]x[0-9]"),
            (r"\bfoo\B", r"(?-u:\b)foo(?-u:\B)"),
            (r"\\d", r"\\d"),
            (r"\p{L}\.\[\d\]", r"\p{L}\.\[[0-9]\]"),
        ] {
            assert_eq!(go_classes(pattern), rewritten, "{pattern}");
        }
        assert!(matches!(
            go_classes(r"plain\.com$"),
            std::borrow::Cow::Borrowed(_)
        ));

        // 只含 ASCII 的名字结果和按 Unicode 编译时相同，`\w` 不认非 ASCII 字母，和 v2ray 一样
        // Names of ASCII alone match as compiled for Unicode, and `\w` takes no non-ASCII letter,
        // as in v2ray
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
        assert!(compile_geosite_regex("(unclosed").is_err());
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
        let indexed = TagMatchers::new(vec![
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
        let indexed = TagMatchers::new(vec![
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

    /// 多条正则合成一组以后，命中与否和逐条比较完全一样；合不成时退回逐条比较，结果也一样
    /// Combined into one set, regexes match exactly as they do one by one; when they cannot be
    /// combined they fall back to one by one, with the same results
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
        let written = || patterns.iter().map(|p| p.to_string()).collect::<Vec<_>>();
        let combined = Regexes::new(written());
        assert!(
            matches!(&combined, Regexes::Sets(sets) if sets.len() == 1),
            "several regexes combine into one set"
        );
        let separate = Regexes::with_size_limit(written(), 1);
        assert!(
            matches!(separate, Regexes::Each(_)),
            "over the size limit they stay one by one"
        );
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
            assert_eq!(combined.is_match(domain), expected, "set: {domain:?}");
            assert_eq!(
                separate.is_match(domain),
                expected,
                "one by one: {domain:?}"
            );
        }
        assert_eq!(combined.len(), patterns.len());
        let listed: Vec<String> = combined
            .to_regexes()
            .iter()
            .map(|regex| regex.as_str().to_owned())
            .collect();
        assert_eq!(listed, patterns);
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
        assert!(
            matches!(&regexes, Regexes::Sets(sets) if sets.len() == 3),
            "{count} regexes make three groups"
        );
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
        manager.load_from_dat_file(&path).unwrap();
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
        assert!(GeoSiteManager::parse_dat_file(&path).is_err());
        assert!(GeoSiteManager::parse_dat_file_selective(&path, &["x".to_string()]).is_err());
    }
}
