pub mod advanced_rule;
mod dat_reader;
pub mod geoip;
pub mod geoip_converter;
mod geoip_proto;
pub mod geosite;
mod pattern;
mod requester;
mod response;

use pattern::*;
pub(crate) use pattern::{capitals_warning, regex_within};
use requester::*;
pub use requester::{Requester, RequesterKey, RequesterScope, RequesterTest};
pub use response::{RuntimeResponseMatcher, RuntimeResponseMatcherWithOp};

use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::Context;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{DNSClass, RecordType};
use ipnet::IpNet;
use regex::{Regex, RegexBuilder};
use rustc_hash::FxHashMap;

use crate::config::{self, Action, MatchOperator, PipelineConfig};

// ============================================================================
// TXT Match Mode / TXT 匹配模式
// ============================================================================

/// TXT 匹配模式 / TXT match mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxtMatchMode {
    /// 精确匹配 / Exact match
    Exact,
    /// 前缀匹配 / Prefix match
    Prefix,
    /// 正则匹配 / Regex match
    Regex,
}

impl TxtMatchMode {
    /// 从字符串解析匹配模式 / Parse match mode from string
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> anyhow::Result<Self> {
        match s.to_lowercase().as_str() {
            "exact" => Ok(TxtMatchMode::Exact),
            "prefix" => Ok(TxtMatchMode::Prefix),
            "regex" => Ok(TxtMatchMode::Regex),
            _ => anyhow::bail!(
                "invalid TXT match mode: {}, must be one of: exact, prefix, regex",
                s
            ),
        }
    }
}

// ============================================================================
// Domain Suffix / 域名后缀
// ============================================================================

/// 配置里写的域名值，按名字文本的写法存（见 `proto_utils::name_text`）：转小写，去掉结尾的点。
/// 名字文本不带结尾的点，写了点的值以前永远匹配不上。单独一个点是根，名字文本是空的
/// A domain value from the configuration, kept the way name text is written (see
/// `proto_utils::name_text`): lowercased, without the trailing dot. Name text carries no
/// trailing dot, so a value written with one used to match nothing. A lone dot is the root,
/// whose name text is empty
pub(crate) fn domain_value(value: &str) -> Arc<str> {
    let value = value.to_ascii_lowercase();
    Arc::from(value.strip_suffix('.').unwrap_or(&value))
}

/// 规则写的 GeoSite 标签，转成小写存：数据文件里的标签读进来就转小写（见 `geosite`），在这里转一次，每个查询就不用
/// 再转，写法不同的同一个标签也只算一个（见 [`RuntimePipelineConfig::geosite_tags`]），不会各读一遍数据、各建一份匹配器
/// A GeoSite tag a rule writes, kept lowercased: the tags of data files are lowercased as they
/// are read (see `geosite`), so lowering it once here spares every query doing it, and one tag
/// written in different cases counts once (see [`RuntimePipelineConfig::geosite_tags`]) instead of
/// being read from the data and given matchers once for each spelling
pub(crate) fn geosite_tag(value: &str) -> Arc<str> {
    Arc::from(value.to_ascii_lowercase())
}

/// 域名后缀按点分段比较：`example.com` 命中它本身和每个子域名，`.example.com` 只命中子域名，
/// `notexample.com` 两种都不命中。请求名在解析时已转小写、不带结尾的点，配置值在加载时已转小写。
/// 规则、Pipeline 入口和响应阶段的 `request_domain_suffix` 都用这一个比较，按索引查到的候选和逐条检查的规则结果一致。
///
/// Domain suffixes compare label by label: `example.com` matches itself and every subdomain,
/// `.example.com` subdomains only, and `notexample.com` matches neither. The query name is lowercased
/// without a trailing dot when parsed, and the configured value is lowercased when loaded. Rules,
/// pipeline selectors and the response-phase `request_domain_suffix` all use this one comparison, so a
/// rule found through an index and a rule checked one by one agree.
#[inline]
pub(crate) fn domain_suffix_matches(qname: &str, suffix: &str) -> bool {
    if suffix.is_empty() || suffix.starts_with('.') {
        return qname.ends_with(suffix);
    }
    qname
        .strip_suffix(suffix)
        .is_some_and(|head| head.is_empty() || head.ends_with('.'))
}

/// 后缀索引的键：查找时从整个请求名开始，每次去掉最左边一段，所以键里不带开头的点。
/// 带点的值（只命中子域名）同样能被查到，是否命中本身交给 [`domain_suffix_matches`]。
///
/// The suffix index key. A lookup starts from the whole query name and drops the leftmost label each
/// step, so a key carries no leading dot. A dotted value (subdomains only) is found the same way, and
/// [`domain_suffix_matches`] then decides whether the name itself counts.
#[inline]
pub(crate) fn domain_suffix_index_key(suffix: &str) -> &str {
    suffix.strip_prefix('.').unwrap_or(suffix)
}

// ============================================================================
// Matcher Helper Functions / 匹配器辅助函数
// ============================================================================

/// GeoIP/GeoSite 匹配器辅助函数 / Helper functions for GeoIP/GeoSite matchers
///
/// 这些函数提供可复用的匹配逻辑，避免在多个匹配器中重复代码。
/// These functions provide reusable matching logic to avoid duplication across multiple matchers.
mod matcher_helpers {
    use super::*;

    fn svc_param_ips_match<F>(
        svc_params: &[(
            hickory_proto::rr::rdata::svcb::SvcParamKey,
            hickory_proto::rr::rdata::svcb::SvcParamValue,
        )],
        has_ip: &mut bool,
        predicate: &mut F,
    ) -> bool
    where
        F: FnMut(IpAddr) -> bool,
    {
        use hickory_proto::rr::rdata::svcb::SvcParamValue;

        let mut has_hint = false;
        let mut matched = false;
        for (_, value) in svc_params {
            match value {
                SvcParamValue::Ipv4Hint(hints) => {
                    for hint in &hints.0 {
                        has_hint = true;
                        matched |= predicate(IpAddr::V4(hint.0));
                    }
                }
                SvcParamValue::Ipv6Hint(hints) => {
                    for hint in &hints.0 {
                        has_hint = true;
                        matched |= predicate(IpAddr::V6(hint.0));
                    }
                }
                _ => {}
            }
        }
        *has_ip |= has_hint;
        !has_hint || matched
    }

    /// 一条记录里的地址是否都满足 `predicate`：A/AAAA 的地址，HTTPS/SVCB 的地址提示里有一个满足就算。回答里的每个地址
    /// 都从这里过，所以 IPv4 映射形式的 IPv6 地址（`::ffff:a.b.c.d`）在这里换成它所指的 IPv4 地址：连过去连的就是那个
    /// IPv4 地址，而 `response_answer_ip`、`geoip_private`、`geoip_country` 按 IPv6 地址看它时，AAAA `::ffff:192.168.1.1`
    /// 不算内网，防重绑定的规则就这样放过了它
    /// Whether the addresses in a record all pass `predicate`: an A/AAAA's address, and for an
    /// HTTPS/SVCB one of its hints passing is enough. Every address in an answer comes through
    /// here, so an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) turns here into the IPv4 address
    /// it names: connecting to it reaches that IPv4 address, while `response_answer_ip`,
    /// `geoip_private` and `geoip_country` taking it as an IPv6 address did not count AAAA
    /// `::ffff:192.168.1.1` as a local one, and anti-rebinding rules let it through
    pub fn all_rdata_ips_match<F>(
        data: &hickory_proto::rr::RData,
        has_ip: &mut bool,
        predicate: &mut F,
    ) -> bool
    where
        F: FnMut(IpAddr) -> bool,
    {
        use hickory_proto::rr::RData;

        let predicate = &mut |ip: IpAddr| predicate(ip.to_canonical());
        match data {
            RData::A(address) => {
                *has_ip = true;
                predicate(IpAddr::V4(address.0))
            }
            RData::AAAA(address) => {
                *has_ip = true;
                predicate(IpAddr::V6(address.0))
            }
            RData::SVCB(svcb) => svc_param_ips_match(&svcb.svc_params, has_ip, predicate),
            RData::HTTPS(https) => svc_param_ips_match(&https.svc_params, has_ip, predicate),
            _ => true,
        }
    }

    pub fn rdata_has_matching_ip<F>(data: &hickory_proto::rr::RData, predicate: &mut F) -> bool
    where
        F: FnMut(IpAddr) -> bool,
    {
        let mut has_ip = false;
        all_rdata_ips_match(data, &mut has_ip, predicate) && has_ip
    }

    /// 应答里有没有满足 `predicate` 的 IP：先看 Answer 段，再看 Additional 段；HTTPS/SVCB 的地址
    /// 提示算在它们的 RDATA 里
    /// Whether any IP in the response passes `predicate`: the Answer section first,
    /// then the Additionals. HTTPS/SVCB hints are part of their RDATA.
    pub fn any_ip_matches(msg: &Message, mut predicate: impl FnMut(IpAddr) -> bool) -> bool {
        msg.answers
            .iter()
            .any(|record| rdata_has_matching_ip(&record.data, &mut predicate))
            || msg
                .additionals
                .iter()
                .any(|record| rdata_has_matching_ip(&record.data, &mut predicate))
    }
}

// ============================================================================
// Runtime Pipeline Configuration / 运行时 Pipeline 配置
// ============================================================================

#[derive(Debug, Clone)]
pub struct RuntimePipelineConfig {
    pub settings: config::GlobalSettings,
    pub pipeline_select: Vec<RuntimePipelineSelectRule>,
    pub pipelines: Vec<RuntimePipeline>,
    /// O(1) pipeline lookup index: pipeline_id -> index in pipelines / O(1) 管道查找索引：pipeline_id -> pipelines 中的索引
    pub pipeline_id_index: FxHashMap<Arc<str>, usize>,
    /// 这份配置照样加载、值得知道的写法（见 [`config::warnings`]），编译时找出来：校验的回答、配置生效时的日志和
    /// `ConfigLoaded` 都从这里拿
    /// What this configuration writes that loads all the same yet is worth knowing (see
    /// [`config::warnings`]), found as it compiles: the validation answer, the log as it takes
    /// effect and `ConfigLoaded` all take them from here
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RuntimePipeline {
    pub id: Arc<str>,
    pub rules: Vec<RuntimeRule>,
    /// 规则的索引：给出可能命中一个请求的每条规则（见 `RuleIndex::add_rule`），快速路径和完整路径都从这里找候选
    /// The rules' index, giving every rule that can match a request (see `RuleIndex::add_rule`),
    /// where the fast path and the full path both find their candidates
    pub index: advanced_rule::RuleIndex,
    /// 能当场决定的（见 [`RuntimeRule::precomputed`]）最后一条规则的位置，一条都没有时为 None。快速路径求值候选规则到
    /// 这里为止：再往后不论哪条命中都只能交给完整路径，在快速路径上求值它们（正则、GeoIP）是白算一遍
    /// Where the last rule that decides on the spot (see [`RuntimeRule::precomputed`]) is, None
    /// when there is none. The fast path evaluates candidate rules up to here: whichever matches
    /// beyond it goes to the full path anyway, and evaluating them on the fast path (a regex,
    /// GeoIP) would be work done twice
    pub last_precomputed: Option<usize>,
    /// How the answer can depend on the requester: through this pipeline's rules,
    /// the rules along the response-jump paths its answer checks start, and the
    /// pipelines its rules jump to after an answer check may have continued.
    /// Response cache, inflight and rule cache keys tell requesters apart by it.
    /// 应答如何取决于请求方：来自本 pipeline 的规则、它的回答检查开始的响应跳转路径上的
    /// 规则，以及回答检查可能 continue 之后它的规则跳到的 pipeline。响应缓存、inflight 和
    /// 规则缓存的键按它区分请求方。
    pub requester: RequesterScope,
    /// What this pipeline's own request matchers tell requesters apart by. A rule
    /// decision depends on nothing else, so the rule cache keys on it.
    /// 本 pipeline 自己的请求匹配器区分请求方的依据。规则决策只取决于它，所以规则
    /// 缓存按它区分。
    pub rule_requester: RequesterScope,
    /// 请求阶段有没有正则条件。规则缓存只给这样的 pipeline 存转发的决定：正则要一条条试，同一个名字
    /// 再来时值得省下；别的条件靠索引或几次比较就能算完，为每个新名字存一条缓存反而比重算还贵。规则直接
    /// 回应的决定和跳转不论哪个 pipeline 都存：快速路径靠前者直接回重复的拦截查询，跟着后者到目标里去查。
    /// Whether any request rule has a regex condition. The rule cache keeps forward decisions only
    /// for such pipelines: regexes are tried one by one, which is worth saving when the same name
    /// comes back, while other conditions finish with an index lookup or a few comparisons, and storing
    /// an entry for every new name costs more than computing them again. A rule's own answer and a
    /// jump are kept whatever the pipeline: the fast path answers repeated blocked queries from the
    /// former and follows the latter to look in its target.
    pub matches_regex: bool,
    /// 缓存在这个 pipeline 键下的应答和规则决定取决于哪些 Geo 数据：它自己的规则读的标签，和 [`Self::answered_through`]
    /// 里的 pipeline 的规则读的。别的请求阶段跳转拿到的应答缓存在目标的键下，跟着目标的命名空间走。其中哪个标签的数据换了，按
    /// 旧数据缓存的应答和规则决定就不能再用，这个 pipeline 换缓存命名空间；别的标签换了它不跟着换（见
    /// `EngineInner::at_geo`）
    /// Which Geo data the answers and rule decisions cached under this pipeline's keys depend
    /// on: the tags its own rules read, and those the rules of the pipelines in
    /// [`Self::answered_through`] read. The answers any other request-phase jump gets are cached
    /// under the target's keys and go with the target's namespace. Once the data of any of those tags
    /// changes, answers and rule decisions cached with the old data are no longer valid, and the
    /// pipeline moves to a new cache namespace; other tags changing leave it where it is (see
    /// `EngineInner::at_geo`)
    pub geo_data: GeoData,
    /// 经回答检查的跳转、或者回答检查可能 continue 之后规则的跳转能到达的 pipeline（在 `RuntimePipelineConfig::pipelines`
    /// 里的下标），以及从那里再跳到的：据过上游的回答以后跳过去拿到的应答缓存在这个 pipeline 的键下（见
    /// `engine::execution::Route::enter`），所以它们的配置也算进这个 pipeline 的缓存命名空间（见
    /// `engine::types::build_cache_namespaces`），它们一改，按旧配置缓存的应答就不再用
    /// The pipelines reached by an answer check's jump, or by a jump of the rules after an answer
    /// check may have continued (by index in `RuntimePipelineConfig::pipelines`), and those
    /// jumped to from there: what is got over there once an upstream's answer has been gone by is
    /// cached under this pipeline's key (see `engine::execution::Route::enter`), so their
    /// configuration goes into this pipeline's cache namespace too (see
    /// `engine::types::build_cache_namespaces`), and once they change, answers cached by the
    /// old configuration are no longer used
    pub answered_through: Vec<usize>,
}

/// 规则读的 Geo 数据：两种数据各读哪些标签（编译好的写法，排好序、不重复），由匹配器读的 Geo 数据（见 [`GeoTags`]）得出
///
/// 按客户端地址的 GeoIP 国家判断的规则不算：缓存的键带着客户端那次判断的结果（见 [`RequesterScope`]），数据换了，
/// 判断结果跟着变，查到的就是另一个条目。键和请求后面的规则按同一份数据判断（见 [`GeoManagers`]），条目里的应答
/// 正是键里那个判断结果得出的。
/// The Geo data rules read: the tags of either kind they read (as compiled, sorted, each
/// once), from the Geo data their matchers read (see [`GeoTags`])
///
/// Rules judging the client address's GeoIP country do not count: cache keys carry the
/// result of that judgement for the client (see [`RequesterScope`]), so when the data
/// changes the result changes with it and the lookup finds another entry. The key and the
/// request's later rules judge by the same data (see [`GeoManagers`]), so an entry's answer
/// is what the very judgement in its key gives.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GeoData {
    /// GeoSite 名单：请求域名在不在里面 / GeoSite lists: whether the request's name is in them
    pub site: Vec<Arc<str>>,
    /// GeoIP 网段：回答里的地址在不在里面 / GeoIP networks: whether the addresses in the answer are in them
    pub ip: Vec<Arc<str>>,
}

impl GeoData {
    /// 一个标签都不读 / Reading no tag at all
    pub fn is_empty(&self) -> bool {
        self.site.is_empty() && self.ip.is_empty()
    }

    /// 加上一个匹配器读的 / With what one matcher reads added
    fn add(&mut self, tags: GeoTags<'_>) {
        let (into, tags) = match tags {
            GeoTags::Site(tag) => (&mut self.site, std::slice::from_ref(tag)),
            GeoTags::Ip(tags) => (&mut self.ip, tags),
        };
        for tag in tags {
            if let Err(place) = into.binary_search(tag) {
                into.insert(place, Arc::clone(tag));
            }
        }
    }

    /// 加上 `other` 读的 / With what `other` reads added
    fn extend(&mut self, other: &Self) {
        for tag in &other.site {
            self.add(GeoTags::Site(tag));
        }
        self.add(GeoTags::Ip(&other.ip));
    }
}

/// 一个匹配器读的 Geo 数据：GeoSite 的一个标签，或者 GeoIP 的一组国家代码和标签（都已是规则里编译好的写法，见
/// [`geosite_tag`] 和 `normalize_geoip_country_codes`）。要不要哪份数据、加载哪些标签、规则读了哪些 Geo 数据都由它得出
/// The Geo data a matcher reads: one GeoSite tag, or a set of GeoIP country codes and tags
/// (each as the rule compiled it, see [`geosite_tag`] and `normalize_geoip_country_codes`).
/// Whether either data is needed, which tags are loaded and which Geo data rules read all
/// follow from it
#[derive(Debug, Clone, Copy)]
pub enum GeoTags<'a> {
    Site(&'a Arc<str>),
    Ip(&'a [Arc<str>]),
}

impl<'a> GeoTags<'a> {
    /// GeoSite 的标签 / The GeoSite tag
    pub fn site(self) -> Option<&'a Arc<str>> {
        match self {
            Self::Site(tag) => Some(tag),
            Self::Ip(_) => None,
        }
    }

    /// GeoIP 的国家代码和标签 / The GeoIP country codes and tags
    pub fn ip(self) -> Option<&'a [Arc<str>]> {
        match self {
            Self::Ip(codes) => Some(codes),
            Self::Site(_) => None,
        }
    }
}

/// 编译好的一条规则。规则级的运算符编译时已经定进每个匹配器的运算符里（见 [`apply_rule_operator`]），不另存
/// A compiled rule. The rule-level operators are settled into each matcher's operator as it
/// compiles (see [`apply_rule_operator`]) and not kept apart
#[derive(Debug, Clone)]
pub struct RuntimeRule {
    pub name: Arc<str>,
    /// 请求匹配器：快速路径和完整路径都按这一份、同一个判断（[`RuntimeMatcher::matches`]）求值，两条路径对规则是否命中
    /// 从不分歧
    /// The request matchers: the fast path and the full path both evaluate these, judged the
    /// same way ([`RuntimeMatcher::matches`]), so the two never disagree on whether a rule
    /// matches
    pub matchers: Vec<RuntimeMatcherWithOp>,
    pub actions: Vec<Action>,
    /// 回答检查：响应匹配器和两种结果下的动作，决策带上的就是这一份；没有响应阶段的规则为 None，决策也就什么都不用带。
    /// 以前规则另存一份响应匹配器和动作，和它一模一样
    /// The answer check, the response matchers and the actions for either result, which is
    /// what decisions carry; None for a rule without one, whose decisions then carry nothing.
    /// The rule used to keep its own copy of the response matchers and actions as well
    pub response_phase: Option<Arc<ResponsePhase>>,
    /// Pre-computed merge result for multiple Forward actions (None if <=1 Forward action).
    /// 多个 Forward action 的预计算合并结果（<=1 个 Forward 时为 None）。
    pub merged_forward: Option<config::MergedForward>,
}

impl RuntimeRule {
    /// 回答检查的响应匹配器，没有回答检查时是空的 / The answer check's response matchers, empty
    /// without one
    pub fn response_matchers(&self) -> &[RuntimeResponseMatcherWithOp] {
        ResponsePhase::parts(self.response_phase.as_deref()).0
    }

    /// 规则的全部动作：它自己的，和回答检查两种结果下的 / Every action of the rule: its own, and
    /// its answer check's for either result
    pub fn all_actions(&self) -> impl Iterator<Item = &Action> {
        let (_, on_match, on_miss) = ResponsePhase::parts(self.response_phase.as_deref());
        self.actions.iter().chain(on_match).chain(on_miss)
    }
}

/// 一条规则的响应阶段，它的决策共用一份：每次决策都复制这些匹配器和动作，每个未命中要多分配好几次
/// A rule's response phase, shared by its decisions: copying the matchers and actions into
/// each decision took several more allocations per cache miss
#[derive(Debug)]
pub struct ResponsePhase {
    pub matchers: Vec<RuntimeResponseMatcherWithOp>,
    pub on_match: Vec<Action>,
    pub on_miss: Vec<Action>,
}

impl ResponsePhase {
    /// 匹配器和两种结果下的动作；没有响应阶段时都是空的
    /// The matchers and the actions for either result, all empty without a response phase
    pub fn parts(phase: Option<&Self>) -> (&[RuntimeResponseMatcherWithOp], &[Action], &[Action]) {
        phase.map_or((&[], &[], &[]), |phase| {
            (&phase.matchers, &phase.on_match, &phase.on_miss)
        })
    }
}

#[derive(Debug, Clone)]
pub struct RuntimePipelineSelectRule {
    pub pipeline: String,
    pub matchers: Vec<RuntimePipelineSelectorMatcherWithOp>,
}

#[derive(Debug, Clone)]
pub enum RuntimeMatcher {
    Any,
    DomainExact { value: Arc<str> },
    DomainSuffix { value: Arc<str> },
    ClientIp { net: IpNet },
    DomainRegex { regex: Regex },
    GeoipCountry { country_codes: Vec<Arc<str>> },
    GeoipPrivate { expect: bool },
    Qclass { value: DNSClass },
    EdnsPresent { expect: bool },
    GeoSite { tag: Arc<str> },
    GeoSiteNot { tag: Arc<str> },
    Qtype { value: RecordType },
}

#[derive(Debug, Clone)]
pub struct RuntimeMatcherWithOp {
    pub operator: MatchOperator,
    pub matcher: RuntimeMatcher,
}

/// pipeline_select 的匹配器：监听器标签，或者和规则一样的请求匹配器，读法和判断都是同一份（见
/// [`RuntimeMatcher::matches`]）
/// A pipeline_select matcher: the listener label, or a request matcher as rules have, read and
/// judged the same way (see [`RuntimeMatcher::matches`])
#[derive(Debug, Clone)]
pub enum RuntimePipelineSelectorMatcher {
    ListenerLabel { value: Arc<str> },
    Request(RuntimeMatcher),
}

#[derive(Debug, Clone)]
pub struct RuntimePipelineSelectorMatcherWithOp {
    pub operator: MatchOperator,
    pub matcher: RuntimePipelineSelectorMatcher,
}

/// 编好的 `compiled`；编不了时为 None，`refused` 记一条开头写着它在哪（`place`）的错误
/// What `compiled` holds; None when it could not be compiled, `refused` noting an error starting
/// with where it is (`place`)
fn compiled<T>(
    refused: &mut Vec<String>,
    place: std::fmt::Arguments<'_>,
    compiled: anyhow::Result<T>,
) -> Option<T> {
    compiled
        .map_err(|err| refused.push(format!("{place}: {err:#}")))
        .ok()
}

impl RuntimePipelineConfig {
    /// 把一份配置编译成运行时的样子，转发时要用的在这里先算好，只算这一遍：几个 forward 合成的一次转发（上游读配置时就
    /// 拆好，见 `config::ForwardTarget`）。说不通的设置（见 `GlobalSettings::validate`）和编译不了的匹配器一次列全（见
    /// [`config::Problems`]），匹配器的开头写着它的位置，写成 `pipelines[0].rules[2].matchers[1]` 这样的路径，和读不懂
    /// 的键一样
    /// Compiles a configuration into its runtime form, working out here, once, what forwarding
    /// needs: the one forward several forwards merge into (the upstreams being split as the
    /// configuration is read, see `config::ForwardTarget`). Settings that make no sense (see
    /// `GlobalSettings::validate`) and matchers that cannot be compiled are listed all at once
    /// (see [`config::Problems`]), a matcher's starting with its place, a path like
    /// `pipelines[0].rules[2].matchers[1]` as for the keys not read
    pub fn from_config(mut cfg: PipelineConfig) -> Result<Self, config::Problems> {
        cfg.settings.hold_to_limits();
        let mut refused = Vec::new();
        config::Problems::gather(&mut refused, cfg.settings.validate());
        let warnings = config::warnings(&cfg);

        let mut pipelines = Vec::new();
        // What each pipeline's rules tell requesters apart by / 每个 pipeline 的规则区分请求方的依据
        let mut reads = Vec::new();
        for (i, p) in cfg.pipelines.into_iter().enumerate() {
            let mut rules = Vec::new();
            for (j, mut r) in p.rules.into_iter().enumerate() {
                // Pre-compute merged Forward upstreams for multi-Forward rules (performance optimization).
                // Eliminates per-request FxHashSet + format! + join overhead on the hot path.
                // 预计算多 Forward 规则的合并上游（性能优化）。
                // 消除热路径上每请求的 FxHashSet + format! + join 开销。
                r.compute_merged_forward();
                let mut matchers: Vec<_> = r
                    .matchers
                    .into_iter()
                    .enumerate()
                    .filter_map(|(k, m)| {
                        let matcher = RuntimeMatcher::from_config(m.matcher);
                        let place = format_args!("pipelines[{i}].rules[{j}].matchers[{k}]");
                        compiled(&mut refused, place, matcher).map(|matcher| RuntimeMatcherWithOp {
                            operator: m.operator,
                            matcher,
                        })
                    })
                    .collect();
                apply_rule_operator(&mut matchers, r.matcher_operator, |m| &mut m.operator);

                let mut response_matchers: Vec<_> = r
                    .response_matchers
                    .into_iter()
                    .enumerate()
                    .filter_map(|(k, rm)| {
                        let matcher = RuntimeResponseMatcher::from_config(rm.matcher);
                        let place =
                            format_args!("pipelines[{i}].rules[{j}].response_matchers[{k}]");
                        compiled(&mut refused, place, matcher).map(|matcher| {
                            RuntimeResponseMatcherWithOp {
                                operator: rm.operator,
                                matcher,
                            }
                        })
                    })
                    .collect();
                apply_rule_operator(&mut response_matchers, r.response_matcher_operator, |rm| {
                    &mut rm.operator
                });
                let (mut actions, mut on_match, mut on_miss) = (
                    r.actions,
                    r.response_actions_on_match,
                    r.response_actions_on_miss,
                );
                // 作答动作的静态应答先编好，每个查询不再读一遍（见 `Action::compile_answer`）/ The
                // answering actions' static answers compiled now, so no query reads them again (see
                // `Action::compile_answer`)
                for action in actions.iter_mut().chain(&mut on_match).chain(&mut on_miss) {
                    action.compile_answer();
                }
                let response_phase =
                    (!(response_matchers.is_empty() && on_match.is_empty() && on_miss.is_empty()))
                        .then(|| {
                            Arc::new(ResponsePhase {
                                matchers: response_matchers,
                                on_match,
                                on_miss,
                            })
                        });
                rules.push(RuntimeRule {
                    name: Arc::from(r.name),
                    matchers,
                    actions,
                    response_phase,
                    merged_forward: r.merged_forward,
                });
            }

            reads.push(RuleReads::of(&rules));
            let matches_regex = rules
                .iter()
                .flat_map(|rule| rule.matchers.iter())
                .any(|m| matches!(m.matcher, RuntimeMatcher::DomainRegex { .. }));
            pipelines.push(RuntimePipeline {
                id: Arc::from(p.id),
                index: advanced_rule::RuleIndex::of(&rules),
                last_precomputed: rules.iter().rposition(|rule| rule.precomputed().is_some()),
                rules,
                // Filled in below, once every pipeline is known / 所有 pipeline 都建好后在下面填入
                requester: RequesterScope::default(),
                rule_requester: RequesterScope::default(),
                matches_regex,
                // Filled in below, once every pipeline is known / 所有 pipeline 都建好后在下面填入
                geo_data: GeoData::default(),
                answered_through: Vec::new(),
            });
        }

        let mut pipeline_select = Vec::new();
        for (i, s) in cfg.pipeline_select.into_iter().enumerate() {
            let mut matchers: Vec<_> = s
                .matchers
                .into_iter()
                .enumerate()
                .filter_map(|(k, m)| {
                    let matcher = RuntimePipelineSelectorMatcher::from_config(m.matcher);
                    let place = format_args!("pipeline_select[{i}].matchers[{k}]");
                    compiled(&mut refused, place, matcher).map(|matcher| {
                        RuntimePipelineSelectorMatcherWithOp {
                            operator: m.operator,
                            matcher,
                        }
                    })
                })
                .collect();
            apply_rule_operator(&mut matchers, s.matcher_operator, |m| &mut m.operator);
            pipeline_select.push(RuntimePipelineSelectRule {
                pipeline: s.pipeline,
                matchers,
            });
        }

        config::Problems::refuse(refused)?;

        // Build O(1) pipeline id lookup index / 构建 O(1) pipeline id 查找索引
        let pipeline_id_index: FxHashMap<Arc<str>, usize> = pipelines
            .iter()
            .enumerate()
            .map(|(i, p)| (p.id.clone(), i))
            .collect();

        fill_requester_scopes(&mut pipelines, &reads, &pipeline_id_index);

        let mut runtime = Self {
            settings: cfg.settings,
            pipeline_select,
            pipelines,
            pipeline_id_index,
            warnings,
        };
        let geo = config::geo_tags_without_data(
            &runtime.settings,
            &runtime.geosite_tags(),
            &runtime.geoip_tags(),
        );
        runtime.warnings.extend(geo);
        runtime
            .warnings
            .extend(config::host_names_without_bootstrap(&runtime));
        Ok(runtime)
    }

    pub fn min_ttl(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.settings.min_ttl as u64)
    }

    /// id 为 `id` 的 pipeline / The pipeline whose id is `id`
    pub fn pipeline(&self, id: &str) -> Option<&RuntimePipeline> {
        self.pipeline_id_index
            .get(id)
            .and_then(|&idx| self.pipelines.get(idx))
    }

    pub fn upstream_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.settings.upstream_timeout_ms)
    }

    /// 规则（连同 pipeline_select 和回答检查）用到的 GeoSite 标签（已经是小写），排好序、去掉重复：数据文件只读这些标签。
    /// 写成空的不算：那样的匹配器已经算一条问题或告警（见 `config::problems`、`config::warnings`），不再算作没有数据的标签
    /// The GeoSite tags rules use (pipeline_select and answer checks included), lowercase
    /// already, sorted and deduplicated: data files are read for these tags alone. One written
    /// empty does not count: its matcher is a problem or a warning already (see
    /// `config::problems`, `config::warnings`), not one more tag without data
    pub fn geosite_tags(&self) -> Vec<String> {
        used_tags(
            self.geo_tags()
                .filter_map(GeoTags::site)
                .filter(|tag| !tag.is_empty())
                .map(std::slice::from_ref),
        )
    }

    /// 规则按 GeoIP 匹配的国家代码和命名标签（已经是大写），排好序、去掉重复；`geoip_private` 不需要 GeoIP 数据，不算在内
    /// The country codes and named tags rules match on GeoIP (uppercase already), sorted and
    /// deduplicated; `geoip_private` needs no GeoIP data and does not count
    pub fn geoip_tags(&self) -> Vec<String> {
        used_tags(self.geo_tags().filter_map(GeoTags::ip))
    }

    /// 配置里每个匹配器读的 Geo 数据：pipeline_select 的、规则的、回答检查的 / The Geo data every
    /// matcher of the configuration reads: pipeline_select's, the rules', the answer checks'
    pub fn geo_tags(&self) -> impl Iterator<Item = GeoTags<'_>> {
        let select = self
            .pipeline_select
            .iter()
            .flat_map(|rule| &rule.matchers)
            .filter_map(|m| m.matcher.geo_tags());
        let rules = self.pipelines.iter().flat_map(|pipeline| &pipeline.rules);
        let request = rules
            .clone()
            .flat_map(|rule| rule.matchers.iter())
            .filter_map(|m| m.matcher.geo_tags());
        let response = rules
            .flat_map(RuntimeRule::response_matchers)
            .filter_map(|m| m.matcher.geo_tags());
        select.chain(request).chain(response)
    }
}

/// 几组标签合起来，排好序、去掉重复 / Groups of tags put together, sorted and deduplicated
fn used_tags<'a>(groups: impl Iterator<Item = &'a [Arc<str>]>) -> Vec<String> {
    let mut tags: Vec<String> = groups.flatten().map(|tag| tag.to_string()).collect();
    tags.sort_unstable();
    tags.dedup();
    tags
}

/// 规则级的运算符：每个匹配器都还是默认的 and 时，由它替所有匹配器定运算符
/// The rule-level operator: while every matcher still has the default `and`, it sets
/// the operator of them all
fn apply_rule_operator<T>(
    matchers: &mut [T],
    rule_operator: MatchOperator,
    operator: impl Fn(&mut T) -> &mut MatchOperator,
) {
    if rule_operator != MatchOperator::And
        && matchers
            .iter_mut()
            .all(|m| *operator(m) == MatchOperator::And)
    {
        for m in matchers {
            *operator(m) = rule_operator;
        }
    }
}

fn normalize_geoip_country_codes(country_codes: Vec<String>) -> Vec<Arc<str>> {
    country_codes
        .into_iter()
        .map(|code| Arc::from(code.to_ascii_uppercase()))
        .collect()
}

/// 配置和 GeoSite 数据里的一条正则最长多少字节，在解析之前查。正则先整条解析成语法树，才只留 ASCII 的部分（见
/// [`ascii_hir`]），`\w`、`\pL` 这样的 Unicode 字符类在树里每个都是几 KB 的区间：1 MiB 的 `\w` 解析时就要 3 GB 以上的
/// 内存，16 KiB 以内不到 50 MB，用完就放掉。域名最长 253 字节，真用到的正则短得多
/// The most bytes one regex of a configuration or of GeoSite data may be written in, checked
/// before it is parsed. A regex is parsed whole into its syntax tree before it is kept to ASCII
/// (see [`ascii_hir`]), and each Unicode class such as `\w` or `\pL` is several KB of ranges
/// there: 1 MiB of `\w` took over 3 GB to parse, and within 16 KiB it stays under 50 MB, freed
/// once done. A name is at most 253 bytes and the regexes really used are far shorter
pub(crate) const MAX_REGEX_LEN: usize = 16 * 1024;

/// 逗号分隔的 CIDR 列表，空项跳过，每项按 [`canonical_net`] 读
/// A comma-separated CIDR list, empty items skipped, each read by [`canonical_net`]
fn cidr_list(cidr: &str) -> anyhow::Result<Vec<IpNet>> {
    cidr.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(canonical_net)
        .collect()
}

/// 规则里写的网段，写错时报出写的是什么。匹配器看到的地址都是规范的：双栈套接字上的 IPv4 客户端按 IPv4 地址看（见
/// engine/execution.rs 的 `client_address`），回答和作答上游里 IPv4 映射形式的地址也按它所指的 IPv4 地址看（见
/// `matcher_helpers`），所以写成 IPv4 映射形式的网段（`::ffff:a.b.c.d/n`，n 不小于 96）换成它所指的 IPv4 网段。
/// A network a rule writes, naming what was written when it is mistyped. The addresses
/// matchers see are canonical: an IPv4 client on a dual-stack socket is seen by its IPv4
/// address (see `client_address` in engine/execution.rs), and an IPv4-mapped address in an
/// answer or of the answering upstream by the IPv4 address it names (see `matcher_helpers`),
/// so a network written in the IPv4-mapped form (`::ffff:a.b.c.d/n`, n of 96 or more)
/// becomes the IPv4 network it names.
fn canonical_net(cidr: &str) -> anyhow::Result<IpNet> {
    let net: IpNet = cidr
        .parse()
        .with_context(|| format!("\"{cidr}\" is not an IP network"))?;
    if let IpNet::V6(v6) = net
        && let Some(v4) = v6.network().to_ipv4_mapped()
        && let Some(prefix) = v6.prefix_len().checked_sub(96)
        && let Ok(v4) = ipnet::Ipv4Net::new(v4, prefix)
    {
        return Ok(IpNet::V4(v4));
    }
    Ok(net)
}

impl RuntimeMatcher {
    fn from_config(m: config::Matcher) -> anyhow::Result<Self> {
        Ok(match m {
            config::Matcher::Any => RuntimeMatcher::Any,
            // 规则看不到是哪个入口收的查询 / A rule does not see which entry took the query
            config::Matcher::ListenerLabel { .. } => {
                anyhow::bail!("listener_label works in pipeline_select only")
            }
            config::Matcher::DomainSuffix { value } => RuntimeMatcher::DomainSuffix {
                value: domain_value(&value),
            },
            config::Matcher::DomainExact { value } => RuntimeMatcher::DomainExact {
                value: domain_value(&value),
            },
            config::Matcher::ClientIp { cidr } => RuntimeMatcher::ClientIp {
                net: canonical_net(&cidr)?,
            },
            config::Matcher::DomainRegex { value } => RuntimeMatcher::DomainRegex {
                regex: domain_regex(&value)?,
            },
            config::Matcher::GeoipCountry { country_codes } => RuntimeMatcher::GeoipCountry {
                country_codes: normalize_geoip_country_codes(country_codes),
            },
            config::Matcher::GeoipPrivate { expect } => RuntimeMatcher::GeoipPrivate { expect },
            config::Matcher::Qclass { value } => RuntimeMatcher::Qclass {
                value: parse_dns_class(&value)?,
            },
            config::Matcher::EdnsPresent { expect } => RuntimeMatcher::EdnsPresent { expect },
            config::Matcher::GeoSite { value } => RuntimeMatcher::GeoSite {
                tag: geosite_tag(&value),
            },
            config::Matcher::GeoSiteNot { value } => RuntimeMatcher::GeoSiteNot {
                tag: geosite_tag(&value),
            },
            config::Matcher::Qtype { value } => RuntimeMatcher::Qtype {
                value: parse_dns_type(&value)?,
            },
        })
    }

    /// 请求 `facts` 合不合这个匹配器，按 Geo 数据 `geo` 判断（见 [`GeoManagers`]）。规则、pipeline_select 和快速路径
    /// 都走这里：没有那个 GeoSite 标签的数据时 geo_site 不命中、geo_site_not 命中，没有 GeoIP 数据时 geoip_country
    /// 不命中
    /// Whether request `facts` meets this matcher, judged by the Geo data `geo` (see
    /// [`GeoManagers`]). Rules, pipeline_select and the fast path all come here: without data for
    /// the GeoSite tag geo_site does not match and geo_site_not does, and without GeoIP data
    /// geoip_country does not match
    pub fn matches(&self, facts: &RequestFacts<'_>, geo: &GeoManagers) -> bool {
        let RequestFacts {
            qname,
            qtype,
            qclass,
            client_ip,
            edns_present,
        } = *facts;
        match self {
            RuntimeMatcher::Any => true,
            RuntimeMatcher::DomainExact { value } => {
                // 完全匹配，大小写不敏感 / Exact match, case insensitive
                qname.eq_ignore_ascii_case(value)
            }
            RuntimeMatcher::DomainSuffix { value } => domain_suffix_matches(qname, value),
            RuntimeMatcher::ClientIp { net } => net.contains(&client_ip),
            RuntimeMatcher::DomainRegex { regex } => regex.is_match(qname),
            RuntimeMatcher::GeoipCountry { country_codes } => {
                geo.geoip.matches_any_tag(client_ip, country_codes)
            }
            RuntimeMatcher::GeoipPrivate { expect } => {
                crate::matcher::geoip::is_private_ip(client_ip) == *expect
            }
            RuntimeMatcher::Qclass { value } => qclass == *value,
            RuntimeMatcher::EdnsPresent { expect } => *expect == edns_present,
            RuntimeMatcher::GeoSite { tag } => geo.geosite.matches(tag, qname),
            RuntimeMatcher::GeoSiteNot { tag } => !geo.geosite.matches(tag, qname),
            RuntimeMatcher::Qtype { value } => *value == qtype,
        }
    }

    /// 读的 Geo 数据（`geoip_private` 不读）/ The Geo data it reads (`geoip_private` reads none)
    #[inline]
    pub fn geo_tags(&self) -> Option<GeoTags<'_>> {
        match self {
            RuntimeMatcher::GeoSite { tag } | RuntimeMatcher::GeoSiteNot { tag } => {
                Some(GeoTags::Site(tag))
            }
            RuntimeMatcher::GeoipCountry { country_codes } => Some(GeoTags::Ip(country_codes)),
            _ => None,
        }
    }
}

/// 请求匹配器和回答检查看的请求：名字（名字文本，见 `proto_utils::name_text`）、类型、类别、客户端地址、带不带 EDNS。
/// 每个请求只建一份：选 pipeline、求值规则、检查回答都拿它
/// The request as request matchers and answer checks see it: the name (as name text, see
/// `proto_utils::name_text`), type, class, client address, and whether it carries EDNS. Each
/// request builds one: choosing the pipeline, evaluating rules and checking answers all take it
#[derive(Debug, Clone, Copy)]
pub struct RequestFacts<'a> {
    pub qname: &'a str,
    pub qtype: RecordType,
    pub qclass: DNSClass,
    pub client_ip: IpAddr,
    pub edns_present: bool,
}

#[cfg(test)]
impl<'a> RequestFacts<'a> {
    /// 测试用：127.0.0.1 不带 EDNS 问 `qname` 的 A 记录 / For tests: 127.0.0.1 asking for the A
    /// record of `qname` without EDNS
    pub(crate) fn a_query(qname: &'a str) -> Self {
        Self {
            qname,
            qtype: RecordType::A,
            qclass: DNSClass::IN,
            client_ip: IpAddr::from([127, 0, 0, 1]),
            edns_present: false,
        }
    }
}

/// 匹配器判断时读的 Geo 数据：引擎状态里的那一份（见 `EngineInner::geo`），建好以后只读，换数据时整份换成新的。
/// 一个请求只 load 一次状态，选 pipeline、算键、求值规则、检查回答都按这同一份判断，换数据时还在路上的请求照旧按它
/// 开始时的那份，和它的缓存命名空间算的是同一份数据；匹配时不拿锁
/// The Geo data matchers read as they judge: the copy in the engine state (see
/// `EngineInner::geo`), read-only once built and replaced whole when the data changes. A
/// request loads the state once, and choosing the pipeline, working out the keys, evaluating
/// rules and checking answers all judge by this one copy: a request still on its way when the
/// data changes goes on with the copy it started with, the very data its cache namespace was
/// worked out from. Matching takes no lock
#[derive(Clone, Default)]
pub struct GeoManagers {
    pub geoip: Arc<geoip::GeoIpManager>,
    pub geosite: Arc<geosite::GeoSiteManager>,
}

impl GeoManagers {
    /// 是不是和 `other` 同一份数据（同一对管理器）/ Whether this is the very data of `other` (the
    /// same pair of managers)
    pub fn is(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.geoip, &other.geoip) && Arc::ptr_eq(&self.geosite, &other.geosite)
    }

    /// `uses` 里每个标签的数据的指纹写进 `hasher`，没有数据的写 None（见 `GeoSiteManager::fingerprint`、
    /// `GeoIpManager::fingerprint`）。缓存命名空间算上 pipeline 读的标签的（见 `EngineInner::at_geo`）：数据换了样子，
    /// 读它的 pipeline 换命名空间；换回先前的样子，就回到先前的命名空间，那里的条目都是按这份数据判断出来的（见上）
    /// Writes the fingerprint of the data of each tag of `uses` into `hasher`, None for a tag
    /// without data (see `GeoSiteManager::fingerprint` and `GeoIpManager::fingerprint`). Cache
    /// namespaces take in those of the tags a pipeline reads (see `EngineInner::at_geo`): once
    /// the data changes the pipelines reading it move namespace, and data changing back to what
    /// it was brings back the namespace of before, whose entries were all judged by that very
    /// data (see above)
    pub fn hash_data(&self, uses: &GeoData, hasher: &mut impl Hasher) {
        for tag in &uses.site {
            self.geosite.fingerprint(tag).hash(hasher);
        }
        for tag in &uses.ip {
            self.geoip.fingerprint(tag).hash(hasher);
        }
    }
}

#[cfg(test)]
impl GeoManagers {
    /// 测试用：两份都没有数据 / For tests: neither holding any data
    pub(crate) fn empty() -> &'static Self {
        static EMPTY: std::sync::LazyLock<GeoManagers> = std::sync::LazyLock::new(Default::default);
        &EMPTY
    }
}

impl RuntimePipelineSelectorMatcher {
    fn from_config(m: config::Matcher) -> anyhow::Result<Self> {
        match m {
            config::Matcher::ListenerLabel { value } => Ok(Self::ListenerLabel {
                value: Arc::from(value),
            }),
            request => RuntimeMatcher::from_config(request).map(Self::Request),
        }
    }

    /// 读的 Geo 数据 / The Geo data it reads
    #[inline]
    pub fn geo_tags(&self) -> Option<GeoTags<'_>> {
        match self {
            Self::ListenerLabel { .. } => None,
            Self::Request(matcher) => matcher.geo_tags(),
        }
    }

    /// 从 `listener_label` 来的请求 `facts` 合不合这个匹配器，请求匹配器的判断见 [`RuntimeMatcher::matches`]
    /// Whether request `facts`, come in at `listener_label`, meets this matcher, a request
    /// matcher judging as in [`RuntimeMatcher::matches`]
    #[inline]
    pub fn matches(
        &self,
        listener_label: &str,
        facts: &RequestFacts<'_>,
        geo: &GeoManagers,
    ) -> bool {
        match self {
            Self::ListenerLabel { value } => value.eq_ignore_ascii_case(listener_label),
            Self::Request(matcher) => matcher.matches(facts, geo),
        }
    }
}

/// Evaluate a left-to-right chain where each item carries its own operator. / 评估从左到右的链，其中每个项目都带有自己的运算符
/// The first item's result seeds the accumulator; empty chains default to true. / 第一个项目的结果作为累加器的种子；空链默认为 true
#[inline]
pub fn eval_match_chain<T>(
    entries: &[T],
    mut op_of: impl FnMut(&T) -> MatchOperator,
    mut pred: impl FnMut(&T) -> bool,
) -> bool {
    let mut iter = entries.iter();
    let Some(first) = iter.next() else {
        return true;
    };
    let mut acc = pred(first);
    for item in iter {
        // 前面的结果等于 `needs` 时才看这一项（否则短路），看了就取它的结果，`negate` 时取反
        // The item is looked at only when the result so far equals `needs` (otherwise
        // it short-circuits), and then gives its result, negated with `negate`
        let (needs, negate) = match op_of(item) {
            MatchOperator::And => (true, false),
            MatchOperator::Or => (false, false),
            MatchOperator::AndNot => (true, true),
            MatchOperator::OrNot => (false, true),
        };
        if acc == needs {
            acc = pred(item) != negate;
        }
    }
    acc
}

fn parse_dns_class(v: &str) -> anyhow::Result<DNSClass> {
    let upper = v.to_ascii_uppercase();
    let parsed = match upper.as_str() {
        "IN" => DNSClass::IN,
        "CH" | "CHAOS" => DNSClass::CH,
        "HS" => DNSClass::HS,
        _ => anyhow::bail!("unsupported qclass: {upper}"),
    };
    Ok(parsed)
}

/// 配置里写的 RCODE（不分大小写）：NOERROR、FORMERR、SERVFAIL、NXDOMAIN、NOTIMP、REFUSED，别的为 None
/// An RCODE as a configuration writes it (in any case): NOERROR, FORMERR, SERVFAIL, NXDOMAIN,
/// NOTIMP or REFUSED, None for anything else
pub(crate) fn parse_rcode(rcode: &str) -> Option<ResponseCode> {
    match rcode.to_ascii_uppercase().as_str() {
        "NOERROR" => Some(ResponseCode::NoError),
        "FORMERR" => Some(ResponseCode::FormErr),
        "SERVFAIL" => Some(ResponseCode::ServFail),
        "NXDOMAIN" => Some(ResponseCode::NXDomain),
        "NOTIMP" => Some(ResponseCode::NotImp),
        "REFUSED" => Some(ResponseCode::Refused),
        _ => None,
    }
}

/// `static_ip_response` 的地址：逗号分隔的 IPv4/IPv6 地址，有一个读不出来就是 None
/// The addresses of a `static_ip_response`: comma-separated IPv4/IPv6 addresses;
/// None when any of them cannot be read
pub(crate) fn static_ips(ips: &str) -> Option<Vec<IpAddr>> {
    ips.split(',').map(|ip| ip.trim().parse().ok()).collect()
}

/// `static_cname_response` 的目标域名；空的或读不出来就是 None
/// The target of a `static_cname_response`; None when empty or unreadable
pub(crate) fn static_cname_target(target: &str) -> Option<hickory_proto::rr::Name> {
    let target = target.trim();
    if target.is_empty() {
        return None;
    }
    <hickory_proto::rr::Name as std::str::FromStr>::from_str(target).ok()
}

/// `qtype`、`response_type` 写的类型：hickory 认得的名字（HTTPS、SVCB、CAA、ANY……），或者 RFC 3597 的 `TYPEnnn`。以前只认
/// 十种，「HTTPS 查询回 NODATA」这样的规则写不出来，整份配置被拒
/// The type a `qtype` or `response_type` writes: a name hickory knows (HTTPS, SVCB, CAA, ANY…),
/// or RFC 3597's `TYPEnnn`. Only ten used to be known, so a rule like "answer HTTPS queries
/// with NODATA" could not be written and the whole configuration was refused
fn parse_dns_type(v: &str) -> anyhow::Result<RecordType> {
    let upper = v.to_ascii_uppercase();
    if let Some(code) = upper
        .strip_prefix("TYPE")
        .and_then(|code| code.parse::<u16>().ok())
    {
        return Ok(RecordType::from(code));
    }
    <RecordType as std::str::FromStr>::from_str(&upper)
        .map_err(|_| anyhow::anyhow!("unsupported qtype: {upper}"))
}

#[cfg(test)]
mod dns_type_tests {
    use super::parse_dns_type;
    use hickory_proto::rr::RecordType;

    /// hickory 认得的类型名都能写，大小写不论，还能写 `TYPEnnn`；不认得的照旧是错。以前只认十种，HTTPS、SVCB 写不出来
    /// Every type name hickory knows can be written, in any case, and `TYPEnnn` too; an unknown
    /// one is still an error. Only ten used to be known, HTTPS and SVCB among those that were not
    #[test]
    fn query_types_go_by_name_or_number() {
        for (written, expected) in [
            ("HTTPS", RecordType::HTTPS),
            ("svcb", RecordType::SVCB),
            ("CAA", RecordType::CAA),
            ("ANY", RecordType::ANY),
            ("a", RecordType::A),
            ("TYPE65", RecordType::HTTPS),
            ("type4321", RecordType::Unknown(4321)),
        ] {
            assert_eq!(parse_dns_type(written).unwrap(), expected, "{written}");
        }
        assert!(parse_dns_type("HTTPSS").is_err());
        assert!(parse_dns_type("TYPE70000").is_err());
    }
}

#[cfg(test)]
mod canonical_net_tests {
    use super::canonical_net;

    #[test]
    fn an_ipv4_mapped_network_becomes_the_ipv4_network() {
        for (written, net) in [
            ("::ffff:198.51.100.0/120", "198.51.100.0/24"),
            ("::ffff:198.51.100.7/128", "198.51.100.7/32"),
            ("::ffff:0:0/96", "0.0.0.0/0"),
            ("198.51.100.0/24", "198.51.100.0/24"),
            // 不全在映射范围内的 IPv6 网段照旧 / IPv6 networks beyond the mapped range stay as they are
            ("::/0", "::/0"),
            ("::ffff:0:0/80", "::ffff:0:0/80"),
            ("2001:db8::/32", "2001:db8::/32"),
        ] {
            assert_eq!(
                canonical_net(written).unwrap(),
                net.parse::<ipnet::IpNet>().unwrap(),
                "{written}"
            );
        }
        assert!(canonical_net("not a network").is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 规则级的运算符只在每个匹配器都还是默认的 and 时才替它们定；有一个写了别的运算符，就都照各自写的。
    /// 请求规则、响应规则、pipeline 选择三处一样
    /// The rule-level operator only sets the matchers' operators while every one of them
    /// still has the default `and`; once one names another operator, each keeps its own.
    /// The same for request rules, response rules and pipeline selection
    #[test]
    fn a_rule_operator_applies_only_while_every_matcher_has_the_default() {
        use MatchOperator::{And, AndNot, Or};
        let config = |default_ops: bool| {
            let second = |kind: &str| {
                if default_ops {
                    serde_json::json!({ "type": kind, "value": "b.test" })
                } else {
                    serde_json::json!({ "type": kind, "value": "b.test", "operator": "and_not" })
                }
            };
            runtime_of(serde_json::json!({
                "settings": { "default_upstream": "127.0.0.1:9" },
                "pipeline_select": [{
                    "pipeline": "main",
                    "matcher_operator": "or",
                    "matchers": [
                        { "type": "domain_suffix", "value": "a.test" },
                        second("domain_suffix")
                    ]
                }],
                "pipelines": [{ "id": "main", "rules": [{
                    "name": "r",
                    "matcher_operator": "or",
                    "matchers": [
                        { "type": "domain_suffix", "value": "a.test" },
                        second("domain_suffix")
                    ],
                    "actions": [{ "type": "forward", "upstream": "127.0.0.1:9" }],
                    "response_matcher_operator": "or",
                    "response_matchers": [
                        { "type": "request_domain_suffix", "value": "a.test" },
                        second("request_domain_suffix")
                    ],
                    "response_actions_on_match": [{ "type": "allow" }]
                }] }]
            }))
            .expect("build runtime config")
        };
        for (default_ops, expected) in [(true, [Or, Or]), (false, [And, AndNot])] {
            let config = config(default_ops);
            let rule = &config.pipelines[0].rules[0];
            let ops = |ops: Vec<MatchOperator>| <[MatchOperator; 2]>::try_from(ops).unwrap();
            assert_eq!(
                ops(rule.matchers.iter().map(|m| m.operator).collect()),
                expected
            );
            assert_eq!(
                ops(phase(rule).matchers.iter().map(|m| m.operator).collect()),
                expected
            );
            assert_eq!(
                ops(config.pipeline_select[0]
                    .matchers
                    .iter()
                    .map(|m| m.operator)
                    .collect()),
                expected
            );
        }
    }

    /// 配置里写 "not" 就是 and_not：读进来是同一个运算符，匹配结果也一样
    /// "not" in a configuration is and_not: it reads as the same operator and matches the
    /// same
    #[test]
    fn the_not_operator_is_and_not() {
        let matched = |operator: &str| {
            let config = runtime_of(one_rule(serde_json::json!([
                { "type": "domain_suffix", "value": "example.com" },
                { "type": "domain_suffix", "value": "ads.example.com", "operator": operator }
            ])))
            .expect("build runtime config");
            let rule = &config.pipelines[0].rules[0];
            assert_eq!(
                rule.matchers[1].operator,
                MatchOperator::AndNot,
                "{operator}"
            );
            ["www.example.com", "x.ads.example.com", "other.test"].map(|qname| {
                eval_match_chain(
                    &rule.matchers,
                    |m| m.operator,
                    |m| {
                        m.matcher.matches(
                            &RequestFacts {
                                qname,
                                qtype: RecordType::A,
                                qclass: DNSClass::IN,
                                client_ip: IpAddr::from([192, 0, 2, 1]),
                                edns_present: false,
                            },
                            GeoManagers::empty(),
                        )
                    },
                )
            })
        };
        assert_eq!(matched("not"), [true, false, false]);
        assert_eq!(matched("and_not"), matched("not"));
    }

    /// 规则用到、却没配可读的数据的 Geo 标签各算一条 warnings：没写 geosite_data_paths 时的 GeoSite 标签，没写 geoip_dat_path
    /// 时 MMDB 也答不了的 GeoIP 标签；配了数据的不算。以前一个数据文件都没配时什么都不说，用它们的规则悄悄地从不按数据判断
    /// The Geo tags rules use with no data configured to read them from make one warning for
    /// each kind: GeoSite tags without geosite_data_paths, and without geoip_dat_path the GeoIP
    /// tags the MMDB cannot answer either; tags with data do not count. With no data file
    /// configured nothing used to be said, and rules using them quietly never judged by any data
    #[test]
    fn geo_tags_without_data_are_warned_about() {
        let warnings = |settings: serde_json::Value| {
            let mut all = serde_json::json!({ "default_upstream": "127.0.0.1:9" });
            all.as_object_mut()
                .unwrap()
                .extend(settings.as_object().unwrap().clone());
            runtime_of(serde_json::json!({
                "settings": all,
                "pipeline_select": [{
                    "pipeline": "main",
                    "matchers": [{ "type": "geo_site", "value": "ads" }]
                }],
                "pipelines": [{ "id": "main", "rules": [{
                    "name": "r",
                    "matchers": [{ "type": "geoip_country", "country_codes": ["CN", "cloudflare"] }],
                    "actions": [{ "type": "forward", "upstream": "127.0.0.1:9" }],
                    "response_matchers": [{ "type": "response_request_domain_geo_site_not", "value": "cn" }],
                    "response_actions_on_match": [{ "type": "allow" }]
                }] }]
            }))
            .expect("build runtime config")
            .warnings
        };
        let geosite = "settings.geosite_data_paths: empty, so the GeoSite tags ads, cn have no data to match against: geo_site never matches them and geo_site_not always does";
        assert_eq!(
            warnings(serde_json::json!({})),
            [
                geosite,
                "settings.geoip_dat_path: not set and neither is settings.geoip_db_path, so the GeoIP tags CLOUDFLARE, CN have no data to match against: geoip_country never matches them"
            ]
        );
        assert_eq!(
            warnings(serde_json::json!({ "geoip_db_path": "/data/country.mmdb" })),
            [
                geosite,
                "settings.geoip_dat_path: not set, and settings.geoip_db_path answers two-letter country codes alone, so the GeoIP tags CLOUDFLARE have no data to match against: geoip_country never matches them"
            ]
        );
        assert!(
            warnings(serde_json::json!({
                "geoip_dat_path": "/data/geoip.dat",
                "geosite_data_paths": ["/data/geosite.dat"]
            }))
            .is_empty()
        );
    }

    /// 按 JSON 建运行时配置 / A runtime configuration built from JSON
    fn runtime_of(raw: serde_json::Value) -> Result<RuntimePipelineConfig, config::Problems> {
        RuntimePipelineConfig::from_config(serde_json::from_value(raw).expect("parse config"))
    }

    /// 规则按 GeoIP 匹配的标签算上 pipeline_select 的，`geoip_private` 不读 GeoIP 数据，不算
    /// The tags rules match on GeoIP count pipeline_select's, and `geoip_private`, reading no
    /// GeoIP data, does not count
    #[test]
    fn geoip_tags_cover_selectors_but_not_private_matchers() {
        let selector = runtime_of(serde_json::json!({
            "pipeline_select": [{
                "pipeline": "default",
                "matchers": [{ "type": "geoip_country", "country_codes": ["CN"] }]
            }],
            "pipelines": [{ "id": "default" }]
        }))
        .unwrap();
        assert_eq!(selector.geoip_tags(), ["CN"]);

        let private_only = runtime_of(serde_json::json!({
            "pipelines": [{
                "id": "default",
                "rules": [{
                    "name": "private-only",
                    "matchers": [{ "type": "geoip_private", "expect": true }],
                    "response_matchers": [{
                        "type": "response_answer_ip_geoip_private",
                        "expect": true
                    }]
                }]
            }]
        }))
        .unwrap();
        assert!(private_only.geoip_tags().is_empty());
    }

    /// 只有一条规则、规则只有 `matchers` 的 pipeline / A pipeline of one rule with `matchers`
    fn one_rule(matchers: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "settings": { "default_upstream": "127.0.0.1:9" },
            "pipelines": [{ "id": "main", "rules": [{
                "name": "r",
                "matchers": matchers,
                "actions": [{ "type": "static_response", "rcode": "NXDOMAIN" }]
            }] }]
        })
    }

    /// 规则的回答检查 / The rule's answer check
    fn phase(rule: &RuntimeRule) -> &ResponsePhase {
        rule.response_phase.as_deref().expect("an answer check")
    }

    /// CIDR 列表按逗号分开，各项去掉两边的空白，空项跳过；两种响应匹配器一样
    /// A CIDR list splits on commas, each item trimmed, empty items skipped; the same
    /// for both response matchers
    #[test]
    fn a_cidr_list_trims_its_items_and_skips_empty_ones() {
        let expected: Vec<IpNet> = vec![
            "10.0.0.0/8".parse().unwrap(),
            "192.0.2.0/24".parse().unwrap(),
        ];
        for kind in ["response_answer_ip", "response_upstream_ip"] {
            let config = runtime_of(serde_json::json!({
                "settings": { "default_upstream": "127.0.0.1:9" },
                "pipelines": [{ "id": "main", "rules": [{
                    "name": "r",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "forward", "upstream": "127.0.0.1:9" }],
                    "response_matchers": [{ "type": kind, "cidr": " 10.0.0.0/8 , ,192.0.2.0/24," }],
                    "response_actions_on_match": [{ "type": "allow" }]
                }] }]
            }))
            .expect("build runtime config");
            let nets = match &phase(&config.pipelines[0].rules[0]).matchers[0].matcher {
                RuntimeResponseMatcher::ResponseAnswerIp { nets }
                | RuntimeResponseMatcher::ResponseUpstreamIp { nets } => nets.clone(),
                other => panic!("{kind}: {other:?}"),
            };
            assert_eq!(nets, expected, "{kind}");
        }
    }

    /// 三种域名正则（请求规则、pipeline 选择、响应规则）各写一条 `pattern` 的配置
    /// A configuration for each of the three domain regexes (request rules, pipeline selection,
    /// response rules), written as `pattern`
    fn domain_regex_configs(pattern: &str) -> [serde_json::Value; 3] {
        [
            one_rule(serde_json::json!([{ "type": "domain_regex", "value": pattern }])),
            serde_json::json!({
                "settings": { "default_upstream": "127.0.0.1:9" },
                "pipeline_select": [{
                    "pipeline": "main",
                    "matchers": [{ "type": "domain_regex", "value": pattern }]
                }],
                "pipelines": [{ "id": "main", "rules": [] }]
            }),
            serde_json::json!({
                "settings": { "default_upstream": "127.0.0.1:9" },
                "pipelines": [{ "id": "main", "rules": [{
                    "name": "r",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "forward", "upstream": "127.0.0.1:9" }],
                    "response_matchers": [{ "type": "request_domain_regex", "value": pattern }],
                    "response_actions_on_match": [{ "type": "allow" }]
                }] }]
            }),
        ]
    }

    /// 恰好 `len` 字节、内容寻常的域名正则：`first` 和一串名字任选其一（GeoSite 的测试也用）
    /// A domain regex of exactly `len` bytes with ordinary content: any one of `first` and a run
    /// of names (the GeoSite tests use it too)
    pub(super) fn names_regex(first: &str, len: usize) -> String {
        let mut pattern = format!("^(?:{first}");
        for i in 0..len {
            if pattern.len() + 64 > len {
                break;
            }
            pattern.push_str(&format!(r"|host{i}\.example\.com"));
        }
        // 剩下的用一个名字补足 / One more name makes up the rest
        let rest = len - pattern.len() - "|)$".len();
        pattern.push('|');
        pattern.push_str(&"x".repeat(rest));
        pattern.push_str(")$");
        assert_eq!(pattern.len(), len);
        pattern
    }

    /// 配置里的正则最长 16384 字节，在解析之前查。正则先整条解析成语法树才只留 ASCII、看编译后的大小，`\w` 在树里每个
    /// 都是几 KB 的 Unicode 区间：以前 1 MiB 的 `\w` 送去校验，要 3 GB 以上的内存。三种域名正则都是：刚好 16384 字节、
    /// 内容寻常的照常读入；长一个字节的读不进来，说明写了多长；`\w` 连写 64 KiB 报的也是太长（以前解析完才报编译超限，
    /// 要两百来 MB）。短于上限的照旧：编译超过 1 MB 的（`\w{30000}`）仍按编译的上限拒绝
    /// A configuration's regex is at most 16384 bytes, checked before it is parsed. A regex is
    /// parsed whole into its syntax tree before it is kept to ASCII and its compiled size looked
    /// at, and each `\w` is several KB of Unicode ranges there: 1 MiB of `\w` sent for
    /// validation used to take over 3 GB. So for all three domain regexes: one of exactly 16384
    /// bytes with ordinary content loads; one byte longer is refused, saying how long it is;
    /// 64 KiB of `\w` written out is refused as too long as well (it used to be parsed first,
    /// taking some two hundred MB, and then refused for its compiled size). Below the limit
    /// nothing changes: one over 1 MB compiled (`\w{30000}`) is still refused by the compiled limit
    #[test]
    fn a_regex_in_a_configuration_is_at_most_16_kib() {
        let validate = |config: serde_json::Value| crate::config::validate(&config.to_string());
        let refused = |config: serde_json::Value| format!("{:#}", validate(config).unwrap_err());
        let at_limit = names_regex(r"at-limit\.example", MAX_REGEX_LEN);
        for (which, config) in domain_regex_configs(&at_limit).into_iter().enumerate() {
            if let Err(err) = validate(config) {
                panic!("matcher {which}: {err:#}");
            }
        }
        let over = names_regex(r"over\.example", MAX_REGEX_LEN + 1);
        let written_out = r"\w".repeat(32 * 1024);
        for (which, (over, written_out)) in domain_regex_configs(&over)
            .into_iter()
            .zip(domain_regex_configs(&written_out))
            .enumerate()
        {
            let err = refused(over);
            assert!(
                err.contains("regex pattern too long: 16385 bytes (max 16384)"),
                "matcher {which}: {err}"
            );
            let err = refused(written_out);
            assert!(
                err.contains("regex pattern too long: 65536 bytes (max 16384)"),
                "matcher {which}: {err}"
            );
        }
        for (which, below) in domain_regex_configs(r"\w{30000}").into_iter().enumerate() {
            let err = refused(below);
            assert!(
                err.contains("exceeds size limit") && !err.contains("too long"),
                "matcher {which}: {err}"
            );
        }
    }

    /// 三种域名正则（请求规则、pipeline 选择、响应规则）编译时都限 1 MB：`\w{10000}` 编得出，`\w{30000}` 超出上限、配置读
    /// 不进来（默认上限下它编得出）。`\w` 只留 ASCII，一个就是一个状态
    /// The three domain regexes (request rules, pipeline selection, response rules) all compile
    /// within 1 MB: `\w{10000}` compiles, while `\w{30000}` exceeds the limit and the
    /// configuration is refused (it compiles under the default limits). `\w` kept to ASCII is
    /// one state each
    #[test]
    fn a_domain_regex_is_limited_to_a_megabyte() {
        assert!(regex::Regex::new(r"(?-u:\w){30000}").is_ok());
        let configs = domain_regex_configs;
        for (which, (small, large)) in configs(r"\w{10000}")
            .into_iter()
            .zip(configs(r"\w{30000}"))
            .enumerate()
        {
            assert!(runtime_of(small).is_ok(), "matcher {which}");
            assert!(runtime_of(large).is_err(), "matcher {which}");
        }
    }

    /// 三种域名正则各照 `pattern` 建好，拿去匹配一个名字：请求规则、pipeline 选择、响应规则各自的结果
    /// The three domain regexes built from `pattern`, matching a name: what the request rule,
    /// the pipeline selection and the response rule each say
    fn domain_regex_matchers(pattern: &str) -> impl Fn(&str) -> [bool; 3] {
        let [rule, select, response] = domain_regex_configs(pattern)
            .map(|config| runtime_of(config).unwrap_or_else(|err| panic!("{pattern}: {err:#}")));
        let message = Message::new(0, MessageType::Response, OpCode::Query);
        move |name: &str| {
            let facts = RequestFacts {
                qname: name,
                qtype: RecordType::A,
                qclass: DNSClass::IN,
                client_ip: IpAddr::from([192, 0, 2, 1]),
                edns_present: false,
            };
            let geo = GeoManagers::empty();
            [
                rule.pipelines[0].rules[0].matchers[0]
                    .matcher
                    .matches(&facts, geo),
                select.pipeline_select[0].matchers[0]
                    .matcher
                    .matches("test", &facts, geo),
                phase(&response.pipelines[0].rules[0]).matchers[0]
                    .matcher
                    .matches(&facts, "udp:test", &message, geo),
            ]
        }
    }

    /// 域名正则里的字符类只留 ASCII 的部分，词边界按 ASCII 分，和 GeoSite 的 `regexp:` 一样：规则看到的名字只有 ASCII
    /// （见 `proto_utils::name_text`）。按 Unicode 理解时一个 `\w` 就是几百个区间，`\w{50}` 编译后超过 1 MB，一份配置里
    /// 这样的短正则一多，校验和运行时都要好几 GB。下面每一条照写的按 Unicode、1 MB 的上限都编不出，现在三种域名正则里
    /// 都读得进来：连写的 `\w`、取反的、字符类里的、`(?i)` 下的，带 `\b{start}`、`\<` 这类词边界的，`\pL` 这样的 Unicode
    /// 属性也是
    /// Classes in a domain regex are kept to their ASCII part and word boundaries drawn the ASCII
    /// way, as in a GeoSite `regexp:`: the names rules see are ASCII alone (see
    /// `proto_utils::name_text`). Read as Unicode one `\w` is hundreds of ranges, `\w{50}` is
    /// over 1 MB compiled, and a configuration with many such short regexes takes gigabytes to
    /// validate and to run. Every pattern below fails to compile as written, as Unicode within
    /// 1 MB, and now loads in all three domain regexes: `\w` written out, negated, inside a
    /// class, under `(?i)`, next to word boundaries such as `\b{start}` or `\<`, and Unicode
    /// properties such as `\pL` too
    #[test]
    fn word_classes_in_a_domain_regex_are_ascii() {
        let as_written = |pattern: &str| {
            RegexBuilder::new(pattern)
                .size_limit(1_000_000)
                .dfa_size_limit(1_000_000)
                .build()
        };
        for pattern in [
            r"\w{50}".to_owned(),
            r"\w{60}".to_owned(),
            r"\w".repeat(200),
            r"\W{60}".to_owned(),
            r"[\w.-]{60}".to_owned(),
            r"[^\W\d]{60}".to_owned(),
            r"(?i)\w{60}".to_owned(),
            r"\b{start}\w{60}\b{end}".to_owned(),
            r"\<\w{60}\>".to_owned(),
            r"\pL{60}".to_owned(),
            r"(?i)[^\PL\d]{60}".to_owned(),
        ] {
            assert!(as_written(&pattern).is_err(), "{pattern} as Unicode");
            for (which, config) in domain_regex_configs(&pattern).into_iter().enumerate() {
                if let Err(err) = crate::config::validate(&config.to_string()) {
                    panic!("{pattern}, matcher {which}: {err:#}");
                }
            }
        }
    }

    /// 一份配置里一千条 `^\w{18}\.example-N\.com$`：照写的按 Unicode 编译，每条都超过 64 KiB，一千条校验时要 1.5 GB
    /// 以上、好几秒。现在这份配置校验通过，读进来的每一条正则在 64 KiB 的上限下也编得出
    /// A thousand `^\w{18}\.example-N\.com$` in one configuration: compiled as written, as
    /// Unicode, each is over 64 KiB, and validating the thousand took over 1.5 GB and seconds.
    /// Now the configuration validates, and every regex it loads compiles within 64 KiB
    #[test]
    fn a_thousand_word_class_regexes_stay_small() {
        let within_64_kib = |pattern: &str| {
            RegexBuilder::new(pattern)
                .size_limit(64 * 1024)
                .dfa_size_limit(64 * 1024)
                .build()
                .is_ok()
        };
        let pattern = |i: usize| format!(r"^\w{{18}}\.example-{i}\.com$");
        assert!(!within_64_kib(&pattern(0)), "as written, as Unicode");
        let compiled = |config: serde_json::Value| -> Vec<String> {
            let config = runtime_of(config).expect("build runtime config");
            config.pipelines[0]
                .rules
                .iter()
                .map(|rule| match &rule.matchers[0].matcher {
                    RuntimeMatcher::DomainRegex { regex } => regex.as_str().to_owned(),
                    other => panic!("{other:?}"),
                })
                .collect()
        };
        // 先看一条，以前的写法在这里就停下，不用把一千条都按 Unicode 编一遍
        // One first, so the old way stops here without compiling a thousand as Unicode
        let one = compiled(one_rule(serde_json::json!([
            { "type": "domain_regex", "value": pattern(0) }
        ])));
        assert!(within_64_kib(&one[0]), "{}", one[0]);

        let rules: Vec<serde_json::Value> = (0..1000)
            .map(|i| {
                serde_json::json!({
                    "name": format!("r{i}"),
                    "matchers": [{ "type": "domain_regex", "value": pattern(i) }],
                    "actions": [{ "type": "static_response", "rcode": "NXDOMAIN" }]
                })
            })
            .collect();
        let config = serde_json::json!({
            "settings": { "default_upstream": "127.0.0.1:9" },
            "pipelines": [{ "id": "main", "rules": rules }]
        });
        let report = crate::config::validate(&config.to_string()).expect("validate");
        assert_eq!(report.rule_count, 1000);
        let regexes = compiled(config);
        assert_eq!(regexes.len(), 1000);
        for regex in &regexes {
            assert!(within_64_kib(regex), "{regex}");
        }
    }

    /// 只含 ASCII 的名字，匹配结果和按 Unicode 照写编译时一样：`\w`、`\d`、`\s`、`\b` 和取反形式，字符类里的、
    /// 嵌套和求交的，锚点、`(?i)`、`(?x)`、分支，`\b{start}`、`\<` 这类词边界，和 `\p{..}` 混写的。名字按规则看到的
    /// 写法给（见 `proto_utils::name_text`）：小写，标签里的点、空格和非 ASCII 字节写成 `\DDD`；另加几个带大写的。
    /// 三种域名正则都比；每条正则至少命中一个名字、至少漏掉一个，表才不是空比
    /// Names of ASCII alone match as they do with the pattern compiled as written, as Unicode:
    /// `\w`, `\d`, `\s`, `\b` and their negations, inside classes, nested and intersected,
    /// with anchors, `(?i)`, `(?x)`, alternations, word boundaries such as `\b{start}` or `\<`,
    /// and mixed with `\p{..}`. Names come as rules see them (see `proto_utils::name_text`):
    /// lower case, with a dot, a space or a non-ASCII byte inside a label written as `\DDD`;
    /// a few with capitals besides. All three domain regexes are compared; each pattern
    /// matches at least one name and misses at least one, so the table compares something
    #[test]
    fn ascii_names_match_a_domain_regex_as_before() {
        let names = [
            "www.example.com",
            "a-b_c.example.com",
            "_dmarc.example.com",
            "cdn12.example.net",
            "ads.site3.example",
            "track.site10.example",
            "trackads.example",
            "1.2.0.192.in-addr.arpa",
            "x.test",
            "x1.test",
            "-.test",
            "*.wild.test",
            r"a\046b.example",
            r"a\032b.example",
            r"\195\169.example",
            "WWW.Example.COM",
            "Cdn7.EXAMPLE.net",
        ];
        for pattern in [
            r"^\w+\.example\.com$",
            r"^[\w-]+\.example\.com$",
            r"^cdn\d+\.example\.net$",
            r"(?i)^cdn\d+\.example\.net$",
            r"^[^\d]+\.test$",
            r"\bads\b",
            r"\Bads",
            r"\w\W\w",
            r"^\W",
            r"\D\d\.",
            r"^\S+\.test$",
            r"\s|-",
            r"^\S*\\\d{3}",
            r"(?i)^WWW\.\w+\.COM$",
            r"^(ads?|track\d*)\.site\d+\.example$",
            r"^\d{1,3}(\.\d{1,3}){3}\.in-addr\.arpa$",
            r"^[a\W]",
            r"^[[:alpha:]\d]+\.test$",
            r"^[\w&&[^\d]]+\.test$",
            r"^[\w--_]+\.",
            r"^[a-z]\w*\.test$",
            r"\b{start}www\b{end}",
            r"\<site\d+\>",
            r"(?x) ^ \w+ \. example \. com $",
            r"^\p{L}\w*\.test$",
        ] {
            let unicode = regex::Regex::new(pattern).expect(pattern);
            let matched = domain_regex_matchers(pattern);
            let mut seen = [false; 2];
            for name in names {
                let before = unicode.is_match(name);
                assert_eq!(matched(name), [before; 3], "{pattern} against {name}");
                seen[usize::from(before)] = true;
            }
            assert_eq!(seen, [true, true], "{pattern} matches some names, not all");
        }
    }

    /// 和照写的按 Unicode 理解不同的只有含非 ASCII 字符的文本：`\w`、`\pL`、`.`、`[^x]` 都不认 `é`，`\d` 不认 `٣`，`\s`
    /// 不认不换行空格，`\b`、`\<` 把 `é` 当作词外的字符。规则看不到这样的文本：标签里不是可打印 ASCII 的字节写成
    /// `\DDD`，同一个名字两种理解结果一样
    /// Only text beyond ASCII reads differently from the pattern as written, as Unicode: `\w`,
    /// `\pL`, `.` and `[^x]` take no `é`, `\d` no `٣`, `\s` no no-break space, and `\b` and `\<`
    /// take `é` as outside a word. Rules never see such text: a label byte that is not printable
    /// ASCII is written as `\DDD`, and the same name matches the same either way
    #[test]
    fn only_text_beyond_ascii_reads_a_domain_regex_differently() {
        for (pattern, text) in [
            (r"^\w+\.example$", "é.example"),
            (r"^x\d\.example$", "x٣.example"),
            (r"^a\sb\.example$", "a\u{a0}b.example"),
            (r"^\pL\.example$", "é.example"),
            (r"^.\.example$", "é.example"),
            (r"^[^x]\.example$", "é.example"),
            (r"^é\bexample$", "éexample"),
            (r"^é\<example$", "éexample"),
        ] {
            let unicode = regex::Regex::new(pattern).unwrap();
            let matched = domain_regex_matchers(pattern);
            assert!(
                unicode.is_match(text) != matched(text)[0],
                "{pattern} against {text}"
            );
            assert_eq!(
                matched(text),
                [matched(text)[0]; 3],
                "{pattern} against {text}"
            );

            // 规则看到的是 `\DDD` 写出的名字 / What rules see is the name written with `\DDD`
            let labels: Vec<&[u8]> = text.split('.').map(str::as_bytes).collect();
            let name = Name::from_labels(labels).unwrap();
            let seen = crate::proto_utils::name_text(&name);
            assert!(seen.is_ascii(), "{seen}");
            assert_eq!(
                matched(&seen),
                [unicode.is_match(&seen); 3],
                "{pattern} against {seen}"
            );
        }
    }

    /// 只留 ASCII 不改哪些写法算错：照写的写错了照旧拒绝，报错里是照写的那条，没有只留 ASCII 后的写法。`[\w-a]`
    /// （`\w` 不能当区间的一端）、`\p{Foo}`、没闭合的括号都是。三种域名正则都是
    /// Keeping to ASCII does not change which patterns are wrong: one written wrong is refused as
    /// before, with the error quoting it as written and nothing of the ASCII form: `[\w-a]` (`\w`
    /// cannot end a range), `\p{Foo}`, an unclosed group. All three domain regexes alike
    #[test]
    fn a_domain_regex_written_wrong_is_refused_in_its_own_words() {
        for (pattern, cause) in [
            (r"^[\w-a]+$", "invalid range boundary, must be a literal"),
            (r"^\w+\p{Foo}$", "Unicode property not found"),
            (r"^(\w+\.example$", "unclosed group"),
        ] {
            for (which, config) in domain_regex_configs(pattern).into_iter().enumerate() {
                let err = format!(
                    "{:#}",
                    crate::config::validate(&config.to_string()).unwrap_err()
                );
                assert!(
                    err.contains(cause) && err.contains(pattern) && !err.contains("0-9A-Za-z_"),
                    "{pattern}, matcher {which}: {err}"
                );
            }
        }
    }

    /// 域名正则里不在 `(?i)` 下写成大写的字母照写永远命不中（规则看到的名字是小写的），三种域名正则都记一条警告，说在哪、
    /// 是哪一段：带大写的字面量，只取大写字母的字符类。`(?i)` 下的、字符类里也有别的字符的不算。以前配置不提示，这样的
    /// 规则悄悄地从不命中
    /// Capitals in a domain regex outside `(?i)` never match as written (the names rules see are
    /// lowercase), and each of the three domain regexes gets a warning saying where and which
    /// part: a literal holding a capital, a class taking capitals alone. Those under `(?i)`, and
    /// classes taking other characters too, do not count. The configuration used to say
    /// nothing, and such a rule silently never matched
    #[test]
    fn capitals_in_a_domain_regex_are_warned_about() {
        let places = [
            ("pipelines[0].rules[0].matchers[0]", "domain_regex"),
            ("pipeline_select[0].matchers[0]", "domain_regex"),
            (
                "pipelines[0].rules[0].response_matchers[0]",
                "request_domain_regex",
            ),
        ];
        for (pattern, capitals) in [
            (r"^Ads\.example$", r#""Ads\.example""#),
            (r"^(?:ads|Track)\.[A-Z]+$", r#""Track", "[A-Z]""#),
            (r"^\x41\d$", r#""A""#),
            (r"^(?-u:[A-Z])x$", r#""(?-u:[A-Z])""#),
        ] {
            assert_eq!(domain_regex_matchers(pattern)("ads.example"), [false; 3]);
            for (config, (place, kind)) in domain_regex_configs(pattern).into_iter().zip(places) {
                let warnings = runtime_of(config).unwrap().warnings;
                assert_eq!(
                    warnings,
                    [format!(
                        "{place}: {kind} \"{pattern}\": the capitals in {capitals} never match, as the names rules see are lowercase; write them in lowercase or under (?i)"
                    )],
                    "{pattern}"
                );
            }
        }
        for pattern in [
            r"(?i)^Ads\.example$",
            r"^ads\.(?i:EXAMPLE)$",
            r"^[A-Z0-9]+\.example$",
            r"^\w+\.example$",
        ] {
            for config in domain_regex_configs(pattern) {
                assert!(runtime_of(config).unwrap().warnings.is_empty(), "{pattern}");
            }
        }
    }

    /// 请求阶段、命中后和未命中时三类动作里的 forward，读配置时就把逗号分开的上游拆好（各项去掉两边的
    /// 空白，空项跳过），转发时不用每次再拆
    /// The forwards of the request-phase, on-match and on-miss actions get their
    /// comma-separated upstreams split when the configuration is read (each item trimmed,
    /// empty items skipped), so forwarding does not split them again each time
    #[test]
    fn every_action_phase_has_its_forward_upstreams_split_ahead() {
        let config = runtime_of(serde_json::json!({
            "settings": { "default_upstream": "127.0.0.1:9" },
            "pipelines": [{ "id": "main", "rules": [{
                "name": "r",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": "192.0.2.1:53, 192.0.2.2:53" }],
                "response_matchers": [{ "type": "upstream_equals", "value": "192.0.2.1:53" }],
                "response_actions_on_match": [{ "type": "forward", "upstream": "192.0.2.3:53" }],
                "response_actions_on_miss": [
                    { "type": "forward", "upstream": " 192.0.2.4:53 ,, 192.0.2.5:53" }
                ]
            }] }]
        }))
        .expect("build runtime config");
        let rule = &config.pipelines[0].rules[0];
        let split_ahead = |actions: &[Action]| match &actions[0] {
            Action::Forward { upstream, .. } => upstream.as_ref().map(|target| {
                target
                    .pre_split_upstreams
                    .iter()
                    .map(|u| u.to_string())
                    .collect::<Vec<_>>()
            }),
            other => panic!("{other:?}"),
        };
        assert_eq!(
            split_ahead(&rule.actions),
            Some(vec!["192.0.2.1:53".to_string(), "192.0.2.2:53".to_string()])
        );
        assert_eq!(
            split_ahead(&phase(rule).on_match),
            Some(vec!["192.0.2.3:53".to_string()])
        );
        assert_eq!(
            split_ahead(&phase(rule).on_miss),
            Some(vec!["192.0.2.4:53".to_string(), "192.0.2.5:53".to_string()])
        );
    }

    /// 每项带着自己的运算符，从左到右和前面的结果合起来，并且短路：and、and_not 只在前面成立时看
    /// 这一项，or、or_not 只在前面不成立时看；and_not、or_not 取这一项的反（配置里的 not 就是
    /// and_not）。空链成立。两项、三项的链逐个穷举，核对结果和哪些项被求值了。
    /// Each item carries its own operator and combines with the result so far from left
    /// to right, short-circuiting: and and and_not look at the item only when the result
    /// so far holds, or and or_not only when it does not; and_not and or_not take the item
    /// negated ("not" in a configuration is and_not). An empty chain holds. Chains of two
    /// and three items are enumerated one by one, checking the result and which items were
    /// evaluated.
    #[test]
    fn a_match_chain_combines_left_to_right_and_short_circuits() {
        const OPERATORS: [MatchOperator; 4] = [
            MatchOperator::And,
            MatchOperator::Or,
            MatchOperator::AndNot,
            MatchOperator::OrNot,
        ];
        // 参考：一项一项照定义算 / Reference: one item at a time, by the definition
        let reference = |items: &[(MatchOperator, bool)]| {
            let mut evaluated = vec![0];
            let mut acc = items[0].1;
            for (idx, &(operator, value)) in items.iter().enumerate().skip(1) {
                let (looks, negated) = match operator {
                    MatchOperator::And => (acc, false),
                    MatchOperator::Or => (!acc, false),
                    MatchOperator::AndNot => (acc, true),
                    MatchOperator::OrNot => (!acc, true),
                };
                if looks {
                    evaluated.push(idx);
                    acc = value != negated;
                }
            }
            (acc, evaluated)
        };
        let check = |items: Vec<(MatchOperator, bool)>| {
            let mut evaluated = Vec::new();
            let result = eval_match_chain(
                &items.iter().enumerate().collect::<Vec<_>>(),
                |(_, (operator, _))| *operator,
                |(idx, (_, value))| {
                    evaluated.push(*idx);
                    *value
                },
            );
            assert_eq!((result, evaluated), reference(&items), "{items:?}");
        };

        assert!(eval_match_chain(
            &[] as &[()],
            |_| MatchOperator::And,
            |_| false
        ));
        for first in [false, true] {
            check(vec![(MatchOperator::And, first)]);
            for second_op in OPERATORS {
                for second in [false, true] {
                    check(vec![(MatchOperator::And, first), (second_op, second)]);
                    for third_op in OPERATORS {
                        for third in [false, true] {
                            check(vec![
                                (MatchOperator::And, first),
                                (second_op, second),
                                (third_op, third),
                            ]);
                        }
                    }
                }
            }
        }
    }
    use hickory_proto::{
        op::{MessageType, OpCode},
        rr::{
            Name, RData, Record,
            rdata::{
                A, AAAA, HTTPS, SVCB,
                svcb::{IpHint, SvcParamKey, SvcParamValue},
            },
        },
    };
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn settings_config(overrides: serde_json::Value) -> crate::config::PipelineConfig {
        serde_json::from_value(serde_json::json!({ "settings": overrides }))
            .expect("parse settings")
    }

    /// 这些数字不再使用，旧配置里写着什么都照常加载，哪怕当年会被拒绝
    /// These numbers are no longer used, and an old configuration loads whatever it says, even
    /// what used to be rejected
    #[test]
    fn old_flow_control_numbers_do_not_stop_a_configuration_from_loading() {
        let old = settings_config(serde_json::json!({
            "flow_control_enabled": true,
            "flow_control_min_permits": 100,
            "flow_control_initial_permits": 900,
            "flow_control_max_permits": 800,
            "flow_control_adjustment_interval_secs": 5
        }));
        RuntimePipelineConfig::from_config(old).expect("the old numbers do nothing now");
    }

    /// upstream_timeout_ms = 0 让每次上游请求在发出的同一刻超时，配置能通过
    /// 但没有任何查询能被应答。
    /// upstream_timeout_ms = 0 expires every upstream request as it is issued:
    /// the configuration loads and then no query can ever be answered.
    #[test]
    fn a_zero_upstream_timeout_is_rejected() {
        let zero = settings_config(serde_json::json!({ "upstream_timeout_ms": 0 }));
        let error = RuntimePipelineConfig::from_config(zero)
            .expect_err("upstream_timeout_ms = 0 must be rejected");
        assert!(
            error.to_string().contains("upstream_timeout_ms"),
            "unexpected error: {error}"
        );

        let one = settings_config(serde_json::json!({ "upstream_timeout_ms": 1 }));
        RuntimePipelineConfig::from_config(one).expect("a one millisecond timeout stays valid");
    }

    /// 这两个值此前没有校验：cache_max_ttl = 0 静默关掉缓存，
    /// threshold_percent > 100 让每次缓存命中都触发后台刷新。
    /// Neither value was validated: cache_max_ttl = 0 silently disabled the
    /// cache and a threshold above 100 made every cache hit refresh upstream.
    #[test]
    fn cache_settings_outside_their_range_are_rejected() {
        let zero_ttl = settings_config(serde_json::json!({ "cache_max_ttl": 0 }));
        let error = RuntimePipelineConfig::from_config(zero_ttl)
            .expect_err("cache_max_ttl = 0 must be rejected");
        assert!(
            error.to_string().contains("cache_max_ttl"),
            "unexpected error: {error}"
        );

        let over_100 = settings_config(serde_json::json!({
            "cache_refresh_threshold_percent": 250
        }));
        let error = RuntimePipelineConfig::from_config(over_100)
            .expect_err("a refresh threshold above 100% must be rejected");
        assert!(
            error
                .to_string()
                .contains("cache_refresh_threshold_percent"),
            "unexpected error: {error}"
        );

        let at_100 = settings_config(serde_json::json!({
            "cache_refresh_threshold_percent": 100
        }));
        RuntimePipelineConfig::from_config(at_100)
            .expect_err("100% refreshes on every hit, same as above 100");

        // 边界值仍然合法 / The boundary values stay valid
        RuntimePipelineConfig::from_config(settings_config(serde_json::json!({
            "cache_max_ttl": 1,
            "cache_refresh_threshold_percent": 99
        })))
        .expect("boundary values must stay valid");
    }

    /// 只在启动时读的设置，校验放过的值引擎一定建得起来，建不起来的校验就拒掉。以前 `dashmap_shards: 1` 能过校验、
    /// 热重载和面板保存，到下次启动 DashMap 断言分片数大于 1，内核直接 panic；DoQ 空闲超时写得太大，启动才报错；
    /// 连接池多大都收，UDP 池开不出那么多 socket、大到 2^64 的池分配不出内存。上限以内的分片数和连接池，引擎照样建得起来
    /// Of the settings read only at startup, a value the check lets through always builds an
    /// engine, and one that cannot is refused by the check. `dashmap_shards: 1` used to pass the
    /// check, a hot reload and a panel save, and at the next start DashMap's assertion of more
    /// than one shard panicked the kernel; a DoQ idle timeout too large failed only at startup;
    /// a pool of any size was taken, with more UDP sockets than could be opened, or one as large
    /// as 2^64 that could not be allocated. Shard counts and pools up to their limits still
    /// build an engine
    #[tokio::test]
    async fn startup_only_settings_the_check_lets_through_build_an_engine() {
        let build = |settings: serde_json::Value| {
            RuntimePipelineConfig::from_config(settings_config(settings)).map(|runtime| {
                crate::engine::Engine::new(runtime, "test".to_string()).expect("engine builds")
            })
        };
        use crate::config::{MAX_DASHMAP_SHARDS, MAX_POOL_SIZE};
        for shards in [0usize, 2, 64, 4096, MAX_DASHMAP_SHARDS] {
            build(serde_json::json!({ "dashmap_shards": shards }))
                .unwrap_or_else(|error| panic!("dashmap_shards {shards}: {error:#}"));
        }
        for shards in [1usize, 3] {
            let refused = build(serde_json::json!({ "dashmap_shards": shards }))
                .err()
                .unwrap_or_else(|| panic!("dashmap_shards {shards} must be refused"));
            assert!(refused.to_string().contains("dashmap_shards"), "{refused}");
        }
        let pools = [
            "udp_pool_size",
            "tcp_pool_size",
            "doh_pool_size",
            "dot_pool_size",
            "doq_pool_size",
        ];
        build(serde_json::Value::Object(
            pools
                .iter()
                .map(|pool| (pool.to_string(), serde_json::json!(MAX_POOL_SIZE)))
                .collect(),
        ))
        .expect("every pool at its largest");
        build(serde_json::json!({ "doq_connection_idle_timeout_seconds": 86_400 }))
            .expect("a day of DoQ idle time");
        let refused = build(serde_json::json!({ "doq_connection_idle_timeout_seconds": u64::MAX }))
            .err()
            .expect("more than QUIC can carry");
        assert!(
            refused
                .to_string()
                .contains("doq_connection_idle_timeout_seconds"),
            "{refused}"
        );
    }

    #[test]
    fn overlapping_geoip_tag_reaches_all_runtime_matchers() {
        let json = r#"{
            "entries": [
                { "country_code": "US", "ips": ["104.16.0.0/12"] },
                { "country_code": "cloudflare", "ips": ["104.16.0.0/12", "2606:4700::/32"] }
            ]
        }"#;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("geoip_runtime_matchers.json");
        std::fs::write(&path, json).unwrap();

        let mut manager = geoip::GeoIpManager::default();
        manager.load_from_v2ray_file(&path).unwrap();
        let ip: IpAddr = "104.16.0.1".parse().unwrap();
        let tags = vec![Arc::from("CLOUDFLARE")];

        let facts = RequestFacts {
            qname: "example.com",
            qtype: RecordType::A,
            qclass: DNSClass::IN,
            client_ip: ip,
            edns_present: false,
        };
        let geo = &GeoManagers {
            geoip: Arc::new(manager),
            ..GeoManagers::default()
        };
        let request = RuntimeMatcher::GeoipCountry {
            country_codes: tags.clone(),
        };
        assert!(request.matches(&facts, geo));

        let pipeline = RuntimePipelineSelectorMatcher::Request(RuntimeMatcher::GeoipCountry {
            country_codes: tags.clone(),
        });
        assert!(pipeline.matches("test", &facts, geo));
        let response = RuntimeResponseMatcher::ResponseAnswerIpGeoipCountry {
            country_codes: tags,
        };
        let mut message = Message::new(0, MessageType::Response, OpCode::Query);
        message.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            300,
            RData::A(A(Ipv4Addr::new(104, 16, 0, 1))),
        ));
        assert!(response.matches(
            &RequestFacts::a_query("example.com"),
            "udp:test",
            &message,
            geo,
        ));

        let mut https_message = Message::new(0, MessageType::Response, OpCode::Query);
        https_message.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            300,
            RData::HTTPS(HTTPS(SVCB::new(
                1,
                Name::root(),
                vec![
                    (
                        SvcParamKey::Ipv4Hint,
                        SvcParamValue::Ipv4Hint(IpHint(vec![A(Ipv4Addr::new(104, 21, 11, 126))])),
                    ),
                    (
                        SvcParamKey::Ipv6Hint,
                        SvcParamValue::Ipv6Hint(IpHint(vec![AAAA(
                            "2606:4700:3034::6815:b7e".parse::<Ipv6Addr>().unwrap(),
                        )])),
                    ),
                ],
            ))),
        ));
        assert!(response.matches(
            &RequestFacts {
                qtype: RecordType::HTTPS,
                qclass: DNSClass::IN,
                ..RequestFacts::a_query("example.com")
            },
            "udp:test",
            &https_message,
            geo,
        ));
        let country_response = RuntimeResponseMatcher::ResponseAnswerIpGeoipCountry {
            country_codes: vec![Arc::from("US")],
        };
        assert!(country_response.matches(
            &RequestFacts {
                qtype: RecordType::HTTPS,
                qclass: DNSClass::IN,
                ..RequestFacts::a_query("example.com")
            },
            "udp:test",
            &https_message,
            geo,
        ));

        let no_hint_record = Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            300,
            RData::HTTPS(HTTPS(SVCB::new(1, Name::root(), vec![]))),
        );
        let mut no_hint_message = Message::new(0, MessageType::Response, OpCode::Query);
        no_hint_message.add_answer(no_hint_record.clone());
        assert!(!country_response.matches(
            &RequestFacts {
                qtype: RecordType::HTTPS,
                qclass: DNSClass::IN,
                ..RequestFacts::a_query("example.com")
            },
            "udp:test",
            &no_hint_message,
            geo,
        ));
        let mut mixed_no_hint_message = https_message.clone();
        mixed_no_hint_message.add_answer(no_hint_record);
        assert!(country_response.matches(
            &RequestFacts {
                qtype: RecordType::HTTPS,
                qclass: DNSClass::IN,
                ..RequestFacts::a_query("example.com")
            },
            "udp:test",
            &mixed_no_hint_message,
            geo,
        ));

        assert!(!response.matches(
            &RequestFacts {
                qtype: RecordType::HTTPS,
                qclass: DNSClass::IN,
                ..RequestFacts::a_query("example.com")
            },
            "udp:test",
            &https_message,
            GeoManagers::empty(),
        ));

        let cidr_response = RuntimeResponseMatcher::ResponseAnswerIp {
            nets: vec!["104.21.0.0/16".parse().unwrap()],
        };
        assert!(cidr_response.matches(
            &RequestFacts {
                qtype: RecordType::HTTPS,
                qclass: DNSClass::IN,
                ..RequestFacts::a_query("example.com")
            },
            "udp:test",
            &https_message,
            geo,
        ));

        let mut svcb_answer_message = Message::new(0, MessageType::Response, OpCode::Query);
        svcb_answer_message.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            300,
            RData::SVCB(SVCB::new(
                1,
                Name::root(),
                vec![
                    (
                        SvcParamKey::Ipv4Hint,
                        SvcParamValue::Ipv4Hint(IpHint(vec![A(Ipv4Addr::new(104, 21, 11, 126))])),
                    ),
                    (
                        SvcParamKey::Ipv6Hint,
                        SvcParamValue::Ipv6Hint(IpHint(vec![AAAA(
                            "2606:4700:3034::6815:b7e".parse::<Ipv6Addr>().unwrap(),
                        )])),
                    ),
                ],
            )),
        ));
        assert!(country_response.matches(
            &RequestFacts {
                qtype: RecordType::SVCB,
                qclass: DNSClass::IN,
                ..RequestFacts::a_query("example.com")
            },
            "udp:test",
            &svcb_answer_message,
            geo,
        ));
        assert!(cidr_response.matches(
            &RequestFacts {
                qtype: RecordType::SVCB,
                qclass: DNSClass::IN,
                ..RequestFacts::a_query("example.com")
            },
            "udp:test",
            &svcb_answer_message,
            geo,
        ));

        let mut mixed_message = https_message.clone();
        mixed_message.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            300,
            RData::A(A(Ipv4Addr::new(203, 0, 113, 1))),
        ));
        assert!(!response.matches(
            &RequestFacts {
                qtype: RecordType::HTTPS,
                qclass: DNSClass::IN,
                ..RequestFacts::a_query("example.com")
            },
            "udp:test",
            &mixed_message,
            geo,
        ));

        let mut additional_message = Message::new(0, MessageType::Response, OpCode::Query);
        additional_message.add_additional(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            300,
            RData::A(A(Ipv4Addr::new(104, 21, 11, 126))),
        ));
        assert!(!response.matches(
            &RequestFacts::a_query("example.com"),
            "udp:test",
            &additional_message,
            geo,
        ));
        assert!(cidr_response.matches(
            &RequestFacts::a_query("example.com"),
            "udp:test",
            &additional_message,
            geo,
        ));

        let mut svcb_message = Message::new(0, MessageType::Response, OpCode::Query);
        svcb_message.add_additional(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            300,
            RData::SVCB(SVCB::new(
                1,
                Name::root(),
                vec![(
                    SvcParamKey::Ipv4Hint,
                    SvcParamValue::Ipv4Hint(IpHint(vec![A(Ipv4Addr::new(192, 168, 1, 1))])),
                )],
            )),
        ));
        let private_response =
            RuntimeResponseMatcher::ResponseAnswerIpGeoipPrivate { expect: true };
        assert!(private_response.matches(
            &RequestFacts {
                qtype: RecordType::SVCB,
                qclass: DNSClass::IN,
                ..RequestFacts::a_query("example.com")
            },
            "udp:test",
            &svcb_message,
            geo,
        ));

        let _ = std::fs::remove_file(path);
    }

    /// 回答里 IPv4 映射形式的地址（AAAA 和 `ipv6hint` 里的 `::ffff:a.b.c.d`）按它所指的 IPv4 地址判断，写成映射形式
    /// 的网段按它所指的 IPv4 网段读：看回答地址的三个匹配器都这样。以前按 IPv6 地址看，AAAA `::ffff:192.168.1.1`
    /// 不算内网、不在 192.168.0.0/16 里，防重绑定的规则放过了它
    /// An IPv4-mapped address in an answer (`::ffff:a.b.c.d` in an AAAA or an `ipv6hint`) is
    /// judged as the IPv4 address it names, and a network written in the mapped form is read as
    /// the IPv4 network it names, by all three matchers of answer addresses. Taken as an IPv6
    /// address, AAAA `::ffff:192.168.1.1` used to be neither local nor in 192.168.0.0/16, and
    /// anti-rebinding rules let it through
    #[test]
    fn an_ipv4_mapped_answer_counts_as_its_ipv4_address() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lan.json");
        std::fs::write(
            &path,
            r#"{ "entries": [{ "country_code": "LAN", "ips": ["192.168.0.0/16"] }] }"#,
        )
        .unwrap();
        let mut geoip = geoip::GeoIpManager::default();
        geoip.load_from_v2ray_file(&path).unwrap();
        let geo = &GeoManagers {
            geoip: Arc::new(geoip),
            ..GeoManagers::default()
        };

        let matcher = |config: serde_json::Value| {
            RuntimeResponseMatcher::from_config(serde_json::from_value(config).unwrap()).unwrap()
        };
        let matchers = [
            matcher(
                serde_json::json!({ "type": "response_answer_ip_geoip_private", "expect": true }),
            ),
            matcher(serde_json::json!({ "type": "response_answer_ip", "cidr": "192.168.0.0/16" })),
            matcher(
                serde_json::json!({ "type": "response_answer_ip_geoip_country", "country_codes": ["LAN"] }),
            ),
        ];
        let answer = |data: RData| {
            let mut message = Message::new(0, MessageType::Response, OpCode::Query);
            message.add_answer(Record::from_rdata(Name::root(), 300, data));
            message
        };
        let mapped: Ipv6Addr = "::ffff:192.168.1.1".parse().unwrap();
        let answers = [
            answer(RData::AAAA(AAAA(mapped))),
            answer(RData::HTTPS(HTTPS(SVCB::new(
                1,
                Name::root(),
                vec![(
                    SvcParamKey::Ipv6Hint,
                    SvcParamValue::Ipv6Hint(IpHint(vec![AAAA(mapped)])),
                )],
            )))),
        ];
        for (which, matcher) in matchers.iter().enumerate() {
            for message in &answers {
                assert!(
                    matcher.matches(
                        &RequestFacts {
                            qtype: RecordType::AAAA,
                            qclass: DNSClass::IN,
                            ..RequestFacts::a_query("example.com")
                        },
                        "udp:test",
                        message,
                        geo,
                    ),
                    "matcher {which}: {:?}",
                    message.answers[0].data
                );
            }
        }

        let mapped_net = matcher(
            serde_json::json!({ "type": "response_answer_ip", "cidr": "::ffff:192.168.0.0/112" }),
        );
        assert!(mapped_net.matches(
            &RequestFacts::a_query("example.com"),
            "udp:test",
            &answer(RData::A(A(Ipv4Addr::new(192, 168, 1, 1)))),
            GeoManagers::empty(),
        ));
    }

    /// 域名后缀按点分段：不带点的值命中它本身和子域名，带点的值只命中子域名，尾巴相同的别的域名都不算。
    /// Domain suffixes compare by label: a plain value matches itself and subdomains, a dotted one subdomains
    /// only, and another name that merely ends in the same letters matches neither.
    #[test]
    fn domain_suffix_matches_by_label() {
        let cases = [
            ("example.com", "example.com", true),
            ("www.example.com", "example.com", true),
            ("a.b.example.com", "example.com", true),
            ("notexample.com", "example.com", false),
            ("example.com.cn", "example.com", false),
            ("example.com", ".example.com", false),
            ("www.example.com", ".example.com", true),
            ("notexample.com", ".example.com", false),
            ("cn", "cn", true),
            ("example.cn", "cn", true),
            ("examplecn", "cn", false),
            ("anything.test", "", true),
        ];
        for (qname, suffix, expected) in cases {
            assert_eq!(
                domain_suffix_matches(qname, suffix),
                expected,
                "{qname} against {suffix:?}"
            );
        }
    }

    /// 两种写法进后缀索引时用同一个键：查找是按点从整名往上走的，带开头的点就永远查不到。
    /// Both spellings enter the suffix index under one key: lookups walk up the name by label, so a key with
    /// a leading dot would never be found.
    #[test]
    fn domain_suffix_index_keys_drop_the_leading_dot() {
        assert_eq!(domain_suffix_index_key(".example.com"), "example.com");
        assert_eq!(domain_suffix_index_key("example.com"), "example.com");
        let cfg: PipelineConfig = serde_json::from_value(serde_json::json!({
            "pipelines": [{
                "id": "main",
                "rules": [
                    { "name": "dotted", "matchers": [{ "type": "domain_suffix", "value": ".dotted.test" }], "actions": [{ "type": "deny" }] },
                    { "name": "plain", "matchers": [{ "type": "domain_suffix", "value": "Plain.Test" }], "actions": [{ "type": "deny" }] }
                ]
            }]
        }))
        .expect("parse config");
        let runtime = RuntimePipelineConfig::from_config(cfg).expect("runtime config");
        let index = &runtime.pipelines[0].index.domain_suffix;
        assert_eq!(index.get("dotted.test").map(Vec::as_slice), Some(&[0][..]));
        assert_eq!(index.get("plain.test").map(Vec::as_slice), Some(&[1][..]));
        assert!(!index.contains_key(".dotted.test"));
    }

    /// 响应阶段的 request_domain_suffix 和请求阶段同一个比较。
    /// The response-phase request_domain_suffix uses the same comparison as the request phase.
    #[test]
    fn response_request_domain_suffix_matches_by_label() {
        let message = Message::new(0, MessageType::Response, OpCode::Query);
        let check = |value: &str, qname: &str| {
            RuntimeResponseMatcher::RequestDomainSuffix {
                value: Arc::from(value),
            }
            .matches(
                &RequestFacts::a_query(qname),
                "udp:test",
                &message,
                GeoManagers::empty(),
            )
        };
        assert!(check("svc.test", "svc.test"));
        assert!(check("svc.test", "a.svc.test"));
        assert!(!check("svc.test", "notsvc.test"));
        assert!(!check(".svc.test", "svc.test"));
        assert!(check(".svc.test", "a.svc.test"));
    }
}
