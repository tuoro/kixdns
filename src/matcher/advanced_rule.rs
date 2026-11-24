use std::net::IpAddr;
use std::sync::Arc;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{Name, RecordType};
use rustc_hash::FxHashMap;
use smallvec::SmallVec;

use crate::config::{Action, MatchOperator};
use crate::matcher::{RuntimeMatcher, RuntimeRule};
use crate::matcher::{domain_suffix_index_key, parse_rcode, static_cname_target, static_ips};

/// 规则当场作出的决定：它第一个动作编好的静态应答（见 `Action::static_answer`），或跳到另一个 pipeline，快速路径跟过去在
/// 那里接着查
/// What a rule decides on the spot: the static answer its first action compiled to (see
/// `Action::static_answer`), or a jump to another pipeline, which the fast path follows to go on
/// looking there
#[derive(Debug, Clone, Copy)]
pub enum PrecomputedAction<'a> {
    Answer(&'a StaticAnswer),
    Jump(&'a Arc<str>),
}

impl RuntimeRule {
    /// 这条规则当场作出的决定：第一个动作是作答动作或跳转时就是它，别的（转发、先记日志的）为 None，交给完整路径
    /// What this rule decides on the spot: its first action when that answers or jumps, None
    /// otherwise (a forward, one logging first), left to the full path
    pub fn precomputed(&self) -> Option<PrecomputedAction<'_>> {
        let first = self.actions.first()?;
        match first {
            Action::JumpToPipeline { pipeline } => Some(PrecomputedAction::Jump(pipeline)),
            _ => first.static_answer().map(PrecomputedAction::Answer),
        }
    }
}

/// 作答动作照配置写好的静态应答，配置加载时编好、存在动作上（见 `Action::compile_answer`）。快速路径、请求阶段、回答阶段
/// 都照它给一个查询的 RCODE 和记录（见 `engine::response`），每个查询不再读一遍配置里的文本
/// The static answer an answering action writes, compiled at config load and kept on the
/// action (see `Action::compile_answer`). The fast path, the request phase and the response
/// phase all give a query its RCODE and records by it (see `engine::response`), no query reading
/// the configuration's text again
#[derive(Debug, Clone)]
pub enum StaticAnswer {
    /// 只有 RCODE、不带记录：static_response、deny（REFUSED），以及写的地址或 CNAME 目标读不出来、TXT 一个字符串也没有或
    /// 装不下时的 SERVFAIL（配置检查报过，见 `engine::response::txt_problem`）
    /// An RCODE alone, with no records: static_response, deny (REFUSED), and the SERVFAIL of an
    /// address or CNAME target that cannot be read, or of a TXT that names no string or does not
    /// fit (which the configuration check reports, see `engine::response::txt_problem`)
    Rcode(ResponseCode),
    /// 按问题给的记录 / Records given by the question
    Records(StaticRecords),
}

/// 静态应答按问题给的记录 / The records a static answer gives by the question
#[derive(Debug, Clone)]
pub enum StaticRecords {
    /// static_ip_response 的地址，按问的类型挑 / A static_ip_response's addresses, picked by the
    /// type asked
    Addresses(Box<[IpAddr]>),
    /// static_cname_response 的目标 / A static_cname_response's target
    Cname { target: Name, ttl: u32 },
    /// static_txt_response 的文本，replace_txt_response 换成的也是它 / A static_txt_response's
    /// text, which replace_txt_response replaces the answer with too
    Txt { text: Box<[String]>, ttl: u32 },
}

/// 没编过的动作答 SERVFAIL：动作在配置加载时编好（见 `Action::compile_answer`），反序列化出来时还没有
/// An action not compiled answers SERVFAIL: actions are compiled at config load (see
/// `Action::compile_answer`), and not yet when deserialized
impl Default for StaticAnswer {
    fn default() -> Self {
        Self::Rcode(ResponseCode::ServFail)
    }
}

impl StaticAnswer {
    /// 静态记录不写 TTL 时用的 TTL，static_ip_response 的地址也是它 / The TTL of static records
    /// written without one, and of static_ip_response's addresses
    pub const DEFAULT_TTL: u32 = 300;

    /// deny 的应答 / What deny answers
    pub const DENY: Self = Self::Rcode(ResponseCode::Refused);

    /// static_response 的应答；读不出来的 RCODE 按 NXDOMAIN / What static_response answers; an
    /// RCODE that cannot be read as NXDOMAIN
    pub fn rcode(rcode: &str) -> Self {
        Self::Rcode(parse_rcode(rcode).unwrap_or(ResponseCode::NXDomain))
    }

    /// static_ip_response 的应答 / What static_ip_response answers
    pub fn addresses(ips: &str) -> Self {
        static_ips(ips).map_or(Self::Rcode(ResponseCode::ServFail), |addresses| {
            Self::Records(StaticRecords::Addresses(addresses.into_boxed_slice()))
        })
    }

    /// static_cname_response 的应答 / What static_cname_response answers
    pub fn cname(target: &str, ttl: Option<u32>) -> Self {
        static_cname_target(target).map_or(Self::Rcode(ResponseCode::ServFail), |target| {
            Self::Records(StaticRecords::Cname {
                target,
                ttl: ttl.unwrap_or(Self::DEFAULT_TTL),
            })
        })
    }

    /// static_txt_response 和 replace_txt_response 的应答；一个字符串也没有、按最长的名字算装不下时是 SERVFAIL（见
    /// `engine::response::txt_problem`），编好的 TXT 问什么名字都装得下 / What static_txt_response and
    /// replace_txt_response answer; SERVFAIL with no string, or when it does not fit for the
    /// longest name (see `engine::response::txt_problem`), so a TXT compiled fits whatever name
    /// is asked
    pub fn txt(text: &[String], ttl: Option<u32>) -> Self {
        if crate::engine::response::txt_problem(text).is_some() {
            return Self::Rcode(ResponseCode::ServFail);
        }
        Self::Records(StaticRecords::Txt {
            text: text.into(),
            ttl: ttl.unwrap_or(Self::DEFAULT_TTL),
        })
    }
}

/// 一个条件能让规则记在索引的哪一格 / Where in the index a condition can file a rule
enum IndexKey<'a> {
    Exact(&'a Arc<str>),
    Suffix(&'a str),
    Qtype(RecordType),
}

impl<'a> IndexKey<'a> {
    fn of(matcher: &'a RuntimeMatcher) -> Option<Self> {
        match matcher {
            RuntimeMatcher::DomainExact { value } if !value.is_empty() => Some(Self::Exact(value)),
            RuntimeMatcher::DomainSuffix { value } => {
                let suffix = domain_suffix_index_key(value);
                (!suffix.is_empty()).then_some(Self::Suffix(suffix))
            }
            RuntimeMatcher::Qtype { value } => Some(Self::Qtype(*value)),
            _ => None,
        }
    }

    /// 越小越挑：同一个名字只落在一格精确名字、几格后缀里，同一个类型却人人都问
    /// The smaller, the more selective: one name lands in one exact entry and a few suffix
    /// entries, while everyone asks for the same type
    fn rank(&self) -> u8 {
        match self {
            Self::Exact(_) => 0,
            Self::Suffix(_) => 1,
            Self::Qtype(_) => 2,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct RuleIndex {
    pub domain_exact: FxHashMap<Arc<str>, Vec<usize>>,
    pub domain_suffix: FxHashMap<Arc<str>, Vec<usize>>,
    pub query_type: FxHashMap<RecordType, Vec<usize>>,
    pub always_check: Vec<usize>,
}

impl RuleIndex {
    /// `rules` 的索引，规则按它们的位置记 / The index of `rules`, each rule filed by its place
    pub fn of(rules: &[RuntimeRule]) -> Self {
        let mut index = Self::default();
        for (idx, rule) in rules.iter().enumerate() {
            index.add_rule(idx, rule);
        }
        index
    }

    /// 「且」连起来的规则只在每个条件都成立时命中，记在哪个条件下都不会漏掉它；记在最挑的那个下，它当候选的次数最少：
    /// 先看精确的名字，再看后缀，最后看类型。以前记在第一个能记的条件下，写成「qtype A 且后缀 example.com」的规则，
    /// 每个 A 查询都要求值一遍
    /// A rule joined by "and" matches only when every condition holds, so filing it under any
    /// one of them never misses it; filed under the most selective one, it is a candidate the
    /// fewest times: an exact name first, then a suffix, then a type. It used to be filed under
    /// the first condition that could be, and a rule written "qtype A and suffix example.com" was
    /// evaluated for every A query
    fn add_rule(&mut self, rule_idx: usize, rule: &RuntimeRule) {
        let and_chain = rule
            .matchers
            .iter()
            .skip(1)
            .all(|m| matches!(m.operator, MatchOperator::And));
        let key = and_chain
            .then(|| {
                rule.matchers
                    .iter()
                    .filter_map(|m| IndexKey::of(&m.matcher))
                    .min_by_key(IndexKey::rank)
            })
            .flatten();
        match key {
            Some(IndexKey::Exact(value)) => self.domain_exact.entry(value.clone()).or_default(),
            Some(IndexKey::Suffix(suffix)) => {
                self.domain_suffix.entry(Arc::from(suffix)).or_default()
            }
            Some(IndexKey::Qtype(value)) => self.query_type.entry(value).or_default(),
            None => &mut self.always_check,
        }
        .push(rule_idx);
    }

    /// 可能命中 `qname`、`qtype` 的规则，按规则顺序排好、去掉重复；一般不超过 32 条，放在栈上
    /// The rules that can match `qname` and `qtype`, in rule order without duplicates; there
    /// are 32 at most as a rule, kept on the stack
    pub fn get_candidates(&self, qname: &str, qtype: RecordType) -> SmallVec<[usize; 32]> {
        let mut out = SmallVec::from_slice(&self.always_check);

        if let Some(indices) = self.domain_exact.get(qname) {
            out.extend_from_slice(indices);
        }

        let mut search_name = qname;
        loop {
            if let Some(indices) = self.domain_suffix.get(search_name) {
                out.extend_from_slice(indices);
            }
            if let Some(idx) = search_name.find('.') {
                search_name = &search_name[idx + 1..];
            } else {
                break;
            }
        }

        if let Some(indices) = self.query_type.get(&qtype) {
            out.extend_from_slice(indices);
        }

        out.sort_unstable();
        out.dedup();
        out
    }
}
