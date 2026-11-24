use std::net::IpAddr;
use std::sync::Arc;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{DNSClass, Record, RecordType};
use rustc_hash::FxHashMap;
use smallvec::SmallVec;

use crate::config::{Action, MatchOperator};
use crate::engine::{make_static_cname_answer, make_static_ip_answer, static_ips};
use crate::matcher::{GeoManagers, RequestFacts, RuntimeMatcher, RuntimePipeline, RuntimeRule};
use crate::matcher::{domain_suffix_index_key, eval_match_chain, parse_rcode};

/// 规则当场作出的决定：照配置写好的应答，或跳到另一个 pipeline，快速路径跟过去在那里接着查
/// What a rule decides on the spot: an answer as the configuration writes it, or a jump to
/// another pipeline, which the fast path follows to go on looking there
#[derive(Debug, Clone)]
pub enum PrecomputedAction {
    Answer(PrecomputedAnswer),
    Jump(Arc<str>),
}

/// 照配置写好、当场就能给的应答 / An answer as the configuration writes it, ready on the spot
#[derive(Debug, Clone)]
pub enum PrecomputedAnswer {
    Static {
        rcode: ResponseCode,
    },
    StaticIp {
        ip: String,
        /// `ip` 读出的地址，每个查询不用再读一遍；读不出来时为 None / The addresses `ip` holds, so no query reads it
        /// again; None when it cannot be read
        addresses: Option<Box<[IpAddr]>>,
    },
    StaticCname {
        target: String,
        ttl: u32,
    },
}

impl PrecomputedAnswer {
    /// 这个应答对这个查询给的应答码和记录 / The response code and records this answer gives this query
    pub(crate) fn records(
        &self,
        qname: &str,
        qtype: RecordType,
        qclass: DNSClass,
    ) -> (ResponseCode, Vec<Record>) {
        match self {
            Self::Static { rcode } => (*rcode, Vec::new()),
            Self::StaticIp { ip, .. } => make_static_ip_answer(qname, qtype, qclass, ip),
            Self::StaticCname { target, ttl } => {
                make_static_cname_answer(qname, qclass, target, *ttl)
            }
        }
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

/// 规则当场作出的决定：第一个动作是照配置写好的应答或跳转时就是它，别的（转发、先记日志的）为 None
/// What a rule decides on the spot: its first action when that is an answer as the
/// configuration writes it or a jump, None otherwise (a forward, one logging first)
pub(super) fn precompute_action(actions: &[Action]) -> Option<PrecomputedAction> {
    let answer = match actions.first()? {
        Action::StaticResponse { rcode } => PrecomputedAnswer::Static {
            rcode: parse_rcode(rcode)?,
        },
        Action::StaticIpResponse { ip } => PrecomputedAnswer::StaticIp {
            ip: ip.clone(),
            addresses: static_ips(ip).map(Vec::into_boxed_slice),
        },
        Action::StaticCnameResponse { target, ttl } => PrecomputedAnswer::StaticCname {
            target: target.clone(),
            ttl: ttl.unwrap_or(300),
        },
        Action::Deny => PrecomputedAnswer::Static {
            rcode: ResponseCode::Refused,
        },
        Action::JumpToPipeline { pipeline } => {
            return Some(PrecomputedAction::Jump(Arc::clone(pipeline)));
        }
        _ => return None,
    };
    Some(PrecomputedAction::Answer(answer))
}

/// Test-only shorthand for [`fast_static_match_with_rule`] without the rule name
/// and without Geo data.
#[cfg(test)]
pub(crate) fn fast_static_match(
    pipeline: &RuntimePipeline,
    qname: &str,
    qtype: RecordType,
    qclass: DNSClass,
    client_ip: IpAddr,
    edns_present: bool,
) -> Option<crate::engine::Decision> {
    use crate::engine::Decision;
    fast_static_match_with_rule(
        pipeline,
        &RequestFacts {
            qname,
            qtype,
            qclass,
            client_ip,
            edns_present,
        },
        GeoManagers::empty(),
    )
    .map(|(action, _)| match action {
        PrecomputedAction::Answer(answer) => {
            let (rcode, answers) = answer.records(qname, qtype, qclass);
            Decision::Static { rcode, answers }
        }
        PrecomputedAction::Jump(pipeline) => Decision::Jump {
            pipeline: Arc::clone(pipeline),
        },
    })
}

/// Like [`fast_static_match`], giving the matched rule's action instead of a decision, so that a
/// caller who can answer from it need not make the records, and the name of that rule.
/// 同 [`fast_static_match`]，但给出命中规则的动作而不是决策（能直接按动作回答的就不必做记录），以及规则名。
pub(crate) fn fast_static_match_with_rule<'a>(
    pipeline: &'a RuntimePipeline,
    facts: &RequestFacts<'_>,
    geo: GeoManagers<'_>,
) -> Option<(&'a PrecomputedAction, &'a str)> {
    let last = pipeline.last_precomputed?;
    let candidates = pipeline.index.get_candidates(facts.qname, facts.qtype);
    // 候选按规则顺序排好（见 `RuleIndex::get_candidates`）/ Candidates come in rule order (see
    // `RuleIndex::get_candidates`)
    for idx in candidates.into_iter().take_while(|&idx| idx <= last) {
        let rule = &pipeline.rules[idx];
        let matched = eval_match_chain(
            &rule.matchers,
            |m| m.operator,
            |m| m.matcher.matches(facts, geo),
        );
        if matched {
            // 第一条命中的规则定下结果：不能当场决定的（转发、先记日志的）连同规则顺序一起留给完整路径，
            // 「domain_regex → forward」不会被后面的「domain_suffix → static_ip」越过
            // The first rule matching settles it: one that does not decide on the spot (a
            // forward, one logging first) is left to the full path with the rule order, so a
            // "domain_regex → forward" is not passed over for a later "domain_suffix → static_ip"
            return rule
                .precomputed
                .as_ref()
                .map(|action| (action, &*rule.name));
        }
    }
    None
}
