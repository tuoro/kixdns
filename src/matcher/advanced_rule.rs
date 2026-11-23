use std::net::IpAddr;
use std::sync::Arc;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{DNSClass, Record, RecordType};
use rustc_hash::FxHashMap;
use smallvec::SmallVec;

use crate::config::{Action, MatchOperator};
use crate::engine::utils::parse_rcode;
use crate::engine::{make_static_cname_answer, make_static_ip_answer, static_ips};
use crate::matcher::geoip::GeoIpManager;
use crate::matcher::{
    RuntimeMatcher, RuntimeMatcherWithOp, RuntimePipeline, RuntimePipelineConfig, RuntimeRule,
};
use crate::matcher::{domain_suffix_index_key, eval_match_chain};
use parking_lot::RwLock;

#[derive(Debug, Clone)]
pub struct CompiledPipeline {
    pub id: Arc<str>,
    pub rules: Vec<CompiledRule>,
    pub index: RuleIndex,
    /// 能当场决定的（见 `CompiledRule::precomputed`）最后一条规则的位置，一条都没有时为 None。快速路径求值候选规则到
    /// 这里为止：再往后不论哪条命中都只能交给完整路径，在快速路径上求值它们（正则、GeoIP）是白算一遍
    /// Where the last rule that decides on the spot (see `CompiledRule::precomputed`) is, None
    /// when there is none. The fast path evaluates candidate rules up to here: whichever matches
    /// beyond it goes to the full path anyway, and evaluating them on the fast path (a regex,
    /// GeoIP) was work done twice
    pub last_precomputed: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct CompiledRule {
    /// Rule name from the configuration, reported to observers on fast-path matches.
    /// 配置中的规则名，快速路径命中时上报给观察者。
    pub rule_name: Arc<str>,
    /// 规则的匹配器，和完整规则路径用的是同一份、同一个判断（`RuntimeMatcher::matches_with_qtype`），两条路径对规则
    /// 是否命中从不分歧。以前快速路径另有一份 `CompiledMatcher`，把每种匹配器重写了一遍
    /// The rule's matchers, the same ones the full rule path uses, judged the same way
    /// (`RuntimeMatcher::matches_with_qtype`), so the two paths never disagree on whether a rule
    /// matches. The fast path used to keep a `CompiledMatcher` of its own, every kind of
    /// matcher written out again
    pub matchers: Vec<RuntimeMatcherWithOp>,
    pub precomputed: Option<PrecomputedAction>,
    /// Whether a matcher needs GeoSite data, which the fast path leaves to the
    /// full rule path (see `fast_static_match_with_rule`).
    /// 是否有匹配器要用 GeoSite 数据；快速路径把这样的规则留给完整规则路径
    /// （见 `fast_static_match_with_rule`）。
    pub needs_geosite: bool,
}

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

#[derive(Debug, Clone, Default)]
pub struct RuleIndex {
    pub domain_exact: FxHashMap<Arc<str>, Vec<usize>>,
    pub domain_suffix: FxHashMap<Arc<str>, Vec<usize>>,
    pub query_type: FxHashMap<RecordType, Vec<usize>>,
    pub always_check: Vec<usize>,
}

impl RuleIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_rule(&mut self, rule_idx: usize, rule: &CompiledRule) {
        let and_chain = rule
            .matchers
            .iter()
            .skip(1)
            .all(|m| matches!(m.operator, MatchOperator::And));

        if !and_chain {
            self.always_check.push(rule_idx);
            return;
        }

        let mut indexed = false;
        for m in &rule.matchers {
            match &m.matcher {
                RuntimeMatcher::DomainExact { value } if !value.is_empty() => {
                    self.domain_exact
                        .entry(value.clone())
                        .or_default()
                        .push(rule_idx);
                    indexed = true;
                    break;
                }
                RuntimeMatcher::DomainSuffix { value }
                    if !domain_suffix_index_key(value.as_ref()).is_empty() =>
                {
                    self.domain_suffix
                        .entry(Arc::from(domain_suffix_index_key(value.as_ref())))
                        .or_default()
                        .push(rule_idx);
                    indexed = true;
                    break;
                }
                RuntimeMatcher::Qtype { value } => {
                    self.query_type.entry(*value).or_default().push(rule_idx);
                    indexed = true;
                    break;
                }
                _ => {}
            }
        }

        if !indexed {
            self.always_check.push(rule_idx);
        }
    }

    /// Get candidate rule indices into provided SmallVec to avoid allocation
    /// SmallVec<[usize; 32]> keeps up to 32 candidates on stack (typical case)
    pub fn get_candidates_into(
        &self,
        qname: &str,
        qtype: RecordType,
        out: &mut SmallVec<[usize; 32]>,
    ) {
        out.extend_from_slice(&self.always_check);

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
    }

    pub fn get_candidates(&self, qname: &str, qtype: RecordType) -> SmallVec<[usize; 32]> {
        let mut candidates = SmallVec::new();
        self.get_candidates_into(qname, qtype, &mut candidates);
        candidates
    }
}

pub fn compile_pipelines(cfg: &RuntimePipelineConfig) -> Vec<CompiledPipeline> {
    cfg.pipelines.iter().map(compile_pipeline).collect()
}

fn compile_pipeline(p: &RuntimePipeline) -> CompiledPipeline {
    let mut rules = Vec::with_capacity(p.rules.len());
    let mut index = RuleIndex::new();

    for (idx, rule) in p.rules.iter().enumerate() {
        let compiled = compile_rule(rule);
        index.add_rule(idx, &compiled);
        rules.push(compiled);
    }

    CompiledPipeline {
        id: p.id.clone(),
        last_precomputed: rules.iter().rposition(|rule| rule.precomputed.is_some()),
        rules,
        index,
    }
}

fn compile_rule(rule: &RuntimeRule) -> CompiledRule {
    CompiledRule {
        rule_name: rule.name.clone(),
        matchers: rule.matchers.clone(),
        precomputed: precompute_action(rule),
        needs_geosite: rule.matchers.iter().any(|m| {
            matches!(
                m.matcher,
                RuntimeMatcher::GeoSite { .. } | RuntimeMatcher::GeoSiteNot { .. }
            )
        }),
    }
}

fn precompute_action(rule: &RuntimeRule) -> Option<PrecomputedAction> {
    let answer = match rule.actions.first()? {
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
/// and without GeoIP data.
#[cfg(test)]
pub(crate) fn fast_static_match(
    pipeline: &CompiledPipeline,
    qname: &str,
    qtype: RecordType,
    qclass: DNSClass,
    client_ip: IpAddr,
    edns_present: bool,
) -> Option<crate::engine::Decision> {
    use crate::engine::Decision;
    fast_static_match_with_rule(
        pipeline,
        qname,
        qtype,
        qclass,
        client_ip,
        edns_present,
        None,
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
    pipeline: &'a CompiledPipeline,
    qname: &str,
    qtype: RecordType,
    qclass: DNSClass,
    client_ip: IpAddr,
    edns_present: bool,
    geoip: Option<&Arc<RwLock<GeoIpManager>>>,
) -> Option<(&'a PrecomputedAction, &'a str)> {
    let last = pipeline.last_precomputed?;
    let candidates = pipeline.index.get_candidates(qname, qtype);
    // 候选按规则顺序排好（见 `RuleIndex::get_candidates_into`）/ Candidates come in rule order (see
    // `RuleIndex::get_candidates_into`)
    for idx in candidates.into_iter().take_while(|&idx| idx <= last) {
        let rule = &pipeline.rules[idx];
        // GeoSite matching can scan a whole tag for a name it has not seen, and
        // the fast path runs before a request is admitted, so a rule that needs
        // it is left to the full rule path, which also keeps the rule order.
        // GeoSite 匹配遇到没见过的域名可能要扫描整个标签，而快速路径运行在请求被准入
        // 之前，所以用到它的规则留给完整规则路径，规则顺序也由那里保持。
        if rule.needs_geosite {
            return None;
        }
        // GeoIP 和完整规则路径一样求值；GeoSite 走不到这里（见 `CompiledRule::needs_geosite`）
        // GeoIP is evaluated as on the full rule path; GeoSite never gets here (see
        // `CompiledRule::needs_geosite`)
        let matched = eval_match_chain(
            &rule.matchers,
            |m| m.operator,
            |m| {
                m.matcher.matches_with_qtype(
                    qname,
                    qclass,
                    client_ip,
                    edns_present,
                    qtype,
                    geoip,
                    None,
                )
            },
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
                .map(|action| (action, &*rule.rule_name));
        }
    }
    None
}
