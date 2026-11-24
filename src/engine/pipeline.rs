use std::sync::Arc;
use std::time::Instant;

use hickory_proto::op::ResponseCode;
use smallvec::SmallVec;

use crate::config::{Action, Transport};
use crate::matcher::{
    GeoManagers, RequestFacts, Requester, RuntimePipeline, RuntimePipelineConfig, eval_match_chain,
    parse_rcode,
};

use super::core::Engine;
use super::observation::{
    Observed, decision_kind, report_decision, report_matched_rules, report_rule_cache_hit,
};
use super::rules::Decision;
use super::rules::{RULE_CACHE_MAX_AGE, RuleCacheEntry, RuleCacheRecord, RuleQuestion};
use super::types::EngineInner;
use super::{make_static_cname_answer, make_static_ip_answer, make_static_txt_answer};
use crate::observe::{RuleCacheLookup, RuleEvaluated, RulePhase};

/// `cfg` 给从 `listener_label` 进来的请求 `facts` 选的 pipeline：第一条命中的 pipeline_select，都不命中时是第一个
/// pipeline；匹配器要用 Geo 数据时才拿读锁（见 `GeoManagers`）
/// The pipeline `cfg` picks for request `facts` come in at `listener_label`: that of the first
/// pipeline_select matching, the first pipeline when none does; a matcher read-locks Geo data
/// only to use it (see `GeoManagers`)
pub fn select_pipeline<'a>(
    cfg: &'a RuntimePipelineConfig,
    listener_label: &str,
    facts: &RequestFacts<'_>,
    geo: GeoManagers<'_>,
) -> Option<&'a RuntimePipeline> {
    for rule in &cfg.pipeline_select {
        let matched = eval_match_chain(
            &rule.matchers,
            |m| m.operator,
            |m| m.matcher.matches(listener_label, facts, geo),
        );
        if matched && let Some(p) = cfg.pipeline(&rule.pipeline) {
            return Some(p);
        }
    }

    cfg.pipelines.first()
}

/// 没有 Pipeline 时用的名字 / The name used with no pipeline
pub(crate) const NO_PIPELINE: &str = "default";

/// 一次规则求值自己的设定，请求本身见 [`RequestFacts`] / What one rule evaluation is set to do, the
/// request itself being [`RequestFacts`]
pub struct RuleEvaluationContext<'a> {
    /// 从规则组里第几条规则（从 0 起）求值：continue 以后是被越过的那条规则的下一条，它之前的规则这个请求都已经求值过
    /// （见 `Route::resume_at`）；0 是求值整个规则组
    /// The place in the pipeline (from 0) of the rule evaluation starts at: after a continue the
    /// one after the rule continued past, every rule before it evaluated for this request
    /// already (see `Route::resume_at`); 0 to evaluate the whole pipeline
    pub resume_at: usize,
    /// 后台刷新：求值整条 pipeline，不读规则缓存，照常写入决策
    /// A background refresh: the whole pipeline is evaluated, the rule cache is not read,
    /// and the decision is written as usual
    pub background_refresh: bool,
    /// Observer context of the request being evaluated; `None` disables
    /// rule-match events. / 所属请求的观察者上下文；None 时不上报规则命中。
    pub observed: Observed<'a>,
}

impl<'a> RuleEvaluationContext<'a> {
    pub fn new(resume_at: usize, background_refresh: bool) -> Self {
        Self {
            resume_at,
            background_refresh,
            observed: None,
        }
    }

    /// Attach the observer context of the request so rule matches are reported.
    pub fn with_observed(mut self, observed: Observed<'a>) -> Self {
        self.observed = observed;
        self
    }
}

impl Engine {
    /// `pipeline` 对请求 `facts` 在规则缓存里的问题，按规则对请求方的判定（见 [`RuleQuestion`]）。规则的决定从不取决于
    /// ECS：规则缓存的判定只有请求匹配器的那些（见 `RuntimePipeline::rule_requester`），它们只看请求的事实
    /// The rule cache question of `pipeline` for request `facts`, by how the rules judge the
    /// requester (see [`RuleQuestion`]). Rule decisions never depend on ECS: the rule cache
    /// judges by the request matchers alone (see `RuntimePipeline::rule_requester`), which read
    /// the request's facts and nothing more
    pub(crate) fn rule_question<'a>(
        &self,
        cache_namespace: u64,
        pipeline: &'a RuntimePipeline,
        facts: &RequestFacts<'a>,
    ) -> RuleQuestion<'a> {
        let requester = Requester {
            address: facts.client_ip,
            edns: facts.edns_present,
            ecs: None,
        };
        RuleQuestion::new(
            cache_namespace,
            &pipeline.id,
            facts.qname,
            facts.qtype,
            facts.qclass,
            pipeline
                .rule_requester
                .key(requester, Some(&self.geoip_manager)),
        )
    }

    /// 规则缓存里给 `question`、在 `now` 这一刻还有效的决定。过期的这里不去掉：求值以后原地写回，它在淘汰队列里的位置
    /// 还在，写不回的由清扫去掉。快速路径和完整路径都从这里查
    /// The rule cache's decision for `question`, still valid at `now`. An expired one is not
    /// removed here: written back after evaluating, it keeps its place in the eviction queues,
    /// and one that is not goes with the sweep. The fast path and the full path both look here
    pub(crate) fn cached_decision(
        &self,
        question: &RuleQuestion<'_>,
        now: Instant,
    ) -> Option<Arc<RuleCacheRecord>> {
        self.rule_cache
            .get(question.key)
            .filter(|record| record.entry.answers(question, now))
    }

    /// 把求值给 `question` 作出的决定存进规则缓存，留 [`RULE_CACHE_MAX_AGE`]：静态应答、跳转、转发都一样，带回答检查的
    /// 转发也是，检查看的是每次上游给的应答，规则缓存只替请求阶段记下由哪条规则去转发。`matched_rules` 是求值时命中的
    /// 规则，只在有观察者时记下
    /// Store the decision evaluating made for `question` in the rule cache, for
    /// [`RULE_CACHE_MAX_AGE`]: static answers, jumps and forwards alike, one with an answer check
    /// too, the check reading each answer the upstream gives and the rule cache only standing in
    /// for the request phase naming the rule that forwards. `matched_rules` are the rules that
    /// matched on the way, kept only with an observer
    pub(crate) fn insert_rule_cache(
        &self,
        question: &RuleQuestion<'_>,
        decision: Decision,
        matched_rules: Option<&[Arc<str>]>,
        decided_by_rule: bool,
    ) {
        let expires_at = Instant::now() + RULE_CACHE_MAX_AGE;
        self.rule_cache.insert(
            question.key,
            Arc::new(RuleCacheRecord {
                entry: RuleCacheEntry::new(question, decision, expires_at),
                matched_rules: matched_rules.map(Arc::from),
                decided_by_rule,
            }),
        );
    }

    pub fn apply_rules(
        &self,
        state: &EngineInner,
        pipeline: &RuntimePipeline,
        facts: &RequestFacts<'_>,
        request: &RuleEvaluationContext<'_>,
    ) -> Decision {
        let RuleEvaluationContext {
            resume_at,
            background_refresh,
            ..
        } = *request;
        // 1. Check Rule Cache
        let question = self.rule_question(state.cache_namespace(&pipeline.id), pipeline, facts);
        // Resuming after a continue, this evaluation does not give the pipeline's decision
        // for the name, so it neither reads nor writes the rule cache. A background refresh
        // evaluates the whole pipeline: it does not read the cache but still writes its
        // decision.
        // continue 以后接着求值时，得出的不是这个 pipeline 对这个名字的决策，所以既不读也不写规则缓存。后台刷新求值的
        // 是整条 pipeline：不读缓存，但照常写入决策。
        let whole_pipeline = resume_at == 0;
        let allow_rule_cache_lookup = !background_refresh && whole_pipeline;

        if allow_rule_cache_lookup
            && let Some(record) = self.cached_decision(&question, Instant::now())
        {
            if let Some((observer, ctx)) = request.observed {
                report_rule_cache_hit(observer, ctx, &pipeline.id, &record, false);
            }
            return record.entry.decision.clone();
        }
        if allow_rule_cache_lookup && let Some((observer, ctx)) = request.observed {
            observer.rule_cache_lookup(
                ctx,
                &RuleCacheLookup {
                    pipeline: &pipeline.id,
                    hit: false,
                    matched_rules: 0,
                },
            );
        }

        // 2. Evaluate rules in order; None means no rule decided and the
        //    default upstream applies.
        // 2. 按顺序求值规则；None 表示没有规则做出决策，使用默认上游。
        let mut matched_rules: SmallVec<[Arc<str>; 4]> = SmallVec::new();
        let mut logged = false;
        let decided = self.evaluate_rules(
            state,
            pipeline,
            facts,
            request,
            &mut matched_rules,
            &mut logged,
        );
        let decided_by_rule = decided.is_some();
        let decision =
            decided.unwrap_or_else(|| Decision::default_forward(&state.pipeline.settings));

        if let Some((observer, ctx)) = request.observed {
            report_matched_rules(
                observer,
                ctx,
                &pipeline.id,
                &matched_rules,
                decided_by_rule.then(|| decision_kind(&decision)),
                false,
            );
            report_decision(
                observer,
                ctx,
                &pipeline.id,
                decided_by_rule
                    .then(|| matched_rules.last())
                    .flatten()
                    .map(AsRef::as_ref),
                &decision,
            );
        }
        // 规则直接回应的决定和跳转都存：快速路径靠前者回重复的查询，跟着后者到目标 pipeline 里去查（跳转不带记录，存一条
        // 很便宜）；转发只在有正则条件的 pipeline 里存，别的 pipeline 重算一遍比存一条缓存便宜（见
        // `RuntimePipeline::matches_regex`）。求值时执行了 log 动作的决定不存：规则缓存替求值给出决定，命中时不执行规则的
        // 动作，log 动作就不再记下这些查询
        // A rule's own answer and a jump are always kept: the fast path answers repeated queries from
        // the former and follows the latter to look in its target pipeline (a jump carries no records,
        // cheap to keep); a forward decision is kept only in a pipeline with regex conditions, since
        // elsewhere computing it again is cheaper than storing an entry (see
        // `RuntimePipeline::matches_regex`). A decision whose evaluation ran a log action is not kept:
        // the rule cache gives the decision in place of evaluating, running none of the rules' actions
        // on a hit, and the log action would no longer record those queries
        let worth_keeping =
            !logged && (pipeline.matches_regex || !matches!(decision, Decision::Forward { .. }));
        if whole_pipeline && worth_keeping {
            self.insert_rule_cache(
                &question,
                decision.clone(),
                request.observed.map(|_| &matched_rules[..]),
                decided_by_rule,
            );
        }
        decision
    }

    /// Evaluate `pipeline`'s rules in order for `facts` as `request` says. Returns the first
    /// decision, or `None` when every matching rule continued. The names of
    /// the rules whose matchers matched are appended to `matched_rules`, and
    /// `logged` is set once a log action runs.
    /// 按顺序求值规则：返回第一个决策，所有命中规则都继续时返回 None。
    /// 匹配器命中的规则名追加到 `matched_rules`，执行了 log 动作就把 `logged` 置上。
    fn evaluate_rules(
        &self,
        state: &EngineInner,
        pipeline: &RuntimePipeline,
        facts: &RequestFacts<'_>,
        request: &RuleEvaluationContext<'_>,
        matched_rules: &mut SmallVec<[Arc<str>; 4]>,
        logged: &mut bool,
    ) -> Option<Decision> {
        let RequestFacts {
            qname,
            qtype,
            qclass,
            client_ip,
            ..
        } = *facts;
        let resume_at = request.resume_at;
        // 2. Candidate Selection: the pipeline's index gives every rule that can match (see
        // `RuleIndex::add_rule`)
        // 2. 候选规则：pipeline 的索引给出所有可能命中的规则（见 `RuleIndex::add_rule`）
        // SmallVec<[usize; 32]> avoids heap allocation for typical rule sets (<= 32 candidates)
        let candidate_indices: SmallVec<[usize; 32]> = pipeline.index.get_candidates(qname, qtype);

        // 3. Execute Rules
        let geo = self.geo();

        'rules: for idx in candidate_indices {
            // continue 越过的规则和它之前的都已经求值过 / The rule a continue passed and those
            // before it have been evaluated already
            if idx < resume_at {
                continue;
            }
            // 候选出自这个 pipeline 自己的索引 / The candidates come from this pipeline's own index
            let rule = &pipeline.rules[idx];
            let req_match = eval_match_chain(
                &rule.matchers,
                |m| m.operator,
                |m| m.matcher.matches(facts, geo),
            );
            if let Some((observer, observed_ctx)) = request.observed {
                observer.rule_evaluated(
                    observed_ctx,
                    &RuleEvaluated {
                        pipeline: &pipeline.id,
                        rule: &rule.name,
                        phase: RulePhase::Request,
                        matched: req_match,
                        matchers: rule.matchers.len(),
                    },
                );
            }

            if req_match {
                // Names are only needed for observers; skip the clone otherwise
                // 规则名只有观察者需要，无观察者时不做克隆
                if request.observed.is_some() {
                    matched_rules.push(rule.name.clone());
                }
                for action in &rule.actions {
                    match action {
                        Action::StaticResponse { rcode } => {
                            let code = parse_rcode(rcode).unwrap_or(ResponseCode::NXDomain);
                            let d = Decision::Static {
                                rcode: code,
                                answers: Vec::new(),
                            };
                            return Some(d);
                        }
                        Action::StaticIpResponse { ip } => {
                            let (rcode, answers) = make_static_ip_answer(qname, qtype, qclass, ip);
                            let d = Decision::Static { rcode, answers };
                            return Some(d);
                        }
                        Action::StaticCnameResponse { target, ttl } => {
                            let (rcode, answers) =
                                make_static_cname_answer(qname, qclass, target, ttl.unwrap_or(300));
                            let d = Decision::Static { rcode, answers };
                            return Some(d);
                        }
                        Action::JumpToPipeline { pipeline: target } => {
                            let d = Decision::Jump {
                                pipeline: Arc::clone(target),
                            };
                            return Some(d);
                        }
                        Action::Allow => {
                            return Some(Decision::allow(
                                &state.pipeline.settings,
                                rule.name.clone(),
                                idx,
                            ));
                        }
                        Action::Deny => {
                            let d = Decision::Static {
                                rcode: ResponseCode::Refused,
                                answers: Vec::new(),
                            };
                            return Some(d);
                        }
                        Action::Forward {
                            upstream,
                            transport,
                            ecs,
                            pre_split_upstreams,
                            upstream_shared,
                        } => {
                            // 规则写了几个 forward 时，轮到头一个就照配置加载时合并好的一起问（见
                            // `Rule::compute_merged_forward`），每个上游的传输写在它自己的地址里，没写前缀的用 UDP；
                            // 写在前面的 log 和只有一个 forward 时一样已经执行过。以前合并的转发在执行动作之前就给出，
                            // 这样的规则 log 从不执行
                            // With several forwards written, the first one's turn asks them all as merged
                            // at config load (see `Rule::compute_merged_forward`), each upstream's
                            // transport written in its own address, UDP for one without a scheme; a log
                            // written before has run, as with a single forward. The merged forward used to
                            // be given before any action ran, and the log of such a rule never did
                            let (upstream, pre_split_upstreams, transport, ecs) =
                                match &rule.merged_forward {
                                    Some(merged) => (
                                        merged.upstream_str.clone(),
                                        Some(merged.upstream_list.clone()),
                                        Transport::Udp,
                                        merged.ecs.clone(),
                                    ),
                                    None => (
                                        match (upstream_shared, upstream) {
                                            (Some(shared), _) => Arc::clone(shared),
                                            (None, Some(upstream)) => Arc::from(upstream.as_str()),
                                            (None, None) => {
                                                state.pipeline.settings.default_upstream_arc()
                                            }
                                        },
                                        pre_split_upstreams.clone(),
                                        transport.unwrap_or(Transport::Udp),
                                        ecs.clone(),
                                    ),
                                };
                            return Some(Decision::Forward {
                                upstream,
                                pre_split_upstreams,
                                response_phase: rule.response_phase.clone(),
                                rule_name: rule.name.clone(),
                                rule_index: Some(idx),
                                transport,
                                ecs,
                                allow_reuse: false,
                            });
                        }
                        Action::Log { level } => {
                            super::rules::log_match(level.as_deref(), &rule.name, qname, client_ip);
                            *logged = true;
                        }
                        Action::StaticTxtResponse { text, ttl } => {
                            // 和响应阶段一样：装不进一条记录的文本回 SERVFAIL
                            // As in the response phase: text that does not fit a record is
                            // answered SERVFAIL
                            let (rcode, answers) = make_static_txt_answer(
                                qname,
                                qtype,
                                qclass,
                                text,
                                ttl.unwrap_or(300),
                            );
                            return Some(Decision::Static { rcode, answers });
                        }
                        Action::ReplaceTxtResponse { .. } => {
                            continue 'rules;
                        }
                        Action::Continue => {
                            continue 'rules;
                        }
                    }
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod observer_rule_cache_tests {
    use std::sync::Arc;

    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};

    use crate::config::PipelineConfig;
    use crate::engine::Engine;
    use crate::matcher::RuntimePipelineConfig;
    use crate::observe::NoopObserver;

    fn runtime() -> RuntimePipelineConfig {
        let raw = serde_json::json!({
            "settings": { "default_upstream": "127.0.0.1:9", "min_ttl": 0 },
            "pipelines": [{
                "id": "main",
                "rules": [{
                    "name": "block",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "static_response", "rcode": "NXDOMAIN" }]
                }]
            }]
        });
        let cfg: PipelineConfig = serde_json::from_value(raw).expect("parse config");
        RuntimePipelineConfig::from_config(cfg).expect("runtime config")
    }

    fn query() -> Vec<u8> {
        let mut message = Message::new(1, MessageType::Query, OpCode::Query);
        message.add_query(Query::query(
            Name::from_str_relaxed("example.com").unwrap(),
            RecordType::A,
        ));
        message.to_vec().unwrap()
    }

    /// Collect the `matched_rules` of every rule cache record after one request.
    async fn recorded_rules(engine: Engine) -> Vec<Option<usize>> {
        engine
            .handle_packet(&query(), "127.0.0.1:53000".parse().unwrap())
            .await
            .expect("static answer");
        engine
            .rule_cache
            .values()
            .iter()
            .map(|record| record.matched_rules.as_ref().map(|rules| rules.len()))
            .collect()
    }

    #[tokio::test]
    async fn rule_cache_records_no_rule_names_without_observer() {
        let engine = Engine::new(runtime(), "test".to_string()).expect("engine");
        let records = recorded_rules(engine).await;
        assert!(
            !records.is_empty(),
            "the request must populate the rule cache"
        );
        assert!(
            records.iter().all(Option::is_none),
            "matched_rules must stay None without an observer: {records:?}"
        );
    }

    #[tokio::test]
    async fn rule_cache_records_rule_names_with_observer() {
        let engine = Engine::builder(runtime())
            .observer(Arc::new(NoopObserver))
            .build()
            .expect("engine");
        let records = recorded_rules(engine).await;
        assert_eq!(records, vec![Some(1)]);
    }
}

#[cfg(test)]
mod continued_rule_cache_tests {
    use super::RuleEvaluationContext;
    use crate::engine::Engine;
    use crate::engine::rules::Decision;
    use crate::engine::test_support::engine_from;
    use crate::matcher::RequestFacts;

    /// `first` forwards and continues on a miss; `next` forwards elsewhere. `first` matches by
    /// regex: only a pipeline with regex conditions keeps forward decisions in the rule cache.
    /// `first` 转发，未命中时 continue；`next` 转发到别处。`first` 用正则条件：只有带正则条件的
    /// pipeline 才把转发决定存进规则缓存。
    fn engine() -> Engine {
        engine_from(serde_json::json!({
            "settings": { "default_upstream": "127.0.0.1:9", "min_ttl": 60 },
            "pipelines": [{
                "id": "main",
                "rules": [
                    {
                        "name": "first",
                        "matchers": [{ "type": "domain_regex", "value": "example" }],
                        "actions": [{ "type": "forward", "upstream": "127.0.0.1:9" }],
                        "response_actions_on_miss": [{ "type": "continue" }]
                    },
                    {
                        "name": "next",
                        "matchers": [{ "type": "any" }],
                        "actions": [{ "type": "forward", "upstream": "127.0.0.1:10" }]
                    }
                ]
            }]
        }))
    }

    fn rule_of(decision: &Decision) -> &str {
        match decision {
            Decision::Forward { rule_name, .. } => rule_name,
            other => panic!("expected a forward decision, got {other:?}"),
        }
    }

    /// continue 之后，决策循环从越过的规则后面接着求值。那时得出的决策不是这个 pipeline 对这个名字的决策，不进规则缓存：
    /// 进了的话，在缓存过期前（最长 60 秒）之后的请求都直接从 `next` 开始，不经过 `first`。
    /// After a continue, the decision loop resumes evaluating after the rule it passed. The
    /// decision it reaches then is not the pipeline's decision for the name and stays out of
    /// the rule cache: written there, later requests would start at `next` and skip `first`
    /// until that entry expired (up to 60 s).
    #[tokio::test]
    async fn a_decision_reached_after_a_continue_is_not_cached() {
        let engine = engine();
        let state = engine.state.load_full();
        let pipeline = &state.pipeline.pipelines[0];
        let facts = RequestFacts::a_query("example.com");
        let request = |resume_at| RuleEvaluationContext::new(resume_at, false);

        let after_continue = engine.apply_rules(&state, pipeline, &facts, &request(1));
        assert_eq!(rule_of(&after_continue), "next");

        let fresh = engine.apply_rules(&state, pipeline, &facts, &request(0));
        assert_eq!(
            rule_of(&fresh),
            "first",
            "a new request must start at the first rule again"
        );

        // 正常求值的决策照常缓存 / A decision from a normal evaluation is still cached
        let cached: Vec<_> = engine
            .rule_cache
            .values()
            .iter()
            .map(|record| rule_of(&record.entry.decision).to_owned())
            .collect();
        assert_eq!(cached, ["first"]);
    }
}

/// 规则缓存存什么：规则直接回应的决定（快速路径靠它回重复的拦截查询）和跳转（快速路径跟着它到目标里去查）都存；转发决定只在
/// 带正则条件的 pipeline 里存，别处重算一遍比为每个新名字存一条缓存便宜。
/// What the rule cache keeps: a rule's own answer (the fast path answers repeated blocked
/// queries from it) and a jump (the fast path follows it to look in the target) always; a
/// forward decision only in a pipeline with regex conditions, since elsewhere computing it again
/// is cheaper than storing an entry for every new name.
#[cfg(test)]
mod rule_cache_policy_tests {
    use std::sync::Arc;
    use std::time::Instant;

    use hickory_proto::rr::{DNSClass, RecordType};

    use super::RuleEvaluationContext;
    use crate::engine::Engine;
    use crate::engine::rules::{Decision, RULE_CACHE_MAX_AGE, calculate_rule_hash};
    use crate::engine::test_support::engine_from;
    use crate::matcher::{RequestFacts, RequesterKey};

    /// `plain` pipeline 只有后缀和 any 条件，`regex` pipeline 带正则条件
    /// The `plain` pipeline has suffix and any conditions only, the `regex` one a regex condition
    fn engine() -> Engine {
        engine_from(serde_json::json!({
            "settings": { "default_upstream": "127.0.0.1:9" },
            "pipelines": [
                {
                    "id": "plain",
                    "rules": [
                        {
                            "name": "block",
                            "matchers": [{ "type": "domain_suffix", "value": "ads.example" }],
                            "actions": [{ "type": "static_response", "rcode": "NXDOMAIN" }]
                        },
                        {
                            "name": "elsewhere",
                            "matchers": [{ "type": "domain_suffix", "value": "jump.example" }],
                            "actions": [{ "type": "jump_to_pipeline", "pipeline": "regex" }]
                        },
                        {
                            "name": "rest",
                            "matchers": [{ "type": "any" }],
                            "actions": [{ "type": "forward", "upstream": "127.0.0.1:9" }]
                        }
                    ]
                },
                {
                    "id": "regex",
                    "rules": [
                        {
                            "name": "www",
                            "matchers": [{ "type": "domain_regex", "value": "^www\\." }],
                            "actions": [{ "type": "forward", "upstream": "127.0.0.1:9" }]
                        },
                        {
                            "name": "rest",
                            "matchers": [{ "type": "any" }],
                            "actions": [{ "type": "forward", "upstream": "127.0.0.1:9" }]
                        }
                    ]
                }
            ]
        }))
    }

    #[tokio::test]
    async fn own_answers_and_jumps_are_kept_and_forwards_only_where_regexes_run() {
        let engine = engine();
        let state = engine.state.load_full();
        let [plain, regex] = [0, 1].map(|index| &state.pipeline.pipelines[index]);
        assert!(!plain.matches_regex);
        assert!(regex.matches_regex);
        let ask = |pipeline, name| {
            let request = RuleEvaluationContext::new(0, false);
            engine.apply_rules(&state, pipeline, &RequestFacts::a_query(name), &request)
        };
        assert!(matches!(ask(plain, "ads.example"), Decision::Static { .. }));
        assert!(matches!(ask(plain, "jump.example"), Decision::Jump { .. }));
        assert!(matches!(
            ask(plain, "example.com"),
            Decision::Forward { .. }
        ));
        assert!(matches!(
            ask(regex, "www.example.com"),
            Decision::Forward { .. }
        ));
        assert!(matches!(
            ask(regex, "example.com"),
            Decision::Forward { .. }
        ));

        let mut kept: Vec<(String, &str)> = engine
            .rule_cache
            .values()
            .iter()
            .map(|record| {
                let kind = match &record.entry.decision {
                    Decision::Static { .. } => "static",
                    Decision::Forward { .. } => "forward",
                    Decision::Jump { .. } => "jump",
                };
                (record.entry.pipeline_id.to_string(), kind)
            })
            .collect();
        kept.sort();
        assert_eq!(
            kept,
            [
                ("plain".to_owned(), "jump"),
                ("plain".to_owned(), "static"),
                ("regex".to_owned(), "forward"),
                ("regex".to_owned(), "forward"),
            ]
        );
    }

    /// 落到同一个键上的决定是给别的名字的，就不拿来用：该转发的名字不会照着别人的决定被拦下
    /// A decision on the same key but for another name is not used: a name to be forwarded is not blocked
    /// on another's decision
    #[tokio::test]
    async fn a_decision_for_another_name_on_the_same_key_is_not_used() {
        let engine = engine();
        let state = engine.state.load_full();
        let plain = &state.pipeline.pipelines[0];
        let ask = |name| {
            let request = RuleEvaluationContext::new(0, false);
            engine.apply_rules(&state, plain, &RequestFacts::a_query(name), &request)
        };
        let key_of = |name| {
            calculate_rule_hash(
                state.cache_namespace("plain"),
                "plain",
                name,
                RecordType::A,
                DNSClass::IN,
                &RequesterKey::NONE,
            )
        };
        assert!(matches!(ask("ads.example"), Decision::Static { .. }));
        let block = engine
            .rule_cache
            .get(key_of("ads.example"))
            .expect("cached");
        engine.rule_cache.insert(key_of("example.com"), block);
        assert!(matches!(ask("example.com"), Decision::Forward { .. }));
    }

    /// 每个决策在规则缓存里都用 `RULE_CACHE_MAX_AGE`：静态回答、跳转、转发都一样，静态回答的记录 TTL 比它短、是 0
    /// 也一样，规则下次求值给的还是同一份
    /// Every decision serves from the rule cache for `RULE_CACHE_MAX_AGE`: static answers, jumps
    /// and forwards alike, a static answer whose records' TTL is shorter, or 0, too, the rules
    /// giving the same answer when evaluated again
    #[tokio::test]
    async fn every_decision_lasts_the_rule_cache_max_age() {
        let engine = engine_from(serde_json::json!({
            "settings": { "default_upstream": "127.0.0.1:9" },
            "pipelines": [
                {
                    "id": "main",
                    "rules": [
                        {
                            "name": "block",
                            "matchers": [{ "type": "domain_suffix", "value": "ads.example" }],
                            "actions": [{ "type": "static_response", "rcode": "NXDOMAIN" }]
                        },
                        {
                            "name": "short",
                            "matchers": [{ "type": "domain_suffix", "value": "short.example" }],
                            "actions": [{ "type": "static_cname_response", "target": "a.test.", "ttl": 5 }]
                        },
                        {
                            "name": "uncached",
                            "matchers": [{ "type": "domain_suffix", "value": "zero.example" }],
                            "actions": [{ "type": "static_cname_response", "target": "a.test.", "ttl": 0 }]
                        },
                        {
                            "name": "elsewhere",
                            "matchers": [{ "type": "domain_suffix", "value": "jump.example" }],
                            "actions": [{ "type": "jump_to_pipeline", "pipeline": "other" }]
                        },
                        {
                            // 有正则的 pipeline 才缓存转发 / Only a pipeline with regexes caches forwards
                            "name": "www",
                            "matchers": [{ "type": "domain_regex", "value": "^www\\." }],
                            "actions": [{ "type": "forward", "upstream": "127.0.0.1:9" }]
                        },
                        {
                            "name": "rest",
                            "matchers": [{ "type": "any" }],
                            "actions": [{ "type": "forward", "upstream": "127.0.0.1:9" }]
                        }
                    ]
                },
                {
                    "id": "other",
                    "rules": [{
                        "name": "rest",
                        "matchers": [{ "type": "any" }],
                        "actions": [{ "type": "forward", "upstream": "127.0.0.1:9" }]
                    }]
                }
            ]
        }));
        let state = engine.state.load_full();
        let pipeline = &state.pipeline.pipelines[0];
        assert!(pipeline.matches_regex);
        let before = Instant::now();
        for name in [
            "ads.example",
            "short.example",
            "zero.example",
            "jump.example",
            "example.com",
        ] {
            let request = RuleEvaluationContext::new(0, false);
            engine.apply_rules(&state, pipeline, &RequestFacts::a_query(name), &request);
        }
        let after = Instant::now();

        let mut kinds: Vec<&str> = Vec::new();
        for record in engine.rule_cache.values() {
            kinds.push(match &record.entry.decision {
                Decision::Static { .. } => "static",
                Decision::Jump { .. } => "jump",
                Decision::Forward { .. } => "forward",
            });
            let expires = record.entry.expires_at;
            assert!(
                expires >= before + RULE_CACHE_MAX_AGE && expires <= after + RULE_CACHE_MAX_AGE,
                "a {} decision serves {:?}",
                kinds.last().unwrap(),
                expires.saturating_duration_since(before)
            );
        }
        kinds.sort_unstable();
        assert_eq!(kinds, ["forward", "jump", "static", "static", "static"]);
    }

    /// 规则和默认上游的决策共用配置加载时算好的那份上游名字，每次决策不再各分配一份
    /// Decisions by a rule and by the default upstream share the upstream name made at config
    /// load, rather than allocating one each
    #[tokio::test]
    async fn decisions_share_one_copy_of_their_upstream() {
        let engine = engine_from(serde_json::json!({
            "settings": { "default_upstream": "127.0.0.1:9" },
            "pipelines": [{
                "id": "main",
                "rules": [{
                    "name": "named",
                    "matchers": [{ "type": "domain_suffix", "value": "named.example" }],
                    "actions": [{ "type": "forward", "upstream": "127.0.0.1:10" }]
                }]
            }]
        }));
        let state = engine.state.load_full();
        let pipeline = &state.pipeline.pipelines[0];
        let upstream_of = |name: &str| {
            let request = RuleEvaluationContext::new(0, false);
            match engine.apply_rules(&state, pipeline, &RequestFacts::a_query(name), &request) {
                Decision::Forward {
                    upstream,
                    rule_name,
                    ..
                } => (upstream, rule_name),
                _ => panic!("every name here forwards"),
            }
        };
        let first = upstream_of("a.named.example");
        assert_eq!(&*first.0, "127.0.0.1:10");
        assert!(Arc::ptr_eq(&first.0, &upstream_of("b.named.example").0));
        let default = upstream_of("a.other.example");
        assert_eq!((&*default.0, &*default.1), ("127.0.0.1:9", "default"));
        let again = upstream_of("b.other.example");
        assert!(Arc::ptr_eq(&default.0, &again.0));
        assert!(Arc::ptr_eq(&default.1, &again.1));
    }

    /// 转发在规则缓存里只受 `RULE_CACHE_MAX_AGE` 限制，带不带响应阶段、min_ttl 是多少都一样。以前带响应阶段的按 min_ttl
    /// 过期，默认的 0 让它从不进规则缓存
    /// A forward is bounded by `RULE_CACHE_MAX_AGE` alone in the rule cache, with a response
    /// phase or without, whatever min_ttl is. One with a response phase used to expire by
    /// min_ttl, kept out of the rule cache at the default 0
    #[tokio::test]
    async fn a_forward_lasts_the_rule_cache_max_age_with_or_without_a_response_phase() {
        let lasts = |min_ttl: u64, response_phase: bool| {
            let mut rule = serde_json::json!({
                "name": "www",
                "matchers": [{ "type": "domain_regex", "value": "^www\\." }],
                "actions": [{ "type": "forward", "upstream": "127.0.0.1:9" }]
            });
            if response_phase {
                rule["response_actions_on_miss"] = serde_json::json!([{ "type": "allow" }]);
            }
            let engine = engine_from(serde_json::json!({
                "settings": { "default_upstream": "127.0.0.1:9", "min_ttl": min_ttl },
                "pipelines": [{ "id": "main", "rules": [rule] }]
            }));
            let state = engine.state.load_full();
            let request = RuleEvaluationContext::new(0, false);
            let before = Instant::now();
            engine.apply_rules(
                &state,
                &state.pipeline.pipelines[0],
                &RequestFacts::a_query("www.example.com"),
                &request,
            );
            engine.rule_cache.values().first().map(|record| {
                record
                    .entry
                    .expires_at
                    .saturating_duration_since(before)
                    .as_secs_f64()
            })
        };
        let longest = RULE_CACHE_MAX_AGE.as_secs_f64();
        for min_ttl in [0, 30] {
            for response_phase in [true, false] {
                let bounded = lasts(min_ttl, response_phase).expect("cached");
                assert!(
                    (longest - 1.0..longest + 1.0).contains(&bounded),
                    "min_ttl {min_ttl}, response phase {response_phase}: {bounded}"
                );
            }
        }
    }

    /// 规则的决策共用它的响应阶段，每次决策不再复制匹配器和动作；响应阶段里只要有一样，决策就带上；
    /// 什么都没有的规则，决策什么都不带
    /// A rule's decisions share its response phase instead of copying the matchers and actions;
    /// a decision carries it when any part is written, and nothing for a rule with none
    #[tokio::test]
    async fn decisions_share_their_rules_response_phase() {
        let forward = serde_json::json!([{ "type": "forward", "upstream": "127.0.0.1:10" }]);
        let any = serde_json::json!([{ "type": "any" }]);
        let allow = serde_json::json!([{ "type": "allow" }]);
        let engine = engine_from(serde_json::json!({
            "settings": { "default_upstream": "127.0.0.1:9" },
            "pipelines": [{
                "id": "main",
                "rules": [
                    {
                        "name": "plain",
                        "matchers": [{ "type": "domain_suffix", "value": "plain.example" }],
                        "actions": forward
                    },
                    {
                        "name": "matchers",
                        "matchers": [{ "type": "domain_suffix", "value": "matchers.example" }],
                        "actions": forward,
                        "response_matchers": [{ "type": "response_type", "value": "A" }]
                    },
                    {
                        "name": "on_match",
                        "matchers": [{ "type": "domain_suffix", "value": "on-match.example" }],
                        "actions": forward,
                        "response_actions_on_match": allow
                    },
                    {
                        "name": "on_miss",
                        "matchers": any,
                        "actions": forward,
                        "response_actions_on_miss": allow
                    }
                ]
            }]
        }));
        let state = engine.state.load_full();
        let pipeline = &state.pipeline.pipelines[0];
        let phase_of = |name: &str| {
            let request = RuleEvaluationContext::new(0, false);
            match engine.apply_rules(&state, pipeline, &RequestFacts::a_query(name), &request) {
                Decision::Forward { response_phase, .. } => response_phase,
                _ => panic!("every name here forwards"),
            }
        };
        assert!(phase_of("a.plain.example").is_none(), "nothing written");
        for (first, second, parts) in [
            ("a.matchers.example", "b.matchers.example", (1, 0, 0)),
            ("a.on-match.example", "b.on-match.example", (0, 1, 0)),
            ("a.other.example", "b.other.example", (0, 0, 1)),
        ] {
            let phase = phase_of(first).expect("something written");
            assert!(Arc::ptr_eq(&phase, &phase_of(second).unwrap()), "{first}");
            assert_eq!(
                (
                    phase.matchers.len(),
                    phase.on_match.len(),
                    phase.on_miss.len()
                ),
                parts,
                "{first}"
            );
        }
    }

    /// 跳转的决策共用配置读进来的那份目标名字，每次决策不再各分配一份
    /// Jump decisions share the target's name read in with the configuration, rather than
    /// allocating one each
    #[tokio::test]
    async fn jumps_share_one_copy_of_their_target() {
        let engine = engine();
        let state = engine.state.load_full();
        let plain = &state.pipeline.pipelines[0];
        let target_of = |name: &str| {
            let request = RuleEvaluationContext::new(0, false);
            match engine.apply_rules(&state, plain, &RequestFacts::a_query(name), &request) {
                Decision::Jump { pipeline } => pipeline,
                other => panic!("{name} jumps, got {other:?}"),
            }
        };
        let first = target_of("a.jump.example");
        assert_eq!(&*first, "regex");
        assert!(Arc::ptr_eq(&first, &target_of("b.jump.example")));
    }

    /// 过期的决策不拿来用；重新求值后原地写回，访问计数还在，也就还留在淘汰队列原来的位置
    /// An expired decision does not serve; evaluating again writes it back in place, with its
    /// access count, so it keeps its place in the eviction queues
    #[tokio::test]
    async fn an_expired_decision_is_evaluated_again_and_written_back() {
        let engine = engine_from(serde_json::json!({
            "settings": { "default_upstream": "127.0.0.1:9" },
            "pipelines": [{
                "id": "main",
                "rules": [{
                    "name": "block",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "static_response", "rcode": "NXDOMAIN" }]
                }]
            }]
        }));
        let state = engine.state.load_full();
        let pipeline = &state.pipeline.pipelines[0];
        let evaluate = || {
            let request = RuleEvaluationContext::new(0, false);
            engine.apply_rules(
                &state,
                pipeline,
                &RequestFacts::a_query("ads.example"),
                &request,
            );
        };
        evaluate();
        let key = calculate_rule_hash(
            state.cache_namespace("main"),
            "main",
            "ads.example",
            RecordType::A,
            DNSClass::IN,
            &RequesterKey::NONE,
        );
        let mut record = engine.rule_cache.get(key).expect("cached");
        let expired = Instant::now() - std::time::Duration::from_secs(1);
        Arc::make_mut(&mut record).entry.expires_at = expired;
        engine.rule_cache.insert(key, record);
        let count = engine.rule_cache.access_count(key).unwrap();
        assert!(count > 0);

        evaluate();
        assert_eq!(engine.rule_cache.entry_count(), 1);
        assert!(
            engine.rule_cache.access_count(key).unwrap() >= count,
            "written back in place"
        );
        let record = engine.rule_cache.get(key).expect("written back");
        assert!(record.entry.is_valid_at(Instant::now()), "evaluated again");
    }
}

/// 域名后缀在每条路径上结果一样：Pipeline 入口、只有一个条件的规则（走索引）、几个条件「满足任一」的规则（逐条检查），
/// 而且静态快速路径和普通路径各测一遍（规则的第一个动作是 log 时不走快速路径）。
/// Domain suffixes give one answer on every path: pipeline selectors, single-condition rules (found through
/// the index) and any-of rules (checked one by one), each on both the static fast path and the regular path
/// (a rule whose first action is log skips the fast path).
#[cfg(test)]
mod domain_suffix_path_tests {
    use std::net::Ipv4Addr;

    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RData, RecordType};

    use crate::engine::Engine;
    use crate::engine::test_support::engine_from;

    fn rule(
        name: &str,
        operator: &str,
        suffixes: &[&str],
        ip: &str,
        fast: bool,
    ) -> serde_json::Value {
        let matchers: Vec<_> = suffixes
            .iter()
            .map(|value| serde_json::json!({ "type": "domain_suffix", "value": value, "operator": operator }))
            .collect();
        let answer = serde_json::json!({ "type": "static_ip_response", "ip": ip });
        let actions = if fast {
            serde_json::json!([answer])
        } else {
            serde_json::json!([{ "type": "log", "level": "debug" }, answer])
        };
        serde_json::json!({ "name": name, "matcher_operator": operator, "matchers": matchers, "actions": actions })
    }

    fn engine() -> Engine {
        let rules = vec![
            rule("fast-plain", "and", &["fast.test"], "10.0.1.1", true),
            rule("fast-dotted", "and", &[".fastdot.test"], "10.0.1.2", true),
            rule(
                "fast-any",
                "or",
                &["unused.invalid", "fastany.test"],
                "10.0.1.3",
                true,
            ),
            rule("slow-plain", "and", &["slow.test"], "10.0.2.1", false),
            rule("slow-dotted", "and", &[".slowdot.test"], "10.0.2.2", false),
            rule(
                "slow-any",
                "or",
                &["unused.invalid", "slowany.test"],
                "10.0.2.3",
                false,
            ),
            serde_json::json!({ "name": "rest", "matchers": [{ "type": "any" }], "actions": [{ "type": "static_ip_response", "ip": "10.0.9.9" }] }),
        ];
        let raw = serde_json::json!({
            "settings": { "default_upstream": "127.0.0.1:9", "min_ttl": 0 },
            "pipeline_select": [
                { "pipeline": "dotted", "matchers": [{ "type": "domain_suffix", "value": ".seldot.test" }] },
                { "pipeline": "plain", "matchers": [{ "type": "domain_suffix", "value": "sel.test" }] }
            ],
            "pipelines": [
                { "id": "main", "rules": rules },
                { "id": "dotted", "rules": [{ "name": "dotted", "matchers": [{ "type": "any" }], "actions": [{ "type": "static_ip_response", "ip": "10.0.0.1" }] }] },
                { "id": "plain", "rules": [{ "name": "plain", "matchers": [{ "type": "any" }], "actions": [{ "type": "static_ip_response", "ip": "10.0.0.2" }] }] }
            ]
        });
        engine_from(raw)
    }

    async fn answer(engine: &Engine, qname: &str) -> Ipv4Addr {
        let mut message = Message::new(7, MessageType::Query, OpCode::Query);
        message.add_query(Query::query(
            Name::from_str_relaxed(qname).unwrap(),
            RecordType::A,
        ));
        let bytes = engine
            .handle_packet(
                &message.to_vec().unwrap(),
                "127.0.0.1:53000".parse().unwrap(),
            )
            .await
            .expect("static answer");
        let response = Message::from_vec(&bytes).expect("parse response");
        match response.answers.first().map(|record| &record.data) {
            Some(RData::A(a)) => a.0,
            other => panic!("{qname}: expected one A record, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn domain_suffix_matches_by_label_on_every_path() {
        let engine = engine();
        let rest = Ipv4Addr::new(10, 0, 9, 9);
        let cases = [
            // 入口 / pipeline selectors
            ("sel.test", Ipv4Addr::new(10, 0, 0, 2)),
            ("a.sel.test", Ipv4Addr::new(10, 0, 0, 2)),
            ("notsel.test", rest),
            ("seldot.test", rest),
            ("a.seldot.test", Ipv4Addr::new(10, 0, 0, 1)),
            // 快速路径 / static fast path
            ("fast.test", Ipv4Addr::new(10, 0, 1, 1)),
            ("a.fast.test", Ipv4Addr::new(10, 0, 1, 1)),
            ("notfast.test", rest),
            ("fastdot.test", rest),
            ("a.fastdot.test", Ipv4Addr::new(10, 0, 1, 2)),
            ("fastany.test", Ipv4Addr::new(10, 0, 1, 3)),
            ("notfastany.test", rest),
            // 普通路径 / regular path
            ("slow.test", Ipv4Addr::new(10, 0, 2, 1)),
            ("a.slow.test", Ipv4Addr::new(10, 0, 2, 1)),
            ("notslow.test", rest),
            ("slowdot.test", rest),
            ("a.slowdot.test", Ipv4Addr::new(10, 0, 2, 2)),
            ("slowany.test", Ipv4Addr::new(10, 0, 2, 3)),
            ("notslowany.test", rest),
        ];
        for (qname, expected) in cases {
            assert_eq!(answer(&engine, qname).await, expected, "{qname}");
        }
    }
}
