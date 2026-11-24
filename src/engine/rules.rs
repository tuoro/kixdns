use bytes::Bytes;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{DNSClass, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use smallvec::SmallVec;
use std::hash::Hasher;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::observation::report_response_decision;
use crate::cache_store::Cached;
use crate::config::{Action, Transport};
use crate::engine::core::Engine;
use crate::engine::execution::Request;
use crate::engine::response::{
    least_ttl, make_static_cname_answer, make_static_ip_answer, make_static_txt_answer,
    static_reply,
};
use crate::engine::upstream::UpstreamFailure;
use crate::matcher::RuntimeResponseMatcherWithOp;
use crate::matcher::eval_match_chain;
use crate::matcher::{RequestFacts, RequesterKey, ResponsePhase, parse_rcode};

#[derive(Debug, Clone)]
pub enum Decision {
    Static {
        rcode: ResponseCode,
        answers: Vec<Record>,
    },
    Forward {
        upstream: Arc<str>,
        /// Pre-split upstream list (performance optimization) / 预分割的 upstream 列表（性能优化）
        pre_split_upstreams: Option<std::sync::Arc<Vec<std::sync::Arc<str>>>>,
        response_phase: Option<Arc<ResponsePhase>>,
        rule_name: Arc<str>,
        /// 作出决策的规则在它的规则组里排第几（从 0 起）；没有规则作出决策时为 None。它 continue 以后求值从这个
        /// 位置的下一条接着走（见 `Route::resume_at`），不按名字找它：名字只是标签，两条规则可以同名
        /// The place in its pipeline (from 0) of the rule that decided; None when no rule did.
        /// Once it continues, evaluation resumes at the place after this one (see
        /// `Route::resume_at`), not by its name: a name is a label, and two rules may share one
        rule_index: Option<usize>,
        /// 没写协议前缀的上游用的传输；写了前缀（`tcp://`、`https://` 这些）的照前缀（见 `upstream::forward_upstream`）
        /// The transport of an upstream written without a scheme; one written with a scheme
        /// (`tcp://`, `https://` and so on) goes by it (see `upstream::forward_upstream`)
        transport: Transport,
        /// EDNS Client Subnet (RFC 7871) request rewriting mode / EDNS 客户端子网 (RFC 7871) 请求改写模式
        ecs: Option<crate::config::EcsMode>,
        allow_reuse: bool,
    },
    Jump {
        pipeline: Arc<str>,
    },
}

/// 没有规则作出决策时，决策记在这个名字下 / The name a decision goes under when no rule makes it
static DEFAULT_RULE_NAME: std::sync::LazyLock<Arc<str>> =
    std::sync::LazyLock::new(|| Arc::from("default"));

impl Decision {
    /// 没有规则作出决策时：用 UDP 转发给默认上游 / When no rule decides: forwarded over UDP to
    /// the default upstream
    pub(crate) fn default_forward(settings: &crate::config::GlobalSettings) -> Self {
        Self::to_default_upstream(settings, Arc::clone(&DEFAULT_RULE_NAME), None)
    }

    /// 排第 `rule_index` 的规则 `rule_name` 的 `allow`：和没有规则作出决策时一样转发给默认上游，continue 之后复用规则越过的
    /// 应答（见 `Route::reused_response`）
    /// The `allow` of rule `rule_name` at `rule_index`: forwarded to the default upstream as
    /// when no rule decides, reusing the answer a rule continued past after a continue (see
    /// `Route::reused_response`)
    pub(crate) fn allow(
        settings: &crate::config::GlobalSettings,
        rule_name: Arc<str>,
        rule_index: usize,
    ) -> Self {
        Self::to_default_upstream(settings, rule_name, Some(rule_index))
    }

    /// 用 UDP 转发给默认上游，记在 `rule_name` 下；规则（排第 `rule_index`）的 allow 复用越过的应答，没有规则作出决策时不复用
    /// Forwarded over UDP to the default upstream, under `rule_name`; a rule's allow (at
    /// `rule_index`) reuses the answer continued past, the default with no rule deciding does not
    fn to_default_upstream(
        settings: &crate::config::GlobalSettings,
        rule_name: Arc<str>,
        rule_index: Option<usize>,
    ) -> Self {
        Decision::Forward {
            upstream: settings.default_upstream_arc(),
            pre_split_upstreams: settings.default_upstream_pre_split.clone(),
            response_phase: None,
            rule_name,
            rule_index,
            transport: Transport::Udp,
            ecs: None,
            allow_reuse: rule_index.is_some(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ResponseContext {
    pub raw: Bytes,
    pub msg: Message,
    pub upstream: Arc<str>,
}

/// The `source` of the SERVFAIL that a response action's jump answers when no
/// jumps are left / 响应动作的跳转没有剩余次数时给出的 SERVFAIL 的 `source`
pub const JUMP_LIMIT: &str = "jump_limit";

#[derive(Debug)]
pub enum ResponseActionResult {
    Upstream {
        ctx: ResponseContext,
    },
    Static {
        bytes: Bytes,
        rcode: ResponseCode,
        /// 它带的 TTL：记录里最小的，没有记录时为 None（见 `Route::static_ttl`）/ The TTL it
        /// carries: the least of its records', None without records (see `Route::static_ttl`)
        ttl: Option<u32>,
        source: &'static str,
    },
    /// 跳到 `pipeline` 接着走规则；次数由跳过去的一方数（见 `Route::response_jumped`），这里只看还剩没剩
    /// Jump to `pipeline` and go on with its rules; the side making the jump counts it (see
    /// `Route::response_jumped`), and this only checks whether any are left
    Jump {
        pipeline: Arc<str>,
    },
    Continue {
        ctx: Option<ResponseContext>,
    },
}

/// 规则缓存的键：和响应缓存的槽位一样用带密钥的 `Engine::question_hasher` 写进问题（为什么带密钥见那里），再写进规则对
/// 请求方的判定。以前用不带密钥的 FxHash，请求方能凑出一串落在同一处的名字，存储层只好对所有键再散一遍
/// The rule cache key: the question written into the keyed `Engine::question_hasher` as for a
/// response cache slot (why keyed, see there), then how the rules judge the requester. It used
/// to be an unkeyed FxHash, with which a requester could make up a run of names landing in one
/// place, so the store hashed every key a second time
#[inline]
pub fn calculate_rule_hash(
    cache_namespace: u64,
    pipeline_id: &str,
    qname: &str,
    qtype: RecordType,
    qclass: DNSClass,
    requester: &RequesterKey,
) -> u64 {
    let mut hasher = Engine::question_hasher(
        cache_namespace,
        pipeline_id,
        qname.as_bytes(),
        qtype,
        qclass,
    );
    requester.hash_into(&mut hasher);
    hasher.finish()
}

#[derive(Clone)]
pub struct RuleCacheEntry {
    pub pipeline_id: Arc<str>,
    /// 这个决定是给哪个名字的。键只是哈希，不同的名字可能落到同一个键上，决定不能给错名字。放在记录里，多数名字放得下，
    /// 写入时不用再分配一次
    /// The name this decision is for. The key is only a hash, on which different names may land, and a
    /// decision must not go to the wrong name. Kept in the record, where most names fit, sparing writing
    /// another allocation
    pub qname: SmallVec<[u8; 32]>,
    pub qtype: u16,
    pub qclass: u16,
    /// The requester the decision was made for, as far as the key separates it
    /// 决策是为哪个请求方做的（以键区分到的程度为限）
    pub requester: RequesterKey,
    pub decision: Decision,
    /// 过期的时刻：写入以后 [`RULE_CACHE_MAX_AGE`] / When it expires: [`RULE_CACHE_MAX_AGE`]
    /// after it was written
    pub expires_at: Instant,
}

/// Rule cache value: the cached decision plus the request-phase rules whose
/// matchers matched while producing it (in evaluation order, the last one
/// being the deciding rule). Rule cache hits replay them to observers.
/// 规则缓存值：缓存的决策以及产生它时命中的请求阶段规则（按求值顺序，最后
/// 一条为决定性规则）。规则缓存命中时向观察者回放。
#[derive(Clone)]
pub struct RuleCacheRecord {
    pub entry: RuleCacheEntry,
    /// Recorded only when an observer is installed; `None` otherwise, so the
    /// rule cache costs nothing extra without one. / 仅在安装了观察者时记录，否则为 None。
    pub matched_rules: Option<Arc<[Arc<str>]>>,
    /// `false` when no rule decided and the default upstream applied.
    /// 无规则决定、使用默认上游时为 false。
    pub decided_by_rule: bool,
}

/// 规则缓存里的每个决策都用这么久。决策只取决于配置、Geo 数据和规则对请求方的判定，键已经跟着它们走（命名空间见
/// `EngineInner::at_geo`，请求方的判定见 `RequesterScope`）；静态应答记录的 TTL 是写给客户端的，规则下次求值给的还是
/// 同一份，不必照它过期。这个时限让一条决策过一阵就重新求值，只问过一次的名字占着的地方也由清扫收回
/// How long every rule cache decision serves. A decision depends on the configuration, the Geo
/// data and how the rules judge the requester alone, and the keys already follow them (the
/// namespaces see `EngineInner::at_geo`, the judgement of the requester `RequesterScope`); the
/// TTL of a static answer's records is written for the client, the rules giving the same answer
/// when evaluated again, and is nothing to expire by. This limit has a decision evaluated again
/// after a while, and the room a name asked once takes is reclaimed by the sweep
pub(crate) const RULE_CACHE_MAX_AGE: Duration = Duration::from_secs(60);

/// 每条记录计重 1，到 `expires_at` 就过期（见 [`RULE_CACHE_MAX_AGE`]）
/// Each record weighs 1 and is outlived at `expires_at` (see [`RULE_CACHE_MAX_AGE`])
impl Cached for Arc<RuleCacheRecord> {
    fn weight(&self) -> u32 {
        1
    }

    fn outlived(&self, _kept: Duration, now: Instant) -> bool {
        !self.entry.is_valid_at(now)
    }
}

/// 规则缓存里一个决定所答的问题：哪个 pipeline、名字、类型、类别，和规则对请求方的判定；`key` 是它在规则缓存里的键（见
/// [`calculate_rule_hash`]）。查和写都按它（见 `Engine::cached_decision`、`Engine::insert_rule_cache`）
/// The question a decision in the rule cache answers: which pipeline, name, type and class, and
/// how the rules judge the requester; `key` is where it sits in the rule cache (see
/// [`calculate_rule_hash`]). Lookups and writes both go by it (see `Engine::cached_decision`,
/// `Engine::insert_rule_cache`)
#[derive(Clone, Copy)]
pub(crate) struct RuleQuestion<'a> {
    pub(crate) pipeline_id: &'a Arc<str>,
    pub(crate) qname: &'a str,
    pub(crate) qtype: RecordType,
    pub(crate) qclass: DNSClass,
    pub(crate) requester: RequesterKey,
    pub(crate) key: u64,
}

impl<'a> RuleQuestion<'a> {
    /// 命名空间 `cache_namespace` 下的这个问题 / This question under the namespace `cache_namespace`
    pub(crate) fn new(
        cache_namespace: u64,
        pipeline_id: &'a Arc<str>,
        qname: &'a str,
        qtype: RecordType,
        qclass: DNSClass,
        requester: RequesterKey,
    ) -> Self {
        Self {
            key: calculate_rule_hash(
                cache_namespace,
                pipeline_id,
                qname,
                qtype,
                qclass,
                &requester,
            ),
            pipeline_id,
            qname,
            qtype,
            qclass,
            requester,
        }
    }
}

impl RuleCacheEntry {
    /// 给 `question` 的决定 `decision`，到 `expires_at` 为止 / The decision `decision` for
    /// `question`, until `expires_at`
    pub(crate) fn new(
        question: &RuleQuestion<'_>,
        decision: Decision,
        expires_at: Instant,
    ) -> Self {
        Self {
            pipeline_id: Arc::clone(question.pipeline_id),
            qname: SmallVec::from_slice(question.qname.as_bytes()),
            qtype: u16::from(question.qtype),
            qclass: u16::from(question.qclass),
            requester: question.requester,
            decision,
            expires_at,
        }
    }

    /// 这个决定在 `now` 这一刻还有效、答的就是 `question` / Whether this decision is still valid at
    /// `now` and answers `question`
    #[inline]
    pub(crate) fn answers(&self, question: &RuleQuestion<'_>, now: Instant) -> bool {
        self.is_valid_at(now)
            && self.qtype == u16::from(question.qtype)
            && self.qclass == u16::from(question.qclass)
            && self.requester == question.requester
            && *self.pipeline_id == **question.pipeline_id
            && self.qname.as_slice() == question.qname.as_bytes()
    }

    /// 在 `now` 这一刻还有效 / Still valid at `now`
    #[inline]
    pub fn is_valid_at(&self, now: Instant) -> bool {
        now <= self.expires_at
    }
}

/// 几个上游一起问、全都失败（`failure`）、其中有上游回了失败应答时（见 `UpstreamFailure`），把最先收到的那个
/// 应答连同回它的上游交给规则的回答检查 `check`：检查通过、而且通过后有动作（`on_match`）要执行时，它就是这次转发
/// 的应答，和只问一个上游时一样，连同回它的上游和解析好的报文一起给出。其余情况给出 None，照旧是失败：检查不通过时
/// on_miss 照旧在没有应答的情况下执行，没有 on_miss 时照旧是过期缓存或 SERVFAIL。后台刷新不受影响：调用之后紧跟着
/// `reject_failure_reply_on_refresh`，刷新照旧拿到失败，缓存的条目不动。
/// When several upstreams asked together all failed with `failure` and one of them replied
/// with a failure (see `UpstreamFailure`), the first such reply goes to the rule's answer
/// check `check` with the upstream that sent it: when it passes and has actions to run
/// (`on_match`), that reply is this forward's answer, as with a single upstream, and comes
/// back with the upstream and its parsed message. Otherwise this gives None and it stays a
/// failure: when the check fails on_miss still runs without an answer, and without on_miss
/// the stale entry or SERVFAIL still answers. A background refresh is not affected: the
/// caller runs `reject_failure_reply_on_refresh` right after, so the refresh still gets the
/// failure and leaves the cached entry alone.
pub(crate) fn check_failure_reply(
    failure: &anyhow::Error,
    on_match: &[Action],
    check: impl FnOnce(&Message, &str) -> bool,
) -> Option<(Bytes, Arc<str>, Message)> {
    if on_match.is_empty() {
        return None;
    }
    let (raw, upstream) = UpstreamFailure::reply_of(failure)?;
    let msg = Message::from_bytes(raw)
        .ok()
        .filter(|msg| check(msg, upstream))?;
    Some((raw.clone(), upstream.clone(), msg))
}

/// 响应匹配器对 `upstream`（作答的上游，`udp:1.1.1.1:53`）给请求 `facts` 的应答 `msg` 是否成立；没有应答（`None`）时不成立，
/// 没有匹配器时成立。每个匹配器只在求值时拿它要的那把 Geo 读锁，和请求规则一样（见 `RuntimeResponseMatcher::matches`）：
/// 不用 Geo 数据的检查一把都不拿；一次只拿一把，也就不会和排队的写者互相等
/// Whether the response matchers hold for the answer `msg` that `upstream` gave request
/// `facts` (the answering upstream, `udp:1.1.1.1:53`); without an answer (`None`) they do not,
/// and with no matchers they do. Each matcher takes the Geo read lock it needs only while it is
/// evaluated, as request rules do (see `RuntimeResponseMatcher::matches`): a check using no Geo
/// data takes none, and holding one at a time, it never waits on a queued writer that waits on
/// it
pub(crate) fn response_matches(
    engine: &Engine,
    matchers: &[RuntimeResponseMatcherWithOp],
    facts: &RequestFacts<'_>,
    upstream: &str,
    msg: Option<&Message>,
) -> bool {
    let geo = engine.geo();
    msg.is_some_and(|msg| {
        eval_match_chain(
            matchers,
            |m| m.operator,
            |m| m.matcher.matches(facts, upstream, msg, geo),
        )
    })
}

/// 执行响应动作要的：请求本身（问题、谁在问、用的配置、观察者），和它这次转发的几样
/// What running the response actions takes: the request itself (its question, who is asking,
/// the configuration it uses, its observer), and a few things of this forward of it
pub(crate) struct ApplyResponseActionsContext<'a> {
    pub(crate) engine: &'a Engine,
    pub(crate) request: &'a Request<'a>,
    pub(crate) actions: &'a [Action],
    pub(crate) ctx_opt: Option<ResponseContext>,
    /// 规则自己的转发发出的包；动作里自己写了 `ecs` 的转发从客户端发来的查询改写（见 `Request::packet`）
    /// The packet the rule's own forward sent; a forward among the actions writing an `ecs` of
    /// its own rewrites the query as the client sent it instead (see `Request::packet`)
    pub(crate) packet: &'a [u8],
    pub(crate) pipeline_id: &'a str,
    pub(crate) rule_name: &'a str,
    pub(crate) remaining_jumps: usize,
    /// Where a forward among the actions records its reply, or its failure (see `Route::trail`)
    /// 动作里的转发在哪里记下它的应答或失败（见 `Route::trail`）
    pub(crate) trail: &'a mut crate::ecs_scope::EcsReach,
    /// The ECS the rule's own forward sent, which a forward among the actions without an `ecs`
    /// of its own sends too, forwarding the same packet
    /// 规则自己的转发发出的 ECS：动作里没写 `ecs` 的转发发的是同一个包，也就是这一份
    pub(crate) rule_ecs: crate::ecs_scope::ForwardEcs,
}

/// 执行响应动作：响应阶段 forward 动作的上游尝试和动作最后作出的决定，都经请求的观察者上报
/// Run the response actions: the upstream attempts of response-phase `forward` actions and the
/// decision the actions arrive at are reported through the request's observer
pub(crate) async fn apply_response_actions(
    ctx: ApplyResponseActionsContext<'_>,
) -> anyhow::Result<ResponseActionResult> {
    let (observed, pipeline, rule) = (ctx.request.observed, ctx.pipeline_id, ctx.rule_name);
    let result = run_response_actions(ctx).await?;
    if let Some((observer, context)) = observed {
        report_response_decision(observer, context, pipeline, rule, &result);
    }
    Ok(result)
}

async fn run_response_actions(
    mut ctx: ApplyResponseActionsContext<'_>,
) -> anyhow::Result<ResponseActionResult> {
    let request = ctx.request;
    let (qname, qtype, qclass) = (request.qname.as_ref(), request.qtype, request.qclass);
    const MAX_RESPONSE_FORWARDS: usize = 4;
    let mut forward_attempts = 0usize;

    for action in ctx.actions {
        match action {
            Action::Log { level } => {
                log_match(
                    level.as_deref(),
                    ctx.pipeline_id,
                    ctx.rule_name,
                    qname,
                    qtype,
                    request.peer.ip(),
                );
            }
            Action::StaticResponse { rcode } => {
                let code = parse_rcode(rcode).unwrap_or(ResponseCode::NXDomain);
                return Ok(static_answer(request, code, &[], "response_action"));
            }
            Action::StaticIpResponse { ip } => {
                let (rcode, answers) = make_static_ip_answer(qname, qtype, qclass, ip);
                return Ok(static_answer(request, rcode, &answers, "response_action"));
            }
            Action::StaticCnameResponse { target, ttl } => {
                let (rcode, answers) =
                    make_static_cname_answer(qname, qclass, target, ttl.unwrap_or(300));
                return Ok(static_answer(request, rcode, &answers, "response_action"));
            }
            Action::StaticTxtResponse { text, ttl } => {
                let (rcode, answers) =
                    make_static_txt_answer(qname, qtype, qclass, text, ttl.unwrap_or(300));
                return Ok(static_answer(request, rcode, &answers, "response_action"));
            }
            Action::JumpToPipeline { pipeline } => {
                if ctx.remaining_jumps == 0 {
                    return Ok(servfail(request, JUMP_LIMIT));
                }
                return Ok(ResponseActionResult::Jump {
                    pipeline: Arc::clone(pipeline),
                });
            }
            // 和所有动作执行完一样：有应答就交出它，没有就 SERVFAIL
            // As when every action has run: the answer if there is one, SERVFAIL if not
            Action::Allow => break,
            Action::Deny => {
                return Ok(static_answer(
                    request,
                    ResponseCode::Refused,
                    &[],
                    "response_action",
                ));
            }
            Action::Continue => {
                return Ok(ResponseActionResult::Continue { ctx: ctx.ctx_opt });
            }
            // 换掉手上的应答，换成的和 static_txt_response 给出的一样（TTL 是它的默认值）：只有 TXT、ANY 查询拿到
            // TXT 记录，别的类型、别的类别回 NODATA，响应码是 NOERROR，装不下时回 SERVFAIL。以前不看这些，A 查询也
            // 拿到 TXT 记录，上游回 NXDOMAIN 时还带着它。手上没有应答（上游失败以后）就没有可换的，回 SERVFAIL
            // The answer in hand is replaced with what static_txt_response gives (its default
            // TTL): only TXT and ANY queries get the TXT record, other types and classes NODATA,
            // with NOERROR, and SERVFAIL when it does not fit. None of this used to be looked at,
            // an A query getting the TXT record too, and an upstream's NXDOMAIN keeping it. With
            // no answer in hand (after an upstream failure) there is nothing to replace: SERVFAIL
            Action::ReplaceTxtResponse { text } => {
                if ctx.ctx_opt.is_none() {
                    return Ok(servfail(request, "response_action"));
                }
                let (rcode, answers) = make_static_txt_answer(qname, qtype, qclass, text, 300);
                return Ok(static_answer(request, rcode, &answers, "replace_txt"));
            }
            Action::Forward {
                upstream,
                transport,
                ecs,
                pre_split_upstreams,
                upstream_shared: _,
            } => {
                forward_attempts += 1;
                if forward_attempts > MAX_RESPONSE_FORWARDS {
                    crate::warn_sparse!(
                        event = "response_action_limit",
                        qname = %qname,
                        qtype = ?qtype,
                        client_ip = %request.peer.ip(),
                        pipeline = %ctx.pipeline_id,
                        rule = %ctx.rule_name,
                        "response actions exceeded forward limit"
                    );
                    return Ok(servfail(request, "response_action"));
                }

                // 手上应答记的来源（`udp:1.1.1.1:53`）不是能发查询的地址，所以没写 upstream 时和请求
                // 阶段一样用 default_upstream
                // Where the answer in hand came from (`udp:1.1.1.1:53`) is no address to query,
                // so without an upstream this uses default_upstream as the request phase does
                let upstream_addr: Arc<str> = Arc::from(
                    upstream
                        .as_deref()
                        .unwrap_or(&request.state.pipeline.settings.default_upstream),
                );
                let use_transport = transport.unwrap_or(Transport::Udp);
                // 自己写了 `ecs` 的照它从客户端的查询改写，应答适用于谁也按它算；没写的和规则自己的转发发同一个包。以前
                // 这里的 `ecs` 读进来就丢掉了
                // One writing an `ecs` of its own rewrites the client's query by it, and whom the
                // reply applies to goes by it too; one without sends the packet of the rule's own
                // forward. The `ecs` here used to be read and dropped
                let own_ecs = ecs.as_ref().map(|mode| {
                    let packet = crate::ecs::apply_ecs_for(
                        request.packet,
                        mode,
                        request.peer.ip(),
                        request.requester.ecs.as_ref(),
                    );
                    let view = request.requester.ecs_view();
                    (packet, crate::ecs_scope::ForwardEcs::of(Some(mode), &view))
                });
                let packet = own_ecs.as_ref().map_or(ctx.packet, |(packet, _)| packet);
                if let Some((packet, sent)) = &own_ecs {
                    ctx.trail.check_sent(packet, sent);
                }
                let sent_ecs = own_ecs.as_ref().map_or(ctx.rule_ecs, |(_, sent)| *sent);
                // hickory 读不了的应答，回答检查和后面的动作都用不了，和上游失败一样算这次转发失败
                // A reply hickory cannot read is of no use to the checks and actions after, and
                // fails this forward as the upstream failing does
                let forwarded = crate::engine::upstream::forward_upstream(
                    ctx.engine,
                    packet,
                    &upstream_addr,
                    request.state.pipeline.upstream_timeout(),
                    use_transport,
                    pre_split_upstreams.as_ref(),
                    request.observed,
                    request.asker(),
                )
                .await
                .and_then(|(raw, upstream)| match Message::from_bytes(&raw) {
                    Ok(msg) => Ok(ResponseContext { raw, msg, upstream }),
                    Err(error) => Err(anyhow::Error::new(error)
                        .context(format!("the reply from {upstream} cannot be read"))),
                });
                match forwarded {
                    Ok(answer) => {
                        ctx.trail.record_reply(sent_ecs, &answer.raw);
                        ctx.ctx_opt = Some(answer);
                    }
                    Err(err) => {
                        ctx.trail.record_failure(sent_ecs);
                        // 流控没让等的失败是这台设备自己的事（见 `UpstreamFailure::withheld`）：原样交回，这个
                        // 请求只给自己回 SERVFAIL，它登记的条目随之放下，不把 SERVFAIL 交给等着的别的请求（见
                        // `Engine::answer`）
                        // A failure with flow control keeping the query from waiting is the
                        // device's own affair (see `UpstreamFailure::withheld`): it goes back
                        // as it is, the request answering SERVFAIL to itself alone, and the
                        // entries it registered go with it, no SERVFAIL being handed to the other
                        // requests waiting (see `Engine::answer`)
                        if UpstreamFailure::was_withheld(&err) {
                            tracing::debug!(
                                event = "response_action_withheld",
                                upstream = %upstream_addr,
                                qname = %qname,
                                client_ip = %request.peer.ip(),
                                error = %err,
                                "flow control kept the response action forward from the upstream"
                            );
                            return Err(err);
                        }
                        crate::warn_sparse!(
                            event = "response_action_failure",
                            upstream = %upstream_addr,
                            qname = %qname,
                            qtype = ?qtype,
                            client_ip = %request.peer.ip(),
                            pipeline = %ctx.pipeline_id,
                            rule = %ctx.rule_name,
                            error = %format_args!("{err:#}"),
                            "response action forward failed"
                        );
                        return Ok(servfail(request, "response_action"));
                    }
                }
            }
        }
    }

    // 动作都执行完：有应答就交出它，没有就 SERVFAIL
    // Every action has run: the answer if there is one, SERVFAIL if not
    Ok(match ctx.ctx_opt {
        Some(resp_ctx) => ResponseActionResult::Upstream { ctx: resp_ctx },
        None => servfail(request, "response_action"),
    })
}

/// 执行 log 动作：按 `level`（trace、debug、warn、error，别的和不写都是 info）记下命中的 Pipeline 和规则、查询名、查询类型
/// 和客户端地址
/// Runs a log action: records the pipeline and rule that matched, the query name, the query type
/// and the client address at `level` (trace, debug, warn or error, info for anything else or none)
pub(crate) fn log_match(
    level: Option<&str>,
    pipeline: &str,
    rule_name: &str,
    qname: &str,
    qtype: RecordType,
    client_ip: std::net::IpAddr,
) {
    match level.unwrap_or("info") {
        "trace" => {
            tracing::trace!(event = "matcher_log", pipeline = %pipeline, rule = %rule_name, qname = %qname, qtype = ?qtype, client_ip = %client_ip, level = "trace")
        }
        "debug" => {
            tracing::debug!(event = "matcher_log", pipeline = %pipeline, rule = %rule_name, qname = %qname, qtype = ?qtype, client_ip = %client_ip, level = "debug")
        }
        "warn" => {
            tracing::warn!(event = "matcher_log", pipeline = %pipeline, rule = %rule_name, qname = %qname, qtype = ?qtype, client_ip = %client_ip, level = "warn")
        }
        "error" => {
            tracing::error!(event = "matcher_log", pipeline = %pipeline, rule = %rule_name, qname = %qname, qtype = ?qtype, client_ip = %client_ip, level = "error")
        }
        _ => {
            tracing::info!(event = "matcher_log", pipeline = %pipeline, rule = %rule_name, qname = %qname, qtype = ?qtype, client_ip = %client_ip, level = "info")
        }
    }
}

/// 响应动作照请求给出的静态应答，带着它记录里最小的 TTL：照线上格式从客户端的查询写（见 `response::static_reply`），不为它
/// 解析请求
/// A static answer the response actions give for the request, with the least TTL of its records:
/// written on the wire from the client's query (see `response::static_reply`), with no parse of
/// the request for it
fn static_answer(
    request: &Request<'_>,
    rcode: ResponseCode,
    answers: &[Record],
    source: &'static str,
) -> ResponseActionResult {
    ResponseActionResult::Static {
        ttl: least_ttl(answers),
        bytes: static_reply(
            request.packet,
            request.qname,
            request.qtype,
            request.qclass,
            rcode,
            answers,
        ),
        rcode,
        source,
    }
}

/// 响应动作给不出应答时的 SERVFAIL，`source` 说明为什么（见 `ResponseActionResult::Static`）
/// The SERVFAIL of response actions that find no answer, `source` telling why (see
/// `ResponseActionResult::Static`)
fn servfail(request: &Request<'_>, source: &'static str) -> ResponseActionResult {
    ResponseActionResult::Static {
        bytes: crate::proto_utils::servfail_reply(request.packet),
        rcode: ResponseCode::ServFail,
        ttl: None,
        source,
    }
}

#[cfg(test)]
mod response_jump_tests {
    use crate::engine::test_support::{answering_upstream, engine_from};
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RData, RecordType};
    use hickory_proto::serialize::binary::BinDecodable;
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use std::time::Duration;

    #[tokio::test]
    async fn a_response_jump_starts_the_target_pipeline_from_its_first_rule() {
        let upstream = answering_upstream(Ipv4Addr::new(192, 0, 2, 1), 300)
            .await
            .address;
        let any = serde_json::json!([{ "type": "any" }]);
        let forward = serde_json::json!([{ "type": "forward", "upstream": upstream }]);
        let jump_to =
            |target: &str| serde_json::json!([{ "type": "jump_to_pipeline", "pipeline": target }]);
        let answer = |ip: &str| serde_json::json!([{ "type": "static_ip_response", "ip": ip }]);
        // "middle" continues past its rule "first", then jumps from the
        // response phase into "last", which has a rule of the same name.
        // "middle" 越过自己的 "first" 规则后，在响应阶段跳到 "last"，
        // 而 "last" 里也有一条同名的规则。
        let raw = serde_json::json!({
            "settings": { "default_upstream": upstream, "min_ttl": 60 },
            "pipelines": [
                { "id": "entry", "rules": [
                    { "name": "hop", "matchers": any, "actions": forward,
                      "response_actions_on_match": jump_to("middle") }
                ]},
                { "id": "middle", "rules": [
                    { "name": "first", "matchers": any, "actions": forward,
                      "response_actions_on_match": [{ "type": "continue" }] },
                    { "name": "second", "matchers": any, "actions": forward,
                      "response_actions_on_match": jump_to("last") }
                ]},
                { "id": "last", "rules": [
                    { "name": "first", "matchers": any, "actions": answer("192.0.2.5") },
                    { "name": "fallback", "matchers": any, "actions": answer("192.0.2.9") }
                ]}
            ]
        });
        let engine = engine_from(raw);

        let mut request = Message::new(0x5157, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(
            Name::from_str("example.com.").unwrap(),
            RecordType::A,
        ));
        let bytes = tokio::time::timeout(
            Duration::from_secs(5),
            engine.handle_packet(
                &request.to_vec().unwrap(),
                "127.0.0.1:53000".parse().unwrap(),
            ),
        )
        .await
        .expect("request finishes")
        .expect("request succeeds");

        let reply = Message::from_bytes(&bytes).expect("parse reply");
        let answers: Vec<_> = reply
            .answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::A(a) => Some(a.0),
                _ => None,
            })
            .collect();
        assert_eq!(answers, [Ipv4Addr::new(192, 0, 2, 5)]);
    }

    /// `peer` 问 `example.com.` 的 A 记录，应答里的 A 记录 / The A records of the answer `peer`
    /// gets asking the A record of `example.com.`
    async fn ask(engine: &crate::engine::Engine) -> Vec<Ipv4Addr> {
        let mut request = Message::new(0x5157, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(
            Name::from_str("example.com.").unwrap(),
            RecordType::A,
        ));
        let bytes = tokio::time::timeout(
            Duration::from_secs(5),
            engine.handle_packet(
                &request.to_vec().unwrap(),
                "127.0.0.1:53000".parse().unwrap(),
            ),
        )
        .await
        .expect("request finishes")
        .expect("request succeeds");
        Message::from_bytes(&bytes)
            .expect("parse reply")
            .answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::A(a) => Some(a.0),
                _ => None,
            })
            .collect()
    }

    /// 回答检查跳过去以后上游失败，照样执行那条规则的 on_miss，和不经跳转一样。以前跳转路径另有一套转发处理，
    /// 上游失败直接回 SERVFAIL
    /// An upstream failing after an answer check's jump runs that rule's miss actions as it
    /// would without the jump. The jump path used to have a forward handling of its own, an
    /// upstream failure answering SERVFAIL there and then
    #[tokio::test]
    async fn an_upstream_failure_after_a_response_jump_runs_the_miss_actions() {
        let first = answering_upstream(Ipv4Addr::new(192, 0, 2, 1), 300)
            .await
            .address;
        let engine = engine_from(serde_json::json!({
            "settings": { "default_upstream": first, "upstream_timeout_ms": 300 },
            "pipelines": [
                { "id": "entry", "rules": [{
                    "name": "hop", "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "forward", "upstream": first }],
                    "response_actions_on_match": [{ "type": "jump_to_pipeline", "pipeline": "other" }]
                }] },
                { "id": "other", "rules": [{
                    "name": "dead", "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "forward", "upstream": "127.0.0.1:9" }],
                    "response_actions_on_miss": [{ "type": "static_ip_response", "ip": "192.0.2.7" }]
                }] }
            ]
        }));
        assert_eq!(ask(&engine).await, [Ipv4Addr::new(192, 0, 2, 7)]);
    }

    /// 分流常见的写法：先问一组上游，回答检查不满意（比如结果被污染）就跳去问另一组。跳过去拿到的应答缓存在入口的键下，
    /// 同样的问题再来，两组上游都不必再问。以前这条路径什么都不缓存，每次都两边各问一遍
    /// The usual way of splitting: ask one group of upstreams, and when the answer check is
    /// not satisfied (a polluted result, say) jump to ask another. The answer got over there is
    /// cached under the entry's key, and the same question coming again asks neither group. This
    /// path used to cache nothing, asking both every time
    #[tokio::test]
    async fn an_answer_got_through_a_response_jump_is_cached() {
        let domestic = answering_upstream(Ipv4Addr::new(192, 0, 2, 1), 300).await;
        let abroad = answering_upstream(Ipv4Addr::new(198, 51, 100, 1), 300).await;
        let engine = engine_from(serde_json::json!({
            "settings": { "default_upstream": domestic.address },
            "pipelines": [
                { "id": "entry", "rules": [{
                    "name": "domestic", "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "forward", "upstream": domestic.address }],
                    "response_matchers": [{ "type": "response_answer_ip", "cidr": "192.0.2.0/24" }],
                    "response_actions_on_match": [{ "type": "jump_to_pipeline", "pipeline": "abroad" }]
                }] },
                { "id": "abroad", "rules": [{
                    "name": "abroad", "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "forward", "upstream": abroad.address }]
                }] }
            ]
        }));
        for _ in 0..3 {
            assert_eq!(ask(&engine).await, [Ipv4Addr::new(198, 51, 100, 1)]);
        }
        assert_eq!((domestic.queries(), abroad.queries()), (1, 1));
    }
}

#[cfg(test)]
mod geo_lock_tests {
    use std::net::Ipv4Addr;
    use std::sync::mpsc;
    use std::time::Duration;

    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};

    use crate::engine::test_support::{answering_upstream, ask, engine_from, first_a, peer};

    /// 不用 Geo 数据的回答检查一把 Geo 读锁都不拿：GeoIP、GeoSite 都在写入时，它照样答上。以前每次检查都等着把两把锁都拿到
    /// An answer check using no Geo data takes no Geo read lock: with GeoIP and GeoSite both
    /// being written it still answers. Every check used to wait until it held both
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_answer_check_without_geo_conditions_takes_no_geo_lock() {
        let answer = Ipv4Addr::new(192, 0, 2, 1);
        let upstream = answering_upstream(answer, 60).await;
        let engine = engine_from(serde_json::json!({
            "settings": { "default_upstream": "127.0.0.1:9" },
            "pipelines": [{ "id": "main", "rules": [{
                "name": "checked", "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": upstream.address }],
                "response_matchers": [{ "type": "response_answer_ip", "cidr": "192.0.2.0/24" }],
                "response_actions_on_match": [{ "type": "allow" }]
            }] }]
        }));
        let mut query = Message::new(0x6c6c, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
        let query = query.to_vec().unwrap();

        let (geoip, geosite) = (engine.geoip_manager.clone(), engine.geosite_manager.clone());
        let writing = (geoip.write(), geosite.write());
        // 等在这个线程上，不用运行时的计时器：读锁要是拿不到，等着的那个工作线程也就不再推动计时器
        // Waited for on this thread, not with the runtime's timer: a worker stuck waiting for a
        // read lock no longer drives the timer either
        let (answered, reply) = mpsc::channel();
        tokio::spawn(async move {
            let _ = answered.send(ask(&engine, &query, peer()).await);
        });
        let reply = reply.recv_timeout(Duration::from_secs(3));
        drop(writing);
        let reply = reply.expect("answered while the Geo data was written");
        assert_eq!(first_a(&reply), Some(answer));
    }
}
