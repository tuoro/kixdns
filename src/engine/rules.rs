use anyhow::Context;
use bytes::Bytes;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::rdata::TXT;
use hickory_proto::rr::{DNSClass, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use rustc_hash::FxHasher;
use smallvec::SmallVec;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::warn;

use super::observation::{Observed, report_response_decision};
use crate::cache_store::Cached;
use crate::config::{Action, Transport};
use crate::engine::core::Engine;
use crate::engine::matcher_adapter::log_match;
use crate::engine::response::{
    make_static_cname_answer, make_static_ip_answer, make_static_txt_answer,
};
use crate::engine::upstream::UpstreamFailure;
use crate::engine::utils::engine_helpers::{self, build_response};
use crate::engine::utils::parse_rcode;
use crate::matcher::RuntimeResponseMatcherWithOp;
use crate::matcher::eval_match_chain;
use crate::matcher::{RequesterKey, ResponsePhase};

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
        /// 作出决策的规则在它的规则组里排第几（从 0 起）；没有规则作出决策时为 None。它 continue 以后按这个
        /// 位置跳过它，不按名字：名字只是标签，两条规则可以同名
        /// The place in its pipeline (from 0) of the rule that decided; None when no rule did.
        /// Once it continues it is skipped by this place, not by name: a name is a label, and
        /// two rules may share one
        rule_index: Option<usize>,
        transport: Option<Transport>, // None means each upstream decides itself (via protocol prefix) / None 表示每个 upstream 自己决定（通过协议前缀）
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
        Decision::Forward {
            upstream: settings.default_upstream_arc(),
            pre_split_upstreams: settings.default_upstream_pre_split.clone(),
            response_phase: None,
            rule_name: Arc::clone(&DEFAULT_RULE_NAME),
            rule_index: None,
            transport: Some(Transport::Udp),
            ecs: None,
            allow_reuse: false,
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
        source: &'static str,
    },
    /// 跳到 `pipeline` 接着走规则；次数由跳过去的一方数（见 `handle_packet_internal`），这里只看还剩没剩
    /// Jump to `pipeline` and go on with its rules; the side making the jump counts it (see
    /// `handle_packet_internal`), and this only checks whether any are left
    Jump {
        pipeline: Arc<str>,
    },
    Continue {
        ctx: Option<ResponseContext>,
    },
}

#[inline]
pub fn calculate_rule_hash(
    cache_namespace: u64,
    pipeline_id: &str,
    qname: &str,
    qtype: RecordType,
    qclass: DNSClass,
    requester: &RequesterKey,
) -> u64 {
    let mut hasher = FxHasher::default();
    cache_namespace.hash(&mut hasher);
    pipeline_id.hash(&mut hasher);
    qname.hash(&mut hasher);
    u16::from(qtype).hash(&mut hasher);
    u16::from(qclass).hash(&mut hasher);
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
    /// Expiration time based on DNS TTL / 基于 DNS TTL 的过期时间
    pub expires_at: Option<Instant>,
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

/// 规则缓存里的决策最多用这么久，不论决策本身的 TTL：键不随 GeoIP/GeoSite 数据更新而变，靠它限制
/// 按旧数据做的决策还能用多久
/// The longest a rule cache decision serves, whatever its own TTL: the key does not
/// change when GeoIP/GeoSite data updates, so this bounds how long a decision made on
/// the old data goes on serving
pub(crate) const RULE_CACHE_MAX_AGE: Duration = Duration::from_secs(60);

/// 每条记录计重 1；`expires_at` 已经含了 `RULE_CACHE_MAX_AGE`，按它判断过期
/// Each record weighs 1; `expires_at` already includes `RULE_CACHE_MAX_AGE`, so it
/// decides when a record is outlived
impl Cached for Arc<RuleCacheRecord> {
    fn weight(&self) -> u32 {
        1
    }

    fn outlived(&self, _kept: Duration, now: Instant) -> bool {
        !self.entry.is_valid_at(now)
    }
}

impl RuleCacheEntry {
    pub fn new(
        pipeline_id: Arc<str>,
        qname: &str,
        qtype: RecordType,
        qclass: DNSClass,
        requester: RequesterKey,
        decision: Decision,
    ) -> Self {
        Self {
            pipeline_id,
            qname: SmallVec::from_slice(qname.as_bytes()),
            qtype: u16::from(qtype),
            qclass: u16::from(qclass),
            requester,
            decision,
            expires_at: None,
        }
    }

    #[inline]
    pub fn matches(
        &self,
        pipeline_id: &str,
        qname: &str,
        qtype: RecordType,
        qclass: DNSClass,
        requester: &RequesterKey,
    ) -> bool {
        self.matches_at(Instant::now(), pipeline_id, qname, qtype, qclass, requester)
    }

    /// 同 [`Self::matches`]，时刻是已经读好的 / As [`Self::matches`], with the moment already read
    #[inline]
    pub fn matches_at(
        &self,
        now: Instant,
        pipeline_id: &str,
        qname: &str,
        qtype: RecordType,
        qclass: DNSClass,
        requester: &RequesterKey,
    ) -> bool {
        // Check expiration first / 首先检查过期
        if !self.is_valid_at(now) {
            return false;
        }

        if self.qtype != u16::from(qtype) || self.qclass != u16::from(qclass) {
            return false;
        }

        if self.requester != *requester {
            return false;
        }

        self.pipeline_id.as_ref() == pipeline_id && self.qname.as_slice() == qname.as_bytes()
    }

    /// 在 `now` 这一刻还有效 / Still valid at `now`
    #[inline]
    pub fn is_valid_at(&self, now: Instant) -> bool {
        self.expires_at.is_none_or(|expires| now <= expires)
    }
}

/// 辅助函数：获取 GeoIP 和 GeoSite 锁（带非阻塞快速路径）
/// Helper function: Acquire GeoIP and GeoSite locks (with non-blocking fast path)
///
/// 优化：消除重复的锁获取逻辑 / Optimization: Eliminate duplicate lock acquisition logic
///
/// 有争用时，先放掉已经拿到的那把，再按固定顺序阻塞读取：先 GeoSite、后 GeoIP，和 `select_pipeline`
/// 一样。不这样做会卡死，原因有两个：
/// - 再读一次已经持有的锁：parking_lot 的 `read()` 在有写者排队时要等那个写者，而写者在等这个线程
///   放掉第一次读；
/// - 拿着一把、按相反的顺序等另一把：两边的写者同时排队时，几方互相等待。
///
/// On contention, drop whichever lock was taken and block in one fixed order, GeoSite then GeoIP,
/// as `select_pipeline` does. Otherwise it can deadlock in two ways:
/// - reading a held lock again: parking_lot's `read()` waits behind a queued writer, which waits
///   for this thread's first read;
/// - holding one lock while waiting for the other in the opposite order: once writers queue on
///   both, the parties wait on each other.
#[inline]
pub(crate) fn acquire_geo_locks<'a>(
    engine: &'a Engine,
) -> (
    Option<parking_lot::RwLockReadGuard<'a, crate::matcher::geoip::GeoIpManager>>,
    Option<parking_lot::RwLockReadGuard<'a, crate::matcher::geosite::GeoSiteManager>>,
) {
    // Try to acquire read locks non-blockingly (fast path for concurrent reads)
    // 尝试非阻塞获取读锁（并发读的快速路径）
    let mut geoip_manager = engine.geoip_manager.try_read();
    let mut geosite_manager = engine.geosite_manager.try_read();

    // Fallback to blocking read if try_read fails (rare write operation in progress)
    // 如果 try_read 失败则回退到阻塞读取（罕见的写操作进行中）
    if geoip_manager.is_none() || geosite_manager.is_none() {
        tracing::debug!("GeoIP/GeoSite lock contention, falling back to blocking read");
        drop(geoip_manager.take());
        drop(geosite_manager.take());
        geosite_manager = Some(engine.geosite_manager.read());
        geoip_manager = Some(engine.geoip_manager.read());
    }

    (geoip_manager, geosite_manager)
}

/// 几个上游一起问、全都失败、其中有上游回了失败应答时（见 `UpstreamFailure`），把最先收到的那个
/// 应答连同回它的上游交给规则的回答检查 `check`：检查通过、而且通过后有动作（`on_match`）要执行时，它就是这次转发
/// 的应答，和只问一个上游时一样。其余情况照旧是失败：检查不通过时 on_miss 照旧在没有应答的情况下
/// 执行，没有 on_miss 时照旧是过期缓存或 SERVFAIL。后台刷新不受影响：两处调用之后紧跟着
/// `reject_failure_reply_on_refresh`，刷新照旧拿到失败，缓存的条目不动。
/// When several upstreams asked together all failed and one of them replied with a failure
/// (see `UpstreamFailure`), the first such reply goes to the rule's answer check `check`
/// with the upstream that sent it:
/// when it passes and has actions to run (`on_match`), that reply is this forward's answer,
/// as with a single upstream. Otherwise it stays a failure: when the check fails on_miss
/// still runs without an answer, and without on_miss the stale entry or SERVFAIL still
/// answers. A background refresh is not affected: both callers run
/// `reject_failure_reply_on_refresh` right after, so the refresh still gets the failure
/// and leaves the cached entry alone.
pub(crate) fn check_failure_reply(
    resp: anyhow::Result<(Bytes, Arc<str>)>,
    on_match: &[Action],
    check: impl FnOnce(&Message, &str) -> bool,
) -> anyhow::Result<(Bytes, Arc<str>)> {
    let Err(err) = resp else {
        return resp;
    };
    if on_match.is_empty() {
        return Err(err);
    }
    match UpstreamFailure::reply_of(&err) {
        Some((raw, upstream))
            if Message::from_bytes(raw).is_ok_and(|msg| check(&msg, upstream)) =>
        {
            Ok((raw.clone(), upstream.clone()))
        }
        _ => Err(err),
    }
}

/// 响应匹配器对 `upstream`（作答的上游，`udp:1.1.1.1:53`）给的应答 `msg` 是否成立；没有应答（`None`）时不成立。没有匹配器时成立，也不用去拿
/// GeoIP、GeoSite 的读锁；有匹配器时读锁只在求值时拿着
/// Whether the response matchers hold for the answer `msg` that `upstream` gave (the
/// answering upstream, `udp:1.1.1.1:53`); without an answer (`None`) they do not. With no matchers they hold, and the GeoIP and GeoSite read locks are not
/// taken; with some, the locks are held only while they are evaluated
pub(crate) fn response_matches(
    engine: &Engine,
    matchers: &[RuntimeResponseMatcherWithOp],
    upstream: &str,
    qname: &str,
    qtype: RecordType,
    qclass: DNSClass,
    msg: Option<&Message>,
) -> bool {
    let Some(msg) = msg else {
        return false;
    };
    if matchers.is_empty() {
        return true;
    }
    let (geoip_manager, geosite_manager) = acquire_geo_locks(engine);
    eval_match_chain(
        matchers,
        |m| m.operator,
        |m| {
            m.matcher.matches(
                upstream,
                qname,
                qtype,
                qclass,
                msg,
                geoip_manager.as_deref(),
                geosite_manager.as_deref(),
            )
        },
    )
}

/// 请求问题的类别：静态应答照它给不给记录（见 `has_static_records`）。回答阶段的应答照抄这个请求的问题
/// The class of the request's question, by which a static answer gives records or not
/// (see `has_static_records`). A response-phase answer copies this request's question
fn question_class(req: &Message) -> DNSClass {
    req.queries
        .first()
        .map_or(DNSClass::IN, |question| question.query_class())
}

pub struct ApplyResponseActionsContext<'a> {
    pub engine: &'a Engine,
    pub actions: &'a [Action],
    pub ctx_opt: Option<ResponseContext>,
    pub req: &'a Message,
    /// 规则自己的转发发出的包 / The packet the rule's own forward sent
    pub packet: &'a [u8],
    /// 客户端发来的查询，和它自己带的 ECS（见 `ForwardDecisionContext::query`）/ The query as the client sent
    /// it, and the ECS it carried itself (see `ForwardDecisionContext::query`)
    pub query: &'a [u8],
    pub client_ecs: Option<crate::ecs::EcsKey>,
    pub upstream_timeout: Duration,
    pub qname: &'a str,
    pub qtype: RecordType,
    pub client_ip: IpAddr,
    /// 响应动作里的转发是替谁问的；后台刷新不替谁问，是 None（见 `upstream::forward_upstream`）/ Whom a forward
    /// among the response actions is asked for; None on a background refresh, asked for nobody
    /// (see `upstream::forward_upstream`)
    pub asker: Option<IpAddr>,
    pub upstream_default: &'a str,
    pub pipeline_id: &'a str,
    pub rule_name: &'a str,
    pub remaining_jumps: usize,
    /// Where a forward among the actions records its reply, or its failure, and the
    /// ECS the rule's own forward sent, which a forward among the actions without an `ecs` of
    /// its own sends too, forwarding the same packet (see `ForwardDecisionContext::trail`).
    /// None where nothing is cached.
    /// 动作里的转发在哪里记下它的应答或失败，以及规则自己的转发发出的 ECS：动作里没写 `ecs` 的转发发的是同一个包，
    /// 也就是这一份（见 `ForwardDecisionContext::trail`）。不缓存的地方为 None。
    pub trail: Option<(
        &'a mut crate::ecs_scope::EcsReach,
        crate::ecs_scope::ForwardEcs,
    )>,
}

/// Test-only shorthand for [`apply_response_actions_observed`] without an observer context.
#[cfg(test)]
pub(crate) async fn apply_response_actions(
    ctx: ApplyResponseActionsContext<'_>,
) -> anyhow::Result<ResponseActionResult> {
    apply_response_actions_observed(ctx, None).await
}

/// [`apply_response_actions`] with the observer context of the request, so
/// upstream attempts made by response-phase `forward` actions are reported, and
/// so is the decision the actions arrive at.
/// 带观察者上下文的 [`apply_response_actions`]，使响应阶段 forward 动作的上游尝试得以上报，
/// 动作最后作出的决定也一并上报。
pub(crate) async fn apply_response_actions_observed(
    ctx: ApplyResponseActionsContext<'_>,
    observed: Observed<'_>,
) -> anyhow::Result<ResponseActionResult> {
    let (pipeline, rule) = (ctx.pipeline_id, ctx.rule_name);
    let result = run_response_actions(ctx, observed).await?;
    if let Some((observer, request)) = observed {
        report_response_decision(observer, request, pipeline, rule, &result);
    }
    Ok(result)
}

async fn run_response_actions(
    mut ctx: ApplyResponseActionsContext<'_>,
    observed: Observed<'_>,
) -> anyhow::Result<ResponseActionResult> {
    const MAX_RESPONSE_FORWARDS: usize = 4;
    let mut forward_attempts = 0usize;

    for action in ctx.actions {
        match action {
            Action::Log { level } => {
                log_match(level.as_deref(), ctx.rule_name, ctx.qname, ctx.client_ip);
            }
            Action::StaticResponse { rcode } => {
                let code = parse_rcode(rcode).unwrap_or(ResponseCode::NXDomain);
                let bytes = build_response(ctx.req, code, Vec::new())?;
                return Ok(ResponseActionResult::Static {
                    bytes,
                    rcode: code,
                    source: "response_action",
                });
            }
            Action::StaticIpResponse { ip } => {
                let (rcode, answers) =
                    make_static_ip_answer(ctx.qname, ctx.qtype, question_class(ctx.req), ip);
                let bytes = build_response(ctx.req, rcode, answers)?;
                return Ok(ResponseActionResult::Static {
                    bytes,
                    rcode,
                    source: "response_action",
                });
            }
            Action::StaticCnameResponse { target, ttl } => {
                let (rcode, answers) = make_static_cname_answer(
                    ctx.qname,
                    question_class(ctx.req),
                    target,
                    ttl.unwrap_or(300),
                );
                let bytes = build_response(ctx.req, rcode, answers)?;
                return Ok(ResponseActionResult::Static {
                    bytes,
                    rcode,
                    source: "response_action",
                });
            }
            Action::StaticTxtResponse { text, ttl } => {
                let ttl = ttl.unwrap_or(300);
                let (rcode, answers) = make_static_txt_answer(
                    ctx.qname,
                    ctx.qtype,
                    question_class(ctx.req),
                    text,
                    ttl,
                );
                let bytes = build_response(ctx.req, rcode, answers)?;
                return Ok(ResponseActionResult::Static {
                    bytes,
                    rcode,
                    source: "response_action",
                });
            }
            Action::JumpToPipeline { pipeline } => {
                if ctx.remaining_jumps == 0 {
                    let bytes = engine_helpers::build_servfail_response(ctx.req)?;
                    return Ok(ResponseActionResult::Static {
                        bytes,
                        rcode: ResponseCode::ServFail,
                        source: JUMP_LIMIT,
                    });
                }
                return Ok(ResponseActionResult::Jump {
                    pipeline: Arc::from(pipeline.as_str()),
                });
            }
            // 和所有动作执行完一样：有应答就交出它，没有就 SERVFAIL
            // As when every action has run: the answer if there is one, SERVFAIL if not
            Action::Allow => break,
            Action::Deny => {
                let bytes = engine_helpers::build_refused_response(ctx.req)?;
                return Ok(ResponseActionResult::Static {
                    bytes,
                    rcode: ResponseCode::Refused,
                    source: "response_action",
                });
            }
            Action::Continue => {
                return Ok(ResponseActionResult::Continue { ctx: ctx.ctx_opt });
            }
            Action::ReplaceTxtResponse { text } => {
                if let Some(ref resp_ctx) = ctx.ctx_opt {
                    let name = resp_ctx
                        .msg
                        .queries
                        .first()
                        .map(|q| q.name().clone())
                        .ok_or_else(|| anyhow::anyhow!("No query name"))?;

                    // 和静态 TXT 一样，装不进应答时回 SERVFAIL（见 `txt_size_problem`）
                    // As for a static TXT, SERVFAIL when it does not fit the answer (see
                    // `txt_size_problem`)
                    if let Some(problem) = crate::engine::response::txt_size_problem(
                        text,
                        crate::engine::response::name_wire_len(&name),
                    ) {
                        warn!(qname = %ctx.qname, %problem, "replaced TXT answer does not fit a message");
                        return response_action_servfail(ctx.req);
                    }
                    // Create new TXT record / 创建新的 TXT 记录
                    let txt = TXT::new(text.to_vec());
                    let record = Record::from_rdata(name, 300, RData::TXT(txt));

                    // Replace TXT records in answers / 替换答案中的 TXT 记录
                    let new_answers = vec![record];
                    let rcode = resp_ctx.msg.metadata.response_code;

                    let bytes = build_response(ctx.req, rcode, new_answers)?;
                    return Ok(ResponseActionResult::Static {
                        bytes,
                        rcode,
                        source: "replace_txt",
                    });
                }
                return response_action_servfail(ctx.req);
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
                        qname = %ctx.qname,
                        qtype = ?ctx.qtype,
                        client_ip = %ctx.client_ip,
                        pipeline = %ctx.pipeline_id,
                        rule = %ctx.rule_name,
                        "response actions exceeded forward limit"
                    );
                    return response_action_servfail(ctx.req);
                }

                // 手上应答记的来源（`udp:1.1.1.1:53`）不是能发查询的地址，所以没写 upstream 时和请求
                // 阶段一样用 default_upstream
                // Where the answer in hand came from (`udp:1.1.1.1:53`) is no address to query,
                // so without an upstream this uses default_upstream as the request phase does
                let upstream_addr: Arc<str> =
                    Arc::from(upstream.as_deref().unwrap_or(ctx.upstream_default));
                let use_transport = transport.unwrap_or(Transport::Udp);
                // 自己写了 `ecs` 的照它从客户端的查询改写，应答适用于谁也按它算；没写的和规则自己的转发发同一个包。以前
                // 这里的 `ecs` 读进来就丢掉了
                // One writing an `ecs` of its own rewrites the client's query by it, and whom the
                // reply applies to goes by it too; one without sends the packet of the rule's own
                // forward. The `ecs` here used to be read and dropped
                let own_ecs = ecs.as_ref().map(|mode| {
                    let view = crate::ecs_scope::EcsView {
                        peer: ctx.client_ip,
                        client: ctx.client_ecs,
                    };
                    let packet = crate::ecs::apply_ecs_for(
                        ctx.query,
                        mode,
                        ctx.client_ip,
                        ctx.client_ecs.as_ref(),
                    );
                    (packet, crate::ecs_scope::ForwardEcs::of(Some(mode), &view))
                });
                let packet = own_ecs.as_ref().map_or(ctx.packet, |(packet, _)| packet);
                if let (Some((trail, _)), Some((packet, sent))) = (ctx.trail.as_mut(), &own_ecs) {
                    trail.check_sent(packet, sent);
                }
                let sent_ecs = |rule_ecs: crate::ecs_scope::ForwardEcs| {
                    own_ecs.as_ref().map_or(rule_ecs, |(_, sent)| *sent)
                };
                let (raw, actual_upstream) = match crate::engine::upstream::forward_upstream(
                    ctx.engine,
                    packet,
                    &upstream_addr,
                    ctx.upstream_timeout,
                    Some(use_transport),
                    pre_split_upstreams.as_ref(),
                    observed,
                    ctx.asker,
                )
                .await
                {
                    Ok(result) => {
                        if let Some((trail, rule_ecs)) = ctx.trail.as_mut() {
                            trail.record_reply(sent_ecs(*rule_ecs), &result.0);
                        }
                        result
                    }
                    Err(err) => {
                        if let Some((trail, rule_ecs)) = ctx.trail.as_mut() {
                            trail.record_failure(sent_ecs(*rule_ecs));
                        }
                        if UpstreamFailure::was_withheld(&err) {
                            tracing::debug!(
                                event = "response_action_withheld",
                                upstream = %upstream_addr,
                                qname = %ctx.qname,
                                client_ip = %ctx.client_ip,
                                error = %err,
                                "flow control kept the response action forward from the upstream"
                            );
                        } else {
                            crate::warn_sparse!(
                                event = "response_action_failure",
                                upstream = %upstream_addr,
                                qname = %ctx.qname,
                                qtype = ?ctx.qtype,
                                client_ip = %ctx.client_ip,
                                pipeline = %ctx.pipeline_id,
                                rule = %ctx.rule_name,
                                error = %err,
                                "response action forward failed"
                            );
                        }
                        // 流控没让等的失败是这台设备自己的事（见 `UpstreamFailure::withheld`）：原样交回，这个
                        // 请求出错、由监听器回 SERVFAIL，它登记的条目随之放下，不把 SERVFAIL 交给等着的别的请求
                        // A failure with flow control keeping the query from waiting is the
                        // device's own affair (see `UpstreamFailure::withheld`): it goes back
                        // as it is, the request fails with the listener answering SERVFAIL,
                        // and the entries it registered go with it, no SERVFAIL being handed
                        // to the other requests waiting
                        if err.downcast_ref::<UpstreamFailure>().is_none()
                            || UpstreamFailure::was_withheld(&err)
                        {
                            return Err(err);
                        }
                        return response_action_servfail(ctx.req);
                    }
                };
                let msg = Message::from_bytes(&raw).context("parse upstream response")?;
                ctx.ctx_opt = Some(ResponseContext {
                    raw,
                    msg,
                    upstream: actual_upstream, // Use actual responding upstream
                });
            }
        }
    }

    // 动作都执行完：有应答就交出它，没有就 SERVFAIL
    // Every action has run: the answer if there is one, SERVFAIL if not
    match ctx.ctx_opt {
        Some(resp_ctx) => Ok(ResponseActionResult::Upstream { ctx: resp_ctx }),
        None => response_action_servfail(ctx.req),
    }
}

/// 响应动作给不出应答时的 SERVFAIL / The SERVFAIL of response actions that find no answer
fn response_action_servfail(req: &Message) -> anyhow::Result<ResponseActionResult> {
    Ok(ResponseActionResult::Static {
        bytes: engine_helpers::build_servfail_response(req)?,
        rcode: ResponseCode::ServFail,
        source: "response_action",
    })
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
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use super::acquire_geo_locks;
    use crate::engine::Engine;
    use crate::engine::test_support::engine_from;

    fn engine() -> Engine {
        engine_from(serde_json::json!({
            "settings": { "default_upstream": "127.0.0.1:9" },
            "pipelines": [{ "id": "main", "rules": [] }]
        }))
    }

    /// GeoIP is being written, so the reader gets only GeoSite and waits for GeoIP.
    /// Meanwhile a GeoSite writer queues behind the reader's read. Reading GeoSite a
    /// second time would wait behind that writer, which waits for the reader: a deadlock.
    /// GeoIP 正在写入，读者只拿到 GeoSite，然后等 GeoIP；这时一个 GeoSite 写者排在它的读锁
    /// 后面。再读一次 GeoSite 就要等那个写者，而写者在等读者，两边卡死。
    #[tokio::test]
    async fn waiting_for_one_geo_lock_never_reads_the_other_again() {
        let engine = engine();
        let geoip = engine.geoip_manager.clone();
        let geosite = engine.geosite_manager.clone();

        let geoip_write = geoip.write();
        let (done, finished) = mpsc::channel();
        let reader_engine = engine.clone();
        let reader = std::thread::spawn(move || {
            let (geoip_read, geosite_read) = acquire_geo_locks(&reader_engine);
            let both = geoip_read.is_some() && geosite_read.is_some();
            drop((geoip_read, geosite_read));
            let _ = done.send(both);
        });

        // The reader holds GeoSite once its try_read succeeded; it then waits for GeoIP.
        // 读者的 try_read 拿到 GeoSite 后就一直持有，接着等 GeoIP。
        let deadline = Instant::now() + Duration::from_secs(5);
        while !geosite.is_locked() {
            assert!(Instant::now() < deadline, "the reader never took GeoSite");
            std::thread::sleep(Duration::from_millis(1));
        }
        let queued = geosite.clone();
        let writer = std::thread::spawn(move || drop(queued.write()));
        // Give the writer time to queue behind the reader's read.
        // 给写者时间排到读者的读锁后面。
        std::thread::sleep(Duration::from_millis(200));

        drop(geoip_write);
        assert_eq!(
            finished.recv_timeout(Duration::from_secs(5)),
            Ok(true),
            "the reader must get both locks without reading GeoSite twice"
        );
        reader.join().unwrap();
        writer.join().unwrap();
    }

    /// Another reader, like `select_pipeline`, holds GeoSite and goes on to read GeoIP. A GeoSite
    /// writer queues behind it, so the helper gets GeoIP but not GeoSite. Had the helper kept
    /// GeoIP and waited for GeoSite, a GeoIP writer queued behind it would stop the other
    /// reader's GeoIP read, and the four would wait on each other.
    /// 另一个读者像 `select_pipeline` 那样拿着 GeoSite、接着读 GeoIP；一个 GeoSite 写者排在它后面，
    /// 于是辅助函数拿到 GeoIP、拿不到 GeoSite。要是它拿着 GeoIP 等 GeoSite，排在它后面的 GeoIP 写者
    /// 会挡住另一个读者读 GeoIP，四方互相等待。
    #[tokio::test]
    async fn the_fallback_takes_geosite_before_geoip_as_select_pipeline_does() {
        let engine = engine();
        let geoip = engine.geoip_manager.clone();
        let geosite = engine.geosite_manager.clone();
        let pause = || std::thread::sleep(Duration::from_millis(200));

        let (go, wait_for_go) = mpsc::channel::<()>();
        let (holding, held) = mpsc::channel::<()>();
        let (other_done, other_finished) = mpsc::channel::<()>();
        let (other_geosite, other_geoip) = (geosite.clone(), geoip.clone());
        let other = std::thread::spawn(move || {
            let geosite_read = other_geosite.read();
            holding.send(()).unwrap();
            wait_for_go.recv().unwrap();
            let geoip_read = other_geoip.read();
            drop((geoip_read, geosite_read));
            let _ = other_done.send(());
        });
        held.recv().unwrap();

        let queued_geosite = geosite.clone();
        let geosite_writer = std::thread::spawn(move || drop(queued_geosite.write()));
        pause();

        let (done, finished) = mpsc::channel();
        let reader_engine = engine.clone();
        let reader = std::thread::spawn(move || {
            let (geoip_read, geosite_read) = acquire_geo_locks(&reader_engine);
            let both = geoip_read.is_some() && geosite_read.is_some();
            drop((geoip_read, geosite_read));
            let _ = done.send(both);
        });
        pause();

        let queued_geoip = geoip.clone();
        let geoip_writer = std::thread::spawn(move || drop(queued_geoip.write()));
        pause();
        go.send(()).unwrap();

        assert_eq!(
            finished.recv_timeout(Duration::from_secs(5)),
            Ok(true),
            "the helper must wait for GeoSite holding nothing, then take GeoIP"
        );
        assert!(
            other_finished.recv_timeout(Duration::from_secs(5)).is_ok(),
            "the other reader must get GeoIP"
        );
        for thread in [other, geosite_writer, reader, geoip_writer] {
            thread.join().unwrap();
        }
    }
}
