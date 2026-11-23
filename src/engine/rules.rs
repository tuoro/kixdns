use anyhow::Context;
use bytes::Bytes;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{DNSClass, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use rustc_hash::FxHasher;
use smallvec::SmallVec;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::observation::report_response_decision;
use crate::cache_store::Cached;
use crate::config::{Action, Transport};
use crate::engine::core::Engine;
use crate::engine::execution::Request;
use crate::engine::matcher_adapter::log_match;
use crate::engine::response::{
    least_ttl, make_static_cname_answer, make_static_ip_answer, make_static_txt_answer,
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
        /// 它带的 TTL：记录里最小的，没有记录时为 None（见 `phases::static_ttl`）/ The TTL it
        /// carries: the least of its records', None without records (see `phases::static_ttl`)
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

/// 规则缓存里的决策最多用这么久，不论决策本身的 TTL。键已经跟着配置和 Geo 数据走（命名空间见
/// `EngineInner::at_geo`，请求方的判定见 `RequesterScope`），这个上限让一条决策过一阵就重新求值，只问过一次的
/// 名字占着的地方也由清扫收回
/// The longest a rule cache decision serves, whatever its own TTL. The keys already follow
/// the configuration and the Geo data (the namespaces see `EngineInner::at_geo`, the
/// judgement of the requester `RequesterScope`); this bound has a decision evaluated again
/// after a while, and the room a name asked once takes is reclaimed by the sweep
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

/// 执行响应动作要的：请求本身（问题、谁在问、用的配置、观察者），和它这次转发的几样
/// What running the response actions takes: the request itself (its question, who is asking,
/// the configuration it uses, its observer), and a few things of this forward of it
pub(crate) struct ApplyResponseActionsContext<'a> {
    pub(crate) engine: &'a Engine,
    pub(crate) request: &'a Request<'a>,
    pub(crate) actions: &'a [Action],
    pub(crate) ctx_opt: Option<ResponseContext>,
    pub(crate) req: &'a Message,
    /// 规则自己的转发发出的包；动作里自己写了 `ecs` 的转发从客户端发来的查询改写（见 `Request::packet`）
    /// The packet the rule's own forward sent; a forward among the actions writing an `ecs` of
    /// its own rewrites the query as the client sent it instead (see `Request::packet`)
    pub(crate) packet: &'a [u8],
    pub(crate) pipeline_id: &'a str,
    pub(crate) rule_name: &'a str,
    pub(crate) remaining_jumps: usize,
    /// Where a forward among the actions records its reply, or its failure, and the
    /// ECS the rule's own forward sent, which a forward among the actions without an `ecs` of
    /// its own sends too, forwarding the same packet (see `Route::trail`).
    /// None where nothing is cached.
    /// 动作里的转发在哪里记下它的应答或失败，以及规则自己的转发发出的 ECS：动作里没写 `ecs` 的转发发的是同一个包，
    /// 也就是这一份（见 `Route::trail`）。不缓存的地方为 None。
    pub(crate) trail: Option<(
        &'a mut crate::ecs_scope::EcsReach,
        crate::ecs_scope::ForwardEcs,
    )>,
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
                log_match(level.as_deref(), ctx.rule_name, qname, request.peer.ip());
            }
            Action::StaticResponse { rcode } => {
                let code = parse_rcode(rcode).unwrap_or(ResponseCode::NXDomain);
                return static_answer(ctx.req, code, Vec::new(), "response_action");
            }
            Action::StaticIpResponse { ip } => {
                let (rcode, answers) = make_static_ip_answer(qname, qtype, qclass, ip);
                return static_answer(ctx.req, rcode, answers, "response_action");
            }
            Action::StaticCnameResponse { target, ttl } => {
                let (rcode, answers) =
                    make_static_cname_answer(qname, qclass, target, ttl.unwrap_or(300));
                return static_answer(ctx.req, rcode, answers, "response_action");
            }
            Action::StaticTxtResponse { text, ttl } => {
                let (rcode, answers) =
                    make_static_txt_answer(qname, qtype, qclass, text, ttl.unwrap_or(300));
                return static_answer(ctx.req, rcode, answers, "response_action");
            }
            Action::JumpToPipeline { pipeline } => {
                if ctx.remaining_jumps == 0 {
                    let bytes = engine_helpers::build_servfail_response(ctx.req)?;
                    return Ok(ResponseActionResult::Static {
                        bytes,
                        rcode: ResponseCode::ServFail,
                        ttl: None,
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
                    ttl: None,
                    source: "response_action",
                });
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
                    return response_action_servfail(ctx.req);
                }
                let (rcode, answers) = make_static_txt_answer(qname, qtype, qclass, text, 300);
                return static_answer(ctx.req, rcode, answers, "replace_txt");
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
                    return response_action_servfail(ctx.req);
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
                    request.state.pipeline.upstream_timeout(),
                    Some(use_transport),
                    pre_split_upstreams.as_ref(),
                    request.observed,
                    request.asker(),
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
                                qname = %qname,
                                client_ip = %request.peer.ip(),
                                error = %err,
                                "flow control kept the response action forward from the upstream"
                            );
                        } else {
                            crate::warn_sparse!(
                                event = "response_action_failure",
                                upstream = %upstream_addr,
                                qname = %qname,
                                qtype = ?qtype,
                                client_ip = %request.peer.ip(),
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

/// 响应动作照请求给出的静态应答，带着它记录里最小的 TTL / A static answer the response actions give
/// for the request, with the least TTL of its records
fn static_answer(
    req: &Message,
    rcode: ResponseCode,
    answers: Vec<Record>,
    source: &'static str,
) -> anyhow::Result<ResponseActionResult> {
    Ok(ResponseActionResult::Static {
        ttl: least_ttl(&answers),
        bytes: build_response(req, rcode, answers)?,
        rcode,
        source,
    })
}

/// 响应动作给不出应答时的 SERVFAIL / The SERVFAIL of response actions that find no answer
fn response_action_servfail(req: &Message) -> anyhow::Result<ResponseActionResult> {
    Ok(ResponseActionResult::Static {
        bytes: engine_helpers::build_servfail_response(req)?,
        rcode: ResponseCode::ServFail,
        ttl: None,
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
