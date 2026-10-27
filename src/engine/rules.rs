use anyhow::Context;
use bytes::{Bytes, BytesMut};
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::rdata::TXT;
use hickory_proto::rr::{DNSClass, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use rustc_hash::{FxHashSet, FxHasher};
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::warn;

use crate::config::{Action, Transport};
use crate::engine::core::Engine;
use crate::engine::matcher_adapter::log_match;
use crate::engine::pipeline::RuleEvaluationContext;
use crate::engine::response::{
    make_static_cname_answer, make_static_ip_answer, make_static_txt_answer,
};
use crate::engine::types::EngineInner;
use crate::engine::types::{InflightEntry, InflightMap, InflightQuestion, inflight_pending};
use crate::engine::upstream::{UpstreamFailure, reject_failure_reply_on_refresh};
use crate::engine::utils::engine_helpers::{self, build_response};
use crate::engine::utils::parse_rcode;
use crate::matcher::RuntimeResponseMatcherWithOp;
use crate::matcher::eval_match_chain;
use crate::matcher::{Requester, RequesterKey, RuntimePipeline};
use crate::observe::{RuleEvaluated, RuleMatched, RulePhase};

use super::observation::{Observed, report_response_decision, response_decision_kind};

#[derive(Debug, Clone)]
pub enum Decision {
    Static {
        rcode: ResponseCode,
        answers: Vec<Record>,
    },
    Forward {
        upstream: Arc<str>,
        /// Pre-split upstream list (performance optimization) / 预分割的 upstream 列表（性能优化）
        #[allow(dead_code)]
        pre_split_upstreams: Option<std::sync::Arc<Vec<std::sync::Arc<str>>>>,
        response_matchers: Vec<RuntimeResponseMatcherWithOp>,
        response_matcher_operator: crate::config::MatchOperator,
        response_actions_on_match: Vec<Action>,
        response_actions_on_miss: Vec<Action>,
        rule_name: Arc<str>,
        transport: Option<Transport>, // None means each upstream decides itself (via protocol prefix) / None 表示每个 upstream 自己决定（通过协议前缀）
        /// EDNS Client Subnet (RFC 7871) request rewriting mode / EDNS 客户端子网 (RFC 7871) 请求改写模式
        ecs: Option<crate::config::EcsMode>,
        #[allow(dead_code)]
        continue_on_match: bool,
        #[allow(dead_code)]
        continue_on_miss: bool,
        allow_reuse: bool,
    },
    Jump {
        pipeline: Arc<str>,
    },
}

#[derive(Clone, Debug)]
pub struct ResponseContext {
    pub raw: Bytes,
    pub msg: Message,
    pub upstream: Arc<str>,
    pub transport: Transport,
}

/// The `source` of the SERVFAIL that a response action's jump answers when no
/// jumps are left / 响应动作的跳转没有剩余次数时给出的 SERVFAIL 的 `source`
pub const JUMP_LIMIT: &str = "jump_limit";

#[derive(Debug)]
pub enum ResponseActionResult {
    Upstream {
        ctx: ResponseContext,
        resp_match: bool,
    },
    Static {
        bytes: Bytes,
        rcode: ResponseCode,
        source: &'static str,
    },
    Jump {
        pipeline: Arc<str>,
        remaining_jumps: usize,
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

/// The requester's part of a rule cache key for `pipeline`: how its own request
/// matchers judge the requester (see `RuntimePipeline::rule_requester`). With
/// background refresh on, it also carries the client address, as the rule
/// cache did before scopes existed.
/// `pipeline` 的规则缓存键里属于请求方的部分：它自己的请求匹配器对请求方的判定（见
/// `RuntimePipeline::rule_requester`）。开着后台刷新时还带上客户端地址，和引入范围
/// 之前的规则缓存一样。
pub fn rule_cache_requester(
    pipeline: &RuntimePipeline,
    background_refresh: bool,
    requester: Requester,
    geoip_manager: Option<&Arc<crate::lock::RwLock<crate::matcher::geoip::GeoIpManager>>>,
) -> RequesterKey {
    RequesterKey {
        address: background_refresh.then_some(requester.address),
        ..pipeline.rule_requester.key(requester, geoip_manager)
    }
}

#[derive(Clone)]
pub struct RuleCacheEntry {
    pub pipeline_id: Arc<str>,
    pub qname_hash: u64,
    pub qtype: u16,
    pub qclass: u16,
    /// The requester the decision was made for, as far as the key separates it
    /// 决策是为哪个请求方做的（以键区分到的程度为限）
    pub requester: RequesterKey,
    pub decision: Arc<Decision>,
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
            qname_hash: fast_hash_str(qname),
            qtype: u16::from(qtype),
            qclass: u16::from(qclass),
            requester,
            decision: Arc::new(decision),
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
        // Check expiration first / 首先检查过期
        if let Some(expires) = self.expires_at
            && Instant::now() > expires
        {
            return false;
        }

        if self.qtype != u16::from(qtype) || self.qclass != u16::from(qclass) {
            return false;
        }

        if self.requester != *requester {
            return false;
        }

        self.pipeline_id.as_ref() == pipeline_id && self.qname_hash == fast_hash_str(qname)
    }

    /// Check if entry is still valid (not expired)
    /// 检查条目是否仍然有效（未过期）
    #[inline]
    pub fn is_valid(&self) -> bool {
        if let Some(expires) = self.expires_at {
            Instant::now() <= expires
        } else {
            true // No expiration = permanent
        }
    }
}

#[inline]
pub fn fast_hash_str(s: &str) -> u64 {
    let mut h = FxHasher::default();
    s.hash(&mut h);
    h.finish()
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
    Option<crate::lock::RwLockReadGuard<'a, crate::matcher::geoip::GeoIpManager>>,
    Option<crate::lock::RwLockReadGuard<'a, crate::matcher::geosite::GeoSiteManager>>,
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

#[inline]
pub fn contains_continue(actions: &[Action]) -> bool {
    actions
        .iter()
        .any(|action| matches!(action, Action::Continue))
}

pub struct ApplyResponseActionsContext<'a> {
    pub engine: &'a Engine,
    pub actions: &'a [Action],
    pub ctx_opt: Option<ResponseContext>,
    pub req: &'a Message,
    pub packet: &'a [u8],
    pub upstream_timeout: Duration,
    pub response_matchers: &'a [RuntimeResponseMatcherWithOp],
    pub qname: &'a str,
    pub qtype: RecordType,
    pub qclass: DNSClass,
    pub client_ip: IpAddr,
    pub upstream_default: &'a str,
    pub pipeline_id: &'a str,
    pub rule_name: &'a str,
    pub remaining_jumps: usize,
    /// Where a forward among the actions records its reply, or its failure, and the
    /// ECS it sends: the rule's own, as it forwards the same packet (see
    /// `ForwardDecisionContext::trail`). None where nothing is cached.
    /// 动作里的转发在哪里记下它的应答或失败，以及它发出的 ECS：与规则自己的转发相同，因为
    /// 它转发的是同一个包（见 `ForwardDecisionContext::trail`）。不缓存的地方为 None。
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
                let (rcode, answers) = make_static_ip_answer(ctx.qname, ctx.qtype, ip);
                let bytes = build_response(ctx.req, rcode, answers)?;
                return Ok(ResponseActionResult::Static {
                    bytes,
                    rcode,
                    source: "response_action",
                });
            }
            Action::StaticCnameResponse { target, ttl } => {
                let (rcode, answers) =
                    make_static_cname_answer(ctx.qname, target, ttl.unwrap_or(300));
                let bytes = build_response(ctx.req, rcode, answers)?;
                return Ok(ResponseActionResult::Static {
                    bytes,
                    rcode,
                    source: "response_action",
                });
            }
            Action::StaticTxtResponse { text, ttl } => {
                let ttl = ttl.unwrap_or(300);
                let (rcode, answers) = make_static_txt_answer(ctx.qname, text, ttl);
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
                    remaining_jumps: ctx.remaining_jumps - 1,
                });
            }
            Action::Allow => {
                if let Some(resp_ctx) = ctx.ctx_opt {
                    // 优化：使用辅助函数获取锁，消除重复代码
                    // Optimization: Use helper function to acquire locks, eliminate duplicate code
                    let (geoip_manager, geosite_manager) = acquire_geo_locks(ctx.engine);
                    let geoip_manager_ref = geoip_manager.as_deref();
                    let geosite_manager_ref = geosite_manager.as_deref();

                    let resp_match = eval_match_chain(
                        ctx.response_matchers,
                        |m| m.operator,
                        |m| {
                            m.matcher.matches(
                                &resp_ctx.upstream,
                                ctx.qname,
                                ctx.qtype,
                                ctx.qclass,
                                &resp_ctx.msg,
                                geoip_manager_ref,
                                geosite_manager_ref,
                            )
                        },
                    );
                    return Ok(ResponseActionResult::Upstream {
                        ctx: resp_ctx,
                        resp_match,
                    });
                } else {
                    let bytes = engine_helpers::build_servfail_response(ctx.req)?;
                    return Ok(ResponseActionResult::Static {
                        bytes,
                        rcode: ResponseCode::ServFail,
                        source: "response_action",
                    });
                }
            }
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
                let bytes = engine_helpers::build_servfail_response(ctx.req)?;
                return Ok(ResponseActionResult::Static {
                    bytes,
                    rcode: ResponseCode::ServFail,
                    source: "response_action",
                });
            }
            Action::Forward {
                upstream,
                transport,
                ecs: _,
                pre_split_upstreams,
            } => {
                forward_attempts += 1;
                if forward_attempts > MAX_RESPONSE_FORWARDS {
                    warn!(
                        event = "response_action_limit",
                        qname = %ctx.qname,
                        qtype = ?ctx.qtype,
                        client_ip = %ctx.client_ip,
                        pipeline = %ctx.pipeline_id,
                        rule = %ctx.rule_name,
                        "response actions exceeded forward limit"
                    );
                    let bytes = engine_helpers::build_servfail_response(ctx.req)?;
                    return Ok(ResponseActionResult::Static {
                        bytes,
                        rcode: ResponseCode::ServFail,
                        source: "response_action",
                    });
                }

                let upstream_addr: Arc<str> = upstream
                    .as_ref()
                    .map(|s| Arc::from(s.as_str()))
                    .unwrap_or_else(|| {
                        ctx.ctx_opt
                            .as_ref()
                            .map(|c| c.upstream.clone())
                            .unwrap_or_else(|| Arc::from(ctx.upstream_default))
                    });
                let use_transport = transport.unwrap_or(Transport::Udp);
                let (raw, actual_upstream) = match crate::engine::upstream::forward_upstream(
                    ctx.engine,
                    ctx.packet,
                    &upstream_addr,
                    ctx.upstream_timeout,
                    Some(use_transport),
                    pre_split_upstreams.as_ref(),
                    observed,
                )
                .await
                {
                    Ok(result) => {
                        if let Some((trail, ecs)) = ctx.trail.as_mut() {
                            trail.record_reply(*ecs, &result.0);
                        }
                        result
                    }
                    Err(err) => {
                        if let Some((trail, ecs)) = ctx.trail.as_mut() {
                            trail.record_failure(*ecs);
                        }
                        warn!(
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
                        if err.downcast_ref::<UpstreamFailure>().is_none() {
                            return Err(err);
                        }
                        let bytes = engine_helpers::build_servfail_response(ctx.req)?;
                        return Ok(ResponseActionResult::Static {
                            bytes,
                            rcode: ResponseCode::ServFail,
                            source: "response_action",
                        });
                    }
                };
                let msg = Message::from_bytes(&raw).context("parse upstream response")?;
                ctx.ctx_opt = Some(ResponseContext {
                    raw,
                    msg,
                    upstream: Arc::from(actual_upstream.as_str()), // Use actual responding upstream
                    transport: use_transport,
                });
            }
        }
    }

    if let Some(resp_ctx) = ctx.ctx_opt {
        // 优化：使用辅助函数获取锁，消除重复代码
        // Optimization: Use helper function to acquire locks, eliminate duplicate code
        let (geoip_manager, geosite_manager) = acquire_geo_locks(ctx.engine);
        let geoip_manager_ref = geoip_manager.as_deref();
        let geosite_manager_ref = geosite_manager.as_deref();

        let resp_match = eval_match_chain(
            ctx.response_matchers,
            |m| m.operator,
            |m| {
                m.matcher.matches(
                    &resp_ctx.upstream,
                    ctx.qname,
                    ctx.qtype,
                    ctx.qclass,
                    &resp_ctx.msg,
                    geoip_manager_ref,
                    geosite_manager_ref,
                )
            },
        );
        return Ok(ResponseActionResult::Upstream {
            ctx: resp_ctx,
            resp_match,
        });
    }

    let bytes = engine_helpers::build_servfail_response(ctx.req)?;
    Ok(ResponseActionResult::Static {
        bytes,
        rcode: ResponseCode::ServFail,
        source: "response_action",
    })
}

pub(crate) struct ResponseJumpContext<'a> {
    pub state: &'a EngineInner,
    pub pipeline_id: Arc<str>,
    pub remaining_jumps: usize,
    pub req: &'a Message,
    pub packet: &'a [u8],
    pub peer: SocketAddr,
    pub qname: &'a str,
    pub qtype: RecordType,
    pub qclass: DNSClass,
    pub edns_present: bool,
    /// The ECS option the client carries itself / 客户端自己带的 ECS 选项
    pub client_ecs: Option<crate::ecs::EcsKey>,
    pub upstream_timeout: Duration,
    pub skip_cache: bool,
    /// The ECS the packet carries: how the forward before the jump derived it, and
    /// what it sent
    /// 包里携带的 ECS：跳转前那次转发怎样取得它，以及发出了什么
    pub carried: crate::ecs_scope::ForwardEcs,
    /// Where the forwards on the path record their replies, for the echo the client
    /// gets (nothing on this path is cached), and the floor from before the jump
    /// (see `phases::client_reply`)
    /// 这条路径上的转发在哪里记下应答，供客户端拿到的回显使用（这条路径不缓存），以及跳转之前
    /// 的下限（见 `phases::client_reply`）
    pub trail: &'a mut crate::ecs_scope::EcsReach,
    pub echo_floor: u8,
    /// Observer context of the request / 所属请求的观察者上下文
    pub observed: Observed<'a>,
    /// In-flight entries the request already holds as it jumps: the one its
    /// forward registered, and one a `continue` kept (see
    /// `ForwardDecisionContext::held_inflight`). Nobody else answers them, so
    /// the jump target never waits on them.
    /// 请求跳转时已经握着的 in-flight 条目：这次转发登记的那条，以及 `continue` 留下的
    /// 那条（见 `ForwardDecisionContext::held_inflight`）。没有别人会应答它们，所以跳转
    /// 目标从不等它们。
    pub held_inflight: [Option<u64>; 2],
}

pub(crate) async fn process_response_jump(
    engine: &Engine,
    context: ResponseJumpContext<'_>,
    response: &mut crate::engine::response_log::ResponseInfo,
) -> anyhow::Result<Bytes> {
    let ResponseJumpContext {
        state,
        mut pipeline_id,
        mut remaining_jumps,
        req,
        packet,
        peer,
        qname,
        qtype,
        qclass,
        edns_present,
        client_ecs,
        upstream_timeout,
        skip_cache,
        carried,
        trail,
        echo_floor,
        observed,
        held_inflight,
    } = context;
    let requester = Requester {
        address: peer.ip(),
        edns: edns_present,
        ecs: client_ecs,
    };
    let cfg = &state.pipeline;
    struct InflightCleanupGuard {
        inflight: Arc<InflightMap>,
        hash: u64,
        active: bool,
    }

    impl InflightCleanupGuard {
        fn new(inflight: Arc<InflightMap>, hash: u64) -> Self {
            Self {
                inflight,
                hash,
                active: true,
            }
        }

        fn defuse(&mut self) {
            self.active = false;
        }
    }

    impl Drop for InflightCleanupGuard {
        fn drop(&mut self) {
            if self.active {
                self.inflight.remove(&self.hash);
            }
        }
    }

    let mut skip_rules: FxHashSet<Arc<str>> = FxHashSet::default();
    let mut reused_response: Option<ResponseContext> = None;
    let mut inflight_hashes = Vec::new();
    let mut cleanup_guards: Vec<InflightCleanupGuard> = Vec::new();
    // The request's own entries: the ones it held before the jump and the ones
    // it registers on the way. Waiting on one waits on itself, since only this
    // request answers it, and the query hangs until the client gives up; it
    // forwards by itself instead, as `handle_forward_decision` does with a held
    // entry. Other requests' entries are still joined.
    // 请求自己的条目：跳转前握着的，和一路上登记的。等它就是等自己（只有这个请求
    // 会应答它），查询会一直挂到客户端放弃；改为自己转发，和 `handle_forward_decision`
    // 对握着的条目的做法一样。别的请求的条目照旧合并等待。
    let holds = |inflight_hashes: &[u64], hash: u64| {
        inflight_hashes.contains(&hash) || held_inflight.contains(&Some(hash))
    };
    // Whether this pass enters a pipeline (by the jump that led here, or a
    // later one) rather than resuming the same pipeline after a `continue`:
    // only entering reports `pipeline_selected` and counts against the jump
    // limit.
    // 这一轮是不是进入一个 pipeline（经由引来的跳转或之后的跳转），而不是
    // `continue` 后在同一 pipeline 继续：只有进入才上报 `pipeline_selected`，
    // 也只有进入才受跳转上限约束。
    let mut entering = true;
    let join_wait = crate::engine::upstream::hedge_timeout(upstream_timeout);

    loop {
        response.pipeline = Some(pipeline_id.clone());
        response.upstream = None;
        // The limit counts jumps: a `continue` resuming the same pipeline is not one.
        // How many jumps a request has left here depends on the way it came along
        // the jump path, which no key carries: the waiters on its entries may have
        // jumps to spare. Returning drops the guards, which removes the entries,
        // and the waiters forward themselves.
        // 上限数的是跳转：`continue` 在同一 pipeline 继续不算一次。请求在这里还能跳几次
        // 取决于它沿跳转路径怎么来的，键里没有这一项：等在它条目上的请求可能还有余量。
        // 返回时守卫被丢弃，条目随之移除，等待者自己转发。
        if entering && remaining_jumps == 0 {
            return engine_helpers::build_servfail_response(req);
        }

        let Some(pipeline) = cfg
            .pipeline_id_index
            .get(pipeline_id.as_ref())
            .and_then(|&idx| cfg.pipelines.get(idx))
        else {
            let resp_bytes = engine_helpers::build_servfail_response(req)?;
            for g in &mut cleanup_guards {
                g.defuse();
            }
            for h in &inflight_hashes {
                engine
                    .notify_inflight_waiters(*h, || {
                        crate::engine::phases::for_waiters(
                            &resp_bytes,
                            &requester,
                            trail,
                            echo_floor,
                        )
                    })
                    .await;
            }
            return Ok(resp_bytes);
        };
        if entering && let Some((observer, ctx)) = observed {
            observer.pipeline_selected(ctx, &pipeline.id);
        }
        entering = true;

        let mut decision = engine.apply_rules(
            state,
            pipeline,
            &RuleEvaluationContext::new(
                peer.ip(),
                qname,
                qtype,
                qclass,
                edns_present,
                if skip_rules.is_empty() {
                    None
                } else {
                    Some(&skip_rules)
                },
                skip_cache,
            )
            .with_observed(observed),
        );

        // Resolve nested rule-level jumps first
        let mut local_jumps = remaining_jumps;
        loop {
            if let Decision::Jump { pipeline } = decision {
                if local_jumps == 0 {
                    // See the jump limit above / 同上面的跳转上限
                    return engine_helpers::build_servfail_response(req);
                }
                pipeline_id = pipeline;
                response.pipeline = Some(pipeline_id.clone());
                local_jumps -= 1;
                if let Some(next_pipeline) = cfg
                    .pipeline_id_index
                    .get(pipeline_id.as_ref())
                    .and_then(|&idx| cfg.pipelines.get(idx))
                {
                    if let Some((observer, ctx)) = observed {
                        observer.pipeline_selected(ctx, &next_pipeline.id);
                    }
                    skip_rules.clear();
                    // 留着复用的应答属于上一个 pipeline，见 handle_packet_internal 里请求阶段的跳转
                    // An answer kept for reuse belongs to the previous pipeline; see the
                    // request-phase jump in handle_packet_internal
                    reused_response = None;
                    decision = engine.apply_rules(
                        state,
                        next_pipeline,
                        &RuleEvaluationContext::new(
                            peer.ip(),
                            qname,
                            qtype,
                            qclass,
                            edns_present,
                            None,
                            skip_cache,
                        )
                        .with_observed(observed),
                    );
                    continue;
                } else {
                    let resp_bytes = engine_helpers::build_servfail_response(req)?;
                    for g in &mut cleanup_guards {
                        g.defuse();
                    }
                    for h in &inflight_hashes {
                        engine
                            .notify_inflight_waiters(*h, || {
                                crate::engine::phases::for_waiters(
                                    &resp_bytes,
                                    &requester,
                                    trail,
                                    echo_floor,
                                )
                            })
                            .await;
                    }
                    return Ok(resp_bytes);
                }
            }
            break;
        }

        remaining_jumps = local_jumps;
        // Answers on this path are not cached: no lookup uses a key of the
        // response-jump path, so they would only take up room. Only the inflight key
        // is needed.
        // 这条路径上的应答不写缓存：没有哪次查找用响应跳转路径的键，写进去只会占地方。这里只需要
        // inflight 键。
        let inflight_question = InflightQuestion {
            namespace: state.cache_namespace(&pipeline_id),
            pipeline_id: &pipeline_id,
            qname: qname.as_bytes(),
            qtype,
            qclass,
            flags: crate::proto_utils::QueryFlags::of(packet),
            requester: cfg
                .requester_key(
                    &pipeline_id,
                    Requester {
                        address: peer.ip(),
                        edns: edns_present,
                        ecs: client_ecs,
                    },
                    Some(&engine.geoip_manager),
                )
                .on_response_jump_path(&carried),
            client_ecs,
        };
        let dedupe_hash = inflight_question.key();

        match decision {
            Decision::Static { rcode, answers } => {
                response.upstream = Some(Arc::from("static"));
                let resp_bytes = build_response(req, rcode, answers)?;
                for g in &mut cleanup_guards {
                    g.defuse();
                }
                for h in &inflight_hashes {
                    engine
                        .notify_inflight_waiters(*h, || {
                            crate::engine::phases::for_waiters(
                                &resp_bytes,
                                &requester,
                                trail,
                                echo_floor,
                            )
                        })
                        .await;
                }
                return Ok(resp_bytes);
            }
            Decision::Forward {
                upstream,
                pre_split_upstreams,
                response_matchers,
                response_matcher_operator: _response_matcher_operator,
                response_actions_on_match,
                response_actions_on_miss,
                rule_name,
                transport,
                ecs: _,
                continue_on_match: _,
                continue_on_miss: _,
                allow_reuse,
            } => {
                response.upstream = Some(upstream.clone());
                // A reused answer is in the trail already / 复用的应答已经记在 trail 里
                let mut reused = false;
                let resp = if allow_reuse {
                    if let Some(ctx) = reused_response.take() {
                        reused = true;
                        Ok((ctx.raw, ctx.upstream.to_string()))
                    } else {
                        // FIX: Background refresh must skip inflight check
                        // 修复：后台刷新必须跳过 inflight 检查
                        if !skip_cache {
                            use dashmap::mapref::entry::Entry;
                            let rx = match engine.inflight.entry(dedupe_hash) {
                                Entry::Vacant(entry) => {
                                    // No other request in progress, create watch channel
                                    // 没有其他请求在进行,创建 watch channel
                                    let (tx, _rx) = tokio::sync::watch::channel(inflight_pending());
                                    entry.insert(InflightEntry::new(&inflight_question, tx));
                                    cleanup_guards.push(InflightCleanupGuard::new(
                                        engine.inflight.clone(),
                                        dedupe_hash,
                                    ));
                                    inflight_hashes.push(dedupe_hash);
                                    None
                                }
                                // This request's own entry: forward instead (see `holds`)
                                // 这个请求自己的条目：改为自己转发（见 `holds`）
                                Entry::Occupied(_) if holds(&inflight_hashes, dedupe_hash) => None,
                                // Another question's entry under the same key: forward instead (see
                                // `InflightQuestion`)
                                // 同一个键下别的问题的条目：改为自己转发（见 `InflightQuestion`）
                                Entry::Occupied(entry) if !entry.get().asks(&inflight_question) => {
                                    None
                                }
                                Entry::Occupied(entry) => {
                                    // Another request in progress, subscribe to its result
                                    // 已有请求在进行,订阅其结果
                                    let rx = entry.get().tx.subscribe();
                                    Some(rx)
                                }
                            };

                            if let Some(mut rx) = rx {
                                // The request holds entries of its own on the jump path, so the one it
                                // waits on may in turn be waiting on it (two requests that jumped into
                                // each other's pipeline). Wait only until an upstream should have
                                // answered (see `hedge_timeout`), then forward by itself.
                                // 跳转路上的请求自己握着条目，它等的那一个可能反过来也在等它（两个请求互相
                                // 跳进了对方的 pipeline）。只等到上游应当已经应答的时间点（见
                                // `hedge_timeout`），之后自己转发。
                                if let Ok(Ok(())) =
                                    tokio::time::timeout(join_wait, rx.changed()).await
                                {
                                    if let Some((observer, ctx)) = observed {
                                        observer.inflight_joined(ctx);
                                    }
                                    // Clone result to avoid holding RwLockReadGuard across await
                                    // 克隆结果以避免在 await 跨度持有 RwLockReadGuard
                                    let result = rx.borrow().clone();
                                    match &result {
                                        Ok(bytes) => {
                                            // Rewrite Transaction ID for followers using BytesMut
                                            let mut resp_mut = BytesMut::from(bytes.as_ref());
                                            if resp_mut.len() >= 2 {
                                                let id_bytes = req.metadata.id.to_be_bytes();
                                                resp_mut[0] = id_bytes[0];
                                                resp_mut[1] = id_bytes[1];
                                            }
                                            let resp_bytes = resp_mut.freeze();

                                            for g in &mut cleanup_guards {
                                                g.defuse();
                                            }
                                            for h in &inflight_hashes {
                                                engine
                                                    .notify_inflight_waiters(*h, || {
                                                        crate::engine::phases::for_waiters(
                                                            bytes, &requester, trail, echo_floor,
                                                        )
                                                    })
                                                    .await;
                                            }
                                            response.upstream = Some(Arc::from("inflight"));
                                            return Ok(resp_bytes);
                                        }
                                        Err(e) => return Err(anyhow::anyhow!("{}", e)),
                                    }
                                }
                                // Otherwise the sender dropped, or no answer came within the upstream
                                // timeout: forward by itself
                                // 否则发送端已丢弃，或上游超时内没等到应答：自己转发
                            }
                        }
                        crate::engine::upstream::forward_upstream(
                            engine,
                            packet,
                            &upstream,
                            upstream_timeout,
                            transport,
                            pre_split_upstreams.as_ref(),
                            observed,
                        )
                        .await
                    }
                } else {
                    // If reuse is not allowed (e.g. explicit Forward action), we must clear any reused response
                    // and force a new request.

                    // FIX: Background refresh must skip inflight check
                    // 修复：后台刷新必须跳过 inflight 检查
                    if !skip_cache {
                        use dashmap::mapref::entry::Entry;
                        let rx = match engine.inflight.entry(dedupe_hash) {
                            Entry::Vacant(entry) => {
                                // No other request in progress, create watch channel
                                // 没有其他请求在进行,创建 watch channel
                                let (tx, _rx) = tokio::sync::watch::channel(inflight_pending());
                                entry.insert(InflightEntry::new(&inflight_question, tx));
                                cleanup_guards.push(InflightCleanupGuard::new(
                                    engine.inflight.clone(),
                                    dedupe_hash,
                                ));
                                inflight_hashes.push(dedupe_hash);
                                None
                            }
                            // See the same arm above / 同上
                            Entry::Occupied(_) if holds(&inflight_hashes, dedupe_hash) => None,
                            // See the same arm above / 同上
                            Entry::Occupied(entry) if !entry.get().asks(&inflight_question) => None,
                            Entry::Occupied(entry) => {
                                // Another request in progress, subscribe to its result
                                // 已有请求在进行,订阅其结果
                                let rx = entry.get().tx.subscribe();
                                Some(rx)
                            }
                        };

                        if let Some(mut rx) = rx {
                            // See the same wait above / 同上
                            if let Ok(Ok(())) = tokio::time::timeout(join_wait, rx.changed()).await
                            {
                                if let Some((observer, ctx)) = observed {
                                    observer.inflight_joined(ctx);
                                }
                                // Clone result to avoid holding RwLockReadGuard across await
                                // 克隆结果以避免在 await 跨度持有 RwLockReadGuard
                                let result = rx.borrow().clone();
                                match &result {
                                    Ok(bytes) => {
                                        // Rewrite Transaction ID for followers using BytesMut
                                        let mut resp_mut = BytesMut::from(bytes.as_ref());
                                        if resp_mut.len() >= 2 {
                                            let id_bytes = req.metadata.id.to_be_bytes();
                                            resp_mut[0] = id_bytes[0];
                                            resp_mut[1] = id_bytes[1];
                                        }
                                        let resp_bytes = resp_mut.freeze();

                                        for g in &mut cleanup_guards {
                                            g.defuse();
                                        }
                                        for h in &inflight_hashes {
                                            engine
                                                .notify_inflight_waiters(*h, || {
                                                    crate::engine::phases::for_waiters(
                                                        bytes, &requester, trail, echo_floor,
                                                    )
                                                })
                                                .await;
                                        }
                                        response.upstream = Some(Arc::from("inflight"));
                                        return Ok(resp_bytes);
                                    }
                                    Err(e) => return Err(anyhow::anyhow!("{}", e)),
                                }
                            }
                            // Otherwise the sender dropped, or no answer came within the upstream
                            // timeout: forward by itself
                            // 否则发送端已丢弃，或上游超时内没等到应答：自己转发
                        }
                    }
                    crate::engine::upstream::forward_upstream(
                        engine,
                        packet,
                        &upstream,
                        upstream_timeout,
                        transport,
                        pre_split_upstreams.as_ref(),
                        observed,
                    )
                    .await
                };
                // As in handle_forward_decision_logged / 同 handle_forward_decision_logged
                let resp = resp.and_then(|reply| {
                    reject_failure_reply_on_refresh(skip_cache, &reply.0).map(|()| reply)
                });
                // Forwards here send the carried packet / 这里的转发发出的是带过来的包
                match &resp {
                    Ok(_) if reused => {}
                    Ok((raw, _)) => trail.record_reply(carried, raw),
                    Err(_) => trail.record_failure(carried),
                }

                match resp {
                    Ok((raw, actual_upstream)) => {
                        response.upstream = Some(Arc::from(actual_upstream.as_str()));
                        let msg = Message::from_bytes(&raw).context("parse upstream response")?;

                        // Get manager references for GeoIP/GeoSite matching in response matchers
                        // Try to acquire read locks non-blockingly (fast path for concurrent reads)
                        // Use scope to ensure locks are released immediately after use
                        // 获取 manager 引用以用于响应匹配器中的 GeoIP/GeoSite 匹配
                        // 尝试非阻塞获取读锁（并发读的快速路径）
                        // 使用作用域确保锁在使用后立即释放
                        let resp_match_ok = {
                            let (geoip_manager, geosite_manager) = acquire_geo_locks(engine);

                            let geoip_manager_ref = geoip_manager.as_deref();
                            let geosite_manager_ref = geosite_manager.as_deref();

                            eval_match_chain(
                                &response_matchers,
                                |m| m.operator,
                                |m| {
                                    m.matcher.matches(
                                        &upstream,
                                        qname,
                                        qtype,
                                        qclass,
                                        &msg,
                                        geoip_manager_ref,
                                        geosite_manager_ref,
                                    )
                                },
                            )
                        }; // guards are dropped here / 锁在此处释放

                        if !response_matchers.is_empty()
                            && let Some((observer, ctx)) = observed
                        {
                            observer.rule_evaluated(
                                ctx,
                                &RuleEvaluated {
                                    pipeline: &pipeline_id,
                                    rule: &rule_name,
                                    phase: RulePhase::Response,
                                    matched: resp_match_ok,
                                    matchers: response_matchers.len(),
                                },
                            );
                            if resp_match_ok {
                                observer.rule_matched(
                                    ctx,
                                    &RuleMatched {
                                        pipeline: &pipeline_id,
                                        rule: &rule_name,
                                        phase: RulePhase::Response,
                                        decision: response_decision_kind(
                                            &response_actions_on_match,
                                        ),
                                        fast_path: false,
                                    },
                                );
                            }
                        }

                        let actions_to_run = if !response_actions_on_match.is_empty()
                            || !response_actions_on_miss.is_empty()
                        {
                            if resp_match_ok {
                                &response_actions_on_match
                            } else {
                                &response_actions_on_miss
                            }
                        } else {
                            &Vec::new()
                        };

                        if actions_to_run.is_empty() {
                            for g in &mut cleanup_guards {
                                g.defuse();
                            }
                            for h in &inflight_hashes {
                                engine
                                    .notify_inflight_waiters(*h, || {
                                        crate::engine::phases::for_waiters(
                                            &raw, &requester, trail, echo_floor,
                                        )
                                    })
                                    .await;
                            }
                            return Ok(raw);
                        }

                        let ctx = ResponseContext {
                            raw,
                            msg,
                            upstream: Arc::from(actual_upstream.as_str()), // Use actual responding upstream
                            transport: transport.unwrap_or(Transport::Udp),
                        };
                        let apply_ctx = ApplyResponseActionsContext {
                            engine,
                            actions: actions_to_run,
                            ctx_opt: Some(ctx),
                            req,
                            packet,
                            upstream_timeout,
                            response_matchers: &response_matchers,
                            qname,
                            qtype,
                            qclass,
                            client_ip: peer.ip(),
                            upstream_default: cfg.settings.default_upstream.as_str(),
                            pipeline_id: &pipeline_id,
                            rule_name: &rule_name,
                            remaining_jumps,
                            // For the echo only: nothing on this path is cached
                            // 只为回显：这条路径上不缓存
                            trail: Some((&mut *trail, carried)),
                        };
                        let action_result =
                            apply_response_actions_observed(apply_ctx, observed).await?;

                        match action_result {
                            ResponseActionResult::Upstream { ctx, resp_match: _ } => {
                                // The reply to a response action's forward / 响应动作转发拿到的应答
                                reject_failure_reply_on_refresh(skip_cache, &ctx.raw)?;
                                for g in &mut cleanup_guards {
                                    g.defuse();
                                }
                                for h in &inflight_hashes {
                                    engine
                                        .notify_inflight_waiters(*h, || {
                                            crate::engine::phases::for_waiters(
                                                &ctx.raw, &requester, trail, echo_floor,
                                            )
                                        })
                                        .await;
                                }
                                response.upstream = Some(ctx.upstream);
                                return Ok(ctx.raw);
                            }
                            ResponseActionResult::Static { bytes, source, .. } => {
                                // A jump limit reached here is this request's own (see
                                // the jump limit above) / 在这里到达的跳转上限只属于本请求（见上）
                                if source == JUMP_LIMIT {
                                    return Ok(bytes);
                                }
                                for g in &mut cleanup_guards {
                                    g.defuse();
                                }
                                for h in &inflight_hashes {
                                    engine
                                        .notify_inflight_waiters(*h, || {
                                            crate::engine::phases::for_waiters(
                                                &bytes, &requester, trail, echo_floor,
                                            )
                                        })
                                        .await;
                                }
                                response.upstream = Some(Arc::from("static"));
                                return Ok(bytes);
                            }
                            ResponseActionResult::Jump {
                                pipeline,
                                remaining_jumps: next_remaining,
                            } => {
                                pipeline_id = pipeline;
                                remaining_jumps = next_remaining;
                                // Rules passed by a continue belong to the pipeline
                                // being left; the target starts from its first rule,
                                // as on a rule-level jump.
                                // continue 越过的规则属于要离开的 pipeline；与规则阶段的
                                // 跳转一样，目标从第一条规则开始。
                                skip_rules.clear();
                                // 同上：留着复用的应答不带进下一个 pipeline
                                // As above: an answer kept for reuse stays behind
                                reused_response = None;
                                continue;
                            }
                            ResponseActionResult::Continue { ctx } => {
                                // The rule continued past this answer, so it is not one
                                // to hand over: drop the guards, which removes the
                                // entries without it, and their waiters forward
                                // themselves. The next rule's Forward (same
                                // dedupe_hash) then finds no entry of this request's to
                                // wait on.
                                // 规则越过了这个应答，它不该交给别人：丢弃守卫，条目随之
                                // 移除而不交出它，等待者自己转发。下一条规则的 Forward
                                // （相同 dedupe_hash）也就不会等在本请求自己的条目上。
                                cleanup_guards.clear();
                                inflight_hashes.clear();
                                reused_response = ctx;
                                skip_rules.insert(rule_name.clone());
                                entering = false;
                                continue;
                            }
                        }
                    }
                    Err(err) => {
                        // A background refresh answers no client, so it gets the failure
                        // itself (see handle_forward_decision_logged).
                        // 后台刷新没有要应答的客户端，失败原样交回（同 handle_forward_decision_logged）。
                        if skip_cache || err.downcast_ref::<UpstreamFailure>().is_none() {
                            return Err(err);
                        }
                        let resp_bytes = engine_helpers::build_servfail_response(req)?;
                        for g in &mut cleanup_guards {
                            g.defuse();
                        }
                        for h in &inflight_hashes {
                            engine
                                .notify_inflight_waiters(*h, || {
                                    crate::engine::phases::for_waiters(
                                        &resp_bytes,
                                        &requester,
                                        trail,
                                        echo_floor,
                                    )
                                })
                                .await;
                        }
                        return Ok(resp_bytes);
                    }
                }
            }
            Decision::Jump { pipeline } => {
                pipeline_id = pipeline;
                if remaining_jumps > 0 {
                    remaining_jumps -= 1;
                    continue;
                } else {
                    let resp_bytes = engine_helpers::build_servfail_response(req)?;
                    return Ok(resp_bytes);
                }
            }
        }
    }
}

#[cfg(test)]
mod response_jump_tests {
    use crate::engine::core::Engine;
    use crate::matcher::RuntimePipelineConfig;
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use hickory_proto::serialize::binary::BinDecodable;
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use std::time::Duration;

    /// Local UDP upstream that answers every query with one A record.
    /// 本机 UDP 上游：每个查询都回一条 A 记录。
    async fn spawn_answering_upstream() -> String {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                let Ok(query) = Message::from_bytes(&buf[..n]) else {
                    continue;
                };
                let Some(question) = query.queries.first().cloned() else {
                    continue;
                };
                let mut resp = Message::new(query.id, MessageType::Response, OpCode::Query);
                resp.add_query(question.clone());
                resp.add_answer(Record::from_rdata(
                    question.name().clone(),
                    300,
                    RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(192, 0, 2, 1))),
                ));
                let _ = sock.send_to(&resp.to_vec().unwrap(), peer).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn a_response_jump_starts_the_target_pipeline_from_its_first_rule() {
        let upstream = spawn_answering_upstream().await;
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
        let config: crate::config::PipelineConfig =
            serde_json::from_value(raw).expect("parse config");
        let engine = Engine::new(
            RuntimePipelineConfig::from_config(config).expect("build runtime config"),
            "test".to_string(),
        )
        .expect("engine");

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
}

#[cfg(test)]
mod geo_lock_tests {
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use super::acquire_geo_locks;
    use crate::engine::Engine;
    use crate::matcher::RuntimePipelineConfig;

    fn engine() -> Engine {
        let raw = serde_json::json!({
            "settings": { "default_upstream": "127.0.0.1:9" },
            "pipelines": [{ "id": "main", "rules": [] }]
        });
        let config: crate::config::PipelineConfig =
            serde_json::from_value(raw).expect("parse config");
        Engine::new(
            RuntimePipelineConfig::from_config(config).expect("build runtime config"),
            "test".to_string(),
        )
        .expect("engine")
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
