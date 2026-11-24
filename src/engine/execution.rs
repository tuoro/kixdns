use std::cell::Cell;
use std::hash::{BuildHasher, DefaultHasher, Hash, RandomState};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{DNSClass, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use smallvec::SmallVec;

use crate::cache::{CacheEntry, CachedQuestion};
use crate::ecs_scope::EcsReach;
use crate::matcher::advanced_rule::{PrecomputedAction, StaticAnswer, StaticRecords};
use crate::matcher::{Requester, RequesterKey, RuntimePipelineConfig};
use crate::observe::{
    CacheHit, CacheHitKind, DecisionDetail, DecisionKind, DecisionMade, EngineObserver,
    RequestContext, RequestOutcome, RequestStatus, RuleAnswer, RuleMatched, RulePhase,
};
use crate::proto_utils::parse_quick;

use super::concurrency::PermitGuard;
use super::core::Engine;
use super::observation::{ObservedRequest, report_decision, report_rule_cache_hit};
use super::phases;
use super::pipeline::{NO_PIPELINE, RuleEvaluationContext, fast_static_match, select_pipeline};
use super::refresh::{RefreshCheck, RefreshTarget};
use super::response::{StaticAddresses, static_reply, write_static_reply};
use super::response_log::{ResponseInfo, ResponseLog, Source};
use super::rules::{Decision, ResponseContext, RuleCacheRecord};
use super::types::{CacheKeys, EngineInner, FastPathResponse, KeyedQuestion};
use super::utils::InflightCleanupGuard;

/// The address the engine judges a client by. A dual-stack socket (an inbound DoH
/// listener on `[::]`, say) reports an IPv4 client as an IPv4-mapped IPv6 address
/// (::ffff:a.b.c.d); rules, GeoIP, ECS and the cache see the IPv4 address it
/// carries, as they would on an IPv4 socket. Replies still go to the address the
/// listener received from.
/// 引擎据以判断客户端的地址。双栈套接字（例如监听 `[::]` 的入站 DoH）把 IPv4 客户端报成
/// IPv4 映射的 IPv6 地址（::ffff:a.b.c.d）；规则、GeoIP、ECS 和缓存看到的是它背后的 IPv4
/// 地址，和在 IPv4 套接字上一样。应答仍发往监听器收到请求的那个地址。
fn client_address(peer: SocketAddr) -> SocketAddr {
    match peer {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), v6.port()),
            None => peer,
        },
        SocketAddr::V4(_) => peer,
    }
}

/// A query read already, so as not to parse it again: the query as `handle_packet_fast` or
/// `Engine::read_full` read it and the pipeline picked, for this very packet (see
/// `Engine::handle_packet_full`)
/// 读好的查询，不必再解析一遍：`handle_packet_fast` 或 `Engine::read_full` 读出的查询和选中的 pipeline，是这一个包的
/// （见 `Engine::handle_packet_full`）
#[derive(Clone)]
pub struct PreParsedData {
    head: RequestHead,
    /// 选出 `pipeline_id` 的那份配置：请求从头到尾照它走，异步路径上的规则、缓存，连同监听器给它的整体时限（见
    /// `Engine::answer_after_fast_path`）。中间赶上热重载也不换：这份配置选的 pipeline 新配置里可能没有，请求里面各段等待的
    /// 上限也是照这份配置算的
    /// The configuration that selected `pipeline_id`, which the request follows all the way: the
    /// rules and the cache on the async path, and the overall time limit the listener gives it
    /// (see `Engine::answer_after_fast_path`). A hot reload in between changes none of it: the
    /// new configuration may lack the pipeline this one picked, and the waits within the request
    /// are bounded by this configuration
    pub(super) state: Arc<EngineInner>,
}
/// 配置快照太大，不打出来 / The configuration snapshot is too large to print
impl std::fmt::Debug for PreParsedData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreParsedData")
            .field("head", &self.head)
            .finish_non_exhaustive()
    }
}

/// 静态应答（见 [`static_reply`]）交给客户端前的样子：带了 ECS 的客户端拿到回显它自己子网的应答（见
/// `phases::client_reply`），静态应答本来不带 ECS、不取决于任何 ECS；再照查询规整。查询没有附加段就不会有 OPT 和 ECS，
/// 写好的就是最后的样子，不必再规整一遍
/// A static answer (see [`static_reply`]) as it goes to the client: a client that sent ECS gets
/// the echo of its own subnet (see `phases::client_reply`), a static answer carrying no ECS and
/// depending on none; then shaped as the query asks. A query with no additional section has no
/// OPT and no ECS, and the answer as written is final, with nothing left to shape
fn shaped_static_reply(reply: Bytes, packet: &[u8], client: Option<&crate::ecs::EcsKey>) -> Bytes {
    if packet[10..12] == [0, 0] {
        return reply;
    }
    let reply = match client {
        Some(_) => phases::client_reply(reply, client, 0),
        None => reply,
    };
    crate::proto_utils::reply_as_asked(reply, packet)
}

/// 请求编号一个线程一次领这么多，用完再领：这个数所有核都要写，每个查询领一次就是每个查询抢一次
/// A thread takes this many request numbers at a time and comes back when they run out: all cores write
/// the shared number, so taking one per query would mean fighting over it for every query
const REQUEST_ID_BLOCK: u64 = 1_024;

/// 整个进程共用：同一个线程可能轮流处理几个引擎的请求，共用才保证同一个引擎里的编号不重复
/// Shared by the whole process: one thread may handle several engines' requests in turn, and only sharing
/// keeps the numbers within an engine from repeating
static NEXT_REQUEST_ID_BLOCK: AtomicU64 = AtomicU64::new(1);

thread_local! {
    /// 这个线程手里还没用的编号：下一个，和用到哪儿为止 / The numbers this thread still holds: the next one,
    /// and where they end
    static REQUEST_IDS: Cell<(u64, u64)> = const { Cell::new((0, 0)) };
}

fn next_request_id() -> u64 {
    REQUEST_IDS.with(|ids| {
        let (next, end) = ids.get();
        if next < end {
            ids.set((next + 1, end));
            return next;
        }
        let start = NEXT_REQUEST_ID_BLOCK.fetch_add(REQUEST_ID_BLOCK, Ordering::Relaxed);
        ids.set((start + 1, start + REQUEST_ID_BLOCK));
        start
    })
}

/// What answered a request on the synchronous fast path, for observer reporting.
/// 快速路径上应答请求的来源，用于观察者上报。
enum FastPathAnswer<'a> {
    /// Response cache entry, fresh or served stale / 响应缓存条目，新鲜的或当作过期应答交出的
    Cache(CacheHit<'a>),
    /// Compiled static rule matched directly / 编译后的静态规则直接命中
    StaticRule {
        rule: &'a str,
        rcode: ResponseCode,
        answers: usize,
    },
    /// 规则缓存里的静态决定，它的 RCODE 和几条记录 / A static decision from the rule cache, with
    /// its RCODE and how many records it has
    CachedRules {
        record: &'a RuleCacheRecord,
        rcode: ResponseCode,
        answers: usize,
    },
}

/// 快速路径跟着走过的一次请求阶段跳转：从哪个 pipeline、凭什么跳走的（见 `Engine::observe_fast_path`）
/// A request-phase jump the fast path followed: from which pipeline, and on what (see
/// `Engine::observe_fast_path`)
enum Hop<'a> {
    /// 编译后的跳转规则 `rule` 直接命中，跳到 `target` / The compiled jump rule `rule` matched,
    /// jumping to `target`
    Rule {
        pipeline: &'a str,
        rule: &'a str,
        target: &'a str,
    },
    /// 规则缓存里的跳转决定 / A jump decision from the rule cache
    CachedRules {
        pipeline: &'a str,
        record: Arc<RuleCacheRecord>,
    },
}

impl Hop<'_> {
    /// 从哪个 pipeline 跳走 / The pipeline jumped from
    fn pipeline(&self) -> &str {
        match self {
            Self::Rule { pipeline, .. } | Self::CachedRules { pipeline, .. } => pipeline,
        }
    }
}

/// 快速路径上一条编译规则当场作出的决定，照完整路径求值时的样子上报：规则 `rule` 命中，作出 `detail`
/// A decision a compiled rule made on the spot on the fast path, reported as the full path's
/// evaluation reports it: the rule `rule` matched, deciding `detail`
fn report_compiled_rule(
    observer: &dyn EngineObserver,
    ctx: &RequestContext<'_>,
    pipeline: &str,
    rule: &str,
    decision: DecisionKind,
    detail: DecisionDetail<'_>,
) {
    observer.rule_matched(
        ctx,
        &RuleMatched {
            pipeline,
            rule,
            phase: RulePhase::Request,
            decision,
            fast_path: true,
        },
    );
    observer.decision_made(
        ctx,
        &DecisionMade {
            pipeline,
            rule: Some(rule),
            phase: RulePhase::Request,
            detail,
        },
    );
}

// ============================================================================
// Constants / 常量
// ============================================================================

/// 留给"取出过期条目、改写 TXID、写回客户端"的余量。等待上限从本次请求的
/// 剩余预算里扣掉它，免得刚好等到截止时刻才去组装应答，被外层超时抢先。
/// Reserved for pulling the stale entry, patching the TXID and writing the
/// answer back. It comes off the remaining request budget so the wait never
/// runs right up to the deadline and loses the race with the outer timeout.
const STALE_SERVE_RESERVE: Duration = Duration::from_millis(20);

/// 整体请求超时：显式配置优先，否则按 upstream_timeout_ms 的 2.5 倍推导
/// （hedge 1/3 + 全量 1 倍 + TCP 回落 1 倍，再留一点余量）。
/// The overall request timeout: the configured value when set, otherwise 2.5
/// times upstream_timeout_ms (hedge at a third, a full attempt, a TCP fallback
/// and a little margin).
///
/// 单独成函数是为了让持有配置快照的调用方按同一份快照推导，不必再 load 一次
/// 状态，也不会出现两处各算一遍而慢慢算岔。
/// It is a function so a caller already holding a config snapshot derives from
/// that same snapshot instead of loading state again, and so the derivation
/// never drifts between two copies.
pub(super) fn request_timeout_ms(settings: &crate::config::GlobalSettings) -> u64 {
    settings
        .request_timeout_ms
        .unwrap_or(settings.default_request_timeout_ms())
}

impl Engine {
    /// Reload configuration and update compiled pipelines / 重新加载配置并更新编译后的管线
    ///
    /// Allocates the next configuration generation and reports `config_loaded`
    /// (without path or source) in the same call; use [`Engine::reload_from`]
    /// when the configuration came from a file.
    ///
    /// The observer's `config_loaded` runs under the engine's reload lock, so
    /// it must not call `reload` / `reload_from` itself, directly or
    /// indirectly; doing so blocks this call and every later reload forever.
    pub fn reload(&self, new_cfg: RuntimePipelineConfig) {
        self.apply_config(new_cfg, None, None);
    }

    /// Like [`Engine::reload`], additionally telling the observer which file
    /// (`path`) and text (`source`) the configuration came from.
    /// 同 [`Engine::reload`]，并把配置来源文件与文本告知观察者。
    ///
    /// The observer's `config_loaded` runs under the engine's reload lock, so
    /// it must not call `reload` / `reload_from` itself, directly or
    /// indirectly; doing so blocks this call and every later reload forever.
    pub fn reload_from(&self, new_cfg: RuntimePipelineConfig, path: &Path, source: &str) {
        self.apply_config(new_cfg, Some(path), Some(source));
    }

    fn apply_config(
        &self,
        new_cfg: RuntimePipelineConfig,
        path: Option<&Path>,
        source: Option<&str>,
    ) {
        let pool_keys = super::upstream::pool_keys(&new_cfg);
        // Store, generation and event stay together under the reload lock, so
        // the reported generation is the one this reload allocated.
        // 存储、代数与事件在重载锁内一起完成，事件中的代数就是本次分配的值。
        let mut geo_sources = self.reload_lock.lock();
        // serve_stale 重载即生效，能续用多久决定了应答过了 TTL 还留多久
        // serve_stale takes effect on reload, and how long an answer may be served stale
        // decides how long it stays past its TTL
        self.cache
            .set_kept(super::phases::kept_past_ttl(&new_cfg.settings));
        // 新配置连同它要的 Geo 数据一起存进状态，新规则从第一个请求起就用新的标签和文件
        // The new configuration goes into the state with the Geo data it needs, so the new
        // rules find the new tags and files from their first query
        geo_sources.follow(new_cfg);
        let generation = self.config_generation.fetch_add(1, Ordering::Relaxed) + 1;
        self.report_config_loaded(generation, path, source);
        // 新配置不再用到的上游，连接池就此丢掉。此前它们一直留到重启：TCP 和 DoT 连接开着，
        // DoQ 连接每过一个保活间隔还要给旧上游发一次包。
        // The pools of upstreams the new configuration no longer uses are dropped. They
        // used to stay until a restart: TCP and DoT connections stayed open, and DoQ
        // connections kept pinging the old upstream every keep-alive interval.
        self.tcp_mux
            .retain_upstreams(|upstream| pool_keys.tcp.contains(upstream));
        self.dot_mux
            .retain_upstreams(|upstream| pool_keys.dot.contains(upstream));
        self.doq_client
            .retain_upstreams(|upstream| pool_keys.doq.contains(upstream));
    }

    /// `client` 的一个要等上游的查询能不能处理，`emptied_at` 是 UDP socket 上次收空的时刻，TCP、DoH 和轮流时没有（见
    /// `FlowControlState::permit`）；没开流控时看在途的预算（见 `PermitManager::query_permit`）
    /// Whether a query from `client` that waits on an upstream can go ahead, `emptied_at` being
    /// when the UDP socket last ran empty, with none over TCP, DoH and while taking turns (see
    /// `FlowControlState::permit`); without flow control by the budget in flight (see
    /// `PermitManager::query_permit`)
    #[inline]
    pub fn query_permit(&self, emptied_at: Option<Instant>, client: IpAddr) -> Option<PermitGuard> {
        let device = self.permit_manager.slot_of(client);
        let permit = match &self.flow_control_state {
            Some(state) => state.permit(&self.permit_manager, emptied_at, device),
            None => self.permit_manager.query_permit(device),
        };
        if permit.is_none() {
            self.permit_manager.note_refused(client);
        }
        permit
    }

    /// `client` 的一条 TCP 或 DoH 新连接接不接：连接一共开得太多时不给占满了自己那一份的设备（见
    /// `PermitManager::connection_permit`），开着流控时还看内存（见 `FlowControlState::connection_permit`）。连接本身也占
    /// 内存，所以也算在途
    /// Whether a new TCP or DoH connection from `client` is taken: with too many open in all, not
    /// for a device holding its share (see `PermitManager::connection_permit`), and with flow
    /// control on by memory too (see `FlowControlState::connection_permit`). A connection holds
    /// memory too, so it counts as in flight
    #[inline]
    pub fn connection_permit(&self, client: IpAddr) -> Option<PermitGuard> {
        let device = self.permit_manager.slot_of(client);
        let permit = match &self.flow_control_state {
            Some(state) => state.connection_permit(&self.permit_manager, device),
            None => self.permit_manager.connection_permit(device),
        };
        if permit.is_none() {
            self.permit_manager.note_refused(client);
        }
        permit
    }

    /// 算槽位号、inflight 键和规则缓存的键的哈希，先写进问题；查询位由响应缓存自己再写（规则从不看它们）。带密钥
    /// （SipHash），密钥每个进程随机取一份：问题名是请求方随意挑的，不带密钥的哈希（以前的 FxHash 对同样长的输入，换什么
    /// 初值都撞在一起），请求方就能算出一串落在同一个槽位上的名字，挤掉别人存着的应答，也能让 inflight 表的同一个桶越排越
    /// 长。存储层因此直接用这些键的各位定分片和桶，不再散一遍（见 `cache_store`）。问题名带着长度写入（已经是小写，见
    /// `parse_quick`），两个不同的问题写进去的不会是同一串字节
    /// The hasher of slot numbers, inflight keys and rule cache keys, with the question
    /// written in; the response cache writes the query flags itself (rules never read them).
    /// It is keyed (SipHash), the key drawn at random once per process: the question name is
    /// the requester's to pick, and with an unkeyed hash (the FxHash this used, whose
    /// collisions between inputs of one length hold whatever it starts from) a requester could
    /// work out a run of names landing in one slot, pushing out the answers others have cached,
    /// or piling up in one bucket of the inflight map. The store therefore picks shards and
    /// buckets by the bits of these keys as they are, hashing them no second time (see
    /// `cache_store`). The name goes in with its length (it is lowercase already, see
    /// `parse_quick`), so no two questions write the same bytes
    #[inline]
    pub(crate) fn question_hasher(
        cache_namespace: u64,
        pipeline_id: &str,
        qname: &[u8],
        qtype: hickory_proto::rr::RecordType,
        qclass: hickory_proto::rr::DNSClass,
    ) -> DefaultHasher {
        static KEYS: LazyLock<RandomState> = LazyLock::new(RandomState::new);
        let mut h = KEYS.build_hasher();
        cache_namespace.hash(&mut h);
        pipeline_id.hash(&mut h);
        qname.hash(&mut h);
        u16::from(qtype).hash(&mut h);
        u16::from(qclass).hash(&mut h);
        h
    }

    /// Every answer is cached through here. A truncated answer never is: it is incomplete,
    /// and the client is meant to ask again over TCP (RFC 2181 section 9), which a cached copy
    /// would answer with the same truncated answer for its whole TTL. A refresh that gets one
    /// keeps the old entry. Neither is a TSIG-signed answer: its signature holds for the one
    /// request that was signed (RFC 8945), and another client gets it unaltered, spelled as
    /// that request asked. The answer is stored without its ECS option: it may be served to
    /// requesters in other subnets, which get their own echo (see `phases::served_from_cache`).
    /// 所有应答都经这里写进缓存。截断的应答从不缓存：它不完整，客户端本该改用 TCP 再问（RFC 2181
    /// 第 9 节），缓存了就会在整个 TTL 内拿同一个截断的应答回答它。刷新拿到这样的应答时，旧条目保留。
    /// TSIG 签过的应答也不缓存：签名只对签它的那个请求有效（RFC 8945），别的客户端拿到的是原封不动、
    /// 照那个请求写法的应答。应答去掉 ECS 选项后存放：它可能交给别的子网的请求方，它们各自得到自己的
    /// 回显（见 `phases::served_from_cache`）。
    pub(crate) fn insert_dns_cache_entry(&self, slot: u64, mut entry: CacheEntry) {
        // 失败不进缓存：SERVFAIL 不管从哪里来都不缓存（RFC 2308 第 7.1 节最多允许 5 分钟，缓存了，一次瞬时的
        // 故障就会在缓存里留到条目到期）；上游回的 REFUSED 和扩展 RCODE 也不缓存，带着记录也一样。规则自己给出的
        // REFUSED（deny）照常缓存，拦截靠它走缓存
        // Failures stay out of the cache: a SERVFAIL is never cached, wherever it comes from
        // (RFC 2308 section 7.1 allows five minutes at most, and once cached one passing
        // failure stays until the entry expires); neither is a REFUSED or an extended RCODE
        // from an upstream, records or not. A REFUSED the rules give themselves (deny) is
        // cached as before, and blocking relies on it
        if entry.rcode == ResponseCode::ServFail
            || (entry.upstream.is_some() && crate::engine::upstream::is_failure_reply(entry.rcode))
        {
            tracing::debug!(
                event = "failure_not_cached",
                qname = %entry.qname,
                pipeline = %entry.pipeline_id,
                rcode = %crate::observe::rcode_name(entry.rcode.into()),
                "failure reply is not cached"
            );
            return;
        }
        if crate::proto_utils::truncated_response(&entry.bytes) {
            tracing::debug!(
                event = "truncated_answer_not_cached",
                qname = %entry.qname,
                pipeline = %entry.pipeline_id,
                "truncated answer is not cached"
            );
            return;
        }
        if crate::proto_utils::last_record_is_tsig(&entry.bytes) {
            tracing::debug!(
                event = "signed_answer_not_cached",
                qname = %entry.qname,
                pipeline = %entry.pipeline_id,
                "TSIG-signed answer is not cached"
            );
            return;
        }
        if entry.reach.is_uncacheable() {
            tracing::debug!(
                event = "answer_for_this_request_alone_not_cached",
                qname = %entry.qname,
                pipeline = %entry.pipeline_id,
                "whom else the answer applies to is not known, so it is not cached"
            );
            return;
        }
        let Ok(bytes) = crate::proto_utils::without_ecs(entry.bytes) else {
            return;
        };
        entry.bytes = bytes;
        self.cache_insert(slot, Arc::new(entry));
    }

    /// Observer context for a request answered on the fast path.
    /// 快速路径应答请求的观察者上下文。
    fn fast_path_context<'a>(
        &'a self,
        started: Instant,
        peer: SocketAddr,
        qname: &'a str,
        qtype: hickory_proto::rr::RecordType,
        qclass: DNSClass,
    ) -> RequestContext<'a> {
        RequestContext {
            request_id: next_request_id(),
            listener_label: &self.listener_label,
            client: peer,
            transport: self.client_transport,
            qname,
            qtype,
            qclass,
            background_refresh: false,
            started,
            reported_at_once: true,
        }
    }

    /// Report a request that `handle_packet_fast` answered without the async
    /// path: the whole lifecycle is emitted in one batch at the answering site.
    /// `response` is the answer. `hops` are the request-phase jumps followed on the
    /// way to `pipeline_id`, reported as the full path reports them; a request that
    /// jumped is not offered whole, an offer having room for one pipeline.
    /// 上报由 handle_packet_fast 直接应答的请求：整个生命周期在应答处一次性上报。
    /// `response` 是应答。`hops` 是到 `pipeline_id` 之前跟着走过的请求阶段跳转，照完整路径的样子上报；跳转过的请求不整份
    /// 提供，整份的只放得下一个 pipeline。
    fn observe_fast_path(
        &self,
        observer: &dyn EngineObserver,
        ctx: &RequestContext<'_>,
        hops: &[Hop<'_>],
        pipeline_id: &str,
        answer: FastPathAnswer<'_>,
        response: &[u8],
    ) {
        let outcome = RequestOutcome {
            latency: ctx.started.elapsed(),
            status: RequestStatus::Completed,
            response: Some(response),
            error: None,
        };
        let taken_whole = hops.is_empty()
            && match &answer {
                FastPathAnswer::Cache(hit) => {
                    observer.answered_from_cache(ctx, pipeline_id, hit, &outcome)
                }
                FastPathAnswer::StaticRule {
                    rule,
                    rcode,
                    answers,
                } => observer.answered_by_rule(
                    ctx,
                    pipeline_id,
                    &RuleAnswer {
                        rules: &[rule],
                        decided_by_rule: true,
                        rcode: *rcode,
                        answers: *answers,
                    },
                    &outcome,
                ),
                FastPathAnswer::CachedRules {
                    record,
                    rcode,
                    answers,
                } => {
                    let rules: SmallVec<[&str; 4]> = record
                        .matched_rules
                        .iter()
                        .flat_map(|rules| rules.iter())
                        .map(AsRef::as_ref)
                        .collect();
                    observer.answered_by_rule(
                        ctx,
                        pipeline_id,
                        &RuleAnswer {
                            rules: &rules,
                            decided_by_rule: record.decided_by_rule && !rules.is_empty(),
                            rcode: *rcode,
                            answers: *answers,
                        },
                        &outcome,
                    )
                }
            };
        if taken_whole {
            return;
        }
        observer.request_started(ctx);
        for hop in hops {
            let pipeline = hop.pipeline();
            observer.pipeline_selected(ctx, pipeline);
            observer.cache_lookup(ctx);
            observer.cache_miss(ctx);
            match hop {
                Hop::Rule { rule, target, .. } => report_compiled_rule(
                    observer,
                    ctx,
                    pipeline,
                    rule,
                    DecisionKind::Jump,
                    DecisionDetail::Jump { pipeline: target },
                ),
                Hop::CachedRules { record, .. } => {
                    report_rule_cache_hit(observer, ctx, pipeline, record, true);
                }
            }
        }
        observer.pipeline_selected(ctx, pipeline_id);
        observer.cache_lookup(ctx);
        match answer {
            FastPathAnswer::Cache(hit) => observer.cache_hit(ctx, &hit),
            FastPathAnswer::StaticRule {
                rule,
                rcode,
                answers,
            } => {
                observer.cache_miss(ctx);
                report_compiled_rule(
                    observer,
                    ctx,
                    pipeline_id,
                    rule,
                    DecisionKind::Static,
                    DecisionDetail::Static { rcode, answers },
                );
            }
            FastPathAnswer::CachedRules { record, .. } => {
                observer.cache_miss(ctx);
                // 快速路径只从规则缓存答静态决策 / The fast path answers only static decisions from the rule cache
                report_rule_cache_hit(observer, ctx, pipeline_id, record, true);
            }
        }
        observer.request_finished(ctx, &outcome);
    }

    /// 快速路径：同步地答查询。Some 是当场答上了（`Direct`、`CacheHit`），或者要等上游、交给异步路径（`AsyncNeeded`，带着
    /// 读出的查询和选中的 pipeline）；None 是快速解析读不了这个查询，由完整路径从头读
    /// Fast path: answer a query synchronously. Some when it is answered on the spot
    /// (`Direct`, `CacheHit`), or waits on an upstream and goes on to the async path
    /// (`AsyncNeeded`, with the query as read and the pipeline picked); None when the quick
    /// parse cannot read the query, which the full path reads from scratch
    /// Every answer goes back with what it copies from the query as the client wrote it
    /// (see `proto_utils::reply_as_asked`), and the observer is lent that same answer
    /// 每个回答照抄查询的部分都照客户端的写法发回（见 `proto_utils::reply_as_asked`），出借给
    /// 观察者的也是这同一份
    #[inline]
    pub fn handle_packet_fast(&self, packet: &[u8], peer: SocketAddr) -> Option<FastPathResponse> {
        let peer = client_address(peer);
        // 这个请求的时刻只读这一次：查缓存、算 TTL、上报都用它，答完才再读一次算耗时
        // The request's moment is read once, here: the cache lookup, the TTL and the report all use
        // it, and only the latency reads the clock again once answered
        let start = Instant::now();
        // Quick parsing, avoiding full Message parsing and massive allocations / 快速解析，避免完整 Message 解析和大量分配
        // Use stack buffer to avoid String allocation / 使用栈上缓冲区避免 String 分配
        let mut qname_buf = [0u8; 256];
        // 快速解析读不了的交给完整路径 / What the quick parse cannot read goes to the full path
        let q = parse_quick(packet, &mut qname_buf)?;
        // Observer: requests answered here are reported in one batch at the
        // answering site; requests that fall through are reported by the async path.
        // 观察者：在此应答的请求在应答处一次性上报；回落的请求由异步路径上报。
        let observed = self.observer.as_deref();

        // Get pipeline ID / 获取 pipeline ID
        // 只借不留：`load_full` 每个查询要改一次所有核共用的引用计数 / Borrowed, not kept: `load_full` writes the
        // reference count all cores share for every query
        let state = self.state.load();
        let cfg = &state.pipeline;
        let qclass = DNSClass::from(q.qclass);
        let qtype = hickory_proto::rr::RecordType::from(q.qtype);
        let qname_str = q.qname;
        // 选 pipeline、算键、求值规则都看这一份，GeoIP、GeoSite 数据也是它带着的那份（见 `EngineInner::geo`），交给完整
        // 路径的也是它
        // Choosing the pipeline, working out the keys and evaluating the rules all look at this
        // one, the GeoIP and GeoSite data being the copy it carries (see `EngineInner::geo`), and
        // this one goes on to the full path too
        let facts = crate::matcher::RequestFacts {
            qname: qname_str,
            qtype,
            qclass,
            client_ip: peer.ip(),
            edns_present: q.edns_present,
        };
        let pipeline_opt = self.pick_pipeline(&state, &facts);

        let name_of = |pipeline: Option<&crate::matcher::RuntimePipeline>| {
            pipeline.map_or_else(|| Arc::from(NO_PIPELINE), |pipeline| pipeline.id.clone())
        };
        // 在这里答上的请求各记一条响应日志，和完整路径一样记在最后到的那个 pipeline 下
        // Each request answered here gets a response record, under the pipeline it got to last,
        // as on the full path
        let response_log = |pipeline| {
            ResponseLog::with_pipeline(
                qname_str,
                qtype,
                peer,
                move || name_of(pipeline),
                start,
                false,
            )
        };

        // RFC 6891 第 6.1.3 节：不支持请求的 EDNS 版本时回 BADVERS，而不是照版本 0 去答
        // RFC 6891 section 6.1.3: an unsupported EDNS version is answered BADVERS rather
        // than as if it were version 0
        if q.edns_version != 0 {
            let reply = crate::proto_utils::reply_as_asked(
                crate::proto_utils::badvers_response(packet, q.question_end),
                packet,
            );
            if let Some(observer) = observed {
                let ctx = self.fast_path_context(start, peer, qname_str, qtype, qclass);
                observer.request_started(&ctx);
                observer.request_finished(
                    &ctx,
                    &RequestOutcome {
                        latency: start.elapsed(),
                        status: RequestStatus::Completed,
                        response: Some(&reply),
                        error: None,
                    },
                );
            }
            // 和完整路径一样记一条响应日志，pipeline 是选中的那个
            // A response record as the full path writes, with the pipeline picked
            response_log(pipeline_opt).answered(&reply);
            return Some(FastPathResponse::Direct(reply));
        }

        let requester = Requester {
            address: peer.ip(),
            edns: q.edns_present,
            ecs: q.client_subnet,
        };
        let view = requester.ecs_view();
        // 第一条命中的规则或规则缓存给的是跳转时，和完整路径一样跟过去（见 `decide`），按目标的键再查一遍，至多跳
        // response_jump_limit 次；再要跳的、目标不存在的交给完整路径，由它回 SERVFAIL。走过的跳转在答上时照完整路径的
        // 样子上报
        // When the first rule matching or the rule cache gives a jump, it is followed as on the
        // full path (see `decide`) and the target looked in again under its own keys, up to
        // response_jump_limit jumps; one jump more, or a target that does not exist, goes to the
        // full path, which answers SERVFAIL. The jumps followed are reported as the full path
        // reports them once the request is answered
        let mut hops: SmallVec<[Hop<'_>; 2]> = SmallVec::new();
        let mut pipeline = pipeline_opt;
        loop {
            let pipeline_id = pipeline.map_or(NO_PIPELINE, |pipeline| &*pipeline.id);

            // 1. Check Response Cache (L2) / 1. 检查响应缓存（L2）
            let asked = CachedQuestion {
                qname: qname_str,
                pipeline_id,
                qtype: q.qtype,
                qclass: q.qclass,
                flags: q.flags,
            };
            let slot = state.question(pipeline, &asked, requester).slot();

            if let Some(hit) = self.cache_get(slot, &view, &asked) {
                let elapsed_secs = crate::proto_utils::saturating_u64_to_u32(
                    start.saturating_duration_since(hit.inserted_at).as_secs(),
                );
                let age = phases::age_of(&hit, u64::from(elapsed_secs), &cfg.settings);
                // 现在就能交出的过期应答在这里交出，和查缓存一样（见 `phases::stale_at_once`）：留给异步路径的话，过载时
                // 异步路径收不下，手上这份能用的应答就变成了 SERVFAIL
                // A stale answer that may go out right now goes out here, as on the cache lookup
                // (see `phases::stale_at_once`): left to the async path, under overload the async
                // path takes no more, and the usable answer in hand turned into SERVFAIL
                if age == phases::Age::Stale
                    && let Some(kind) = phases::stale_at_once(self, &cfg.settings, slot, &hit)
                {
                    // 和完整路径一样照读出的请求查（见 `Request::lookup`）/ Looked up by the request as
                    // read, as on the full path (see `Request::lookup`)
                    let head = RequestHead::quick(&q, name_of(pipeline));
                    let request = head.request(&state, packet, peer, q.client_subnet, start);
                    let mut log = response_log(pipeline);
                    let reply = crate::proto_utils::reply_as_asked(
                        phases::serve_stale(
                            self,
                            &request.lookup(pipeline_id, slot),
                            &hit,
                            &view,
                            kind,
                            &mut log.info,
                        ),
                        packet,
                    );
                    if let Some(observer) = observed {
                        self.observe_fast_path(
                            observer,
                            &self.fast_path_context(start, peer, qname_str, qtype, qclass),
                            &hops,
                            pipeline_id,
                            FastPathAnswer::Cache(phases::cache_hit_of(&hit, kind, elapsed_secs)),
                            &reply,
                        );
                    }
                    log.answered(&reply);
                    return Some(FastPathResponse::Direct(reply));
                }
                // 其余过期的（不能再用的、要先等上游的）留给异步路径：那里的查找选中的是同一份，由它决定。在这里删掉，那次
                // 查找就会退到一份更宽、更旧的应答上，而上游已不再把它给这个请求方
                // Any other expired answer (of no further use, or waiting on the upstream first) is
                // left to the async path, whose lookup picks this same answer and decides. Dropping
                // it here would let that lookup fall back to a wider, older answer the upstream no
                // longer meant for this requester
                if age == phases::Age::Fresh {
                    self.refresh_if_due(&state, &hit, elapsed_secs, slot, requester);

                    // Return current cache immediately, don't wait for refresh to complete
                    // 直接返回当前缓存，不等待刷新完成
                    // Next query will automatically use refreshed new cache (if completed)
                    // 下次查询时会自动使用刷新后的新缓存（如果已完成）
                    // A client that sent ECS gets the echo of its own subnet, built here
                    // (see `phases::served_from_cache`); the rest get the stored bytes,
                    // which carry no ECS, and the listener ages them. Either way the
                    // answer is shaped as this client asked
                    // 带了 ECS 的客户端在这里拿到回显它自己子网的应答（见
                    // `phases::served_from_cache`）；其余的拿到存着的字节（不带 ECS），由监听器修正
                    // TTL。两种都按这个客户端问的样子规整
                    let echoed = q.client_subnet.is_some();
                    // 快速解析读过查询的 OPT，规整应答时不必再走一遍查询 / The quick parse read the query's
                    // OPT, so shaping the reply need not walk the query again
                    let reply = crate::proto_utils::reply_as_asked_knowing(
                        if echoed {
                            phases::served_from_cache(
                                &hit,
                                q.tx_id,
                                &view,
                                phases::ServedTtl::Elapsed(elapsed_secs),
                            )
                        } else {
                            hit.bytes.clone()
                        },
                        packet,
                        q.edns_present.then_some(q.flags.dnssec_ok()),
                    );
                    if let Some(observer) = observed {
                        self.observe_fast_path(
                            observer,
                            &self.fast_path_context(start, peer, qname_str, qtype, qclass),
                            &hops,
                            pipeline_id,
                            FastPathAnswer::Cache(phases::cache_hit_of(
                                &hit,
                                CacheHitKind::Fresh,
                                elapsed_secs,
                            )),
                            &reply,
                        );
                    }
                    let mut log = response_log(pipeline);
                    log.info.served_from_cache(&hit);
                    log.answered(&reply);
                    return Some(if echoed {
                        FastPathResponse::Direct(reply)
                    } else {
                        FastPathResponse::CacheHit {
                            cached: reply,
                            tx_id: q.tx_id,
                            elapsed_secs,
                        }
                    });
                }
            }

            // 编译规则或规则缓存给的静态应答，照客户端问的样子交出（见 `shaped_static_reply`）
            // A static answer from a compiled rule or the rule cache, going out as the client
            // asked (see `shaped_static_reply`)
            let finish_static = |reply: Bytes, answer: FastPathAnswer<'_>| {
                let reply = shaped_static_reply(reply, packet, q.client_subnet.as_ref());
                if let Some(observer) = observed {
                    self.observe_fast_path(
                        observer,
                        &self.fast_path_context(start, peer, qname_str, qtype, qclass),
                        &hops,
                        pipeline_id,
                        answer,
                        &reply,
                    );
                }
                let mut log = response_log(pipeline);
                log.info.upstream = Some(Source::Static);
                log.answered(&reply);
                Some(FastPathResponse::Direct(reply))
            };
            let answer_static = |rcode, answers: &[hickory_proto::rr::Record], answer| {
                finish_static(
                    static_reply(packet, qname_str, qtype, qclass, rcode, answers),
                    answer,
                )
            };

            // 2. 规则缓存（L1）：和完整路径一样先看规则缓存（见 `apply_rules`），存着决定的不必再求值规则。以前快速路径
            // 先把编译规则求值一遍，存着的是转发时那一遍白算
            // 2. Check Rule Cache (L1): the rule cache comes first, as on the full path (see
            // `apply_rules`), and a decision kept there needs no rules evaluated. The fast path
            // used to evaluate the compiled rules first, for nothing when a forward was kept
            let cached = pipeline
                .and_then(|p| self.cached_decision(&Self::rule_question(&state, p, &facts), start));
            let (next, hop) = if let Some(record) = cached {
                match &record.entry.decision {
                    Decision::Static { rcode, answers } => {
                        return answer_static(
                            *rcode,
                            answers,
                            FastPathAnswer::CachedRules {
                                record: &record,
                                rcode: *rcode,
                                answers: answers.len(),
                            },
                        );
                    }
                    Decision::Jump { pipeline: target } => (
                        cfg.pipeline(target),
                        Hop::CachedRules {
                            pipeline: pipeline_id,
                            record,
                        },
                    ),
                    Decision::Forward { .. } => break,
                }
            } else {
                // 3. 规则：第一条命中的规则当场作出的决定
                // 3. The rules: what the first rule matching decides on the spot
                let matched =
                    pipeline.and_then(|pipeline| fast_static_match(pipeline, &facts, &state.geo));
                match matched {
                    Some((PrecomputedAction::Jump(target), rule)) => (
                        cfg.pipeline(target),
                        Hop::Rule {
                            pipeline: pipeline_id,
                            rule,
                            target,
                        },
                    ),
                    Some((PrecomputedAction::Answer(answer), rule_name)) => {
                        // 规则按配置直接答的不做记录，写不了的才走下面 / What a rule answers straight from the config
                        // makes no records; only what cannot be written goes on below
                        let direct = match answer {
                            StaticAnswer::Rcode(rcode) => {
                                Some((*rcode, StaticAddresses::Configured(&[], qtype)))
                            }
                            StaticAnswer::Records(StaticRecords::Addresses(addresses)) => Some((
                                ResponseCode::NoError,
                                StaticAddresses::Configured(addresses, qtype),
                            )),
                            StaticAnswer::Records(_) => None,
                        };
                        if let Some((rcode, addresses)) = direct
                            && let Some(reply) = write_static_reply(packet, rcode, addresses)
                        {
                            let answers = usize::from(u16::from_be_bytes([reply[6], reply[7]]));
                            let answer = FastPathAnswer::StaticRule {
                                rule: rule_name,
                                rcode,
                                answers,
                            };
                            return finish_static(reply, answer);
                        }
                        let (rcode, answers) = answer.records(qname_str, qtype, qclass);
                        let answer = FastPathAnswer::StaticRule {
                            rule: rule_name,
                            rcode,
                            answers: answers.len(),
                        };
                        return answer_static(rcode, &answers, answer);
                    }
                    None => break,
                }
            };
            let Some(next) =
                next.filter(|_| hops.len() < cfg.settings.response_jump_limit as usize)
            else {
                break;
            };
            hops.push(hop);
            pipeline = Some(next);
        }
        // `hops` 借着这份配置，配置交给异步路径之前先放掉 / `hops` borrows this configuration, so it
        // goes before the configuration is handed to the async path
        drop(hops);

        // 这里答不上（要问上游、要先等上游的过期应答、跳到了头，或者规则当场决定不了）：交给异步路径，带上读好的查询、选中
        // 的 pipeline 和选它的那份配置，不再解析一遍（见 `Engine::handle_packet_full`）
        // Not answered here (an upstream to ask, a stale answer to wait on the upstream first, the
        // jumps followed as far as they go, or rules that cannot decide on the spot): on to the
        // async path with the query as read, the pipeline picked and the configuration that
        // picked it, parsed no second time (see `Engine::handle_packet_full`)
        Some(FastPathResponse::AsyncNeeded(PreParsedData {
            head: RequestHead::quick(&q, name_of(pipeline_opt)),
            state: arc_swap::Guard::into_inner(state),
        }))
    }

    /// 客户端的查询走完整路径，从头读（见 [`Self::read_full`]）：读不了的是 [`UnreadableQuery`]；读得了的照
    /// [`Self::handle_packet_full`] 作答
    /// The full path for a client's query, read from scratch (see [`Self::read_full`]): one that
    /// cannot be read is an [`UnreadableQuery`]; one that can is answered as
    /// [`Self::handle_packet_full`] answers it
    pub async fn handle_packet(
        &self,
        packet: &[u8],
        peer: SocketAddr,
    ) -> Result<Bytes, UnreadableQuery> {
        let pre_parsed = self.read_full(packet, peer)?;
        Ok(self.handle_packet_full(packet, peer, pre_parsed).await)
    }

    /// 从头读客户端的查询，照当前的配置选好 pipeline，请求以后就照这份配置走（见 [`PreParsedData`]）。读不了的是
    /// [`UnreadableQuery`]，监听器据此回 FORMERR（见 `Engine::answer_after_fast_path`）
    /// A client's query read from scratch and its pipeline picked by the current configuration,
    /// which the request follows from then on (see [`PreParsedData`]). One that cannot be read is
    /// an [`UnreadableQuery`], which the listener answers FORMERR (see
    /// `Engine::answer_after_fast_path`)
    pub(super) fn read_full(
        &self,
        packet: &[u8],
        peer: SocketAddr,
    ) -> Result<PreParsedData, UnreadableQuery> {
        let state = self.state.load_full();
        let head = self.read_request(packet, client_address(peer).ip(), &state)?;
        Ok(PreParsedData { head, state })
    }

    /// 读好的客户端查询走完整路径：`pre_parsed` 是这同一个包读出来的请求和选中它的 pipeline 的那份配置（`handle_packet_fast`
    /// 给的，或者 [`Self::read_full`] 刚读的），不再解析一遍。客户端总拿到应答：以错误结束的请求（跳转上限、流控没让转发等，
    /// 见 `decide`）回 SERVFAIL，没有回音在客户端看来就是超时，stub 解析器会重试（RFC 1035）。每个应答都带着它的客户端该看到的
    /// ECS 选项、照客户端写法的照抄部分离开（见 `proto_utils::reply_as_asked`）；等待者在这之前拿到应答，各自为自己的客户端做同样的
    /// 处理。三个监听器都经 `Engine::answer_after_fast_path` 从这里进来
    /// The full path for a client's query that has been read: `pre_parsed` is the request read
    /// from this very packet and the configuration that picked its pipeline (given by
    /// `handle_packet_fast`, or just read by [`Self::read_full`]), with no second parse. The
    /// client always gets an answer: a request that ended in an error (the jump limit, flow
    /// control keeping a forward from waiting, see `decide`) is answered SERVFAIL, silence being
    /// a timeout to the client, which the stub resolver retries (RFC 1035). Every reply leaves
    /// with the ECS option its client should see, and with what it copies from the query as the
    /// client wrote it (see `proto_utils::reply_as_asked`); waiters were handed the reply before
    /// this and do the same for their own clients. All three listeners come in here through
    /// `Engine::answer_after_fast_path`
    pub async fn handle_packet_full(
        &self,
        packet: &[u8],
        peer: SocketAddr,
        pre_parsed: PreParsedData,
    ) -> Bytes {
        let PreParsedData { head, state } = pre_parsed;
        let answered = self.answer(packet, peer, &state, &head, None).await;
        let reply = answered
            .result
            .unwrap_or_else(|_| crate::proto_utils::servfail_reply(packet));
        let reply = crate::proto_utils::reply_as_asked(
            phases::client_reply(reply, head.client_ecs.as_ref(), answered.echo_scope),
            packet,
        );
        answered.journal.finish(&Ok(reply.clone()));
        reply
    }

    /// 后台刷新：照配置 `state` 重放 `packet`，更新的是 `target`（见 [`Self::spawn_background_refresh`]）。刷新不查缓存，总是去问
    /// 上游；它照原请求重放，沿着规则走到哪里就写在哪里的键下，和客户端请求一样，路线没变时就是原请求查过的那个槽位；不上报缓存
    /// 命中、不记应答日志。结果原样交回（见 `renewing`），失败由 refresh.rs 记下
    /// A background refresh: `packet` replayed under the configuration `state`, renewing
    /// `target` (see [`Self::spawn_background_refresh`]). A refresh looks up no cache and always
    /// asks upstream; replaying the original request, it writes under the keys of wherever the
    /// rules lead it, as a client request does, which is the slot the original request looked up
    /// while the route is the same; it reports no cache hit and writes no response record. What
    /// it comes to goes back as it is (see `renewing`), a failure for refresh.rs to note
    pub(crate) async fn handle_refresh(
        &self,
        packet: &[u8],
        peer: SocketAddr,
        target: RefreshTarget,
        state: Arc<EngineInner>,
    ) -> anyhow::Result<Bytes> {
        let head = self.read_request(packet, client_address(peer).ip(), &state)?;
        let answered = self
            .answer(packet, peer, &state, &head, Some(&target))
            .await;
        answered.journal.finish(&answered.result);
        answered.result
    }

    /// 在响应缓存里找能直接回答这个请求的应答：新鲜的立刻给；过期的按 serve_stale 的设置
    /// 立刻给，或者先等后台刷新（RFC 8767 客户端超时）再给。上报一次 `cache_lookup`，
    /// 之后恰好跟一个 `cache_hit` 或 `cache_miss`。
    /// Look in the response cache for an answer to this request. A fresh entry is
    /// served at once; an expired one is served per the serve_stale settings, either
    /// at once or after waiting for the background refresh (RFC 8767 client timeout).
    /// Reports one `cache_lookup`, followed by exactly one `cache_hit` or `cache_miss`.
    async fn answer_from_cache(
        &self,
        lookup: &phases::CacheLookupContext<'_>,
        info: &mut ResponseInfo,
    ) -> Option<Bytes> {
        if let Some((observer, ctx)) = lookup.request.observed {
            observer.cache_lookup(ctx);
        }
        let answer = match phases::check_cache(self, lookup, info) {
            phases::Looked::Answered(answer) => Some(answer),
            phases::Looked::Waiting(stale) => {
                let still_refreshing = self.wait_for_refresh(lookup, &stale).await;
                phases::check_cache_after_wait(self, lookup, still_refreshing, info)
            }
            phases::Looked::Missed => None,
        };
        if answer.is_none()
            && let Some((observer, ctx)) = lookup.request.observed
        {
            observer.cache_miss(ctx);
        }
        answer
    }

    /// RFC 8767 客户端超时（对应 Unbound 的 serve-expired-client-timeout）：等过期的 `stale` 的刷新结束，最多等
    /// serve_stale_client_timeout_ms，给出等到头时刷新还在不在跑。刷新是查缓存时发起的（见 `phases::check_cache`），
    /// 刷新标记一放开就叫醒这里；没有刷新在跑（已经结束了，或者同时在刷的太多、没发起）就不等
    /// RFC 8767 client timeout (Unbound's serve-expired-client-timeout): wait for the refresh of
    /// the stale `stale` to end, for serve_stale_client_timeout_ms at most, telling whether it
    /// still runs when the wait is over. The lookup started the refresh (see
    /// `phases::check_cache`), and its mark going wakes this; with no refresh running (it
    /// ended already, or none started, too many running at once) there is no wait
    async fn wait_for_refresh(
        &self,
        lookup: &phases::CacheLookupContext<'_>,
        stale: &CacheEntry,
    ) -> bool {
        let settings = &lookup.request.state.pipeline.settings;
        let mark = super::refresh::RefreshTarget::mark_of(lookup.slot, &stale.reach);
        // 等待上限取客户端等待与本次请求剩余预算中的较小者。手上这份
        // 过期应答只有赶在外层请求超时之前返回才有意义，否则客户端拿到
        // 的是 SERVFAIL，而那条本可以立刻给出的应答被丢掉。
        //
        // 上界不能取单次上游超时：后台刷新没有外层包裹，UDP 链是
        // hedge(T/3) + 全量(T) + TCP 回落(T)，最坏约 2.33T，按 T 截断
        // 会把本来能成功的刷新提前掐掉，白白把新鲜应答降级成过期应答。
        //
        // Bound the wait by the smaller of the client wait and what is
        // left of this request's budget. The stale answer in hand is
        // only worth anything if it goes out before the outer request
        // timeout; past that the client gets SERVFAIL and an answer
        // that was ready is dropped. One upstream timeout is the wrong
        // bound: a background refresh has no outer wrapper and its UDP
        // chain is hedge at T/3, a full attempt at T and a TCP fallback
        // at T, so roughly 2.33T in the worst case. Cutting at T ends
        // refreshes that would have landed and downgrades a fresh
        // answer to a stale one for nothing.
        let budget = Duration::from_millis(request_timeout_ms(settings));
        let client_timeout = Duration::from_millis(settings.serve_stale_client_timeout_ms).min(
            budget
                .saturating_sub(lookup.request.start.elapsed())
                .saturating_sub(STALE_SERVE_RESERVE),
        );
        // 先登记要被叫醒，再看刷新还在不在，这样不会错过在两步之间结束的刷新。以前每 5 毫秒查一次缓存，等 1.8 秒要醒
        // 360 次
        // Being woken is registered first and whether the refresh still runs is looked at
        // after, so one ending in between is not missed. It used to look at the cache every
        // 5 ms, 360 times in a wait of 1.8 seconds
        let Some(ended) = self.refreshing.get(&mark).map(|ended| Arc::clone(&ended)) else {
            return false;
        };
        let ending = ended.notified();
        tokio::pin!(ending);
        ending.as_mut().enable();
        let wait_start = Instant::now();
        let still_refreshing = self.refreshing.contains_key(&mark)
            && tokio::time::timeout(client_timeout, ending).await.is_err();
        tracing::debug!(
            event = "client_wait_for_refresh",
            qname = %lookup.request.qname,
            wait_ms = wait_start.elapsed().as_millis() as u64,
            still_refreshing,
            "waited for the background refresh of a stale answer"
        );
        still_refreshing
    }

    /// 读好的请求 `head` 照配置 `state` 作答（见 [`Self::decide`]）：交回得出的结果，和还没收尾的记录，由入口照它交回去的样子
    /// 收尾。请求从选 pipeline 到响应动作、写缓存都用这同一份配置：选中它的那份（快速路径选的、刚读的），后台刷新是发起它的
    /// 那次命中 load 的快照。`refresh` 是后台刷新要更新的条目，有它就是后台刷新（见 [`Self::handle_refresh`]），它的结果在这里
    /// 定下（见 [`renewing`]）
    /// Answer the request `head` as read under the configuration `state` (see
    /// [`Self::decide`]): what it came to goes back with the records not yet finished, for the
    /// entry to finish by what it hands back. A request uses this one configuration from picking
    /// its pipeline through response actions and cache writes: the one that picked it (on the
    /// fast path, or just read), for a background refresh the snapshot the hit that started it
    /// loaded. `refresh` is the entry a background refresh renews, the request being one exactly
    /// when it is given (see [`Self::handle_refresh`]), and what it comes to is settled here
    /// (see [`renewing`])
    async fn answer<'a>(
        &'a self,
        packet: &'a [u8],
        peer: SocketAddr,
        state: &'a Arc<EngineInner>,
        head: &'a RequestHead,
        refresh: Option<&'a RefreshTarget>,
    ) -> Answered<'a> {
        let peer = client_address(peer);
        let background_refresh = refresh.is_some();
        // A refresh replays its request's ECS from the key the cache kept, as an option
        // nobody can read does not survive into the replayed packet (see
        // `RefreshTarget::client_ecs`)
        // 刷新按缓存留下的键重放请求的 ECS：读不懂的选项进不了重放的包（见
        // `RefreshTarget::client_ecs`）
        let client_ecs = refresh
            .and_then(|target| target.client_ecs)
            .or(head.client_ecs);
        let start = Instant::now();
        let mut journal = Journal {
            // Observer handle for this request: borrows the parsed query and
            // reports request_finished when dropped, so cancelled requests
            // (listener timeouts drop the future) are reported as well.
            // 本请求的观察者句柄：借用已解析的查询，drop 时上报 request_finished，
            // 因此被取消的请求（监听器超时会丢弃 future）同样会上报。
            observed: self.observer.as_deref().map(|observer| {
                ObservedRequest::new(
                    observer,
                    RequestContext {
                        request_id: next_request_id(),
                        listener_label: &self.listener_label,
                        client: peer,
                        // A refresh is the engine's own query, whichever listener's request scheduled it.
                        // 刷新是引擎自己的查询，与安排它的请求来自哪个监听器无关。
                        transport: if background_refresh {
                            None
                        } else {
                            self.client_transport
                        },
                        qname: &head.qname,
                        qtype: head.qtype,
                        qclass: head.qclass,
                        background_refresh,
                        started: start,
                        reported_at_once: false,
                    },
                )
            }),
            log: ResponseLog::new(
                &head.qname,
                head.qtype,
                peer,
                head.pipeline_id.clone(),
                start,
                background_refresh,
            ),
        };
        if let Some(observed) = &journal.observed {
            observed.observer.request_started(&observed.ctx);
            observed
                .observer
                .pipeline_selected(&observed.ctx, &head.pipeline_id);
        }

        let request = Request {
            refresh,
            observed: journal
                .observed
                .as_ref()
                .map(|observed| (observed.observer, &observed.ctx)),
            ..head.request(state, packet, peer, client_ecs, start)
        };
        let pipeline = state.pipeline.pipeline(&head.pipeline_id);
        let mut route = Route::new(&request, &head.pipeline_id, pipeline);
        let result = self
            .decide(&request, pipeline, &mut route, &mut journal.log.info)
            .await;

        // 刷新的结果只在这里定下：一路上它和客户端请求一样作答、写缓存，被刷新的那份留不留，到这里一次决定（见
        // `renewing`）
        // What a refresh comes to is settled here alone: on the way it answers and caches as a
        // client request does, and whether the answer it renews stays is decided here once (see
        // `renewing`)
        let result = match refresh {
            Some(target) => result
                .and_then(renewing)
                .inspect(|_| request.drop_refreshed(self, target)),
            None => result,
        };
        // A request that continued still holds its entry here, and its waiters get
        // the final answer: the entry's key keeps them to requesters that the rules
        // run after the continue treat alike (see `RuntimePipeline::requester`). A
        // request that ends without an answer to share (an error: the jump limit, flow
        // control keeping a forward from waiting, see `decide`) or is cancelled drops
        // the guard, which removes the entry, and the waiters forward themselves.
        // continue 过的请求走到这里仍持有条目，等待者拿到最终应答：条目的键只让 continue
        // 之后运行的规则一样对待的请求方等在上面（见 `RuntimePipeline::requester`）。请求
        // 没以可以交出的应答结束（出错：跳转上限、流控没让转发等，见 `decide`）或者被取消时，
        // 守卫被丢弃并移除条目，等待者自己转发。
        if let Some(mut guard) = route.held_inflight.take()
            && let Ok(bytes) = &result
        {
            guard.hand_over(|| phases::for_waiters(bytes, &request.requester, &route.trail));
        }
        let echo_scope = route.trail.echo_scope(&request.requester.ecs_view());
        Answered {
            result,
            echo_scope,
            journal,
        }
    }

    /// 读出请求的问题，选好 pipeline：先快速解析，读不了再完整解析，还读不了就是 [`UnreadableQuery`]
    /// Read the request's question and pick its pipeline: the quick parse first, the full one
    /// when it cannot read it, and a query neither reads is an [`UnreadableQuery`]
    fn read_request(
        &self,
        packet: &[u8],
        client: IpAddr,
        state: &EngineInner,
    ) -> Result<RequestHead, UnreadableQuery> {
        let pipeline_of = |head: (&str, RecordType, DNSClass, bool)| {
            let (qname, qtype, qclass, edns_present) = head;
            let facts = crate::matcher::RequestFacts {
                qname,
                qtype,
                qclass,
                client_ip: client,
                edns_present,
            };
            self.pick_pipeline(state, &facts)
                .map_or_else(|| Arc::from(NO_PIPELINE), |pipeline| pipeline.id.clone())
        };
        let mut qname_buf = [0u8; 256];
        if let Some(q) = parse_quick(packet, &mut qname_buf) {
            let pipeline_id = pipeline_of((
                q.qname,
                RecordType::from(q.qtype),
                DNSClass::from(q.qclass),
                q.edns_present,
            ));
            return Ok(RequestHead::quick(&q, pipeline_id));
        }
        let name_end = crate::proto_utils::question_name_end(packet).ok_or(UnreadableQuery)?;
        let req = Message::from_bytes(packet).map_err(|_| UnreadableQuery)?;
        let question = req.queries.first().ok_or(UnreadableQuery)?;
        // The text parse_quick would have built / parse_quick 会拼出的同一段文本
        let qname: Arc<str> = Arc::from(crate::proto_utils::name_text(question.name()));
        let (qtype, qclass) = (question.query_type(), question.query_class());
        let edns_present = req.edns.is_some();
        Ok(RequestHead {
            pipeline_id: pipeline_of((&qname, qtype, qclass, edns_present)),
            qname,
            qtype,
            qclass,
            tx_id: req.metadata.id,
            flags: crate::proto_utils::QueryFlags::of(packet),
            edns_present,
            edns_version: crate::proto_utils::edns_version(packet).unwrap_or(0),
            // 照 `question_name_end` 读得出的问题名不压缩，hickory 读到的是同一个名字，类型和类别跟在它后面
            // A question name `question_name_end` reads is uncompressed, the same name hickory
            // read, with the type and the class after it
            question_end: name_end + 4,
            client_ecs: crate::proto_utils::client_subnet(packet),
        })
    }

    /// 状态 `state` 的配置按它的 Geo 数据为请求 `facts` 选的 pipeline（见 [`select_pipeline`]），快速路径和完整路径
    /// 都从这里选
    /// The pipeline the configuration of state `state` picks for request `facts` by its Geo data
    /// (see [`select_pipeline`]), the fast path and the full path both picking here
    fn pick_pipeline<'a>(
        &self,
        state: &'a EngineInner,
        facts: &crate::matcher::RequestFacts<'_>,
    ) -> Option<&'a crate::matcher::RuntimePipeline> {
        select_pipeline(&state.pipeline, &self.listener_label, facts, &state.geo)
    }

    /// 决定怎么回答 `request`：不支持的 EDNS 版本回 BADVERS；查缓存；然后沿着规则走（跳转、continue、静态应答、转发），
    /// 直到得出应答。每个出口都在这里，收尾在 [`Self::answer`] 和交回结果的入口
    /// Decide how to answer `request`: BADVERS for an unsupported EDNS version; the cache; then
    /// along the rules (jumps, continues, static answers, forwards) until an answer comes out.
    /// Every exit is here, the finishing in [`Self::answer`] and the entry handing the outcome
    /// back
    async fn decide(
        &self,
        request: &Request<'_>,
        pipeline: Option<&crate::matcher::RuntimePipeline>,
        route: &mut Route,
        info: &mut ResponseInfo,
    ) -> anyhow::Result<Bytes> {
        let packet = request.packet;
        // RFC 6891 section 6.1.3, as on the fast path: an unsupported EDNS version is
        // answered BADVERS, a query the fast parser cannot read (trailing bytes, a name that
        // needs escapes) included
        // RFC 6891 第 6.1.3 节，和快速路径一样：不支持的 EDNS 版本回 BADVERS，快速解析读不了的查询（结尾多了
        // 字节、名字要转义）也一样
        if request.edns_version != 0 {
            return Ok(crate::proto_utils::badvers_response(
                packet,
                request.question_end,
            ));
        }
        let background_refresh = request.refresh.is_some();
        // A background refresh looks up no cache / 后台刷新不查缓存
        if !background_refresh
            && let Some(answer) = self.answer_from_cache(&route.lookup(request), info).await
        {
            return Ok(answer);
        }

        let cfg = &request.state.pipeline;
        let response_jump_limit = cfg.settings.response_jump_limit as usize;
        // 从第 `resume_at` 条规则起求值 `pipeline`（见 `Route::resume_at`）
        // Evaluate `pipeline` from its rule at `resume_at` on (see `Route::resume_at`)
        let facts = request.facts();
        let evaluate = |pipeline: &crate::matcher::RuntimePipeline, resume_at: usize| {
            self.apply_rules(
                request.state,
                pipeline,
                &facts,
                &RuleEvaluationContext::new(resume_at, background_refresh)
                    .with_observed(request.observed),
            )
        };
        let mut decision = match pipeline {
            Some(p) => evaluate(p, route.resume_at),
            None => {
                let decision = Decision::default_forward(&cfg.settings);
                if let Some((observer, ctx)) = request.observed {
                    report_decision(observer, ctx, &route.pipeline, None, &decision);
                }
                decision
            }
        };
        // 请求现在所在的 pipeline，continue 以后在它里面接着求值；选不到 pipeline 时为 None，那时的默认转发不会 continue
        // The pipeline the request is in now, where evaluation resumes after a continue; None
        // when no pipeline was picked, whose default forward never continues
        let mut current = pipeline;
        loop {
            match decision {
                Decision::Jump { pipeline: target } => {
                    if route.jumps_left == 0 {
                        super::rules::warn_jump_limit(request, &route.pipeline, &target, "request");
                        // How many jumps a request has left depends on the way it
                        // came, which no key carries, so this SERVFAIL is its own
                        // (see `Engine::answer`): a waiter on its held entry
                        // may have jumps to spare, so the entry goes rather than hand
                        // it over, and it is not cached for a request that enters
                        // this pipeline directly.
                        // 请求还能跳几次取决于它一路怎么来的，键里没有这一项，所以这个
                        // SERVFAIL 只属于它（见 `Engine::answer`）：等在持有条目上的
                        // 请求可能还有余量，所以放掉条目，不把它交出去；也不缓存给直接进入
                        // 这个 pipeline 的请求。
                        info.upstream = Some(Source::Static);
                        anyhow::bail!("the jump limit was reached");
                    }
                    route.jumps_left -= 1;
                    let Some(p) = cfg.pipeline(&target) else {
                        crate::warn_sparse!(
                            event = "jump_target_missing",
                            qname = %request.qname,
                            qtype = ?request.qtype,
                            client_ip = %request.peer.ip(),
                            pipeline = %route.pipeline,
                            target = %target,
                            "jump target pipeline not found, answering SERVFAIL"
                        );
                        info.upstream = Some(Source::Static);
                        return Ok(crate::proto_utils::servfail_reply(packet));
                    };
                    info.pipeline = Some(p.id.clone());
                    if let Some((observer, ctx)) = request.observed {
                        observer.pipeline_selected(ctx, &p.id);
                    }
                    // 跳转换了键（见 `Route::enter`）就按目标 pipeline 的键再查一次响应缓存。转发回来的应答存在这个键下，
                    // 而入口那次查找用的是入口 pipeline 的键，所以以前跳转过的请求永远查不到它，每次都去问上游。后台刷新照
                    // 请求原样重放（同一个地址，带不带 EDNS、类别都一样，见 refresh.rs），走的是同一条路线、写回同一个键。
                    // 键里带着目标按自己的规则（连同它跳得到的 pipeline）分辨请求方的结果，和直接选进目标的请求查的是同一套
                    // 键，所以目标按「谁在问」给不同应答时也照查。回答检查据过上游的回答以后（continue 之后的跳转）键不换，
                    // 照这套键查过的那一次已经没查到
                    // When the jump changed the keys (see `Route::enter`), look in the response cache
                    // again under the target pipeline's key. A forwarded answer is stored under that
                    // key, while the entry lookup used the entry pipeline's, so a request that jumped
                    // used to never find it and go upstream every time. A background refresh replays
                    // the request as it came (from the same address, with or without EDNS, in the
                    // same class, see refresh.rs), taking the same route and writing back under the
                    // same key. The key carries how the target's rules (with the pipelines it can
                    // jump to) tell requesters apart, the same keys a request selected into the
                    // target looks up, so a target answering by who is asking is looked up as well.
                    // Once an answer check has gone by an upstream's answer (a jump after a continue)
                    // the keys stay, and the lookup under them has missed already
                    if route.enter(request, p)
                        && !background_refresh
                        && let Some(answer) =
                            self.answer_from_cache(&route.lookup(request), info).await
                    {
                        return Ok(answer);
                    }
                    current = Some(p);
                    decision = evaluate(p, route.resume_at);
                }
                Decision::Static { rcode, answers } => {
                    info.upstream = Some(Source::Static);
                    return Ok(phases::handle_static_decision(
                        self, request, route, rcode, &answers,
                    ));
                }
                Decision::Forward {
                    upstream,
                    pre_split_upstreams,
                    response_phase,
                    rule_name,
                    rule_index,
                    transport,
                    ecs,
                    allow_reuse,
                } => {
                    let forwarded = phases::handle_forward_decision(
                        self,
                        request,
                        route,
                        phases::ForwardDecision {
                            upstream: &upstream,
                            pre_split_upstreams: pre_split_upstreams.as_ref(),
                            rule_name: &rule_name,
                            response: response_phase.as_deref(),
                            transport,
                            ecs: ecs.as_ref(),
                            allow_reuse,
                        },
                        info,
                    )
                    .await;

                    match forwarded {
                        Ok(phases::ForwardResult::Success(bytes)) => return Ok(bytes),
                        Ok(phases::ForwardResult::Continue { ctx }) => {
                            // 只有规则的回答检查会 continue，所以作出决定的是当前 pipeline 的一条规则
                            // Only a rule's answer check continues, so a rule of the current
                            // pipeline made the decision
                            let (Some(p), Some(rule)) = (current, rule_index) else {
                                unreachable!("only a rule's answer check continues");
                            };
                            route.continued(*ctx, rule);
                            decision = evaluate(p, route.resume_at);
                        }
                        Ok(phases::ForwardResult::Jump {
                            pipeline,
                            packet,
                            carried,
                        }) => {
                            route.response_jumped(packet, carried, response_jump_limit);
                            decision = Decision::Jump { pipeline };
                        }
                        // 这次转发没以应答结束。后台刷新没有要应答的客户端：上游失败了就到此为止，失败原样交回，由
                        // refresh.rs 记录。客户端请求只剩流控没让等的这一种（见 `UpstreamFailure::withheld`）：上游失败、
                        // 应答读不了都已经在转发里化成了过期应答、SERVFAIL 或 miss 动作的结果。它是这台设备自己的事，
                        // 这个请求只给自己回 SERVFAIL，不交给等在它条目上的别的请求（见 `Engine::answer`）；
                        // 也不逐个记警告，拦着的时候每秒可以有几万个
                        // The forward ended without an answer. A background refresh answers no
                        // client: once the upstream failed it ends there, the failure coming back
                        // as it is for refresh.rs to log. For a client request only one is left,
                        // flow control keeping the query from waiting (see
                        // `UpstreamFailure::withheld`): an upstream failure or a reply that cannot be
                        // read has become a stale answer, SERVFAIL or the miss actions' outcome
                        // within the forward. It is the device's own affair, so the request answers
                        // SERVFAIL to itself alone and not to the requests waiting on its entry (see
                        // `Engine::answer`); nor is a warning logged for each, held back
                        // there being tens of thousands a second
                        Err(e) => {
                            if !background_refresh {
                                tracing::debug!(
                                    event = "forward_withheld",
                                    error = %e,
                                    rule = %rule_name,
                                    "flow control kept the forward from the upstream, returning SERVFAIL"
                                );
                            }
                            return Err(e);
                        }
                    }
                }
            }
        }
    }

    /// 槽位 `slot` 里新鲜的 `renewed` 存了 `elapsed_secs` 秒，快到期了（见 `RefreshCheck`）就为它发起后台刷新；已经在刷新的
    /// 由 `spawn_background_refresh` 认出来。查缓存和快速路径交出新鲜应答时都经这里
    /// The fresh `renewed` in slot `slot` has been stored `elapsed_secs` seconds: once it is due
    /// (see `RefreshCheck`) a background refresh is started for it, one already being refreshed
    /// being told by `spawn_background_refresh`. The cache lookup and the fast path both go
    /// through here when they serve a fresh answer
    pub(crate) fn refresh_if_due(
        &self,
        state: &Arc<EngineInner>,
        renewed: &Arc<CacheEntry>,
        elapsed_secs: u32,
        slot: u64,
        requester: Requester,
    ) {
        let Some(check) = RefreshCheck::of(&state.pipeline.settings, renewed, elapsed_secs)
            .filter(RefreshCheck::due)
        else {
            return;
        };
        tracing::debug!(
            event = "cache_background_refresh_trigger",
            qname = %renewed.qname,
            qtype = ?hickory_proto::rr::RecordType::from(renewed.qtype),
            remaining_ttl = check.remaining_ttl,
            original_ttl = renewed.original_ttl,
            "Triggering background refresh for cached entry"
        );
        self.spawn_background_refresh(state, renewed, slot, requester);
    }

    /// Construct standard DNS query packet using hickory_proto
    /// 使用 hickory_proto 构造标准 DNS 查询包
    ///
    /// Design: Use hickory-proto to ensure RFC compliance
    /// 设计：使用 hickory-proto 确保 RFC 合规性
    /// - Has TXID 0, which is what RFC 8484 section 4.1 asks of DoH. Its ID means nothing on
    ///   the way: UDP and TCP give each query a random one of their own (RFC 5452 section
    ///   9.2), DoQ 0 (RFC 9250 section 4.2.1), and over DoH HTTP pairs the answer with the
    ///   query; each hands the answer back with the query's ID, and the answer goes to no
    ///   client but into the cache, where its ID counts for nothing
    /// - Sets the query bits `flags` the replayed request had (RD, CD, DO), so its
    ///   answer is fetched and stored the same way
    /// - Encodes QNAME correctly
    /// - TXID 为 0，RFC 8484 第 4.1 节要 DoH 这样发。它的 ID 一路上都没有意义：UDP、TCP 给每个查询换上自己随机取的
    ///   （RFC 5452 第 9.2 节），DoQ 换成 0（RFC 9250 第 4.2.1 节），DoH 上 HTTP 把应答和查询配好对；交回应答时都换回
    ///   查询的 ID，而应答不交给哪个客户端，只进缓存，ID 在那里没有意义
    /// - 带上被重放的请求的查询位 `flags`（RD、CD、DO），应答按同样的方式取回、存放
    /// - 正确编码 QNAME
    /// - Carries EDNS when `edns` is set, and the client's own ECS `ecs`, as the
    ///   request being replayed did
    /// - `edns` 为真时带上 EDNS，并带上客户端自己的 ECS `ecs`，与被重放的请求一致
    pub(crate) fn construct_dns_packet(
        &self,
        qname: &str,
        qtype: hickory_proto::rr::RecordType,
        qclass: DNSClass,
        edns: bool,
        ecs: Option<&crate::ecs::EcsKey>,
        flags: crate::proto_utils::QueryFlags,
    ) -> anyhow::Result<Bytes> {
        use hickory_proto::op::{Message, MessageType, Query};

        // Build DNS query message
        // 构建 DNS 查询消息
        // hickory-proto 0.26: Message::new() defaults RD=false (was true in 0.24), so RD
        // is set from the replayed request.
        // hickory-proto 0.26: Message::new() 默认 RD=false（0.24 中为 true），所以 RD 按被重放的
        // 请求设置。
        let mut msg = Message::new(0, MessageType::Query, hickory_proto::op::OpCode::Query);
        msg.metadata.recursion_desired = flags.recursion_desired();
        msg.metadata.checking_disabled = flags.checking_disabled();

        // Add question section
        // 添加问题部分
        let name = crate::proto_utils::name_from_text(qname)
            .ok_or_else(|| anyhow::anyhow!("query name text {qname:?}"))?;
        // 按客户端问的类别问：缓存槽位分类别，刷新拿回的应答会写回这个类别的槽位
        // In the class the client asked: cache slots are kept apart by class, and the
        // refreshed answer goes back into this class's slot
        let mut query = Query::query(name.clone(), qtype);
        query.set_query_class(qclass);
        msg.add_query(query);
        // An ECS option and the DO bit only travel inside EDNS / ECS 选项和 DO 位只能放在 EDNS 里
        if edns || ecs.is_some() || flags.dnssec_ok() {
            let mut opt = hickory_proto::op::Edns::new();
            opt.set_max_payload(crate::proto_utils::UDP_PAYLOAD);
            opt.set_dnssec_ok(flags.dnssec_ok());
            if let Some(subnet) = ecs
                && let Some(address) = subnet.ip()
            {
                opt.options_mut()
                    .insert(hickory_proto::rr::rdata::opt::EdnsOption::Subnet(
                        hickory_proto::rr::rdata::opt::ClientSubnet::new(
                            address,
                            subnet.source_prefix,
                            0,
                        ),
                    ));
            }
            msg.edns = Some(opt);
        }

        // Serialize to bytes
        // 序列化为字节
        let bytes = msg.to_vec()?;

        Ok(Bytes::from(bytes))
    }
}

/// 读不了的查询：问题名不合规、完整解析也读不了、没有问题（见 `Engine::read_request`）。读得了读不了在读的那一刻定下，
/// 监听器据此回 FORMERR（见 `Engine::answer_after_fast_path`）；读得了的查询以后怎样都不会再是它
/// A query that cannot be read: a question name that breaks the rules, the full parse failing
/// too, no question (see `Engine::read_request`). Whether a query can be read is settled the
/// moment it is read, and the listener answers FORMERR by it (see
/// `Engine::answer_after_fast_path`); a query that was read never becomes one later
#[derive(Debug)]
pub struct UnreadableQuery;

impl std::fmt::Display for UnreadableQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the query cannot be read")
    }
}

impl std::error::Error for UnreadableQuery {}

/// 一个请求的记录：观察者句柄和应答日志。收尾时记下请求的结局；没收尾就丢掉的（请求被取消）照样上报
/// A request's records: the observer handle and the response log. Finishing notes how the
/// request ended; dropped unfinished (the request cancelled), they report all the same
struct Journal<'a> {
    observed: Option<ObservedRequest<'a>>,
    log: ResponseLog<'a>,
}

impl Journal<'_> {
    /// 记下请求以 `result` 结束：客户端的请求是交给客户端的应答，后台刷新是它得出的结果。失败只有观察者记得到：应答日志只记
    /// 客户端的请求（见 `ResponseLog::with_pipeline`），它们总以应答结束（见 `Engine::handle_packet_full`）
    /// Note that the request ended in `result`: for a client's request the reply its client
    /// gets, for a background refresh what it came to. Only the observer notes a failure: the
    /// response log records client requests alone (see `ResponseLog::with_pipeline`), which
    /// always end in a reply (see `Engine::handle_packet_full`)
    fn finish(mut self, result: &anyhow::Result<Bytes>) {
        if let Some(observed) = self.observed.as_mut() {
            observed.finish(result);
        }
        if let Ok(reply) = result {
            self.log.answered(reply);
        }
    }
}

/// 走完规则的请求（见 `Engine::answer`）：得出的结果，客户端的应答至少依赖它的 ECS 的多少位（见
/// `phases::client_reply`），和还没收尾的记录
/// A request through the rules (see `Engine::answer`): what it came to, how many bits of the
/// client's ECS its reply depends on at least (see `phases::client_reply`), and the records
/// not yet finished
struct Answered<'a> {
    result: anyhow::Result<Bytes>,
    echo_scope: u8,
    journal: Journal<'a>,
}

/// 读出来的请求和选中的 pipeline（见 `Engine::read_request`）；快速路径读过的照样交给异步路径（见 [`PreParsedData`]）
/// The request as read, and the pipeline picked (see `Engine::read_request`); what the fast
/// path read goes on to the async path as it is (see [`PreParsedData`])
#[derive(Debug, Clone)]
struct RequestHead {
    qname: Arc<str>,
    qtype: RecordType,
    qclass: DNSClass,
    tx_id: u16,
    flags: crate::proto_utils::QueryFlags,
    edns_present: bool,
    /// 请求 OPT 里的 EDNS 版本，没有 OPT 时为 0 / The EDNS version in the request's OPT, 0 without one
    edns_version: u8,
    /// 问题段在哪里结束 / Where the question section ends
    question_end: usize,
    client_ecs: Option<crate::ecs::EcsKey>,
    pipeline_id: Arc<str>,
}

impl RequestHead {
    /// 快速解析读出的 `q`，选中的是 `pipeline_id` / `q` as the quick parse read it, `pipeline_id` picked
    fn quick(q: &crate::proto_utils::QuickQuery<'_>, pipeline_id: Arc<str>) -> Self {
        Self {
            qname: Arc::from(q.qname),
            qtype: RecordType::from(q.qtype),
            qclass: DNSClass::from(q.qclass),
            tx_id: q.tx_id,
            flags: q.flags,
            edns_present: q.edns_present,
            edns_version: q.edns_version,
            question_end: q.question_end,
            client_ecs: q.client_subnet,
            pipeline_id,
        }
    }

    /// 这样读出来的请求：`packet` 是它的包，来自 `peer`、带着 `ecs`，从 `start` 起照配置 `state` 处理。它不是后台刷新，
    /// 也不上报观察者，是的话由调用的一方改这两项
    /// The request read so: `packet` its packet, from `peer` with `ecs`, handled under the
    /// configuration `state` from `start` on. It is no background refresh and reports to no
    /// observer, the caller setting the two where it is or does
    fn request<'a>(
        &'a self,
        state: &'a Arc<EngineInner>,
        packet: &'a [u8],
        peer: SocketAddr,
        ecs: Option<crate::ecs::EcsKey>,
        start: Instant,
    ) -> Request<'a> {
        Request {
            state,
            packet,
            qname: &self.qname,
            qtype: self.qtype,
            qclass: self.qclass,
            tx_id: self.tx_id,
            flags: self.flags,
            edns_version: self.edns_version,
            question_end: self.question_end,
            peer,
            // Who is asking, as far as rules and ECS can tell / 规则和 ECS 能分辨的请求方
            requester: Requester {
                address: peer.ip(),
                edns: self.edns_present,
                ecs,
            },
            start,
            refresh: None,
            observed: None,
        }
    }
}

/// 一个请求在整个处理过程中不变的部分：它的包、问题、谁在问、用的配置快照，和后台刷新时要更新的条目
/// What stays the same for a request all the way through: its packet, its question, who is
/// asking, the configuration snapshot it uses, and for a background refresh the entry it renews
pub(crate) struct Request<'a> {
    pub(crate) state: &'a Arc<EngineInner>,
    /// 客户端发来的查询，没经过哪次转发改写 / The query as the client sent it, rewritten by no
    /// forward
    pub(crate) packet: &'a [u8],
    pub(crate) qname: &'a Arc<str>,
    pub(crate) qtype: hickory_proto::rr::RecordType,
    pub(crate) qclass: DNSClass,
    pub(crate) tx_id: u16,
    pub(crate) flags: crate::proto_utils::QueryFlags,
    /// 请求 OPT 里的 EDNS 版本，没有 OPT 时为 0 / The EDNS version in the request's OPT, 0
    /// without one
    pub(crate) edns_version: u8,
    /// 问题段在 `packet` 里哪里结束 / Where the question section ends in `packet`
    pub(crate) question_end: usize,
    pub(crate) peer: SocketAddr,
    /// Who is asking (address, EDNS, the client's own ECS) / 谁在问（地址、EDNS、客户端自己的 ECS）
    pub(crate) requester: Requester,
    pub(crate) start: Instant,
    /// For a background refresh, the entry it renews; the request is one exactly when it is
    /// given / 后台刷新时它要更新的条目，有它就是后台刷新
    pub(crate) refresh: Option<&'a RefreshTarget>,
    /// Observer context of the request / 所属请求的观察者上下文
    pub(crate) observed: super::observation::Observed<'a>,
}

impl Request<'_> {
    /// 匹配器看的这个请求（见 [`crate::matcher::RequestFacts`]）/ This request as matchers see it
    /// (see [`crate::matcher::RequestFacts`])
    pub(crate) fn facts(&self) -> crate::matcher::RequestFacts<'_> {
        crate::matcher::RequestFacts {
            qname: self.qname,
            qtype: self.qtype,
            qclass: self.qclass,
            client_ip: self.requester.address,
            edns_present: self.requester.edns,
        }
    }

    /// 这个请求在 `pipeline` 下、命名空间 `namespace` 里的问题，请求方部分是 `requester`（见 [`KeyedQuestion`]）：路线照算
    /// 键时的这两样拼回它（见 `Route::question`）
    /// This request's question under `pipeline`, in namespace `namespace`, with `requester` as
    /// the requester's part (see [`KeyedQuestion`]): a route puts it back together from those
    /// two as its keys were computed (see `Route::question`)
    pub(crate) fn question<'q>(
        &'q self,
        pipeline: &'q str,
        namespace: u64,
        requester: RequesterKey,
    ) -> KeyedQuestion<'q> {
        KeyedQuestion {
            namespace,
            pipeline_id: pipeline,
            qname: self.qname.as_bytes(),
            qtype: self.qtype,
            qclass: self.qclass,
            flags: self.flags,
            requester,
            client_ecs: self.requester.ecs,
        }
    }

    /// 这个请求在 id 为 `id` 的 pipeline（`pipeline` 是它，选不到时为 None）下的键：按它的规则分辨请求方
    /// This request's keys under the pipeline of id `id` (`pipeline` being it, None when none was
    /// picked): requesters told apart by its rules
    fn keys(&self, id: &str, pipeline: Option<&crate::matcher::RuntimePipeline>) -> CacheKeys {
        self.state
            .question(pipeline, &self.cached_question(id), self.requester)
            .keys()
    }

    /// 槽位里的应答要回答的这个问题，在 `pipeline` 下 / This question as the answers in a slot of
    /// `pipeline` must answer it
    pub(crate) fn cached_question<'q>(&'q self, pipeline: &'q str) -> CachedQuestion<'q> {
        CachedQuestion {
            qname: self.qname,
            pipeline_id: pipeline,
            qtype: u16::from(self.qtype),
            qclass: u16::from(self.qclass),
            flags: self.flags,
        }
    }

    /// 在 `pipeline` 的槽位 `slot` 里查这个请求的应答 / Looking up this request's answer in slot
    /// `slot` of `pipeline`
    pub(crate) fn lookup<'s>(
        &'s self,
        pipeline: &'s str,
        slot: u64,
    ) -> phases::CacheLookupContext<'s> {
        phases::CacheLookupContext {
            request: self,
            pipeline_id: pipeline,
            slot,
        }
    }

    /// 这个请求发给上游的查询替谁问（见 `upstream::forward_upstream`）：替客户端；后台刷新不替谁问，是 None
    /// Whom this request's upstream queries are asked for (see `upstream::forward_upstream`):
    /// the client; nobody, None, for a background refresh
    pub(crate) fn asker(&self) -> Option<std::net::IpAddr> {
        self.refresh.is_none().then(|| self.peer.ip())
    }

    /// 去掉刷新要更新的那份应答，它还在的话（见 [`renewing`]）/ Drop the answer the refresh
    /// renews, if it is still there (see [`renewing`])
    fn drop_refreshed(&self, engine: &Engine, target: &RefreshTarget) {
        engine.drop_refreshed(&self.cached_question(&target.pipeline), target);
    }
}

/// 后台刷新以 `answer` 结束时拿不拿得来更新条目。缓存从来不收的应答（SERVFAIL，不论从哪里来：跳转上限、跳转目标不存在、
/// 静态 SERVFAIL；截断的；TSIG 签过的，见 `Engine::insert_dns_cache_entry`）拿不来：刷新以失败结束，由 refresh.rs 记下，
/// 被刷新的那份原样留着（开着 serve_stale_ttl_reset 时还续期）。别的应答都拿得来，被刷新的那份随后去掉：照它的问题和适用
/// 范围写回了缓存的，已经取代了它；没写回去的（TTL 为 0、没有 SOA 的否定应答、不缓存的静态应答，或者写在了别的键、别的
/// 适用范围下），它就和规则、和上游现在的说法对不上了，留着的话每次命中都被当过期应答交出去再续上（RFC 8767 只在取不到
/// 新应答时才用过期的），下一个客户端请求自己走规则。以前这些各在半路判断：只拿到截断的应答时，条目先当作不进缓存的
/// 完整应答删了，到出口才算失败，续期也落了空
/// Whether a background refresh ending in `answer` can renew its entry with it. Not with an
/// answer the cache never takes (SERVFAIL, wherever it comes from: the jump limit, a jump
/// target that does not exist, a static SERVFAIL; a truncated one; a TSIG-signed one, see
/// `Engine::insert_dns_cache_entry`): the refresh ends as a failure, which refresh.rs notes,
/// and the answer it renews stays as it is (renewed with serve_stale_ttl_reset on). Any other
/// answer will do, and the renewed one is dropped after: written back under its question and
/// reach, the new one has taken its place already; not written back (a TTL of 0, a negative
/// answer without SOA, a static answer that is not cached, or written under another key or
/// reach), it no longer matches the rules or what the upstream says now, and kept it would go
/// out stale and be renewed on every hit (RFC 8767 serves stale only when no new answer can be
/// had), so the next client request runs the rules itself. These used to be judged halfway:
/// with only a truncated answer back, the entry was first dropped as for a whole answer that
/// is not cached, the refresh counting as failed only at the exit, its renewal coming to
/// nothing
fn renewing(answer: Bytes) -> anyhow::Result<Bytes> {
    let no_answer = if crate::proto_utils::parse_response_quick(&answer)
        .is_some_and(|qr| qr.rcode == ResponseCode::ServFail)
    {
        "the rules answered SERVFAIL"
    } else if crate::proto_utils::truncated_response(&answer) {
        "only a truncated answer came back"
    } else if crate::proto_utils::last_record_is_tsig(&answer) {
        "only a signed answer came back"
    } else {
        return Ok(answer);
    };
    Err(crate::engine::upstream::UpstreamFailure::error(
        anyhow::anyhow!(no_answer),
    ))
}

/// 请求沿着规则走的路线：现在在哪个 pipeline、应答缓存在哪个键下、还能跳几次、规则越过了什么，以及它在路上记下的
/// What a request's way along the rules has come to: which pipeline it is in, which key its answers
/// are cached under, how many jumps are left, what rules continued past, and what it noted on the way
pub(crate) struct Route {
    /// 现在所在的 pipeline / The pipeline it is in now
    pub(crate) pipeline: Arc<str>,
    /// 应答缓存在哪个 pipeline 的键下：回答检查据过上游的回答或失败之前，请求阶段的跳转换成目标的；据过以后不再换（见
    /// [`Self::enter`]），回答检查跳过去的、continue 以后的规则跳过去的，拿到的应答都缓存在据那份回答的 pipeline 的键下
    /// The pipeline whose key answers are cached under: until an answer check has gone by an
    /// upstream's answer or failure, a request-phase jump changes it to the target's; after
    /// that it changes no more (see [`Self::enter`]), what is got over there, by an answer
    /// check's jump or by a jump of the rules after a continue, being cached under the key of
    /// the pipeline that went by that answer
    pub(crate) key_pipeline: Arc<str>,
    pub(crate) keys: CacheKeys,
    /// 在当前 pipeline 里从第几条规则（从 0 起）接着求值：规则 continue 以后是它的下一条，它和它之前的规则都已经求值过、
    /// 没有作出这个请求的决定，不再执行一遍（它们的 log 动作也不再记一次）；0 是从头求值，进了别的 pipeline 也从 0 起
    /// The place (from 0) of the rule in the current pipeline evaluation resumes at: after a
    /// rule continued, the one after it, that rule and those before it having been evaluated
    /// already without deciding the request, and run no second time (nor their log actions
    /// logging again); 0 to evaluate from the start, as on entering another pipeline
    resume_at: usize,
    /// 规则越过、留着给后面的 `allow` 复用的应答 / The answer a rule continued past, kept for a later `allow`
    pub(crate) reused_response: Option<ResponseContext>,
    /// 响应阶段跳转以后：转发照原样发出的包，不再按 `ecs` 改写，和它带的 ECS / After a response-phase
    /// jump: the packet the forwards send as it is rather than rewritten by `ecs`, and the ECS it
    /// carries
    pub(crate) jumped: Option<(Bytes, crate::ecs_scope::ForwardEcs)>,
    /// 还能跳几次，在要跳的地方数：请求阶段的跳转一份，响应动作的跳转连同它之后的规则级跳转另一份（见
    /// `Route::response_jumped`）
    /// How many more jumps may be made, counted where a jump is made: the request phase's jumps
    /// have one budget, a response action's jump with the rule-level jumps after it another (see
    /// `Route::response_jumped`)
    jumps_left: usize,
    /// 接下来的应答所依据的上游应答的 TTL：在这些键下回答检查做决定时据的每一份上游应答里最短的那个，每份都和记录的 TTL
    /// 一样收进 min_ttl..=cache_max_ttl（见 `Route::went_by`），还没据过哪份应答时为 None。此后缓存的应答都不比它留得久，
    /// 交出去的每条记录 TTL 也不比它长（见 `Route::cache`），规则给出的静态应答、转发拿到的应答都一样：哪一份到期了，上游都
    /// 可能答得不一样，回答检查也就可能走另一条路，给出别的应答。请求阶段的跳转只在它为 None、`fell_back` 也没置上时换键（见
    /// [`Self::enter`]）：那时跳过去给出的，直接进那里的请求也照样拿到
    /// The TTL of the upstream answers what answers next goes by: the least of every upstream
    /// answer an answer check decided on under these keys, each brought into
    /// min_ttl..=cache_max_ttl as a record's TTL is (see `Route::went_by`), None while none has
    /// been gone by. No answer cached from here on stays longer, nor does any record TTL going
    /// out run longer (see `Route::cache`), be it a static answer the rules give or one a
    /// forward fetches: once any of them expires the upstream may answer otherwise, and the
    /// checks may take another way to another answer. A request-phase jump changes the keys only
    /// while it is None and `fell_back` unset (see [`Self::enter`]): what is given over there
    /// then is given to the requests entering there directly too
    answer_ttl: Option<u32>,
    /// 回答检查据上游失败做了决定（见 `Route::went_by`）：上游没有回答、miss 动作接手了，或者回答检查看到的是失败应答（见
    /// `upstream::is_failure_reply`）。此后规则给出的静态应答只是这一次请求的兜底，不是这个问题的应答，不缓存（见
    /// `Route::static_ttl`）。转发拿到的应答照常缓存：故障期间备用上游的回答也是这个问题的回答
    /// An answer check decided on an upstream failure (see `Route::went_by`): the upstream gave
    /// no answer and the miss actions took over, or the check saw a failure reply (see
    /// `upstream::is_failure_reply`). A static answer the rules give from here on is a fallback
    /// for this request, not the answer to the question, and is not cached (see
    /// `Route::static_ttl`). An answer a forward fetches is cached as usual: a backup upstream's
    /// answer during the failure answers the question all the same
    fell_back: bool,
    /// The forwards the request passed, each with the ECS it sent and whom its reply applies
    /// to; every answer the request caches applies to the requesters all of them admit (see
    /// `CacheEntry::reach`). A forward adds its own here. None is passed before the keys change
    /// at a request-phase jump: a forward either answers or goes on through an answer check
    /// (see [`Self::enter`]). After the request, what its last answer was cached with
    /// 请求经过的转发，每次都记着它发出的 ECS 和应答适用于谁；请求缓存的每份应答适用于它们全都接受的请求方（见
    /// `CacheEntry::reach`）。转发把自己的这一次记在这里。请求阶段跳转换键之前一个也没有：转发要么就此作答，要么经回答检查
    /// 往下走（见 [`Self::enter`]）。请求结束后就是它最后一份应答缓存时带的那份
    pub(crate) trail: EcsReach,
    /// The inflight entry this request registered and still holds after a rule
    /// continued. The request keeps it for the rest of the decision loop, so its
    /// waiters get the final answer rather than one a rule continued past; a
    /// request holding an entry never waits on one. The entry's key keeps its
    /// waiters to requesters that the rules run after the continue treat alike
    /// (see `RuntimePipeline::requester`).
    /// 规则 continue 后本请求仍持有的 inflight 条目。它在决策循环余下的部分一直由
    /// 本请求持有，等待者拿到的是最终应答，而不是规则越过的那一个；持有条目的请求
    /// 从不等条目。条目的键只让 continue 之后运行的规则一样对待的请求方等在上面（见
    /// `RuntimePipeline::requester`）。
    pub(crate) held_inflight: Option<InflightCleanupGuard>,
}

impl Route {
    /// 从选中的 `pipeline_id` 出发（`pipeline` 是它，选不到时为 None）
    /// Starting from the picked `pipeline_id` (`pipeline` being it, None when none was picked)
    fn new(
        request: &Request<'_>,
        pipeline_id: &Arc<str>,
        pipeline: Option<&crate::matcher::RuntimePipeline>,
    ) -> Self {
        Self {
            pipeline: Arc::clone(pipeline_id),
            key_pipeline: Arc::clone(pipeline_id),
            keys: request.keys(pipeline_id, pipeline),
            resume_at: 0,
            reused_response: None,
            jumped: None,
            jumps_left: request.state.pipeline.settings.response_jump_limit as usize,
            answer_ttl: None,
            fell_back: false,
            trail: EcsReach::default(),
            held_inflight: None,
        }
    }

    /// 请求阶段跳进 `p`，给出缓存键换没换（换了就该按新键再查一次缓存）。回答检查据过上游的回答或失败以后（`answer_ttl`
    /// 有值或 `fell_back`）键和 trail 都留着，和响应阶段跳转一样：跳过去得出的应答取决于据过的那份回答，缓存在据它的
    /// pipeline 的键下，带着 `answer_ttl` 的上限；上游故障时那里也就有过期应答可交（RFC 8767）。换到目标的键下的话，入口这条
    /// 路线从不缓存，每个请求都要先问一遍据的那个上游，客户端拿到的 TTL 也不受那份回答约束。键里早已带着 continue 以后跳得到的
    /// pipeline 怎样分辨请求方，它们的配置也算进这个 pipeline 的缓存命名空间（见 `RuntimePipeline::answered_through`）。
    /// 据过之前不曾有转发作完（转发要么就此作答，要么经回答检查往下走），换键时也就没有 trail、上限要清
    /// Jump into `p` in the request phase, telling whether the keys changed (and the cache is to
    /// be looked up again under them). Once an answer check has gone by an upstream's answer or
    /// failure (`answer_ttl` set or `fell_back`), the keys and the trail stay, as after a
    /// response-phase jump: the answer reached over there depends on the answer gone by, and is
    /// cached under the key of the pipeline that went by it, within `answer_ttl`, so a stale
    /// answer is there to give when that upstream fails (RFC 8767). Moved to the target's keys,
    /// the entry's route would never be cached, every request asking the upstream gone by first,
    /// and the TTL a client gets would not be bounded by that answer. The keys carry already how
    /// the pipelines a jump after a continue reaches tell requesters apart, and their
    /// configuration goes into this pipeline's cache namespace (see
    /// `RuntimePipeline::answered_through`). No forward is done before any answer has been gone
    /// by (a forward either answers or goes on through an answer check), so a change of keys
    /// finds no trail or bound to clear
    fn enter(&mut self, request: &Request<'_>, p: &crate::matcher::RuntimePipeline) -> bool {
        self.pipeline = p.id.clone();
        self.resume_at = 0;
        // 留着复用的应答属于取到它的那个 pipeline：那边的转发、按那边的 ECS 拿到的，这里的 allow 不拿它
        // An answer kept for reuse belongs to the pipeline that fetched it, through its forward
        // and with its ECS, and an allow here does not take it
        self.reused_response = None;
        if self.answer_ttl.is_some() || self.fell_back {
            return false;
        }
        self.key_pipeline = p.id.clone();
        // The keys follow the pipeline / 键随 pipeline 改变
        self.keys = request.keys(&p.id, Some(p));
        true
    }

    /// 这条路线的键所依据的问题（见 `Request::question`）：转发照它在 inflight 表里登记、等待
    /// The question this route's keys came from (see `Request::question`), which a forward
    /// registers and waits under in the inflight map
    pub(crate) fn question<'q>(&'q self, request: &'q Request<'_>) -> KeyedQuestion<'q> {
        request.question(&self.key_pipeline, self.keys.namespace, self.keys.requester)
    }

    /// 在这条路线的键下查 `request` 的应答：槽位属于 `key_pipeline`，两样一起交出
    /// Looking up `request`'s answer under this route's keys: the slot belongs to
    /// `key_pipeline`, and the two go out together
    pub(crate) fn lookup<'s>(&'s self, request: &'s Request<'_>) -> phases::CacheLookupContext<'s> {
        request.lookup(&self.key_pipeline, self.keys.slot)
    }

    /// 排第 `rule` 的规则越过了这个应答（continue）：`reused` 留给后面的 `allow`，求值从它的下一条接着走
    /// The rule at `rule` continued past this answer: `reused` is kept for a later `allow`, and
    /// evaluation resumes at the rule after it
    fn continued(&mut self, reused: Option<ResponseContext>, rule: usize) {
        self.reused_response = reused;
        self.resume_at = rule + 1;
    }

    /// 回答检查做了决定，据的是一份 TTL 为 `ttl` 的上游回答（`Some(ttl)`，它自己的 TTL 收进 min_ttl..=cache_max_ttl，见
    /// `phases::ttl_within`）：记进 `answer_ttl`，此后缓存的应答最多留这么久；或者据的是上游失败（None）：记进
    /// `fell_back`，此后规则给出的静态应答是兜底
    /// An answer check decided, going by an upstream answer of TTL `ttl` (`Some(ttl)`, its own
    /// TTL brought into min_ttl..=cache_max_ttl, see `phases::ttl_within`): noted in
    /// `answer_ttl`, no answer cached from here on staying longer; or going by an upstream
    /// failure (None): noted in `fell_back`, a static answer the rules give from here on being a
    /// fallback
    pub(crate) fn went_by(&mut self, ttl: Option<u32>) {
        match ttl {
            Some(ttl) => {
                self.answer_ttl = Some(self.answer_ttl.map_or(ttl, |before| before.min(ttl)));
            }
            None => self.fell_back = true,
        }
    }

    /// 规则给出的静态应答要缓存多久（再经 [`Self::cache`] 收进 `answer_ttl` 以内）。`carried` 是它带的 TTL（记录里最小的，
    /// 见 `response::least_ttl`）；不带记录的（deny 的 REFUSED、static_response、问的类型没有记录时的 NODATA）没有自己的
    /// TTL，留 `answer_ttl`。只有据上游应答给出的才缓存，下次不必再问上游：规则直接给出的（`answer_ttl` 为 None）规则下次
    /// 照样直接给出（快速路径、规则缓存），不用问谁，从响应缓存拿的话查询日志和规则计数就记不到这条规则，它的 log 动作也不
    /// 执行；上游失败以后兜底给出的（`fell_back`）只是这一次请求的。请求阶段和响应阶段都照这一处算。min_ttl 只抬上游回答
    /// 的 TTL，不抬规则写的：抬了缓存时间、记录却不抬，缓存里的记录 TTL 先走完，交出去的就是 TTL 为 0 的记录
    /// How long a static answer the rules give is to be cached (brought within `answer_ttl` by
    /// [`Self::cache`] after). `carried` is the TTL it carries (the least of its records', see
    /// `response::least_ttl`); one without records (deny's REFUSED, static_response, the NODATA
    /// of a type with no records) has no TTL of its own and stays for `answer_ttl`. Only one
    /// given by an upstream answer is cached, so the upstream need not be asked next time: one
    /// the rules give outright (`answer_ttl` None) they give again outright (the fast path, the
    /// rule cache) with nobody to ask, and taken from the response cache it would be missing
    /// from the query log and rule counts under its rule, its log action not run; one given as
    /// a fallback after an upstream failure (`fell_back`) is for this request alone. The request
    /// phase and the response phase both go by this. min_ttl raises the TTLs of upstream
    /// answers, not those a rule writes: raising the time cached and not the records would have
    /// the cached records' TTLs run out first, going out as 0
    pub(crate) fn static_ttl(&self, carried: Option<u32>) -> u32 {
        match self.answer_ttl {
            Some(answer_ttl) if !self.fell_back => carried.unwrap_or(answer_ttl),
            _ => 0,
        }
    }

    /// 在这条路线的键下为 `request` 缓存应答 `bytes`，适用于 trail 接受的请求方，给出交出去的那一份：留 `ttl` 秒，但不比
    /// `answer_ttl` 久，为 0 时不写（见 `phases::ttl_to_cache`、[`Self::static_ttl`]）。有 `answer_ttl` 时，比它长的记录
    /// TTL 一律封到它（见 `proto_utils::reply_within_ttls`），不论记录里最短的那个比它短还是长：短 A 记录旁边的长 CNAME、
    /// 没有 SOA 的否定应答带的别名都不例外。交给客户端、等待者的和写进缓存的是同一份，客户端留每条记录的时间都不比缓存长。
    /// 转发拿到的、规则给出的应答都经这里写，都受这个上限
    /// Cache the answer `bytes` for `request` under this route's keys, for the requesters the
    /// trail admits, giving back the copy that goes out: for `ttl` seconds yet no longer than
    /// `answer_ttl`, nothing being cached at 0 (see `phases::ttl_to_cache`,
    /// [`Self::static_ttl`]). With `answer_ttl` given, every record TTL longer than it is
    /// brought down to it (see `proto_utils::reply_within_ttls`), whether the least of the
    /// records' is shorter or longer: a long CNAME next to a short A record, or the aliases of a
    /// negative answer without SOA, are no exception. The client, the waiters and the cache get
    /// the one copy, the client keeping no record longer than the cache does. Answers forwards
    /// fetch and answers the rules give are written here alike, under this bound alike
    pub(crate) fn cache(
        &self,
        engine: &Engine,
        request: &Request<'_>,
        bytes: Bytes,
        rcode: ResponseCode,
        upstream: Option<Arc<str>>,
        ttl: u32,
    ) -> Bytes {
        let (bytes, ttl) = match self.answer_ttl {
            Some(most) => (
                crate::proto_utils::reply_within_ttls(bytes, 0, most),
                ttl.min(most),
            ),
            None => (bytes, ttl),
        };
        if ttl > 0 {
            engine.insert_dns_cache_entry(
                self.keys.slot,
                CacheEntry::from_response(
                    bytes.clone(),
                    rcode,
                    upstream,
                    Arc::clone(request.qname),
                    Arc::clone(&self.key_pipeline),
                    u16::from(request.qtype),
                    u16::from(request.qclass),
                    request.flags,
                    ttl,
                )
                .with_reach(self.trail.clone()),
            );
        }
        bytes
    }

    /// 响应动作还能跳几次：头一次响应阶段的跳转之前是整份 `limit`，之后是那一份剩下的（见 [`Self::response_jumped`]）
    /// How many more jumps the response actions may make: the whole `limit` before the first
    /// response-phase jump, what is left of that budget after it (see [`Self::response_jumped`])
    pub(crate) fn response_jumps_left(&self, limit: usize) -> usize {
        if self.jumped.is_some() {
            self.jumps_left
        } else {
            limit
        }
    }

    /// 响应动作跳走：跳过去以前那次转发的应答就是越过的那个，和 continue 一样；此后的转发照原样发出 `packet`。第一次
    /// 响应阶段的跳转起另算一份次数（`limit`）
    /// A response action jumped away: the answer of the forward before the jump is one passed
    /// over, as on a continue; the forwards from here on send `packet` as it is. The first
    /// response-phase jump starts a budget of its own (`limit`)
    fn response_jumped(
        &mut self,
        packet: Bytes,
        carried: crate::ecs_scope::ForwardEcs,
        limit: usize,
    ) {
        if self.jumped.is_none() {
            self.jumps_left = limit;
        }
        self.jumped = Some((packet, carried));
    }
}

#[cfg(test)]
#[allow(unnameable_test_items)]
mod tests {
    use super::*;
    use crate::config::{Action, GlobalSettings};
    use crate::engine::response::*;
    use crate::engine::rules::*;
    use crate::engine::test_support::{
        self as support, answering_upstream, answering_upstream_after, engine_from,
        engine_with_steps,
    };
    use crate::engine::types::{InflightEntry, KeyedQuestion};
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use rustc_hash::FxHashMap;
    use std::hash::Hasher;
    use std::net::IpAddr;
    use std::str::FromStr;
    use std::sync::Arc;

    fn runtime_with_upstream(upstream: &str) -> RuntimePipelineConfig {
        let raw = serde_json::json!({
            "settings": { "default_upstream": "1.1.1.1:53" },
            "pipelines": [{
                "id": "main",
                "rules": [{
                    "name": "forward",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "forward", "upstream": upstream }]
                }]
            }]
        });
        let config: crate::config::PipelineConfig =
            serde_json::from_value(raw).expect("parse config");
        RuntimePipelineConfig::from_config(config).expect("build runtime config")
    }

    /// 回答检查在 `upstream` 回答以后给出 `ip` 的配置：这样的静态应答才进缓存
    /// A configuration whose answer check gives `ip` once `upstream` answered: such a static
    /// answer is one that is cached
    fn runtime_with_static_ip(upstream: &str, ip: &str) -> RuntimePipelineConfig {
        let raw = serde_json::json!({
            "settings": { "default_upstream": "1.1.1.1:53" },
            "pipelines": [{
                "id": "main",
                "rules": [{
                    "name": "static",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "forward", "upstream": upstream }],
                    "response_actions_on_match": [{ "type": "static_ip_response", "ip": ip }]
                }]
            }]
        });
        let config: crate::config::PipelineConfig =
            serde_json::from_value(raw).expect("parse config");
        RuntimePipelineConfig::from_config(config).expect("build runtime config")
    }

    #[tokio::test]
    async fn reload_changes_cache_keys_only_when_pipeline_configuration_changes() {
        let original = runtime_with_upstream("8.8.8.8:53");
        let engine = Engine::new(original.clone(), "test".to_string()).expect("create engine");
        let original_namespace = engine.state.load().cache_namespace("main");
        let old_key = KeyedQuestion {
            namespace: original_namespace,
            pipeline_id: "main",
            qname: b"example.com",
            qtype: RecordType::A,
            qclass: DNSClass::IN,
            flags: crate::proto_utils::QueryFlags::RECURSIVE,
            requester: RequesterKey::NONE,
            client_ecs: None,
        }
        .slot();
        // A real reply: the cache keeps only replies it can read through to their ECS
        // 真实的应答：缓存只存它能读到 ECS 为止的应答
        let mut reply = Message::new(0, MessageType::Response, OpCode::Query);
        reply.add_query(Query::query(
            Name::from_str("example.com").unwrap(),
            RecordType::A,
        ));
        engine.insert_dns_cache_entry(
            old_key,
            CacheEntry::from_response(
                Bytes::from(reply.to_vec().unwrap()),
                ResponseCode::NoError,
                Some(Arc::from("8.8.8.8:53")),
                "example.com",
                Arc::from("main"),
                u16::from(RecordType::A),
                u16::from(DNSClass::IN),
                crate::proto_utils::QueryFlags::RECURSIVE,
                60,
            ),
        );

        engine.reload(original);
        assert_eq!(
            original_namespace,
            engine.state.load().cache_namespace("main"),
            "an unchanged pipeline should retain its cache namespace"
        );
        assert!(engine.cached(old_key).is_some());

        engine.reload(runtime_with_upstream("8.8.4.4:53"));
        let changed_namespace = engine.state.load().cache_namespace("main");
        assert_ne!(
            original_namespace, changed_namespace,
            "a changed pipeline must stop addressing entries from the old configuration"
        );

        let new_key = KeyedQuestion {
            namespace: changed_namespace,
            pipeline_id: "main",
            qname: b"example.com",
            qtype: RecordType::A,
            qclass: DNSClass::IN,
            flags: crate::proto_utils::QueryFlags::RECURSIVE,
            requester: RequesterKey::NONE,
            client_ecs: None,
        }
        .slot();
        assert_ne!(old_key, new_key);
        assert!(
            engine.cached(new_key).is_none(),
            "the changed pipeline must not address the previous response cache entry"
        );
    }

    #[tokio::test]
    async fn a_request_snapshot_writes_only_into_its_own_namespace_after_reload() {
        let upstream = answering_upstream("192.0.2.9".parse().unwrap(), 300)
            .await
            .address;
        let engine = Engine::new(
            runtime_with_static_ip(&upstream, "192.0.2.1"),
            "test".to_string(),
        )
        .expect("create engine");
        let mut request = Message::new(0xCAFE, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(
            Name::from_str("example.com").unwrap(),
            RecordType::A,
        ));
        let request = request.to_vec().unwrap();
        // 刷新重放的查询算出的槽位 / The slot the query a refresh replays works out to
        let slot_in = |namespace| {
            KeyedQuestion {
                namespace,
                pipeline_id: "main",
                qname: b"example.com",
                qtype: RecordType::A,
                qclass: DNSClass::IN,
                flags: crate::proto_utils::QueryFlags::of(&request),
                requester: RequesterKey::NONE,
                client_ecs: None,
            }
            .slot()
        };
        let old_state = engine.state.load_full();
        let old_key = slot_in(old_state.cache_namespace("main"));

        engine.reload(runtime_with_static_ip(&upstream, "192.0.2.2"));
        let new_key = slot_in(engine.state.load().cache_namespace("main"));

        let response = engine
            .handle_refresh(
                &request,
                "127.0.0.1:53000".parse().unwrap(),
                engine.refresh_of(old_key),
                old_state,
            )
            .await
            .expect("complete request from old snapshot");
        let response = Message::from_bytes(&response).expect("parse response");

        assert!(matches!(
            response.answers.first().map(|record| &record.data),
            Some(RData::A(address)) if address.0 == "192.0.2.1".parse::<std::net::Ipv4Addr>().unwrap()
        ));
        assert!(engine.cached(old_key).is_some());
        assert!(
            engine.cached(new_key).is_none(),
            "work from the old snapshot must not populate the new configuration's namespace"
        );
    }

    /// 刷新照客户端请求的样子把应答写在它这一路的键下，查这个问题的请求就在那里找到它，不论被刷新的条目在哪个槽位。这里
    /// 条目在请求阶段跳转的目标下，而刷新这次没有跳过去。同一份配置快照下两者本来走同一条路，这里把它们分开，验的是兜底：
    /// 刷新只认自己这一路的键，不靠被刷新条目的槽位。以前刷新把槽位改成条目的：应答连同入口 pipeline 的问题落在目标的槽位
    /// 里，查这个问题的请求谁也不去那里找
    /// A refresh writes its answer under the keys of the way it goes, as a client request does,
    /// and a request asking the question finds it there, whichever slot the renewed entry is in.
    /// Here the entry is under the target of a request-phase jump, which the refresh does not
    /// make this time. Under one configuration snapshot the two go the same way; parting them here
    /// checks the fallback: a refresh goes by the keys of its own way alone, not by the renewed
    /// entry's slot. A refresh used to take the entry's slot for its own: the answer, with the
    /// entry pipeline's question, landed in the target's slot, where no request asking that
    /// question looks
    #[tokio::test]
    async fn a_refresh_caches_its_answer_where_its_route_leads() {
        let upstream = answering_upstream("192.0.2.9".parse().unwrap(), 300).await;
        let engine = Engine::new(runtime_with_upstream(&upstream.address), "test".to_string())
            .expect("create engine");
        let request = example_query();
        let slot_of = |pipeline| {
            KeyedQuestion {
                namespace: engine.state.load().cache_namespace(pipeline),
                pipeline_id: pipeline,
                qname: b"example.com",
                qtype: RecordType::A,
                qclass: DNSClass::IN,
                flags: crate::proto_utils::QueryFlags::of(&request),
                requester: RequesterKey::NONE,
                client_ecs: None,
            }
            .slot()
        };
        let renewed = RefreshTarget::new(
            slot_of("target"),
            Arc::from("target"),
            Default::default(),
            std::time::Instant::now(),
        );
        engine
            .handle_refresh(
                &request,
                "127.0.0.1:53000".parse().unwrap(),
                renewed,
                engine.state.load_full(),
            )
            .await
            .expect("refreshed");

        assert!(engine.cached(slot_of("target")).is_none());
        assert!(engine.cached(slot_of("main")).is_some());
        support::ask(&engine, &request, "127.0.0.1:53000".parse().unwrap()).await;
        assert_eq!(
            upstream.queries(),
            1,
            "the request found the refreshed answer"
        );
    }

    fn jump_config(upstream: &str, target_ip: &str) -> RuntimePipelineConfig {
        let raw = serde_json::json!({
            "settings": { "default_upstream": "1.1.1.1:53", "min_ttl": 60 },
            "pipelines": [
                {
                    "id": "main",
                    "rules": [{
                        "name": "forward-and-jump",
                        "matchers": [{ "type": "any" }],
                        "actions": [{ "type": "forward", "upstream": upstream }],
                        "response_matchers": [{ "type": "upstream_equals", "value": upstream }],
                        "response_actions_on_match": [
                            { "type": "jump_to_pipeline", "pipeline": "target" }
                        ]
                    }]
                },
                {
                    "id": "target",
                    "rules": [{
                        "name": "static",
                        "matchers": [{ "type": "any" }],
                        "actions": [{ "type": "static_ip_response", "ip": target_ip }]
                    }]
                }
            ]
        });
        let config: crate::config::PipelineConfig =
            serde_json::from_value(raw).expect("parse config");
        RuntimePipelineConfig::from_config(config).expect("build runtime config")
    }

    /// 快速路径选好 pipeline、转去异步处理的查询，中间赶上热重载也照旧用选出它的那份配置。以前异步路径再取一次当前
    /// 配置：新配置里没有旧配置选的 pipeline，就落到默认转发上，回答来自两份配置都不会去问的上游
    /// A query the fast path selected a pipeline for and passed on to the async path keeps using
    /// the configuration that selected it, a hot reload in between notwithstanding. The async path
    /// used to take the current configuration again: lacking the pipeline the old one selected, it
    /// fell through to the default forward, the answer coming from an upstream neither
    /// configuration would ask
    #[tokio::test]
    async fn a_query_deferred_by_the_fast_path_keeps_its_configuration_through_a_reload() {
        let chosen = answering_upstream("192.0.2.1".parse().unwrap(), 300).await;
        let default = answering_upstream("192.0.2.2".parse().unwrap(), 300).await;
        let config = |pipeline: &str| {
            let raw = serde_json::json!({
                "settings": { "default_upstream": default.address },
                "pipelines": [{ "id": pipeline, "rules": [{
                    "name": "chosen",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "forward", "upstream": chosen.address }]
                }] }]
            });
            let config: crate::config::PipelineConfig =
                serde_json::from_value(raw).expect("parse config");
            RuntimePipelineConfig::from_config(config).expect("build runtime config")
        };
        let engine = Engine::new(config("old"), "test".to_string()).expect("engine");
        let mut request = Message::new(0x5157, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(
            Name::from_str("example.com.").unwrap(),
            RecordType::A,
        ));
        let packet = request.to_vec().unwrap();
        let peer: SocketAddr = "10.0.0.1:53000".parse().unwrap();
        let Some(FastPathResponse::AsyncNeeded(pre_parsed)) =
            engine.handle_packet_fast(&packet, peer)
        else {
            panic!("a miss goes on to the async path");
        };

        engine.reload(config("new"));
        let answer = engine.handle_packet_full(&packet, peer, pre_parsed).await;
        let answer = Message::from_bytes(&answer).expect("parse answer");
        assert!(matches!(
            answer.answers.first().map(|record| &record.data),
            Some(RData::A(address)) if address.0 == "192.0.2.1".parse::<std::net::Ipv4Addr>().unwrap()
        ));
        assert_eq!((chosen.queries(), default.queries()), (1, 0));
    }

    /// 响应跳转执行请求所用配置快照里的目标 pipeline，跳过去拿到的应答缓存在跳转前那个 pipeline 的键下，同样的问题
    /// 再来就从缓存答。以前这条路径上什么都不缓存，用了回答检查跳转的配置（比如结果被污染时改问另一组上游）每次都要把
    /// 两边的上游各问一遍。目标的配置算进入口的缓存命名空间：重载只改了目标，按旧配置缓存的应答也不再用
    /// A response jump runs the target pipeline of the request's configuration snapshot, and
    /// the answer got over there is cached under the key of the pipeline jumped from, the same
    /// question coming again answered from the cache. Nothing on this path used to be cached, a
    /// configuration with an answer check's jump (asking another upstream group when the result
    /// is polluted, say) asking both sides' upstreams every time. The target's configuration goes
    /// into the entry's cache namespace: with a reload changing only the target, answers cached
    /// by the old configuration are no longer used either
    #[tokio::test]
    async fn a_response_jump_runs_its_own_snapshot_and_caches_its_answer() {
        let upstream = answering_upstream(std::net::Ipv4Addr::LOCALHOST, 300).await;
        let engine = Engine::new(
            jump_config(&upstream.address, "192.0.2.1"),
            "test".to_string(),
        )
        .expect("engine");
        let old_state = engine.state.load_full();
        let mut request = Message::new(0xBEEF, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(
            Name::from_str("example.com").unwrap(),
            RecordType::A,
        ));
        let request = request.to_vec().unwrap();
        let peer: SocketAddr = "127.0.0.1:53000".parse().unwrap();
        let answered = |response: Bytes| {
            let response = Message::from_bytes(&response).expect("parse response");
            match response.answers.first().map(|record| &record.data) {
                Some(RData::A(address)) => address.0,
                other => panic!("an A record, not {other:?}"),
            }
        };

        // 重载只改跳转目标：入口 pipeline 的规则没变 / The reload changes only the jump target: the
        // entry pipeline's rules stay as they were
        engine.reload(jump_config(&upstream.address, "192.0.2.2"));
        let pre_parsed = PreParsedData {
            head: engine
                .read_request(&request, peer.ip(), &old_state)
                .expect("a query"),
            state: old_state,
        };
        let response = engine.handle_packet_full(&request, peer, pre_parsed).await;
        // The jump must execute the target pipeline of the request snapshot
        // (192.0.2.1), not the reloaded one (192.0.2.2).
        assert_eq!(
            answered(response),
            "192.0.2.1".parse::<std::net::Ipv4Addr>().unwrap()
        );
        assert_eq!(
            engine.cache.entry_count(),
            1,
            "cached under the entry's key"
        );

        for round in ["miss", "hit"] {
            let response = engine
                .handle_packet(&request, peer)
                .await
                .expect("answered");
            assert_eq!(
                answered(response),
                "192.0.2.2".parse::<std::net::Ipv4Addr>().unwrap(),
                "{round}: the current target's answer"
            );
        }
        assert_eq!(
            upstream.queries(),
            2,
            "the second round came from the cache"
        );
    }

    fn continue_config(
        pipeline_select: serde_json::Value,
        pipelines: serde_json::Value,
    ) -> serde_json::Value {
        continue_config_with_timeout(pipeline_select, pipelines, 100)
    }

    /// The same with `upstream_timeout_ms`, for tests whose upstreams answer slowly on
    /// purpose: 100 ms leaves too little room on a busy machine
    /// 同上，可设 `upstream_timeout_ms`，给上游故意慢答的测试用：100 毫秒在机器忙时余量不够
    fn continue_config_with_timeout(
        pipeline_select: serde_json::Value,
        pipelines: serde_json::Value,
        upstream_timeout_ms: u64,
    ) -> serde_json::Value {
        serde_json::json!({
            "settings": {
                "default_upstream": "127.0.0.1:9",
                "upstream_timeout_ms": upstream_timeout_ms,
                "enable_tcp_fallback": false
            },
            "pipeline_select": pipeline_select,
            "pipelines": pipelines
        })
    }

    fn example_query() -> Vec<u8> {
        let mut request = Message::new(0xBEEF, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(
            Name::from_str("example.com").unwrap(),
            RecordType::A,
        ));
        request.to_vec().unwrap()
    }

    /// 两个按以前的写法（逐字节写进不带密钥的 FxHash）落在同一个槽位、同一个 inflight 键上的不同名字。FxHasher 对每个
    /// 字节算 (h + b) * K mod 2^64，两个等长的名字只在第一个标签上不同时，两个键的差是各字节的差乘上 K 的各次幂之和，
    /// 与前面写入的命名空间和 pipeline 无关。用格基约简找到一组都在 ±25 以内、这个和为 0 的差，换成小写字母就是这两个
    /// 标签。键带了密钥以后它们落在不同的地方（见 `names_made_to_collide_in_an_unkeyed_hash_land_apart`）
    /// Two different names landing on one slot and one inflight key the way keys used to be
    /// made (written byte by byte into the unkeyed FxHash). FxHasher computes (h + b) * K mod
    /// 2^64 for every byte, so for two names of equal length that differ only in their first label
    /// the keys differ by the byte differences times powers of K, summed, whatever namespace and
    /// pipeline were written before. Lattice reduction found differences within ±25 for which
    /// that sum is zero, and lowercase letters spell them as these two labels. With keys keyed
    /// they land apart (see `names_made_to_collide_in_an_unkeyed_hash_land_apart`)
    const COLLIDING_NAMES: [&str; 2] = [
        "abacaacgbafgoaca.example.com",
        "jafaekaaaiaaaaad.example.com",
    ];

    fn query_for(name: &str) -> Vec<u8> {
        let mut request = Message::new(0xBEEF, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
        request.to_vec().unwrap()
    }

    /// The name of the question a reply answers / 应答回答的那个问题的名字
    fn answered_name(reply: &Bytes) -> String {
        let reply = Message::from_bytes(reply).expect("parse");
        reply
            .queries
            .first()
            .expect("a question")
            .name()
            .to_string()
    }

    /// 先问 `COLLIDING_NAMES` 的第一个名字，它还在等上游时问第二个，返回两个应答
    /// Ask the first of `COLLIDING_NAMES`, then the second while the first still waits for its
    /// upstream, and return both replies
    async fn ask_colliding_names(engine: &Engine, clients: [&str; 2]) -> [Bytes; 2] {
        ask_two(engine, COLLIDING_NAMES, clients).await
    }

    /// 和 `COLLIDING_NAMES` 的哪个都不落在同一个键上的名字，对照用：两个请求都问它
    /// A name on no key of `COLLIDING_NAMES`, for the controls: both requests ask it
    const SAME_NAME: &str = "same.example.com";

    /// 先问 `names` 的第一个，它还在等上游时问第二个，返回两个应答
    /// Ask the first of `names`, then the second while the first still waits for its
    /// upstream, and return both replies
    async fn ask_two(engine: &Engine, names: [&str; 2], clients: [&str; 2]) -> [Bytes; 2] {
        let first = async {
            engine
                .handle_packet(&query_for(names[0]), clients[0].parse().unwrap())
                .await
        };
        let second = async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            engine
                .handle_packet(&query_for(names[1]), clients[1].parse().unwrap())
                .await
        };
        let (first, second) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(first, second)
        })
        .await
        .expect("both answer in time");
        [first.expect("an answer"), second.expect("an answer")]
    }

    /// 同 `continue_config_with_timeout`，上游超时 1 秒，默认上游是 `default_upstream`
    /// The same as `continue_config_with_timeout` with a 1 s upstream timeout and
    /// `default_upstream` as the default upstream
    fn config_with_default_upstream(
        pipeline_select: serde_json::Value,
        pipelines: serde_json::Value,
        default_upstream: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "settings": {
                "default_upstream": default_upstream,
                "upstream_timeout_ms": 1000,
                "enable_tcp_fallback": false
            },
            "pipeline_select": pipeline_select,
            "pipelines": pipelines
        })
    }

    /// 把查询发往上游的两种动作：明写的 forward，和发往默认上游、可以复用规则越过的应答的 allow
    /// The two actions that send a query upstream: an explicit forward, and allow, which goes to
    /// the default upstream and may reuse an answer a rule continued past
    fn forwarding_actions(upstream: &str) -> [serde_json::Value; 2] {
        [
            serde_json::json!({ "type": "forward", "upstream": upstream }),
            serde_json::json!({ "type": "allow" }),
        ]
    }

    /// 合并查询只合并问同一个问题的请求。另一个问题的条目落在同一个键上时，请求自己转发，拿到的是自己
    /// 问题的应答，而不是那个条目交出的别的问题的应答。
    /// 转发回来写进缓存的应答，共用请求和配置手里已有的那几份：Pipeline 名、上游的名字，每条应答不再各存一份
    /// Answers cached after a forward share what the request and configuration already hold: the
    /// pipeline's name and the upstream's name, with no copies per answer
    #[tokio::test]
    async fn a_cached_answer_shares_what_the_request_already_holds() {
        let upstream = answering_upstream("192.0.2.20".parse().unwrap(), 300).await;
        let (engine, _steps) = engine_with_steps(config_with_default_upstream(
            serde_json::json!([]),
            serde_json::json!([{ "id": "main", "rules": [{
                "name": "all",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": upstream.address }]
            }] }]),
            &upstream.address,
        ));
        let peer: SocketAddr = "10.0.0.1:53000".parse().unwrap();
        let mut answers = Vec::new();
        for name in ["one.example", "two.example"] {
            let labels: Vec<Vec<u8>> = name.split('.').map(|l| l.as_bytes().to_vec()).collect();
            let query = static_query(7, [1, 0], &labels, 1, 1, (0, &[]));
            engine.handle_packet(&query, peer).await.unwrap();
            let keys = KeyedQuestion {
                namespace: engine.state.load().cache_namespace("main"),
                pipeline_id: "main",
                qname: name.as_bytes(),
                qtype: RecordType::A,
                qclass: DNSClass::IN,
                flags: crate::proto_utils::QueryFlags::RECURSIVE,
                requester: RequesterKey::NONE,
                client_ecs: None,
            }
            .keys();
            answers.push(engine.cached_entries(keys.slot).remove(0));
        }
        let state = engine.state.load();
        let pipeline = state.pipeline.pipeline("main").expect("configured");
        for answer in &answers {
            assert!(Arc::ptr_eq(&answer.pipeline_id, &pipeline.id), "pipeline");
        }
        let names: Vec<_> = answers
            .iter()
            .map(|answer| {
                answer
                    .upstream
                    .clone()
                    .expect("a forward names its upstream")
            })
            .collect();
        assert!(Arc::ptr_eq(&names[0], &names[1]), "upstream");
        assert_eq!(&*names[0], format!("udp:{}", upstream.address));
    }

    /// 要用到请求本身的响应动作（静态回答、拒绝、转发失败后的 SERVFAIL、跳转到静态回答），答的还是客户端问的
    /// 那个问题：只有用不到请求的动作才不解析它
    /// The response actions that use the request itself (a static answer, a refusal, the
    /// SERVFAIL after a failed forward, a jump to a static answer) still answer the question
    /// the client asked: only actions with no use for the request leave it unparsed
    #[tokio::test]
    async fn response_actions_answer_the_question_that_was_asked() {
        let upstream = answering_upstream("192.0.2.20".parse().unwrap(), 300).await;
        let static_rule = serde_json::json!([{
            "name": "fixed",
            "matchers": [{ "type": "any" }],
            "actions": [{ "type": "static_response", "rcode": "NXDOMAIN" }]
        }]);
        for (actions, rcode) in [
            (
                serde_json::json!([{ "type": "static_response", "rcode": "NXDOMAIN" }]),
                ResponseCode::NXDomain,
            ),
            (
                serde_json::json!([{ "type": "static_ip_response", "ip": "192.0.2.99" }]),
                ResponseCode::NoError,
            ),
            (
                serde_json::json!([{ "type": "static_cname_response", "target": "t.example" }]),
                ResponseCode::NoError,
            ),
            (
                serde_json::json!([{ "type": "deny" }]),
                ResponseCode::Refused,
            ),
            (
                serde_json::json!([{
                    "type": "forward",
                    "upstream": "127.0.0.1:9",
                    "transport": "tcp"
                }]),
                ResponseCode::ServFail,
            ),
            (
                serde_json::json!([{ "type": "jump_to_pipeline", "pipeline": "other" }]),
                ResponseCode::NXDomain,
            ),
        ] {
            let (engine, _steps) = engine_with_steps(config_with_default_upstream(
                serde_json::json!([]),
                serde_json::json!([
                    { "id": "main", "rules": [{
                        "name": "all",
                        "matchers": [{ "type": "any" }],
                        "actions": [{ "type": "forward", "upstream": upstream.address }],
                        "response_matchers": [{ "type": "response_rcode", "value": "NOERROR" }],
                        "response_actions_on_match": actions
                    }] },
                    { "id": "other", "rules": static_rule }
                ]),
                &upstream.address,
            ));
            let labels = [b"asked".to_vec(), b"example".to_vec()];
            let query = static_query(0x1234, [1, 0], &labels, 1, 1, (0, &[]));
            let reply = engine
                .handle_packet(&query, "10.0.0.1:53000".parse().unwrap())
                .await
                .unwrap();
            let reply = Message::from_bytes(&reply).unwrap();
            assert_eq!(reply.metadata.response_code, rcode, "{actions}");
            assert_eq!(reply.metadata.id, 0x1234, "{actions}");
            assert_eq!(reply.queries.len(), 1, "{actions}");
            assert_eq!(
                reply.queries[0].name().to_ascii(),
                "asked.example.",
                "{actions}"
            );
            assert_eq!(reply.queries[0].query_type(), RecordType::A, "{actions}");
        }
    }

    /// 请求方能凑出一串落在同一个槽位、同一个 inflight 键上的名字，挤掉别人存着的应答，排长 inflight 表的一个桶。键带了
    /// 密钥，以前撞在一起的名字现在落在不同的地方
    /// A requester used to be able to make up a run of names landing on one slot and one
    /// inflight key, pushing out the answers others had cached and piling up one bucket of the
    /// inflight map. With keys keyed, names that used to collide land apart
    #[test]
    fn names_made_to_collide_in_an_unkeyed_hash_land_apart() {
        let [first, second] = COLLIDING_NAMES.map(|name| {
            KeyedQuestion {
                namespace: 0,
                pipeline_id: "main",
                qname: name.as_bytes(),
                qtype: RecordType::A,
                qclass: DNSClass::IN,
                flags: crate::proto_utils::QueryFlags::RECURSIVE,
                requester: RequesterKey::NONE,
                client_ecs: None,
            }
            .keys()
        });
        assert_ne!(first.slot, second.slot);
        assert_ne!(first.inflight, second.inflight);
    }

    /// 合并只合并问同一个问题的请求。另一个问题的条目落在同一个键上时（键只是哈希，见 `KeyedQuestion`；带了密钥，两个
    /// 问题撞上只能是碰巧，这里直接把那个条目放上去），请求自己去问，拿到自己问题的应答，不挂在那个条目上，也什么都不交给它
    /// Merging only merges requests asking the same question. When another question's entry lands
    /// on the same key (the key is only a hash, see `KeyedQuestion`; keyed, two questions
    /// collide by chance alone, and the entry is put there directly here), the request forwards
    /// by itself and gets the answer to its own question, joining that entry and handing it
    /// nothing.
    #[tokio::test]
    async fn a_request_never_takes_another_questions_answer_from_a_shared_key() {
        let upstream = answering_upstream("192.0.2.20".parse().unwrap(), 300).await;
        let [other, asked] = COLLIDING_NAMES;
        for action in forwarding_actions(&upstream.address) {
            let (engine, steps) = engine_with_steps(config_with_default_upstream(
                serde_json::json!([]),
                serde_json::json!([{ "id": "main", "rules": [{
                    "name": "all",
                    "matchers": [{ "type": "any" }],
                    "actions": [action]
                }] }]),
                &upstream.address,
            ));
            let namespace = engine.state.load().cache_namespace("main");
            let question = |name: &'static str| KeyedQuestion {
                flags: crate::proto_utils::QueryFlags::of(&query_for(name)),
                namespace,
                pipeline_id: "main",
                qname: name.as_bytes(),
                qtype: RecordType::A,
                qclass: DNSClass::IN,
                requester: RequesterKey::NONE,
                client_ecs: None,
            };
            // 另一个问题的条目，放在这个问题的 inflight 键下 / Another question's entry under this
            // question's inflight key
            let (owner, waiting) = tokio::sync::watch::channel(None);
            engine.inflight.insert(
                question(asked).keys().inflight,
                InflightEntry::new(&question(other)).with_channel(owner),
            );

            let before = upstream.queries();
            let reply = engine
                .handle_packet(&query_for(asked), "10.0.0.1:53000".parse().unwrap())
                .await
                .expect("an answer");
            assert_eq!(answered_name(&reply), format!("{asked}."), "{action}");
            assert_eq!(
                upstream.queries() - before,
                1,
                "{action}: asked upstream itself"
            );
            assert!(!steps.joined("10.0.0.1:53000"), "{action}");
            assert!(
                !waiting
                    .has_changed()
                    .expect("the entry's owner is still there"),
                "{action}: nothing handed to the other question's entry"
            );
        }
    }

    /// 响应跳转路径上也一样：两个请求从不同的 pipeline 跳进同一个 pipeline，后来的请求不拿前一个的应答，
    /// 各自去问；同一个入口的两个请求问同一个问题时，第二个等在第一个跳转之前登记的条目上。
    /// The same on the response-jump path: two requests jump into one pipeline from different
    /// pipelines and the later one takes nothing of the earlier one's answer, each asking itself;
    /// two requests of one entry pipeline asking one question, the second waits on the entry the
    /// first registered before its jump.
    #[tokio::test]
    async fn a_request_on_the_jump_path_never_takes_another_questions_answer() {
        let pre = answering_upstream("192.0.2.10".parse().unwrap(), 300)
            .await
            .address;
        let slow = answering_upstream_after(
            "192.0.2.20".parse().unwrap(),
            300,
            Duration::from_millis(200),
        )
        .await;
        let entry = |id: &str| {
            serde_json::json!({ "id": id, "rules": [{
                "name": "r",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": pre }],
                "response_matchers": [{ "type": "upstream_equals", "value": pre }],
                "response_actions_on_match": [{ "type": "jump_to_pipeline", "pipeline": "other" }]
            }] })
        };
        for action in forwarding_actions(&slow.address) {
            let (engine, steps) = engine_with_steps(config_with_default_upstream(
                serde_json::json!([
                    { "pipeline": "a", "matchers": [{ "type": "client_ip", "cidr": "10.0.0.1/32" }] },
                    { "pipeline": "b", "matchers": [{ "type": "client_ip", "cidr": "10.0.0.2/32" }] }
                ]),
                serde_json::json!([
                    entry("a"),
                    entry("b"),
                    { "id": "other", "rules": [{
                        "name": "all",
                        "matchers": [{ "type": "any" }],
                        "actions": [action]
                    }] }
                ]),
                &slow.address,
            ));

            let before = slow.queries();
            let [_, second] =
                ask_colliding_names(&engine, ["10.0.0.1:53000", "10.0.0.2:53000"]).await;
            assert_eq!(
                answered_name(&second),
                format!("{}.", COLLIDING_NAMES[1]),
                "{action}"
            );
            assert_eq!(
                slow.queries() - before,
                2,
                "{action}: each name asked upstream itself"
            );
            // 第二个问题自己的转发发出时，第一个的转发还在等慢上游：它持有跳转之前登记的条目，自己去问，没有挂上去
            // The second question's own forward went out while the first's still waited on the
            // slow upstream: holding the entry it registered before its jump, it asked itself
            // rather than join
            assert!(
                steps.forwarded_while_waiting(
                    ("10.0.0.1:53000", &slow.address),
                    ("10.0.0.2:53000", &slow.address)
                ),
                "{action}: {:?}",
                steps.taken()
            );
            assert!(!steps.joined("10.0.0.2:53000"), "{action}");

            // 对照：同一个入口的两个请求问同一个问题、时序一样，第二个挂在第一个的条目上，拿到第一个跳过去以后的
            // 应答，上游只问一次
            // Control: two requests of one entry pipeline asking the same question with the same
            // timing; the second joins the first one's entry and takes the answer it got after its
            // jump, and the upstream is asked once
            let before = slow.queries();
            let [_, second] = ask_two(
                &engine,
                [SAME_NAME; 2],
                ["10.0.0.1:53002", "10.0.0.1:53003"],
            )
            .await;
            assert_eq!(answered_name(&second), format!("{SAME_NAME}."), "{action}");
            assert!(
                steps.joined("10.0.0.1:53003"),
                "{action}: {:?}",
                steps.taken()
            );
            assert_eq!(slow.queries() - before, 1, "{action}: asked once");
        }
    }

    /// 应答里的第一个 A 记录，请求必须得到了应答 / The first A record in the reply a request
    /// must have got
    fn first_a_record(response: Result<Bytes, UnreadableQuery>) -> Option<std::net::Ipv4Addr> {
        support::first_a(&response.expect("answer"))
    }

    /// 同一个 example.com 查询从 `clients` 同时发出：第一个登记 inflight，第二个等在
    /// 它上面。按顺序返回两个应答的 A 记录（没有就是 None），并断言没有留下 inflight 条目。
    /// The same example.com query sent from `clients` at once: the first registers
    /// in inflight and the second waits on it. Returns both answers' A records in
    /// order (None without one) and asserts that no inflight entry is left behind.
    async fn ask_at_once(engine: &Engine, clients: [&str; 2]) -> [Option<std::net::Ipv4Addr>; 2] {
        let packet = example_query();
        let [first, second] = clients.map(|client| client.parse::<SocketAddr>().unwrap());
        // 修复前会挂到监听器超时；5 秒只用来区分「挂住」
        // Before the fix these hung until the listener timeout; 5 s only tells a hang apart
        let (first, second) = tokio::time::timeout(Duration::from_secs(5), async {
            let mut leader = std::pin::pin!(engine.handle_packet(&packet, first));
            // 先让第一个请求跑到等上游为止：它已登记条目，由它领头
            // Run the first request until it waits on its upstream: it has registered
            // its entry, so it leads
            let polled =
                std::future::poll_fn(|cx| std::task::Poll::Ready(leader.as_mut().poll(cx))).await;
            assert!(
                polled.is_pending() && engine.inflight.len() == 1,
                "the first request must lead"
            );
            tokio::join!(leader, engine.handle_packet(&packet, second))
        })
        .await
        .expect("a request after a continue must not hang");
        assert!(
            engine.inflight.is_empty(),
            "a finished request must not leave its inflight entry behind"
        );
        [first_a_record(first), first_a_record(second)]
    }

    const ONE_CLIENT: [&str; 2] = ["127.0.0.1:53000"; 2];

    /// 先 continue 到下一条规则的配置：`first` 转发到 `first_upstream`，失败后 continue，
    /// 下一条是 `next`。
    /// A configuration that continues on a miss: `first` forwards to
    /// `first_upstream` and continues when it fails; the next rule is `next`.
    fn continue_on_miss_to(first_upstream: &str, next: serde_json::Value) -> serde_json::Value {
        continue_config(
            serde_json::json!([]),
            serde_json::json!([{
                "id": "main",
                "rules": [
                    {
                        "name": "first",
                        "matchers": [{ "type": "any" }],
                        "actions": [{ "type": "forward", "upstream": first_upstream }],
                        "response_actions_on_miss": [{ "type": "continue" }]
                    },
                    next
                ]
            }]),
        )
    }

    /// 同一份配置下，一个请求单独发出和两个请求同时发出，`first` 的死上游各收到多少
    /// 数据包。两者相等说明等待者没有自己再转发一遍。
    /// Datagrams the dead `first` upstream receives for one request alone and for
    /// two at once under the same configuration. Equal counts show the waiting
    /// request did not forward again itself.
    async fn datagrams_alone_and_at_once(
        next: serde_json::Value,
    ) -> (usize, usize, [Option<std::net::Ipv4Addr>; 2]) {
        let alone = support::upstream(|_| Vec::new()).await;
        let engine = engine_from(continue_on_miss_to(&alone.address, next.clone()));
        tokio::time::timeout(
            Duration::from_secs(5),
            engine.handle_packet(&example_query(), ONE_CLIENT[0].parse().unwrap()),
        )
        .await
        .expect("a request after a continue must not hang")
        .expect("answer");

        let silent = support::upstream(|_| Vec::new()).await;
        let engine = engine_from(continue_on_miss_to(&silent.address, next));
        let answers = ask_at_once(&engine, ONE_CLIENT).await;
        (alone.queries(), silent.queries(), answers)
    }

    /// on_miss 里的 continue 要把请求交给下一条规则。以前这里卸掉清理守卫，条目留在
    /// 表里却没人持有：下一条规则以相同 dedupe_hash 转发时等的正是这一条，请求和等在
    /// 它上面的请求一起挂到监听器超时。现在条目由请求一直持有，等待者拿到下一条规则
    /// 的应答，不会自己再转发一遍。
    /// A continue in response_actions_on_miss must hand the request to the next
    /// rule. The guard used to be defused here, leaving the entry behind with
    /// nobody holding it: the next rule's Forward, under the same dedupe_hash,
    /// waited on that very entry, and the request hung until the listener timeout
    /// along with every request waiting on it. Now the request keeps holding the
    /// entry, and waiters get the next rule's answer without forwarding again.
    #[tokio::test]
    async fn a_continue_on_miss_hands_the_request_to_the_next_rule() {
        let answer = "192.0.2.20".parse().unwrap();
        let answering = answering_upstream(answer, 300).await.address;
        let (alone, at_once, answers) = datagrams_alone_and_at_once(serde_json::json!({
            "name": "next",
            "matchers": [{ "type": "any" }],
            "actions": [{ "type": "forward", "upstream": answering }]
        }))
        .await;

        assert_eq!(answers, [Some(answer); 2]);
        assert_eq!(
            at_once, alone,
            "the waiting request must get the answer, not forward again"
        );
    }

    /// continue 之后以静态应答结束时，等待者拿到同一个应答，不会自己再转发。
    /// When a continue ends on a static answer, waiters get that same answer
    /// without forwarding again.
    #[tokio::test]
    async fn waiters_get_a_static_answer_reached_after_a_continue() {
        let (alone, at_once, answers) = datagrams_alone_and_at_once(serde_json::json!({
            "name": "static",
            "matchers": [{ "type": "any" }],
            "actions": [{ "type": "static_ip_response", "ip": "192.0.2.30" }]
        }))
        .await;

        assert_eq!(answers, [Some("192.0.2.30".parse().unwrap()); 2]);
        assert_eq!(
            at_once, alone,
            "the waiting request must get the answer, not forward again"
        );
    }

    /// continue 之后下一条规则也失败：两个请求都拿到 SERVFAIL，不挂，也不留下条目。
    /// When the next rule after a continue fails too, both requests get SERVFAIL,
    /// neither hangs, and no entry is left behind.
    #[tokio::test]
    async fn a_failure_after_a_continue_answers_every_request() {
        let silent = support::upstream(|_| Vec::new()).await.address;
        let engine = engine_from(continue_on_miss_to(
            &silent,
            serde_json::json!({
                "name": "next",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": silent }]
            }),
        ));

        assert_eq!(ask_at_once(&engine, ONE_CLIENT).await, [None; 2]);
    }

    /// `check` 转发到 `checked`，应答来自它就 continue；`then` 接在后面。
    /// `check` forwards to `checked` and continues when the answer comes from it;
    /// `then` follows.
    fn continue_on_match_rules(checked: &str, then: serde_json::Value) -> serde_json::Value {
        let mut rules = vec![serde_json::json!({
            "name": "check",
            "matchers": [{ "type": "any" }],
            "actions": [{ "type": "forward", "upstream": checked }],
            "response_matchers": [{ "type": "upstream_equals", "value": checked }],
            "response_actions_on_match": [{ "type": "continue" }]
        })];
        rules.extend(then.as_array().expect("rules").iter().cloned());
        serde_json::Value::Array(rules)
    }

    /// on_match 里的 continue：规则越过了第一个上游的应答，等待者也必须拿到最终
    /// 应答。以前它们拿到的是被越过的那个，例如防污染配置里被判为污染的应答。
    /// A continue in response_actions_on_match: the rule continued past the first
    /// upstream's answer, so waiters must get the final answer too. They used to
    /// get the one continued past, such as an answer judged poisoned.
    #[tokio::test]
    async fn waiters_get_the_final_answer_after_a_continue_on_match() {
        let checked = answering_upstream("192.0.2.10".parse().unwrap(), 300)
            .await
            .address;
        let answer = "192.0.2.20".parse().unwrap();
        let answering = answering_upstream(answer, 300).await.address;
        let engine = engine_from(continue_config(
            serde_json::json!([]),
            serde_json::json!([{
                "id": "main",
                "rules": continue_on_match_rules(&checked, serde_json::json!([{
                    "name": "next",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "forward", "upstream": answering }]
                }]))
            }]),
        ));

        assert_eq!(ask_at_once(&engine, ONE_CLIENT).await, [Some(answer); 2]);
    }

    /// 按客户端匹配的 pipeline 在 continue 之后给出的静态应答只属于那个客户端（例如
    /// 只对某台设备屏蔽），不能交给等在它上面的另一个客户端。
    /// A static answer a client-matching pipeline gives after a continue belongs to
    /// that client alone (such as blocking one device) and must not reach another
    /// client waiting on it.
    #[tokio::test]
    async fn a_client_specific_static_answer_is_not_handed_to_another_client() {
        let checked = answering_upstream("192.0.2.10".parse().unwrap(), 300)
            .await
            .address;
        let answer = "192.0.2.20".parse().unwrap();
        let answering = answering_upstream(answer, 300).await.address;
        let engine = engine_from(continue_config(
            serde_json::json!([]),
            serde_json::json!([{
                "id": "main",
                "rules": continue_on_match_rules(&checked, serde_json::json!([
                    {
                        "name": "block",
                        "matchers": [{ "type": "client_ip", "cidr": "10.0.0.1/32" }],
                        "actions": [{ "type": "static_ip_response", "ip": "0.0.0.0" }]
                    },
                    {
                        "name": "next",
                        "matchers": [{ "type": "any" }],
                        "actions": [{ "type": "forward", "upstream": answering }]
                    }
                ]))
            }]),
        ));

        let blocked = std::net::Ipv4Addr::UNSPECIFIED;
        assert_eq!(
            ask_at_once(&engine, ["10.0.0.1:53000", "10.0.0.2:53000"]).await,
            [Some(blocked), Some(answer)]
        );
    }

    /// 只把 10.0.0.1 送进 `device` pipeline 的规则。
    /// A rule that sends 10.0.0.1 alone to the `device` pipeline.
    fn to_device() -> serde_json::Value {
        serde_json::json!({
            "name": "device",
            "matchers": [{ "type": "client_ip", "cidr": "10.0.0.1/32" }],
            "actions": [{ "type": "jump_to_pipeline", "pipeline": "device" }]
        })
    }

    /// `id` pipeline，只有一条匹配一切的规则。
    /// The `id` pipeline with one rule that matches everything.
    fn pipeline_of(
        id: &str,
        actions: serde_json::Value,
        extra: serde_json::Value,
    ) -> serde_json::Value {
        let mut rule =
            serde_json::json!({ "name": id, "matchers": [{ "type": "any" }], "actions": actions });
        if let (Some(rule), Some(extra)) = (rule.as_object_mut(), extra.as_object()) {
            rule.extend(extra.clone());
        }
        serde_json::json!({ "id": id, "rules": [rule] })
    }

    /// continue 之后，只给 10.0.0.1 的应答（这里是 0.0.0.0）可能经由几条路径产生：
    /// 同一 pipeline 里的客户端规则跳到静态应答或转发，跳进带客户端规则的 pipeline，
    /// 或者响应跳转（应答之后或失败之后）进入那样的 pipeline。无论哪一条，等在它上面
    /// 的 10.0.0.2 都必须拿到自己的应答。
    /// After a continue, an answer meant for 10.0.0.1 alone (0.0.0.0 here) can come
    /// from several paths: a client rule in the same pipeline jumping to a static
    /// answer or to a forward, a jump into a pipeline with a client rule, or a
    /// response jump (after an answer or after a failure) into one. Whichever it
    /// is, 10.0.0.2 waiting on it must get its own answer.
    #[tokio::test]
    async fn a_client_specific_answer_after_a_continue_is_not_handed_to_another_client() {
        let checked = answering_upstream("192.0.2.10".parse().unwrap(), 300)
            .await
            .address;
        let relay = answering_upstream("192.0.2.40".parse().unwrap(), 300)
            .await
            .address;
        let sinkhole = answering_upstream(std::net::Ipv4Addr::UNSPECIFIED, 300)
            .await
            .address;
        let silent = support::upstream(|_| Vec::new()).await.address;
        let answer = "192.0.2.20".parse().unwrap();
        let answering = answering_upstream(answer, 300).await.address;

        let next = serde_json::json!({
            "name": "next",
            "matchers": [{ "type": "any" }],
            "actions": [{ "type": "forward", "upstream": answering }]
        });
        let static_device = pipeline_of(
            "device",
            serde_json::json!([{ "type": "static_ip_response", "ip": "0.0.0.0" }]),
            serde_json::json!({}),
        );
        let split = serde_json::json!({ "id": "split", "rules": [to_device(), next.clone()] });
        let into_split = |actions: serde_json::Value, extra: serde_json::Value| {
            let mut rule = pipeline_of("into-split", actions, extra)["rules"][0].clone();
            rule["name"] = serde_json::json!("into-split");
            continue_on_match_rules(&checked, serde_json::json!([rule]))
        };
        let jump_to_split =
            serde_json::json!([{ "type": "jump_to_pipeline", "pipeline": "split" }]);

        let paths = [
            (
                "a client rule in the same pipeline, then a static answer",
                serde_json::json!([
                    { "id": "main", "rules": continue_on_match_rules(&checked, serde_json::json!([to_device(), next.clone()])) },
                    static_device.clone()
                ]),
            ),
            (
                "a client rule in the same pipeline, then a forward",
                serde_json::json!([
                    { "id": "main", "rules": continue_on_match_rules(&checked, serde_json::json!([to_device(), next.clone()])) },
                    pipeline_of("device", serde_json::json!([{ "type": "forward", "upstream": sinkhole }]), serde_json::json!({}))
                ]),
            ),
            (
                "a jump into a pipeline with a client rule",
                serde_json::json!([
                    { "id": "main", "rules": into_split(jump_to_split.clone(), serde_json::json!({})) },
                    split.clone(),
                    static_device.clone()
                ]),
            ),
            (
                "a response jump into a pipeline with a client rule",
                serde_json::json!([
                    { "id": "main", "rules": into_split(
                        serde_json::json!([{ "type": "forward", "upstream": relay }]),
                        serde_json::json!({
                            "response_matchers": [{ "type": "upstream_equals", "value": relay }],
                            "response_actions_on_match": jump_to_split
                        }),
                    ) },
                    split.clone(),
                    static_device.clone()
                ]),
            ),
            (
                "a response jump on a failure into a pipeline with a client rule",
                serde_json::json!([
                    { "id": "main", "rules": into_split(
                        serde_json::json!([{ "type": "forward", "upstream": silent }]),
                        serde_json::json!({ "response_actions_on_miss": jump_to_split }),
                    ) },
                    split.clone(),
                    static_device.clone()
                ]),
            ),
        ];
        let mut handed_over = Vec::new();
        for (path, pipelines) in paths {
            let engine = engine_from(continue_config(serde_json::json!([]), pipelines));
            let answers = ask_at_once(&engine, ["10.0.0.1:53000", "10.0.0.2:53000"]).await;
            if answers != [Some(std::net::Ipv4Addr::UNSPECIFIED), Some(answer)] {
                handed_over.push((path, answers));
            }
        }
        assert!(handed_over.is_empty(), "{handed_over:#?}");
    }

    /// 两个客户端各进各的 pipeline，两边都在 continue 之后跳进对方。持有条目的请求如果
    /// 还会去等别人，两个请求就各自持有对方在等的条目，互相等下去。两边一直来回跳，
    /// 直到跳转上限给出 SERVFAIL。规则不看客户端，所以两个请求的条目落在同一个键上；
    /// 规则缓存则按客户端分开（开着后台刷新时就是这样），免得 continue 之后缓存下来的
    /// 决策把另一个请求直接送走。
    /// Two clients enter a pipeline each, and both pipelines continue and then jump
    /// into the other. If a request holding an entry still waited on others, each
    /// would hold what the other waits on, and both would wait on. They jump back
    /// and forth until the jump limit answers SERVFAIL. The rules do not look at
    /// the client, so both requests' entries share keys, while the rule cache keys
    /// by client (as it does with background refresh on), so that a decision cached
    /// after a continue cannot send the other request on without forwarding.
    #[tokio::test]
    async fn requests_holding_entries_never_wait_on_each_other() {
        let checked = answering_upstream("192.0.2.10".parse().unwrap(), 300)
            .await
            .address;
        let pipeline = |id: &str, other: &str| {
            serde_json::json!({
                "id": id,
                "rules": continue_on_match_rules(&checked, serde_json::json!([{
                    "name": "cross",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "jump_to_pipeline", "pipeline": other }]
                }]))
            })
        };
        let raw = serde_json::json!({
            "settings": {
                "default_upstream": "127.0.0.1:9",
                "upstream_timeout_ms": 100,
                "enable_tcp_fallback": false,
                "cache_background_refresh": true
            },
            "pipeline_select": [
                { "pipeline": "p1", "matchers": [{ "type": "client_ip", "cidr": "10.0.0.1/32" }] },
                { "pipeline": "p2", "matchers": [{ "type": "client_ip", "cidr": "10.0.0.2/32" }] }
            ],
            "pipelines": [pipeline("p1", "p2"), pipeline("p2", "p1")]
        });
        let engine = engine_from(raw);

        assert_eq!(
            ask_at_once(&engine, ["10.0.0.1:53000", "10.0.0.2:53000"]).await,
            [None; 2]
        );
    }

    /// 两个请求同时问，后到的等在先到的那个跳转之前登记的条目上；先到的经响应跳转进入 `shared`，那里的
    /// 规则 continue 越过了 `checked` 的应答。等待者必须拿到最终应答，而不是被越过的那个。
    /// Two requests ask at once, the later one waiting on the entry the earlier one registered
    /// before its jump; the earlier one enters `shared` through a response jump, where a rule
    /// continues past `checked`'s answer. The waiter must get the final answer, not the one
    /// continued past.
    #[tokio::test]
    async fn a_waiter_on_a_jump_path_does_not_get_an_answer_continued_past() {
        let entry = answering_upstream("192.0.2.50".parse().unwrap(), 300)
            .await
            .address;
        // 慢一点，保证后到的请求到达时先到的还在等它。两个请求先各自问 `entry`，谁先拿到回答不定，所以谁先到
        // `checked` 也不定
        // Slow, so the later request arrives while the earlier one still waits on it. Each
        // first asks `entry`, and which gets its answer first may go either way, so either may
        // reach `checked` first
        let checked = answering_upstream_after(
            "192.0.2.10".parse().unwrap(),
            300,
            Duration::from_millis(200),
        )
        .await
        .address;
        let answer = "192.0.2.20".parse().unwrap();
        let answering = answering_upstream(answer, 300).await.address;
        let enter = |id: &str| {
            pipeline_of(
                id,
                serde_json::json!([{ "type": "forward", "upstream": entry }]),
                serde_json::json!({
                    "response_matchers": [{ "type": "upstream_equals", "value": entry }],
                    "response_actions_on_match": [{ "type": "jump_to_pipeline", "pipeline": "shared" }]
                }),
            )
        };
        let config = |shared_rules: serde_json::Value| {
            continue_config_with_timeout(
                serde_json::json!([
                    { "pipeline": "p1", "matchers": [{ "type": "client_ip", "cidr": "10.0.0.1/32" }] },
                    { "pipeline": "p2", "matchers": [{ "type": "client_ip", "cidr": "10.0.0.2/32" }] }
                ]),
                serde_json::json!([
                    enter("p1"),
                    enter("p2"),
                    { "id": "shared", "rules": shared_rules }
                ]),
                1000,
            )
        };
        let (engine, steps) = engine_with_steps(config(continue_on_match_rules(
            &checked,
            serde_json::json!([{
                "name": "next",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": answering }]
            }]),
        )));

        // 两个请求从同一个入口进来 / Both requests come in through one entry pipeline
        let clients = ["10.0.0.1:53000", "10.0.0.1:53001"];
        assert_eq!(ask_at_once(&engine, clients).await, [Some(answer); 2]);
        assert!(
            clients.iter().any(|client| steps.joined(client)),
            "{:?}",
            steps.taken()
        );

        // 对照：shared 的规则不越过应答，同样两个请求，后到的挂在先到的条目上，拿到 `checked` 的应答
        // Control: the rule in shared does not continue past the answer; with the same two
        // requests the later one joins the earlier one's entry and takes `checked`'s answer
        let (engine, steps) = engine_with_steps(config(serde_json::json!([{
            "name": "checked",
            "matchers": [{ "type": "any" }],
            "actions": [{ "type": "forward", "upstream": checked }]
        }])));
        assert_eq!(
            ask_at_once(&engine, clients).await,
            [Some("192.0.2.10".parse().unwrap()); 2]
        );
        assert!(
            clients.iter().any(|client| steps.joined(client)),
            "{:?}",
            steps.taken()
        );
    }

    /// 后台刷新不登记 inflight 条目，也就不能把自己的应答交给别人登记的条目：刷新不运行
    /// 响应动作，它的应答可能正是规则会越过的那一个。
    /// A background refresh registers no inflight entry, so it must not hand its
    /// answer to an entry another request registered: a refresh runs no response
    /// actions, and its answer may be the one a rule would continue past.
    #[tokio::test]
    async fn a_background_refresh_hands_nothing_to_an_entry_it_did_not_register() {
        let answering = answering_upstream("192.0.2.20".parse().unwrap(), 300)
            .await
            .address;
        let engine = engine_from(continue_config(
            serde_json::json!([]),
            serde_json::json!([{ "id": "main", "rules": [{
                "name": "next",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": answering }]
            }] }]),
        ));
        let question = KeyedQuestion {
            flags: crate::proto_utils::QueryFlags::RECURSIVE,
            namespace: engine.state.load().cache_namespace("main"),
            pipeline_id: "main",
            qname: b"example.com",
            qtype: RecordType::A,
            qclass: DNSClass::IN,
            requester: RequesterKey::NONE,
            client_ecs: None,
        };
        let keys = question.keys();
        let key = keys.slot;
        // 另一个请求在刷新所用的 inflight 键下登记的条目 / Another request's entry under the refresh's inflight key
        let (owner, waiter) = tokio::sync::watch::channel(None);
        engine.inflight.insert(
            keys.inflight,
            InflightEntry::new(&question).with_channel(owner),
        );

        let refreshed = tokio::time::timeout(
            Duration::from_secs(5),
            engine.handle_refresh(
                &example_query(),
                "10.0.0.1:53000".parse().unwrap(),
                engine.refresh_of(key),
                engine.state.load_full(),
            ),
        )
        .await
        .expect("the refresh finishes");
        assert!(refreshed.is_ok());
        assert!(
            !waiter
                .has_changed()
                .expect("the entry's owner is still there"),
            "the refresh must not hand its answer to another request's entry"
        );
        assert!(engine.inflight.contains_key(&keys.inflight));
    }

    /// continue 之后还能跳几次，取决于请求一路怎么来的，键里没有这一项。经过两次跳转才到
    /// `r` 的请求先用完了次数；直接进入 `r`、等在它上面的请求还有余量，不能拿到它的
    /// SERVFAIL。
    /// How many jumps a request has left after a continue depends on the way it
    /// came, which no key carries. One that reached `r` through two jumps runs out
    /// first; one that entered `r` directly and waits on it has jumps to spare
    /// and must not get its SERVFAIL.
    #[tokio::test]
    async fn a_waiter_with_jumps_to_spare_does_not_take_the_jump_limit() {
        let checked = answering_upstream_after(
            "192.0.2.10".parse().unwrap(),
            300,
            Duration::from_millis(50),
        )
        .await
        .address;
        let answer = "192.0.2.20".parse().unwrap();
        let answering = answering_upstream(answer, 300).await.address;
        let jump = |name: &str, target: &str| {
            serde_json::json!({
                "name": name,
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "jump_to_pipeline", "pipeline": target }]
            })
        };
        let raw = |r_rules: serde_json::Value| {
            serde_json::json!({
                "settings": {
                    "default_upstream": "127.0.0.1:9",
                    "upstream_timeout_ms": 1000,
                    "enable_tcp_fallback": false,
                    "response_jump_limit": 3
                },
                "pipeline_select": [
                    { "pipeline": "a1", "matchers": [{ "type": "client_ip", "cidr": "10.0.0.1/32" }] },
                    { "pipeline": "r", "matchers": [{ "type": "client_ip", "cidr": "10.0.0.2/32" }] }
                ],
                "pipelines": [
                    { "id": "a1", "rules": [jump("a1", "a2")] },
                    { "id": "a2", "rules": [jump("a2", "r")] },
                    { "id": "r", "rules": r_rules },
                    { "id": "t", "rules": [jump("to-u", "u")] },
                    { "id": "u", "rules": [{
                        "name": "next",
                        "matchers": [{ "type": "any" }],
                        "actions": [{ "type": "forward", "upstream": answering }]
                    }] }
                ]
            })
        };
        let (engine, steps) = engine_with_steps(raw(continue_on_match_rules(
            &checked,
            serde_json::json!([jump("to-t", "t")]),
        )));

        assert_eq!(
            ask_at_once(&engine, ["10.0.0.1:53000", "10.0.0.2:53000"]).await,
            [None, Some(answer)]
        );
        // 第二个请求走到 `checked` 那一步时，第一个在那里的转发还在等：它等在第一个的条目上；第一个用完了跳转次数，
        // 条目放掉以后，它才自己去问，没有挂上去拿应答
        // When the second request got to the forward to `checked`, the first one's forward there
        // still waited: it waited on the first one's entry, and once the first ran out of jumps,
        // letting the entry go, it asked itself rather than take an answer from it
        assert!(
            steps.waited_on("10.0.0.1:53000", &checked, "10.0.0.2:53000"),
            "{:?}",
            steps.taken()
        );
        assert!(!steps.joined("10.0.0.2:53000"));

        // 对照：r 的规则不越过应答，第一个也就用不完跳转次数；同样两个请求，第二个挂在第一个的条目上，
        // 拿到 `checked` 的应答
        // Control: r's rule does not continue past the answer, so the first does not run out of
        // jumps either; with the same two requests the second joins the first one's entry and
        // takes `checked`'s answer
        let (engine, steps) = engine_with_steps(raw(serde_json::json!([{
            "name": "checked",
            "matchers": [{ "type": "any" }],
            "actions": [{ "type": "forward", "upstream": checked }]
        }])));
        assert_eq!(
            ask_at_once(&engine, ["10.0.0.1:53000", "10.0.0.2:53000"]).await,
            [Some("192.0.2.10".parse().unwrap()); 2]
        );
        assert!(steps.joined("10.0.0.2:53000"), "{:?}", steps.taken());
    }

    /// 请求阶段到达跳转上限给出的 SERVFAIL 只属于这个请求：开着 min_ttl 时也不缓存给
    /// 直接进入同一个 pipeline、还有余量的请求。
    /// The SERVFAIL a request gets at the request-phase jump limit is its own: even
    /// with min_ttl on, it is not cached for a request that enters the same
    /// pipeline directly with jumps to spare.
    #[tokio::test]
    async fn a_jump_limit_servfail_is_not_cached_for_another_request() {
        let answer = "192.0.2.20".parse().unwrap();
        let answering = answering_upstream(answer, 300).await.address;
        let jump = |name: &str, target: &str| {
            serde_json::json!({
                "name": name,
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "jump_to_pipeline", "pipeline": target }]
            })
        };
        let raw = serde_json::json!({
            "settings": {
                "default_upstream": "127.0.0.1:9",
                "upstream_timeout_ms": 100,
                "enable_tcp_fallback": false,
                "response_jump_limit": 1,
                "min_ttl": 60
            },
            "pipeline_select": [
                { "pipeline": "a", "matchers": [{ "type": "client_ip", "cidr": "10.0.0.1/32" }] },
                { "pipeline": "b", "matchers": [{ "type": "client_ip", "cidr": "10.0.0.2/32" }] }
            ],
            "pipelines": [
                { "id": "a", "rules": [jump("a", "b")] },
                { "id": "b", "rules": [jump("b", "c")] },
                { "id": "c", "rules": [{
                    "name": "c",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "forward", "upstream": answering }]
                }] }
            ]
        });
        let engine = engine_from(raw);
        let ask = |client: &str| {
            let peer = client.parse().unwrap();
            let engine = &engine;
            async move {
                first_a_record(
                    tokio::time::timeout(
                        Duration::from_secs(5),
                        engine.handle_packet(&example_query(), peer),
                    )
                    .await
                    .expect("answer in time"),
                )
            }
        };

        // a → b → c 用完了次数；直接进入 b 的 b → c 还有余量
        // a → b → c runs out of jumps; b → c from a direct entry into b does not
        assert_eq!(ask("10.0.0.1:53000").await, None);
        assert_eq!(ask("10.0.0.2:53000").await, Some(answer));
    }

    /// 在响应跳转路径上，跳转次数同样取决于请求一路怎么来的。经过更多跳转才到 `s` 的
    /// 请求先用完了次数（在 `s` 的回答检查要跳转时，或在之后一次规则级跳转时），它的
    /// SERVFAIL 不能交给直接从 `p2` 跳来、还有余量的请求：两个请求的条目各在自己的入口，
    /// 跳转之后谁也不等谁。
    /// On the response-jump path too, the jumps left depend on the way a request
    /// came. One that reached `s` through more jumps runs out first (when the answer
    /// check in `s` jumps, or at a rule-level hop after it), and its SERVFAIL must
    /// not reach a request that jumped there from `p2` with jumps to spare: each keeps
    /// its entry at its own entry pipeline, and after the jumps neither waits on the other.
    #[tokio::test]
    async fn a_jump_path_waiter_with_jumps_to_spare_does_not_take_the_jump_limit() {
        let entry = answering_upstream("192.0.2.50".parse().unwrap(), 300)
            .await
            .address;
        // p2 慢一点，第一个请求先在 s 登记 / p2 is slower, so the first request registers at s first
        let later_entry = answering_upstream_after(
            "192.0.2.51".parse().unwrap(),
            300,
            Duration::from_millis(30),
        )
        .await
        .address;
        let slow = answering_upstream_after(
            "192.0.2.10".parse().unwrap(),
            300,
            Duration::from_millis(100),
        )
        .await
        .address;
        let answer = "192.0.2.20".parse().unwrap();
        let answering = answering_upstream(answer, 300).await.address;
        let checked_jump = |id: &str, upstream: &str, target: &str| {
            pipeline_of(
                id,
                serde_json::json!([{ "type": "forward", "upstream": upstream }]),
                serde_json::json!({
                    "response_matchers": [{ "type": "upstream_equals", "value": upstream }],
                    "response_actions_on_match": [{ "type": "jump_to_pipeline", "pipeline": target }]
                }),
            )
        };
        let hop = |id: &str, target: &str| {
            pipeline_of(
                id,
                serde_json::json!([{ "type": "jump_to_pipeline", "pipeline": target }]),
                serde_json::json!({}),
            )
        };
        let answers_at = |id: &str| {
            pipeline_of(
                id,
                serde_json::json!([{ "type": "forward", "upstream": answering }]),
                serde_json::json!({}),
            )
        };
        // 第一个请求在 s 之前多走一次或两次规则级跳转，于是比从 p2 来的请求先用完次数：
        // 在 s 的回答检查要跳转时，或在之后一次规则级跳转时。（上限 N 就是能跳 N 次：带着
        // 0 次进入下一个 pipeline 不算超限，所以没有「在入口用完」这种情况。）
        // The first request takes one or two more rule-level hops before s, so it
        // runs out before the one from p2: when the answer check in s jumps, or at a
        // rule-level hop after it. (A limit of N is N jumps: entering the next
        // pipeline with none left is within it, so nothing runs out on entering.)
        let paths = [
            (
                "at the answer check's jump",
                3,
                vec![
                    hop("y", "y2"),
                    hop("y2", "s"),
                    checked_jump("s", &slow, "t"),
                    answers_at("t"),
                ],
            ),
            (
                "at a rule-level hop after the answer check",
                4,
                vec![
                    hop("y", "s"),
                    checked_jump("s", &slow, "z"),
                    hop("z", "z2"),
                    hop("z2", "z3"),
                    answers_at("z3"),
                ],
            ),
        ];
        for (where_it_runs_out, limit, rest) in paths {
            let mut pipelines = vec![
                checked_jump("p1", &entry, "y"),
                checked_jump("p2", &later_entry, "s"),
            ];
            pipelines.extend(rest);
            let raw = serde_json::json!({
                "settings": {
                    "default_upstream": "127.0.0.1:9",
                    "upstream_timeout_ms": 500,
                    "enable_tcp_fallback": false,
                    "response_jump_limit": limit
                },
                "pipeline_select": [
                    { "pipeline": "p1", "matchers": [{ "type": "client_ip", "cidr": "10.0.0.1/32" }] },
                    { "pipeline": "p2", "matchers": [{ "type": "client_ip", "cidr": "10.0.0.2/32" }] }
                ],
                "pipelines": pipelines
            });
            // 对照用：跳转次数放宽到用不完 / For the control: the jump limit raised so none runs out
            let mut roomy = raw.clone();
            roomy["settings"]["response_jump_limit"] = serde_json::json!(limit + 10);
            let (engine, steps) = engine_with_steps(raw);
            assert_eq!(
                ask_at_once(&engine, ["10.0.0.1:53000", "10.0.0.2:53000"]).await,
                [None, Some(answer)],
                "{where_it_runs_out}"
            );
            assert!(!steps.joined("10.0.0.2:53000"), "{where_it_runs_out}");

            // 对照：跳转次数用不完时，同样两个请求都拿到最终的应答
            // Control: with jumps to spare, the same two requests both get the final answer
            let (engine, _) = engine_with_steps(roomy);
            assert_eq!(
                ask_at_once(&engine, ["10.0.0.1:53000", "10.0.0.2:53000"]).await,
                [Some(answer); 2],
                "{where_it_runs_out}"
            );
        }
    }

    // ========================================================================
    // Original Engine Tests / 原有引擎测试
    // ========================================================================
    use std::net::Ipv4Addr;
    use tokio::time::Duration;

    /// `static_ip_response` 写成 `ips` 时给这个查询的 RCODE 和记录（见 `StaticAnswer::records`）/ The RCODE and
    /// records a `static_ip_response` written as `ips` gives this query (see `StaticAnswer::records`)
    fn make_static_ip_answer(
        qname: &str,
        qtype: RecordType,
        qclass: DNSClass,
        ips: &str,
    ) -> (ResponseCode, Vec<Record>) {
        StaticAnswer::addresses(ips).records(qname, qtype, qclass)
    }

    /// 照 `raw` 读出、编好的动作（见 `Action::compile_answer`）/ The action `raw` reads as, compiled
    /// (see `Action::compile_answer`)
    fn compiled(raw: serde_json::Value) -> Action {
        let mut action: Action = serde_json::from_value(raw).expect("an action");
        action.compile_answer();
        action
    }

    #[test]
    fn make_static_ip_answer_returns_ipv4_record() {
        // Arrange: Define test domain and IPv4 address
        let domain = "example.com";
        let ipv4 = "1.2.3.4";

        // Act: Generate static IP answer
        let (rcode, answers) = make_static_ip_answer(domain, RecordType::A, DNSClass::IN, ipv4);

        // Assert: Verify response code and record type
        assert_eq!(
            rcode,
            ResponseCode::NoError,
            "Should return NoError for valid IP"
        );
        assert_eq!(answers.len(), 1, "Should have exactly one answer");
        assert_eq!(
            answers[0].record_type(),
            RecordType::A,
            "Should be A record for IPv4"
        );
    }

    #[test]
    fn make_static_ip_answer_returns_ipv6_record() {
        // Arrange: Define test domain and IPv6 address
        let domain = "example.com";
        let ipv6 = "2001:db8::1";

        // Act: Generate static IP answer
        let (rcode, answers) = make_static_ip_answer(domain, RecordType::AAAA, DNSClass::IN, ipv6);

        // Assert: Verify response code and record type
        assert_eq!(
            rcode,
            ResponseCode::NoError,
            "Should return NoError for valid IP"
        );
        assert_eq!(answers.len(), 1, "Should have exactly one answer");
        assert_eq!(
            answers[0].record_type(),
            RecordType::AAAA,
            "Should be AAAA record for IPv6"
        );
    }

    #[test]
    fn make_static_ip_answer_filters_comma_separated_addresses_by_query_type() {
        let ips = " 192.0.2.1, 2001:db8::1,192.0.2.2 ";

        let (a_rcode, a_answers) =
            make_static_ip_answer("example.com", RecordType::A, DNSClass::IN, ips);
        assert_eq!(a_rcode, ResponseCode::NoError);
        assert_eq!(a_answers.len(), 2);
        assert!(
            a_answers
                .iter()
                .all(|answer| answer.record_type() == RecordType::A)
        );

        let (aaaa_rcode, aaaa_answers) =
            make_static_ip_answer("example.com", RecordType::AAAA, DNSClass::IN, ips);
        assert_eq!(aaaa_rcode, ResponseCode::NoError);
        assert_eq!(aaaa_answers.len(), 1);
        assert_eq!(aaaa_answers[0].record_type(), RecordType::AAAA);
    }

    #[test]
    fn make_static_ip_answer_returns_nodata_for_unconfigured_query_family() {
        let (rcode, answers) =
            make_static_ip_answer("example.com", RecordType::AAAA, DNSClass::IN, "192.0.2.1");

        assert_eq!(rcode, ResponseCode::NoError);
        assert!(answers.is_empty());
    }

    #[test]
    fn make_static_ip_answer_returns_nodata_for_https_query() {
        let (rcode, answers) = make_static_ip_answer(
            "example.com",
            RecordType::HTTPS,
            DNSClass::IN,
            "192.0.2.1,2001:db8::1",
        );

        assert_eq!(rcode, ResponseCode::NoError);
        assert!(answers.is_empty());
    }

    #[test]
    fn make_static_ip_answer_returns_both_families_for_any_query() {
        let (rcode, answers) = make_static_ip_answer(
            "example.com",
            RecordType::ANY,
            DNSClass::IN,
            "192.0.2.1,2001:db8::1",
        );

        assert_eq!(rcode, ResponseCode::NoError);
        assert_eq!(answers.len(), 2);
        assert_eq!(answers[0].record_type(), RecordType::A);
        assert_eq!(answers[1].record_type(), RecordType::AAAA);
    }

    #[test]
    fn make_static_ip_answer_rejects_invalid_input_atomically() {
        let (rcode, answers) = make_static_ip_answer(
            "example.com",
            RecordType::A,
            DNSClass::IN,
            "192.0.2.1,not-an-ip,2001:db8::1",
        );

        assert_eq!(
            rcode,
            ResponseCode::ServFail,
            "Should return ServFail when any IP is invalid"
        );
        assert!(answers.is_empty(), "Should not return a partial answer");
    }

    #[test]
    fn make_static_ip_answer_rejects_empty_entries() {
        for ips in ["", "192.0.2.1,", ",192.0.2.1", "192.0.2.1,,2001:db8::1"] {
            let (rcode, answers) =
                make_static_ip_answer("example.com", RecordType::A, DNSClass::IN, ips);
            assert_eq!(rcode, ResponseCode::ServFail, "input: {ips:?}");
            assert!(answers.is_empty(), "input: {ips:?}");
        }
    }

    /// 请求的 EDNS 版本不受支持（不是 0）时回 BADVERS，带上版本为 0 的 OPT 和原来的问题；以前照
    /// 版本 0 回答。版本 0 的请求照常回答。
    /// A request with an unsupported EDNS version (anything but 0) is answered BADVERS with an
    /// OPT of version 0 and its own question; it used to be answered as if it were version 0.
    /// A version 0 request is answered as usual.
    #[tokio::test]
    async fn an_unsupported_edns_version_is_answered_badvers() {
        let raw = serde_json::json!({
            "settings": { "default_upstream": "127.0.0.1:9" },
            "pipelines": [{
                "id": "main",
                "rules": [{
                    "name": "static",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "static_ip_response", "ip": "192.0.2.1" }]
                }]
            }]
        });
        let engine = engine_from(raw);
        let peer = "127.0.0.1:53000".parse().unwrap();
        let ask = |version: u8| {
            let mut request = Message::new(0xBEEF, MessageType::Query, OpCode::Query);
            request.metadata.recursion_desired = true;
            request.add_query(Query::query(
                Name::from_ascii("example.com.").unwrap(),
                RecordType::A,
            ));
            let mut edns = hickory_proto::op::Edns::new();
            edns.set_version(version);
            request.edns = Some(edns);
            let packet = request.to_vec().unwrap();
            let Some(FastPathResponse::Direct(reply)) = engine.handle_packet_fast(&packet, peer)
            else {
                panic!("version {version}: answered on the fast path");
            };
            (request, Message::from_vec(&reply).expect("parse reply"))
        };

        let (request, reply) = ask(1);
        // 16 同时登记为 BADVERS（OPT）和 BADSIG（TSIG），hickory 读出来叫 BADSIG，所以比较数值
        // 16 is registered both as BADVERS (OPT) and BADSIG (TSIG), and hickory reads it as
        // BADSIG, so the value is compared
        assert_eq!(u16::from(reply.metadata.response_code), 16);
        assert_eq!(reply.metadata.id, 0xBEEF);
        assert_eq!(reply.queries, request.queries);
        assert!(reply.answers.is_empty());
        assert_eq!(reply.edns.as_ref().map(|edns| edns.version()), Some(0));

        let (_, reply) = ask(0);
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert_eq!(reply.answers.len(), 1);
    }

    /// 快速解析读不了的查询（结尾多一个字节、名字要转义）走完整路径，EDNS 版本不是 0 时同样回
    /// BADVERS；以前照版本 0 回答。版本 0 的照常回答。
    /// A query the fast parser cannot read (a trailing byte, a name that needs escapes) takes
    /// the full path, and an EDNS version other than 0 is answered BADVERS there too; it used
    /// to be answered as if it were version 0. Version 0 is answered as usual.
    #[tokio::test]
    async fn the_full_path_answers_an_unsupported_edns_version_badvers() {
        let raw = serde_json::json!({
            "settings": { "default_upstream": "127.0.0.1:9" },
            "pipelines": [{
                "id": "main",
                "rules": [{
                    "name": "static",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "static_ip_response", "ip": "192.0.2.1" }]
                }]
            }]
        });
        let engine = engine_from(raw);
        let peer = "127.0.0.1:53000".parse().unwrap();
        for (label, trailing) in [(&b"example"[..], &b"\0"[..]), (b"a b", b"")] {
            for version in [1u8, 0] {
                let mut request = Message::new(0xBEEF, MessageType::Query, OpCode::Query);
                request.metadata.recursion_desired = true;
                request.add_query(Query::query(
                    Name::from_labels([label, b"com"]).unwrap(),
                    RecordType::A,
                ));
                let mut edns = hickory_proto::op::Edns::new();
                edns.set_version(version);
                request.edns = Some(edns);
                let mut packet = request.to_vec().unwrap();
                packet.extend_from_slice(trailing);
                let case = format!("{label:?} + {trailing:?}, version {version}");
                assert!(
                    engine.handle_packet_fast(&packet, peer).is_none(),
                    "{case}: the fast parser leaves it to the full path"
                );
                let reply = engine.handle_packet(&packet, peer).await.expect(&case);
                let reply = Message::from_vec(&reply).expect("parse reply");
                assert_eq!(reply.metadata.id, 0xBEEF, "{case}");
                assert_eq!(reply.queries, request.queries, "{case}");
                if version == 0 {
                    assert_eq!(
                        reply.metadata.response_code,
                        ResponseCode::NoError,
                        "{case}"
                    );
                    assert_eq!(reply.answers.len(), 1, "{case}");
                } else {
                    // Compared as a number, see above / 按数值比较，见上
                    assert_eq!(u16::from(reply.metadata.response_code), 16, "{case}");
                    assert!(reply.answers.is_empty(), "{case}");
                    assert_eq!(reply.edns.as_ref().map(|edns| edns.version()), Some(0));
                }
            }
        }
    }

    #[tokio::test]
    async fn static_ip_fast_path_serializes_multiple_answers_by_query_type() {
        let raw = serde_json::json!({
            "settings": { "default_upstream": "1.1.1.1:53" },
            "pipelines": [{
                "id": "static",
                "rules": [{
                    "name": "static-ip",
                    "matchers": [{ "type": "domain_suffix", "value": "example.com" }],
                    "actions": [{
                        "type": "static_ip_response",
                        "ip": "192.0.2.1,2001:db8::1,192.0.2.2"
                    }]
                }]
            }]
        });
        let engine = engine_from(raw);
        let peer = "127.0.0.1:53000".parse().unwrap();

        let assert_response = |qtype, expected_ips: &[IpAddr]| {
            let mut request = Message::new(0xCAFE, MessageType::Query, OpCode::Query);
            request.metadata.recursion_desired = true;
            request.add_query(Query::query(
                Name::from_str("www.example.com").unwrap(),
                qtype,
            ));

            let response = match engine.handle_packet_fast(&request.to_vec().unwrap(), peer) {
                Some(FastPathResponse::Direct(bytes)) => Message::from_bytes(&bytes).unwrap(),
                other => panic!("expected direct fast-path response, got {other:?}"),
            };

            assert_eq!(response.metadata.id, 0xCAFE);
            assert_eq!(response.metadata.message_type, MessageType::Response);
            assert_eq!(response.metadata.response_code, ResponseCode::NoError);
            assert!(response.metadata.recursion_desired);
            assert!(response.metadata.recursion_available);
            assert_eq!(response.queries.len(), 1);
            assert_eq!(response.queries[0].query_type(), qtype);

            let actual_ips: Vec<IpAddr> = response
                .answers
                .iter()
                .map(|answer| {
                    assert_eq!(answer.ttl, 300);
                    match &answer.data {
                        RData::A(address) => IpAddr::V4(address.0),
                        RData::AAAA(address) => IpAddr::V6(address.0),
                        other => panic!("unexpected static IP answer: {other:?}"),
                    }
                })
                .collect();
            assert_eq!(actual_ips, expected_ips);
        };

        assert_response(
            RecordType::A,
            &["192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap()],
        );
        assert_response(RecordType::AAAA, &["2001:db8::1".parse().unwrap()]);
    }

    #[tokio::test]
    async fn static_cname_fast_path_maps_query_name_to_target() {
        let raw = serde_json::json!({
            "settings": { "default_upstream": "1.1.1.1:53" },
            "pipelines": [{
                "id": "static",
                "rules": [{
                    "name": "static-cname",
                    "matchers": [{ "type": "domain_suffix", "value": "alias.example" }],
                    "actions": [{
                        "type": "static_cname_response",
                        "target": "origin.example.",
                        "ttl": 120
                    }]
                }]
            }]
        });
        let engine = engine_from(raw);
        let peer = "127.0.0.1:53000".parse().unwrap();

        let mut request = Message::new(0xCAFE, MessageType::Query, OpCode::Query);
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(
            Name::from_str("alias.example").unwrap(),
            RecordType::A,
        ));

        let response = match engine.handle_packet_fast(&request.to_vec().unwrap(), peer) {
            Some(FastPathResponse::Direct(bytes)) => Message::from_bytes(&bytes).unwrap(),
            other => panic!("expected direct fast-path response, got {other:?}"),
        };

        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert_eq!(response.queries[0].query_type(), RecordType::A);
        assert_eq!(response.answers.len(), 1);
        assert_eq!(&response.answers[0].name, response.queries[0].name());
        assert_eq!(response.answers[0].record_type(), RecordType::CNAME);
        assert_eq!(response.answers[0].ttl, 120);
        match &response.answers[0].data {
            RData::CNAME(cname) => {
                assert_eq!(cname.0, Name::from_str("origin.example.").unwrap());
            }
            other => panic!("unexpected static CNAME answer: {other:?}"),
        }
    }

    /// 第一个动作是哪种作答动作，快速路径都当场答，和完整路径给的一样：静态 TXT 照它的 TTL，写错的 rcode 照完整路径回
    /// NXDOMAIN（配置检查报过）。以前这两种留给完整路径，快速路径只认 static_response（rcode 写对的）、static_ip_response、
    /// static_cname_response 和 deny
    /// Whichever answering action comes first, the fast path answers on the spot, with what the
    /// full path gives: a static TXT by its TTL, a misspelt rcode NXDOMAIN as on the full path
    /// (the configuration check reports it). These two used to be left to the full path, the fast
    /// path taking only static_response (spelt right), static_ip_response, static_cname_response
    /// and deny
    #[tokio::test]
    async fn every_answering_action_is_answered_on_the_fast_path() {
        for (action, qtype, rcode, ttls) in [
            (
                serde_json::json!({ "type": "static_txt_response", "text": "hello", "ttl": 90 }),
                RecordType::TXT,
                ResponseCode::NoError,
                vec![90],
            ),
            (
                serde_json::json!({ "type": "static_response", "rcode": "NXDOMAN" }),
                RecordType::A,
                ResponseCode::NXDomain,
                vec![],
            ),
        ] {
            let engine = engine_from(serde_json::json!({
                "settings": { "default_upstream": "1.1.1.1:53" },
                "pipelines": [{ "id": "static", "rules": [{
                    "name": "static",
                    "matchers": [{ "type": "any" }],
                    "actions": [action]
                }]}]
            }));
            let mut request = Message::new(0xCAFE, MessageType::Query, OpCode::Query);
            request.metadata.recursion_desired = true;
            request.add_query(Query::query(
                Name::from_str("static.example").unwrap(),
                qtype,
            ));
            let packet = request.to_vec().unwrap();
            let peer = "127.0.0.1:53000".parse().unwrap();
            let fast = match engine.handle_packet_fast(&packet, peer) {
                Some(FastPathResponse::Direct(bytes)) => Message::from_bytes(&bytes).unwrap(),
                other => panic!("{action}: expected a direct answer, got {other:?}"),
            };
            let full =
                Message::from_bytes(&engine.handle_packet(&packet, peer).await.unwrap()).unwrap();
            for response in [&fast, &full] {
                assert_eq!(response.metadata.response_code, rcode, "{action}");
                assert_eq!(
                    response.answers.iter().map(|r| r.ttl).collect::<Vec<_>>(),
                    ttls,
                    "{action}"
                );
            }
        }
    }

    #[test]
    fn pipeline_select_picks_matching_pipeline() {
        // Arrange: Create configuration with pipeline selection rules
        let raw = serde_json::json!({
            "pipelines": [
                { "id": "p1", "rules": [] },
                { "id": "p2", "rules": [] }
            ],
            "pipeline_select": [
                { "pipeline": "p2", "matchers": [ { "type": "listener_label", "value": "edge" } ] }
            ]
        });

        // Act: Parse and compile configuration
        let cfg: crate::config::PipelineConfig = serde_json::from_value(raw).expect("parse");
        let runtime = RuntimePipelineConfig::from_config(cfg).expect("runtime");

        // Act: Select pipeline for edge listener
        let opt = select_pipeline(
            &runtime,
            "edge",
            &crate::matcher::RequestFacts::a_query("any.example.com"),
            crate::matcher::GeoManagers::empty(),
        );
        let id = opt.map_or(NO_PIPELINE, |pipeline| &*pipeline.id);

        // Assert: Verify correct pipeline was selected
        assert!(opt.is_some(), "Should find matching pipeline");
        assert_eq!(id, "p2", "Should select p2 pipeline for edge listener");
    }

    #[test]
    fn pipeline_select_respects_match_operator_or() {
        // Arrange: Create configuration with OR operator in pipeline selector
        let raw = serde_json::json!({
            "pipelines": [
                { "id": "p1", "rules": [] },
                { "id": "p2", "rules": [] }
            ],
            "pipeline_select": [
                {
                    "pipeline": "p2",
                    "matcher_operator": "or",
                    "matchers": [
                        { "type": "listener_label", "value": "edge" },
                        { "type": "domain_suffix", "value": ".internal" }
                    ]
                }
            ]
        });

        // Act: Parse and compile configuration
        let cfg: crate::config::PipelineConfig = serde_json::from_value(raw).expect("parse");
        let runtime = RuntimePipelineConfig::from_config(cfg).expect("runtime");

        // Act: Select pipeline for edge listener
        let opt = select_pipeline(
            &runtime,
            "edge",
            &crate::matcher::RequestFacts::a_query("example.com"),
            crate::matcher::GeoManagers::empty(),
        );
        let id = opt.map_or(NO_PIPELINE, |pipeline| &*pipeline.id);

        // Assert: Verify correct pipeline was selected
        assert!(opt.is_some(), "Should find matching pipeline");
        assert_eq!(id, "p2", "Should select p2 pipeline for edge listener");
    }

    #[allow(dead_code)]
    #[tokio::test]
    async fn apply_rules_static_and_forward_allow_jump() {
        // Arrange: Build a config with rules exercising StaticResponse, Forward, Allow, Jump
        let raw = serde_json::json!({
            "settings": { "default_upstream": "1.1.1.1:53" },
            "pipelines": [
                {
                    "id": "p",
                    "rules": [
                        {
                            "name": "static",
                            "matchers": [ { "type": "any" } ],
                            "actions": [ { "type": "static_response", "rcode": "NXDOMAIN" } ]
                        }
                    ]
                }
            ]
        });

        // Act: Parse configuration and create engine
        let cfg: crate::config::PipelineConfig = serde_json::from_value(raw).expect("parse");
        let runtime = RuntimePipelineConfig::from_config(cfg.clone()).expect("runtime");
        let engine = Engine::new(runtime.clone(), "lbl".to_string()).expect("initialize engine");
        let state = engine.state.load();

        // Act: Apply rules - StaticResponse should return Static decision
        let decision = engine.apply_rules(
            &state,
            &state.pipeline.pipelines[0],
            &crate::matcher::RequestFacts::a_query("a.example.com"),
            &RuleEvaluationContext::new(0, false),
        );

        // Assert: Verify StaticResponse returns NXDOMAIN
        match decision {
            Decision::Static { rcode, .. } => assert_eq!(
                rcode,
                ResponseCode::NXDomain,
                "StaticResponse should return NXDOMAIN"
            ),
            _ => panic!("expected static decision"),
        }

        // Arrange: Test Forward action with provided upstream and response matchers
        let raw2 = serde_json::json!({
            "settings": { "default_upstream": "1.1.1.1:53" },
            "pipelines": [
                {
                    "id": "p2",
                    "rules": [
                        {
                            "name": "fwd",
                            "matchers": [ { "type": "any" } ],
                            "actions": [ { "type": "forward", "upstream": "8.8.8.8:53" } ],
                            "response_matchers": [ { "type": "upstream_equals", "value": "8.8.8.8:53" } ],
                            "response_matcher_operator": "and"
                        }
                    ]
                }
            ]
        });
        let cfg2: crate::config::PipelineConfig = serde_json::from_value(raw2).expect("parse");
        let runtime2 = RuntimePipelineConfig::from_config(cfg2.clone()).expect("runtime");
        let engine2 = Engine::new(runtime2.clone(), "lbl".to_string()).expect("initialize engine");
        let state2 = engine2.state.load();

        // Act: Apply rules - Forward should return Forward decision with upstream and matchers
        let decision2 = engine2.apply_rules(
            &state2,
            &state2.pipeline.pipelines[0],
            &crate::matcher::RequestFacts::a_query("x.example.com"),
            &RuleEvaluationContext::new(0, false),
        );

        // Assert: Verify Forward action returns correct upstream and matchers
        match decision2 {
            Decision::Forward {
                upstream,
                response_phase,
                ..
            } => {
                let (response_matchers, _, _) =
                    crate::matcher::ResponsePhase::parts(response_phase.as_deref());
                assert_eq!(
                    upstream.as_ref(),
                    "8.8.8.8:53",
                    "Forward should use configured upstream"
                );
                assert_eq!(
                    response_matchers.len(),
                    1,
                    "Forward should have one response matcher"
                );
                assert_eq!(
                    response_matchers[0].operator,
                    crate::config::MatchOperator::And,
                    "Forward should use AND operator"
                );
            }
            _ => panic!("expected forward decision"),
        }

        // Arrange: Test Allow action - should forward to default upstream
        let raw3 = serde_json::json!({
            "settings": { "default_upstream": "1.2.3.4:53" },
            "pipelines": [ { "id": "p3", "rules": [ { "name": "a", "matchers": [ { "type": "any" } ], "actions": [ { "type": "allow" } ] } ] } ]
        });
        let cfg3: crate::config::PipelineConfig = serde_json::from_value(raw3).expect("parse");
        let runtime3 = RuntimePipelineConfig::from_config(cfg3.clone()).expect("runtime");
        let engine3 = Engine::new(runtime3.clone(), "lbl".to_string()).expect("initialize engine");
        let state3 = engine3.state.load();

        // Act: Apply rules - Allow should forward to default upstream
        let decision3 = engine3.apply_rules(
            &state3,
            &state3.pipeline.pipelines[0],
            &crate::matcher::RequestFacts::a_query("y.example.com"),
            &RuleEvaluationContext::new(0, false),
        );

        // Assert: Verify Allow action forwards to default upstream
        match decision3 {
            Decision::Forward { upstream, .. } => assert_eq!(
                upstream.as_ref(),
                "1.2.3.4:53",
                "Allow should forward to default upstream"
            ),
            _ => panic!("expected forward decision from allow"),
        }

        // Arrange: Test JumpToPipeline action
        let raw4 = serde_json::json!({
            "pipelines": [ { "id": "p4", "rules": [ { "name": "j", "matchers": [ { "type": "any" } ], "actions": [ { "type": "jump_to_pipeline", "pipeline": "other" } ] } ] } ]
        });
        let cfg4: crate::config::PipelineConfig = serde_json::from_value(raw4).expect("parse");
        let runtime4 = RuntimePipelineConfig::from_config(cfg4.clone()).expect("runtime");
        let engine4 = Engine::new(runtime4.clone(), "lbl".to_string()).expect("initialize engine");
        let state4 = engine4.state.load();

        // Act: Apply rules - JumpToPipeline should return Jump decision
        let decision4 = engine4.apply_rules(
            &state4,
            &state4.pipeline.pipelines[0],
            &crate::matcher::RequestFacts::a_query("z.example.com"),
            &RuleEvaluationContext::new(0, false),
        );

        // Assert: Verify JumpToPipeline returns correct target pipeline
        match decision4 {
            Decision::Jump { pipeline } => assert_eq!(
                pipeline.as_ref(),
                "other",
                "JumpToPipeline should jump to target pipeline"
            ),
            _ => panic!("expected jump decision"),
        }
    }

    const TEST_UPSTREAM: &str = "1.1.1.1:53";

    // 每个等上游的查询都带着这份状态，三万个在途查询就是三万份。以前是 10 KB 多：应答回来以后的处理
    // （包括响应动作和响应跳转）和最大的那种传输（DoT）都按最坏的情况预留着。这两样单独分配以后剩
    // 3.8 KB；上限给编译器版本的差别留了余量，哪一样重新放回来都会超
    // Every query waiting on an upstream carries this state, thirty thousand copies for
    // thirty thousand queries in flight. It was over 10 KB: what happens once the reply is
    // in (the response actions and the response jump included) and the largest transport
    // (DoT) both reserved room for the worst case. With the two allocated on their own it is
    // 3.8 KB; the limit leaves room for compiler differences, and putting either back goes
    // over it
    #[tokio::test]
    async fn a_pending_query_stays_small() {
        const LIMIT: usize = 4608;
        let engine = build_test_engine();
        let peer: SocketAddr = "127.0.0.1:5300".parse().expect("peer");
        let packet = query_for("a.test");
        let full = engine.handle_packet(&packet, peer);
        let Some(FastPathResponse::AsyncNeeded(pre_parsed)) =
            engine.handle_packet_fast(&packet, peer)
        else {
            panic!("the fast path leaves a forward to the async path");
        };
        let pre_parsed = engine.handle_packet_full(&packet, peer, pre_parsed);
        for (entry, size) in [
            ("handle_packet", std::mem::size_of_val(&full)),
            ("pre-parsed", std::mem::size_of_val(&pre_parsed)),
        ] {
            assert!(
                size <= LIMIT,
                "{entry}: a pending query holds {size} bytes, over {LIMIT}"
            );
        }
    }

    fn build_test_engine() -> Engine {
        let runtime = runtime_with_settings(GlobalSettings {
            default_upstream: TEST_UPSTREAM.to_string(),
            ..Default::default()
        });
        Engine::new(runtime, "lbl".to_string()).expect("initialize test engine")
    }

    /// 只有全局设置 `settings`、没有 pipeline 的运行配置
    /// A runtime configuration with the global `settings` alone and no pipelines
    fn runtime_with_settings(settings: GlobalSettings) -> RuntimePipelineConfig {
        RuntimePipelineConfig {
            settings,
            pipeline_select: Vec::new(),
            pipelines: Vec::new(),
            pipeline_id_index: FxHashMap::default(),
            warnings: Vec::new(),
        }
    }

    fn build_response_context() -> ResponseContext {
        let mut msg = Message::new(0, MessageType::Response, OpCode::Query);
        msg.metadata.response_code = ResponseCode::NoError;
        let name = Name::from_str("example.com").expect("name");
        let record = Record::from_rdata(name, 300, RData::A(A(Ipv4Addr::new(1, 2, 3, 4))));
        msg.add_answer(record);
        ResponseContext {
            raw: Bytes::from_static(b"resp"),
            msg,
            upstream: Arc::from(TEST_UPSTREAM),
        }
    }

    /// 问 `qname` 的 `qtype` 的查询 / A query asking `qname` for `qtype`
    fn query_packet(qname: &str, qtype: RecordType) -> Vec<u8> {
        let mut query = Message::new(0xCAFE, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(Name::from_str(qname).unwrap(), qtype));
        query.to_vec().unwrap()
    }

    /// 来自 10.0.0.1、问 `qname` 的 `qtype` 的请求，包是 `packet` / A request from 10.0.0.1 asking
    /// `qname` for `qtype`, its packet being `packet`
    fn asked(
        engine: &Engine,
        qname: &str,
        qtype: RecordType,
        packet: &[u8],
    ) -> crate::engine::test_support::Asked {
        crate::engine::test_support::Asked::new(
            engine,
            qname,
            qtype,
            packet.to_vec(),
            "10.0.0.1:53000".parse().unwrap(),
        )
    }

    /// 在 `engine` 上为 `request` 执行 `actions` 的上下文，手上的应答是 `ctx_opt`，转发记在 `trail` 里
    /// The context for running `actions` on `engine` for `request`, with `ctx_opt` the answer
    /// in hand and forwards noted in `trail`
    fn response_actions_context<'a>(
        engine: &'a Engine,
        request: &'a Request<'a>,
        actions: &'a [Action],
        ctx_opt: Option<ResponseContext>,
        trail: &'a mut EcsReach,
    ) -> ApplyResponseActionsContext<'a> {
        ApplyResponseActionsContext {
            engine,
            request,
            actions,
            ctx_opt,
            packet: request.packet,
            pipeline_id: "pipeline",
            rule_name: "rule",
            remaining_jumps: 10,
            trail,
            rule_ecs: crate::ecs_scope::ForwardEcs::of(None, &request.requester.ecs_view()),
        }
    }

    #[tokio::test]
    async fn response_actions_allow_returns_the_upstream_answer() {
        // Arrange: Build test engine and response context
        let engine = build_test_engine();
        let ctx = build_response_context();
        let actions = [Action::Allow];
        let packet = query_packet("example.com", RecordType::A);

        // Act: Apply response actions with Allow action
        let asked = asked(&engine, "example.com", RecordType::A, &packet);
        let request = asked.request();
        let mut trail = EcsReach::default();
        let ctx = response_actions_context(&engine, &request, &actions, Some(ctx), &mut trail);
        let result = apply_response_actions(ctx)
            .await
            .expect("response actions allow should succeed");

        // Assert: Verify Allow action returns upstream result with match=true
        match result {
            ResponseActionResult::Upstream { ctx } => {
                assert_eq!(
                    ctx.raw.as_ref(),
                    b"resp",
                    "Allow keeps the upstream's answer"
                );
                assert_eq!(
                    ctx.upstream.as_ref(),
                    TEST_UPSTREAM,
                    "Allow should use test upstream"
                );
            }
            _ => panic!("expected upstream result"),
        }
    }

    /// `allow` 交出手上的应答，排在它后面的动作不再执行
    /// `allow` hands over the answer in hand, and the actions after it do not run
    #[tokio::test]
    async fn response_actions_stop_at_allow() {
        let engine = build_test_engine();
        let actions = [
            Action::Allow,
            compiled(serde_json::json!({ "type": "static_ip_response", "ip": "192.0.2.9" })),
        ];
        let packet = query_packet("example.com", RecordType::A);
        let asked = asked(&engine, "example.com", RecordType::A, &packet);
        let request = asked.request();
        let mut trail = EcsReach::default();
        let ctx = response_actions_context(
            &engine,
            &request,
            &actions,
            Some(build_response_context()),
            &mut trail,
        );
        match apply_response_actions(ctx).await.expect("response actions") {
            ResponseActionResult::Upstream { ctx, .. } => {
                assert_eq!(ctx.raw.as_ref(), b"resp", "the upstream's answer goes out");
            }
            other => panic!("expected the upstream's answer, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn response_actions_continue_returns_continue_with_context() {
        // Arrange: Build test engine, response context, and Continue action
        let engine = build_test_engine();
        let ctx = build_response_context();
        let actions = [Action::Continue];
        let packet = query_packet("example.com", RecordType::A);

        // Act: Apply response actions with Continue action
        let asked = asked(&engine, "example.com", RecordType::A, &packet);
        let request = asked.request();
        let mut trail = EcsReach::default();
        let ctx = response_actions_context(&engine, &request, &actions, Some(ctx), &mut trail);
        let result = apply_response_actions(ctx)
            .await
            .expect("response actions continue should succeed");

        // Assert: Verify Continue action returns Continue with the response context
        match result {
            ResponseActionResult::Continue { ctx } => {
                assert!(
                    ctx.is_some(),
                    "Continue must carry the received response context for reuse"
                );
            }
            _ => panic!("expected continue result"),
        }
    }

    #[tokio::test]
    async fn response_actions_allow_after_a_log_keeps_the_answer() {
        // Arrange: Build test engine and response context with non-matching response matcher
        let engine = build_test_engine();
        let ctx = build_response_context();
        let actions = [Action::Log { level: None }, Action::Allow];
        let packet = query_packet("example.com", RecordType::A);

        // Act: Apply response actions with Allow action and non-matching matcher
        let asked = asked(&engine, "example.com", RecordType::A, &packet);
        let request = asked.request();
        let mut trail = EcsReach::default();
        let ctx = response_actions_context(&engine, &request, &actions, Some(ctx), &mut trail);
        let result = apply_response_actions(ctx)
            .await
            .expect("response actions allow should succeed even on miss");

        // Assert: Allow keeps the upstream's answer whether or not the matchers hold
        match result {
            ResponseActionResult::Upstream { ctx } => {
                assert_eq!(
                    ctx.raw.as_ref(),
                    b"resp",
                    "Allow keeps the upstream's answer"
                );
                assert_eq!(ctx.upstream.as_ref(), TEST_UPSTREAM);
            }
            _ => panic!("expected upstream result"),
        }
    }

    #[tokio::test]
    async fn response_actions_deny_returns_refused() {
        // Arrange: Build test engine with Deny action
        let engine = build_test_engine();
        let actions = [Action::Deny];
        let packet = query_packet("example.com", RecordType::A);

        // Act: Apply response actions with Deny action
        let asked = asked(&engine, "example.com", RecordType::A, &packet);
        let request = asked.request();
        let mut trail = EcsReach::default();
        let ctx = response_actions_context(&engine, &request, &actions, None, &mut trail);
        let result = apply_response_actions(ctx)
            .await
            .expect("response actions deny should return static");

        // Assert: Verify Deny action returns Refused response code
        match result {
            ResponseActionResult::Static { rcode, .. } => {
                assert_eq!(rcode, ResponseCode::Refused, "Deny should return Refused");
            }
            _ => panic!("expected static refused"),
        }
    }

    #[tokio::test]
    async fn response_actions_static_ip_filters_answers_by_query_type() {
        // Arrange: Build test engine with a multi-address static IP response action
        let engine = build_test_engine();
        let actions = [compiled(serde_json::json!({
            "type": "static_ip_response",
            "ip": "192.0.2.1,2001:db8::1,192.0.2.2"
        }))];
        let run = async |qtype: RecordType| {
            let asked = asked(
                &engine,
                "example.com",
                qtype,
                &query_packet("example.com", qtype),
            );
            let request = asked.request();
            let mut trail = EcsReach::default();
            apply_response_actions(response_actions_context(
                &engine, &request, &actions, None, &mut trail,
            ))
            .await
        };
        let answer_ips = |resp: &Message| -> Vec<IpAddr> {
            resp.answers
                .iter()
                .map(|answer| match &answer.data {
                    RData::A(a) => IpAddr::V4(a.0),
                    RData::AAAA(a) => IpAddr::V6(a.0),
                    other => panic!("unexpected static IP answer: {other:?}"),
                })
                .collect()
        };

        // Act & Assert: A query returns only the IPv4 addresses
        match run(RecordType::A).await.expect("static ip") {
            ResponseActionResult::Static { bytes, rcode, .. } => {
                assert_eq!(rcode, ResponseCode::NoError);
                assert_eq!(
                    answer_ips(&Message::from_bytes(&bytes).unwrap()),
                    vec![
                        "192.0.2.1".parse::<IpAddr>().unwrap(),
                        "192.0.2.2".parse().unwrap()
                    ]
                );
            }
            _ => panic!("expected static result"),
        }

        // Act & Assert: AAAA query returns only the IPv6 address
        match run(RecordType::AAAA).await.expect("static ip") {
            ResponseActionResult::Static { bytes, rcode, .. } => {
                assert_eq!(rcode, ResponseCode::NoError);
                assert_eq!(
                    answer_ips(&Message::from_bytes(&bytes).unwrap()),
                    vec!["2001:db8::1".parse::<IpAddr>().unwrap()]
                );
            }
            _ => panic!("expected static result"),
        }

        // Act & Assert: HTTPS query returns NODATA (no synthesized address records)
        match run(RecordType::HTTPS).await.expect("static ip") {
            ResponseActionResult::Static { bytes, rcode, .. } => {
                assert_eq!(rcode, ResponseCode::NoError);
                assert!(
                    Message::from_bytes(&bytes).unwrap().answers.is_empty(),
                    "HTTPS should get NODATA, not synthesized A/AAAA records"
                );
            }
            _ => panic!("expected static result"),
        }
    }

    #[tokio::test]
    async fn response_actions_static_cname_returns_configured_alias() {
        let engine = build_test_engine();
        let actions = [compiled(serde_json::json!({
            "type": "static_cname_response",
            "target": "origin.example.",
            "ttl": 60
        }))];
        let packet = query_packet("alias.example", RecordType::A);
        let asked = asked(&engine, "alias.example", RecordType::A, &packet);
        let request = asked.request();
        let mut trail = EcsReach::default();
        let ctx = response_actions_context(&engine, &request, &actions, None, &mut trail);

        match apply_response_actions(ctx).await.expect("static cname") {
            ResponseActionResult::Static { bytes, rcode, .. } => {
                assert_eq!(rcode, ResponseCode::NoError);
                let response = Message::from_bytes(&bytes).unwrap();
                assert_eq!(response.answers.len(), 1);
                assert_eq!(&response.answers[0].name, response.queries[0].name());
                assert_eq!(response.answers[0].ttl, 60);
                match &response.answers[0].data {
                    RData::CNAME(cname) => {
                        assert_eq!(cname.0, Name::from_str("origin.example.").unwrap());
                    }
                    other => panic!("unexpected static CNAME answer: {other:?}"),
                }
            }
            _ => panic!("expected static result"),
        }
    }

    #[test]
    fn test_calculate_rule_hash_respects_the_requester_key() {
        // Arrange: Define test data
        let pipeline_id = "test_p";
        let qname = "example.com";
        let qtype = RecordType::A;
        let qclass = DNSClass::IN;
        let hash =
            |key: RequesterKey| calculate_rule_hash(0, pipeline_id, qname, qtype, qclass, &key);
        let class = |class| RequesterKey {
            class: Some(class),
            ..RequesterKey::NONE
        };

        // Act & Assert: Without requester facts nothing more is written than the question
        // 没有请求方的判定时，写进去的只有问题本身
        let base = Engine::question_hasher(0, pipeline_id, qname.as_bytes(), qtype, qclass);
        assert_eq!(hash(RequesterKey::NONE), base.finish());

        // Act & Assert: Different requester classes should result in different hashes
        assert_ne!(hash(class(1)), hash(class(2)));
        assert_ne!(hash(RequesterKey::NONE), hash(class(1)));
    }

    #[tokio::test]
    async fn test_cache_expiration_triggers_requery() {
        // Arrange: Build engine and insert expired cache entry
        let engine = build_test_engine();
        let pipeline_id = Arc::from("default");
        let qname = "expire.com";
        let qtype = RecordType::A;
        let qclass = DNSClass::IN;
        let dedupe_hash = KeyedQuestion {
            namespace: 0,
            pipeline_id: &pipeline_id,
            qname: qname.as_bytes(),
            qtype,
            qclass,
            flags: crate::proto_utils::QueryFlags::RECURSIVE,
            requester: RequesterKey::NONE,
            client_ecs: None,
        }
        .slot();

        // Insert an entry that expired 5 seconds ago
        let entry = CacheEntry {
            qname: Arc::from(qname),
            ..(*stale_entry("default")).clone()
        };
        engine.cache_insert(dedupe_hash, Arc::new(entry));

        // Act: Create DNS query packet and check fast path
        let mut packet = vec![0u8; 12];
        packet[0] = 0xAA;
        packet[1] = 0xBB; // TXID
        packet[5] = 1; // QDCOUNT
        packet.extend_from_slice(b"\x06expire\x03com\x00\x00\x01\x00\x01");

        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let fast_res = engine.handle_packet_fast(&packet, peer);

        // Assert: Expired cache should NOT be served — should fall through to AsyncNeeded
        // (None means parse_quick failed; AsyncNeeded means "parsed OK, need upstream query")
        match &fast_res {
            Some(FastPathResponse::CacheHit { .. }) => {
                panic!("Expired cache entry should not be served as CacheHit");
            }
            Some(FastPathResponse::AsyncNeeded(_)) => { /* correct: requery needed */ }
            Some(FastPathResponse::Direct(_)) => {
                panic!("Expired cache should not produce a Direct response");
            }
            None => {
                panic!(
                    "parse_quick should succeed for valid packet; expected AsyncNeeded, got None"
                );
            }
        }

        // The fast path leaves the expired entry to the async path's lookup, which a
        // listener runs next: that lookup picks the same entry and, with serve_stale
        // off (build_test_engine), misses on it, leaving it for the answer the request
        // forwards for to replace (see `phases::usable_hit`)
        // 快速路径把过期条目留给异步路径的查找（监听器接着就会走它）：那次查找选中同一条，
        // serve_stale 关着（build_test_engine），不用它，把它留给请求转发取回的应答去取代（见
        // `phases::usable_hit`）
        assert!(engine.cached(dedupe_hash).is_some());
        // 递归地问，和条目存的查询位一样 / Asked recursively, as the entry's query bits say
        let mut recursive = packet.clone();
        recursive[2] = 0x01;
        let asked = crate::engine::test_support::Asked::new(&engine, qname, qtype, recursive, peer);
        let looked_up = phases::check_cache(
            &engine,
            &asked.request().lookup(&pipeline_id, dedupe_hash),
            &mut Default::default(),
        );
        assert!(
            matches!(looked_up, phases::Looked::Missed),
            "an expired entry is not served"
        );

        assert!(
            engine.cached(dedupe_hash).is_some(),
            "the lookup leaves the expired entry in place"
        );
    }

    /// 等待上限必须是本次请求的剩余预算，两头都要卡住：等过头会让过期应答被
    /// 外层请求超时砍掉，客户端拿到 SERVFAIL；而按单次上游超时截断又太狠，
    /// 后台刷新没有外层包裹，UDP 链最坏约 2.33 倍上游超时，按 1 倍砍会把本来
    /// 能成功的刷新提前掐掉。
    /// The wait has to be bounded by what is left of this request's budget, and
    /// pinned from both sides: waiting too long lets the outer request timeout
    /// kill the stale answer and hand the client SERVFAIL, while cutting at one
    /// upstream timeout is too harsh, because a background refresh has no outer
    /// wrapper and its UDP chain runs to roughly 2.33 upstream timeouts.
    #[tokio::test]
    async fn the_serve_stale_wait_is_bounded_by_the_remaining_request_budget() {
        const UPSTREAM_TIMEOUT_MS: u64 = 200;
        const CLIENT_WAIT_MS: u64 = 1500;

        let engine = build_test_engine();
        engine.reload(runtime_with_settings(GlobalSettings {
            // TEST-NET-1：可路由地发出去、永远没有应答
            // TEST-NET-1: the datagram leaves and nothing ever answers
            default_upstream: "192.0.2.1:53".to_string(),
            serve_stale: true,
            serve_stale_client_timeout_ms: CLIENT_WAIT_MS,
            upstream_timeout_ms: UPSTREAM_TIMEOUT_MS,
            ..Default::default()
        }));

        let dedupe_hash = stale_com_keys(&engine).slot;
        engine.cache_insert(dedupe_hash, stale_entry("default"));

        let packet = stale_com_query();
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let start = Instant::now();
        let _ = engine.handle_packet(&packet, peer).await;
        let elapsed = start.elapsed();

        // request_timeout_ms 未配置，按 upstream * 2.5 推导为 500 ms
        // request_timeout_ms is unset, so it derives to 500 ms as upstream * 2.5
        let budget = Duration::from_millis(UPSTREAM_TIMEOUT_MS * 5 / 2);
        assert!(
            elapsed < Duration::from_millis(CLIENT_WAIT_MS / 2),
            "the wait must be bounded by the {budget:?} request budget, \
             not the {CLIENT_WAIT_MS} ms client wait; took {elapsed:?}"
        );
        // 明显高于一次上游超时、明显低于预算，才能把"按 T 截断"和"按预算截断"
        // 区分开：前者约 200 ms，后者约 480 ms。
        // Sits well above one upstream timeout and well below the budget, which
        // is what separates cutting at T (about 200 ms) from cutting at the
        // budget (about 480 ms).
        let cut_at_one_upstream_timeout = Duration::from_millis(UPSTREAM_TIMEOUT_MS * 7 / 4);
        assert!(
            elapsed >= cut_at_one_upstream_timeout,
            "the wait must not be cut at one {UPSTREAM_TIMEOUT_MS} ms upstream timeout, \
             which would end refreshes that still had budget left; took {elapsed:?}"
        );
    }

    /// serve_stale 等设置曾在构造 Engine 时拷贝，热重载改不动；这里断言重载后的
    /// 新值立刻生效：serve_stale 打开后过期条目必须保留下来供兜底。
    /// serve_stale and friends used to be copied when the Engine was built, so a
    /// reload could not change them; assert the reloaded value takes effect at
    /// once: with serve_stale on, an expired entry must be kept for fallback.
    #[tokio::test]
    async fn reloaded_serve_stale_setting_keeps_expired_entries() {
        let engine = build_test_engine();
        engine.reload(runtime_with_settings(GlobalSettings {
            default_upstream: TEST_UPSTREAM.to_string(),
            serve_stale: true,
            ..Default::default()
        }));

        let dedupe_hash = stale_com_keys(&engine).slot;
        engine.cache_insert(dedupe_hash, stale_entry("default"));

        let packet = stale_com_query();
        let peer = "127.0.0.1:12345".parse().unwrap();
        engine.handle_packet_fast(&packet, peer);

        assert!(
            engine.cached(dedupe_hash).is_some(),
            "serve_stale enabled by the reload must keep the expired entry"
        );
    }

    /// 存了 `age` 秒、TTL 等于 `cache_max_ttl` 的应答，上游又答不了：客户端是不是还拿到它
    /// An answer stored `age` seconds ago with a TTL equal to `cache_max_ttl`, with an upstream
    /// that cannot answer: whether the client still gets it
    async fn answers_after(engine: &Engine, cache_max_ttl: u32, age: u64) -> bool {
        let name = Name::from_str("stale.com.").unwrap();
        let mut answer = Message::new(0, MessageType::Response, OpCode::Query);
        answer.add_query(Query::query(name.clone(), RecordType::A));
        answer.add_answer(Record::from_rdata(
            name,
            cache_max_ttl,
            RData::A(std::net::Ipv4Addr::new(192, 0, 2, 7).into()),
        ));
        let then = Instant::now() - Duration::from_secs(age);
        engine.cache_insert(
            stale_com_keys(engine).slot,
            Arc::new(CacheEntry {
                bytes: Bytes::from(answer.to_vec().unwrap()),
                inserted_at: then,
                original_ttl: cache_max_ttl,
                ..(*stale_entry("default")).clone()
            }),
        );
        // 缓存里存的是 RD 位置上的查询的应答 / The cache holds the answer to a query with RD set
        let mut query = stale_com_query();
        query[2] = 0x01;
        let reply = engine
            .handle_packet(&query, "127.0.0.1:12345".parse().unwrap())
            .await
            .unwrap();
        !Message::from_bytes(&reply).unwrap().answers.is_empty()
    }

    /// 只有全局设置的引擎：TTL 上限 2 秒，`serve_stale`、`stale` 如给定
    /// An engine of global settings alone: a TTL cap of 2 seconds, `serve_stale` and `stale` as given
    fn stale_settings(serve_stale: bool, stale: u64) -> RuntimePipelineConfig {
        runtime_with_settings(GlobalSettings {
            default_upstream: DEAD_UPSTREAM.to_string(),
            upstream_timeout_ms: 100,
            cache_max_ttl: 2,
            serve_stale,
            serve_stale_expire_ttl: stale,
            ..Default::default()
        })
    }

    /// TTL 被 cache_max_ttl 封顶的应答，到期后照样能续用 serve_stale_expire_ttl 这么久；0 是不限
    /// An answer whose TTL cache_max_ttl capped can still be served stale for
    /// serve_stale_expire_ttl after it expires, 0 meaning no limit
    #[tokio::test]
    async fn serve_stale_keeps_an_answer_as_long_as_the_cap_for_its_own_window() {
        for (serve_stale, stale, age, served) in [
            (false, 10, 3, false),
            (true, 10, 3, true),
            (true, 10, 11, true),
            (true, 1, 5, false),
            (true, 0, 30, true),
        ] {
            let engine =
                Engine::new(stale_settings(serve_stale, stale), "lbl".to_string()).unwrap();
            assert_eq!(
                answers_after(&engine, 2, age).await,
                served,
                "serve_stale {serve_stale}, window {stale}, stored {age} s ago"
            );
            assert_eq!(
                engine.ttl_cap(),
                2,
                "the window does not raise the TTL an answer may carry"
            );
        }
    }

    /// 过了 TTL 还留多久跟着重载走：打开 serve_stale 后马上留到续用的时限，关掉后到 TTL 为止
    /// How long answers stay past their TTL follows a reload: as long as they may be served
    /// stale as soon as serve_stale goes on, up to their TTL once it goes off
    #[tokio::test]
    async fn a_reload_changes_how_long_answers_stay() {
        let engine = Engine::new(stale_settings(false, 10), "lbl".to_string()).unwrap();
        assert_eq!(engine.cache.kept(), Duration::ZERO);
        assert!(!answers_after(&engine, 2, 3).await);

        engine.reload(stale_settings(true, 10));
        assert_eq!(engine.cache.kept(), Duration::from_secs(10));
        assert!(answers_after(&engine, 2, 3).await);

        engine.reload(stale_settings(true, 0));
        assert_eq!(engine.cache.kept(), Duration::from_secs(u64::MAX));

        engine.reload(stale_settings(false, 10));
        assert_eq!(engine.cache.kept(), Duration::ZERO);
        assert_eq!(engine.ttl_cap(), 2);
    }

    /// 一条 `stale.com` 的 A 查询。 / A query for `stale.com` A.
    fn stale_com_query() -> Vec<u8> {
        let mut packet = vec![0u8; 12];
        packet[0] = 0xAA;
        packet[1] = 0xBB;
        packet[5] = 1;
        packet.extend_from_slice(b"\x05stale\x03com\x00\x00\x01\x00\x01");
        packet
    }

    /// 没有人监听的本机端口：查询被拒或得不到应答，不会发到机器外面。
    /// A local port nobody listens on: queries are refused or go unanswered, and
    /// nothing leaves the machine.
    const DEAD_UPSTREAM: &str = "127.0.0.1:9";

    /// 只有一个死上游、上游超时很短的引擎，以及 `stale.com` 查询的去重 hash。
    /// An engine whose only upstream is dead, with a short upstream timeout, plus
    /// the dedupe hash of the `stale.com` query.
    fn engine_without_an_answering_upstream(serve_stale: bool) -> (Engine, u64) {
        let engine = Engine::new(
            runtime_with_settings(GlobalSettings {
                default_upstream: DEAD_UPSTREAM.to_string(),
                upstream_timeout_ms: 100,
                serve_stale,
                serve_stale_ttl_reset: true,
                ..Default::default()
            }),
            "lbl".to_string(),
        )
        .expect("initialize engine");

        let dedupe_hash = stale_com_keys(&engine).slot;
        (engine, dedupe_hash)
    }

    /// 上游失败只记一条 warn，带着查询名、规则组和失败的完整原因（上游是没回答、拒绝了连接还是别的什么）：回 SERVFAIL 的、
    /// 执行 miss 动作的、响应动作转发失败的都一样。只问了一个上游时不说「所有上游」，也不带每次都一样的 RCODE 字段和规则写的
    /// 默认传输（写了前缀的上游不走它）。以前只问一个上游时 `forward_upstream` 先记一条不带查询名的，调用方再记一条，原因前头
    /// 是「all upstreams failed」
    /// An upstream failure logs one warning, with the query name, the pipeline and the failure's
    /// whole cause (whether the upstream did not answer, refused the connection or what else):
    /// answering SERVFAIL, running the miss actions, or a response action's forward failing
    /// alike. With one upstream asked it says nothing of "all upstreams", and carries no RCODE
    /// field that is the same every time nor the rule's default transport (which an upstream
    /// written with a scheme does not take). With one upstream asked, `forward_upstream` used to
    /// log one first without the query name, the caller another, its cause led by "all
    /// upstreams failed"
    #[tokio::test]
    async fn an_upstream_failure_is_logged_once_with_its_cause() {
        let answering = support::answering_upstream(std::net::Ipv4Addr::new(192, 0, 2, 1), 300)
            .await
            .address;
        let dead = serde_json::json!([{ "type": "forward", "upstream": DEAD_UPSTREAM }]);
        let fallback = serde_json::json!([{ "type": "static_ip_response", "ip": "192.0.2.9" }]);
        let cases = [
            (
                "SERVFAIL",
                serde_json::json!({ "name": "r", "matchers": [{ "type": "any" }], "actions": dead.clone() }),
                "upstream_failure",
                "upstream failed",
            ),
            (
                "the miss actions",
                serde_json::json!({
                    "name": "r", "matchers": [{ "type": "any" }], "actions": dead.clone(),
                    "response_actions_on_miss": fallback
                }),
                "miss_actions_on_upstream_failure",
                "upstream failed, running the miss actions",
            ),
            (
                "a response action's forward",
                serde_json::json!({
                    "name": "r", "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "forward", "upstream": answering }],
                    "response_actions_on_match": dead.clone()
                }),
                "response_action_failure",
                "response action forward failed",
            ),
        ];
        for (path, rule, event, message) in cases {
            let engine = support::engine_from(serde_json::json!({
                "settings": { "default_upstream": DEAD_UPSTREAM, "upstream_timeout_ms": 100 },
                "pipelines": [{ "id": "main", "rules": [rule] }]
            }));
            let (warnings, guard) = support::Warnings::capture();
            engine
                .handle_packet(&stale_com_query(), "127.0.0.1:12345".parse().unwrap())
                .await
                .expect("answered");
            drop(guard);
            let lines = warnings.lines();
            assert_eq!(lines.len(), 1, "{path}: {lines:#?}");
            let line = &lines[0];
            for part in [
                format!("event=\"{event}\""),
                format!("{message} "),
                "qname=stale.com".to_owned(),
                "pipeline=main".to_owned(),
                "upstream failed: ".to_owned(),
            ] {
                assert!(line.contains(&part), "{path}: {part} in {line}");
            }
            for absent in ["all upstreams", "transport=", "rcode="] {
                assert!(!line.contains(absent), "{path}: {absent} in {line}");
            }
        }
    }

    /// The keys of the `stale.com` query in the default pipeline / 默认 pipeline 里 `stale.com` 查询的键
    fn stale_com_keys(engine: &Engine) -> CacheKeys {
        stale_com_question(engine).keys()
    }

    /// The question of the `stale.com` query in the default pipeline
    /// 默认 pipeline 里 `stale.com` 查询的问题
    fn stale_com_question(engine: &Engine) -> KeyedQuestion<'static> {
        KeyedQuestion {
            flags: crate::proto_utils::QueryFlags::RECURSIVE,
            namespace: engine.state.load().cache_namespace("default"),
            pipeline_id: "default",
            qname: b"stale.com",
            qtype: RecordType::A,
            qclass: DNSClass::IN,
            requester: crate::matcher::RequesterKey::NONE,
            client_ecs: None,
        }
    }

    fn engine_from_json(raw: serde_json::Value) -> Engine {
        let config: crate::config::PipelineConfig =
            serde_json::from_value(raw).expect("parse config");
        Engine::new(
            RuntimePipelineConfig::from_config(config).expect("build runtime config"),
            "lbl".to_string(),
        )
        .expect("initialize engine")
    }

    /// 一条已经过期的 `stale.com` 缓存条目。 / An expired `stale.com` cache entry.
    fn stale_entry(pipeline_id: &str) -> Arc<CacheEntry> {
        Arc::new(CacheEntry {
            flags: crate::proto_utils::QueryFlags::RECURSIVE,
            bytes: Bytes::from_static(b"old_resp"),
            rcode: ResponseCode::NoError,
            upstream: None,
            qname: Arc::from("stale.com"),
            pipeline_id: Arc::from(pipeline_id),
            qtype: u16::from(RecordType::A),
            qclass: u16::from(DNSClass::IN),
            inserted_at: Instant::now() - Duration::from_secs(10),
            original_ttl: 5,
            reach: Default::default(),
            fetched_at: Instant::now(),
        })
    }

    /// 一条查询的原始字节：`labels` 是问题名的各个标签，`additional` 接在问题后面
    /// A query's raw bytes: `labels` make up the question name, `additional` follows the question
    fn static_query(
        id: u16,
        flags: [u8; 2],
        labels: &[Vec<u8>],
        qtype: u16,
        qclass: u16,
        additional: (u16, &[u8]),
    ) -> Vec<u8> {
        let mut packet = id.to_be_bytes().to_vec();
        packet.extend_from_slice(&flags);
        packet.extend_from_slice(&[0, 1, 0, 0, 0, 0]);
        packet.extend_from_slice(&additional.0.to_be_bytes());
        for label in labels {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label);
        }
        packet.push(0);
        packet.extend_from_slice(&qtype.to_be_bytes());
        packet.extend_from_slice(&qclass.to_be_bytes());
        packet.extend_from_slice(additional.1);
        packet
    }

    /// 这条查询下，写成字节的和 hickory 搭出来再规整的一字不差。写不了（None）的走老路，也算对。交回比了几回
    /// For this query, what is written as bytes is byte for byte what hickory builds and shaping then does.
    /// What cannot be written (None) goes the old way, which is right too. Gives how many were compared
    fn static_reply_agrees(packet: &[u8]) -> usize {
        const ANSWERS: [(ResponseCode, &str); 8] = [
            (ResponseCode::NoError, ""),
            (ResponseCode::NXDomain, ""),
            (ResponseCode::Refused, ""),
            (ResponseCode::ServFail, ""),
            (ResponseCode::NoError, "192.0.2.1"),
            (ResponseCode::NoError, "2001:db8::1"),
            (ResponseCode::NoError, "192.0.2.1,2001:db8::1,198.51.100.7"),
            (ResponseCode::NoError, "0.0.0.0,::"),
        ];
        let mut buffer = [0u8; 256];
        let Some(q) = parse_quick(packet, &mut buffer) else {
            return 0;
        };
        let text = q.qname;
        let qtype = RecordType::from(q.qtype);
        let subnet = q.client_subnet.as_ref();
        let mut compared = 0;
        for (rcode, ips) in ANSWERS {
            let (rcode, records) = if ips.is_empty() {
                (rcode, Vec::new())
            } else {
                make_static_ip_answer(text, qtype, DNSClass::from(q.qclass), ips)
            };
            let addresses = if ips.is_empty() {
                Vec::new()
            } else {
                crate::matcher::static_ips(ips).unwrap()
            };
            let old = || {
                let built = super::super::response::hickory_static_reply(
                    packet,
                    text,
                    qtype,
                    DNSClass::from(q.qclass),
                    rcode,
                    &records,
                )
                .expect("what can be written can be built");
                shaped_static_reply(
                    crate::proto_utils::reply_as_asked(built, packet),
                    packet,
                    subnet,
                )
            };
            for written in [
                write_static_reply(
                    packet,
                    rcode,
                    StaticAddresses::Configured(&addresses, qtype),
                ),
                write_static_reply(packet, rcode, StaticAddresses::Records(&records)),
            ]
            .into_iter()
            .flatten()
            {
                let expected = old();
                assert_eq!(
                    shaped_static_reply(written, packet, subnet),
                    expected,
                    "{text} {qtype:?} {rcode:?} {ips}: {packet:?}"
                );
                compared += 1;
            }
        }
        compared
    }

    /// 随机的名字（大小写、要转义的字节、点和反斜杠、零字节）、类型、类别、查询位、EDNS、ECS 和地址：写成字节的和 hickory
    /// 的一字不差
    /// Random names (case, bytes to escape, dots and backslashes in a label, zero bytes), types, classes, query
    /// bits, EDNS, ECS and addresses: what is written as bytes is byte for byte hickory's
    #[test]
    fn a_static_reply_written_as_bytes_is_what_hickory_builds() {
        const NAME_BYTES: &[u8] = b"abcXYZ019-_.\\ *\x00\xFF\x7F";
        const PLAIN_BYTES: &[u8] = b"abcdefXYZ0189-";
        let opt = |do_bit: u8, options: &[u8]| {
            let mut record = vec![0, 0, 41, 0x10, 0, 0, 0, do_bit, 0];
            record.extend_from_slice(&(options.len() as u16).to_be_bytes());
            record.extend_from_slice(options);
            record
        };
        let ecs = [0, 8, 0, 7, 0, 1, 24, 0, 192, 0, 2];
        let another = [0, 0, 16, 0, 1, 0, 0, 0, 0, 0, 1, 0];
        let additionals: [(u16, Vec<u8>); 6] = [
            (0, Vec::new()),
            (1, opt(0, &[])),
            (1, opt(0x80, &[])),
            (1, opt(0, &ecs)),
            (1, another.to_vec()),
            (2, [another.to_vec(), opt(0x80, &[])].concat()),
        ];
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut compared = 0;
        for _ in 0..3_000 {
            // 多数名字只有字母数字，少数带上别的字节：快速解析放弃的走不到这里 / Most names are alphanumeric and a few
            // carry other bytes: what the quick parse gives up on never gets here
            let bytes = if next() % 8 == 0 {
                NAME_BYTES
            } else {
                PLAIN_BYTES
            };
            let labels: Vec<Vec<u8>> = (0..1 + next() % 4)
                .map(|_| {
                    (0..1 + next() % 12)
                        .map(|_| bytes[(next() % bytes.len() as u64) as usize])
                        .collect()
                })
                .collect();
            let qtype = [1, 28, 255, 15, 16, 65_280][(next() % 6) as usize];
            let qclass = [1, 1, 1, 3, 255][(next() % 5) as usize];
            let flags = [(next() % 2) as u8, if next() % 2 == 0 { 0 } else { 0x10 }];
            let additional = &additionals[(next() % 6) as usize];
            compared += static_reply_agrees(&static_query(
                next() as u16,
                flags,
                &labels,
                qtype,
                qclass,
                (additional.0, &additional.1),
            ));
        }
        assert!(compared > 20_000, "{compared}");
    }

    /// 名字的边界：63 字节的标签，线上正好 255 字节的名字。写得了就和 hickory 一样
    /// The limits of a name: a 63-byte label, a name of exactly 255 bytes on the wire. What can be written is
    /// hickory's
    #[test]
    fn a_static_reply_is_written_up_to_the_longest_name() {
        let label = |len| vec![b'a'; len];
        // 63 + 1 三个，61 + 1 一个，加根，正好 255 / Three of 63 + 1, one of 61 + 1, and the root: exactly 255
        let longest = vec![label(63), label(63), label(63), label(61)];
        for labels in [vec![label(63)], longest] {
            let packet = static_query(7, [1, 0], &labels, 1, 1, (0, &[]));
            assert!(static_reply_agrees(&packet) > 0);
        }
    }

    /// 写不了的交回 None：压缩过的问题名、根名、截断的问题、要 OPT 的响应码、别的类型的记录、别的主人、别的类别
    /// What cannot be written gives None: a compressed question name, the root, a question cut short, a
    /// response code needing an OPT, records of another type, owner or class
    #[test]
    fn a_static_reply_it_cannot_write_is_left_to_hickory() {
        use hickory_proto::rr::rdata::{A, CNAME};
        use hickory_proto::rr::{Name, RData, Record};
        let none = StaticAddresses::Records(&[]);
        let name = Name::from_ascii("www.example.com.").unwrap();
        let labels = [b"www".to_vec(), b"example".to_vec(), b"com".to_vec()];
        let packet = static_query(7, [1, 0], &labels, 1, 1, (0, &[]));
        assert!(write_static_reply(&packet, ResponseCode::NoError, none).is_some());

        let mut compressed = packet[..12].to_vec();
        compressed.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1]);
        let root = static_query(7, [1, 0], &[], 1, 1, (0, &[]));
        for unwritable in [&compressed[..], &root[..], &packet[..packet.len() - 1]] {
            assert!(write_static_reply(unwritable, ResponseCode::NoError, none).is_none());
        }
        assert!(write_static_reply(&packet, ResponseCode::BADVERS, none).is_none());
        // 线上 257 字节的名字 / A name of 257 bytes on the wire
        let too_long = vec![
            vec![b'a'; 63],
            vec![b'b'; 63],
            vec![b'c'; 63],
            vec![b'd'; 63],
        ];
        let too_long = static_query(7, [1, 0], &too_long, 1, 1, (0, &[]));
        assert!(write_static_reply(&too_long, ResponseCode::NoError, none).is_none());

        let address = RData::A(A::new(192, 0, 2, 1));
        let written = |record: Record| {
            write_static_reply(
                &packet,
                ResponseCode::NoError,
                StaticAddresses::Records(&[record]),
            )
        };
        assert!(written(Record::from_rdata(name.clone(), 300, address.clone())).is_some());
        let mut upper = Record::from_rdata(name.clone(), 300, address.clone());
        upper.name = Name::from_ascii("WWW.example.com.").unwrap();
        assert!(
            written(upper).is_some(),
            "the case of the owner does not matter"
        );
        for other_owner in [
            "example.com.",
            "www.example.",
            "www.example.com.cn.",
            "ww.example.com.",
        ] {
            let owner = Name::from_ascii(other_owner).unwrap();
            assert!(written(Record::from_rdata(owner, 300, address.clone())).is_none());
        }
        let cname = RData::CNAME(CNAME(name.clone()));
        assert!(written(Record::from_rdata(name.clone(), 300, cname)).is_none());
        let mut chaos = Record::from_rdata(name, 300, address);
        chaos.dns_class = DNSClass::CH;
        assert!(written(chaos).is_none());
    }

    /// 快速路径上规则按配置答的（地址、响应码）和规则缓存答的，给出去的就是 hickory 搭的样子；CNAME 还走老路
    /// What a rule answers from the config on the fast path (addresses, a response code) and what the rule
    /// cache answers go out as hickory builds them; a CNAME still goes the old way
    #[tokio::test]
    async fn the_fast_path_answers_rules_with_written_bytes() {
        let engine = engine_from_json(serde_json::json!({
            "settings": { "default_upstream": DEAD_UPSTREAM },
            "pipelines": [{ "id": "main", "rules": [
                { "name": "ip", "matchers": [{ "type": "domain_suffix", "value": "ip.test" }],
                  "actions": [{ "type": "static_ip_response", "ip": "192.0.2.1,2001:db8::1" }] },
                { "name": "no", "matchers": [{ "type": "domain_suffix", "value": "no.test" }],
                  "actions": [{ "type": "static_response", "rcode": "NXDOMAIN" }] },
                { "name": "deny", "matchers": [{ "type": "domain_suffix", "value": "deny.test" }],
                  "actions": [{ "type": "deny" }] },
                { "name": "alias", "matchers": [{ "type": "domain_suffix", "value": "alias.test" }],
                  "actions": [{ "type": "static_cname_response", "target": "www.example.com" }] },
            ] }]
        }));
        let peer = SocketAddr::from(([10, 0, 0, 1], 53000));
        let ask = |name: &str, qtype: RecordType| {
            let mut query = Message::new(0x4242, MessageType::Query, OpCode::Query);
            query.metadata.recursion_desired = true;
            query.add_query(hickory_proto::op::Query::query(
                hickory_proto::rr::Name::from_ascii(name).unwrap(),
                qtype,
            ));
            let packet = query.to_vec().unwrap();
            let Some(FastPathResponse::Direct(reply)) = engine.handle_packet_fast(&packet, peer)
            else {
                panic!("{name} is answered on the spot");
            };
            Message::from_vec(&reply).unwrap()
        };
        // 配置里的地址读一次就留着，不用每个查询读 / The config's addresses are read once and kept, not for every query
        let state = engine.state.load_full();
        assert!(matches!(
            state.pipeline.pipelines[0].rules[0].precomputed(),
            Some(PrecomputedAction::Answer(StaticAnswer::Records(StaticRecords::Addresses(addresses)))) if addresses.len() == 2
        ));
        let a = ask("A.Ip.Test.", RecordType::A);
        assert_eq!(a.metadata.response_code, ResponseCode::NoError);
        assert_eq!(a.queries[0].name().to_string(), "A.Ip.Test.");
        assert_eq!(a.answers.len(), 1);
        assert_eq!(a.answers[0].ttl, 300);
        assert_eq!(a.answers[0].data.to_string(), "192.0.2.1");
        let aaaa = ask("a.ip.test.", RecordType::AAAA);
        assert_eq!(aaaa.answers.len(), 1);
        assert_eq!(aaaa.answers[0].data.to_string(), "2001:db8::1");
        let mx = ask("a.ip.test.", RecordType::MX);
        assert_eq!(mx.metadata.response_code, ResponseCode::NoError);
        assert!(mx.answers.is_empty());
        assert_eq!(
            ask("a.no.test.", RecordType::A).metadata.response_code,
            ResponseCode::NXDomain
        );
        assert_eq!(
            ask("a.deny.test.", RecordType::A).metadata.response_code,
            ResponseCode::Refused
        );
        let alias = ask("a.alias.test.", RecordType::A);
        assert_eq!(alias.answers.len(), 1);
        assert!(matches!(
            alias.answers[0].data,
            hickory_proto::rr::RData::CNAME(_)
        ));
    }

    /// 一个查规则缓存才答得了的引擎（用到 GeoSite 的规则留给完整路径），观察者记下规则回答；连同往规则缓存里放一条
    /// `ip.test` 静态决定的办法，交回它的键
    /// An engine that answers only from the rule cache (a rule using GeoSite is left to the full path), with
    /// an observer noting rules' answers; and a way of putting a static decision for `ip.test` in the rule
    /// cache, giving its key
    fn rule_cache_engine(observer: Arc<dyn EngineObserver>) -> Engine {
        let raw = serde_json::json!({
            "settings": { "default_upstream": DEAD_UPSTREAM },
            "pipelines": [{ "id": "main", "rules": [{
                "name": "geo",
                "matchers": [{ "type": "geo_site", "value": "nosuchtag" }],
                "actions": [{ "type": "forward", "upstream": DEAD_UPSTREAM }],
            }] }]
        });
        let config: crate::config::PipelineConfig =
            serde_json::from_value(raw).expect("parse config");
        Engine::builder(RuntimePipelineConfig::from_config(config).expect("build runtime config"))
            .observer(observer)
            .build()
            .expect("build engine")
    }

    fn put_rule_answer(
        engine: &Engine,
        expires_at: Instant,
        matched_rules: Option<&[&str]>,
        decided_by_rule: bool,
    ) -> u64 {
        let pipeline_id: Arc<str> = Arc::from("main");
        let question = crate::engine::rules::RuleQuestion::new(
            engine.state.load().cache_namespace("main"),
            &pipeline_id,
            "ip.test",
            RecordType::A,
            DNSClass::IN,
            RequesterKey::NONE,
        );
        let key = question.key;
        engine.rule_cache.insert(
            key,
            Arc::new(RuleCacheRecord {
                entry: RuleCacheEntry::new(
                    &question,
                    Decision::Static {
                        rcode: ResponseCode::NXDomain,
                        answers: Vec::new(),
                    },
                    expires_at,
                ),
                matched_rules: matched_rules
                    .map(|rules| rules.iter().map(|rule| Arc::from(*rule)).collect()),
                decided_by_rule,
            }),
        );
        key
    }

    fn ip_test_query() -> Vec<u8> {
        let labels = [b"ip".to_vec(), b"test".to_vec()];
        static_query(7, [1, 0], &labels, 1, 1, (0, &[]))
    }

    /// 记下每条规则回答的命中规则和是不是规则定的 / Notes each rule answer's matched rules and whether a rule decided
    #[derive(Default)]
    struct RuleAnswers(std::sync::Mutex<Vec<(Vec<String>, bool)>>);

    impl EngineObserver for RuleAnswers {
        fn answered_by_rule(
            &self,
            _ctx: &RequestContext<'_>,
            _pipeline: &str,
            answer: &RuleAnswer<'_>,
            _outcome: &RequestOutcome<'_>,
        ) -> bool {
            let rules = answer.rules.iter().map(ToString::to_string).collect();
            self.0.lock().unwrap().push((rules, answer.decided_by_rule));
            true
        }
    }

    /// 规则缓存里的条目，有规则定的才说是规则定的：记下的规则只是一路命中的、一条规则也没记下时都不算
    /// An entry in the rule cache says a rule decided only when one did: not when the rules recorded merely
    /// matched on the way, nor with no rule recorded
    #[tokio::test]
    async fn a_rule_cache_answer_says_whether_a_rule_decided() {
        let observer = Arc::new(RuleAnswers::default());
        let engine = rule_cache_engine(observer.clone());
        let peer = SocketAddr::from(([10, 0, 0, 1], 53000));
        for (rules, decided_by_rule, expected) in [
            (Some(&["first", "block"][..]), true, true),
            (Some(&["first"][..]), false, false),
            (None, true, false),
        ] {
            put_rule_answer(
                &engine,
                Instant::now() + RULE_CACHE_MAX_AGE,
                rules,
                decided_by_rule,
            );
            let answered = engine.handle_packet_fast(&ip_test_query(), peer);
            assert!(matches!(answered, Some(FastPathResponse::Direct(_))));
            let (seen, decided) = observer.0.lock().unwrap().pop().unwrap();
            assert_eq!(decided, expected, "{rules:?}");
            assert_eq!(seen.len(), rules.map_or(0, <[&str]>::len));
        }
    }

    /// 规则缓存里过期的条目不拿来答，但留在原处等求值后写回；有效的拿来答
    /// An expired entry in the rule cache does not answer but stays where it is, to be written
    /// back after evaluating; a valid one answers
    #[tokio::test]
    async fn the_fast_path_leaves_an_expired_rule_cache_entry_in_place() {
        let engine = rule_cache_engine(Arc::new(RuleAnswers::default()));
        let peer = SocketAddr::from(([10, 0, 0, 1], 53000));
        let expired = Instant::now() - Duration::from_secs(1);
        let key = put_rule_answer(&engine, expired, Some(&["block"]), true);
        let answered = engine.handle_packet_fast(&ip_test_query(), peer);
        assert!(matches!(answered, Some(FastPathResponse::AsyncNeeded(_))));
        assert!(engine.rule_cache.get(key).is_some());

        let valid = Instant::now() + RULE_CACHE_MAX_AGE;
        let key = put_rule_answer(&engine, valid, Some(&["block"]), true);
        let answered = engine.handle_packet_fast(&ip_test_query(), peer);
        assert!(matches!(answered, Some(FastPathResponse::Direct(_))));
        assert!(engine.rule_cache.get(key).is_some());
    }

    /// 落到同一个键上的条目是给别的名字的，就不拿来答，走完整路径自己求值
    /// An entry on the same key but for another name does not answer: the request takes the full path and
    /// evaluates for itself
    #[tokio::test]
    async fn the_fast_path_does_not_answer_from_an_entry_for_another_name() {
        let engine = rule_cache_engine(Arc::new(RuleAnswers::default()));
        let peer = SocketAddr::from(([10, 0, 0, 1], 53000));
        let key = put_rule_answer(
            &engine,
            Instant::now() + RULE_CACHE_MAX_AGE,
            Some(&["block"]),
            true,
        );
        let mut record = engine.rule_cache.get(key).unwrap();
        Arc::make_mut(&mut record).entry.qname = "other.test".as_bytes().into();
        engine.rule_cache.insert(key, record);
        let answered = engine.handle_packet_fast(&ip_test_query(), peer);
        assert!(matches!(answered, Some(FastPathResponse::AsyncNeeded(_))));
    }

    /// 请求编号一个线程领一批：跨过好几批、好几个线程，也没有两个一样的
    /// A thread takes request numbers in blocks: across many blocks and threads, no two are the same
    #[test]
    fn request_numbers_never_repeat_across_threads() {
        let per_thread = REQUEST_ID_BLOCK as usize * 3 + 5;
        let threads: Vec<_> = (0..8)
            .map(|_| {
                std::thread::spawn(move || {
                    (0..per_thread)
                        .map(|_| next_request_id())
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let numbers: Vec<u64> = threads
            .into_iter()
            .flat_map(|thread| thread.join().unwrap())
            .collect();
        assert_eq!(numbers.len(), 8 * per_thread);
        let distinct: std::collections::HashSet<u64> = numbers.iter().copied().collect();
        assert_eq!(distinct.len(), numbers.len());
        assert!(numbers.iter().all(|number| *number > 0));
    }

    /// 快速路径交出的是应答在缓存里实际停留的整秒数，写出去的 TTL 按它调低（RFC 1035 §5.2）
    /// The fast path hands over the whole seconds the answer really sat in the cache, and the TTLs
    /// written are lowered by them (RFC 1035 §5.2)
    #[tokio::test]
    async fn a_fast_path_hit_ages_its_ttls_by_its_time_in_the_cache() {
        use hickory_proto::op::{MessageType, OpCode, Query};
        use hickory_proto::rr::rdata::A;
        use hickory_proto::rr::{Name, RData, Record};

        let engine = engine_from_json(serde_json::json!({
            "settings": { "default_upstream": DEAD_UPSTREAM },
            "pipelines": []
        }));
        let name = Name::from_ascii("stale.com.").unwrap();
        let mut answer = Message::new(0, MessageType::Response, OpCode::Query);
        answer.add_query(Query::query(name.clone(), RecordType::A));
        let address = std::net::Ipv4Addr::new(192, 0, 2, 66);
        answer.add_answer(Record::from_rdata(name, 300, RData::A(A(address))));
        let entry = Arc::new(CacheEntry {
            bytes: Bytes::from(answer.to_vec().unwrap()),
            inserted_at: Instant::now() - Duration::from_secs(30),
            original_ttl: 300,
            ..(*stale_entry("default")).clone()
        });
        engine.cache_insert(stale_com_keys(&engine).slot, entry);
        // RD 置位，和 `QueryFlags::RECURSIVE` 一样 / RD set, as in `QueryFlags::RECURSIVE`
        let mut packet = stale_com_query();
        packet[2] = 0x01;
        let peer = SocketAddr::from(([10, 0, 0, 1], 53000));
        let Some(FastPathResponse::CacheHit {
            cached,
            tx_id,
            elapsed_secs,
        }) = engine.handle_packet_fast(&packet, peer)
        else {
            panic!("a fresh answer in the cache is a fast-path hit");
        };
        assert!((30..=31).contains(&elapsed_secs), "{elapsed_secs}");
        let mut written = bytes::BytesMut::new();
        crate::engine::write_cache_hit(&mut written, &cached, tx_id, elapsed_secs);
        let written = Message::from_vec(&written).unwrap();
        assert_eq!(written.metadata.id, 0xAABB);
        assert_eq!(written.answers[0].ttl, 300 - elapsed_secs);
    }

    /// 两个请求同时问 `stale.com`，缓存里都没有；先到的那个转发，上游不应答。这期间缓存里有了一条
    /// 过期应答，转发失败以后拿它兜底（RFC 8767），等着的那个拿到同一份，不再自己去问
    /// Two requests for `stale.com` at once, neither found in the cache; the earlier one
    /// forwards and the upstream never answers. Meanwhile an expired answer lands in the
    /// cache, which serves once the forward fails (RFC 8767); the waiting one gets the
    /// same and does not ask itself
    #[tokio::test]
    async fn waiters_get_the_stale_answer_a_failed_forward_falls_back_on() {
        use crate::engine::test_support::{ask, first_a, upstream};
        use hickory_proto::op::{MessageType, OpCode, Query};
        use hickory_proto::rr::rdata::A;
        use hickory_proto::rr::{Name, RData, Record};

        let silent = upstream(|_| Vec::new()).await;
        let engine = engine_from_json(serde_json::json!({
            "settings": {
                "default_upstream": silent.address,
                "upstream_timeout_ms": 300,
                "enable_tcp_fallback": false,
                "serve_stale": true,
                "serve_stale_client_timeout_ms": 0
            },
            "pipelines": []
        }));
        let stale = std::net::Ipv4Addr::new(192, 0, 2, 66);
        let name = Name::from_ascii("stale.com.").unwrap();
        let mut answer = Message::new(0, MessageType::Response, OpCode::Query);
        answer.add_query(Query::query(name.clone(), RecordType::A));
        answer.add_answer(Record::from_rdata(name, 5, RData::A(A(stale))));
        let entry = Arc::new(CacheEntry {
            bytes: Bytes::from(answer.to_vec().unwrap()),
            ..(*stale_entry("default")).clone()
        });
        let slot = stale_com_keys(&engine).slot;
        // RD 置位，和 `QueryFlags::RECURSIVE` 一样 / RD set, as in `QueryFlags::RECURSIVE`
        let mut packet = stale_com_query();
        packet[2] = 0x01;
        let peer = |last| SocketAddr::from(([10, 0, 0, last], 53000));
        let (one, two, ()) = tokio::join!(
            ask(&engine, &packet, peer(1)),
            ask(&engine, &packet, peer(2)),
            async {
                tokio::time::sleep(Duration::from_millis(50)).await;
                engine.cache_insert(slot, entry);
            }
        );
        assert_eq!([first_a(&one), first_a(&two)], [Some(stale); 2]);
        // 先到的那个两次 UDP 尝试（见 `upstream::hedge_timeout`）
        // The earlier one's two UDP attempts (see `upstream::hedge_timeout`)
        assert_eq!(
            silent.queries(),
            2,
            "the second request waited on the first"
        );
    }

    /// 两个请求同时问 `stale.com`，缓存里都没有；先到的那个转发，上游不应答。这期间别人往同一个槽位写进一份新鲜的应答（同时
    /// 在问、inflight 键不同的请求拿到的，或者后台刷新拿到的），转发失败以后照常交出它，开不开 serve_stale 都一样，等着的那个
    /// 也拿到同一份。以前只认过期的，两个请求都拿 SERVFAIL
    /// Two requests for `stale.com` at once, neither found in the cache; the earlier one
    /// forwards and the upstream never answers. Meanwhile someone else writes a fresh answer
    /// into the same slot (a request asking at once under another inflight key, or a background
    /// refresh), which goes out as usual once the forward fails, serve_stale on or off, and the
    /// waiting one gets the same. Only a stale one used to count, both requests getting SERVFAIL
    #[tokio::test]
    async fn a_failed_forward_answers_with_a_fresh_answer_cached_meanwhile() {
        use crate::engine::test_support::{ask, first_a, upstream};
        use hickory_proto::op::{MessageType, OpCode, Query};
        use hickory_proto::rr::rdata::A;
        use hickory_proto::rr::{Name, RData, Record};

        for serve_stale in [false, true] {
            let silent = upstream(|_| Vec::new()).await;
            let engine = engine_from_json(serde_json::json!({
                "settings": {
                    "default_upstream": silent.address,
                    "upstream_timeout_ms": 300,
                    "enable_tcp_fallback": false,
                    "serve_stale": serve_stale
                },
                "pipelines": []
            }));
            let fresh = std::net::Ipv4Addr::new(192, 0, 2, 67);
            let name = Name::from_ascii("stale.com.").unwrap();
            let mut answer = Message::new(0, MessageType::Response, OpCode::Query);
            answer.add_query(Query::query(name.clone(), RecordType::A));
            answer.add_answer(Record::from_rdata(name, 300, RData::A(A(fresh))));
            let entry = Arc::new(CacheEntry {
                bytes: Bytes::from(answer.to_vec().unwrap()),
                inserted_at: Instant::now(),
                original_ttl: 300,
                ..(*stale_entry("default")).clone()
            });
            let slot = stale_com_keys(&engine).slot;
            // RD 置位，和 `QueryFlags::RECURSIVE` 一样 / RD set, as in `QueryFlags::RECURSIVE`
            let mut packet = stale_com_query();
            packet[2] = 0x01;
            let peer = |last| SocketAddr::from(([10, 0, 0, last], 53000));
            let (one, two, ()) = tokio::join!(
                ask(&engine, &packet, peer(1)),
                ask(&engine, &packet, peer(2)),
                async {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    engine.cache_insert(slot, entry);
                }
            );
            assert_eq!(
                [first_a(&one), first_a(&two)],
                [Some(fresh); 2],
                "serve_stale {serve_stale}"
            );
        }
    }

    /// 只有 `stale.com` 一条过期应答的引擎，`settings` 决定 serve_stale 的几个设置；连同查它用的上下文
    /// An engine holding one expired answer for `stale.com`, `settings` setting the
    /// serve_stale options; with the context to look it up
    fn engine_with_a_stale_answer(settings: GlobalSettings) -> (Engine, u64) {
        let engine = Engine::new(
            runtime_with_settings(GlobalSettings {
                default_upstream: DEAD_UPSTREAM.to_string(),
                upstream_timeout_ms: 100,
                serve_stale: true,
                ..settings
            }),
            "lbl".to_string(),
        )
        .expect("initialize engine");
        let slot = stale_com_keys(&engine).slot;
        engine.cache_insert(slot, stale_entry("default"));
        (engine, slot)
    }

    /// 从 `peer` 递归地问 `stale.com` 的请求 / The request asking `stale.com` recursively from
    /// `peer`
    fn stale_com_asked(engine: &Engine, peer: SocketAddr) -> crate::engine::test_support::Asked {
        let mut packet = stale_com_query();
        // RD 置位，和条目存的 `QueryFlags::RECURSIVE` 一样 / RD set, as the entry's `QueryFlags::RECURSIVE`
        packet[2] = 0x01;
        crate::engine::test_support::Asked::new(engine, "stale.com", RecordType::A, packet, peer)
    }

    /// 过期超过 serve_stale_expire_ttl 的应答不再当作 stale 提供：查缓存、上游失败时的兜底都不用它，也都不删它，留给
    /// 重新取回的应答去取代；还在窗口里的两处都照常提供。`stale_entry` 过期了 5 秒
    /// An answer expired for longer than serve_stale_expire_ttl is no longer served
    /// stale: a lookup and the fallback after an upstream failure both pass it by, leaving it
    /// in place for the answer fetched again to replace; one still within the window serves on
    /// both. `stale_entry` expired 5 seconds ago
    #[tokio::test]
    async fn a_stale_answer_past_the_expire_window_is_not_served() {
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        for (expire_ttl, served) in [(3, false), (10, true), (0, true)] {
            let (engine, slot) = engine_with_a_stale_answer(GlobalSettings {
                serve_stale_expire_ttl: expire_ttl,
                ..Default::default()
            });
            let asked = stale_com_asked(&engine, peer);
            let request = asked.request();
            let context = request.lookup("default", slot);
            assert_eq!(
                phases::check_cache_after_failure(&engine, &context, &mut Default::default())
                    .is_some(),
                served,
                "expire_ttl {expire_ttl}: the fallback"
            );
            assert!(
                engine.cached(slot).is_some(),
                "expire_ttl {expire_ttl}: the fallback leaves the entry"
            );
            engine.cache_insert(slot, stale_entry("default"));
            assert_eq!(
                matches!(
                    phases::check_cache(&engine, &context, &mut Default::default()),
                    phases::Looked::Answered(_)
                ),
                served,
                "expire_ttl {expire_ttl}: the lookup"
            );
            assert!(
                engine.cached(slot).is_some(),
                "expire_ttl {expire_ttl}: the lookup leaves the entry"
            );
        }
    }

    /// 当作 stale 提供不动这条应答的过期计时，查缓存和上游失败时的兜底都一样，开不开 serve_stale_ttl_reset 都是：
    /// 续期只在后台刷新失败以后（见 `a_failed_refresh_renews_a_stale_answer_with_ttl_reset_on`）。以前开着时每交出
    /// 一次就重新算一次
    /// Serving an answer stale leaves its expiry alone, on a lookup and on the fallback after an
    /// upstream failure alike, with serve_stale_ttl_reset on or off: renewal comes only after a
    /// failed background refresh (see `a_failed_refresh_renews_a_stale_answer_with_ttl_reset_on`).
    /// With it on, every answer served stale used to count afresh
    #[tokio::test]
    async fn serving_stale_leaves_the_expiry_alone() {
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        for reset in [true, false] {
            for fallback in [false, true] {
                let (engine, slot) = engine_with_a_stale_answer(GlobalSettings {
                    serve_stale_ttl_reset: reset,
                    ..Default::default()
                });
                let asked = stale_com_asked(&engine, peer);
                let request = asked.request();
                let context = request.lookup("default", slot);
                let served = if fallback {
                    phases::check_cache_after_failure(&engine, &context, &mut Default::default())
                        .is_some()
                } else {
                    matches!(
                        phases::check_cache(&engine, &context, &mut Default::default()),
                        phases::Looked::Answered(_)
                    )
                };
                assert!(served, "reset {reset}, fallback {fallback}");
                let entry = engine.cached(slot).expect("still cached");
                // `stale_entry` 10 秒前写入、TTL 5 秒 / `stale_entry` went in 10 s ago with a TTL of 5 s
                let stale_for = entry.inserted_at.elapsed().as_secs() - entry.original_ttl as u64;
                assert_eq!(stale_for, 5, "reset {reset}, fallback {fallback}");
            }
        }
    }

    /// 规则据上游应答给出的 deny（REFUSED，不带上游）过期以后和上游的应答一样当作 stale 提供：查缓存、上游失败时的兜底
    /// 都用它。上游的失败应答进不了缓存（见 `Engine::insert_dns_cache_entry`），缓存里的 REFUSED 只会是它
    /// A deny the rules gave by an upstream's answer (REFUSED, with no upstream) is served stale
    /// once expired as an upstream's answer is: a lookup and the fallback after an upstream
    /// failure both use it. An upstream's failure reply never goes into the cache (see
    /// `Engine::insert_dns_cache_entry`), so a REFUSED there is only ever this
    #[tokio::test]
    async fn an_expired_deny_is_served_stale_as_any_answer() {
        let (engine, slot) = engine_without_an_answering_upstream(true);
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        for (rcode, upstream) in [
            (ResponseCode::NoError, Some(Arc::from(DEAD_UPSTREAM))),
            (ResponseCode::Refused, None),
        ] {
            let entry = Arc::new(CacheEntry {
                rcode,
                upstream,
                ..(*stale_entry("default")).clone()
            });
            let asked = stale_com_asked(&engine, peer);
            let request = asked.request();
            let context = request.lookup("default", slot);
            engine.cache_insert(slot, entry);
            assert!(
                phases::check_cache_after_failure(&engine, &context, &mut Default::default())
                    .is_some(),
                "{rcode}: the fallback"
            );
            assert!(
                matches!(
                    phases::check_cache(&engine, &context, &mut Default::default()),
                    phases::Looked::Answered(_)
                ),
                "{rcode}: the lookup"
            );
        }
    }

    /// 以后台刷新的身份处理 `stale.com` 查询，结果写入 `cache_hash`。
    /// Handle the `stale.com` query as a background refresh writing to `cache_hash`.
    async fn refresh(engine: &Engine, cache_hash: u64) -> anyhow::Result<Bytes> {
        let peer = "127.0.0.1:12345".parse().unwrap();
        engine
            .handle_refresh(
                &stale_com_query(),
                peer,
                engine.refresh_of(cache_hash),
                engine.state.load_full(),
            )
            .await
    }

    fn assert_upstream_failure(err: &anyhow::Error) {
        assert!(
            err.downcast_ref::<crate::engine::upstream::UpstreamFailure>()
                .is_some(),
            "the refresh must get the upstream failure itself, got: {err:#}"
        );
    }

    /// 所有上游都失败时，后台刷新要把失败原样交回刷新任务，由它记录，开着 serve_stale_ttl_reset 时也由它续期（见
    /// `spawn_background_refresh`）；刷新本身不动条目。以前刷新会拿过期应答（或合成的 SERVFAIL）当成功返回，任务不告警
    /// When every upstream fails, a background refresh must hand the failure back to the
    /// refresh task, which logs it and, with serve_stale_ttl_reset on, renews the entry (see
    /// `spawn_background_refresh`); the refresh itself leaves the entry alone. It used to return
    /// the stale answer (or a synthesized SERVFAIL) as a success, and the task did not warn
    #[tokio::test]
    async fn a_failed_background_refresh_reports_the_failure_and_leaves_the_entry_alone() {
        let (engine, dedupe_hash) = engine_without_an_answering_upstream(true);
        let stale = stale_entry("default");
        engine.cache_insert(dedupe_hash, stale.clone());

        let err = refresh(&engine, dedupe_hash)
            .await
            .expect_err("a refresh whose upstreams all failed must not report success");

        assert_upstream_failure(&err);
        let cached = engine
            .cached(dedupe_hash)
            .expect("a failed refresh must keep the stale entry");
        assert!(
            Arc::ptr_eq(&cached, &stale),
            "the refresh itself leaves the stale entry to the refresh task"
        );
    }

    /// 后台刷新不在 inflight 里登记，失败时也不能去完成同一 hash 下别的请求的
    /// 等待者：那个请求自己的上游查询可能会成功，它的等待者不该先收到刷新的 SERVFAIL。
    /// A background refresh never registers in `inflight`, so its failure must not
    /// complete the waiters of another request for the same hash: that request's
    /// own upstream query may still succeed, and its waiters must not get the
    /// refresh's SERVFAIL first.
    #[tokio::test]
    async fn a_failed_background_refresh_leaves_other_requests_waiters_alone() {
        let (engine, dedupe_hash) = engine_without_an_answering_upstream(false);
        // Another request registered under the inflight key a forward of this query uses
        // 另一个请求在这个查询转发时所用的 inflight 键下登记了条目
        let inflight = stale_com_keys(&engine).inflight;
        let (tx, rx) = tokio::sync::watch::channel(None);
        engine.inflight.insert(
            inflight,
            InflightEntry::new(&stale_com_question(&engine)).with_channel(tx),
        );

        let result = refresh(&engine, dedupe_hash).await;

        assert!(
            result.is_err(),
            "a refresh whose upstreams all failed must fail"
        );
        assert!(
            engine.inflight.contains_key(&inflight),
            "the other request's inflight entry must stay registered"
        );
        assert!(
            matches!(rx.has_changed(), Ok(false)),
            "the other request's waiters must not receive anything from the refresh"
        );
    }

    /// 好几个请求同时为同一个条目发起后台刷新，只刷新一次：查标记和打标记是同一步，不会两个都看见
    /// 「没在刷新」再各刷一次。上游的应答扣到所有请求都发起过才放行，刷新一直在途：以前上游 50 毫秒就答，
    /// 机器忙时晚过屏障的那个请求赶上的已是刷新结束以后，另发起一次刷新本是对的，测试却算它错
    /// Several requests starting the background refresh of one entry at once refresh it
    /// once: checking and setting the mark is a single step, so no two both see "not
    /// refreshing" and refresh each. The upstream's answer is held until every request has
    /// started, so the refresh stays in flight: the upstream used to answer in 50 ms, and on a
    /// busy machine a request late past the barrier came after the refresh had ended, rightly
    /// starting another, which the test counted against it
    #[test]
    fn concurrent_refreshes_of_one_entry_start_once() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let (up, held) = runtime.block_on(crate::engine::test_support::answering_upstream_held(
            std::net::Ipv4Addr::new(192, 0, 2, 1),
            60,
        ));
        // 引擎要在运行时里建 / The engine is built inside the runtime
        let _runtime = runtime.enter();
        let engine = Engine::new(
            runtime_with_settings(GlobalSettings {
                default_upstream: up.address.clone(),
                // 对冲重发在三分之一处，远在放行之后 / The hedged resend comes at a third of it,
                // long after the answer is let out
                upstream_timeout_ms: 30_000,
                enable_tcp_fallback: false,
                ..Default::default()
            }),
            "lbl".to_string(),
        )
        .expect("initialize engine");
        let slot = stale_com_keys(&engine).slot;
        let renewed = stale_entry("default");
        let mark = RefreshTarget::mark_of(slot, &renewed.reach);
        let requester = Requester {
            address: "127.0.0.1".parse().unwrap(),
            edns: false,
            ecs: None,
        };
        const STARTERS: usize = 8;
        for round in 1..=30 {
            held.hold();
            let barrier = std::sync::Barrier::new(STARTERS);
            std::thread::scope(|scope| {
                for _ in 0..STARTERS {
                    scope.spawn(|| {
                        let _runtime = runtime.enter();
                        barrier.wait();
                        engine.spawn_background_refresh(
                            &engine.state.load_full(),
                            &renewed,
                            slot,
                            requester,
                        );
                    });
                }
            });
            held.release();
            runtime.block_on(async {
                tokio::time::timeout(Duration::from_secs(5), async {
                    while engine.refreshing.contains_key(&mark) {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                })
                .await
                .expect("the refresh ends");
            });
            assert_eq!(up.queries(), round, "round {round}: one refresh per round");
        }
    }

    /// 失败的刷新一结束就释放刷新标记。开着 serve_stale_client_timeout_ms 时，请求
    /// 要等下一次过期命中发起的刷新；标记一直占着，它们只能等到超时再拿过期应答。
    /// A failed refresh releases its mark as soon as it ends. With
    /// serve_stale_client_timeout_ms, requests wait for the refresh the next stale
    /// hit starts; a mark held on would leave them waiting out the timeout instead.
    #[tokio::test]
    async fn a_failed_background_refresh_releases_its_mark_when_it_ends() {
        let (engine, dedupe_hash) = engine_without_an_answering_upstream(false);
        let renewed = stale_entry("default");
        let mark = RefreshTarget::mark_of(dedupe_hash, &renewed.reach);
        let marked = || engine.refreshing.contains_key(&mark);
        engine.spawn_background_refresh(
            &engine.state.load_full(),
            &renewed,
            dedupe_hash,
            Requester {
                address: "127.0.0.1".parse().unwrap(),
                edns: false,
                ecs: None,
            },
        );
        assert!(marked(), "the refresh must be marked while it runs");

        let released = tokio::time::timeout(Duration::from_secs(3), async {
            while marked() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(
            released.is_ok(),
            "a failed refresh must release its mark when it ends"
        );
    }

    /// 刷新经 response_actions_on_miss 跳到备用 Pipeline、备用上游也失败时，同样要把
    /// 失败交回刷新任务，而不是一条合成的 SERVFAIL。
    /// When a refresh jumps to a backup Pipeline through response_actions_on_miss and
    /// the backup upstream fails too, the refresh task must still get the failure,
    /// not a synthesized SERVFAIL.
    #[tokio::test]
    async fn a_failed_background_refresh_reports_the_failure_through_an_on_miss_jump() {
        let engine = engine_from_json(serde_json::json!({
            "settings": { "default_upstream": DEAD_UPSTREAM, "upstream_timeout_ms": 100 },
            "pipelines": [
                {
                    "id": "main",
                    "rules": [{
                        "name": "forward",
                        "matchers": [{ "type": "any" }],
                        "actions": [{ "type": "forward", "upstream": DEAD_UPSTREAM }],
                        "response_actions_on_miss": [
                            { "type": "jump_to_pipeline", "pipeline": "backup" }
                        ]
                    }]
                },
                {
                    "id": "backup",
                    "rules": [{
                        "name": "forward",
                        "matchers": [{ "type": "any" }],
                        "actions": [{ "type": "forward", "upstream": DEAD_UPSTREAM }]
                    }]
                }
            ]
        }));

        let err = refresh(&engine, 1)
            .await
            .expect_err("a refresh whose backup upstream also failed must not report success");

        assert_upstream_failure(&err);
    }

    /// 上游失败、on_miss 的转发也失败时，动作合成的 SERVFAIL 不能被刷新写进缓存，
    /// 盖掉它要刷新的过期条目（min_ttl 大于 0 时就会写）。
    /// When the upstream fails and the on-miss forward fails too, the SERVFAIL the
    /// actions synthesize must not be cached by the refresh over the stale entry it
    /// was refreshing, which happens whenever min_ttl is above zero.
    #[tokio::test]
    async fn a_failed_background_refresh_does_not_cache_an_on_miss_servfail() {
        let engine = engine_from_json(serde_json::json!({
            "settings": {
                "default_upstream": DEAD_UPSTREAM,
                "upstream_timeout_ms": 100,
                "min_ttl": 30,
                "serve_stale": true
            },
            "pipelines": [{
                "id": "main",
                "rules": [{
                    "name": "forward",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "forward", "upstream": DEAD_UPSTREAM }],
                    "response_actions_on_miss": [
                        { "type": "forward", "upstream": DEAD_UPSTREAM }
                    ]
                }]
            }]
        }));
        let stale = stale_entry("main");
        engine.cache_insert(1, stale.clone());

        let err = refresh(&engine, 1)
            .await
            .expect_err("a refresh whose on-miss forward also failed must not report success");

        assert_upstream_failure(&err);
        let cached = engine
            .cached(1)
            .expect("a failed refresh must keep the stale entry");
        assert!(
            Arc::ptr_eq(&cached, &stale),
            "a failed refresh must not cache SERVFAIL over the stale entry"
        );
    }

    /// `test_p` 里 `qname` 的 A 查询、请求方判定为 `requester` 的规则缓存问题 / The rule cache question
    /// of an A query for `qname` in `test_p`, the requester judged as `requester`
    fn rule_question<'a>(
        pipeline_id: &'a Arc<str>,
        qname: &'a str,
        requester: RequesterKey,
    ) -> crate::engine::rules::RuleQuestion<'a> {
        crate::engine::rules::RuleQuestion::new(
            0,
            pipeline_id,
            qname,
            RecordType::A,
            DNSClass::IN,
            requester,
        )
    }

    fn no_records() -> Decision {
        Decision::Static {
            rcode: ResponseCode::NoError,
            answers: vec![],
        }
    }

    #[test]
    fn test_rule_cache_entry_matches_respects_the_requester_key() {
        let pipeline_id: Arc<str> = Arc::from("test_p");
        let qname = "example.com";
        let entry = |requester| {
            RuleCacheEntry::new(
                &rule_question(&pipeline_id, qname, requester),
                no_records(),
                Instant::now() + RULE_CACHE_MAX_AGE,
            )
        };
        let class = |class| RequesterKey {
            class: Some(class),
            ..RequesterKey::NONE
        };
        let matches = |entry: &RuleCacheEntry, key: RequesterKey| {
            entry.answers(&rule_question(&pipeline_id, qname, key), Instant::now())
        };

        // An entry without requester facts matches only a key without them
        let shared = entry(RequesterKey::NONE);
        assert!(matches(&shared, RequesterKey::NONE));
        assert!(!matches(&shared, class(1)));

        // An entry for a requester class matches that class only
        let by_class = entry(class(1));
        assert!(matches(&by_class, class(1)));
        assert!(!matches(&by_class, class(2)));
        assert!(!matches(&by_class, RequesterKey::NONE));
    }

    /// 名字整个比，放不进记录、存到堆上的长名字也一样，差最后一个字也不算
    /// Names compare whole, also long ones stored on the heap for not fitting the record: one differing in
    /// its last character is no match
    #[test]
    fn test_rule_cache_entry_matches_only_its_whole_name() {
        let pipeline_id: Arc<str> = Arc::from("test_p");
        let long = format!("{}.example", "a".repeat(60));
        for name in ["short.example", long.as_str()] {
            let entry = RuleCacheEntry::new(
                &rule_question(&pipeline_id, name, RequesterKey::NONE),
                no_records(),
                Instant::now() + RULE_CACHE_MAX_AGE,
            );
            let matches = |asked: &str| {
                entry.answers(
                    &rule_question(&pipeline_id, asked, RequesterKey::NONE),
                    Instant::now(),
                )
            };
            assert!(matches(name));
            assert!(!matches(&format!("{}x", &name[..name.len() - 1])));
            assert!(!matches(&name[..name.len() - 1]));
        }
    }

    #[test]
    fn test_rule_cache_expiration() {
        let pipeline_id: Arc<str> = Arc::from("test_p");
        let question = rule_question(&pipeline_id, "expire.com", RequesterKey::NONE);
        let now = Instant::now();

        let expired = RuleCacheEntry::new(&question, no_records(), now - Duration::from_secs(1));
        assert!(
            !expired.answers(&question, now),
            "Expired entry should not match"
        );

        let fresh = RuleCacheEntry::new(&question, no_records(), now + RULE_CACHE_MAX_AGE);
        assert!(fresh.answers(&question, now), "Fresh entry should match");
    }

    /// 测试 DNS 响应缓存键包含 QCLASS
    #[test]
    fn test_cache_hash_includes_qclass() {
        // Arrange: Define test data
        let pipeline_id = "default";
        let qname = "example.com";
        let qtype = RecordType::A;
        let qclass_in = DNSClass::IN;
        let qclass_ch = DNSClass::CH;

        // Act: Calculate hashes for same QNAME+QTYPE but different QCLASS
        let hash_in = KeyedQuestion {
            namespace: 0,
            pipeline_id,
            qname: qname.as_bytes(),
            qtype,
            qclass: qclass_in,
            flags: crate::proto_utils::QueryFlags::RECURSIVE,
            requester: RequesterKey::NONE,
            client_ecs: None,
        }
        .slot();
        let hash_ch = KeyedQuestion {
            namespace: 0,
            pipeline_id,
            qname: qname.as_bytes(),
            qtype,
            qclass: qclass_ch,
            flags: crate::proto_utils::QueryFlags::RECURSIVE,
            requester: RequesterKey::NONE,
            client_ecs: None,
        }
        .slot();

        // Assert: Verify different QCLASS produces different hashes
        assert_ne!(
            hash_in, hash_ch,
            "Different QCLASS should produce different cache hashes"
        );

        // Act: Calculate hash for same QCLASS to verify consistency
        let hash_in2 = KeyedQuestion {
            namespace: 0,
            pipeline_id,
            qname: qname.as_bytes(),
            qtype,
            qclass: qclass_in,
            flags: crate::proto_utils::QueryFlags::RECURSIVE,
            requester: RequesterKey::NONE,
            client_ecs: None,
        }
        .slot();

        // Assert: Verify same QCLASS produces same hash
        assert_eq!(
            hash_in, hash_in2,
            "Same QCLASS should produce same cache hash"
        );
    }

    /// 测试域名大小写不敏感
    #[test]
    fn test_cache_hash_case_insensitive() {
        // Arrange: Define test data with different case variations
        let pipeline_id = "default";
        let qname_lower = "example.com";
        let qname_upper = "EXAMPLE.COM";
        let qname_mixed = "ExAmPlE.cOm";
        let qtype = RecordType::A;
        let qclass = DNSClass::IN;

        // Act: Calculate hashes for different case variations
        // Note: In parse_quick(), qname is already lowercased before being passed to this function
        // So we simulate that behavior by lowercasing the input first
        // 注意：在 parse_quick() 中，qname 在传递给此函数之前已经转为小写
        // 所以我们通过先小写输入来模拟这种行为
        let hash1 = KeyedQuestion {
            namespace: 0,
            pipeline_id,
            qname: qname_lower.to_lowercase().as_bytes(),
            qtype,
            qclass,
            flags: crate::proto_utils::QueryFlags::RECURSIVE,
            requester: RequesterKey::NONE,
            client_ecs: None,
        }
        .slot();
        let hash2 = KeyedQuestion {
            namespace: 0,
            pipeline_id,
            qname: qname_upper.to_lowercase().as_bytes(),
            qtype,
            qclass,
            flags: crate::proto_utils::QueryFlags::RECURSIVE,
            requester: RequesterKey::NONE,
            client_ecs: None,
        }
        .slot();
        let hash3 = KeyedQuestion {
            namespace: 0,
            pipeline_id,
            qname: qname_mixed.to_lowercase().as_bytes(),
            qtype,
            qclass,
            flags: crate::proto_utils::QueryFlags::RECURSIVE,
            requester: RequesterKey::NONE,
            client_ecs: None,
        }
        .slot();

        // Assert: Verify case-insensitive hashing produces same results
        assert_eq!(hash1, hash2, "QNAME hash should be case-insensitive");
        assert_eq!(hash1, hash3, "QNAME hash should be case-insensitive");
    }

    /// 测试不同 QTYPE 的哈希也不同
    #[test]
    fn test_cache_hash_different_qtype() {
        // Arrange: Define test data with different query types
        let pipeline_id = "default";
        let qname = "example.com";
        let qtype_a = RecordType::A;
        let qtype_aaaa = RecordType::AAAA;
        let qclass = DNSClass::IN;

        // Act: Calculate hashes for different QTYPE values
        let hash_a = KeyedQuestion {
            namespace: 0,
            pipeline_id,
            qname: qname.as_bytes(),
            qtype: qtype_a,
            qclass,
            flags: crate::proto_utils::QueryFlags::RECURSIVE,
            requester: RequesterKey::NONE,
            client_ecs: None,
        }
        .slot();
        let hash_aaaa = KeyedQuestion {
            namespace: 0,
            pipeline_id,
            qname: qname.as_bytes(),
            qtype: qtype_aaaa,
            qclass,
            flags: crate::proto_utils::QueryFlags::RECURSIVE,
            requester: RequesterKey::NONE,
            client_ecs: None,
        }
        .slot();

        // Assert: Verify different QTYPE produces different hashes
        assert_ne!(
            hash_a, hash_aaaa,
            "Different QTYPE should produce different cache hashes"
        );
    }

    /// 测试不同 QNAME 的哈希也不同
    #[test]
    fn test_cache_hash_different_qname() {
        // Arrange: Define test data with different domain names
        let pipeline_id = "default";
        let qname1 = "example.com";
        let qname2 = "test.com";
        let qtype = RecordType::A;
        let qclass = DNSClass::IN;

        // Act: Calculate hashes for different QNAME values
        let hash1 = KeyedQuestion {
            namespace: 0,
            pipeline_id,
            qname: qname1.as_bytes(),
            qtype,
            qclass,
            flags: crate::proto_utils::QueryFlags::RECURSIVE,
            requester: RequesterKey::NONE,
            client_ecs: None,
        }
        .slot();
        let hash2 = KeyedQuestion {
            namespace: 0,
            pipeline_id,
            qname: qname2.as_bytes(),
            qtype,
            qclass,
            flags: crate::proto_utils::QueryFlags::RECURSIVE,
            requester: RequesterKey::NONE,
            client_ecs: None,
        }
        .slot();

        // Assert: Verify different QNAME produces different hashes
        assert_ne!(
            hash1, hash2,
            "Different QNAME should produce different cache hashes"
        );
    }

    /// 快速路径和完整规则路径对同一个查询不能有不同结论。以前快速路径把 GeoIP 和
    /// GeoSite 条件一律当成不成立：越过本该决定的规则，用后面的静态规则作答；在「且非」
    /// 里则反过来让规则命中。现在两种条件都和完整规则路径一样判断，快速路径答得出的都答，
    /// 只把转发交出去。用到 GeoSite 的规则以前整条留给完整规则路径，`category-ads-all`
    /// 这样的拦截规则排在前面时，快速路径每个查询都放手。
    /// The fast path and the full rule path must not reach different decisions for
    /// one query. The fast path used to take GeoIP and GeoSite matchers as never
    /// matching: it passed over the rule that should decide and answered from a
    /// later static rule, and under `and_not` it made a rule match the other way
    /// round. Both are now judged as on the full rule path, and the fast path answers
    /// whatever it can, handing on forwards only. Rules that need GeoSite used to be
    /// left to the full rule path whole, and with a blocking rule like
    /// `category-ads-all` in front the fast path let go of every query.
    #[tokio::test]
    async fn the_fast_path_agrees_with_the_full_rule_path_on_geoip_and_geosite() {
        let forward = |name: &str, matchers: serde_json::Value| {
            serde_json::json!({
                "name": name,
                "matchers": matchers,
                "actions": [{ "type": "forward", "upstream": "127.0.0.1:9" }]
            })
        };
        let block = |name: &str, matchers: serde_json::Value| {
            serde_json::json!({
                "name": name,
                "matchers": matchers,
                "actions": [{ "type": "static_ip_response", "ip": "0.0.0.0" }]
            })
        };
        let block_rest = block("rest", serde_json::json!([{ "type": "any" }]));
        let rule_sets = [
            serde_json::json!([
                forward(
                    "public",
                    serde_json::json!([{ "type": "geoip_private", "expect": false }])
                ),
                block_rest.clone()
            ]),
            serde_json::json!([
                forward(
                    "from-jp",
                    serde_json::json!([{ "type": "geoip_country", "country_codes": ["JP"] }])
                ),
                block_rest.clone()
            ]),
            serde_json::json!([
                forward(
                    "not-cn",
                    serde_json::json!([{ "type": "geo_site_not", "value": "cn" }])
                ),
                block_rest
            ]),
            serde_json::json!([block(
                "block-not-cn",
                serde_json::json!([
                    { "type": "any" },
                    { "type": "geo_site", "value": "cn", "operator": "and_not" }
                ])
            )]),
        ];
        let dir = tempfile::tempdir().expect("temp dir");
        let geoip = dir.path().join("geoip.json");
        std::fs::write(
            &geoip,
            r#"{"entries":[{"country_code":"JP","ips":["198.51.100.0/24"]}]}"#,
        )
        .expect("write geoip");
        let mut geoip_data = crate::matcher::geoip::GeoIpManager::default();
        geoip_data.load_from_v2ray_file(&geoip).expect("load geoip");
        let mut geosite_data = crate::matcher::geosite::GeoSiteManager::default();
        geosite_data
            .load_from_v2ray_string(r#"{"entries":[{"tag":"cn","domains":["domain:example.cn"]}]}"#)
            .expect("load geosite");
        let data = crate::matcher::GeoManagers {
            geoip: Arc::new(geoip_data),
            geosite: Arc::new(geosite_data),
        };

        let mut disagreements = Vec::new();
        for rules in &rule_sets {
            let raw = serde_json::json!({
                "settings": { "default_upstream": "127.0.0.1:9" },
                "pipelines": [{ "id": "main", "rules": rules }]
            });
            let engine = engine_from(raw);
            engine.change_geo(|geo| *geo = data.clone());
            let state = engine.state.load_full();
            let pipeline = &state.pipeline.pipelines[0];

            for client in ["198.51.100.7", "203.0.113.9", "10.0.0.1"] {
                for domain in ["example.com", "example.cn"] {
                    let client_ip: IpAddr = client.parse().unwrap();
                    let case = format!("{} from {client} for {domain}", rules[0]["name"]);
                    let facts = crate::matcher::RequestFacts {
                        client_ip,
                        ..crate::matcher::RequestFacts::a_query(domain)
                    };
                    let full = engine.apply_rules(
                        &state,
                        pipeline,
                        &facts,
                        &RuleEvaluationContext::new(0, true),
                    );
                    let fast = fast_static_match(pipeline, &facts, &state.geo);
                    let agrees = match (&fast, &full) {
                        // 快速路径只把转发交出去 / The fast path hands on forwards only
                        (None, full) => !matches!(full, Decision::Static { .. }),
                        (
                            Some((PrecomputedAction::Answer(answer), _)),
                            Decision::Static {
                                rcode: full_rcode,
                                answers: full_answers,
                            },
                        ) => {
                            let (rcode, answers) =
                                answer.records(domain, RecordType::A, DNSClass::IN);
                            rcode == *full_rcode
                                && format!("{answers:?}") == format!("{full_answers:?}")
                        }
                        (Some(_), _) => false,
                    };
                    if !agrees {
                        disagreements.push(case);
                    }
                }
            }
        }
        assert!(disagreements.is_empty(), "{disagreements:#?}");
    }

    /// 快速路径只求值到最后一条能当场作答的规则：再往后不论哪条命中都交给完整路径，在这里求值它们（正则、GeoIP）是白算；
    /// 一条这样的规则都没有的 pipeline，快速路径什么都不求值
    /// The fast path evaluates rules up to the last one it can answer on the spot: whichever
    /// matches beyond it goes to the full path anyway, so evaluating them here (a regex, GeoIP)
    /// is wasted; for a pipeline with no such rule the fast path evaluates nothing
    #[test]
    fn the_fast_path_stops_at_the_last_rule_it_can_answer() {
        let rule = |name: &str, matcher: serde_json::Value, action: serde_json::Value| serde_json::json!({ "name": name, "matchers": [matcher], "actions": [action] });
        let forward = serde_json::json!({ "type": "forward", "upstream": "223.5.5.5:53" });
        let refuse = serde_json::json!({ "type": "deny" });
        let raw = serde_json::json!({
            "settings": { "default_upstream": "1.1.1.1:53" },
            "pipelines": [
                { "id": "mixed", "rules": [
                    rule("acme", serde_json::json!({ "type": "domain_regex", "value": "^_acme" }), forward.clone()),
                    rule("block", serde_json::json!({ "type": "domain_suffix", "value": "ads.test" }), refuse),
                    rule("regex", serde_json::json!({ "type": "domain_regex", "value": "^x" }), forward.clone()),
                    rule("rest", serde_json::json!({ "type": "any" }), forward.clone()),
                ] },
                { "id": "forwards", "rules": [
                    rule("rest", serde_json::json!({ "type": "any" }), forward),
                ] },
            ]
        });
        let cfg: crate::config::PipelineConfig = serde_json::from_value(raw).expect("parse config");
        let runtime = RuntimePipelineConfig::from_config(cfg).expect("runtime config");
        assert_eq!(runtime.pipelines[0].last_precomputed, Some(1));
        assert_eq!(runtime.pipelines[1].last_precomputed, None);
    }

    /// 快速路径不越过当场决定不了的规则：第一条命中的「domain_regex ^_acme → forward」连同规则顺序留给完整路径，
    /// 后面的「domain_suffix mydomain.com → static_ip」不替它作答；只命中后一条的名字照常当场作答
    /// The fast path does not pass over a rule it cannot decide on the spot: the first rule
    /// matching, "domain_regex ^_acme → forward", is left to the full path with the rule order,
    /// and the later "domain_suffix mydomain.com → static_ip" does not answer for it; a name
    /// matching the latter alone is answered on the spot as usual
    #[test]
    fn test_fast_static_match_preserves_rule_order() {
        let raw = serde_json::json!({
            "settings": { "default_upstream": "1.1.1.1:53" },
            "pipelines": [
                {
                    "id": "test",
                    "rules": [
                        {
                            "name": "acme-forward",
                            "matchers": [{ "type": "domain_regex", "value": "^_acme" }],
                            "actions": [{ "type": "forward", "upstream": "223.5.5.5:53" }]
                        },
                        {
                            "name": "mydomain-static",
                            "matchers": [{ "type": "domain_suffix", "value": "mydomain.com" }],
                            "actions": [{ "type": "static_ip_response", "ip": "192.168.16.42" }]
                        }
                    ]
                }
            ]
        });
        let cfg: crate::config::PipelineConfig = serde_json::from_value(raw).expect("parse config");
        let runtime = RuntimePipelineConfig::from_config(cfg).expect("runtime config");
        let pipeline = &runtime.pipelines[0];
        let geo = crate::matcher::GeoManagers::empty();

        let acme = crate::matcher::RequestFacts {
            qtype: RecordType::TXT,
            ..crate::matcher::RequestFacts::a_query("_acme-challenge.mydomain.com")
        };
        assert!(fast_static_match(pipeline, &acme, geo).is_none());

        let other = crate::matcher::RequestFacts::a_query("other.mydomain.com");
        match fast_static_match(pipeline, &other, geo) {
            Some((PrecomputedAction::Answer(answer), "mydomain-static")) => {
                let (rcode, answers) = answer.records(other.qname, other.qtype, other.qclass);
                assert_eq!(rcode, ResponseCode::NoError);
                assert!(!answers.is_empty());
            }
            decided => panic!("{decided:?}"),
        }
    }
}

// Multi-upstream parsing tests / 多上游解析测试
// Tests for parsing and validating multi-upstream configurations
#[cfg(test)]
#[allow(unnameable_test_items)]
mod tests_multi_upstream {
    use crate::config::Action;

    #[test]
    fn test_parse_multi_upstream_comma_separated() {
        // Arrange: Create configuration with comma-separated upstream list
        let raw = serde_json::json!({
            "pipelines": [
                {
                    "id": "p1",
                    "rules": [
                        {
                            "name": "multi",
                            "matchers": [ { "type": "any" } ],
                            "actions": [ {
                                "type": "forward",
                                "upstream": "1.1.1.1:53,8.8.8.8:53,9.9.9.9:53"
                            } ]
                        }
                    ]
                }
            ]
        });

        // Act: Parse configuration
        let cfg: crate::config::PipelineConfig = serde_json::from_value(raw).expect("parse");
        let rule = &cfg.pipelines[0].rules[0];

        // Assert: Verify upstream is parsed correctly as comma-separated string
        match &rule.actions[0] {
            Action::Forward { upstream, .. } => {
                assert_eq!(
                    upstream.as_ref().map(|s| s.as_str()),
                    Some("1.1.1.1:53,8.8.8.8:53,9.9.9.9:53"),
                    "Comma-separated upstream should be preserved"
                );
            }
            _ => panic!("expected forward action"),
        }
    }

    #[test]
    fn test_parse_multi_upstream_array() {
        // Arrange: Create configuration with array of upstreams
        let raw = serde_json::json!({
            "pipelines": [
                {
                    "id": "p1",
                    "rules": [
                        {
                            "name": "multi",
                            "matchers": [ { "type": "any" } ],
                            "actions": [ {
                                "type": "forward",
                                "upstream": ["1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"]
                            } ]
                        }
                    ]
                }
            ]
        });

        // Act: Parse configuration
        let cfg: crate::config::PipelineConfig = serde_json::from_value(raw).expect("parse");
        let rule = &cfg.pipelines[0].rules[0];

        // Assert: Verify upstream array is converted to comma-separated string
        match &rule.actions[0] {
            Action::Forward { upstream, .. } => {
                assert_eq!(
                    upstream.as_ref().map(|s| s.as_str()),
                    Some("1.1.1.1:53,8.8.8.8:53,9.9.9.9:53"),
                    "Array upstream should be joined with commas"
                );
            }
            _ => panic!("expected forward action"),
        }
    }

    #[test]
    fn test_parse_multi_upstream_empty_array() {
        // Arrange: Create configuration with empty upstream array
        let raw = serde_json::json!({
            "pipelines": [
                {
                    "id": "p1",
                    "rules": [
                        {
                            "name": "empty",
                            "matchers": [ { "type": "any" } ],
                            "actions": [ {
                                "type": "forward",
                                "upstream": []
                            } ]
                        }
                    ]
                }
            ]
        });

        // Act: Parse configuration
        let cfg: crate::config::PipelineConfig = serde_json::from_value(raw).expect("parse");
        let rule = &cfg.pipelines[0].rules[0];

        // Assert: Verify empty array results in None upstream
        match &rule.actions[0] {
            Action::Forward { upstream, .. } => {
                assert!(
                    upstream.is_none(),
                    "Empty upstream array should result in None"
                );
            }
            _ => panic!("expected forward action"),
        }
    }

    #[test]
    fn test_parse_multi_upstream_single_element() {
        // Arrange: Create configuration with single-element upstream array
        let raw = serde_json::json!({
            "pipelines": [
                {
                    "id": "p1",
                    "rules": [
                        {
                            "name": "single",
                            "matchers": [ { "type": "any" } ],
                            "actions": [ {
                                "type": "forward",
                                "upstream": ["1.1.1.1:53"]
                            } ]
                        }
                    ]
                }
            ]
        });

        // Act: Parse configuration
        let cfg: crate::config::PipelineConfig = serde_json::from_value(raw).expect("parse");
        let rule = &cfg.pipelines[0].rules[0];

        // Assert: Verify single-element array is converted to string
        match &rule.actions[0] {
            Action::Forward { upstream, .. } => {
                assert_eq!(
                    upstream.as_ref().map(|s| s.as_str()),
                    Some("1.1.1.1:53"),
                    "Single-element array should be converted to string"
                );
            }
            _ => panic!("expected forward action"),
        }
    }
}

/// 跳转之后的响应缓存：转发回来的应答存在目标 pipeline 的键下，跳转后要按这个键再查一次，
/// 否则跳转过的请求每次都去问上游。
/// The response cache after a jump: a forwarded answer is stored under the target
/// pipeline's key, so it has to be looked up again under that key after the jump;
/// otherwise a request that jumped goes upstream every time.
#[cfg(test)]
mod jump_response_cache_tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::Duration;

    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
    use hickory_proto::serialize::binary::BinDecodable;

    use crate::config::PipelineConfig;
    use crate::engine::Engine;
    use crate::engine::test_support::{self as support, Upstream, answering_upstream, engine_from};
    use crate::matcher::RuntimePipelineConfig;
    use crate::observe::{CacheHit, CacheHitKind, EngineObserver, RequestContext};

    /// 每个查询都答 `ip`（TTL 为 `ttl` 秒）的 UDP 上游，并把查询带来的 ECS 原样回显，作用范围为
    /// `scope`，像支持 ECS 的上游那样
    /// UDP upstream that answers every query with `ip` (TTL `ttl` seconds), echoing the ECS
    /// the query carries with scope `scope`, as an ECS-aware upstream does
    async fn upstream_echoing(ip: Ipv4Addr, ttl: u32, scope: u8) -> Upstream {
        use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};
        support::upstream(move |request| {
            let Some(question) = request.queries.first().cloned() else {
                return Vec::new();
            };
            let mut response =
                Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
            response.add_query(question.clone());
            response.add_answer(Record::from_rdata(
                question.name().clone(),
                ttl,
                RData::A(A(ip)),
            ));
            if let Some(EdnsOption::Subnet(subnet)) = request
                .edns
                .as_ref()
                .and_then(|edns| edns.options().get(EdnsCode::Subnet))
            {
                let mut edns = hickory_proto::op::Edns::new();
                edns.options_mut()
                    .insert(EdnsOption::Subnet(ClientSubnet::new(
                        subnet.addr(),
                        subnet.source_prefix(),
                        scope,
                    )));
                response.edns = Some(edns);
            }
            vec![(Duration::ZERO, response.to_vec().unwrap())]
        })
        .await
    }

    /// 从 `client` 查一次 `qname` 的 A 记录，返回答到的地址 / Query `qname` (A) from `client` and return the address answered
    async fn answer(engine: &Engine, qname: &str, client: &str) -> Ipv4Addr {
        ask(engine, qname, client, DNSClass::IN).await.0
    }

    /// 从 `client` 按类别 `class` 查一次 `qname` 的 A 记录，返回答到的地址和 TTL
    /// Query `qname` (A, class `class`) from `client` and return the address and TTL answered
    async fn ask(engine: &Engine, qname: &str, client: &str, class: DNSClass) -> (Ipv4Addr, u32) {
        let mut message = Message::new(0x2a2a, MessageType::Query, OpCode::Query);
        message.metadata.recursion_desired = true;
        let mut query = Query::query(Name::from_str(qname).unwrap(), RecordType::A);
        query.set_query_class(class);
        message.add_query(query);
        let peer: SocketAddr = format!("{client}:53000").parse().unwrap();
        let bytes = tokio::time::timeout(
            Duration::from_secs(5),
            engine.handle_packet(&message.to_vec().unwrap(), peer),
        )
        .await
        .expect("answered in time")
        .expect("answered");
        let response = Message::from_bytes(&bytes).unwrap();
        match response.answers.first().map(|r| (&r.data, r.ttl)) {
            Some((RData::A(address), ttl)) => (address.0, ttl),
            other => panic!("expected an A answer for {qname}, got {other:?}"),
        }
    }

    fn forward_rule(name: &str, upstream: &str) -> serde_json::Value {
        serde_json::json!({
            "name": name,
            "matchers": [{ "type": "any" }],
            "actions": [{ "type": "forward", "upstream": upstream, "transport": "udp" }]
        })
    }

    /// 入口 pipeline 只跳转、目标 pipeline 转发（面板把「交给上游组」写成的就是这种形状）：
    /// 同一个名字查三次，上游只收到第一次。以前三次都到上游。
    /// The entry pipeline only jumps and the target forwards (the shape a panel writes
    /// for "send to an upstream group"): three queries for one name reach the upstream
    /// once. All three used to reach it.
    #[tokio::test]
    async fn a_request_that_jumps_is_answered_from_the_cache() {
        let upstream = answering_upstream(Ipv4Addr::new(192, 0, 2, 1), 300).await;
        let engine = engine_from(serde_json::json!({
            "settings": { "default_upstream": "127.0.0.1:9", "min_ttl": 0 },
            "pipelines": [
                {
                    "id": "main",
                    "rules": [{
                        "name": "to-group",
                        "matchers": [{ "type": "any" }],
                        "actions": [{ "type": "jump_to_pipeline", "pipeline": "group" }]
                    }]
                },
                { "id": "group", "rules": [forward_rule("fwd", &upstream.address)] }
            ]
        }));

        for _ in 0..3 {
            assert_eq!(
                answer(&engine, "jumped.example", "192.0.2.10").await,
                Ipv4Addr::new(192, 0, 2, 1)
            );
        }
        assert_eq!(upstream.queries(), 1);
    }

    /// 入口按客户端地址跳到不同的目标时，每个目标的应答只给跳到它的请求：
    /// 两个客户端查同一个名字，各自拿到自己目标的地址，每个上游各收到一次。
    /// When the entry jumps to different targets by client address, each target's
    /// answer only serves requests that jumped to it: two clients asking for one name
    /// each get their own target's address, and each upstream is asked once.
    #[tokio::test]
    async fn cached_answers_stay_with_the_target_they_came_from() {
        let first_upstream = answering_upstream(Ipv4Addr::new(192, 0, 2, 1), 300).await;
        let second_upstream = answering_upstream(Ipv4Addr::new(192, 0, 2, 2), 300).await;
        let engine = engine_from(serde_json::json!({
            "settings": { "default_upstream": "127.0.0.1:9", "min_ttl": 0 },
            "pipelines": [
                {
                    "id": "main",
                    "rules": [
                        {
                            "name": "first-client",
                            "matchers": [{ "type": "client_ip", "cidr": "10.0.0.1/32" }],
                            "actions": [{ "type": "jump_to_pipeline", "pipeline": "first" }]
                        },
                        {
                            "name": "everyone-else",
                            "matchers": [{ "type": "any" }],
                            "actions": [{ "type": "jump_to_pipeline", "pipeline": "second" }]
                        }
                    ]
                },
                { "id": "first", "rules": [forward_rule("fwd", &first_upstream.address)] },
                { "id": "second", "rules": [forward_rule("fwd", &second_upstream.address)] }
            ]
        }));

        for _ in 0..2 {
            assert_eq!(
                answer(&engine, "shared.example", "10.0.0.1").await,
                Ipv4Addr::new(192, 0, 2, 1)
            );
            assert_eq!(
                answer(&engine, "shared.example", "10.0.0.2").await,
                Ipv4Addr::new(192, 0, 2, 2)
            );
        }
        assert_eq!(first_upstream.queries(), 1);
        assert_eq!(second_upstream.queries(), 1);
    }

    /// continue 之后才遇到的跳转：路线据过 `try-first` 问来的回答，跳过去拿到的应答缓存在入口的键下（见
    /// `Route::enter`），和回答检查跳转一样。两次查询来自两个客户端，入口按客户端地址判断，两个都在网段里、判定一样，第二个
    /// 从入口的缓存拿到，两个上游都不再问。以前跳转换成目标的键，入口这条路线从不缓存，每个请求都先问 `try-first`
    /// A jump reached only after a continue: the route has gone by the answer `try-first`
    /// fetched, and the answer got over there is cached under the entry's key (see
    /// `Route::enter`), as an answer check's jump is. The two queries come from two clients the
    /// entry judges by address, both in its network and so judged alike, and the second gets the
    /// answer from the entry's cache, neither upstream asked again. The jump used to move to the
    /// target's keys, the entry's route was never cached, and every request asked `try-first`
    /// first
    #[tokio::test]
    async fn a_jump_reached_after_a_continue_is_answered_from_the_entry_cache() {
        let first_upstream = answering_upstream(Ipv4Addr::new(192, 0, 2, 1), 300).await;
        let group_upstream = answering_upstream(Ipv4Addr::new(192, 0, 2, 2), 300).await;
        let engine = engine_from(serde_json::json!({
            "settings": { "default_upstream": "127.0.0.1:9", "min_ttl": 0 },
            "pipelines": [
                {
                    "id": "main",
                    "rules": [
                        {
                            "name": "try-first",
                            "matchers": [{ "type": "client_ip", "cidr": "192.0.2.0/24" }],
                            "actions": [{ "type": "forward", "upstream": first_upstream.address, "transport": "udp" }],
                            "response_matchers": [{ "type": "response_rcode", "value": "NXDOMAIN" }],
                            "response_actions_on_miss": [{ "type": "continue" }]
                        },
                        {
                            "name": "to-group",
                            "matchers": [{ "type": "any" }],
                            "actions": [{ "type": "jump_to_pipeline", "pipeline": "group" }]
                        }
                    ]
                },
                { "id": "group", "rules": [forward_rule("fwd", &group_upstream.address)] }
            ]
        }));

        for client in ["192.0.2.10", "192.0.2.11"] {
            assert_eq!(
                answer(&engine, "continued.example", client).await,
                Ipv4Addr::new(192, 0, 2, 2)
            );
        }
        assert_eq!(
            first_upstream.queries(),
            1,
            "the second from the entry's cache"
        );
        assert_eq!(group_upstream.queries(), 1);
    }

    /// 入口规则问 `first`（回答检查 continue），后面的规则跳到 `group` 问 `second`，`settings` 覆盖在设置上
    /// The entry's rule asks `first` (its answer check continuing), and a later rule jumps to
    /// `group`, which asks `second`, with `settings` on top of the settings
    fn continue_then_jump(
        first: &str,
        second: &str,
        settings: serde_json::Value,
    ) -> PipelineConfig {
        let mut all = serde_json::json!({ "default_upstream": "127.0.0.1:9", "min_ttl": 0 });
        for (key, value) in settings.as_object().unwrap() {
            all[key] = value.clone();
        }
        serde_json::from_value(serde_json::json!({
            "settings": all,
            "pipelines": [
                {
                    "id": "main",
                    "rules": [
                        {
                            "name": "check",
                            "matchers": [{ "type": "any" }],
                            "actions": [{ "type": "forward", "upstream": first }],
                            "response_actions_on_match": [{ "type": "continue" }]
                        },
                        {
                            "name": "to-group",
                            "matchers": [{ "type": "any" }],
                            "actions": [{ "type": "jump_to_pipeline", "pipeline": "group" }]
                        }
                    ]
                },
                { "id": "group", "rules": [forward_rule("fwd", second)] }
            ]
        }))
        .expect("parse config")
    }

    /// 同一个客户端重复查询：continue 之后得出的决策不进规则缓存（olicesx/kixdns#70），每次都从入口查起，应答从入口的缓存
    /// 给出，入口据的上游只问一次；客户端拿到的 TTL 也不比它的回答长：60 秒的回答之后 3600 秒的那份交出 60。以前每次都问
    /// `first`，客户端拿 3600，`first` 早该答别的了还在用
    /// One client asking again: a decision reached after a continue is not rule-cached
    /// (olicesx/kixdns#70), every request starts at the entry, and the answer comes from the
    /// entry's cache, the upstream the entry went by asked once; nor does the client get a TTL
    /// longer than that upstream's answer: the one of 3600 seconds after one of 60 goes out with
    /// 60. `first` used to be asked every time and the client got 3600, kept on long after
    /// `first` would have answered otherwise
    #[tokio::test]
    async fn a_repeated_request_that_continues_is_answered_from_the_entry_cache() {
        let first = answering_upstream(Ipv4Addr::new(192, 0, 2, 1), 60).await;
        let second = answering_upstream(Ipv4Addr::new(192, 0, 2, 2), 3600).await;
        let engine = Engine::new(
            RuntimePipelineConfig::from_config(continue_then_jump(
                &first.address,
                &second.address,
                serde_json::json!({}),
            ))
            .expect("build runtime config"),
            "test".to_string(),
        )
        .expect("engine");
        for round in 0..5 {
            let (address, ttl) =
                ask(&engine, "continued.example", "192.0.2.10", DNSClass::IN).await;
            assert_eq!(address, Ipv4Addr::new(192, 0, 2, 2), "round {round}");
            assert!((59..=60).contains(&ttl), "round {round}: TTL {ttl}");
        }
        assert_eq!(first.queries(), 1);
        assert_eq!(second.queries(), 1);
    }

    /// 记下客户端请求拿到的过期应答是哪一种 / Records which kind of stale answer client requests got
    #[derive(Default)]
    struct StaleKinds(parking_lot::Mutex<Vec<CacheHitKind>>);

    impl EngineObserver for StaleKinds {
        fn cache_hit(&self, ctx: &RequestContext<'_>, event: &CacheHit<'_>) {
            if !ctx.background_refresh && event.kind != CacheHitKind::Fresh {
                self.0.lock().push(event.kind);
            }
        }
    }

    /// continue 之后跳过去拿到的应答过期以后，入口据的上游没有回答时照 serve_stale 交出这份过期应答（RFC 8767）：客户端
    /// 先等刷新，刷新去问入口据的 `first`，`first` 不回答，刷新失败，交出的是上游失败时的过期应答
    /// Once the answer got through a jump after a continue has expired, with the upstream the
    /// entry goes by not answering, serve_stale gives that expired answer (RFC 8767): the client
    /// waits on the refresh first, the refresh asks `first`, which the entry goes by, `first`
    /// does not answer, the refresh fails, and what goes out is the stale answer of an upstream
    /// failure
    #[tokio::test]
    async fn a_jump_after_a_continue_serves_stale_when_the_checked_upstream_fails() {
        let first = answering_upstream(Ipv4Addr::new(192, 0, 2, 1), 1).await;
        let second = answering_upstream(Ipv4Addr::new(192, 0, 2, 2), 1).await;
        let kinds = Arc::new(StaleKinds::default());
        let config = continue_then_jump(
            &first.address,
            &second.address,
            serde_json::json!({
                "serve_stale": true,
                "upstream_timeout_ms": 200,
                "serve_stale_client_timeout_ms": 1000
            }),
        );
        let engine =
            Engine::builder(RuntimePipelineConfig::from_config(config).expect("runtime config"))
                .observer(kinds.clone())
                .build()
                .expect("engine");
        answer(&engine, "continued.example", "192.0.2.10").await;
        // TTL 按整秒算：过了 1 秒就过期 / TTLs go by whole seconds: past 1 second it has expired
        tokio::time::sleep(Duration::from_millis(1100)).await;
        first.silence(true);
        let asked = first.queries();
        let (address, ttl) = ask(&engine, "continued.example", "192.0.2.10", DNSClass::IN).await;
        assert_eq!(address, Ipv4Addr::new(192, 0, 2, 2));
        assert_eq!(ttl, 30, "serve_stale_ttl");
        assert!(first.queries() > asked, "the refresh asked `first`");
        assert_eq!(*kinds.0.lock(), [CacheHitKind::StaleUpstreamFailure]);
    }

    /// 目标 pipeline 按客户端判断时，跳转后按它的键查缓存：键分辨请求方，被拦下的客户端拿不到另一个客户端转发回来的
    /// 应答，放行的客户端再问时从缓存拿到，不再问上游。以前跳转后不查，放行的客户端每次都问上游
    /// A target that matches on the client is looked up after a jump by its key: the key tells
    /// requesters apart, so a client its rules block does not get the answer another client's
    /// forward stored, and a client let through gets it from the cache when asking again, with no
    /// further upstream query. Nothing used to be looked up after the jump, a client let through
    /// asking upstream every time
    #[tokio::test]
    async fn a_target_that_matches_on_the_client_serves_each_client_its_own_answer() {
        let upstream = answering_upstream(Ipv4Addr::new(192, 0, 2, 1), 300).await;
        let engine = engine_from(serde_json::json!({
            "settings": { "default_upstream": "127.0.0.1:9", "min_ttl": 0 },
            "pipelines": [
                {
                    "id": "main",
                    "rules": [{
                        "name": "to-filter",
                        "matchers": [{ "type": "any" }],
                        "actions": [{ "type": "jump_to_pipeline", "pipeline": "filter" }]
                    }]
                },
                {
                    "id": "filter",
                    "rules": [
                        {
                            "name": "block-one-client",
                            "matchers": [{ "type": "client_ip", "cidr": "10.0.0.1/32" }],
                            "actions": [{ "type": "static_ip_response", "ip": "0.0.0.0" }]
                        },
                        forward_rule("fwd", &upstream.address)
                    ]
                }
            ]
        }));

        for _ in 0..3 {
            assert_eq!(
                answer(&engine, "ads.example", "10.0.0.2").await,
                Ipv4Addr::new(192, 0, 2, 1)
            );
        }
        assert_eq!(upstream.queries(), 1, "asked once, then from the cache");
        assert_eq!(
            answer(&engine, "ads.example", "10.0.0.1").await,
            Ipv4Addr::UNSPECIFIED
        );
    }

    /// 路线上有按 EDNS 判断的 pipeline 时，跳转后照常查缓存：后台刷新照原样重放，走同一条路线（见
    /// `a_refresh_after_a_jump_through_an_edns_rule_renews_the_target_entry`）。以前不查，每次都问上游
    /// A route through a pipeline that matches on EDNS looks in the cache after the jump as
    /// usual: a background refresh replays the request as it came and takes the same route (see
    /// `a_refresh_after_a_jump_through_an_edns_rule_renews_the_target_entry`). It used not to
    /// look, asking upstream every time
    #[tokio::test]
    async fn a_route_through_an_edns_rule_is_looked_up_after_the_jump() {
        let upstream = answering_upstream(Ipv4Addr::new(192, 0, 2, 1), 300).await;
        let engine = engine_from(serde_json::json!({
            "settings": { "default_upstream": "127.0.0.1:9", "min_ttl": 0 },
            "pipelines": [
                {
                    "id": "main",
                    "rules": [
                        {
                            "name": "edns-clients",
                            "matchers": [{ "type": "edns_present", "expect": true }],
                            "actions": [{ "type": "static_ip_response", "ip": "192.0.2.9" }]
                        },
                        {
                            "name": "to-group",
                            "matchers": [{ "type": "any" }],
                            "actions": [{ "type": "jump_to_pipeline", "pipeline": "group" }]
                        }
                    ]
                },
                { "id": "group", "rules": [forward_rule("fwd", &upstream.address)] }
            ]
        }));

        for _ in 0..3 {
            assert_eq!(
                answer(&engine, "edns.example", "192.0.2.10").await,
                Ipv4Addr::new(192, 0, 2, 1)
            );
        }
        assert_eq!(upstream.queries(), 1);
    }

    /// 跳转后找到的过期应答由后台刷新，刷新写回同一个目标键：之后的请求拿到新鲜应答，
    /// 不再去问上游，也不再拿过期应答。
    /// An expired answer found after a jump is refreshed in the background, and the
    /// refresh writes back under the same target key: the next request gets a fresh
    /// answer, with no further upstream query and no stale answer.
    #[tokio::test]
    async fn a_refresh_started_after_a_jump_renews_the_target_entry() {
        let upstream = answering_upstream(Ipv4Addr::new(192, 0, 2, 1), 1).await;
        let pipelines = jump_to_group(serde_json::json!([forward_rule("fwd", &upstream.address)]));
        a_refresh_after_a_jump_renews_the_target_entry(&upstream, pipelines).await;
    }

    /// 路线上有按 EDNS 判断的规则时也一样：刷新照原样（不带 EDNS）重放，走同一条路线，写回同一个目标键。以前
    /// 跳转后不查缓存，每次都问上游
    /// Likewise with a rule on the route matching on EDNS: the refresh replays the request as
    /// it came (without EDNS), takes the same route and writes back under the same target key.
    /// The lookup after a jump used to be off, asking upstream every time
    #[tokio::test]
    async fn a_refresh_after_a_jump_through_an_edns_rule_renews_the_target_entry() {
        let upstream = answering_upstream(Ipv4Addr::new(192, 0, 2, 1), 1).await;
        let mut pipelines =
            jump_to_group(serde_json::json!([forward_rule("fwd", &upstream.address)]));
        pipelines[0]["rules"].as_array_mut().unwrap().insert(
            0,
            serde_json::json!({
                "name": "edns-clients",
                "matchers": [{ "type": "edns_present", "expect": true }],
                "actions": [{ "type": "static_ip_response", "ip": "192.0.2.9" }]
            }),
        );
        a_refresh_after_a_jump_renews_the_target_entry(&upstream, pipelines).await;
    }

    /// `pipelines`（先跳到 `group`，再由它转发给 `upstream`）下，跳转后找到的过期应答由后台刷新写回同一个目标键
    /// Under `pipelines` (a jump to `group`, which forwards to `upstream`), an expired answer
    /// found after the jump is renewed by a background refresh under the same target key
    async fn a_refresh_after_a_jump_renews_the_target_entry(
        upstream: &Upstream,
        pipelines: serde_json::Value,
    ) {
        let engine = engine_from(serde_json::json!({
            "settings": {
                "default_upstream": "127.0.0.1:9",
                "min_ttl": 0,
                "serve_stale": true,
                "serve_stale_ttl": 30,
                "serve_stale_client_timeout_ms": 0
            },
            "pipelines": pipelines
        }));

        answer(&engine, "renew.example", "192.0.2.10").await;
        assert_eq!(upstream.queries(), 1);
        tokio::time::sleep(Duration::from_millis(1200)).await;

        // 过期：立刻给过期应答，后台刷新去问上游 / Expired: the stale answer goes out at once and a background refresh asks upstream
        answer(&engine, "renew.example", "192.0.2.10").await;
        let refreshed = tokio::time::timeout(Duration::from_secs(3), async {
            while upstream.queries() < 2 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(
            refreshed.is_ok(),
            "the background refresh never asked upstream"
        );

        // 刷新写回了目标键：很快就拿到新鲜应答（TTL 不超过上游给的 1 秒；过期应答的 TTL 是 30），
        // 而且不再去问上游
        // The refresh wrote back under the target key: a fresh answer arrives shortly (TTL at
        // most the upstream's 1 s; a stale answer carries 30), with no further upstream query
        let fresh = tokio::time::timeout(Duration::from_secs(3), async {
            while ask(&engine, "renew.example", "192.0.2.10", DNSClass::IN)
                .await
                .1
                > 1
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(
            fresh.is_ok(),
            "no fresh answer after the background refresh"
        );
        assert_eq!(upstream.queries(), 2);
    }

    fn jump_to_group(group_rules: serde_json::Value) -> serde_json::Value {
        serde_json::json!([
            {
                "id": "main",
                "rules": [{
                    "name": "to-group",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "jump_to_pipeline", "pipeline": "group" }]
                }]
            },
            { "id": "group", "rules": group_rules }
        ])
    }

    /// pipeline 的选择按 EDNS 判断时，跳转后也照常查缓存：刷新照原样重放，选到的是同一个 pipeline
    /// Selection that matches on EDNS keeps the lookup after a jump too: the refresh replays the
    /// request as it came and selects the same pipeline
    #[tokio::test]
    async fn edns_in_pipeline_selection_keeps_the_lookup_after_a_jump() {
        let upstream = answering_upstream(Ipv4Addr::new(192, 0, 2, 1), 300).await;
        let engine = engine_from(serde_json::json!({
            "settings": { "default_upstream": "127.0.0.1:9", "min_ttl": 0 },
            "pipeline_select": [{
                "pipeline": "main",
                "matchers": [{ "type": "edns_present", "expect": false }]
            }],
            "pipelines": jump_to_group(serde_json::json!([forward_rule("fwd", &upstream.address)]))
        }));

        for _ in 0..2 {
            answer(&engine, "selected.example", "192.0.2.10").await;
        }
        assert_eq!(upstream.queries(), 1);
    }

    /// 类别不是 IN 的查询跳转后也照常查缓存：刷新按同一个类别重放，算出的是同一个键
    /// A query in a class other than IN looks after a jump as well: the refresh replays in the
    /// same class and computes the same key
    #[tokio::test]
    async fn a_query_outside_class_in_is_looked_up_after_a_jump_too() {
        let upstream = answering_upstream(Ipv4Addr::new(192, 0, 2, 1), 300).await;
        let engine = engine_from(serde_json::json!({
            "settings": { "default_upstream": "127.0.0.1:9", "min_ttl": 0 },
            "pipelines": jump_to_group(serde_json::json!([forward_rule("fwd", &upstream.address)]))
        }));

        for _ in 0..2 {
            ask(&engine, "chaos.example", "192.0.2.10", DNSClass::CH).await;
        }
        assert_eq!(upstream.queries(), 1);
    }

    /// 目标的转发按客户端地址带 ECS 子网时，跳转后照常查缓存，但按一个子网定制的应答（作用
    /// 范围 /24）不会给另一个子网的客户端；同一个子网的客户端在跳转之后从缓存拿到它。
    /// A target whose forward sends the client's ECS subnet is looked up after a jump
    /// as usual, but an answer tailored to one subnet (scope /24) does not go to a
    /// client in another; a client in the same subnet gets it from the cache after
    /// the jump.
    #[tokio::test]
    async fn a_target_forwarding_the_client_subnet_is_not_served_across_subnets() {
        let upstream = upstream_echoing(Ipv4Addr::new(192, 0, 2, 1), 300, 24).await;
        let engine = engine_from(serde_json::json!({
            "settings": { "default_upstream": "127.0.0.1:9", "min_ttl": 0 },
            "pipelines": jump_to_group(serde_json::json!([{
                "name": "fwd",
                "matchers": [{ "type": "any" }],
                "actions": [{
                    "type": "forward",
                    "upstream": upstream.address,
                    "transport": "udp",
                    "ecs": { "mode": "from_client_ip" }
                }]
            }]))
        }));

        answer(&engine, "cdn.example", "198.51.100.10").await;
        answer(&engine, "cdn.example", "203.0.113.10").await;
        assert_eq!(upstream.queries(), 2);
        answer(&engine, "cdn.example", "198.51.100.77").await;
        assert_eq!(upstream.queries(), 2);
    }

    /// 上游的应答不带 ECS 时，按 RFC 7871 第 7.3 节当作作用范围 0：跳转后别的子网的客户端也从
    /// 缓存拿到它。
    /// A reply without ECS counts as scope 0 (RFC 7871 section 7.3): after the jump,
    /// a client in another subnet gets it from the cache too.
    #[tokio::test]
    async fn a_target_answer_without_ecs_is_shared_across_subnets() {
        let upstream = answering_upstream(Ipv4Addr::new(192, 0, 2, 1), 300).await;
        let engine = engine_from(serde_json::json!({
            "settings": { "default_upstream": "127.0.0.1:9", "min_ttl": 0 },
            "pipelines": jump_to_group(serde_json::json!([{
                "name": "fwd",
                "matchers": [{ "type": "any" }],
                "actions": [{
                    "type": "forward",
                    "upstream": upstream.address,
                    "transport": "udp",
                    "ecs": { "mode": "from_client_ip" }
                }]
            }]))
        }));

        answer(&engine, "cdn.example", "198.51.100.10").await;
        answer(&engine, "cdn.example", "203.0.113.10").await;
        assert_eq!(upstream.queries(), 1);
    }

    /// 按「谁在问」判断的四种请求匹配让 pipeline 的规则决策按请求方区分，按问题本身判断的不会
    /// The four request matchers that look at who is asking make the pipeline's rule decisions
    /// tell requesters apart, and those that look at the question do not
    #[test]
    fn pipelines_that_match_on_the_requester_tell_requesters_apart() {
        let forward = |ecs: serde_json::Value| {
            serde_json::json!({
                "name": "fwd",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": "127.0.0.1:9", "ecs": ecs }]
            })
        };
        // 转发怎样发送 ECS 都不算：因 ECS 子网而不同的应答由缓存按子网区分（见 `CacheEntry::reach`，
        // 以及 `a_target_forwarding_the_client_subnet_is_not_served_across_subnets`）。pipeline 级
        // 的 `ecs` 也不再起作用。
        // No way of sending ECS counts: answers that differ by ECS subnet are told apart
        // by the cache (see `CacheEntry::reach`, and
        // `a_target_forwarding_the_client_subnet_is_not_served_across_subnets`). The
        // pipeline-level `ecs` no longer counts either.
        let ecs_cases = [
            (
                serde_json::json!({ "id": "p", "rules": [forward(serde_json::json!({ "mode": "from_client_ip" }))] }),
                false,
            ),
            (
                serde_json::json!({
                    "id": "p",
                    "ecs": { "mode": "from_client_ip", "prefix_v4": 16 },
                    "rules": [forward(serde_json::json!({ "mode": "from_client_ip" }))]
                }),
                false,
            ),
            (
                serde_json::json!({ "id": "p", "rules": [forward(serde_json::json!({ "mode": "static", "ip": "198.51.100.0" }))] }),
                false,
            ),
        ];
        for (pipeline, requester) in ecs_cases {
            let config: PipelineConfig = serde_json::from_value(serde_json::json!({
                "settings": { "default_upstream": "127.0.0.1:9" },
                "pipelines": [pipeline.clone()]
            }))
            .expect("parse config");
            let runtime = RuntimePipelineConfig::from_config(config).expect("runtime config");
            assert_eq!(
                !runtime.pipelines[0].rule_requester.tests().is_empty(),
                requester,
                "{pipeline}"
            );
        }

        let cases = [
            (
                serde_json::json!({ "type": "client_ip", "cidr": "10.0.0.0/8" }),
                true,
            ),
            (
                serde_json::json!({ "type": "geoip_country", "country_codes": ["cn"] }),
                true,
            ),
            (
                serde_json::json!({ "type": "geoip_private", "expect": true }),
                true,
            ),
            (
                serde_json::json!({ "type": "edns_present", "expect": true }),
                true,
            ),
            (
                serde_json::json!({ "type": "domain_suffix", "value": "example.com" }),
                false,
            ),
            (serde_json::json!({ "type": "qtype", "value": "A" }), false),
            (serde_json::json!({ "type": "any" }), false),
        ];
        for (matcher, requester) in cases {
            let config: PipelineConfig = serde_json::from_value(serde_json::json!({
                "settings": { "default_upstream": "127.0.0.1:9" },
                "pipelines": [{
                    "id": "main",
                    "rules": [{
                        "name": "r",
                        "matchers": [matcher.clone()],
                        "actions": [{ "type": "static_ip_response", "ip": "192.0.2.1" }]
                    }]
                }]
            }))
            .expect("parse config");
            let runtime = RuntimePipelineConfig::from_config(config).expect("runtime config");
            let pipeline = &runtime.pipelines[0];
            assert_eq!(
                !pipeline.rule_requester.tests().is_empty(),
                requester,
                "{matcher}"
            );
        }
    }
}

/// 应答取决于请求方时，缓存、inflight 和规则缓存都按请求方分开。
/// When the answer depends on the requester, the response cache, inflight and the
/// rule cache keep requesters apart.
#[cfg(test)]
mod requester_scope_tests {
    use super::*;
    use crate::engine::rules::calculate_rule_hash;
    use crate::matcher::RequesterTest;
    use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query};
    use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    use crate::engine::test_support::{
        self as support, Upstream, answering_upstream, answering_upstream_after,
    };

    const SINK: Ipv4Addr = Ipv4Addr::UNSPECIFIED;
    const NORMAL: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 20);
    const OTHER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 30);

    const NO_SUBNET: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 99);

    /// 按查询带来的 ECS 子网作答的本机上游：应答的地址就是子网地址，没有 ECS 时是
    /// NO_SUBNET。像按子网作答的上游那样回显查询的 ECS，作用范围就是查询的前缀。并计数。
    /// A local upstream that answers with the ECS subnet the query carries, or
    /// NO_SUBNET without one, echoing the query's ECS with its prefix as the scope
    /// as an upstream answering per subnet does, counting the queries.
    async fn subnet_echo() -> Upstream {
        support::upstream(|query| {
            let Some(question) = query.queries.first().cloned() else {
                return Vec::new();
            };
            let sent =
                query
                    .edns
                    .as_ref()
                    .and_then(|edns| match edns.options().get(EdnsCode::Subnet) {
                        Some(EdnsOption::Subnet(subnet)) => Some(*subnet),
                        _ => None,
                    });
            let subnet = match sent.map(|subnet| subnet.addr()) {
                Some(IpAddr::V4(v4)) => v4,
                _ => NO_SUBNET,
            };
            let mut resp = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
            resp.add_query(question.clone());
            resp.add_answer(Record::from_rdata(
                question.name().clone(),
                300,
                RData::A(hickory_proto::rr::rdata::A(subnet)),
            ));
            if let Some(sent) = sent {
                let mut edns = Edns::new();
                edns.options_mut().insert(EdnsOption::Subnet(
                    hickory_proto::rr::rdata::opt::ClientSubnet::new(
                        sent.addr(),
                        sent.source_prefix(),
                        sent.source_prefix(),
                    ),
                ));
                resp.edns = Some(edns);
            }
            vec![(Duration::ZERO, resp.to_vec().unwrap())]
        })
        .await
    }

    fn runtime_config(
        settings: serde_json::Value,
        pipeline_select: serde_json::Value,
        pipelines: serde_json::Value,
    ) -> RuntimePipelineConfig {
        let mut all = serde_json::json!({
            "default_upstream": "127.0.0.1:9",
            "upstream_timeout_ms": 500,
            "enable_tcp_fallback": false
        });
        all.as_object_mut()
            .unwrap()
            .extend(settings.as_object().unwrap().clone());
        let raw = serde_json::json!({
            "settings": all,
            "pipeline_select": pipeline_select,
            "pipelines": pipelines
        });
        let config: crate::config::PipelineConfig =
            serde_json::from_value(raw).expect("parse config");
        RuntimePipelineConfig::from_config(config).expect("build runtime config")
    }

    fn engine(pipeline_select: serde_json::Value, pipelines: serde_json::Value) -> Engine {
        Engine::new(
            runtime_config(serde_json::json!({}), pipeline_select, pipelines),
            "test".to_string(),
        )
        .expect("engine")
    }

    /// 同 `engine`，由 [`support::Steps`] 观察 / As `engine`, observed by [`support::Steps`]
    fn engine_observed(
        pipeline_select: serde_json::Value,
        pipelines: serde_json::Value,
    ) -> (Engine, Arc<support::Steps>) {
        support::runtime_with_steps(runtime_config(
            serde_json::json!({}),
            pipeline_select,
            pipelines,
        ))
    }

    fn rule(
        name: &str,
        matchers: serde_json::Value,
        actions: serde_json::Value,
    ) -> serde_json::Value {
        serde_json::json!({ "name": name, "matchers": matchers, "actions": actions })
    }

    fn forward(upstream: &str) -> serde_json::Value {
        serde_json::json!([{ "type": "forward", "upstream": upstream }])
    }

    fn any() -> serde_json::Value {
        serde_json::json!([{ "type": "any" }])
    }

    /// 只匹配 10.0.0.1 / Matches 10.0.0.1 alone
    fn device() -> serde_json::Value {
        serde_json::json!([{ "type": "client_ip", "cidr": "10.0.0.1/32" }])
    }

    fn query(edns: bool) -> Vec<u8> {
        let mut request = Message::new(0xBEEF, MessageType::Query, OpCode::Query);
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(
            Name::from_str("example.com").unwrap(),
            RecordType::A,
        ));
        if edns {
            request.edns = Some(Edns::new());
        }
        request.to_vec().unwrap()
    }

    /// 应答里的第一个 A 记录，请求必须得到了应答 / The first A record in the reply a request
    /// must have got
    fn first_a(response: Result<Bytes, UnreadableQuery>) -> Option<Ipv4Addr> {
        support::first_a(&response.expect("answer"))
    }

    async fn ask(engine: &Engine, client: &str, edns: bool) -> Option<Ipv4Addr> {
        let peer: SocketAddr = format!("{client}:53000").parse().unwrap();
        first_a(
            tokio::time::timeout(
                Duration::from_secs(5),
                engine.handle_packet(&query(edns), peer),
            )
            .await
            .expect("answer in time"),
        )
    }

    /// 两个客户端同时问 / Two clients asking at once
    async fn ask_at_once(engine: &Engine, clients: [&str; 2]) -> [Option<Ipv4Addr>; 2] {
        let packet = query(false);
        let [first, second] = clients.map(|client| {
            // 不带端口时用 53000 / Port 53000 when none is given
            client
                .parse::<SocketAddr>()
                .unwrap_or_else(|_| format!("{client}:53000").parse().unwrap())
        });
        let (first, second) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                engine.handle_packet(&packet, first),
                engine.handle_packet(&packet, second)
            )
        })
        .await
        .expect("answers in time");
        [first_a(first), first_a(second)]
    }

    /// `pipeline` 的各项依据，写成短名 / The tests of `pipeline`, by short name
    fn tests_of(config: &RuntimePipelineConfig, pipeline: &str) -> Vec<String> {
        config.pipelines[config.pipeline_id_index[pipeline]]
            .requester
            .tests()
            .iter()
            .map(|test| match test {
                RequesterTest::InNet(net) => format!("net {net}"),
                RequesterTest::Private => "private".to_string(),
                RequesterTest::Country(codes) => format!("country {}", codes.join(",")),
                RequesterTest::Edns => "edns".to_string(),
                RequesterTest::Subnet {
                    prefix_v4,
                    prefix_v6,
                } => format!("subnet {prefix_v4}/{prefix_v6}"),
            })
            .collect()
    }

    const UP: &str = "127.0.0.1:5353";

    fn ecs_forward(prefix_v4: u8, prefix_v6: u8) -> serde_json::Value {
        serde_json::json!([{
            "type": "forward",
            "upstream": UP,
            "ecs": { "mode": "from_client_ip", "prefix_v4": prefix_v4, "prefix_v6": prefix_v6 }
        }])
    }

    fn pipeline_ecs(prefix_v4: u8, prefix_v6: u8) -> serde_json::Value {
        serde_json::json!({ "mode": "from_client_ip", "prefix_v4": prefix_v4, "prefix_v6": prefix_v6 })
    }

    /// 转发到 UP，应答来自 UP 时执行 `on`（on_match 或 on_miss）里的跳转。
    /// Forwards to UP with `actions`, jumping to `target` from `on` (on_match or on_miss).
    fn checked(actions: serde_json::Value, on: &str, target: &str) -> serde_json::Value {
        let mut rule = rule("check", any(), actions);
        rule["response_matchers"] = serde_json::json!([{ "type": "upstream_equals", "value": UP }]);
        rule[on] = serde_json::json!([{ "type": "jump_to_pipeline", "pipeline": target }]);
        rule
    }

    #[test]
    fn a_scope_has_the_tests_the_rules_tell_requesters_apart_by() {
        let config = runtime_config(
            serde_json::json!({}),
            serde_json::json!([]),
            serde_json::json!([
                { "id": "plain", "rules": [rule("r", any(), forward(UP))] },
                { "id": "client", "rules": [rule("r", device(), forward(UP))] },
                { "id": "private", "rules": [rule("r", serde_json::json!([{ "type": "geoip_private", "expect": true }]), forward(UP))] },
                { "id": "country", "rules": [rule("r", serde_json::json!([{ "type": "geoip_country", "country_codes": ["cn"] }]), forward(UP))] },
                { "id": "edns", "rules": [rule("r", serde_json::json!([{ "type": "edns_present", "expect": true }]), forward(UP))] },
                { "id": "answer-edns", "rules": [{
                    "name": "r", "matchers": any(), "actions": forward(UP),
                    "response_matchers": [{ "type": "response_edns_present", "expect": true }],
                    "response_actions_on_match": [{ "type": "deny" }]
                }] },
                { "id": "twice", "rules": [rule("a", device(), forward(UP)), rule("b", device(), forward(UP))] },
                { "id": "ecs-unkeyed", "rules": [rule("r", any(), ecs_forward(24, 56))] },
                { "id": "ecs-keyed", "ecs": pipeline_ecs(24, 56), "rules": [rule("r", any(), ecs_forward(24, 56))] },
                { "id": "ecs-finer", "ecs": pipeline_ecs(16, 48), "rules": [rule("r", any(), ecs_forward(24, 56))] }
            ]),
        );
        for (pipeline, expected) in [
            ("plain", vec![]),
            ("client", vec!["net 10.0.0.1/32"]),
            ("private", vec!["private"]),
            ("country", vec!["country CN"]),
            ("edns", vec!["edns"]),
            ("answer-edns", vec!["edns"]),
            ("twice", vec!["net 10.0.0.1/32"]),
            ("ecs-unkeyed", vec!["subnet 24/56"]),
            // The pipeline-level `ecs` keys nothing any more, so the forward's subnet
            // has to keep waiting requests apart itself
            // pipeline 级 `ecs` 不再进任何键，转发的子网要自己把等待的请求分开
            ("ecs-keyed", vec!["subnet 24/56"]),
            ("ecs-finer", vec!["subnet 24/56"]),
        ] {
            assert_eq!(tests_of(&config, pipeline), expected, "{pipeline}");
        }
    }

    #[test]
    fn a_scope_takes_in_the_response_jump_paths_it_starts() {
        let jump =
            |target: &str| serde_json::json!([{ "type": "jump_to_pipeline", "pipeline": target }]);
        let config = runtime_config(
            serde_json::json!({}),
            serde_json::json!([]),
            serde_json::json!([
                { "id": "client", "rules": [rule("r", device(), forward(UP))] },
                { "id": "edns", "rules": [rule("r", serde_json::json!([{ "type": "edns_present", "expect": true }]), forward(UP))] },
                // 请求阶段的跳转换成目标自己的键 / A request-phase jump moves to the target's own key
                { "id": "to-client", "rules": [rule("r", any(), jump("client"))] },
                { "id": "check-to-client", "rules": [checked(forward(UP), "response_actions_on_match", "client")] },
                { "id": "miss-to-edns", "rules": [checked(forward(UP), "response_actions_on_miss", "edns")] },
                // 跳转路径上也跟着请求阶段的跳转 / The jump path follows request-phase jumps too
                { "id": "check-to-to-client", "rules": [checked(forward(UP), "response_actions_on_match", "to-client")] },
                { "id": "loop-a", "rules": [checked(forward(UP), "response_actions_on_match", "loop-b")] },
                { "id": "loop-b", "rules": [
                    checked(forward(UP), "response_actions_on_match", "loop-a"),
                    rule("e", serde_json::json!([{ "type": "edns_present", "expect": true }]), forward(UP))
                ] },
                // 转发带着客户端 ECS 跳过去：目标转发的正是这个包
                // A forward with client ECS jumps: the target forwards that very packet
                { "id": "ecs-source", "rules": [checked(ecs_forward(24, 56), "response_actions_on_match", "ecs-target")] },
                { "id": "ecs-target", "rules": [rule("r", any(), forward(UP))] },
                { "id": "keyed-source", "ecs": pipeline_ecs(24, 56), "rules": [checked(ecs_forward(24, 56), "response_actions_on_match", "keyed-target")] },
                { "id": "keyed-target", "rules": [rule("r", any(), forward(UP))] },
                // 跳转路径上的转发不加自己的 ECS / Forwards on the jump path add no ECS of their own
                { "id": "path-source", "rules": [checked(forward(UP), "response_actions_on_match", "ecs-on-path")] },
                { "id": "ecs-on-path", "rules": [rule("r", any(), ecs_forward(24, 56))] },
                { "id": "to-nowhere", "rules": [checked(forward(UP), "response_actions_on_match", "nowhere")] }
            ]),
        );
        for (pipeline, expected) in [
            ("to-client", vec![]),
            ("check-to-client", vec!["net 10.0.0.1/32"]),
            ("miss-to-edns", vec!["edns"]),
            ("check-to-to-client", vec!["net 10.0.0.1/32"]),
            ("loop-a", vec!["edns"]),
            ("loop-b", vec!["edns"]),
            ("ecs-source", vec!["subnet 24/56"]),
            // 跳转路径的键带着包里的 ECS / The jump path's keys carry the packet's ECS
            ("ecs-target", vec![]),
            // As "ecs-keyed" above: the pipeline-level `ecs` keys nothing any more
            // 同上面的 "ecs-keyed"：pipeline 级 `ecs` 不再进任何键
            ("keyed-source", vec!["subnet 24/56"]),
            ("keyed-target", vec![]),
            ("path-source", vec![]),
            ("ecs-on-path", vec!["subnet 24/56"]),
            ("to-nowhere", vec![]),
        ] {
            assert_eq!(tests_of(&config, pipeline), expected, "{pipeline}");
        }
    }

    /// 规则缓存只缓存本 pipeline 规则做出的决策，所以只按它自己的请求匹配器区分请求方：
    /// 不按转发的 ECS 子网，也不按回答检查跳到的 pipeline。
    /// The rule cache holds decisions this pipeline's rules make, so it tells
    /// requesters apart by the pipeline's own request matchers only: not by the
    /// subnet a forward sends, nor by the pipelines its answer checks jump to.
    #[test]
    fn the_rule_cache_scope_is_the_pipelines_own_request_matchers() {
        let config = runtime_config(
            serde_json::json!({}),
            serde_json::json!([]),
            serde_json::json!([
                { "id": "client", "rules": [rule("r", device(), forward(UP))] },
                { "id": "main", "rules": [
                    rule("edns", serde_json::json!([{ "type": "edns_present", "expect": true }]), ecs_forward(24, 56)),
                    {
                        "name": "check", "matchers": any(), "actions": forward(UP),
                        "response_matchers": [
                            { "type": "upstream_equals", "value": UP },
                            { "type": "response_edns_present", "expect": true }
                        ],
                        "response_actions_on_match": [{ "type": "jump_to_pipeline", "pipeline": "client" }]
                    }
                ] }
            ]),
        );
        let main = &config.pipelines[config.pipeline_id_index["main"]];
        assert_eq!(main.rule_requester.tests(), [RequesterTest::Edns]);
        assert_eq!(
            tests_of(&config, "main"),
            ["edns", "subnet 24/56", "net 10.0.0.1/32"]
        );
    }

    /// 回答检查跳进一个 pipeline 之后，跳转路径转发的是跳转前那次转发发出的包，而直接
    /// 进入这个 pipeline 的请求发出的是它自己的转发准备的包（这里带上取自客户端的 ECS）。
    /// 两者同一子网也不能共用条目。
    /// After an answer check jumps into a pipeline, the jump path forwards the
    /// packet the forward before the jump sent, while a request entering that
    /// pipeline directly sends the packet its own forward prepares (with ECS from
    /// the client here). Even within one subnet the two must not share entries.
    #[tokio::test]
    async fn a_response_jump_path_does_not_share_with_direct_requests() {
        let relay = answering_upstream(OTHER, 300).await.address;
        let echo = subnet_echo().await.address;
        let engine = engine(
            serde_json::json!([
                { "pipeline": "geo", "matchers": [{ "type": "client_ip", "cidr": "198.51.100.50/32" }] },
                { "pipeline": "main", "matchers": any() }
            ]),
            serde_json::json!([
                { "id": "main", "rules": [{
                    "name": "check", "matchers": any(), "actions": forward(&relay),
                    "response_matchers": [{ "type": "upstream_equals", "value": relay }],
                    "response_actions_on_match": [{ "type": "jump_to_pipeline", "pipeline": "geo" }]
                }] },
                { "id": "geo", "rules": [rule("rest", any(), serde_json::json!([{
                    "type": "forward", "upstream": echo,
                    "ecs": { "mode": "from_client_ip", "prefix_v4": 24, "prefix_v6": 56 }
                }]))] }
            ]),
        );
        // 跳转路径不加 geo 自己的 ECS / The jump path adds no ECS of geo's own
        assert_eq!(ask(&engine, "198.51.100.7", false).await, Some(NO_SUBNET));
        assert_eq!(
            ask(&engine, "198.51.100.50", false).await,
            Some("198.51.100.0".parse().unwrap())
        );
    }

    /// 回答检查 continue 之后再跳转：请求仍持有条目，等待者拿到跳转之后的最终应答，应答也缓存在这个 pipeline 的键下（见
    /// `Route::enter`）。continue 那条规则之前的跳转不算：跳过去时还没据过上游的回答，换成目标的键，目标自己的键分辨请求方。
    /// 以前只要有回答检查会 continue，所有请求阶段跳转的目标都算
    /// A jump after an answer check continues: the request still holds its entry, its
    /// waiters take the final answer from after the jump, and the answer is cached under this
    /// pipeline's key too (see `Route::enter`). A jump before the rule that continues does not
    /// count: made before any upstream's answer was gone by, it moves to the target's keys, which
    /// tell requesters apart by the target's own. With any answer check that continues, every
    /// request-phase jump's target used to count
    #[test]
    fn a_scope_takes_in_request_jumps_after_a_continue() {
        let jump =
            |target: &str| serde_json::json!([{ "type": "jump_to_pipeline", "pipeline": target }]);
        let continues = || {
            let mut rule = rule("check", any(), forward(UP));
            rule["response_matchers"] =
                serde_json::json!([{ "type": "upstream_equals", "value": UP }]);
            rule["response_actions_on_match"] = serde_json::json!([{ "type": "continue" }]);
            rule
        };
        let config = runtime_config(
            serde_json::json!({}),
            serde_json::json!([]),
            serde_json::json!([
                { "id": "client", "rules": [rule("r", device(), forward(UP))] },
                { "id": "ecs-keyed", "ecs": pipeline_ecs(24, 56), "rules": [rule("r", any(), ecs_forward(24, 56))] },
                { "id": "continue-to-client", "rules": [continues(), rule("all", any(), jump("client"))] },
                { "id": "to-client", "rules": [rule("all", any(), jump("client"))] },
                // 那里的 ECS 键带不过来 / Its ECS key does not carry over
                { "id": "continue-to-ecs", "rules": [continues(), rule("all", any(), jump("ecs-keyed"))] },
                { "id": "client-then-continue", "rules": [
                    rule("some", serde_json::json!([{ "type": "domain_suffix", "value": "jump.test" }]), jump("client")),
                    continues()
                ] }
            ]),
        );
        for (pipeline, expected) in [
            ("continue-to-client", vec!["net 10.0.0.1/32"]),
            ("to-client", vec![]),
            ("client-then-continue", vec![]),
            ("continue-to-ecs", vec!["subnet 24/56"]),
            // As in `a_scope_has_the_tests_the_rules_tell_requesters_apart_by`
            // 同 `a_scope_has_the_tests_the_rules_tell_requesters_apart_by`
            ("ecs-keyed", vec!["subnet 24/56"]),
        ] {
            assert_eq!(tests_of(&config, pipeline), expected, "{pipeline}");
        }
    }

    /// 回答检查 continue 之后跳进按客户端子网转发 ECS 的 pipeline：同时经过同一路线、
    /// 子网不同的客户端不能拿到这个应答。
    /// After an answer check continues, the request jumps into a pipeline that
    /// forwards with ECS from the client: a client in another subnet taking the
    /// same route at once must not get that answer.
    #[tokio::test]
    async fn an_ecs_answer_after_a_continue_stays_with_its_subnet() {
        let relay = answering_upstream(OTHER, 300).await.address;
        let echo = subnet_echo().await.address;
        let engine = engine(
            serde_json::json!([]),
            serde_json::json!([
                { "id": "main", "rules": [
                    {
                        "name": "check", "matchers": any(), "actions": forward(&relay),
                        "response_matchers": [{ "type": "upstream_equals", "value": relay }],
                        "response_actions_on_match": [{ "type": "continue" }]
                    },
                    rule("all", any(), serde_json::json!([{ "type": "jump_to_pipeline", "pipeline": "geo" }]))
                ] },
                { "id": "geo", "ecs": pipeline_ecs(24, 56), "rules": [rule("rest", any(), serde_json::json!([{
                    "type": "forward", "upstream": echo,
                    "ecs": { "mode": "from_client_ip", "prefix_v4": 24, "prefix_v6": 56 }
                }]))] }
            ]),
        );
        let subnet = |text: &str| Some(text.parse::<Ipv4Addr>().unwrap());
        assert_eq!(
            ask_at_once(&engine, ["198.51.100.7", "203.0.113.9"]).await,
            [subnet("198.51.100.0"), subnet("203.0.113.0")]
        );
    }

    /// 只给 10.0.0.1 换上游的 pipeline：sink 回 0.0.0.0，其余请求走 normal。
    /// A pipeline that sends 10.0.0.1 alone to another upstream: sink answers
    /// 0.0.0.0, every other request goes to normal.
    async fn device_split() -> (Engine, Upstream, Upstream) {
        let sink = answering_upstream(SINK, 300).await;
        let normal = answering_upstream(NORMAL, 300).await;
        let engine = engine(
            serde_json::json!([]),
            serde_json::json!([{ "id": "main", "rules": [
                rule("device", device(), forward(&sink.address)),
                rule("rest", any(), forward(&normal.address))
            ] }]),
        );
        (engine, sink, normal)
    }

    /// 一台设备的转发应答不能从缓存交给另一个客户端，而每个客户端照样用得上自己的缓存。
    /// One device's forwarded answer must not reach another client from the cache,
    /// while each client still gets its own cached answer.
    #[tokio::test]
    async fn a_device_specific_answer_is_not_served_to_another_client_from_the_cache() {
        let (engine, sink, normal) = device_split().await;
        let mut answers = Vec::new();
        for client in ["10.0.0.1", "10.0.0.2", "10.0.0.1", "10.0.0.2", "10.0.0.3"] {
            answers.push(ask(&engine, client, false).await);
        }
        assert_eq!(
            answers,
            [
                Some(SINK),
                Some(NORMAL),
                Some(SINK),
                Some(NORMAL),
                Some(NORMAL)
            ]
        );
        // 每个客户端的第二次、以及规则一样对待的其他客户端，都从缓存拿
        // Each client's second query, and any other client the rules treat alike,
        // comes from the cache
        assert_eq!((sink.queries(), normal.queries()), (1, 1));
        // 快速路径查的是同一个键 / The fast path looks up the same key
        for (client, expected) in [("10.0.0.1", SINK), ("10.0.0.2", NORMAL)] {
            let peer: SocketAddr = format!("{client}:53000").parse().unwrap();
            let Some(FastPathResponse::CacheHit { cached, .. }) =
                engine.handle_packet_fast(&query(false), peer)
            else {
                panic!("{client}: the fast path must find its own cached answer");
            };
            assert_eq!(first_a(Ok(cached)), Some(expected), "{client}");
        }
    }

    /// 同时问时，另一个客户端不能等在这台设备的查询上拿走它的应答。
    /// Asking at once, another client must not wait on the device's query and
    /// take its answer.
    #[tokio::test]
    async fn a_device_specific_answer_is_not_handed_to_another_client_waiting() {
        let (engine, _, _) = device_split().await;
        assert_eq!(
            ask_at_once(&engine, ["10.0.0.1", "10.0.0.2"]).await,
            [Some(SINK), Some(NORMAL)]
        );
    }

    /// 按 EDNS 分流时，带与不带 EDNS 的请求各拿各的应答：响应缓存和规则缓存都要分开。
    /// Split by EDNS, requests with and without it each get their own answer:
    /// the response cache and the rule cache must both keep them apart.
    #[tokio::test]
    async fn answers_split_by_edns_presence_stay_apart() {
        let with_edns = answering_upstream(OTHER, 300).await;
        let without = answering_upstream(NORMAL, 300).await;
        let engine = engine(
            serde_json::json!([]),
            serde_json::json!([{ "id": "main", "rules": [
                rule("edns", serde_json::json!([{ "type": "edns_present", "expect": true }]), forward(&with_edns.address)),
                rule("rest", any(), forward(&without.address))
            ] }]),
        );
        let mut answers = Vec::new();
        for edns in [true, false, true, false] {
            answers.push(ask(&engine, "10.0.0.1", edns).await);
        }
        assert_eq!(
            answers,
            [Some(OTHER), Some(NORMAL), Some(OTHER), Some(NORMAL)]
        );
        assert_eq!((with_edns.queries(), without.queries()), (1, 1));
    }

    /// 转发时加上的 ECS 不算客户端带了 EDNS：响应跳转以后，按 EDNS 分流的规则看的仍是客户端发来
    /// 的查询。跳转的三条路都是：应答匹配、应答不匹配、转发失败
    /// An ECS option a forward adds does not count as EDNS from the client: after a
    /// response jump, a rule split by EDNS still sees the query the client sent. So on all
    /// three ways to jump: the reply matching, the reply not matching, the forward failing
    #[tokio::test]
    async fn an_ecs_a_forward_adds_is_no_edns_on_the_jump_path() {
        for way in ["match", "miss", "failure"] {
            let pre = answering_upstream(NORMAL, 300).await.address;
            let with_edns = answering_upstream(OTHER, 300).await;
            let without = answering_upstream(NORMAL, 300).await;
            let jump = serde_json::json!([{ "type": "jump_to_pipeline", "pipeline": "other" }]);
            let forwarded_to = if way == "failure" {
                "127.0.0.1:9"
            } else {
                pre.as_str()
            };
            let mut first = serde_json::json!({
                "name": "pre", "matchers": any(),
                "actions": [{
                    "type": "forward", "upstream": forwarded_to,
                    "ecs": { "mode": "static", "ip": "203.0.113.0" }
                }]
            });
            match way {
                "match" => {
                    first["response_matchers"] =
                        serde_json::json!([{ "type": "upstream_equals", "value": pre }]);
                    first["response_actions_on_match"] = jump;
                }
                "miss" => {
                    first["response_matchers"] = serde_json::json!([{ "type": "upstream_equals", "value": "192.0.2.255:53" }]);
                    first["response_actions_on_miss"] = jump;
                }
                _ => first["response_actions_on_miss"] = jump,
            }
            let engine = engine(
                serde_json::json!([]),
                serde_json::json!([
                    { "id": "main", "rules": [first] },
                    { "id": "other", "rules": [
                        rule("edns", serde_json::json!([{ "type": "edns_present", "expect": true }]), forward(&with_edns.address)),
                        rule("rest", any(), forward(&without.address))
                    ] }
                ]),
            );
            assert_eq!(ask(&engine, "10.0.0.1", false).await, Some(NORMAL), "{way}");
            assert_eq!((with_edns.queries(), without.queries()), (0, 1), "{way}");
        }
    }

    /// 按客户端地址的 GeoIP 分流（这里用私有地址判断）时，应答按地址分开。
    /// Split by the client's GeoIP (private addresses here), answers stay apart by address.
    #[tokio::test]
    async fn answers_split_by_client_geoip_stay_apart() {
        let private = answering_upstream(OTHER, 300).await;
        let public = answering_upstream(NORMAL, 300).await;
        let engine = engine(
            serde_json::json!([]),
            serde_json::json!([{ "id": "main", "rules": [
                rule("private", serde_json::json!([{ "type": "geoip_private", "expect": true }]), forward(&private.address)),
                rule("rest", any(), forward(&public.address))
            ] }]),
        );
        let mut answers = Vec::new();
        for client in ["10.0.0.1", "198.51.100.7", "10.0.0.2", "203.0.113.9"] {
            answers.push(ask(&engine, client, false).await);
        }
        assert_eq!(
            answers,
            [Some(OTHER), Some(NORMAL), Some(OTHER), Some(NORMAL)]
        );
        // 同为私有或同为公网的客户端共用一份 / Private clients share, and so do public ones
        assert_eq!((private.queries(), public.queries()), (1, 1));
    }

    /// 转发带取自客户端的 ECS、pipeline 没有自己的 ecs 时，应答按 ECS 子网分开：同一子网
    /// 的客户端共用，私有地址不发送 ECS，也共用。规则用正则条件，转发决定才进规则缓存。
    /// A forward that sends ECS from the client, in a pipeline without an ecs of
    /// its own, keeps answers apart by subnet: clients in one subnet share, and so
    /// do private addresses, which send no ECS. The rule matches by regex, so its
    /// forward decision goes into the rule cache.
    #[tokio::test]
    async fn answers_by_ecs_subnet_stay_apart_and_are_shared_within_a_subnet() {
        let echo = subnet_echo().await;
        let engine = engine(
            serde_json::json!([]),
            serde_json::json!([{ "id": "main", "rules": [rule("rest", serde_json::json!([{ "type": "domain_regex", "value": "example" }]), serde_json::json!([{
                "type": "forward", "upstream": echo.address,
                "ecs": { "mode": "from_client_ip", "prefix_v4": 24, "prefix_v6": 56 }
            }]))] }]),
        );
        let mut answers = Vec::new();
        for client in [
            "198.51.100.7",
            "198.51.100.9",
            "203.0.113.5",
            "10.0.0.1",
            "10.0.0.2",
        ] {
            answers.push(ask(&engine, client, false).await);
        }
        let subnet = |text: &str| Some(text.parse::<Ipv4Addr>().unwrap());
        assert_eq!(
            answers,
            [
                subnet("198.51.100.0"),
                subnet("198.51.100.0"),
                subnet("203.0.113.0"),
                Some(NO_SUBNET),
                Some(NO_SUBNET)
            ]
        );
        assert_eq!(echo.queries(), 3);
        // 规则的决策不看子网，规则缓存里只有一份 / The rule decision ignores the subnet,
        // so the rule cache holds one entry for everyone
        let rule_key = calculate_rule_hash(
            engine.state.load().cache_namespace("main"),
            "main",
            "example.com",
            RecordType::A,
            DNSClass::IN,
            &RequesterKey::NONE,
        );
        assert!(engine.rule_cache.get(rule_key).is_some());
    }

    /// 带着客户端 ECS 的转发之后，回答检查跳进另一个 pipeline：那里原样转发这个包，应答也
    /// 因子网而不同。直接进入那个 pipeline 的客户端，以及同时经过同一路线、子网不同的客户端，
    /// 都不能拿到它。
    /// After a forward with ECS from the client, an answer check jumps into another
    /// pipeline, which forwards that packet as it is, so its answer differs by
    /// subnet too. Neither a client that enters that pipeline directly nor one in
    /// another subnet taking the same route at once may get it.
    #[tokio::test]
    async fn ecs_carried_into_a_response_jump_keeps_answers_apart() {
        let echo = subnet_echo().await.address;
        let engine = engine(
            serde_json::json!([
                { "pipeline": "geo", "matchers": [{ "type": "client_ip", "cidr": "203.0.113.50/32" }] },
                { "pipeline": "main", "matchers": any() }
            ]),
            serde_json::json!([
                { "id": "main", "rules": [{
                    "name": "check", "matchers": any(),
                    "actions": [{
                        "type": "forward", "upstream": echo,
                        "ecs": { "mode": "from_client_ip", "prefix_v4": 24, "prefix_v6": 56 }
                    }],
                    "response_matchers": [{ "type": "upstream_equals", "value": echo }],
                    "response_actions_on_match": [{ "type": "jump_to_pipeline", "pipeline": "geo" }]
                }] },
                { "id": "geo", "rules": [rule("rest", any(), forward(&echo))] }
            ]),
        );
        let subnet = |text: &str| Some(text.parse::<Ipv4Addr>().unwrap());
        assert_eq!(
            ask(&engine, "198.51.100.7", false).await,
            subnet("198.51.100.0")
        );
        assert_eq!(ask(&engine, "203.0.113.50", false).await, Some(NO_SUBNET));
        assert_eq!(
            ask_at_once(&engine, ["192.0.2.7", "203.0.113.9"]).await,
            [subnet("192.0.2.0"), subnet("203.0.113.0")]
        );
    }

    /// 一条规则里写了几个 forward 时，它们合成一次转发、同时问所有上游，发出的 ECS 只有一个：几个
    /// forward 的 ecs 写得一样时照它发（以前合并时 ecs 被丢掉，一个也不发）；写得不一样时和不写 ecs
    /// 一样，客户端没带 ECS 就不发
    /// The forwards of one rule merge into one forward asking every upstream at once, and
    /// it sends one ECS: the forwards' ecs when they all write the same (the merge used
    /// to drop it and send none); as without ecs when they differ, so a client sending
    /// no ECS has none sent
    #[tokio::test]
    async fn forwards_merged_in_one_rule_send_the_ecs_they_share() {
        let echoes = [subnet_echo().await.address, subnet_echo().await.address];
        let from_client =
            serde_json::json!({ "mode": "from_client_ip", "prefix_v4": 24, "prefix_v6": 56 });
        let fixed = serde_json::json!({ "mode": "static", "ip": "203.0.113.0", "prefix": 24 });
        let subnet = |text: &str| Some(text.parse::<Ipv4Addr>().unwrap());
        for (ecs, sent) in [
            ([&from_client, &from_client], subnet("198.51.100.0")),
            ([&fixed, &fixed], subnet("203.0.113.0")),
            ([&from_client, &fixed], Some(NO_SUBNET)),
        ] {
            let actions: Vec<serde_json::Value> = echoes
                .iter()
                .zip(ecs)
                .map(|(upstream, ecs)| {
                    serde_json::json!({ "type": "forward", "upstream": upstream, "ecs": ecs })
                })
                .collect();
            // 和启动、重载一样经 `parse_config` 读配置：几个 forward 在那里合并好
            // Read through `parse_config` as startup and reload do: that is where the forwards
            // are merged
            let raw = serde_json::json!({
                "settings": {
                    "default_upstream": "127.0.0.1:9",
                    "upstream_timeout_ms": 500,
                    "enable_tcp_fallback": false
                },
                "pipelines": [{ "id": "main", "rules": [rule("both", any(), serde_json::json!(actions))] }]
            });
            let config = crate::config::parse_config(&raw.to_string()).expect("parse config");
            let engine = Engine::new(
                RuntimePipelineConfig::from_config(config).expect("build runtime config"),
                "test".to_string(),
            )
            .expect("engine");
            assert_eq!(ask(&engine, "198.51.100.7", false).await, sent, "{ecs:?}");
        }
    }

    /// 进入按客户端分流的 pipeline 后，这台设备得到静态应答，或者转发给一个慢的 sink 上游。
    /// Inside a pipeline that splits by client the device gets a static answer, or
    /// a forward to a slow sink upstream.
    async fn device_actions() -> (String, [(&'static str, serde_json::Value); 2]) {
        let sink = answering_upstream_after(SINK, 300, Duration::from_millis(100))
            .await
            .address;
        let actions = [
            (
                "static",
                serde_json::json!([{ "type": "static_ip_response", "ip": "0.0.0.0" }]),
            ),
            ("slow forward", forward(&sink)),
        ];
        (sink, actions)
    }

    /// 转发之后回答检查跳进按客户端分流的 pipeline：等在这次转发上的另一个客户端不能拿到
    /// 这台设备的应答；设备在那里转发时，另一个客户端也不能等在设备的转发上。
    /// A forward whose answer check jumps into a pipeline that splits by client:
    /// another client waiting on that forward must not get the device's answer, nor
    /// wait on the device's own forward there.
    #[tokio::test]
    async fn an_answer_from_a_response_jump_into_a_client_split_stays_with_its_client() {
        let relay = answering_upstream(OTHER, 300).await.address;
        let normal = answering_upstream(NORMAL, 300).await.address;
        let (_, actions) = device_actions().await;
        for (device_does, action) in actions {
            let select = serde_json::json!([]);
            let pipelines = serde_json::json!([
                { "id": "main", "rules": [{
                    "name": "check", "matchers": any(), "actions": forward(&relay),
                    "response_matchers": [{ "type": "upstream_equals", "value": relay }],
                    "response_actions_on_match": [{ "type": "jump_to_pipeline", "pipeline": "split" }]
                }] },
                { "id": "split", "rules": [
                    rule("device", device(), action),
                    rule("rest", any(), forward(&normal))
                ] }
            ]);
            let (engine, steps) = engine_observed(select.clone(), pipelines.clone());
            assert_eq!(
                ask_at_once(&engine, ["10.0.0.1", "10.0.0.2"]).await,
                [Some(SINK), Some(NORMAL)],
                "{device_does}"
            );
            // 第二个客户端自己的转发发出时，设备的转发还在等：两边各问各的，没有挂上去
            // The second client's own forward went out while the device's still waited: each asked
            // for itself, and it did not join
            assert!(
                steps.forwarded_while_waiting(
                    ("10.0.0.1:53000", &relay),
                    ("10.0.0.2:53000", &relay)
                ),
                "{device_does}: {:?}",
                steps.taken()
            );
            assert!(!steps.joined("10.0.0.2:53000"), "{device_does}");

            // 对照：同一个客户端发两次（端口不同），第二个挂在第一个的条目上，拿到同样的应答。不同客户端之间
            // 守住串答的，是从入口起就按客户端分开的键
            // Control: one client asking twice (another port): the second joins the first one's
            // entry and takes the same answer. Between different clients, what keeps answers
            // apart is the key split by client from the entry on
            let (engine, steps) = engine_observed(select, pipelines);
            assert_eq!(
                ask_at_once(&engine, ["10.0.0.1:53001", "10.0.0.1:53002"]).await,
                [Some(SINK); 2],
                "{device_does}"
            );
            assert!(
                steps.joined("10.0.0.1:53002"),
                "{device_does}: {:?}",
                steps.taken()
            );
        }
    }

    /// 请求阶段跳进按客户端分流的 pipeline：另一个客户端不能等在设备的转发上。
    /// A request-phase jump into a pipeline that splits by client: another client
    /// must not wait on the device's forward there.
    #[tokio::test]
    async fn a_jump_into_a_client_split_keeps_answers_apart() {
        let normal = answering_upstream(NORMAL, 300).await.address;
        let (sink, actions) = device_actions().await;
        for (device_does, action) in actions {
            let select = serde_json::json!([]);
            let pipelines = serde_json::json!([
                { "id": "main", "rules": [rule("all", any(), serde_json::json!([{ "type": "jump_to_pipeline", "pipeline": "split" }]))] },
                { "id": "split", "rules": [
                    rule("device", device(), action),
                    rule("rest", any(), forward(&normal))
                ] }
            ]);
            let (engine, steps) = engine_observed(select.clone(), pipelines.clone());
            assert_eq!(
                ask_at_once(&engine, ["10.0.0.1", "10.0.0.2"]).await,
                [Some(SINK), Some(NORMAL)],
                "{device_does}"
            );
            // 设备给静态应答时没有转发可等 / A device answered statically has no forward to wait on
            if device_does == "slow forward" {
                // 第二个客户端自己的转发发出时，设备的转发还在等：两边各问各的，没有挂上去
                // The second client's own forward went out while the device's still waited: each asked
                // for itself, and it did not join
                assert!(
                    steps.forwarded_while_waiting(
                        ("10.0.0.1:53000", &sink),
                        ("10.0.0.2:53000", &normal)
                    ),
                    "{device_does}: {:?}",
                    steps.taken()
                );
            }
            assert!(!steps.joined("10.0.0.2:53000"), "{device_does}");

            // 设备给静态应答时不登记条目，没有可挂的 / A device answered statically registers no entry to join
            if device_does == "slow forward" {
                // 对照：同一个客户端发两次（端口不同），第二个挂在第一个的条目上，拿到同样的应答。不同客户端之间
                // 守住串答的，是从入口起就按客户端分开的键
                // Control: one client asking twice (another port): the second joins the first one's
                // entry and takes the same answer. Between different clients, what keeps answers
                // apart is the key split by client from the entry on
                let (engine, steps) = engine_observed(select, pipelines);
                assert_eq!(
                    ask_at_once(&engine, ["10.0.0.1:53001", "10.0.0.1:53002"]).await,
                    [Some(SINK); 2],
                    "{device_does}"
                );
                assert!(
                    steps.joined("10.0.0.1:53002"),
                    "{device_does}: {:?}",
                    steps.taken()
                );
            }
        }
    }

    /// 回答检查一路跳转（p1/p2 → mid → split），最后进入按客户端分流的 pipeline：链上任何
    /// 一个条目的等待者都不能拿到这台设备的应答。
    /// Answer checks jumping along a chain (p1/p2 → mid → split) into a pipeline that
    /// splits by client: no waiter on any entry along the chain may get the device's answer.
    #[tokio::test]
    async fn a_jump_chain_into_a_client_split_keeps_answers_apart() {
        let relay = answering_upstream(OTHER, 300).await.address;
        // mid 用自己的上游，事件里分得清是哪一跳；它慢一点，保证后到 mid 的请求到达时先到的还在等它。两个请求
        // 先各自问 `relay`，谁先拿到回答不定，所以谁先到 mid 也不定
        // mid has an upstream of its own, so the steps tell the hops apart; it is slow, so the
        // later request reaches mid while the earlier one still waits on it. Each first asks
        // `relay`, and which gets its answer first may go either way, so either may reach mid
        // first
        let mid_relay = answering_upstream_after(OTHER, 300, Duration::from_millis(200))
            .await
            .address;
        let normal = answering_upstream(NORMAL, 300).await.address;
        let checked_jump = |id: &str, relay: &str, target: &str| {
            serde_json::json!({ "id": id, "rules": [{
                "name": id, "matchers": any(), "actions": forward(relay),
                "response_matchers": [{ "type": "upstream_equals", "value": relay }],
                "response_actions_on_match": [{ "type": "jump_to_pipeline", "pipeline": target }]
            }] })
        };
        let (_, actions) = device_actions().await;
        for (device_does, action) in actions {
            let select = serde_json::json!([
                { "pipeline": "p1", "matchers": [{ "type": "client_ip", "cidr": "10.0.0.1/32" }] },
                { "pipeline": "p2", "matchers": [{ "type": "client_ip", "cidr": "10.0.0.2/32" }] }
            ]);
            let pipelines = serde_json::json!([
                checked_jump("p1", &relay, "mid"),
                checked_jump("p2", &relay, "mid"),
                checked_jump("mid", &mid_relay, "split"),
                { "id": "split", "rules": [
                    rule("device", device(), action),
                    rule("rest", any(), forward(&normal))
                ] }
            ]);
            let (engine, steps) = engine_observed(select.clone(), pipelines.clone());
            assert_eq!(
                ask_at_once(&engine, ["10.0.0.1", "10.0.0.2"]).await,
                [Some(SINK), Some(NORMAL)],
                "{device_does}"
            );
            // 两个客户端在 mid 的转发同时在等：后到的那个自己转发，两边各问各的，没有挂上去
            // The two clients' forwards at mid waited at once: the later one forwarded itself,
            // each asked for itself, and neither joined
            let clients = ["10.0.0.1:53000", "10.0.0.2:53000"];
            assert!(
                steps.forwarded_together(&mid_relay, clients),
                "{device_does}: {:?}",
                steps.taken()
            );
            assert!(
                !clients.iter().any(|client| steps.joined(client)),
                "{device_does}"
            );

            // 对照：同一个客户端发两次（端口不同），第二个挂在第一个的条目上，拿到同样的应答。不同客户端之间
            // 守住串答的，是从入口起就按客户端分开的键
            // Control: one client asking twice (another port): the second joins the first one's
            // entry and takes the same answer. Between different clients, what keeps answers
            // apart is the key split by client from the entry on
            let (engine, steps) = engine_observed(select, pipelines);
            assert_eq!(
                ask_at_once(&engine, ["10.0.0.1:53001", "10.0.0.1:53002"]).await,
                [Some(SINK); 2],
                "{device_does}"
            );
            assert!(
                steps.joined("10.0.0.1:53002"),
                "{device_does}: {:?}",
                steps.taken()
            );
        }
    }

    /// 应答与请求方无关的 pipeline 照旧共享：不同客户端、带不带 EDNS，都只问一次上游。
    /// A pipeline whose answer does not depend on the requester still shares: different
    /// clients, with or without EDNS, ask the upstream once.
    #[tokio::test]
    async fn requester_independent_answers_are_still_shared() {
        let normal = answering_upstream(NORMAL, 300).await;
        let engine = engine(
            serde_json::json!([]),
            serde_json::json!([{ "id": "main", "rules": [rule("rest", any(), forward(&normal.address))] }]),
        );
        for (client, edns) in [
            ("10.0.0.1", false),
            ("10.0.0.2", true),
            ("198.51.100.7", false),
        ] {
            assert_eq!(ask(&engine, client, edns).await, Some(NORMAL));
        }
        assert_eq!(normal.queries(), 1);
        assert_eq!(
            ask_at_once(&engine, ["10.0.0.3", "10.0.0.4"]).await,
            [Some(NORMAL); 2]
        );
        assert_eq!(normal.queries(), 1);
    }

    /// 后台刷新要按请求原来的样子重放：带 EDNS 的请求刷新时也带 EDNS，否则按 EDNS 分流的
    /// 规则会走另一条路线，把别处的应答写进这个键。快速路径和异步路径两个触发点都测。
    /// A background refresh replays the request as it came: one that carried EDNS
    /// is refreshed with EDNS, or rules that split by EDNS take another route and
    /// write another answer under its key. Both the fast path and the async path
    /// trigger it.
    #[tokio::test]
    async fn a_background_refresh_replays_the_request_with_its_edns() {
        for fast_path in [true, false] {
            // 两秒的 TTL，阈值 99%：一秒之后的命中会触发刷新
            // A two-second TTL at a 99% threshold: a hit after one second refreshes
            let with_edns = answering_upstream(OTHER, 2).await;
            let without = answering_upstream(NORMAL, 2).await;
            let engine = Engine::new(
                runtime_config(
                    serde_json::json!({
                        "cache_background_refresh": true,
                        "cache_refresh_threshold_percent": 99,
                        "cache_refresh_min_ttl": 1
                    }),
                    serde_json::json!([]),
                    serde_json::json!([{ "id": "main", "rules": [
                        rule("edns", serde_json::json!([{ "type": "edns_present", "expect": true }]), forward(&with_edns.address)),
                        rule("rest", any(), forward(&without.address))
                    ] }]),
                ),
                "test".to_string(),
            )
            .expect("engine");
            assert_eq!(ask(&engine, "10.0.0.1", true).await, Some(OTHER));

            tokio::time::sleep(Duration::from_millis(1100)).await;
            let peer: SocketAddr = "10.0.0.1:53000".parse().unwrap();
            if fast_path {
                assert!(matches!(
                    engine.handle_packet_fast(&query(true), peer),
                    Some(FastPathResponse::CacheHit { .. })
                ));
            } else {
                assert_eq!(ask(&engine, "10.0.0.1", true).await, Some(OTHER));
            }
            tokio::time::timeout(Duration::from_secs(3), async {
                while !engine.refreshing.is_empty() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("the refresh finishes");

            assert_eq!(
                (with_edns.queries(), without.queries()),
                (2, 0),
                "the refresh must take the EDNS route (fast path: {fast_path})"
            );
            assert_eq!(
                ask(&engine, "10.0.0.1", true).await,
                Some(OTHER),
                "fast path: {fast_path}"
            );
        }
    }
}

#[cfg(test)]
mod reused_answer_tests {
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use std::time::Duration;

    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RData, RecordType};
    use hickory_proto::serialize::binary::BinDecodable;

    use super::Engine;
    use crate::engine::test_support::{answering_upstream, engine_from};

    /// The default upstream's answer, which an `allow` stands for.
    /// 默认上游的应答，也就是 `allow` 该给出的。
    const DEFAULT: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 30);
    /// The answer a rule checks and continues past, kept for reuse.
    /// 被规则检查后越过、留着复用的应答。
    const CHECKED: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);

    async fn ask(engine: &Engine, client: &str) -> Option<Ipv4Addr> {
        let mut request = Message::new(0x2a2a, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(
            Name::from_str("example.com.").unwrap(),
            RecordType::A,
        ));
        let bytes = tokio::time::timeout(
            Duration::from_secs(5),
            engine.handle_packet(&request.to_vec().unwrap(), client.parse().unwrap()),
        )
        .await
        .expect("must not hang")
        .expect("engine answers");
        Message::from_bytes(&bytes)
            .expect("parse answer")
            .answers
            .iter()
            .find_map(|record| match &record.data {
                RData::A(a) => Some(a.0),
                _ => None,
            })
    }

    /// The rules of `via`: check the answer of `checked` and continue past it, then
    /// jump to `target`.
    /// `via` 的规则：检查 `checked` 的应答并越过它，然后跳到 `target`。
    fn continue_then_jump(id: &str, checked: &str, target: &str) -> serde_json::Value {
        serde_json::json!({ "id": id, "rules": [
            {
                "name": "checked",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": checked }],
                "response_matchers": [{ "type": "upstream_equals", "value": checked }],
                "response_actions_on_match": [{ "type": "continue" }]
            },
            {
                "name": "jump",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "jump_to_pipeline", "pipeline": target }]
            }
        ]})
    }

    fn allow(id: &str) -> serde_json::Value {
        serde_json::json!({ "id": id, "rules": [{
            "name": "allow",
            "matchers": [{ "type": "any" }],
            "actions": [{ "type": "allow" }]
        }]})
    }

    fn settings(default: &str) -> serde_json::Value {
        serde_json::json!({
            "default_upstream": default,
            "upstream_timeout_ms": 500,
            "enable_tcp_fallback": false
        })
    }

    /// A request-phase jump leaves the continued-past answer behind: the target's
    /// `allow` forwards to the default upstream, and a request entering the target
    /// directly is not handed the other pipeline's answer from the cache.
    /// 请求阶段的跳转不把越过的应答带过去：目标的 `allow` 转发到默认上游，直接进入目标的
    /// 请求也不会从缓存拿到另一个 pipeline 的应答。
    #[tokio::test]
    async fn a_request_jump_leaves_the_reused_answer_behind() {
        let checked = answering_upstream(CHECKED, 300).await.address;
        let default = answering_upstream(DEFAULT, 300).await.address;
        let engine = engine_from(serde_json::json!({
            "settings": settings(&default),
            "pipeline_select": [
                { "pipeline": "main", "matchers": [{ "type": "client_ip", "cidr": "10.0.0.1/32" }] },
                { "pipeline": "next", "matchers": [{ "type": "client_ip", "cidr": "10.0.0.2/32" }] }
            ],
            "pipelines": [continue_then_jump("main", &checked, "next"), allow("next")]
        }));
        assert_eq!(ask(&engine, "10.0.0.1:53000").await, Some(DEFAULT));
        assert_eq!(ask(&engine, "10.0.0.2:53000").await, Some(DEFAULT));
    }

    /// The same for a rule-level jump on the response-jump path.
    /// 响应跳转路径上的规则级跳转也一样。
    #[tokio::test]
    async fn a_jump_on_the_response_jump_path_leaves_the_reused_answer_behind() {
        let entry = answering_upstream(Ipv4Addr::new(192, 0, 2, 50), 300)
            .await
            .address;
        let checked = answering_upstream(CHECKED, 300).await.address;
        let default = answering_upstream(DEFAULT, 300).await.address;
        let engine = engine_from(serde_json::json!({
            "settings": settings(&default),
            "pipeline_select": [
                { "pipeline": "main", "matchers": [{ "type": "client_ip", "cidr": "10.0.0.1/32" }] },
                { "pipeline": "next", "matchers": [{ "type": "client_ip", "cidr": "10.0.0.2/32" }] }
            ],
            "pipelines": [
                { "id": "main", "rules": [{
                    "name": "entry",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "forward", "upstream": entry }],
                    "response_matchers": [{ "type": "upstream_equals", "value": entry }],
                    "response_actions_on_match": [{ "type": "jump_to_pipeline", "pipeline": "via" }]
                }]},
                continue_then_jump("via", &checked, "next"),
                allow("next")
            ]
        }));
        assert_eq!(ask(&engine, "10.0.0.1:53000").await, Some(DEFAULT));
        assert_eq!(ask(&engine, "10.0.0.2:53000").await, Some(DEFAULT));
    }

    /// The same for an answer check's jump on the response-jump path.
    /// 响应跳转路径上回答检查触发的跳转也一样。
    #[tokio::test]
    async fn an_answer_check_jump_on_the_response_jump_path_leaves_the_reused_answer_behind() {
        let entry = answering_upstream(Ipv4Addr::new(192, 0, 2, 50), 300)
            .await
            .address;
        let checked = answering_upstream(CHECKED, 300).await.address;
        let hop = answering_upstream(Ipv4Addr::new(192, 0, 2, 60), 300)
            .await
            .address;
        let default = answering_upstream(DEFAULT, 300).await.address;
        let engine = engine_from(serde_json::json!({
            "settings": settings(&default),
            "pipeline_select": [
                { "pipeline": "main", "matchers": [{ "type": "client_ip", "cidr": "10.0.0.1/32" }] },
                { "pipeline": "next", "matchers": [{ "type": "client_ip", "cidr": "10.0.0.2/32" }] }
            ],
            "pipelines": [
                { "id": "main", "rules": [{
                    "name": "entry",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "forward", "upstream": entry }],
                    "response_matchers": [{ "type": "upstream_equals", "value": entry }],
                    "response_actions_on_match": [{ "type": "jump_to_pipeline", "pipeline": "via" }]
                }]},
                { "id": "via", "rules": [
                    {
                        "name": "checked",
                        "matchers": [{ "type": "any" }],
                        "actions": [{ "type": "forward", "upstream": checked }],
                        "response_matchers": [{ "type": "upstream_equals", "value": checked }],
                        "response_actions_on_match": [{ "type": "continue" }]
                    },
                    {
                        "name": "hop",
                        "matchers": [{ "type": "any" }],
                        "actions": [{ "type": "forward", "upstream": hop }],
                        "response_matchers": [{ "type": "upstream_equals", "value": hop }],
                        "response_actions_on_match": [{ "type": "jump_to_pipeline", "pipeline": "next" }]
                    }
                ]},
                allow("next")
            ]
        }));
        assert_eq!(ask(&engine, "10.0.0.1:53000").await, Some(DEFAULT));
        assert_eq!(ask(&engine, "10.0.0.2:53000").await, Some(DEFAULT));
    }
}
