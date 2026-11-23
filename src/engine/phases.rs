use super::Engine;
use crate::cache::{CacheEntry, CachedQuestion};
use crate::config::GlobalSettings;
use crate::config::{Action, Transport};
use crate::ecs_scope::{EcsReach, EcsView, ForwardEcs};
use crate::engine::execution::{Request, Route};
use crate::engine::observation::{Observed, cached_source, report_response_rule};
use crate::engine::refresh::{RefreshCheck, RefreshTarget};
use crate::engine::response::extract_ttl;
use crate::engine::response_log::{ResponseInfo, Source};
use crate::engine::rules::{self, ResponseActionResult, ResponseContext};
use crate::engine::types::{EngineInner, InflightEntry, InflightQuestion};
use crate::engine::upstream::{UpstreamFailure, reject_failure_reply_on_refresh};
use crate::engine::utils::engine_helpers::{build_response, build_servfail_response_fast};
use crate::engine::utils::{InflightCleanupGuard, set_id};
use crate::matcher::{Requester, RuntimeResponseMatcherWithOp};
use crate::observe::{CacheHit, CacheHitKind};
use crate::proto_utils;
use anyhow::Context;
use bytes::{Bytes, BytesMut};
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{DNSClass, Record, RecordType};
use std::borrow::Cow;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::debug;

/// Result of the Forward phase
pub enum ForwardResult {
    /// 请求的应答，上游失败以后改用的（过期条目、SERVFAIL、miss 动作给出的）也是。后台刷新的上游一失败刷新就结束了（见
    /// `Forwarding::settle`），拿到的总是上游的应答或者规则据它给出的
    /// The request's answer, what it answers instead after an upstream failure (a stale entry,
    /// SERVFAIL, what the miss actions produced) included. A background refresh ends as soon
    /// as its upstream fails (see `Forwarding::settle`), and always gets an upstream's answer
    /// or what the rules give by it
    Success(Bytes),
    /// Request needs to continue (e.g. Action::Continue)
    /// Boxed to reduce enum size (ResponseContext is ~256 bytes)
    /// `answer_ttl`：回答检查看的那份上游应答在缓存里能留多久，此后据它给出的静态应答都不超过这么久（见
    /// `Route::answer_ttl`）；miss 动作在上游失败以后做的 continue 手里没有应答，是 0
    /// `answer_ttl`: how long the upstream answer the answer check read may stay in the cache,
    /// which no static answer given by it from here on outlasts (see `Route::answer_ttl`); 0 for
    /// a continue the miss actions made after an upstream failure, with no answer in hand
    Continue {
        ctx: Box<Option<ResponseContext>>,
        answer_ttl: u32,
    },
    /// 响应动作跳到 `pipeline`：请求在那里接着走规则，转发照原样发出这次转发发出的 `packet`，它带的 ECS 是 `carried`；应答
    /// 照旧缓存在跳转前这个 pipeline 的键下（见 `handle_packet_internal`）。这次转发登记的条目留给请求（见 `Route::held_inflight`），
    /// 等它拿到最终的应答再交出去
    /// A response action jumps to `pipeline`: the request goes on with the rules there, its
    /// forwards sending `packet`, what this forward sent, as it is, with `carried` as its ECS;
    /// answers are still cached under the key of this pipeline, the one jumped from (see
    /// `handle_packet_internal`). The entry this forward registered stays with the request (see
    /// `Route::held_inflight`) and is handed the final answer. `answer_ttl` as on Continue
    Jump {
        pipeline: Arc<str>,
        packet: Bytes,
        carried: ForwardEcs,
        answer_ttl: u32,
    },
}
use hickory_proto::serialize::binary::BinDecodable;

/// Immutable cache lookup data shared by normal and refresh-wait paths.
pub struct CacheLookupContext<'a> {
    pub state: &'a Arc<EngineInner>,
    pub qname: &'a str,
    pub qtype: RecordType,
    pub qclass: DNSClass,
    /// The query bits (see `QueryFlags`) / 查询位（见 `QueryFlags`）
    pub flags: proto_utils::QueryFlags,
    pub pipeline_id: &'a str,
    /// Response cache slot / 响应缓存槽位
    pub slot: u64,
    pub tx_id: u16,
    pub start: Instant,
    pub peer: &'a std::net::SocketAddr,
    /// Who is asking: picks the answer in the slot, and a background refresh replays
    /// the request the same way (address, EDNS, the client's own ECS).
    /// 谁在问：据此在槽位里挑应答，后台刷新也照此重放请求（地址、EDNS、客户端自己的 ECS）。
    pub requester: Requester,
    /// Observer context of the request; cache hits are reported through it.
    /// 所属请求的观察者上下文；缓存命中通过它上报。
    pub observed: Observed<'a>,
}

impl CacheLookupContext<'_> {
    /// 槽位里的应答要回答的问题 / The question the answers in the slot must answer
    fn question(&self) -> CachedQuestion<'_> {
        CachedQuestion {
            qname: self.qname,
            pipeline_id: self.pipeline_id,
            qtype: u16::from(self.qtype),
            qclass: u16::from(self.qclass),
            flags: self.flags,
        }
    }
}

/// 缓存里的一份应答现在算什么 / What a cached answer counts as now
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Age {
    /// 还在 TTL 之内 / Still within its TTL
    Fresh,
    /// TTL 到了，还能当过期应答交出去（RFC 8767）/ Past its TTL, and still fit to go out as a stale answer (RFC 8767)
    Stale,
    /// TTL 到了，不能再用 / Past its TTL and of no further use
    Spent,
}

/// 存了 `elapsed_secs` 秒的 `hit` 现在算什么：TTL 之内是新鲜的；TTL 到了以后，开着 serve_stale、不是失败应答
/// （SERVFAIL、REFUSED、扩展 RCODE，见 `is_failure_reply`）、过期没超过 serve_stale_expire_ttl（0 不限）的还能当过期应答
/// 交出去，其余的不能再用。查缓存、上游失败时找过期应答、等刷新时都按这一处判断
/// What `hit`, stored `elapsed_secs` seconds ago, counts as now: within its TTL it is fresh;
/// past it, with serve_stale on, no failure reply (SERVFAIL, REFUSED, an extended RCODE, see
/// `is_failure_reply`) and no longer past its TTL than serve_stale_expire_ttl (0 for no limit)
/// it can still go out stale, and otherwise it is of no use. The cache lookup, looking for a
/// stale answer after an upstream failure and waiting for a refresh all go by this alone
pub(crate) fn age_of(hit: &CacheEntry, elapsed_secs: u64, settings: &GlobalSettings) -> Age {
    if elapsed_secs < u64::from(hit.original_ttl) {
        Age::Fresh
    } else if hit.spent(elapsed_secs, kept_past_ttl(settings)) {
        Age::Spent
    } else {
        Age::Stale
    }
}

/// 应答过了 TTL 还能当过期应答用多久，缓存也就留它这么久（见 `CacheEntry::spent`）：开着 serve_stale 时是
/// serve_stale_expire_ttl（0 是不限，只受缓存容量约束），关着时是 0
/// How long an answer past its TTL can still go out stale, and so how long the cache keeps it
/// (see `CacheEntry::spent`): serve_stale_expire_ttl with serve_stale on (0 for no limit but
/// the cache's capacity), 0 with it off
pub(crate) fn kept_past_ttl(settings: &GlobalSettings) -> Duration {
    match (settings.serve_stale, settings.serve_stale_expire_ttl) {
        (false, _) => Duration::ZERO,
        (true, 0) => Duration::from_secs(u64::MAX),
        (true, stale) => Duration::from_secs(stale),
    }
}

/// 过期还能用的 `hit`（见 [`Age::Stale`]）是不是现在就交出去、按哪种上报：没开 serve_stale_client_timeout_ms
/// 时马上交出；规则自己给出的应答没有上游可等，也马上交出（它的刷新照样发起，见 `serve_stale`）；别的先等上游（见
/// `Engine::answer_from_cache`），只有这份应答刚刷新失败过的不等（RFC 8767 第 5 节，见 `REFRESH_FAILURE_RECHECK`）。
/// 查缓存和快速路径都按这一处判断
/// Whether `hit`, past its TTL and still of use (see [`Age::Stale`]), goes out right now, and
/// reported as what: at once with serve_stale_client_timeout_ms off; at once too for an
/// answer the rules gave, with no upstream to wait for (its refresh starts all the same, see
/// `serve_stale`); any other waits on the upstream first (see `Engine::answer_from_cache`), and
/// only an answer whose refresh failed lately does not wait (RFC 8767 section 5, see
/// `REFRESH_FAILURE_RECHECK`). The cache lookup and the fast path both go by this alone
pub(crate) fn stale_at_once(
    engine: &Engine,
    settings: &GlobalSettings,
    slot: u64,
    hit: &CacheEntry,
) -> Option<CacheHitKind> {
    if settings.serve_stale_client_timeout_ms == 0 || hit.upstream.is_none() {
        Some(CacheHitKind::Stale)
    } else if failed_lately(engine, slot, hit) {
        Some(CacheHitKind::StaleUpstreamFailure)
    } else {
        None
    }
}

/// 槽位 `slot` 里的 `hit` 刷新失败过、还在复查时间之内（见 `RefreshFailures`）/ Whether `hit` in slot
/// `slot` failed a refresh within the recheck time (see `RefreshFailures`)
fn failed_lately(engine: &Engine, slot: u64, hit: &CacheEntry) -> bool {
    engine
        .refresh_failures
        .failed_recently(RefreshTarget::mark_of(slot, &hit.reach), hit.fetched_at)
}

/// 观察者看到的这次缓存命中：存了 `elapsed_secs` 秒的新鲜应答带上剩下的 TTL，过期应答不带
/// The cache hit as the observer sees it: a fresh answer stored `elapsed_secs` seconds ago
/// carries the TTL it has left, a stale one none
pub(crate) fn cache_hit_of(
    hit: &CacheEntry,
    kind: CacheHitKind,
    elapsed_secs: u32,
) -> CacheHit<'_> {
    CacheHit {
        kind,
        remaining_ttl: (kind == CacheHitKind::Fresh)
            .then(|| Duration::from_secs(u64::from(hit.original_ttl.saturating_sub(elapsed_secs)))),
        original_ttl: Some(Duration::from_secs(u64::from(hit.original_ttl))),
        source: cached_source(hit.upstream.as_deref()),
    }
}

/// [`check_cache_logged`] 在缓存里找到的 / What [`check_cache_logged`] found in the cache
pub(crate) enum Looked {
    /// 交出去的应答 / The answer that goes out
    Answered(Bytes),
    /// 先等上游的过期应答（见 `stale_at_once`）：它的刷新已经发起，等它的见 `Engine::answer_from_cache`
    /// A stale answer waiting on the upstream first (see `stale_at_once`): its refresh has
    /// started, and `Engine::answer_from_cache` waits for it
    Waiting(Arc<CacheEntry>),
    /// 没有能用的 / Nothing of use
    Missed,
}

/// 查一次缓存：槽位里这个请求的那份应答、它存了多少秒、现在算什么
/// One cache lookup: this request's answer in the slot, how many seconds it has been stored,
/// and what it counts as now
fn cached_hit(
    engine: &Engine,
    context: &CacheLookupContext<'_>,
) -> Option<(Arc<CacheEntry>, u64, Age)> {
    // 缓存只去掉存了 cache_max_ttl 以上的应答，应答自己的 TTL 到没到在这里判断
    // The cache only drops answers stored cache_max_ttl or longer ago; whether the answer's own
    // TTL ran out is decided here
    let now = Instant::now();
    let hit = engine.cache_get(
        context.slot,
        &context.requester.ecs_view(),
        &context.question(),
    )?;
    let elapsed_secs = now.saturating_duration_since(hit.inserted_at).as_secs();
    let age = age_of(&hit, elapsed_secs, &context.state.pipeline.settings);
    Some((hit, elapsed_secs, age))
}

/// 同 [`cached_hit`]，只给新鲜的、过期还能用的；不能再用的顺手去掉
/// As [`cached_hit`], giving only one fresh, or stale and still of use; one of no further
/// use goes
fn usable_hit(
    engine: &Engine,
    context: &CacheLookupContext<'_>,
) -> Option<(Arc<CacheEntry>, u64, Age)> {
    let (hit, elapsed_secs, age) = cached_hit(engine, context)?;
    if age == Age::Spent {
        engine.cache_invalidate(context.slot, &hit);
        return None;
    }
    Some((hit, elapsed_secs, age))
}

/// Checks the response cache: a fresh answer goes out with its TTLs aged and may start a
/// background refresh; an expired one is served stale, waits on its refresh, or is dropped
/// as serve_stale says.
/// 查响应缓存：新鲜的应答按停留时间减 TTL 后给出，必要时发起后台刷新；过期的按 serve_stale
/// 的设置当作 stale 提供、等它的刷新，或者删掉。
pub(crate) fn check_cache_logged(
    engine: &Engine,
    context: &CacheLookupContext<'_>,
    response: &mut ResponseInfo,
) -> Looked {
    let Some((hit, elapsed_secs, age)) = usable_hit(engine, context) else {
        return Looked::Missed;
    };
    if age == Age::Fresh {
        return Looked::Answered(serve_fresh(engine, context, &hit, elapsed_secs, response));
    }
    let view = context.requester.ecs_view();
    match stale_at_once(engine, &context.state.pipeline.settings, context.slot, &hit) {
        Some(kind) => Looked::Answered(serve_stale(engine, context, &hit, &view, kind, response)),
        // 先等上游：条目留着，等待到头时交出；刷新现在就发起，等的就是它
        // The upstream comes first: the entry stays to go out when the wait runs out,
        // and its refresh, which is what is waited for, starts now
        None => {
            engine.spawn_background_refresh(context.state, &hit, context.slot, context.requester);
            Looked::Waiting(hit)
        }
    }
}

/// 等过上游以后（见 `Engine::answer_from_cache`）再查一次缓存：新鲜的照常给出；还是过期的不再等，按刚才发生的上报——等到
/// 头时刷新还在跑是客户端等待超时，刷新失败过是上游失败，都不是（没有刷新可等，或者刷新结束了却没给这个请求方带回新应答）
/// 就是直接交出的过期应答
/// Look in the cache again once the upstream was waited on (see `Engine::answer_from_cache`):
/// a fresh answer goes out as usual; one still stale waits no more and is reported as what
/// happened — the client wait running out while the refresh still ran (`still_refreshing`), an
/// upstream failure when the refresh failed, and otherwise (no refresh to wait for, or one that
/// ended bringing nothing fresh for this requester) a stale answer served at once
pub(crate) fn check_cache_after_wait(
    engine: &Engine,
    context: &CacheLookupContext<'_>,
    still_refreshing: bool,
    response: &mut ResponseInfo,
) -> Option<Bytes> {
    let (hit, elapsed_secs, age) = usable_hit(engine, context)?;
    if age == Age::Fresh {
        return Some(serve_fresh(engine, context, &hit, elapsed_secs, response));
    }
    let kind = if still_refreshing {
        CacheHitKind::StaleClientTimeout
    } else if failed_lately(engine, context.slot, &hit) {
        CacheHitKind::StaleUpstreamFailure
    } else {
        CacheHitKind::Stale
    };
    let view = context.requester.ecs_view();
    Some(serve_stale(engine, context, &hit, &view, kind, response))
}

/// 交出新鲜的 `hit`：TTL 都减去存了的秒数（RFC 1035 第 5.2 节），快到期的顺带发起后台刷新
/// Serve the fresh `hit`: every TTL less the seconds it has been stored (RFC 1035 section
/// 5.2), with a background refresh started when it is due
fn serve_fresh(
    engine: &Engine,
    context: &CacheLookupContext<'_>,
    hit: &Arc<CacheEntry>,
    elapsed_secs: u64,
    response: &mut ResponseInfo,
) -> Bytes {
    let view = context.requester.ecs_view();
    let elapsed = crate::proto_utils::saturating_u64_to_u32(elapsed_secs);
    let resp_bytes = served_from_cache(hit, context.tx_id, &view, ServedTtl::Elapsed(elapsed));

    // Trigger a background refresh before returning the cached answer / 返回缓存的应答之前，看要不要发起后台刷新
    let refresh = RefreshCheck::of(&context.state.pipeline.settings, hit, elapsed);
    if let Some(RefreshCheck { remaining_ttl, .. }) = refresh.filter(RefreshCheck::due) {
        debug!(
            event = "cache_background_refresh_trigger",
            qname = %context.qname,
            qtype = ?context.qtype,
            remaining_ttl = remaining_ttl,
            original_ttl = hit.original_ttl,
            "Triggering background refresh for cached entry"
        );
        engine.spawn_background_refresh(context.state, hit, context.slot, context.requester);
    }

    response.served_from_cache(hit);
    if let Some((observer, ctx)) = context.observed {
        observer.cache_hit(ctx, &cache_hit_of(hit, CacheHitKind::Fresh, elapsed));
    }
    resp_bytes
}

/// 缓存留一份应答多久：它自己的 TTL（记录里最小的，否定应答用 SOA 的负缓存 TTL）收进
/// `min_ttl..=cache_max_ttl`，和应答带的 TTL 一样（见 `forward_upstream`）；0 就不缓存。
/// 它自己的 TTL 为 0 时不缓存：要么没有可依据的 TTL（没有 SOA 的否定应答，RFC 2308 第 4 节说不要
/// 缓存），要么 min_ttl 为 0 时记录的 TTL 就是 0。
/// How long the cache keeps an answer: its own TTL (the least of its records', the
/// SOA negative TTL for a negative answer) brought into `min_ttl..=cache_max_ttl`,
/// as the TTLs the answer carries are (see `forward_upstream`); 0 means not cached.
/// An own TTL of 0 is not cached: either the answer gives no TTL to go by (a
/// negative answer without SOA, which RFC 2308 section 4 says not to cache), or,
/// with min_ttl 0, its records have TTL 0.
fn ttl_to_cache(engine: &Engine, own_ttl: u64, min_ttl: Duration) -> u32 {
    if own_ttl == 0 {
        return 0;
    }
    proto_utils::saturating_u64_to_u32(own_ttl.max(min_ttl.as_secs())).min(engine.ttl_cap())
}

/// 缓存留一份静态应答多久。它是规则据一份上游应答给出的，那份应答在缓存里能留 `answer_ttl` 秒（见 `ttl_to_cache`）：
/// 过了这么久上游可能答得不一样了，规则也就可能给出别的，所以它留得不比那份应答久。它带的 TTL（`carried`，记录里最小的，
/// 见 `least_ttl`）更短时按它带的；不带记录的（deny 的 REFUSED、static_response、问的类型没有记录时的 NODATA）没有自己的
/// TTL，就留 `answer_ttl`。规则直接给出的、上游失败以后兜底给出的不据哪份应答，`answer_ttl` 是 0，不缓存。请求阶段和响应阶段
/// 都照这一处算。min_ttl 只抬上游回答的 TTL，不抬规则写的：抬了缓存时间、记录却不抬，缓存里的记录 TTL 先走完，交出去的就是
/// TTL 为 0 的记录。以前带记录的不看那份应答，写死的 300 秒比来源的 TTL 长时答错；不带记录的按 min_ttl，默认为 0 时不缓存，
/// 防重绑定的 deny 每次都要再问上游
/// How long the cache keeps a static answer. The rules gave it by an upstream answer that
/// may stay in the cache for `answer_ttl` seconds (see `ttl_to_cache`): after that the
/// upstream may answer otherwise and the rules give something else, so it stays no longer
/// than that answer. The TTL it carries (`carried`, the least of its records', see
/// `least_ttl`) goes when shorter; one without records (deny's REFUSED, static_response, the
/// NODATA of a type with no records) has no TTL of its own and stays for `answer_ttl`. One
/// the rules give outright, or as a fallback after an upstream failure, goes by no answer:
/// `answer_ttl` is 0 and it is not cached. The request phase and the response phase both go
/// by this. min_ttl raises the TTLs of upstream answers, not those a rule writes: raising the
/// time cached and not the records would have the cached records' TTLs run out first, going
/// out as 0. One with records used to ignore that answer, a hard-coded 300 seconds outlasting
/// the TTL it came by and answering wrong; one without went by min_ttl, and with the default
/// 0 was not cached, a deny against rebinding asking the upstream again every time
fn static_ttl(carried: Option<u32>, answer_ttl: u32) -> u32 {
    carried.map_or(answer_ttl, |own| own.min(answer_ttl))
}

/// How a reply served from the cache gets its TTLs / 从缓存给出的应答怎样设置 TTL
#[derive(Debug, Clone, Copy)]
pub(crate) enum ServedTtl {
    /// Fresh: every TTL lowered by the seconds the answer has been cached
    /// 新鲜：每个 TTL 减去应答已经缓存的秒数
    Elapsed(u32),
    /// Stale (RFC 8767): every TTL set to this / 过期（RFC 8767）：每个 TTL 设为这个值
    Stale(u32),
}

/// The reply a cache hit sends: the cached answer with the request's ID, its TTLs
/// as `ttl` says, and the ECS option RFC 7871 section 7.2.2 asks for. A client
/// that sent no ECS gets none (the cached answer has none, see
/// `insert_dns_cache_entry`); one that sent ECS gets its own subnet back, with
/// the scope the answer has for it.
/// 缓存命中时发出的应答：缓存的应答，换上请求的 ID，按 `ttl` 设置 TTL，并带上 RFC 7871
/// 第 7.2.2 节要求的 ECS 选项。没带 ECS 的客户端拿到的应答不带 ECS（缓存的应答本就去掉了，
/// 见 `insert_dns_cache_entry`）；带了 ECS 的客户端拿回它自己的子网，作用范围是这份应答
/// 对它的作用范围。
pub(crate) fn served_from_cache(
    hit: &CacheEntry,
    tx_id: u16,
    view: &EcsView,
    ttl: ServedTtl,
) -> Bytes {
    // An ECS option nobody can read gets no echo: there is nothing well-formed to send back
    // 谁也读不懂的 ECS 选项不回显：没有合规的内容可以发回
    let echoed = view
        .client
        .filter(|client| !client.is_opaque())
        .and_then(|client| proto_utils::echo_ecs(&hit.bytes, &client, hit.reach.echo_scope(view)));
    let mut resp_bytes = BytesMut::from(echoed.as_deref().unwrap_or(&hit.bytes));
    match ttl {
        ServedTtl::Elapsed(0) => {}
        ServedTtl::Elapsed(elapsed) => proto_utils::patch_all_ttls(&mut resp_bytes, elapsed),
        ServedTtl::Stale(stale_ttl) => proto_utils::set_all_ttls(&mut resp_bytes, stale_ttl),
    }
    set_id(&mut resp_bytes, tx_id);
    resp_bytes.freeze()
}

/// RFC 8767: after an upstream failure, check if a stale (expired but still in the cache)
/// cache entry exists. Returns the stale response bytes with TTL set to serve_stale_ttl,
/// reported to the observer as served on an upstream failure.
/// RFC 8767：上游失败以后，检查是否存在过期但仍在缓存中的缓存条目。返回 TTL 设置为
/// serve_stale_ttl 的过期响应字节，按上游失败时交出的那种上报观察者。
///
/// Does not emit the `dns_response` record; only the engine request path logs it.
/// 不输出 `dns_response` 记录；该记录只由引擎请求路径输出。
pub(crate) fn check_stale_cache_logged(
    engine: &Engine,
    context: &CacheLookupContext<'_>,
    response: &mut ResponseInfo,
) -> Option<Bytes> {
    if !context.state.pipeline.settings.serve_stale {
        return None;
    }
    // 不能再用的留给查缓存去掉 / One of no further use is left for the lookup to drop
    let (hit, _, age) = cached_hit(engine, context)?;
    (age == Age::Stale).then(|| {
        let view = context.requester.ecs_view();
        serve_stale(
            engine,
            context,
            &hit,
            &view,
            CacheHitKind::StaleUpstreamFailure,
            response,
        )
    })
}

/// 把过期的 `hit` 当作 stale 提供（RFC 8767）：TTL 都设成 serve_stale_ttl；顺带发起后台刷新（刷新失败时
/// serve_stale_ttl_reset 才续期，见 `spawn_background_refresh`）；按 `kind` 上报观察者，记下应答取自缓存。
/// 交出过期应答的都走这里：查缓存、等上游到头、上游失败以后，还有快速路径
/// Serve the expired `hit` stale (RFC 8767): every TTL set to serve_stale_ttl; a background
/// refresh is started too (only its failure renews the answer, with serve_stale_ttl_reset on,
/// see `spawn_background_refresh`); the observer hears of it as `kind`, and the answer is noted
/// as taken from the cache. Every stale answer goes out through here: from the cache lookup,
/// when the wait for the upstream runs out, after an upstream failure, and on the fast path
pub(crate) fn serve_stale(
    engine: &Engine,
    context: &CacheLookupContext<'_>,
    hit: &Arc<CacheEntry>,
    view: &EcsView,
    kind: CacheHitKind,
    response: &mut ResponseInfo,
) -> Bytes {
    let settings = &context.state.pipeline.settings;
    debug!(
        event = "serve_stale",
        kind = ?kind,
        qname = %context.qname,
        qtype = ?context.qtype,
        rcode = ?hit.rcode,
        original_ttl = hit.original_ttl,
        stale_for_secs = hit
            .inserted_at
            .elapsed()
            .as_secs()
            .saturating_sub(u64::from(hit.original_ttl)),
        request_ms = context.start.elapsed().as_millis() as u64,
        client_ip = %context.peer.ip(),
        pipeline = %context.pipeline_id,
        "RFC 8767: serving a stale answer"
    );
    let resp_bytes = served_from_cache(
        hit,
        context.tx_id,
        view,
        ServedTtl::Stale(settings.serve_stale_ttl),
    );
    // 发起后台刷新，重新决定一次。规则给的应答（没有上游的那种）也一样：它是对上游那次应答的检查结果，不重新决定的话
    // 每次命中都把它续上，一直用下去
    // Start a background refresh to decide again. An answer the rules gave (one with no
    // upstream) is no different: it is what the check of that one reply came to, and not
    // decided again it would be renewed on every hit and served for ever
    engine.spawn_background_refresh(context.state, hit, context.slot, context.requester);
    if let Some((observer, ctx)) = context.observed {
        observer.cache_hit(ctx, &cache_hit_of(hit, kind, 0));
    }
    response.served_from_cache(hit);
    resp_bytes
}

/// Request data required to build and cache a static DNS response.
pub struct StaticDecisionContext<'a> {
    pub packet: &'a [u8],
    pub qname: &'a str,
    pub qtype: RecordType,
    pub qclass: DNSClass,
    pub pipeline_id: &'a Arc<str>,
    /// Response cache slot / 响应缓存槽位
    pub slot: u64,
    /// The query bits the slot was computed with / 算槽位时用的查询位
    pub flags: proto_utils::QueryFlags,
    /// Whom the answer applies to: the forwards the request passed before it
    /// (see `Route::trail`)
    /// 应答适用于谁：请求在它之前经过的转发（见 `Route::trail`）
    pub reach: &'a EcsReach,
    /// 它所依据的那份上游应答在缓存里能留多久（见 `Route::answer_ttl`、`static_ttl`）：取决于上游应答的缓存起来，下次
    /// 不必再问上游。别的都是 0、不缓存：规则直接给出的，规则下次照样直接给出（快速路径、规则缓存），不用问谁，从响应缓存拿
    /// 的话查询日志和规则计数就记不到这条规则，它的 log 动作也不执行；上游失败以后兜底给出的只是这一次请求的
    /// How long the upstream answer it goes by may stay in the cache (see `Route::answer_ttl`,
    /// `static_ttl`): one depending on an upstream's answer is cached so the upstream need not
    /// be asked next time. Anything else has 0 and is not cached: one the rules give outright
    /// they give again outright (the fast path, the rule cache) with nobody to ask, and taken
    /// from the response cache it would be missing from the query log and rule counts under its
    /// rule, its log action not run; one given as a fallback after an upstream failure is for
    /// this request alone
    pub answer_ttl: u32,
}

/// 处理静态决定：照请求构造应答；取决于上游应答的（见 `StaticDecisionContext::answer_ttl`）按 `static_ttl` 说的
/// 时长缓存。槽位把规则分得开的请求方分开（见 `RuntimePipeline::requester`），所以规则按「谁在问」给的应答也和别的应答
/// 一样缓存。
/// Handles Decision::Static: builds the answer for the request, and caches one that depends
/// on an upstream's answer (see `StaticDecisionContext::answer_ttl`) for as long as
/// `static_ttl` says. The slot keeps apart the requesters the rules tell apart (see
/// `RuntimePipeline::requester`), so an answer the rules give by who is asking is cached like
/// any other.
/// Does not emit the `dns_response` record; only the engine request path logs it.
/// 不输出 `dns_response` 记录；该记录只由引擎请求路径输出。
pub fn handle_static_decision(
    engine: &Engine,
    context: &StaticDecisionContext<'_>,
    rcode: ResponseCode,
    answers: Vec<Record>,
) -> anyhow::Result<Bytes> {
    let StaticDecisionContext {
        packet,
        qname,
        qtype,
        qclass,
        pipeline_id: current_pipeline_id,
        slot,
        flags,
        reach,
        answer_ttl,
    } = *context;
    // Need full request for building response / 需要完整请求来构建响应
    let req = Message::from_bytes(packet).context("parse request for static")?;
    let ttl = static_ttl(super::response::least_ttl(&answers), answer_ttl);
    let resp_bytes = build_response(&req, rcode, answers)?;

    if ttl > 0 {
        engine.insert_dns_cache_entry(
            slot,
            CacheEntry::from_response(
                resp_bytes.clone(),
                rcode,
                None, // Static responses have no upstream
                qname,
                current_pipeline_id.clone(),
                u16::from(qtype),
                u16::from(qclass),
                flags,
                ttl,
            )
            .with_reach(reach.clone()),
        );
    }

    Ok(resp_bytes)
}

/// 转发决定自己说的：问哪些上游、怎样问、回答检查做什么。请求本身见 `Request`，它沿着规则走到了哪里见 `Route`
/// What a forward decision itself says: which upstreams to ask, how, and what the answer check
/// does. The request itself is in `Request`, how far along the rules it has come in `Route`
#[derive(Clone, Copy)]
pub(crate) struct ForwardDecision<'a> {
    pub(crate) upstream: &'a Arc<str>,
    pub(crate) pre_split_upstreams: Option<&'a Arc<Vec<Arc<str>>>>,
    pub(crate) rule_name: &'a str,
    pub(crate) response_matchers: &'a [RuntimeResponseMatcherWithOp],
    pub(crate) response_actions_on_match: &'a [Action],
    pub(crate) response_actions_on_miss: &'a [Action],
    pub(crate) transport: Option<Transport>,
    /// 发出去之前怎样改写 ECS；响应阶段跳转以后不再改写（见 `Route::jumped`）/ How the ECS is rewritten
    /// before the query goes out; no longer after a response-phase jump (see `Route::jumped`)
    pub(crate) ecs: Option<&'a crate::config::EcsMode>,
    /// continue 之后的 `allow`：复用规则越过的那份应答（见 `Route::reused_response`）/ An `allow` after
    /// a continue: the answer a rule continued past is reused (see `Route::reused_response`)
    pub(crate) allow_reuse: bool,
}

/// Handles Decision::Forward: joins or registers in the inflight map, forwards upstream,
/// applies the response rules and caches the answer.
/// 处理转发决定：合并等待或登记 inflight，转发给上游，执行响应规则，缓存应答。
pub(crate) async fn handle_forward_decision_logged<'a>(
    engine: &'a Engine,
    request: &'a Request<'a>,
    route: &'a mut Route,
    decision: ForwardDecision<'a>,
    response: &mut ResponseInfo,
) -> anyhow::Result<ForwardResult> {
    response.upstream = Some(Source::Upstream(Arc::clone(decision.upstream)));
    let mut forwarding = Forwarding::new(engine, request, route, decision);
    let (reply, reused) = match forwarding.fetch(response).await {
        Fetched::Joined(answer) => return Ok(ForwardResult::Success(answer)),
        Fetched::Own { reply, reused } => (reply, reused),
    };
    let reply = forwarding.weigh(reply, reused);
    // 应答回来以后的处理单独在堆上分配：它的状态（解析出来的报文、响应动作的结果等）只在应答回来
    // 以后才用得着，放在这个函数里，等上游的每个查询都得替它多留一千多字节
    // What happens once the reply is in is allocated on its own: its state (the parsed
    // message, the response actions' result and so on) is only needed once the reply is
    // in, and held in this function it made every query waiting on an upstream reserve
    // over a kilobyte more
    Box::pin(forwarding.settle(reply, response)).await
}

/// 上游的应答，和给出它的上游 / An upstream's reply, and the upstream that gave it
type Reply = anyhow::Result<(Bytes, Arc<str>)>;

/// [`Forwarding::weigh`] 掂量过的应答：上游的应答和给出它的上游；几个上游都回了失败应答、回答检查照样放行的那一个，还带着
/// 解析好的报文，回答阶段拿它当已经检查过的应答，不再解析、检查一遍
/// A reply [`Forwarding::weigh`] weighed: the upstream's answer and the upstream that gave
/// it; the failure reply of several upstreams the answer check let through all the same
/// comes with its parsed message too, which the answer phase takes as an answer checked
/// already, with no second parse or check
type Weighed = anyhow::Result<(Bytes, Arc<str>, Option<Message>)>;

/// 进行中的一次转发：请求、它沿着规则走的路线和转发决定，加上这次发出的包、它带的 ECS、它在 inflight 表里登记的条目。
/// 路线由这次转发接着往下记：它经过的转发（`trail`）、留给后面复用的应答、continue 以后还持有的条目
/// A forward under way: the request, its route along the rules and the forward decision, with
/// the packet it sends, the ECS that packet carries and the entry it registered in the inflight
/// map. The forward goes on noting the route: the forwards passed (`trail`), the answer kept for
/// reuse, the entry still held after a continue
struct Forwarding<'a> {
    engine: &'a Engine,
    request: &'a Request<'a>,
    route: &'a mut Route,
    decision: ForwardDecision<'a>,
    /// 发出的包：ECS 请求改写（RFC 7871）以后的，响应阶段跳转以后是跳转前那次转发发出的那个（见 `Route::jumped`）；只在
    /// 缓存未命中的路上改写，缓存命中和静态应答不受影响
    /// The packet sent: after ECS request rewriting (RFC 7871), or after a response-phase jump
    /// what the forward before the jump sent (see `Route::jumped`); only the cache-miss path
    /// rewrites, cache hits and static answers being unaffected
    packet: Cow<'a, [u8]>,
    /// 这次转发发出的 ECS，它决定应答适用于谁 / What this forward sends as ECS, which decides
    /// whom its reply applies to
    forward_ecs: ForwardEcs,
    /// 这次转发登记的条目。只有登记了条目的请求才把应答交给它；在别人的条目下转发的请求（持有自己条目的请求、领头请求
    /// 离开后自己转发的等待者、不登记条目的后台刷新）把它留给条目的主人
    /// The entry this forward registered. Only the request that registered an entry hands it
    /// an answer; one that forwards under another's entry (a request holding an entry of its
    /// own, a waiter forwarding itself after the leader went away, or a background refresh,
    /// which registers none) leaves it to its owner
    registered: Option<InflightCleanupGuard>,
}

/// [`Forwarding::fetch`] 拿到的 / What [`Forwarding::fetch`] got
enum Fetched {
    /// 等到的别人那次同样的转发的应答 / The answer of the same forward another made, waited on
    Joined(Bytes),
    /// 这次转发自己的应答或失败；`reused` 时是规则越过、这里复用的那份
    /// This forward's own reply or failure; with `reused`, the one a rule continued past,
    /// reused here
    Own { reply: Reply, reused: bool },
}

impl<'a> Forwarding<'a> {
    fn new(
        engine: &'a Engine,
        request: &'a Request<'a>,
        route: &'a mut Route,
        decision: ForwardDecision<'a>,
    ) -> Self {
        let (packet, forward_ecs) = match (&route.jumped, decision.ecs) {
            (Some((packet, carried)), _) => (Cow::Owned(packet.to_vec()), *carried),
            (None, Some(mode)) => {
                let modified = crate::ecs::apply_ecs_for(
                    request.packet,
                    mode,
                    request.peer.ip(),
                    request.requester.ecs.as_ref(),
                );
                tracing::debug!(
                    ecs_mode = ?mode,
                    modified = modified.len() != request.packet.len(),
                    "ECS request rewriting applied / 已应用 ECS 请求改写"
                );
                (
                    Cow::Owned(modified),
                    ForwardEcs::of(Some(mode), &request.requester.ecs_view()),
                )
            }
            (None, None) => (
                Cow::Borrowed(request.packet),
                ForwardEcs::of(None, &request.requester.ecs_view()),
            ),
        };
        route.trail.check_sent(&packet, &forward_ecs);
        Self {
            engine,
            request,
            route,
            decision,
            packet,
            forward_ecs,
            registered: None,
        }
    }

    /// 拿这次转发的应答：规则越过的应答只在决定允许时复用（continue 之后的 `allow`）；其余的等已经在问同一个问题的
    /// 那个，或者自己去问。被截断的应答只在传输层处理一次（见 `forward_upstream`）：拿到的截断应答就是 TCP 也取不到
    /// 完整应答时留下的，和别的应答一样往下走，客户端看到 TC 自己改用 TCP。以前这里对 UDP 转发再问一次 TCP，失败了就走
    /// 失败路径，客户端拿到的是 SERVFAIL
    /// Get this forward's reply: an answer a rule continued past is reused only where the
    /// decision allows it (an `allow` after a continue); otherwise the forward waits on
    /// whoever already asks the same question, or asks for its own. A truncated answer is
    /// dealt with once, in the transport layer (see `forward_upstream`): one that comes back
    /// here is what was left when TCP could not fetch the whole answer either, and goes on like
    /// any other, the client turning to TCP itself on seeing TC. A UDP forward used to ask over
    /// TCP once more here, and on failing took the failure path, the client getting SERVFAIL
    async fn fetch(&mut self, response: &mut ResponseInfo) -> Fetched {
        let allow_reuse = self.decision.allow_reuse;
        if let Some(ctx) = self.route.reused_response.take_if(|_| allow_reuse) {
            return Fetched::Own {
                reply: Ok((ctx.raw, ctx.upstream)),
                reused: true,
            };
        }
        let reply = match self.wait_on_another(response).await {
            Some(Ok(answer)) => return Fetched::Joined(answer),
            Some(Err(gave_up)) => Err(gave_up),
            None => self.ask().await,
        };
        Fetched::Own {
            reply,
            reused: false,
        }
    }

    /// 等已经在问同一个问题的那个请求：等到了给出它的应答，卡住、不等了给出那个失败；没有可等的（空着就登记条目）给
    /// None，这次转发自己去问。后台刷新没有客户端，从不登记、也不等
    /// Wait on the request already asking the same question: its answer once it comes, or the
    /// failure of waiting no more when stuck; None when there is nobody to wait on (an entry
    /// registered when the place is free), and this forward asks itself. A background refresh
    /// has no client, and neither registers nor waits
    async fn wait_on_another(
        &mut self,
        response: &mut ResponseInfo,
    ) -> Option<anyhow::Result<Bytes>> {
        let (engine, request) = (self.engine, self.request);
        if request.refresh.is_some() {
            return None;
        }
        let (keys, key_pipeline) = (self.route.keys, &self.route.key_pipeline);
        // What this forward registers or waits under in the inflight map
        // 这次转发在 inflight 表里登记或等待的问题
        let question = InflightQuestion {
            namespace: request.state.cache_namespace(key_pipeline),
            pipeline_id: key_pipeline,
            qname: request.qname.as_bytes(),
            qtype: request.qtype,
            qclass: request.qclass,
            flags: keys.flags,
            requester: keys.requester,
            client_ecs: request.requester.ecs,
        };
        debug_assert_eq!(
            question.key(),
            keys.inflight,
            "the inflight question is what the inflight key was computed from"
        );
        // 等的那个请求没交出结果就走了（被取消、超时）：重新排一次，空着就自己登记、去问，已经有人重新登记了就等它。
        // 以前直接各自去问，一个领头的带着几个等待者走掉，上游就要被多问几遍。每一圈都有一个领头的走掉，圈数不会多过
        // 同时在等的请求
        // The one waited on went away without a result (cancelled, timed out): line up again,
        // registering and asking when the place is free, or waiting on whoever registered again
        // first. Each used to ask by itself, and a leader leaving with several waiting had the
        // upstream asked that many times over. A leader leaves on every round, so there are no
        // more rounds than requests waiting at once
        loop {
            use dashmap::mapref::entry::Entry;
            let mut rx = match engine.inflight.entry(keys.inflight) {
                // 进不了缓存的也不交给别人（流控拦过这个请求、它发出的 ECS 说不准适用于谁）：它不领头，自己转发。以前
                // 流控拦下以后 continue 到下一条规则，那里的转发照样登记条目，把这台设备拿到的兜底交给同时来问的别的设备
                // What may not go into the cache is not handed to others either (flow control
                // kept this request back, or whom the ECS it sends applies to is unknown): it
                // leads no entry and forwards itself. With flow control having kept it back,
                // continuing to the next rule used to register an entry there all the same,
                // handing this device's fallback to the other devices asking meanwhile
                Entry::Vacant(_) if self.route.trail.is_uncacheable() => return None,
                Entry::Vacant(entry) => {
                    entry.insert(InflightEntry::sharing(
                        &question,
                        key_pipeline,
                        Arc::<[u8]>::from(Arc::clone(request.qname)),
                    ));
                    self.registered = Some(InflightCleanupGuard::new(
                        engine.inflight.clone(),
                        keys.inflight,
                    ));
                    return None;
                }
                // A request holding an entry (see `Route::held_inflight`) never waits
                // on one: the entry may be its own, which the next rule forwards
                // under after a continue, or another request's that waits on
                // this one in turn (continue, then jump into each other's
                // pipeline). It forwards itself instead.
                // 持有条目的请求（见 `Route::held_inflight`）从不等条目：这一条可能就是它
                // 自己的（continue 后下一条规则以相同 hash 转发），也可能是另一个
                // 反过来在等它的请求的（continue 后互相跳进对方的 pipeline）。它
                // 自己转发。
                Entry::Occupied(_) if self.route.held_inflight.is_some() => return None,
                // Another question's entry under the same key: the key is only a hash (see
                // `InflightQuestion`), and waiting on it would hand this request another
                // question's answer. It forwards itself instead.
                // 同一个键下别的问题的条目：键只是哈希（见 `InflightQuestion`），等它就会把
                // 别的问题的应答交给这个请求。它自己转发。
                Entry::Occupied(entry) if !entry.get().asks(&question) => return None,
                Entry::Occupied(mut entry) => entry.get_mut().subscribe(),
            };

            // 等别人正在做的同一个转发。开了流控时这次等待也看卡没卡住（见 `PermitManager::join`）：卡住了、这台设备
            // 留着等的又已经够多，就不等了，照上游失败往下走
            // Waiting on the same forward another is making. With flow control on this wait too
            // is seen to for being stuck (see `PermitManager::join`): stuck with enough of the
            // device's kept waiting already it waits no more, and goes on below as the upstream
            // failing
            let waiting = async {
                rx.changed().await.ok()?;
                rx.borrow().clone()
            };
            let answer = match crate::engine::upstream::wait_for_another(
                engine,
                request.peer.ip(),
                self.decision.upstream,
                request.state.pipeline.upstream_timeout(),
                waiting,
            )
            .await
            {
                Ok(Some(answer)) => answer,
                Ok(None) => continue,
                Err(gave_up) => return Some(Err(gave_up)),
            };
            if let Some((observer, ctx)) = request.observed {
                observer.inflight_joined(ctx);
            }
            let mut answer = BytesMut::from(answer.as_ref());
            set_id(&mut answer, request.tx_id);
            response.upstream = Some(Source::Inflight);
            return Some(Ok(answer.freeze()));
        }
    }

    /// 把这次转发发给上游 / Send this forward upstream
    async fn ask(&self) -> Reply {
        let (request, decision) = (self.request, self.decision);
        crate::engine::upstream::forward_upstream(
            self.engine,
            &self.packet,
            decision.upstream,
            request.state.pipeline.upstream_timeout(),
            decision.transport,
            decision.pre_split_upstreams,
            request.observed,
            request.asker(),
        )
        .await
    }

    /// 掂量这次转发拿到的应答或失败，记进 trail：它决定此后得到的每份应答适用于谁
    /// Weigh the reply or failure this forward got, and note it in the trail: it decides whom
    /// every answer reached from here applies to
    fn weigh(&mut self, reply: Reply, reused: bool) -> Weighed {
        // 流控没让等的失败是这台设备自己的事（见 `UpstreamFailure::withheld`）：这个请求登记的条目、规则 continue 以后还
        // 留着的条目，现在都放下，等在上面的别的请求各自去问，不拿这一个的结果；这个请求此后得到的应答也一律不写缓存——规则在
        // 上游失败时给的静态应答、改问备用上游得到的回答、continue 到后面的规则或者跳到别的规则组得到的回答都一样。缓存是所有
        // 设备共用的：别的设备问这个名字时上游并没有失败，该拿到上游的回答；写进去的话，一台被拦着的设备问过哪个名字，哪个名字
        // 在缓存有效期里对所有设备就都换成了备用的答案
        // A failure with flow control keeping the query from waiting is the device's own affair
        // (see `UpstreamFailure::withheld`): the entry this request registered and the one it
        // still holds after a rule continued both go now, so the other requests waiting on them
        // ask for themselves and get nothing of this one's outcome; and nothing the request gets
        // from here on is cached, be it a static answer the rule gives when the upstream fails, the
        // answer of a fallback upstream, or what a later rule after a continue or another pipeline
        // after a jump answers. The cache is shared by all devices: for another device asking the
        // name the upstream has not failed, and the upstream's answer is what it should get; cached,
        // every name a device held back asked would be the fallback's answer for all devices for
        // as long as the entry lives
        if reply.as_ref().is_err_and(UpstreamFailure::was_withheld) {
            self.registered = None;
            self.route.held_inflight = None;
            self.route.trail.mark_uncacheable();
        }
        let (request, decision) = (self.request, self.decision);
        // 几个上游都回了失败应答时，规则的回答检查照样看得到最先收到的那个（见
        // `rules::check_failure_reply`）；放行的那个连同解析好的报文交给回答阶段（见 [`Weighed`]）。刷新随后照旧拒收它
        // When several upstreams all replied with a failure, the rule's answer check still sees
        // the first of those replies (see `rules::check_failure_reply`); one let through goes
        // to the answer phase with its parsed message (see [`Weighed`]). A refresh still
        // rejects it right after
        let reply = match reply {
            Err(failure) => match rules::check_failure_reply(
                &failure,
                decision.response_actions_on_match,
                |msg, answered| {
                    rules::response_matches(
                        self.engine,
                        decision.response_matchers,
                        answered,
                        request.qname,
                        request.qtype,
                        request.qclass,
                        Some(msg),
                    )
                },
            ) {
                Some((raw, upstream, msg)) => Ok((raw, upstream, Some(msg))),
                None => Err(failure),
            },
            Ok((raw, upstream)) => Ok((raw, upstream, None)),
        };
        // A refresh takes a failure reply as a failed attempt before the response rules
        // see it, as forward_upstream does for a rule with several upstreams: the
        // refresh fails as it does on any upstream failure (see `Self::settle`), and
        // never caches the reply (see reject_failure_reply_on_refresh).
        // 刷新在响应规则看到失败应答之前就把它当作一次失败的尝试，和规则有多个上游时
        // forward_upstream 的做法一样：刷新和上游别的失败一样以失败结束（见 `Self::settle`），
        // 也不缓存这个应答（见 reject_failure_reply_on_refresh）。
        let reply = reply.and_then(|reply| {
            reject_failure_reply_on_refresh(request.refresh.is_some(), &reply.0).map(|()| reply)
        });
        match &reply {
            // 这里复用的、规则越过的应答：它那次转发已经记在 trail 里 / An answer a rule continued
            // past, reused here: the trail already has its forward
            Ok(_) if reused => {}
            Ok((raw, ..)) => self.route.trail.record_reply(self.forward_ecs, raw),
            Err(_) => self.route.trail.record_failure(self.forward_ecs),
        }
        reply
    }

    /// 应答或失败之后：上游有应答时按响应匹配器执行 on_match 或 on_miss，上游失败时执行 on_miss；两边接下来的处理只差在
    /// 手里有没有回答检查看过的应答（见 [`Self::act`]）
    /// After the reply or the failure: with an answer from the upstream the response matchers
    /// pick on_match or on_miss, after an upstream failure on_miss runs; what follows differs
    /// between the two only in whether an answer the answer check read is in hand (see
    /// [`Self::act`])
    async fn settle(
        mut self,
        reply: Weighed,
        response: &mut ResponseInfo,
    ) -> anyhow::Result<ForwardResult> {
        let on_miss = self.decision.response_actions_on_miss;
        match reply {
            Ok((raw, upstream, checked)) => self.answered(raw, upstream, checked, response).await,
            // 后台刷新没有客户端，也没在 inflight 里登记：上游失败就到此为止，把失败原样交回（refresh.rs 记下、退避），
            // 缓存条目和别的请求的等待者都不受影响。miss 动作给出的只是兜底，刷新用不着：以前照跑，静态兜底、问备用
            // 上游拿到的都写进缓存，把预取时还新鲜的那条顶掉，刷新还算成功、不退避
            // A background refresh has no client and never registered in `inflight`: an upstream
            // failure ends it there with the failure itself (refresh.rs notes it and backs off),
            // the cached entry and other requests' waiters untouched. What miss actions give is a
            // fallback a refresh has no use for: they used to run, a static fallback or a backup
            // upstream's answer going into the cache over the entry still fresh at a prefetch,
            // and the refresh counting as a success with no backing off
            Err(e) if self.request.refresh.is_some() => Err(e),
            Err(e) if on_miss.is_empty() => self.upstream_failed(e, response),
            Err(e) => match Message::from_bytes(&self.packet) {
                Ok(req) => self.act(on_miss, None, req, response).await,
                Err(_) => Err(e),
            },
        }
    }

    /// 上游的应答：按响应匹配器挑出要执行的动作，带着应答执行；没有动作时应答就是结果，按它的 TTL 写进缓存
    /// The upstream's answer: the response matchers pick the actions to run, which run with
    /// it; with none the answer is the outcome, cached by its TTL
    async fn answered(
        mut self,
        raw: Bytes,
        upstream: Arc<str>,
        checked: Option<Message>,
        response: &mut ResponseInfo,
    ) -> anyhow::Result<ForwardResult> {
        let (request, decision) = (self.request, self.decision);
        response.upstream = Some(Source::Upstream(Arc::clone(&upstream)));
        // Response rules read the parsed message, so they always take hickory's.
        // Otherwise the quick parse is cached as read for a reply whose structure
        // holds up (see `well_formed_reply`); any other is cached as hickory reads
        // it, or, when only the quick parse can read it, not at all and goes on as it
        // is; a reply neither can read fails the request
        // 响应规则要读解析好的报文，所以总用 hickory 的。没有响应规则时，结构经得起检查的应答
        // 照快速解析的结果缓存（见 `well_formed_reply`）；其余的照 hickory 读出的结果缓存，只有
        // 快速解析读得了的不缓存、照样交出去；两边都读不了的，这次请求出错
        let rules_read_the_reply = !(decision.response_matchers.is_empty()
            && decision.response_actions_on_match.is_empty()
            && decision.response_actions_on_miss.is_empty());
        let quick = (!rules_read_the_reply)
            .then(|| proto_utils::parse_response_quick(&raw))
            .flatten();
        // 回答检查已经放行的失败应答（见 [`Weighed`]）照它解析好的报文来 / A failure reply the
        // answer check let through already (see [`Weighed`]) goes by its parsed message
        let passed = checked.is_some();
        let (rcode, ttl, msg) = match (checked, quick) {
            (Some(msg), _) => (msg.metadata.response_code, extract_ttl(&msg), Some(msg)),
            (None, Some(qr)) if proto_utils::well_formed_reply(&raw) => {
                (qr.rcode, u64::from(qr.min_ttl), None)
            }
            (None, quick) => match (Message::from_bytes(&raw), quick) {
                (Ok(msg), _) => (msg.metadata.response_code, extract_ttl(&msg), Some(msg)),
                (Err(_), Some(qr)) => (qr.rcode, 0, None),
                (Err(error), None) => {
                    return Err(anyhow::Error::new(error).context("parse upstream response"));
                }
            },
        };
        let matched = passed
            || rules::response_matches(
                self.engine,
                decision.response_matchers,
                &upstream,
                request.qname,
                request.qtype,
                request.qclass,
                msg.as_ref(),
            );
        // A refresh reports these too: it acts on the response rules like a client
        // request, and the observer tells the two apart by background_refresh.
        // 刷新同样上报：它和客户端请求一样按响应规则行事，观察者按 background_refresh 区分。
        report_response_rule(
            request.observed,
            &self.route.pipeline,
            decision.rule_name,
            decision.response_matchers.len(),
            matched,
            decision.response_actions_on_match,
        );
        // A background refresh applies the response rules as a client request
        // does (a failure reply never gets here, see above): an answer a rule
        // continues past, or replaces, must not be what the refresh caches.
        // 后台刷新和客户端请求一样执行响应规则（失败应答到不了这里，见上）：规则
        // 越过或替换掉的应答，不能成为刷新写进缓存的结果。
        let actions = if matched {
            decision.response_actions_on_match
        } else {
            decision.response_actions_on_miss
        };
        if actions.is_empty() {
            let ttl = ttl_to_cache(self.engine, ttl, request.state.pipeline.min_ttl());
            self.cache(&raw, rcode, Some(upstream), ttl);
            self.hand_over(&raw);
            return Ok(ForwardResult::Success(raw));
        }
        // 有响应规则时应答总经 hickory 解析，解析不了的上面已经让这次请求出错（见 `rules_read_the_reply`）
        // With response rules the reply is always parsed by hickory, and one it cannot parse
        // has failed the request above (see `rules_read_the_reply`)
        let msg = msg.expect("response rules have the reply parsed by hickory");
        // 手里有应答时，这几个动作用不着请求本身，不必为它们解析一遍；分流规则常写的就是这几个。要用请求的动作，请求解析
        // 不了就让这次请求出错，和上游失败以后一样；以前拿一个 TXID 为 0、没有问题的空报文去执行，答出去的客户端认不得。
        // 用不着请求的动作不读它，给个空报文占位
        // With an answer in hand these actions have no use for the request itself, and it is
        // not parsed for them; these are what splitting rules usually write. For actions that
        // use the request, a request that cannot be parsed fails, as after an upstream failure;
        // they used to run on an empty message with TXID 0 and no question, answering what no
        // client recognises. Actions with no use for the request never read it, an empty message
        // holding its place
        let needs_request = !actions.iter().all(|action| {
            matches!(
                action,
                Action::Log { .. } | Action::Allow | Action::Continue
            )
        });
        let req = if needs_request {
            Message::from_bytes(&self.packet).context("parse the request for response actions")?
        } else {
            Message::new(
                0,
                hickory_proto::op::MessageType::Query,
                hickory_proto::op::OpCode::Query,
            )
        };
        let ctx = ResponseContext { raw, msg, upstream };
        self.act(actions, Some(ctx), req, response).await
    }

    /// 上游失败、规则没有 miss 动作时给客户端的应答：所有上游尝试都耗尽了才这样答（别的错误原样交回），先找过期应答
    /// （RFC 8767），没有就 SERVFAIL
    /// The answer for the client when the upstream failed and the rule has no miss actions,
    /// given once every upstream attempt is exhausted (any other error goes back as it is): a
    /// stale answer (RFC 8767), or else SERVFAIL
    fn upstream_failed(
        &mut self,
        e: anyhow::Error,
        response: &mut ResponseInfo,
    ) -> anyhow::Result<ForwardResult> {
        if e.downcast_ref::<UpstreamFailure>().is_none() {
            return Err(e);
        }
        let (request, decision, route) = (self.request, self.decision, &*self.route);
        let withheld = UpstreamFailure::was_withheld(&e);
        let stale = check_stale_cache_logged(
            self.engine,
            &request.lookup(&route.key_pipeline, route.keys.slot),
            response,
        );
        let answer = match stale {
            Some(stale) => {
                if withheld {
                    debug!(
                        event = "serve_stale_on_upstream_withheld",
                        upstream = %decision.upstream,
                        qname = %request.qname,
                        client_ip = %request.peer.ip(),
                        error = %e,
                        "RFC 8767: flow control kept the query from the upstream, serving stale cache"
                    );
                } else {
                    crate::warn_sparse!(
                        event = "serve_stale_on_upstream_failure",
                        upstream = %decision.upstream,
                        qname = %request.qname,
                        qtype = ?request.qtype,
                        client_ip = %request.peer.ip(),
                        pipeline = %route.pipeline,
                        error = %e,
                        "RFC 8767: upstream failed, serving stale cache"
                    );
                }
                stale
            }
            None => {
                if withheld {
                    debug!(
                        event = "upstream_withheld",
                        upstream = %decision.upstream,
                        qname = %request.qname,
                        client_ip = %request.peer.ip(),
                        error = %e,
                        "flow control kept the query from the upstream"
                    );
                } else {
                    crate::warn_sparse!(
                       event = "upstream_failure",
                       upstream = %decision.upstream,
                       qname = %request.qname,
                       qtype = ?request.qtype,
                       rcode = ?ResponseCode::ServFail,
                       client_ip = %request.peer.ip(),
                       error = %e,
                       pipeline = %route.pipeline,
                       transport = ?decision.transport,
                       "upstream failed"
                    );
                }
                // 问题名的文本总能读回成名字（见 `proto_utils::name_text`）；读不回时交回失败，由监听器自己回 SERVFAIL
                // The question name's text always reads back as a name (see
                // `proto_utils::name_text`); when it does not, the failure goes back and the
                // listener answers SERVFAIL by itself
                let Ok(servfail) = build_servfail_response_fast(
                    request.tx_id,
                    request.qname,
                    u16::from(request.qtype),
                    u16::from(request.qclass),
                    request.flags.recursion_desired(),
                ) else {
                    return Err(e);
                };
                servfail
            }
        };
        self.hand_over(&answer);
        Ok(ForwardResult::Success(answer))
    }

    /// 执行 `actions`：带着回答检查看过的上游应答 `ctx`，或者上游失败以后不带，那时给出的结果是兜底（刷新到不了那里，
    /// 见 [`Self::settle`]）。据应答给出的静态应答、continue 或跳转以后给出的，都不比那份应答在缓存里留得久（见
    /// `static_ttl`）；兜底的不据哪份应答，不缓存
    /// Run `actions`: with the upstream answer `ctx` the answer check read, or without one after
    /// an upstream failure, when what they give is a fallback (a refresh never gets there, see
    /// [`Self::settle`]). A static answer given by the answer, or after a continue or a jump on
    /// it, stays in the cache no longer than that answer may (see `static_ttl`); a fallback goes
    /// by no answer and is not cached
    async fn act(
        mut self,
        actions: &'a [Action],
        ctx: Option<ResponseContext>,
        req: Message,
        response: &mut ResponseInfo,
    ) -> anyhow::Result<ForwardResult> {
        let request = self.request;
        let min_ttl = request.state.pipeline.min_ttl();
        let answer_ttl = ctx.as_ref().map_or(0, |ctx| {
            ttl_to_cache(self.engine, extract_ttl(&ctx.msg), min_ttl)
        });
        let ctx = rules::ApplyResponseActionsContext {
            engine: self.engine,
            request,
            actions,
            ctx_opt: ctx,
            req: &req,
            packet: &self.packet,
            pipeline_id: &self.route.pipeline,
            rule_name: self.decision.rule_name,
            remaining_jumps: self
                .route
                .response_jumps_left(request.state.pipeline.settings.response_jump_limit as usize),
            trail: Some((&mut self.route.trail, self.forward_ecs)),
        };
        // 响应动作和响应跳转的状态单独在堆上分配：不走这两条路的查询就不必为它们预留地方。
        // 以前每个等待中的查询都按最大的那条路（跳转）留着 8 KB，慢上游上挂着三万个查询时，
        // 光这一项就占掉两百多兆
        // The response actions' and the response jump's state are allocated on the heap
        // of their own, so a query that takes neither path reserves no room for them.
        // Every waiting query used to reserve 8 KB for the largest path (the jump), over
        // two hundred megabytes for thirty thousand queries on a slow upstream
        let outcome = Box::pin(rules::apply_response_actions(ctx)).await?;

        match outcome {
            ResponseActionResult::Upstream { ctx } => {
                // The reply to a response action's forward (see
                // reject_failure_reply_on_refresh)
                // 响应动作转发拿到的应答（见 reject_failure_reply_on_refresh）
                reject_failure_reply_on_refresh(request.refresh.is_some(), &ctx.raw)?;
                self.cache(
                    &ctx.raw,
                    ctx.msg.metadata.response_code,
                    Some(ctx.upstream.clone()),
                    ttl_to_cache(self.engine, extract_ttl(&ctx.msg), min_ttl),
                );
                self.hand_over(&ctx.raw);
                response.upstream = Some(Source::Upstream(ctx.upstream));
                Ok(ForwardResult::Success(ctx.raw))
            }
            ResponseActionResult::Static {
                bytes, rcode, ttl, ..
            } => {
                // 上游失败以后 miss 动作给的静态应答只是这一次请求的兜底，不是这个问题的应答，不缓存（`answer_ttl` 是
                // 0）：缓存是所有请求方共用的，写进去的话，上游恢复了它还要一直用到条目到期
                // After an upstream failure a static answer of the miss actions is a fallback
                // for this request, not the answer to the question, and is not cached
                // (`answer_ttl` is 0): the cache is shared by every requester, and cached it
                // would go on serving after the upstream recovered, until the entry expired
                self.cache(&bytes, rcode, None, static_ttl(ttl, answer_ttl));
                self.hand_over(&bytes);
                response.upstream = Some(Source::Static);
                Ok(ForwardResult::Success(bytes))
            }
            ResponseActionResult::Jump { pipeline } => {
                // 跳过去以后的才是最终应答：条目留给请求，和 Continue 一样（见 `Route::held_inflight`）
                // What comes after the jump is the final answer: the entry stays with the
                // request, as on Continue (see `Route::held_inflight`)
                self.keep_for_request();
                Ok(ForwardResult::Jump {
                    pipeline,
                    packet: Bytes::copy_from_slice(&self.packet),
                    carried: self.forward_ecs,
                    answer_ttl,
                })
            }
            ResponseActionResult::Continue { ctx } => {
                // The rule continued past this response, so it is not the answer: keep
                // the entry for the rest of the decision loop (see `Route::held_inflight`)
                // instead of handing it to waiters. An entry held from an earlier
                // continue is dropped in its place, and its waiters forward themselves.
                // Defusing the guard here after a failure used to leave the entry behind
                // with nobody holding it, so the next Forward waited on it until the
                // listener timeout.
                // 规则越过了这个应答，它不是最终结果：条目留给决策循环的后续部分（见
                // `Route::held_inflight`），不把它交给等待者。之前 continue 时持有的条目被它替换掉，
                // 那一条的等待者自己转发。以前上游失败以后在这里 defuse 守卫，条目留在表里却
                // 没人持有，下一条转发会一直等它到监听器超时。
                self.keep_for_request();
                Ok(ForwardResult::Continue {
                    ctx: Box::new(ctx),
                    answer_ttl,
                })
            }
        }
    }

    /// 在这次转发的问题下写一条缓存，留 `ttl` 秒，适用于 trail 接受的请求方；`ttl` 为 0 时不写（见 `ttl_to_cache`、
    /// `static_ttl`）
    /// Cache an answer under this forward's question for `ttl` seconds, for the requesters
    /// the trail admits; with `ttl` 0 nothing is cached (see `ttl_to_cache`, `static_ttl`)
    fn cache(&self, bytes: &Bytes, rcode: ResponseCode, upstream: Option<Arc<str>>, ttl: u32) {
        if ttl == 0 {
            return;
        }
        let (request, route) = (self.request, &*self.route);
        self.engine.insert_dns_cache_entry(
            route.keys.slot,
            CacheEntry::from_response(
                bytes.clone(),
                rcode,
                upstream,
                Arc::clone(request.qname),
                Arc::clone(&route.key_pipeline),
                u16::from(request.qtype),
                u16::from(request.qclass),
                route.keys.flags,
                ttl,
            )
            .with_reach(route.trail.clone()),
        );
    }

    /// 把最终应答交给等在这次转发登记的条目上的请求 / Hand the final answer to the requests
    /// waiting on the entry this forward registered
    fn hand_over(&mut self, answer: &Bytes) {
        if let Some(guard) = self.registered.as_mut() {
            let (request, route) = (self.request, &*self.route);
            guard.hand_over(|| {
                for_waiters(answer, &request.requester, &route.trail, route.echo_floor)
            });
        }
    }

    /// 规则越过了这个应答，或者跳走了：登记的条目留给请求，等最终应答（见 `Route::held_inflight`）
    /// A rule continued past this answer, or jumped away: the entry registered stays with the
    /// request for the final answer (see `Route::held_inflight`)
    fn keep_for_request(&mut self) {
        if let Some(guard) = self.registered.take() {
            self.route.held_inflight = Some(guard);
        }
    }
}

/// The reply as it goes to the client, with the ECS option RFC 7871 section 7.2.2
/// asks for. A client that sent no ECS gets none: a forward may have added one
/// for it (`from_client_ip`, `static`). A client that sent ECS gets its own subnet
/// back, with a scope of at least `at_least`: how many bits of the client's ECS
/// the forwards this request passed made the answer depend on (see
/// `EcsReach::echo_scope`), which is what the cache keeps the answer for. The
/// reply itself may say more: an echo of that subnet keeps a longer scope; an
/// error without ECS, or an echo of another subnet (a forward that replaced the
/// client's), says nothing of how far the answer reaches beyond the client's
/// subnet, so it takes the client's own prefix. Answers from the cache already
/// carry their echo (see `served_from_cache`). An ECS option nobody can read is
/// left alone.
/// 交给客户端的应答，带上 RFC 7871 第 7.2.2 节要求的 ECS 选项。没带 ECS 的客户端拿到的应答
/// 不带 ECS：转发可能替它加过（`from_client_ip`、`static`）。带了 ECS 的客户端拿回自己的子网，
/// 作用范围至少为 `at_least`：这个请求经过的转发让应答依赖客户端 ECS 的多少位（见
/// `EcsReach::echo_scope`），缓存也是按这个范围保存应答的。应答本身可能说得更多：回显了这个
/// 子网就保留更长的作用范围；不带 ECS 的报错、或回显了别的子网（转发换掉了客户端的），没说明
/// 应答在客户端子网之外适用到多大范围，于是取客户端自己的前缀。缓存里的应答已经带着回显（见
/// `served_from_cache`）。谁也读不懂的 ECS 选项不动。
pub(crate) fn client_reply(
    reply: Bytes,
    client: Option<&crate::ecs::EcsKey>,
    at_least: u8,
) -> Bytes {
    use crate::ecs_scope::ReplyEcs;
    let Some(client) = client else {
        return proto_utils::ecs_removed(reply);
    };
    if client.is_opaque() {
        return reply;
    }
    let scope = match proto_utils::reply_ecs(&reply) {
        (ReplyEcs::Subnet { subnet, scope }, _) if subnet == *client => {
            if scope >= at_least {
                return reply;
            }
            at_least
        }
        // The forward cut the client's subnet short (`from_client_ip`, RFC 7871
        // section 7.1): the echo names the client's own network, so its scope holds
        // for the client, as on a cache hit
        // 转发把客户端的子网截短了（`from_client_ip`，RFC 7871 第 7.1 节）：回显的是客户端自己
        // 所在的网段，它的作用范围对客户端同样成立，和命中缓存时一样
        (ReplyEcs::Subnet { subnet, scope }, _)
            if subnet.source_prefix < client.source_prefix
                && client.truncated(subnet.source_prefix) == subnet =>
        {
            scope.max(at_least)
        }
        (ReplyEcs::Subnet { .. }, _) | (ReplyEcs::Absent, false) => {
            client.source_prefix.max(at_least)
        }
        (ReplyEcs::Absent, true) => at_least,
        (ReplyEcs::Unreadable, _) => return reply,
    };
    proto_utils::echo_ecs(&reply, client, scope).map_or(reply, Bytes::from)
}

/// What the waiters on this request's entry get: the reply as this request's
/// own client gets it (see `client_reply`). They send the same ECS, which the
/// inflight key carries, so the echo is theirs too and their own `client_reply`
/// keeps it.
/// 等在这个请求条目上的请求拿到的应答：和这个请求自己的客户端拿到的一样（见
/// `client_reply`）。它们发送的 ECS 相同（inflight 键带着它），回显也就是它们的，它们自己的
/// `client_reply` 会保留它。
pub(crate) fn for_waiters(
    reply: &Bytes,
    requester: &Requester,
    trail: &EcsReach,
    echo_floor: u8,
) -> Bytes {
    match requester.ecs {
        None => reply.clone(),
        Some(client) => client_reply(
            reply.clone(),
            Some(&client),
            echo_floor.max(trail.echo_scope(&requester.ecs_view())),
        ),
    }
}

#[cfg(test)]
mod refresh_response_rule_tests {
    use crate::cache::CacheEntry;
    use crate::engine::core::Engine;
    use crate::engine::test_support::{self as support, answering_upstream, engine_from};
    use bytes::Bytes;
    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
    use hickory_proto::serialize::binary::BinDecodable;
    use serde_json::{Value, json};
    use std::net::{Ipv4Addr, SocketAddr};
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::Duration;

    const CLIENT: &str = "127.0.0.1:53000";
    /// Nothing listens here, so a fall-through to the default upstream fails.
    /// 这里没有监听，落到默认上游的请求会失败。
    const DEAD_UPSTREAM: &str = "127.0.0.1:9";
    /// What the entry being refreshed holds / 要刷新的那条缓存里的应答
    const OLD: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 9);
    /// What the first rule's upstream answers / 第一条规则的上游回的应答
    const PASSED_OVER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    /// What the second rule's upstream answers / 第二条规则的上游回的应答
    const FINAL: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
    const STATIC: &str = "192.0.2.5";

    /// 本机 UDP 上游：每个查询都回带 TC 位的应答，给了 `ip` 时带一条 A 记录，不给时回答段是空的（真实的递归服务器
    /// 常这样回）。TCP 上没有它
    /// Local UDP upstream that answers every query truncated (TC set), with one A record for
    /// `ip` given, or with an empty answer section (as real resolvers often send) without it.
    /// It has no TCP
    async fn spawn_upstream_truncating(ip: Option<Ipv4Addr>) -> String {
        spawn_upstream_replying(move |query, question| {
            let mut resp = Message::new(query.id, MessageType::Response, OpCode::Query);
            resp.metadata.truncation = true;
            resp.add_query(question.clone());
            resp.answers.extend(ip.map(|ip| a_record(question, ip)));
            resp
        })
        .await
    }

    /// Local UDP upstream that answers every query SERVFAIL.
    /// 本机 UDP 上游：每个查询都回 SERVFAIL。
    async fn spawn_upstream_answering_servfail() -> String {
        spawn_upstream_replying(|query, question| {
            let mut resp = Message::new(query.id, MessageType::Response, OpCode::Query);
            resp.metadata.response_code = ResponseCode::ServFail;
            resp.add_query(question.clone());
            resp
        })
        .await
    }

    /// 本机 UDP 上游：每个带问题的查询都回 `reply(查询, 问题)`
    /// Local UDP upstream answering every query with a question by `reply(query, question)`
    async fn spawn_upstream_replying(
        reply: impl Fn(&Message, &Query) -> Message + Send + 'static,
    ) -> String {
        support::upstream(move |query| match query.queries.first() {
            Some(question) => vec![(Duration::ZERO, reply(query, question).to_vec().unwrap())],
            None => Vec::new(),
        })
        .await
        .address
    }

    fn a_record(question: &Query, ip: Ipv4Addr) -> Record {
        Record::from_rdata(
            question.name().clone(),
            300,
            RData::A(hickory_proto::rr::rdata::A(ip)),
        )
    }

    fn query() -> Message {
        let mut request = Message::new(0x5157, MessageType::Query, OpCode::Query);
        // A client asks recursively, as the entries here are stored (`QueryFlags::RECURSIVE`)
        // 客户端按递归方式问，和这里存条目时一样（`QueryFlags::RECURSIVE`）
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(
            Name::from_str("example.com.").unwrap(),
            RecordType::A,
        ));
        request
    }

    fn a_records(bytes: &[u8]) -> Vec<Ipv4Addr> {
        Message::from_bytes(bytes)
            .expect("parse reply")
            .answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::A(a) => Some(a.0),
                _ => None,
            })
            .collect()
    }

    /// A rule that matches every query / 匹配所有查询的规则
    fn rule(name: &str, actions: Value, response_rules: Value) -> Value {
        let mut rule = json!({ "name": name, "matchers": [{ "type": "any" }], "actions": actions });
        for (key, value) in response_rules.as_object().unwrap() {
            rule[key] = value.clone();
        }
        rule
    }

    fn forward(upstream: &str) -> Value {
        json!([{ "type": "forward", "upstream": upstream }])
    }

    fn answer_static() -> Value {
        json!([{ "type": "static_ip_response", "ip": STATIC }])
    }

    /// 不进缓存的静态应答：它带的 TTL 是 0（见 `static_ttl`）
    /// A static answer that is not cached: the TTL it carries is 0 (see `static_ttl`)
    fn answer_uncached() -> Value {
        json!([{ "type": "static_cname_response", "target": "alias.example.com.", "ttl": 0 }])
    }

    fn jump_to(pipeline: &str) -> Value {
        json!([{ "type": "jump_to_pipeline", "pipeline": pipeline }])
    }

    fn continue_() -> Value {
        json!([{ "type": "continue" }])
    }

    /// A jump target answering statically / 静态应答的跳转目标
    fn static_target() -> Value {
        rule("target", answer_static(), json!({}))
    }

    /// A jump target whose upstream never answers / 上游不应答的跳转目标
    fn failing_target() -> Value {
        rule("target", forward(DEAD_UPSTREAM), json!({}))
    }

    /// An engine whose pipeline "main" holds a cached answer with [`OLD`], as a
    /// client request left it; returns the key a refresh of it uses.
    /// 引擎的 "main" pipeline 里缓存着一条 [`OLD`] 应答，就像客户端请求留下的那样；
    /// 返回刷新它时用的键。
    fn engine_with_a_cached_answer(settings: Value, pipelines: Value) -> (Engine, u64) {
        let engine = engine_with(settings, pipelines);
        let key = cache_an_answer(&engine, "main", OLD, 300);
        (engine, key)
    }

    /// The same engine with nothing cached / 同样的引擎，缓存里什么也没有
    fn engine_with(settings: Value, pipelines: Value) -> Engine {
        let mut all_settings =
            json!({ "default_upstream": DEAD_UPSTREAM, "upstream_timeout_ms": 200 });
        for (key, value) in settings.as_object().unwrap() {
            all_settings[key] = value.clone();
        }
        engine_from(json!({ "settings": all_settings, "pipelines": pipelines }))
    }

    /// Caches an answer with `ip` for `pipeline` with the given TTL (0: already
    /// stale) and returns its key.
    /// 为 `pipeline` 缓存一条带 `ip` 的应答，TTL 为给定值（0 表示已经过期），返回它的键。
    fn cache_an_answer(engine: &Engine, pipeline: &str, ip: Ipv4Addr, ttl: u32) -> u64 {
        let key = slot_of(engine, pipeline);
        let request = query();
        let mut reply = Message::new(request.id, MessageType::Response, OpCode::Query);
        reply.add_query(request.queries[0].clone());
        reply.add_answer(a_record(&request.queries[0], ip));
        // What a client without ECS gets from a forward without `ecs`: the reach a real
        // request in these pipelines caches with, so a refresh replaces it as usual
        // 不带 ECS 的客户端经不写 `ecs` 的转发得到的应答：这些 pipeline 里真实请求缓存时带的
        // 适用范围，刷新照常取代它
        let mut reach = crate::ecs_scope::EcsReach::default();
        reach.record(
            crate::ecs_scope::ForwardEcs {
                source: crate::ecs_scope::EcsSource::Client,
                sent: crate::ecs_scope::Sent::Absent,
            },
            crate::ecs_scope::ReplyEcs::Absent,
            true,
        );
        engine.insert_dns_cache_entry(
            key,
            CacheEntry::from_response(
                Bytes::from(reply.to_vec().unwrap()),
                ResponseCode::NoError,
                Some(Arc::from(DEAD_UPSTREAM)),
                "example.com",
                Arc::from(pipeline),
                u16::from(RecordType::A),
                u16::from(DNSClass::IN),
                crate::proto_utils::QueryFlags::RECURSIVE,
                ttl,
            )
            .with_reach(reach),
        );
        key
    }

    /// [`query`] 在 `pipeline` 里的缓存槽位 / The cache slot of [`query`] in `pipeline`
    fn slot_of(engine: &Engine, pipeline: &str) -> u64 {
        let state = engine.state.load_full();
        Engine::cache_keys(
            state.cache_namespace(pipeline),
            pipeline,
            b"example.com",
            RecordType::A,
            DNSClass::IN,
            crate::proto_utils::QueryFlags::RECURSIVE,
            &crate::matcher::RequesterKey::NONE,
            None,
        )
        .slot
    }

    /// 三条会写缓存的路径，各一条规则，回答都来自 `upstream`：直接转发、应答之后响应动作的转发、
    /// 上游失败后 on_miss 的转发
    /// The three paths that cache, one rule each with its answer from `upstream`: a
    /// plain forward, a response action's forward after an answer, an on_miss
    /// forward after the upstream failed
    fn caching_paths(upstream: &str) -> [(&'static str, Value); 3] {
        [
            ("forward", rule("all", forward(upstream), json!({}))),
            (
                "response action",
                rule(
                    "all",
                    forward(upstream),
                    json!({
                        "response_matchers": [{ "type": "upstream_equals", "value": upstream }],
                        "response_actions_on_match": forward(upstream)
                    }),
                ),
            ),
            (
                "miss action",
                rule(
                    "all",
                    forward(DEAD_UPSTREAM),
                    json!({ "response_actions_on_miss": forward(upstream) }),
                ),
            ),
        ]
    }

    /// 回答里每条记录的 TTL，按段的先后 / The TTL of every record in a reply, section by section
    fn record_ttls(bytes: &[u8]) -> Vec<u32> {
        let msg = Message::from_bytes(bytes).expect("parse reply");
        msg.answers
            .iter()
            .chain(&msg.authorities)
            .map(|record| record.ttl)
            .collect()
    }

    /// 上游回答里每条记录的 TTL 都收进 min_ttl 到 cache_max_ttl 之间，缓存也照收过的存，客户端留一份
    /// 回答的时间就和缓存一样长；两者冲突时以 cache_max_ttl 为准。此前 min_ttl 只决定存不存，条目还是
    /// 照上游的 TTL 过期；cache_max_ttl 只限制条目存多久，客户端拿到的仍是上游的 TTL。
    /// The TTL of every record in an upstream answer is brought into min_ttl to
    /// cache_max_ttl and the cache keeps what was brought in, so a client keeps an
    /// answer as long as the cache does; cache_max_ttl wins when the two cross.
    /// min_ttl used to decide only whether an answer was cached, the entry still
    /// expiring by the upstream's TTL; cache_max_ttl only bounded how long an entry
    /// was kept, clients still getting the upstream's TTL.
    #[tokio::test]
    async fn answers_carry_and_are_cached_with_ttls_within_min_ttl_and_cache_max_ttl() {
        let upstream = spawn_upstream_replying(|query, question| {
            let mut resp = Message::new(query.id, MessageType::Response, OpCode::Query);
            resp.add_query(question.clone());
            for (ttl, last) in [(5, 1), (100_000, 2)] {
                resp.add_answer(Record::from_rdata(
                    question.name().clone(),
                    ttl,
                    RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(192, 0, 2, last))),
                ));
            }
            resp
        })
        .await;
        let rules = caching_paths(&upstream);
        let cases = [
            (
                json!({ "min_ttl": 60, "cache_max_ttl": 3600 }),
                [60, 3600],
                60,
            ),
            (
                json!({ "min_ttl": 600, "cache_max_ttl": 300 }),
                [300, 300],
                300,
            ),
            (json!({}), [5, 86_400], 5),
        ];
        for (path, rule) in &rules {
            for (settings, carried, cached) in &cases {
                let engine =
                    engine_with(settings.clone(), json!([{ "id": "main", "rules": [rule] }]));
                for round in ["miss", "hit"] {
                    let reply = engine
                        .handle_packet(&query().to_vec().unwrap(), CLIENT.parse().unwrap())
                        .await
                        .expect("answered");
                    let ttls = record_ttls(&reply);
                    // 命中时减去已经缓存的秒数，跨过一秒的边界时少 1 / A hit takes off the seconds cached, 1 past a second boundary
                    assert!(
                        ttls == *carried || ttls == carried.map(|ttl| ttl - 1),
                        "{path} {settings} {round}: {ttls:?}"
                    );
                }
                let entry = engine.cached(slot_of(&engine, "main")).expect("cached");
                assert_eq!(entry.original_ttl, *cached, "{path} {settings}");
            }
        }
    }

    /// 否定回答按 SOA 的负缓存 TTL 缓存，同样收进 min_ttl 到 cache_max_ttl 之间；没有 SOA 的照旧不缓存
    /// （RFC 2308 第 4 节）。
    /// A negative answer is cached by its SOA negative TTL, brought into min_ttl to
    /// cache_max_ttl as well; one without SOA is still not cached (RFC 2308 section 4).
    #[tokio::test]
    async fn negative_answers_are_cached_within_min_ttl_and_cache_max_ttl() {
        for (soa, settings, carried, cached) in [
            (Some((10, 5)), json!({ "min_ttl": 60 }), vec![60], Some(60)),
            (
                Some((100_000, 100_000)),
                json!({ "cache_max_ttl": 3600 }),
                vec![3600],
                Some(3600),
            ),
            (None, json!({ "min_ttl": 60 }), vec![], None),
        ] {
            let upstream = spawn_upstream_replying(move |query, question| {
                let mut resp = Message::new(query.id, MessageType::Response, OpCode::Query);
                resp.metadata.response_code = ResponseCode::NXDomain;
                resp.add_query(question.clone());
                if let Some((ttl, minimum)) = soa {
                    let soa = hickory_proto::rr::rdata::SOA::new(
                        Name::from_str("ns.example.com.").unwrap(),
                        Name::from_str("admin.example.com.").unwrap(),
                        1,
                        3600,
                        900,
                        1_209_600,
                        minimum,
                    );
                    resp.add_authority(Record::from_rdata(
                        Name::from_str("example.com.").unwrap(),
                        ttl,
                        RData::SOA(soa),
                    ));
                }
                resp
            })
            .await;
            for (path, rule) in caching_paths(&upstream) {
                let engine =
                    engine_with(settings.clone(), json!([{ "id": "main", "rules": [rule] }]));
                let reply = engine
                    .handle_packet(&query().to_vec().unwrap(), CLIENT.parse().unwrap())
                    .await
                    .expect("answered");
                assert_eq!(record_ttls(&reply), carried, "{path} {settings}");
                assert_eq!(
                    engine
                        .cached(slot_of(&engine, "main"))
                        .map(|entry| entry.original_ttl),
                    cached,
                    "{path} {settings}"
                );
            }
        }
    }

    /// Runs the call `spawn_background_refresh` makes and returns what the
    /// refreshed key holds afterwards: its A records, or None once dropped.
    /// 执行与 `spawn_background_refresh` 相同的调用，返回之后那个键里的 A 记录，
    /// 被删掉时返回 None。
    async fn refresh(engine: &Engine, key: u64) -> Option<Vec<Ipv4Addr>> {
        refresh_as(engine, key, engine.refresh_of(key)).await
    }

    /// The same, also telling whether the refresh counts as a success, which is
    /// what refresh.rs logs
    /// 同上，另外给出刷新算不算成功，也就是 refresh.rs 记录的结果
    async fn refresh_succeeds(engine: &Engine, key: u64) -> (bool, Option<Vec<Ipv4Addr>>) {
        let result = refresh_result(engine, engine.refresh_of(key)).await;
        (
            result.is_ok(),
            engine.cached(key).map(|entry| a_records(&entry.bytes)),
        )
    }

    /// 更新 `target` 所指条目的刷新调用的返回值
    /// What the refresh call renewing what `target` names returns
    async fn refresh_result(
        engine: &Engine,
        target: crate::engine::refresh::RefreshTarget,
    ) -> anyhow::Result<Bytes> {
        let client: SocketAddr = CLIENT.parse().unwrap();
        tokio::time::timeout(
            Duration::from_secs(5),
            engine.handle_packet_internal(
                &query().to_vec().unwrap(),
                client,
                None,
                Some(target),
                Some(engine.state.load_full()),
            ),
        )
        .await
        .expect("refresh finishes")
    }

    /// 同 [`refresh`]，更新 `target` 所指的条目 / The same as [`refresh`], renewing what
    /// `target` names
    async fn refresh_as(
        engine: &Engine,
        key: u64,
        target: crate::engine::refresh::RefreshTarget,
    ) -> Option<Vec<Ipv4Addr>> {
        let _ = refresh_result(engine, target).await;
        engine.cached(key).map(|entry| a_records(&entry.bytes))
    }

    /// Rule `first` asks the upstream answering [`PASSED_OVER`] with the given
    /// response rules; rule `second` asks the upstream answering [`FINAL`].
    /// 规则 `first` 带着给定的响应规则问回 [`PASSED_OVER`] 的上游；规则 `second`
    /// 问回 [`FINAL`] 的上游。
    async fn refresh_past_the_first_answer(
        response_rules: impl FnOnce(&str, &str) -> Value,
    ) -> Option<Vec<Ipv4Addr>> {
        let first = answering_upstream(PASSED_OVER, 300).await.address;
        let second = answering_upstream(FINAL, 300).await.address;
        let (engine, key) = engine_with_a_cached_answer(
            json!({}),
            json!([{ "id": "main", "rules": [
                rule("first", forward(&first), response_rules(&first, &second)),
                rule("second", forward(&second), json!({})),
            ]}]),
        );
        refresh(&engine, key).await
    }

    /// Rule `first` asks the upstream answering [`PASSED_OVER`] and runs the
    /// given actions on its answer; `later_rules` follow it, and pipeline
    /// "other", the jump target, has the single rule `target`.
    /// 规则 `first` 问回 [`PASSED_OVER`] 的上游，并对它的应答执行给定的动作；
    /// `later_rules` 跟在它后面，跳转目标 pipeline "other" 只有一条规则 `target`。
    async fn refresh_with_actions_on_the_answer(
        settings: Value,
        actions_on_match: Value,
        later_rules: Vec<Value>,
        target: Value,
    ) -> Option<Vec<Ipv4Addr>> {
        let first = answering_upstream(PASSED_OVER, 300).await.address;
        let mut rules = vec![rule(
            "first",
            forward(&first),
            json!({ "response_actions_on_match": actions_on_match }),
        )];
        rules.extend(later_rules);
        let (engine, key) = engine_with_a_cached_answer(
            settings,
            json!([
                { "id": "main", "rules": rules },
                { "id": "other", "rules": [target] }
            ]),
        );
        refresh(&engine, key).await
    }

    #[tokio::test]
    async fn a_refresh_continues_past_an_answer_on_match() {
        let cached = refresh_past_the_first_answer(|first, _| {
            json!({
                "response_matchers": [{ "type": "upstream_equals", "value": first }],
                "response_actions_on_match": continue_()
            })
        })
        .await;
        assert_eq!(cached, Some(vec![FINAL]));
    }

    #[tokio::test]
    async fn a_refresh_continues_past_an_answer_on_miss() {
        let cached = refresh_past_the_first_answer(|_, second| {
            json!({
                "response_matchers": [{ "type": "upstream_equals", "value": second }],
                "response_actions_on_miss": continue_()
            })
        })
        .await;
        assert_eq!(cached, Some(vec![FINAL]));
    }

    #[tokio::test]
    async fn a_refresh_drops_the_entry_for_an_uncached_static_answer() {
        let cached = refresh_with_actions_on_the_answer(
            json!({}),
            answer_uncached(),
            vec![],
            static_target(),
        )
        .await;
        assert_eq!(cached, None);
    }

    /// 刷新按取得时刻认它更新的那份应答，不管条目换没换过：同一份应答续期后（serve_stale_ttl_reset）存成的新条目，
    /// 刷新照样删掉，否则续期可以让过时的应答一直留着
    /// A refresh knows the answer it renews by when it was fetched, however the entry was
    /// replaced since: the new entry a renewal (serve_stale_ttl_reset) stores for the same
    /// answer is dropped all the same, or renewals could keep an outdated answer forever
    #[tokio::test]
    async fn a_refresh_drops_the_entry_renewed_while_it_ran() {
        let first = answering_upstream(PASSED_OVER, 300).await.address;
        let (engine, key) = engine_with_a_cached_answer(
            json!({}),
            json!([
                { "id": "main", "rules": [rule(
                    "first",
                    forward(&first),
                    json!({ "response_actions_on_match": answer_uncached() })
                )] },
                { "id": "other", "rules": [static_target()] }
            ]),
        );
        let target = engine.refresh_of(key);
        let original = engine.cached(key).expect("cached");
        engine.cache_replace(key, &original, original.clone_with_refreshed_ttl());
        assert_eq!(refresh_as(&engine, key, target).await, None);
    }

    /// 刷新进行中，另一个请求给同样的请求方写进一份新应答：刷新要删的是它更新的那份，不是这份。
    /// While the refresh runs, another request writes a new answer for the same
    /// requesters: the refresh drops the answer it renews, not this one.
    #[tokio::test]
    async fn a_refresh_leaves_an_answer_another_request_wrote_meanwhile() {
        let first = answering_upstream(PASSED_OVER, 300).await.address;
        let (engine, key) = engine_with_a_cached_answer(
            json!({}),
            json!([
                { "id": "main", "rules": [rule(
                    "first",
                    forward(&first),
                    json!({ "response_actions_on_match": answer_uncached() })
                )] },
                { "id": "other", "rules": [static_target()] }
            ]),
        );
        let target = engine.refresh_of(key);
        let original = engine.cached(key).expect("cached");
        let newer = CacheEntry {
            fetched_at: std::time::Instant::now(),
            ..(*original).clone()
        };
        engine.cache_insert(key, Arc::new(newer));
        assert_eq!(refresh_as(&engine, key, target).await, Some(vec![OLD]));
    }

    /// 规则现在直接给出静态应答（比如数据重载以后匹配上了另一条规则）：它不缓存，条目已经和规则对不上，刷新照样算成功、
    /// 把条目删掉，下一个客户端请求直接拿到规则的应答。以前只有越过一个应答以后才删，直接给出的静态应答让条目一直留着，
    /// 过期以后每次命中都交出旧应答再续上
    /// The rules now give a static answer outright (another rule matching after a data
    /// reload, say): it is not cached and the entry no longer matches the rules, so the
    /// refresh succeeds all the same and drops the entry, the next client request getting the
    /// rules' answer at once. Only a refresh past an answer used to drop it, and a static answer
    /// given outright left the entry in place, the old answer going out and renewed on every
    /// hit once expired
    #[tokio::test]
    async fn a_refresh_drops_the_entry_when_the_rules_now_answer_statically() {
        let (engine, key) = engine_with_a_cached_answer(
            json!({}),
            json!([{ "id": "main", "rules": [rule("static", answer_static(), json!({}))] }]),
        );
        assert_eq!(refresh_succeeds(&engine, key).await, (true, None));
    }

    #[tokio::test]
    async fn a_refresh_caches_a_static_answer_for_its_ttl() {
        let cached =
            refresh_with_actions_on_the_answer(json!({}), answer_static(), vec![], static_target())
                .await;
        assert_eq!(cached, Some(vec![STATIC.parse().unwrap()]));
    }

    /// 回答检查跳过去拿到的应答缓存在原来的键下，刷新就用它更新条目；拿到的应答不缓存（min_ttl 为 0 时不带记录的静态
    /// 应答）时，条目删掉，下一个客户端请求自己走规则
    /// The answer an answer check's jump gets is cached under the key it came from, and the
    /// refresh renews the entry with it; when what it gets is not cached (a static answer
    /// without records, with min_ttl 0), the entry goes and the next client request runs the
    /// rules itself
    #[tokio::test]
    async fn a_refresh_renews_the_entry_with_what_the_jump_answers() {
        for (target, cached) in [
            (answer_static(), Some(vec![STATIC.parse().unwrap()])),
            (answer_uncached(), None),
        ] {
            let renewed = refresh_with_actions_on_the_answer(
                json!({}),
                jump_to("other"),
                vec![],
                rule("target", target.clone(), json!({})),
            )
            .await;
            assert_eq!(renewed, cached, "{target}");
        }
    }

    #[tokio::test]
    async fn a_refresh_keeps_the_entry_when_the_jump_target_fails() {
        let cached = refresh_with_actions_on_the_answer(
            json!({}),
            jump_to("other"),
            vec![],
            failing_target(),
        )
        .await;
        assert_eq!(cached, Some(vec![OLD]));
    }

    #[tokio::test]
    async fn a_refresh_whose_response_actions_find_no_answer_keeps_the_entry() {
        // With no jumps left the jump action answers SERVFAIL / 跳转次数用完时跳转动作回 SERVFAIL
        let settings = json!({ "min_ttl": 60, "response_jump_limit": 0 });
        let cached =
            refresh_with_actions_on_the_answer(settings, jump_to("other"), vec![], static_target())
                .await;
        assert_eq!(cached, Some(vec![OLD]));
    }

    #[tokio::test]
    async fn a_refresh_keeps_the_entry_when_an_action_forward_answers_servfail() {
        let failing = spawn_upstream_answering_servfail().await;
        let settings = json!({ "min_ttl": 60 });
        let cached = refresh_with_actions_on_the_answer(
            settings,
            forward(&failing),
            vec![],
            static_target(),
        )
        .await;
        assert_eq!(cached, Some(vec![OLD]));
    }

    /// 刷新时上游回了失败应答：刷新到此为止，miss 动作不跑，条目原样留着。以前问了备用上游，拿它的回答把还新鲜的条目
    /// 换掉
    /// A refresh whose upstream gives a failure reply ends there: the miss actions do not run
    /// and the entry stays as it is. The backup upstream used to be asked, its answer replacing
    /// the entry while still fresh
    #[tokio::test]
    async fn a_refresh_ends_at_a_failure_reply_without_running_the_miss_actions() {
        let failing = spawn_upstream_answering_servfail().await;
        let backup = answering_upstream(FINAL, 300).await;
        let (engine, key) = engine_with_a_cached_answer(
            json!({}),
            json!([{ "id": "main", "rules": [rule(
                "first",
                forward(&failing),
                json!({ "response_actions_on_miss": forward(&backup.address) })
            )]}]),
        );
        assert_eq!(refresh(&engine, key).await, Some(vec![OLD]));
        assert_eq!(backup.queries(), 0, "the backup is not asked");
    }

    /// 上游失败以后 on_miss 动作给出的静态答案不顶掉条目：刷新到上游失败就结束了。以前按 min_ttl 写进缓存，预取时一次
    /// 抖动就把还新鲜的应答换成兜底
    /// A static answer of the miss actions does not replace the entry once the upstream failed:
    /// the refresh ends at the failure. It used to be cached under min_ttl, one blip at a
    /// prefetch replacing an answer still fresh with the fallback
    #[tokio::test]
    async fn a_refresh_keeps_the_entry_over_a_static_miss_answer_after_a_failure() {
        let failing = spawn_upstream_answering_servfail().await;
        let (engine, key) = engine_with_a_cached_answer(
            json!({ "min_ttl": 60 }),
            json!([{ "id": "main", "rules": [rule(
                "first",
                forward(&failing),
                json!({ "response_actions_on_miss": answer_static() })
            )]}]),
        );
        assert_eq!(refresh(&engine, key).await, Some(vec![OLD]));
    }

    /// 响应跳转以后，规则越过的应答交给下一条 `allow` 规则复用，不再去问默认上游
    /// After a response jump, an answer a rule continued past is reused by the next
    /// `allow` rule rather than asking the default upstream
    #[tokio::test]
    async fn an_allow_after_a_continue_on_the_jump_path_reuses_the_answer() {
        let pre = answering_upstream(OLD, 300).await.address;
        let passed = answering_upstream(PASSED_OVER, 300).await.address;
        let default = answering_upstream(FINAL, 300).await.address;
        let engine = engine_with(
            json!({ "default_upstream": default, "upstream_timeout_ms": 1000 }),
            json!([
                { "id": "main", "rules": [rule(
                    "first",
                    forward(&pre),
                    json!({
                        "response_matchers": [{ "type": "upstream_equals", "value": pre }],
                        "response_actions_on_match": jump_to("other")
                    })
                )] },
                { "id": "other", "rules": [
                    rule(
                        "passed",
                        forward(&passed),
                        json!({
                            "response_matchers": [{ "type": "upstream_equals", "value": passed }],
                            "response_actions_on_match": continue_()
                        })
                    ),
                    rule("allow", json!([{ "type": "allow" }]), json!({}))
                ] }
            ]),
        );
        let packet = query().to_vec().unwrap();
        let reply = support::ask(&engine, &packet, support::peer()).await;
        assert_eq!(a_records(&reply), vec![PASSED_OVER]);
    }

    #[tokio::test]
    async fn a_refresh_keeps_the_entry_on_a_failure_reply_with_response_rules() {
        let failing = spawn_upstream_answering_servfail().await;
        let (engine, key) = engine_with_a_cached_answer(
            json!({}),
            json!([{ "id": "main", "rules": [rule(
                "first",
                forward(&failing),
                json!({
                    "response_matchers": [{ "type": "upstream_equals", "value": DEAD_UPSTREAM }],
                    "response_actions_on_miss": answer_static()
                })
            )]}]),
        );
        assert_eq!(refresh(&engine, key).await, Some(vec![OLD]));
    }

    #[tokio::test]
    async fn a_refresh_drops_the_entry_when_a_continue_reaches_a_static_answer() {
        let later = vec![rule("static", answer_uncached(), json!({}))];
        let cached =
            refresh_with_actions_on_the_answer(json!({}), continue_(), later, static_target())
                .await;
        assert_eq!(cached, None);
    }

    #[tokio::test]
    async fn a_refresh_caches_a_static_answer_a_continue_reaches_for_its_ttl() {
        let later = vec![rule("static", answer_static(), json!({}))];
        let cached =
            refresh_with_actions_on_the_answer(json!({}), continue_(), later, static_target())
                .await;
        assert_eq!(cached, Some(vec![STATIC.parse().unwrap()]));
    }

    #[tokio::test]
    async fn a_refresh_drops_the_entry_when_a_continue_reaches_a_jump() {
        let later = vec![rule("jump", jump_to("other"), json!({}))];
        let cached =
            refresh_with_actions_on_the_answer(json!({}), continue_(), later, static_target())
                .await;
        assert_eq!(cached, None);
    }

    #[tokio::test]
    async fn a_refresh_drops_the_entry_when_a_continue_jumps_to_an_answering_target() {
        let answering = answering_upstream(FINAL, 300).await.address;
        let later = vec![rule("jump", jump_to("other"), json!({}))];
        let target = rule("target", forward(&answering), json!({}));
        let cached =
            refresh_with_actions_on_the_answer(json!({}), continue_(), later, target).await;
        assert_eq!(cached, None);
    }

    #[tokio::test]
    async fn a_refresh_caches_the_answer_of_a_response_action_forward() {
        let replacement = answering_upstream(FINAL, 300).await.address;
        let cached = refresh_with_actions_on_the_answer(
            json!({}),
            forward(&replacement),
            vec![],
            static_target(),
        )
        .await;
        assert_eq!(cached, Some(vec![FINAL]));
    }

    /// 回答检查给出的 deny 不带记录，刷新按它所依据的那份上游应答的 TTL 缓存它
    /// A deny an answer check gives has no records, and the refresh caches it for the TTL of
    /// the upstream answer it goes by
    #[tokio::test]
    async fn a_refresh_caches_a_deny_for_the_answers_ttl() {
        let first = answering_upstream(PASSED_OVER, 300).await.address;
        let (engine, key) = engine_with_a_cached_answer(
            json!({}),
            json!([{ "id": "main", "rules": [rule(
                "first",
                forward(&first),
                json!({ "response_actions_on_match": [{ "type": "deny" }] })
            )]}]),
        );
        refresh(&engine, key).await;
        let cached = engine.cached(key).expect("the refresh caches the deny");
        assert_eq!(
            (cached.rcode, cached.original_ttl),
            (ResponseCode::Refused, 300)
        );
    }

    #[tokio::test]
    async fn a_refresh_keeps_the_entry_when_the_jump_target_gets_a_failure_reply() {
        let failing = spawn_upstream_answering_servfail().await;
        let target = rule(
            "target",
            forward(&failing),
            json!({
                "response_matchers": [{ "type": "upstream_equals", "value": DEAD_UPSTREAM }],
                "response_actions_on_miss": answer_static()
            }),
        );
        let cached =
            refresh_with_actions_on_the_answer(json!({}), jump_to("other"), vec![], target).await;
        assert_eq!(cached, Some(vec![OLD]));
    }

    #[tokio::test]
    async fn a_refresh_keeps_the_entry_when_a_continue_jumps_to_a_target_serving_stale() {
        let first = answering_upstream(PASSED_OVER, 300).await.address;
        let (engine, key) = engine_with_a_cached_answer(
            json!({ "serve_stale": true }),
            json!([
                { "id": "main", "rules": [
                    rule("first", forward(&first), json!({ "response_actions_on_match": continue_() })),
                    rule("jump", jump_to("other"), json!({})),
                ]},
                { "id": "other", "rules": [failing_target()] }
            ]),
        );
        cache_an_answer(&engine, "other", FINAL, 0);
        assert_eq!(refresh(&engine, key).await, Some(vec![OLD]));
    }

    #[tokio::test]
    async fn a_refresh_keeps_the_entry_when_a_continue_jumps_to_a_failing_target() {
        let later = vec![rule("jump", jump_to("other"), json!({}))];
        let cached =
            refresh_with_actions_on_the_answer(json!({}), continue_(), later, failing_target())
                .await;
        assert_eq!(cached, Some(vec![OLD]));
    }

    #[tokio::test]
    async fn a_refresh_keeps_the_entry_when_a_continue_ends_in_servfail() {
        // A jump to a pipeline that does not exist answers SERVFAIL / 跳到不存在的 pipeline 回 SERVFAIL
        let later = vec![rule("jump", jump_to("nowhere"), json!({}))];
        let settings = json!({ "min_ttl": 60 });
        let cached =
            refresh_with_actions_on_the_answer(settings, continue_(), later, static_target()).await;
        assert_eq!(cached, Some(vec![OLD]));
    }

    #[tokio::test]
    async fn a_refresh_whose_next_rule_fails_keeps_the_entry() {
        let later = vec![rule("dead", forward(DEAD_UPSTREAM), json!({}))];
        let cached =
            refresh_with_actions_on_the_answer(json!({}), continue_(), later, static_target())
                .await;
        assert_eq!(cached, Some(vec![OLD]));
    }

    /// A jump target whose upstream never answers, and whose miss actions answer
    /// with `actions` instead
    /// 上游不应答、改由 on_miss 动作 `actions` 作答的跳转目标
    fn target_falling_back(actions: Value) -> Value {
        rule(
            "target",
            forward(DEAD_UPSTREAM),
            json!({ "response_actions_on_miss": actions }),
        )
    }

    /// Past a continue and a jump, the target's upstream fails and its miss actions
    /// answer: as when the rule's own upstream fails (see the next test), the
    /// refresh has no new answer for the entry, which stays.
    /// continue 再跳转之后，目标的上游失败、由它的 on_miss 动作作答：和规则自己的上游失败
    /// 时一样（见下一个测试），刷新没有拿到这个条目的新应答，条目保留。
    #[tokio::test]
    async fn a_refresh_keeps_the_entry_when_a_continue_jumps_to_a_target_that_falls_back() {
        let backup = answering_upstream(FINAL, 300).await.address;
        for actions in [answer_static(), forward(&backup)] {
            let later = vec![rule("jump", jump_to("other"), json!({}))];
            let cached = refresh_with_actions_on_the_answer(
                json!({}),
                continue_(),
                later,
                target_falling_back(actions.clone()),
            )
            .await;
            assert_eq!(cached, Some(vec![OLD]), "{actions}");
        }
    }

    /// The same when the target's miss action jumps to a pipeline that answers
    /// 目标的 on_miss 动作跳到另一个作答的 pipeline 时也一样
    #[tokio::test]
    async fn a_refresh_keeps_the_entry_when_the_target_falls_back_by_a_jump() {
        let first = answering_upstream(PASSED_OVER, 300).await.address;
        let (engine, key) = engine_with_a_cached_answer(
            json!({}),
            json!([
                { "id": "main", "rules": [
                    rule("first", forward(&first), json!({ "response_actions_on_match": continue_() })),
                    rule("jump", jump_to("other"), json!({})),
                ]},
                { "id": "other", "rules": [target_falling_back(jump_to("third"))] },
                { "id": "third", "rules": [static_target()] }
            ]),
        );
        assert_eq!(refresh(&engine, key).await, Some(vec![OLD]));
    }

    #[tokio::test]
    async fn a_refresh_whose_next_rule_falls_back_keeps_the_entry() {
        let later = vec![rule(
            "dead",
            forward(DEAD_UPSTREAM),
            json!({ "response_actions_on_miss": answer_static() }),
        )];
        let cached =
            refresh_with_actions_on_the_answer(json!({}), continue_(), later, static_target())
                .await;
        assert_eq!(cached, Some(vec![OLD]));
    }

    /// A refresh is after an answer to renew the entry with; one that ends in
    /// SERVFAIL found none, whatever produced it, and counts as a failure. With a
    /// `min_ttl` the SERVFAIL is not cached over the entry either.
    /// 刷新要的是拿来更新条目的应答；以 SERVFAIL 结束的刷新没拿到应答，不论 SERVFAIL 从
    /// 哪里来，都算失败。设了 `min_ttl` 时也不会把 SERVFAIL 缓存进来盖掉条目。
    #[tokio::test]
    async fn a_refresh_that_ends_in_servfail_fails() {
        let cases = [
            (
                "the jump limit",
                json!({ "response_jump_limit": 1 }),
                json!([
                    { "id": "main", "rules": [rule("jump", jump_to("other"), json!({}))] },
                    { "id": "other", "rules": [rule("back", jump_to("main"), json!({}))] }
                ]),
            ),
            (
                "a jump target that does not exist",
                json!({}),
                json!([{ "id": "main", "rules": [rule("jump", jump_to("nowhere"), json!({}))] }]),
            ),
            (
                "a static SERVFAIL",
                json!({}),
                json!([{ "id": "main", "rules": [rule(
                    "servfail",
                    json!([{ "type": "static_response", "rcode": "SERVFAIL" }]),
                    json!({})
                )] }]),
            ),
            (
                "a miss action jumping to a pipeline that does not exist",
                json!({}),
                json!([{ "id": "main", "rules": [rule(
                    "dead",
                    forward(DEAD_UPSTREAM),
                    json!({ "response_actions_on_miss": jump_to("nowhere") })
                )] }]),
            ),
        ];
        for (case, settings, pipelines) in cases {
            for min_ttl in [0, 60] {
                let mut settings = settings.clone();
                settings["min_ttl"] = json!(min_ttl);
                let (engine, key) = engine_with_a_cached_answer(settings, pipelines.clone());
                assert_eq!(
                    refresh_succeeds(&engine, key).await,
                    (false, Some(vec![OLD])),
                    "{case}, min_ttl {min_ttl}"
                );
            }
        }
    }

    /// After an upstream failure the rules go on (a miss action's continue) and a
    /// later rule answers: that answer is a fallback as well, and the entry stays,
    /// in the pipeline itself and in a jump target, whether the later rule answers
    /// statically or from another upstream.
    /// 上游失败后规则接着往下走（on_miss 的 continue），后面的规则作答：这个应答同样是兜底，
    /// 条目保留。无论在本 pipeline 还是跳转目标里、后面的规则是静态作答还是问另一个上游，
    /// 都一样。
    #[tokio::test]
    async fn a_refresh_keeps_the_entry_when_a_continue_after_a_failure_answers() {
        let first = answering_upstream(PASSED_OVER, 300).await.address;
        let backup = answering_upstream(FINAL, 300).await.address;
        let passed = || {
            rule(
                "first",
                forward(&first),
                json!({ "response_actions_on_match": continue_() }),
            )
        };
        let failing_then_on = || {
            rule(
                "dead",
                forward(DEAD_UPSTREAM),
                json!({ "response_actions_on_miss": continue_() }),
            )
        };
        let cases = [
            (
                "a static answer in the pipeline itself",
                json!([{ "id": "main", "rules": [
                    passed(), failing_then_on(), rule("static", answer_static(), json!({}))
                ]}]),
            ),
            (
                "a static answer in a jump target",
                json!([
                    { "id": "main", "rules": [passed(), rule("jump", jump_to("other"), json!({}))] },
                    { "id": "other", "rules": [
                        failing_then_on(), rule("static", answer_static(), json!({}))
                    ]}
                ]),
            ),
            (
                "another upstream in a jump target",
                json!([
                    { "id": "main", "rules": [passed(), rule("jump", jump_to("other"), json!({}))] },
                    { "id": "other", "rules": [
                        failing_then_on(), rule("backup", forward(&backup), json!({}))
                    ]}
                ]),
            ),
            // 失败后的 on_miss 先问了另一个上游再 continue：这次 continue 带着应答，也仍在失败之后
            // The miss actions ask another upstream before the continue: that continue
            // carries an answer, and still comes after the failure
            (
                "a continue past a miss action's own answer, in the pipeline itself",
                json!([{ "id": "main", "rules": [
                    rule(
                        "dead",
                        forward(DEAD_UPSTREAM),
                        json!({ "response_actions_on_miss": [
                            { "type": "forward", "upstream": backup }, { "type": "continue" }
                        ] })
                    ),
                    rule("static", answer_static(), json!({}))
                ]}]),
            ),
            (
                "a continue past a miss action's own answer, in a jump target",
                json!([
                    { "id": "main", "rules": [passed(), rule("jump", jump_to("other"), json!({}))] },
                    { "id": "other", "rules": [
                        rule(
                            "dead",
                            forward(DEAD_UPSTREAM),
                            json!({ "response_actions_on_miss": [
                                { "type": "forward", "upstream": backup }, { "type": "continue" }
                            ] })
                        ),
                        rule("static", answer_static(), json!({}))
                    ]}
                ]),
            ),
        ];
        for (case, pipelines) in cases {
            let (engine, key) = engine_with_a_cached_answer(json!({}), pipelines);
            assert_eq!(refresh(&engine, key).await, Some(vec![OLD]), "{case}");
        }
    }

    /// 上游失败、miss 动作写着 continue：刷新到失败就结束，后面的规则不跑，条目留着
    /// The upstream failing with a miss action that continues: the refresh ends at the failure,
    /// the later rules do not run, and the entry stays
    #[tokio::test]
    async fn a_refresh_ends_at_the_failure_before_the_later_rules() {
        let later = answering_upstream(PASSED_OVER, 300).await;
        let second = later.address.clone();
        let (engine, key) = engine_with_a_cached_answer(
            json!({}),
            json!([{ "id": "main", "rules": [
                rule(
                    "dead",
                    forward(DEAD_UPSTREAM),
                    json!({ "response_actions_on_miss": continue_() })
                ),
                rule(
                    "second",
                    forward(&second),
                    json!({ "response_actions_on_match": continue_() })
                ),
                rule("static", answer_static(), json!({}))
            ]}]),
        );
        assert_eq!(refresh(&engine, key).await, Some(vec![OLD]));
        assert_eq!(later.queries(), 0, "the later rule's upstream is not asked");
    }

    /// The upstream failed and the miss action found no answer either: the refresh
    /// reports the upstream's failure, which says why
    /// 上游失败，on_miss 动作也没拿到应答：刷新报的是上游的失败，说明了原因
    #[tokio::test]
    async fn a_refresh_whose_miss_action_finds_nothing_reports_the_upstream_failure() {
        let (engine, key) = engine_with_a_cached_answer(
            json!({}),
            json!([{ "id": "main", "rules": [rule(
                "dead",
                forward(DEAD_UPSTREAM),
                json!({ "response_actions_on_miss": jump_to("nowhere") })
            )] }]),
        );
        let error = format!(
            "{:#}",
            refresh_result(&engine, engine.refresh_of(key))
                .await
                .unwrap_err()
        );
        assert!(!error.contains("the rules answered SERVFAIL"), "{error}");
    }

    /// 上游失败以后，on_miss 动作给出 SERVFAIL（直接给，或者跳到给 SERVFAIL 的 pipeline）：刷新
    /// 报的是上游的失败，而不是规则给了 SERVFAIL
    /// After the upstream failed, the miss actions answer SERVFAIL (themselves, or by a
    /// jump to a pipeline that does): the refresh reports the upstream's failure rather
    /// than the rules answering SERVFAIL
    #[tokio::test]
    async fn a_refresh_whose_miss_actions_answer_servfail_reports_the_upstream_failure() {
        let servfail = json!([{ "type": "static_response", "rcode": "SERVFAIL" }]);
        for on_miss in [servfail.clone(), jump_to("other")] {
            let (engine, key) = engine_with_a_cached_answer(
                json!({}),
                json!([
                    { "id": "main", "rules": [rule(
                        "dead",
                        forward(DEAD_UPSTREAM),
                        json!({ "response_actions_on_miss": on_miss.clone() })
                    )] },
                    { "id": "other", "rules": [rule("servfail", servfail.clone(), json!({}))] }
                ]),
            );
            let error = format!(
                "{:#}",
                refresh_result(&engine, engine.refresh_of(key))
                    .await
                    .unwrap_err()
            );
            assert!(
                !error.contains("the rules answered SERVFAIL"),
                "{on_miss}: {error}"
            );
            assert_eq!(
                engine.cached(key).map(|entry| a_records(&entry.bytes)),
                Some(vec![OLD])
            );
        }
    }

    /// 上游失败以后，on_miss 跳到给出应答的 pipeline：刷新留着原来的条目，不去删它
    /// After the upstream failed, the miss actions jump to a pipeline that answers: the
    /// refresh leaves the entry in place rather than drop it
    #[tokio::test]
    async fn a_refresh_whose_miss_jump_answers_keeps_the_entry() {
        let (engine, key) = engine_with_a_cached_answer(
            json!({}),
            json!([
                { "id": "main", "rules": [rule(
                    "dead",
                    forward(DEAD_UPSTREAM),
                    json!({ "response_actions_on_miss": jump_to("other") })
                )] },
                { "id": "other", "rules": [static_target()] }
            ]),
        );
        let (_, cached) = refresh_succeeds(&engine, key).await;
        assert_eq!(cached, Some(vec![OLD]));
    }

    /// A client still gets the SERVFAIL the rules answer, as a reply
    /// 客户端照样拿到规则给出的 SERVFAIL 应答
    #[tokio::test]
    async fn a_client_gets_the_servfail_the_rules_answer() {
        for actions in [
            json!([{ "type": "static_response", "rcode": "SERVFAIL" }]),
            jump_to("nowhere"),
        ] {
            let engine = engine_with(
                json!({ "min_ttl": 60 }),
                json!([{ "id": "main", "rules": [rule("servfail", actions.clone(), json!({}))] }]),
            );
            let client: SocketAddr = CLIENT.parse().unwrap();
            let reply = tokio::time::timeout(
                Duration::from_secs(5),
                engine.handle_packet(&query().to_vec().unwrap(), client),
            )
            .await
            .expect("answer in time")
            .expect("a reply, not an error");
            assert_eq!(
                Message::from_bytes(&reply).unwrap().metadata.response_code,
                ResponseCode::ServFail,
                "{actions}"
            );
        }
    }

    /// 只拿到被截断的应答（TCP 也取不到完整的）：它不写缓存，没有拿来更新条目的应答，刷新算失败，条目原样留着。转发本身
    /// 拿到的、回答检查以后响应动作的转发拿到的都一样；回答段是空的也一样，以前它没有 SOA，按 TTL 算不进缓存，条目先被
    /// 当作不进缓存的完整应答删掉，刷新到出口才算失败
    /// Only a truncated answer comes back (with TCP unable to fetch the whole one): it is not
    /// cached, so there is nothing to renew the entry with, the refresh fails and the entry
    /// stays as it is. So it is for what a forward itself gets and for what a response action's
    /// forward gets after an answer check, and with an empty answer section too, which, with
    /// no SOA and so no TTL to cache by, used to have the entry dropped first as for a whole
    /// answer that is not cached, the refresh failing only at the exit
    #[tokio::test]
    async fn a_refresh_that_gets_only_a_truncated_answer_fails() {
        let answering = answering_upstream(PASSED_OVER, 300).await.address;
        for records in [Some(FINAL), None] {
            let truncating = spawn_upstream_truncating(records).await;
            let rules = [
                rule("all", forward(&truncating), json!({})),
                rule(
                    "all",
                    forward(&answering),
                    json!({ "response_actions_on_match": forward(&truncating) }),
                ),
            ];
            for rule in rules {
                let (engine, key) = engine_with_a_cached_answer(
                    json!({}),
                    json!([{ "id": "main", "rules": [rule.clone()] }]),
                );
                assert_eq!(
                    refresh_succeeds(&engine, key).await,
                    (false, Some(vec![OLD])),
                    "{records:?} {rule}"
                );
            }
        }
    }

    /// The same past a continue and a rule-level jump, or through a response jump:
    /// the refresh fails, and the entry stays as on a SERVFAIL there
    /// 越过一个应答再规则级跳转，或者经响应跳转，也一样：刷新失败，条目和那里遇到 SERVFAIL
    /// 时一样保留
    #[tokio::test]
    async fn a_refresh_whose_jump_target_gets_only_a_truncated_answer_keeps_the_entry() {
        let truncating = spawn_upstream_truncating(Some(FINAL)).await;
        let target = rule("target", forward(&truncating), json!({}));
        let settings = json!({ "enable_tcp_fallback": false });
        let after_a_continue = refresh_with_actions_on_the_answer(
            settings.clone(),
            continue_(),
            vec![rule("jump", jump_to("other"), json!({}))],
            target.clone(),
        )
        .await;
        assert_eq!(after_a_continue, Some(vec![OLD]));
        let through_a_response_jump =
            refresh_with_actions_on_the_answer(settings, jump_to("other"), vec![], target).await;
        assert_eq!(through_a_response_jump, Some(vec![OLD]));
    }

    #[tokio::test]
    async fn a_refresh_that_gets_an_answer_succeeds() {
        let answering = answering_upstream(FINAL, 300).await.address;
        let (engine, key) = engine_with_a_cached_answer(
            json!({}),
            json!([{ "id": "main", "rules": [rule("all", forward(&answering), json!({}))] }]),
        );
        assert_eq!(
            refresh_succeeds(&engine, key).await,
            (true, Some(vec![FINAL]))
        );
    }

    #[tokio::test]
    async fn a_refresh_that_continues_after_a_failure_keeps_the_entry() {
        let (engine, key) = engine_with_a_cached_answer(
            json!({}),
            json!([{ "id": "main", "rules": [
                rule(
                    "first",
                    forward(DEAD_UPSTREAM),
                    json!({ "response_actions_on_miss": continue_() })
                ),
                rule("static", answer_static(), json!({})),
            ]}]),
        );
        assert_eq!(refresh(&engine, key).await, Some(vec![OLD]));
    }
}

#[cfg(test)]
mod tcp_fallback_tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use hickory_proto::serialize::binary::BinDecodable;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::engine::Engine;
    use crate::matcher::RuntimePipelineConfig;

    /// The address in the full answer, which only TCP carries.
    /// 完整应答里的地址，只有 TCP 给得出。
    const FULL: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    /// The address a truncated answer may carry.
    /// 截断的应答里可能带的地址。
    const PARTIAL: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 9);
    /// 只走 TCP 的上游答的地址 / The address a TCP-only upstream answers
    const TCP_ONLY: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 77);

    fn reply(request: &[u8], answer: Option<Ipv4Addr>, truncated: bool) -> Option<Vec<u8>> {
        let request = Message::from_bytes(request).ok()?;
        let question = request.queries.first()?.clone();
        let mut reply = Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
        reply.add_query(question.clone());
        reply.metadata.truncation = truncated;
        if let Some(address) = answer {
            reply.add_answer(Record::from_rdata(
                question.name().clone(),
                300,
                RData::A(A(address)),
            ));
        }
        reply.to_vec().ok()
    }

    /// Holds a TCP port without listening on it: connections are refused, and no other
    /// test can take the port while this lives.
    /// 占着一个 TCP 端口但不监听：连接被拒，而且只要它在，别的测试就拿不走这个端口。
    fn hold_tcp_port(addr: SocketAddr) -> std::io::Result<tokio::net::TcpSocket> {
        let socket = tokio::net::TcpSocket::new_v4()?;
        socket.bind(addr)?;
        Ok(socket)
    }

    /// Serves DNS over TCP, answering `answer` after `delay`, and counts the answers.
    /// 在 TCP 上应答 `answer`（延迟 `delay`），并计数。
    fn serve_tcp(
        listener: tokio::net::TcpListener,
        answer: Ipv4Addr,
        delay: Duration,
    ) -> Arc<AtomicUsize> {
        let answered = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&answered);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let counter = Arc::clone(&counter);
                tokio::spawn(async move {
                    let mut len = [0u8; 2];
                    if stream.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let mut request = vec![0u8; u16::from_be_bytes(len) as usize];
                    if stream.read_exact(&mut request).await.is_err() {
                        return;
                    }
                    tokio::time::sleep(delay).await;
                    if let Some(bytes) = reply(&request, Some(answer), false) {
                        counter.fetch_add(1, Ordering::SeqCst);
                        let _ = stream.write_all(&(bytes.len() as u16).to_be_bytes()).await;
                        let _ = stream.write_all(&bytes).await;
                    }
                });
            }
        });
        answered
    }

    /// An upstream whose UDP answers are truncated and whose TCP answers carry [`FULL`].
    /// UDP 应答被截断、TCP 应答带 [`FULL`] 的上游。
    struct TruncatingUpstream {
        addr: String,
        udp_queries: Arc<AtomicUsize>,
        tcp_answers: Arc<AtomicUsize>,
        _closed_tcp: Option<tokio::net::TcpSocket>,
    }

    /// `tcp` is how long the TCP answers take; with `None` the TCP port is held but nothing
    /// listens. `partial` is a record the truncated UDP answers carry.
    /// `tcp` 是 TCP 应答的延迟；为 `None` 时占着 TCP 端口但不监听。`partial` 是截断的 UDP 应答里带的记录。
    async fn spawn_truncating_upstream(
        tcp: Option<Duration>,
        partial: Option<Ipv4Addr>,
    ) -> TruncatingUpstream {
        let mut tries = 0;
        let (udp, listener, closed_tcp) = loop {
            tries += 1;
            assert!(
                tries <= 20,
                "port conflict: no port free for both UDP and TCP in 20 tries"
            );
            let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = udp.local_addr().unwrap();
            let bound = if tcp.is_some() {
                tokio::net::TcpListener::bind(addr)
                    .await
                    .map(|listener| (Some(listener), None))
            } else {
                hold_tcp_port(addr).map(|socket| (None, Some(socket)))
            };
            match bound {
                Ok((listener, closed)) => break (udp, listener, closed),
                Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => continue,
                Err(err) => panic!("bind tcp on the udp port: {err}"),
            }
        };
        let addr = udp.local_addr().unwrap().to_string();
        let udp_queries = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&udp_queries);
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while let Ok((n, peer)) = udp.recv_from(&mut buf).await {
                if let Some(bytes) = reply(&buf[..n], partial, true) {
                    counter.fetch_add(1, Ordering::SeqCst);
                    let _ = udp.send_to(&bytes, peer).await;
                }
            }
        });
        let tcp_answers = match (listener, tcp) {
            (Some(listener), Some(delay)) => serve_tcp(listener, FULL, delay),
            _ => Arc::new(AtomicUsize::new(0)),
        };
        TruncatingUpstream {
            addr,
            udp_queries,
            tcp_answers,
            _closed_tcp: closed_tcp,
        }
    }

    /// 只走 TCP 的上游：延迟 `delay` 后应答 [`TCP_ONLY`] / A TCP-only upstream answering
    /// [`TCP_ONLY`] after `delay`
    async fn spawn_tcp_upstream(delay: Duration) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(serve_tcp(listener, TCP_ONLY, delay));
        format!("tcp://{addr}")
    }

    fn engine_with_rule(upstream: &str, checks: serde_json::Value) -> Engine {
        engine_with(
            serde_json::json!([{ "type": "forward", "upstream": upstream, "transport": "udp" }]),
            checks,
            true,
        )
    }

    /// 一条规则的引擎：动作是 `actions`，`checks` 补上回答检查 / An engine of one rule doing
    /// `actions`, `checks` adding its answer check
    fn engine_with(
        actions: serde_json::Value,
        checks: serde_json::Value,
        tcp_fallback: bool,
    ) -> Engine {
        let mut rule = serde_json::json!({
            "name": "forward",
            "matchers": [{ "type": "any" }],
            "actions": actions
        });
        for (key, value) in checks.as_object().unwrap() {
            rule[key] = value.clone();
        }
        let raw = serde_json::json!({
            "settings": {
                "default_upstream": "127.0.0.1:9",
                "upstream_timeout_ms": 2000,
                "enable_tcp_fallback": tcp_fallback
            },
            "pipelines": [{ "id": "main", "rules": [rule] }]
        });
        let config = crate::config::parse_config(&raw.to_string()).expect("parse config");
        Engine::new(
            RuntimePipelineConfig::from_config(config).expect("build runtime config"),
            "test".to_string(),
        )
        .expect("engine")
    }

    async fn ask(engine: &Engine) -> Message {
        let mut request = Message::new(0x4b1d, MessageType::Query, OpCode::Query);
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(
            Name::from_str("large.example.").unwrap(),
            RecordType::A,
        ));
        let bytes = tokio::time::timeout(
            Duration::from_secs(5),
            engine.handle_packet(
                &request.to_vec().unwrap(),
                "10.0.0.1:53000".parse().unwrap(),
            ),
        )
        .await
        .expect("must not hang")
        .expect("engine answers");
        Message::from_bytes(&bytes).expect("parse answer")
    }

    fn addresses(answer: &Message) -> Vec<Ipv4Addr> {
        answer
            .answers
            .iter()
            .filter_map(|record| match &record.data {
                RData::A(a) => Some(a.0),
                _ => None,
            })
            .collect()
    }

    /// One UDP upstream: the UDP forwarder itself fetches the truncated answer again over
    /// TCP, once, and the full answer comes back.
    /// 只有一个 UDP 上游：UDP 转发自己用 TCP 重取一次被截断的应答，拿回完整应答。
    #[tokio::test]
    async fn a_truncated_answer_from_a_udp_upstream_is_fetched_over_tcp_once() {
        let upstream = spawn_truncating_upstream(Some(Duration::ZERO), None).await;
        let engine = engine_with_rule(&upstream.addr, serde_json::json!({}));
        assert_eq!(addresses(&ask(&engine).await), [FULL]);
        assert_eq!(upstream.tcp_answers.load(Ordering::SeqCst), 1);
    }

    // With a TCP upstream in the same rule, a failed UDP exchange does not fall back to TCP
    // (so TCP is not sent twice), but a truncated answer is still fetched again over TCP. A
    // slow TCP upstream lets the truncated UDP answer arrive first.
    // 同一条规则里还有 TCP 上游时，UDP 失败不再回退到 TCP（免得 TCP 发两次），但截断的应答照样用 TCP
    // 重取。TCP 上游故意慢一些，让截断的 UDP 应答先到。

    /// The answer check sees the full answer fetched over TCP and acts on it.
    /// 回答检查看到的是经 TCP 取回的完整应答，并按它行事。
    #[tokio::test]
    async fn a_truncated_answer_fetched_over_tcp_goes_through_the_response_rules() {
        let truncating = spawn_truncating_upstream(Some(Duration::ZERO), None).await;
        let slow = spawn_tcp_upstream(Duration::from_millis(500)).await;
        let engine = engine_with_rule(
            &format!("{},{slow}", truncating.addr),
            serde_json::json!({
                "response_matchers": [{ "type": "response_answer_ip", "cidr": "192.0.2.1/32" }],
                "response_actions_on_match": [{ "type": "static_response", "rcode": "REFUSED" }]
            }),
        );
        let answer = ask(&engine).await;
        assert_eq!(
            answer.metadata.response_code,
            ResponseCode::Refused,
            "the answer check must act on the TCP answer: {answer:?}"
        );
    }

    /// The full answer fetched over TCP is cached like any answer.
    /// 经 TCP 取回的完整应答和其他应答一样写进缓存。
    #[tokio::test]
    async fn a_truncated_answer_fetched_over_tcp_is_cached() {
        let truncating = spawn_truncating_upstream(Some(Duration::ZERO), None).await;
        let slow = spawn_tcp_upstream(Duration::from_millis(500)).await;
        let engine = engine_with_rule(
            &format!("{},{slow}", truncating.addr),
            serde_json::json!({}),
        );
        assert_eq!(addresses(&ask(&engine).await), [FULL]);
        assert_eq!(addresses(&ask(&engine).await), [FULL]);
        assert_eq!(
            truncating.tcp_answers.load(Ordering::SeqCst),
            1,
            "the second query must be served from the cache"
        );
    }

    /// TCP 也取不到完整应答时，截断的应答和别的应答一样往下走：回答检查看到的是它，失败路径（这里是 on_miss 动作）
    /// 不走，客户端看到 TC 自己改用 TCP。以前 UDP 转发在这之后再问一次 TCP，失败了就走失败路径
    /// When TCP cannot fetch the whole answer either, the truncated answer goes on like any
    /// other: the answer check sees it and the failure path (the miss actions here) does not
    /// run, the client turning to TCP itself on seeing TC. A UDP forward used to ask over TCP
    /// once more after that, and on failing took the failure path
    #[tokio::test]
    async fn a_truncated_answer_tcp_cannot_complete_goes_on_as_the_answer() {
        let truncating = spawn_truncating_upstream(None, Some(PARTIAL)).await;
        let engine = engine_with_rule(
            &truncating.addr,
            serde_json::json!({
                "response_matchers": [{ "type": "response_answer_ip", "cidr": "192.0.2.9/32" }],
                "response_actions_on_miss": [{ "type": "static_response", "rcode": "NXDOMAIN" }]
            }),
        );
        let answer = ask(&engine).await;
        assert!(answer.metadata.truncation, "{answer:?}");
        assert_eq!(addresses(&answer), [PARTIAL]);
    }

    /// 几个上游一起问时（这里是一条规则里的两个 forward），截断的应答不抢先：没有什么能补全它（这里关着 TCP 回退），
    /// 就等别的上游的完整应答。以前它先到先赢，慢一些的完整应答被取消，客户端只拿到截断的那份
    /// Of several upstreams asked together (two forwards of one rule here), a truncated answer
    /// does not come first: with nothing to complete it (TCP fallback off here), the whole
    /// answer of another upstream is waited for. It used to win by coming first, the slower
    /// whole answer cancelled and the client getting only the truncated one
    #[tokio::test]
    async fn a_truncated_answer_does_not_beat_a_whole_one() {
        let truncating = spawn_truncating_upstream(None, Some(PARTIAL)).await;
        let slow = spawn_tcp_upstream(Duration::from_millis(300)).await;
        let engine = engine_with(
            serde_json::json!([
                { "type": "forward", "upstream": truncating.addr },
                { "type": "forward", "upstream": slow }
            ]),
            serde_json::json!({}),
            false,
        );
        let answer = ask(&engine).await;
        assert!(!answer.metadata.truncation, "{answer:?}");
        assert_eq!(addresses(&answer), [TCP_ONLY]);
    }

    /// An upstream written as `udp://` next to a TCP one: its truncated answer is fetched
    /// again over TCP like any UDP upstream's.
    /// 写成 `udp://`、旁边还有 TCP 上游的上游：它截断的应答和其他 UDP 上游一样用 TCP 重取。
    #[tokio::test]
    async fn a_udp_upstream_next_to_a_tcp_one_has_truncated_answers_fetched_over_tcp() {
        let truncating = spawn_truncating_upstream(Some(Duration::ZERO), Some(PARTIAL)).await;
        let slow = spawn_tcp_upstream(Duration::from_millis(500)).await;
        let engine = engine_with_rule(
            &format!("udp://{},{slow}", truncating.addr),
            serde_json::json!({}),
        );
        let answer = ask(&engine).await;
        assert!(!answer.metadata.truncation, "{answer:?}");
        assert_eq!(addresses(&answer), [FULL]);
        assert_eq!(truncating.tcp_answers.load(Ordering::SeqCst), 1);
    }

    /// `tcp_udp` sends both ways at once. A truncated UDP answer that arrives first does
    /// not win: the TCP leg's full answer does.
    /// `tcp_udp` 两路同时发。先到的截断 UDP 应答不算赢，赢的是 TCP 那一路的完整应答。
    #[tokio::test]
    async fn a_truncated_udp_answer_does_not_win_a_tcp_udp_race() {
        let truncating =
            spawn_truncating_upstream(Some(Duration::from_millis(200)), Some(PARTIAL)).await;
        let engine = engine_with(
            serde_json::json!([{ "type": "forward", "upstream": truncating.addr, "transport": "tcp_udp" }]),
            serde_json::json!({}),
            true,
        );
        let answer = ask(&engine).await;
        assert!(!answer.metadata.truncation, "{answer:?}");
        assert_eq!(addresses(&answer), [FULL]);
    }

    /// The response-jump path caches through the same place, so a truncated answer is not
    /// cached there either: a request entering the jump target directly asks the upstream.
    /// 响应跳转路径也经同一个地方写缓存，所以截断的应答在那里同样不缓存：直接进入跳转目标的请求照样去问上游。
    #[tokio::test]
    async fn a_truncated_answer_on_the_response_jump_path_is_not_cached() {
        let truncating = spawn_truncating_upstream(None, Some(PARTIAL)).await;
        let forward = |id: &str, then: serde_json::Value| {
            let mut rule = serde_json::json!({
                "name": id,
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": truncating.addr }]
            });
            for (key, value) in then.as_object().unwrap() {
                rule[key] = value.clone();
            }
            serde_json::json!({ "id": id, "rules": [rule] })
        };
        let raw = serde_json::json!({
            "settings": {
                "default_upstream": "127.0.0.1:9",
                "upstream_timeout_ms": 2000,
                "enable_tcp_fallback": false
            },
            "pipeline_select": [
                { "pipeline": "main", "matchers": [{ "type": "client_ip", "cidr": "10.0.0.1/32" }] },
                { "pipeline": "second", "matchers": [{ "type": "client_ip", "cidr": "10.0.0.2/32" }] }
            ],
            "pipelines": [
                forward("main", serde_json::json!({
                    "response_matchers": [{ "type": "upstream_equals", "value": truncating.addr }],
                    "response_actions_on_match": [{ "type": "jump_to_pipeline", "pipeline": "second" }]
                })),
                forward("second", serde_json::json!({}))
            ]
        });
        let config = crate::config::parse_config(&raw.to_string()).expect("parse config");
        let engine = Engine::new(
            RuntimePipelineConfig::from_config(config).expect("build runtime config"),
            "test".to_string(),
        )
        .expect("engine");
        let ask_from = |client: &'static str| {
            let engine = &engine;
            async move {
                let mut request = Message::new(0x4b1d, MessageType::Query, OpCode::Query);
                request.add_query(Query::query(
                    Name::from_str("large.example.").unwrap(),
                    RecordType::A,
                ));
                tokio::time::timeout(
                    Duration::from_secs(5),
                    engine.handle_packet(&request.to_vec().unwrap(), client.parse().unwrap()),
                )
                .await
                .expect("must not hang")
                .expect("engine answers")
            }
        };
        ask_from("10.0.0.1:53000").await;
        let asked = truncating.udp_queries.load(Ordering::SeqCst);
        assert_eq!(asked, 2, "main's forward and the one on the jump path");
        ask_from("10.0.0.2:53000").await;
        assert_eq!(
            truncating.udp_queries.load(Ordering::SeqCst),
            asked + 1,
            "a request entering the jump target must ask the upstream, not get a cached truncated answer"
        );
    }

    /// With TCP fallback turned off the client gets the truncated answer, which is not
    /// cached: the next query asks the upstream again.
    /// 关掉 TCP 回退时客户端拿到截断的应答，它不写缓存：下一次查询照样去问上游。
    #[tokio::test]
    async fn a_truncated_answer_is_never_cached() {
        let truncating = spawn_truncating_upstream(None, Some(PARTIAL)).await;
        let engine = engine_with(
            serde_json::json!([{ "type": "forward", "upstream": truncating.addr }]),
            serde_json::json!({}),
            false,
        );
        let first = ask(&engine).await;
        assert!(first.metadata.truncation, "{first:?}");
        assert_eq!(addresses(&first), [PARTIAL]);
        ask(&engine).await;
        assert_eq!(
            truncating.udp_queries.load(Ordering::SeqCst),
            2,
            "the second query must ask the upstream again, not use a cached truncated answer"
        );
    }
}

#[cfg(test)]
mod response_matcher_tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::str::FromStr;
    use std::time::Duration;

    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use serde_json::json;

    use crate::engine::test_support::{self as support, counting_settings, engine_from, first_a};

    /// 上游给的地址 / The address the upstream answers
    const UPSTREAM: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 50);
    /// 响应匹配器成立时换上的地址 / The address answered instead when the response matchers hold
    const MATCHED: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 60);

    fn query(name: &str) -> Vec<u8> {
        let mut request = Message::new(0x1357, MessageType::Query, OpCode::Query);
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
        request.to_vec().unwrap()
    }

    /// 要用 GeoSite 数据的响应匹配器照样读得到它，在客户端请求的转发上和响应跳转路径上都一样：问的
    /// 名字在标签里就换成静态应答，不在就是上游的应答
    /// A response matcher that needs GeoSite data still reads it, on a client request's
    /// forward and on the response jump path alike: a name in the tag gets the static
    /// answer instead, any other the upstream's
    #[tokio::test]
    async fn response_matchers_still_read_the_geo_data() {
        let dir = tempfile::tempdir().unwrap();
        let geosite = dir.path().join("geosite.json");
        std::fs::write(
            &geosite,
            r#"{ "entries": [{ "tag": "g", "domains": ["domain:in.test"] }] }"#,
        )
        .unwrap();
        let up = support::upstream(|query| {
            let Some(question) = query.queries.first() else {
                return Vec::new();
            };
            let mut reply = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
            reply.metadata.recursion_desired = query.metadata.recursion_desired;
            reply.add_query(question.clone());
            reply.add_answer(Record::from_rdata(
                question.name().clone(),
                300,
                RData::A(A(UPSTREAM)),
            ));
            vec![(Duration::ZERO, reply.to_vec().unwrap())]
        })
        .await;
        let check = json!({
            "name": "check", "matchers": [{ "type": "any" }],
            "actions": [{ "type": "forward", "upstream": up.address }],
            "response_matchers": [{ "type": "response_request_domain_geo_site", "value": "g" }],
            "response_actions_on_match": [{ "type": "static_ip_response", "ip": MATCHED.to_string() }]
        });
        let engine = engine_from(json!({
            "settings": counting_settings(json!({
                "geosite_data_paths": [geosite.to_string_lossy()]
            })),
            "pipeline_select": [
                { "pipeline": "jump", "matchers": [{ "type": "client_ip", "cidr": "10.0.0.2/32" }] }
            ],
            "pipelines": [
                { "id": "main", "rules": [check] },
                { "id": "jump", "rules": [{
                    "name": "first", "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "forward", "upstream": up.address }],
                    "response_matchers": [{ "type": "upstream_equals", "value": up.address }],
                    "response_actions_on_match": [{ "type": "jump_to_pipeline", "pipeline": "main" }]
                }] }
            ]
        }));
        for client in ["10.0.0.1", "10.0.0.2"] {
            let peer: SocketAddr = format!("{client}:53000").parse().unwrap();
            for (name, expected) in [("a.in.test.", MATCHED), ("a.out.test.", UPSTREAM)] {
                let reply = support::ask(&engine, &query(name), peer).await;
                assert_eq!(first_a(&reply), Some(expected), "{client} {name}");
            }
        }
    }
}
