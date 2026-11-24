use super::Engine;
use crate::cache::CacheEntry;
use crate::config::GlobalSettings;
use crate::config::{Action, ForwardTarget, Transport};
use crate::ecs_scope::{EcsReach, EcsView, ForwardEcs};
use crate::engine::execution::{Request, Route};
use crate::engine::observation::{cached_source, report_response_rule};
use crate::engine::refresh::RefreshTarget;
use crate::engine::response::extract_ttl;
use crate::engine::response_log::{ResponseInfo, Source};
use crate::engine::rules::{self, ResponseActionResult, ResponseContext};
use crate::engine::types::InflightEntry;
use crate::engine::upstream::{UpstreamFailure, is_failure_reply, reject_failure_reply_on_refresh};
use crate::engine::utils::{InflightCleanupGuard, set_id};
use crate::matcher::{Requester, ResponsePhase};
use crate::observe::{CacheHit, CacheHitKind};
use crate::proto_utils;
use bytes::{Bytes, BytesMut};
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::Record;
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
    Continue { ctx: Box<Option<ResponseContext>> },
    /// 响应动作跳到 `pipeline`：请求在那里接着走规则，转发照原样发出这次转发发出的 `packet`，它带的 ECS 是 `carried`；应答
    /// 照旧缓存在跳转前这个 pipeline 的键下（见 `Route::jumped`、`Route::key_pipeline`）。这次转发登记的条目留给请求（见
    /// `Route::held_inflight`），等它拿到最终的应答再交出去
    /// A response action jumps to `pipeline`: the request goes on with the rules there, its
    /// forwards sending `packet`, what this forward sent, as it is, with `carried` as its ECS;
    /// answers are still cached under the key of this pipeline, the one jumped from (see
    /// `Route::jumped`, `Route::key_pipeline`). The entry this forward registered stays with the request (see
    /// `Route::held_inflight`) and is handed the final answer
    Jump {
        pipeline: Arc<str>,
        packet: Bytes,
        carried: ForwardEcs,
    },
}

/// 在 `pipeline_id` 的槽位 `slot` 里查 `request` 的应答：查缓存、等刷新以后再查、上游失败以后再查、交出过期应答都照它；
/// 槽位里按谁在问挑应答，后台刷新也照这个请求重放（地址、EDNS、客户端自己的 ECS），命中经它的观察者上报
/// Looking up `request`'s answer in slot `slot` of `pipeline_id`: the cache lookup, the
/// lookups after waiting for a refresh and after an upstream failure, and serving a stale
/// answer all go by it; the answer in the slot is picked by who is asking, a background refresh
/// replays this request (address, EDNS, the client's own ECS), and hits are reported through
/// its observer
pub struct CacheLookupContext<'a> {
    pub(crate) request: &'a Request<'a>,
    pub(crate) pipeline_id: &'a str,
    /// Response cache slot / 响应缓存槽位
    pub(crate) slot: u64,
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

/// 存了 `elapsed_secs` 秒的 `hit` 现在算什么：TTL 之内是新鲜的；TTL 到了以后，开着 serve_stale、过期没超过
/// serve_stale_expire_ttl（0 不限）的还能当过期应答交出去（见 `CacheEntry::spent`），其余的不能再用。查缓存、上游失败时
/// 找过期应答、等刷新时都按这一处判断
/// What `hit`, stored `elapsed_secs` seconds ago, counts as now: within its TTL it is fresh;
/// past it, with serve_stale on and no longer past its TTL than serve_stale_expire_ttl (0 for
/// no limit), it can still go out stale (see `CacheEntry::spent`), and otherwise it is of no
/// use. The cache lookup, looking for a stale answer after an upstream failure and waiting for
/// a refresh all go by this alone
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
/// 时马上交出；开着的先等上游（见 `Engine::answer_from_cache`），只有这份应答刚刷新失败过的不等（RFC 8767 第 5 节，见
/// `REFRESH_FAILURE_RECHECK`）。规则据上游应答给出的也一样等：它的刷新照样去问上游、把规则重新走一遍。查缓存和快速路径
/// 都按这一处判断
/// Whether `hit`, past its TTL and still of use (see [`Age::Stale`]), goes out right now, and
/// reported as what: at once with serve_stale_client_timeout_ms off; with it on it waits on
/// the upstream first (see `Engine::answer_from_cache`), and only an answer whose refresh
/// failed lately does not wait (RFC 8767 section 5, see `REFRESH_FAILURE_RECHECK`). One the
/// rules gave by an upstream answer waits alike: its refresh asks the upstream all the same
/// and runs the rules again. The cache lookup and the fast path both go by this alone
pub(crate) fn stale_at_once(
    engine: &Engine,
    settings: &GlobalSettings,
    slot: u64,
    hit: &CacheEntry,
) -> Option<CacheHitKind> {
    if settings.serve_stale_client_timeout_ms == 0 {
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

/// [`check_cache`] 在缓存里找到的 / What [`check_cache`] found in the cache
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

/// 查一次缓存：槽位里这个请求的那份应答、它存了多少秒、现在算什么，只给新鲜的、过期还能用的。槽位里的应答全都不能再
/// 用了，缓存才把整个槽位清掉；往槽位里写的时候顺带去掉不能再用的（见 `CacheSlot::with`），所以拿到的这份可能已经不能再
/// 用，现在算什么在这里判断。不能再用的留在原处，等重新取回的应答写进来时取代它，或者随槽位清扫：查缓存不为它拿写锁；它在
/// 的时候，这个请求方的查找也不退到一份更宽、更旧的应答上，和快速路径一样（见 `CacheSlot::select`）
/// One cache lookup: this request's answer in the slot, how many seconds it has been stored,
/// and what it counts as now, giving only one fresh, or stale and still of use. The cache
/// clears a slot only once none of its answers is of use any more, and drops those of no
/// further use from a slot as it writes to it (see `CacheSlot::with`), so the one got here may
/// be of no use already, and what it counts as now is decided here. One of no further use stays
/// where it is, until the answer fetched again replaces it or the slot is swept: a lookup takes
/// no write lock for it, and while it is there this requester's lookups do not fall back to a
/// wider, older answer, as on the fast path (see `CacheSlot::select`)
fn usable_hit(
    engine: &Engine,
    context: &CacheLookupContext<'_>,
) -> Option<(Arc<CacheEntry>, u64, Age)> {
    let now = Instant::now();
    let request = context.request;
    let hit = engine.cache_get(
        context.slot,
        &request.requester.ecs_view(),
        &request.cached_question(context.pipeline_id),
    )?;
    let elapsed_secs = now.saturating_duration_since(hit.inserted_at).as_secs();
    let age = age_of(&hit, elapsed_secs, &request.state.pipeline.settings);
    (age != Age::Spent).then_some((hit, elapsed_secs, age))
}

/// Checks the response cache: a fresh answer goes out with its TTLs aged and may start a
/// background refresh; an expired one still of use is served stale or waits on its refresh as
/// serve_stale says; one of no further use is a miss, left where it is (see `usable_hit`).
/// 查响应缓存：新鲜的应答按停留时间减 TTL 后给出，必要时发起后台刷新；过期还能用的按 serve_stale
/// 的设置当作 stale 提供或者等它的刷新；不能再用的算未命中，留在原处（见 `usable_hit`）。
pub(crate) fn check_cache(
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
    let request = context.request;
    let view = request.requester.ecs_view();
    match stale_at_once(engine, &request.state.pipeline.settings, context.slot, &hit) {
        Some(kind) => Looked::Answered(serve_stale(engine, context, &hit, &view, kind, response)),
        // 先等上游：条目留着，等待到头时交出；刷新现在就发起，等的就是它
        // The upstream comes first: the entry stays to go out when the wait runs out,
        // and its refresh, which is what is waited for, starts now
        None => {
            engine.spawn_background_refresh(request.state, &hit, context.slot, request.requester);
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
    let view = context.request.requester.ecs_view();
    Some(serve_stale(engine, context, &hit, &view, kind, response))
}

/// 上游失败以后（见 `Forwarding::upstream_failed`）再查一次缓存：这期间别人写进同一槽位、也适用于这个请求方的新鲜应答
/// （同时在问、inflight 键不同的请求拿到的，或者后台刷新拿到的）照常交出；过期还能用的按上游失败时交出的过期应答交出
/// （RFC 8767）。以前只认过期的，新鲜的放着不用，客户端拿 SERVFAIL
/// Look in the cache again once the upstream failed (see `Forwarding::upstream_failed`): a fresh
/// answer someone else wrote into the slot meanwhile that applies to this requester too (got by
/// a request asking at once under another inflight key, or by a background refresh) goes out as
/// usual; one stale and still of use goes out as the stale answer of an upstream failure (RFC
/// 8767). Only a stale one used to count, a fresh one left unused and the client getting
/// SERVFAIL
pub(crate) fn check_cache_after_failure(
    engine: &Engine,
    context: &CacheLookupContext<'_>,
    response: &mut ResponseInfo,
) -> Option<Bytes> {
    let (hit, elapsed_secs, age) = usable_hit(engine, context)?;
    if age == Age::Fresh {
        return Some(serve_fresh(engine, context, &hit, elapsed_secs, response));
    }
    let view = context.request.requester.ecs_view();
    Some(serve_stale(
        engine,
        context,
        &hit,
        &view,
        CacheHitKind::StaleUpstreamFailure,
        response,
    ))
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
    let request = context.request;
    let view = request.requester.ecs_view();
    let elapsed = crate::proto_utils::saturating_u64_to_u32(elapsed_secs);
    let resp_bytes = served_from_cache(hit, request.tx_id, &view, ServedTtl::Elapsed(elapsed));

    engine.refresh_if_due(request.state, hit, elapsed, context.slot, request.requester);

    response.served_from_cache(hit);
    if let Some((observer, ctx)) = request.observed {
        observer.cache_hit(ctx, &cache_hit_of(hit, CacheHitKind::Fresh, elapsed));
    }
    resp_bytes
}

/// 一份上游应答自己的 TTL（记录里最小的，否定应答用 SOA 的负缓存 TTL，没有 SOA 的为 0）收进
/// `min_ttl..=cache_max_ttl`，和应答带的每条记录一样（见 `forward_upstream`）。回答检查据它做的决定按这个算（见
/// `Route::went_by`），缓存它多久也从这里算（见 [`ttl_to_cache`]）
/// An upstream answer's own TTL (the least of its records', the SOA negative TTL for a
/// negative answer, 0 for one without SOA) brought into `min_ttl..=cache_max_ttl`, as every
/// record the answer carries is (see `forward_upstream`). A decision an answer check takes on
/// it goes by this (see `Route::went_by`), and how long it is cached comes from here too (see
/// [`ttl_to_cache`])
fn ttl_within(engine: &Engine, own_ttl: u64, min_ttl: Duration) -> u32 {
    proto_utils::saturating_u64_to_u32(own_ttl.max(min_ttl.as_secs())).min(engine.ttl_cap())
}

/// 缓存留一份应答多久：它自己的 TTL 收进范围（见 [`ttl_within`]）；0 就不缓存。它自己的 TTL 为 0 时不缓存：要么没有可
/// 依据的 TTL（没有 SOA 的否定应答，RFC 2308 第 4 节说不要缓存），要么 min_ttl 为 0 时记录的 TTL 就是 0
/// How long the cache keeps an answer: its own TTL brought into the range (see
/// [`ttl_within`]); 0 means not cached. An own TTL of 0 is not cached: either the answer gives
/// no TTL to go by (a negative answer without SOA, which RFC 2308 section 4 says not to
/// cache), or, with min_ttl 0, its records have TTL 0
fn ttl_to_cache(engine: &Engine, own_ttl: u64, min_ttl: Duration) -> u32 {
    if own_ttl == 0 {
        0
    } else {
        ttl_within(engine, own_ttl, min_ttl)
    }
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
    let request = context.request;
    let settings = &request.state.pipeline.settings;
    debug!(
        event = "serve_stale",
        kind = ?kind,
        qname = %request.qname,
        qtype = ?request.qtype,
        rcode = %crate::observe::rcode_name(hit.rcode.into()),
        original_ttl = hit.original_ttl,
        stale_for_secs = hit
            .inserted_at
            .elapsed()
            .as_secs()
            .saturating_sub(u64::from(hit.original_ttl)),
        request_ms = request.start.elapsed().as_millis() as u64,
        client_ip = %request.peer.ip(),
        pipeline = %context.pipeline_id,
        "RFC 8767: serving a stale answer"
    );
    let resp_bytes = served_from_cache(
        hit,
        request.tx_id,
        view,
        ServedTtl::Stale(settings.serve_stale_ttl),
    );
    // 发起后台刷新，重新决定一次。规则据上游应答给出的（没有上游的那种）也一样：它是对上游那次应答的检查结果，过期了就得
    // 照上游现在的回答再检查一遍
    // Start a background refresh to decide again. An answer the rules gave by an upstream's
    // answer (one with no upstream) is no different: it is what the check of that one reply
    // came to, and once expired it is to be checked again on what the upstream answers now
    engine.spawn_background_refresh(request.state, hit, context.slot, request.requester);
    if let Some((observer, ctx)) = request.observed {
        observer.cache_hit(ctx, &cache_hit_of(hit, kind, 0));
    }
    response.served_from_cache(hit);
    resp_bytes
}

/// 处理静态决定：照请求构造应答（见 `response::static_reply`），按 `Route::static_ttl` 说的时长缓存在路线的键下（见
/// `Route::cache`）：取决于上游应答的才缓存，规则直接给出的、上游失败以后兜底给出的不缓存。槽位把规则分得开的请求方分开（见
/// `RuntimePipeline::requester`），所以规则按「谁在问」给的应答也和别的应答一样缓存。不输出 `dns_response` 记录，那只由
/// 引擎的请求路径输出
/// Handles Decision::Static: builds the answer for the request (see `response::static_reply`),
/// and caches it under the route's keys (see `Route::cache`) for as long as
/// `Route::static_ttl` says: one depending on an upstream's answer is cached, one the rules
/// give outright or as a fallback after an upstream failure is not. The slot keeps apart the
/// requesters the rules tell apart (see `RuntimePipeline::requester`), so an answer the rules
/// give by who is asking is cached like any other. Emits no `dns_response` record, which only
/// the engine request path does
pub(crate) fn handle_static_decision(
    engine: &Engine,
    request: &Request<'_>,
    route: &Route,
    rcode: ResponseCode,
    answers: &[Record],
) -> Bytes {
    let reply = super::response::static_reply(
        request.packet,
        request.qname,
        request.qtype,
        request.qclass,
        rcode,
        answers,
    );
    let ttl = route.static_ttl(super::response::least_ttl(answers));
    route.cache(engine, request, reply, rcode, None, ttl)
}

/// 转发决定自己说的：问哪些上游、怎样问、回答检查做什么。请求本身见 `Request`，它沿着规则走到了哪里见 `Route`
/// What a forward decision itself says: which upstreams to ask, how, and what the answer check
/// does. The request itself is in `Request`, how far along the rules it has come in `Route`
#[derive(Clone, Copy)]
pub(crate) struct ForwardDecision<'a> {
    pub(crate) target: &'a ForwardTarget,
    pub(crate) rule_name: &'a str,
    /// 回答检查：响应匹配器和两种结果下的动作，没有回答检查时为 None / The answer check, the
    /// response matchers and the actions for either result; None without one
    pub(crate) response: Option<&'a ResponsePhase>,
    pub(crate) transport: Transport,
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
pub(crate) async fn handle_forward_decision<'a>(
    engine: &'a Engine,
    request: &'a Request<'a>,
    route: &'a mut Route,
    decision: ForwardDecision<'a>,
    response: &mut ResponseInfo,
) -> anyhow::Result<ForwardResult> {
    response.upstream = Some(Source::Upstream(Arc::clone(&decision.target.upstream)));
    let mut forwarding = Forwarding::new(engine, request, route, decision);
    let reply = match forwarding.fetch(response).await {
        Fetched::Joined(answer) => return Ok(ForwardResult::Success(answer)),
        Fetched::Asked(reply) => forwarding.weigh(reply),
        Fetched::Reused(ctx) => forwarding.reuse(ctx),
    };
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

/// [`Forwarding::weigh`] 掂量过的应答（见 [`Answer`]），或者这次转发的失败
/// A reply [`Forwarding::weigh`] weighed (see [`Answer`]), or this forward's failure
type Weighed = anyhow::Result<Answer>;

/// 读出来的上游应答（见 [`Forwarding::read`]）/ An upstream reply as read (see [`Forwarding::read`])
enum Answer {
    /// 只经快速解析读的：应答本身、给出它的上游、它的 RCODE 和自己的 TTL（见 `ttl_to_cache`）
    /// Read by the quick parse alone: the reply itself, the upstream that gave it, its RCODE and
    /// its own TTL (see `ttl_to_cache`)
    Plain {
        raw: Bytes,
        upstream: Arc<str>,
        rcode: ResponseCode,
        ttl: u64,
    },
    /// hickory 读好的，或者规则越过、这里复用的（见 [`Forwarding::reuse`]）
    /// Read by hickory, or one a rule continued past, reused here (see [`Forwarding::reuse`])
    Read(ResponseContext),
    /// 几个上游都回了失败应答、回答检查照样放行的那一个（见 `rules::check_failure_reply`）：回答阶段拿它当已经检查过的
    /// 应答，不再检查一遍
    /// The failure reply of several upstreams the answer check let through all the same (see
    /// `rules::check_failure_reply`): the answer phase takes it as an answer checked already,
    /// with no second check
    Checked(ResponseContext),
}

impl Answer {
    /// 应答本身 / The reply itself
    fn raw(&self) -> &[u8] {
        match self {
            Self::Plain { raw, .. } => raw,
            Self::Read(ctx) | Self::Checked(ctx) => &ctx.raw,
        }
    }
}

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
    /// 这次转发自己问来的应答或失败 / The reply or the failure this forward asked for itself
    Asked(Reply),
    /// 规则越过、这里复用的应答，连同解析好的报文（见 [`Forwarding::reuse`]）/ The answer a rule
    /// continued past, reused here with its parsed message (see [`Forwarding::reuse`])
    Reused(ResponseContext),
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
                    modified = matches!(modified, Cow::Owned(_)),
                    "ECS request rewriting applied / 已应用 ECS 请求改写"
                );
                (
                    modified,
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
            return Fetched::Reused(ctx);
        }
        Fetched::Asked(match self.wait_on_another(response).await {
            Some(Ok(answer)) => return Fetched::Joined(answer),
            Some(Err(gave_up)) => Err(gave_up),
            None => self.ask().await,
        })
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
        let route = &*self.route;
        let (inflight, key_pipeline) = (route.keys.inflight, &route.key_pipeline);
        // What this forward registers or waits under in the inflight map
        // 这次转发在 inflight 表里登记或等待的问题
        let question = route.question(request);
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
            let mut rx = match engine.inflight.entry(inflight) {
                // 进不了缓存的也不交给别人（流控拦过这个请求、它发出的 ECS 说不准适用于谁）：它不领头，自己转发。以前
                // 流控拦下以后 continue 到下一条规则，那里的转发照样登记条目，把这台设备拿到的兜底交给同时来问的别的设备
                // What may not go into the cache is not handed to others either (flow control
                // kept this request back, or whom the ECS it sends applies to is unknown): it
                // leads no entry and forwards itself. With flow control having kept it back,
                // continuing to the next rule used to register an entry there all the same,
                // handing this device's fallback to the other devices asking meanwhile
                Entry::Vacant(_) if route.trail.is_uncacheable() => return None,
                Entry::Vacant(entry) => {
                    entry.insert(InflightEntry::sharing(
                        &question,
                        key_pipeline,
                        Arc::<[u8]>::from(Arc::clone(request.qname)),
                    ));
                    self.registered =
                        Some(InflightCleanupGuard::new(engine.inflight.clone(), inflight));
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
                Entry::Occupied(_) if route.held_inflight.is_some() => return None,
                // Another question's entry under the same key: the key is only a hash (see
                // `KeyedQuestion`), and waiting on it would hand this request another
                // question's answer. It forwards itself instead.
                // 同一个键下别的问题的条目：键只是哈希（见 `KeyedQuestion`），等它就会把
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
                &self.decision.target.upstream,
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
            &request.state.pipeline.settings,
            &self.packet,
            decision.target,
            decision.transport,
            request.observed,
            request.asker(),
        )
        .await
    }

    /// 掂量这次转发拿到的应答或失败，记进 trail：它决定此后得到的每份应答适用于谁
    /// Weigh the reply or failure this forward got, and note it in the trail: it decides whom
    /// every answer reached from here applies to
    fn weigh(&mut self, reply: Reply) -> Weighed {
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
        // `rules::check_failure_reply`）；放行的那个连同解析好的报文交给回答阶段（见 [`Answer`]）。刷新随后照旧拒收它。
        // 别的应答先读出来（见 [`Self::read`]），读不了的和上游失败一样记进 trail
        // When several upstreams all replied with a failure, the rule's answer check still sees
        // the first of those replies (see `rules::check_failure_reply`); one let through goes
        // to the answer phase with its parsed message (see [`Answer`]). A refresh still
        // rejects it right after. Any other reply is read first (see [`Self::read`]), and one
        // that cannot be read goes into the trail as the upstream failing does
        let reply = match reply {
            Err(failure) => decision
                .response
                .and_then(|phase| {
                    rules::check_failure_reply(&failure, &phase.on_match, |ctx| {
                        rules::response_matches(
                            &request.state.geo,
                            &phase.matchers,
                            &request.facts(),
                            &ctx.upstream,
                            &ctx.msg,
                        )
                    })
                })
                .map(Answer::Checked)
                .ok_or(failure),
            Ok((raw, upstream)) => self.read(raw, upstream),
        };
        // A refresh takes a failure reply as a failed attempt before the response rules
        // see it, as forward_upstream does for a rule with several upstreams: the
        // refresh fails as it does on any upstream failure (see `Self::settle`), and
        // never caches the reply (see reject_failure_reply_on_refresh).
        // 刷新在响应规则看到失败应答之前就把它当作一次失败的尝试，和规则有多个上游时
        // forward_upstream 的做法一样：刷新和上游别的失败一样以失败结束（见 `Self::settle`），
        // 也不缓存这个应答（见 reject_failure_reply_on_refresh）。
        let reply = reply.and_then(|answer| {
            reject_failure_reply_on_refresh(request.refresh.is_some(), answer.raw())
                .map(|()| answer)
        });
        match &reply {
            Ok(answer) => self
                .route
                .trail
                .record_reply(self.forward_ecs, answer.raw()),
            Err(_) => self.route.trail.record_failure(self.forward_ecs),
        }
        reply
    }

    /// 复用规则越过的应答 `ctx`（continue 之后的 `allow`）：它那次转发已经记在 trail 里，报文也已经由 hickory 解析好，不再读
    /// 一遍（见 [`Self::read`]）。刷新照样拒收失败应答（见 [`Self::weigh`]）：越过的可能是响应动作转发拿到的
    /// Reuse `ctx`, the answer a rule continued past (an `allow` after a continue): the trail
    /// has its forward already and hickory has parsed its message, which is not read again (see
    /// [`Self::read`]). A refresh still rejects a failure reply (see [`Self::weigh`]): the
    /// answer passed may be one a response action's forward got
    fn reuse(&self, ctx: ResponseContext) -> Weighed {
        reject_failure_reply_on_refresh(self.request.refresh.is_some(), &ctx.raw)?;
        Ok(Answer::Read(ctx))
    }

    /// 读 `upstream` 给的应答 `raw`。回答检查要读解析好的报文，所以有回答检查时总用 hickory 的（见 `rules::read_reply`）。
    /// 没有时，结构经得起检查的应答照快速解析的结果读（见 `well_formed_reply`）；其余的照 hickory 读出的，只有快速解析读得了
    /// 的照样交出去、不缓存（TTL 记 0）。两边都读不了的算这次转发失败（见 [`Self::settle`]）：和上游没回答一样，有过期应答
    /// 就交出过期应答、没有就回 SERVFAIL，或者执行 miss 动作，等在这次转发登记的条目上的请求也拿到它
    /// Read the reply `raw` that `upstream` gave. The answer check reads the parsed message, so
    /// with one hickory's is always taken (see `rules::read_reply`). Without one a reply whose
    /// structure holds up is read as the quick parse reads it (see `well_formed_reply`); any
    /// other as hickory reads it, or, when only the quick parse can read it, it goes on as it is
    /// and is not cached (a TTL of 0). One neither can read fails this forward (see
    /// [`Self::settle`]): as when the upstream gives no answer, a stale answer goes out if there
    /// is one and SERVFAIL if not, or the miss actions run, and the requests waiting on the
    /// entry this forward registered get it too
    fn read(&self, raw: Bytes, upstream: Arc<str>) -> anyhow::Result<Answer> {
        let quick = self
            .decision
            .response
            .is_none()
            .then(|| proto_utils::parse_response_quick(&raw))
            .flatten();
        match quick {
            Some(qr) if proto_utils::well_formed_reply(&raw) => Ok(Answer::Plain {
                raw,
                upstream,
                rcode: qr.rcode,
                ttl: u64::from(qr.min_ttl),
            }),
            quick => match (rules::read_reply(&raw, &upstream), quick) {
                (Ok(msg), _) => Ok(Answer::Read(ResponseContext { raw, msg, upstream })),
                (Err(_), Some(qr)) => Ok(Answer::Plain {
                    raw,
                    upstream,
                    rcode: qr.rcode,
                    ttl: 0,
                }),
                (Err(error), None) => Err(error),
            },
        }
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
        let on_miss = self
            .decision
            .response
            .map_or(&[][..], |phase| phase.on_miss.as_slice());
        match reply {
            Ok(answer) => self.answered(answer, response).await,
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
            Err(e) if on_miss.is_empty() => Ok(self.upstream_failed(e, response)),
            Err(e) => {
                // 上游失败这一次只在这里记一条，带着问题、规则组和原因（见 `upstream_failed`）；流控没让等的不逐个记
                // The upstream failure is logged here once, with the question, the pipeline and
                // the reason (see `upstream_failed`); one with flow control keeping the query
                // from waiting is not logged one by one
                if !UpstreamFailure::was_withheld(&e) {
                    let (request, decision) = (self.request, self.decision);
                    crate::warn_sparse!(
                        per decision.target.upstream;
                        event = "miss_actions_on_upstream_failure",
                        upstream = %decision.target.upstream,
                        qname = %request.qname,
                        qtype = ?request.qtype,
                        client_ip = %request.peer.ip(),
                        pipeline = %self.route.pipeline,
                        error = %format_args!("{e:#}"),
                        "upstream failed, running the miss actions"
                    );
                }
                self.act(on_miss, None, response).await
            }
        }
    }

    /// 上游的应答：按响应匹配器挑出要执行的动作，带着应答执行；没有动作时应答就是结果（见 [`Self::cache_reply`]）
    /// The upstream's answer: the response matchers pick the actions to run, which run with
    /// it; with none the answer is the outcome (see [`Self::cache_reply`])
    async fn answered(
        mut self,
        answer: Answer,
        response: &mut ResponseInfo,
    ) -> anyhow::Result<ForwardResult> {
        let (request, decision) = (self.request, self.decision);
        let (ctx, checked) = match answer {
            Answer::Plain {
                raw,
                upstream,
                rcode,
                ttl,
            } => return Ok(self.cache_reply(raw, upstream, rcode, ttl, response)),
            Answer::Read(ctx) => (ctx, false),
            Answer::Checked(ctx) => (ctx, true),
        };
        // A background refresh applies the response rules as a client request
        // does (a failure reply never gets here, see above): an answer a rule
        // continues past, or replaces, must not be what the refresh caches.
        // 后台刷新和客户端请求一样执行响应规则（失败应答到不了这里，见上）：规则
        // 越过或替换掉的应答，不能成为刷新写进缓存的结果。
        let actions = decision.response.map_or(&[][..], |phase| {
            let matched = checked
                || rules::response_matches(
                    &request.state.geo,
                    &phase.matchers,
                    &request.facts(),
                    &ctx.upstream,
                    &ctx.msg,
                );
            // A refresh reports these too: it acts on the response rules like a client
            // request, and the observer tells the two apart by background_refresh.
            // 刷新同样上报：它和客户端请求一样按响应规则行事，观察者按 background_refresh 区分。
            report_response_rule(
                request.observed,
                &self.route.pipeline,
                decision.rule_name,
                phase.matchers.len(),
                matched,
                &phase.on_match,
            );
            if matched {
                phase.on_match.as_slice()
            } else {
                phase.on_miss.as_slice()
            }
        });
        if actions.is_empty() {
            let (rcode, ttl) = (ctx.msg.metadata.response_code, extract_ttl(&ctx.msg));
            return Ok(self.cache_reply(ctx.raw, ctx.upstream, rcode, ttl, response));
        }
        response.upstream = Some(Source::Upstream(Arc::clone(&ctx.upstream)));
        self.act(actions, Some(ctx), response).await
    }

    /// 上游的应答 `raw` 就是结果：按它自己的 TTL `ttl` 写进缓存（见 `ttl_to_cache`），回答检查 continue 或跳转以后转发拿到的
    /// 也不比这一路上回答检查据过的应答留得久（见 `Route::cache`），交给等在这次转发登记的条目上的请求
    /// The upstream's reply `raw` is the outcome: cached by its own TTL `ttl` (see
    /// `ttl_to_cache`), one fetched after an answer check continued or jumped staying no longer
    /// than the answers the checks on the way went by (see `Route::cache`), and handed to the
    /// requests waiting on the entry this forward registered
    fn cache_reply(
        &mut self,
        raw: Bytes,
        upstream: Arc<str>,
        rcode: ResponseCode,
        ttl: u64,
        response: &mut ResponseInfo,
    ) -> ForwardResult {
        let (engine, request) = (self.engine, self.request);
        response.upstream = Some(Source::Upstream(Arc::clone(&upstream)));
        let ttl = ttl_to_cache(engine, ttl, request.state.pipeline.min_ttl());
        let raw = self
            .route
            .cache(engine, request, raw, rcode, Some(upstream), ttl);
        self.hand_over(&raw);
        ForwardResult::Success(raw)
    }

    /// 上游失败、规则没有 miss 动作时给客户端的应答：所有上游尝试都耗尽了、或者上游的应答读不了（见 [`Self::read`]）才
    /// 这样答，先再查一次缓存（见 `check_cache_after_failure`），没有就 SERVFAIL。这次失败只在这里记一条 warn，带着问题、
    /// 规则组和原因（只问一个上游时 `forward_upstream` 不另记）
    /// The answer for the client when the upstream failed and the rule has no miss actions,
    /// given once every upstream attempt is exhausted or the upstream's reply cannot be read
    /// (see [`Self::read`]): the cache looked in again (see `check_cache_after_failure`), or else
    /// SERVFAIL. The failure is logged here as one warning, with the question, the pipeline and
    /// the reason (`forward_upstream` logging none of its own for a single upstream)
    fn upstream_failed(&mut self, e: anyhow::Error, response: &mut ResponseInfo) -> ForwardResult {
        let (request, decision, route) = (self.request, self.decision, &*self.route);
        let withheld = UpstreamFailure::was_withheld(&e);
        let cached = check_cache_after_failure(self.engine, &route.lookup(request), response);
        let answer = match cached {
            Some(cached) => {
                if withheld {
                    debug!(
                        event = "cached_answer_on_upstream_withheld",
                        upstream = %decision.target.upstream,
                        qname = %request.qname,
                        client_ip = %request.peer.ip(),
                        error = %format_args!("{e:#}"),
                        "flow control kept the query from the upstream, answering from the cache"
                    );
                } else {
                    crate::warn_sparse!(
                        per decision.target.upstream;
                        event = "cached_answer_on_upstream_failure",
                        upstream = %decision.target.upstream,
                        qname = %request.qname,
                        qtype = ?request.qtype,
                        client_ip = %request.peer.ip(),
                        pipeline = %route.pipeline,
                        error = %format_args!("{e:#}"),
                        "upstream failed, answering from the cache"
                    );
                }
                cached
            }
            None => {
                if withheld {
                    debug!(
                        event = "upstream_withheld",
                        upstream = %decision.target.upstream,
                        qname = %request.qname,
                        client_ip = %request.peer.ip(),
                        error = %format_args!("{e:#}"),
                        "flow control kept the query from the upstream"
                    );
                } else {
                    crate::warn_sparse!(
                       per decision.target.upstream;
                       event = "upstream_failure",
                       upstream = %decision.target.upstream,
                       qname = %request.qname,
                       qtype = ?request.qtype,
                       client_ip = %request.peer.ip(),
                       error = %format_args!("{e:#}"),
                       pipeline = %route.pipeline,
                       "upstream failed"
                    );
                }
                proto_utils::servfail_reply(request.packet)
            }
        };
        self.hand_over(&answer);
        ForwardResult::Success(answer)
    }

    /// 执行 `actions`：带着回答检查看过的上游应答 `ctx`，或者上游失败以后不带。回答检查看到的是失败应答（见
    /// `upstream::is_failure_reply`）时和不带一样，算上游失败，那时给出的结果是兜底（刷新到不了那里，见 [`Self::settle`]、
    /// [`Self::weigh`]）。据上游回答给出的、continue 或跳转以后给出的，不论静态应答还是转发拿到的，在缓存里留的时间和交出去
    /// 的记录 TTL 都不比这一路上回答检查据过的哪份回答的 TTL 长，那份回答的 TTL 和记录的一样收进 min_ttl..=cache_max_ttl（见
    /// `Route::answer_ttl`）。上游失败以后给出的静态应答是兜底，不缓存，此后规则给出的静态应答也都不缓存；转发拿到的照常
    /// 缓存，故障期间备用上游的回答也是这个问题的回答（见 `Route::fell_back`）
    /// Run `actions`: with the upstream answer `ctx` the answer check read, or without one after
    /// an upstream failure. A failure reply the check read (see `upstream::is_failure_reply`)
    /// counts as one without, an upstream failure, when what they give is a fallback (a refresh
    /// never gets there, see [`Self::settle`], [`Self::weigh`]). What is given by an upstream
    /// answer, or after a continue or a jump on it, be it a static answer or one a forward
    /// fetched, stays in the cache and carries record TTLs no longer than the TTL of any answer
    /// the checks on the way went by, brought into min_ttl..=cache_max_ttl as a record's is (see
    /// `Route::answer_ttl`). A static answer given after an upstream failure is a fallback
    /// and not cached, nor is any static answer the rules give after it; one a forward fetches
    /// is cached as usual, a backup upstream's answer during the failure answering the question
    /// all the same (see `Route::fell_back`)
    async fn act(
        mut self,
        actions: &'a [Action],
        ctx: Option<ResponseContext>,
        response: &mut ResponseInfo,
    ) -> anyhow::Result<ForwardResult> {
        let request = self.request;
        let min_ttl = request.state.pipeline.min_ttl();
        self.route.went_by(
            ctx.as_ref()
                .filter(|ctx| !is_failure_reply(ctx.msg.metadata.response_code))
                .map(|ctx| ttl_within(self.engine, extract_ttl(&ctx.msg), min_ttl)),
        );
        let ctx = rules::ApplyResponseActionsContext {
            engine: self.engine,
            request,
            actions,
            ctx_opt: ctx,
            packet: &self.packet,
            pipeline_id: &self.route.pipeline,
            rule_name: self.decision.rule_name,
            remaining_jumps: self
                .route
                .response_jumps_left(request.state.pipeline.settings.response_jump_limit as usize),
            trail: &mut self.route.trail,
            rule_ecs: self.forward_ecs,
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
                let (rcode, ttl) = (ctx.msg.metadata.response_code, extract_ttl(&ctx.msg));
                Ok(self.cache_reply(ctx.raw, ctx.upstream, rcode, ttl, response))
            }
            ResponseActionResult::Static { bytes, rcode, ttl } => {
                // 上游失败以后 miss 动作给的静态应答只是这一次请求的兜底，不是这个问题的应答，不缓存（见
                // `Route::fell_back`）：缓存是所有请求方共用的，写进去的话，上游恢复了它还要一直用到条目到期
                // After an upstream failure a static answer of the miss actions is a fallback
                // for this request, not the answer to the question, and is not cached (see
                // `Route::fell_back`): the cache is shared by every requester, and cached it
                // would go on serving after the upstream recovered, until the entry expired
                let ttl = self.route.static_ttl(ttl);
                let bytes = self
                    .route
                    .cache(self.engine, request, bytes, rcode, None, ttl);
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
                Ok(ForwardResult::Continue { ctx: Box::new(ctx) })
            }
        }
    }

    /// 把最终应答交给等在这次转发登记的条目上的请求 / Hand the final answer to the requests
    /// waiting on the entry this forward registered
    fn hand_over(&mut self, answer: &Bytes) {
        if let Some(guard) = self.registered.as_mut() {
            let (request, route) = (self.request, &*self.route);
            guard.hand_over(|| for_waiters(answer, &request.requester, &route.trail));
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
        return proto_utils::ecs_removed(&reply).map_or(reply, Bytes::from);
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
pub(crate) fn for_waiters(reply: &Bytes, requester: &Requester, trail: &EcsReach) -> Bytes {
    match requester.ecs {
        None => reply.clone(),
        Some(client) => client_reply(
            reply.clone(),
            Some(&client),
            trail.echo_scope(&requester.ecs_view()),
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

    /// 不进缓存的静态应答：它带的 TTL 是 0（见 `Route::static_ttl`）
    /// A static answer that is not cached: the TTL it carries is 0 (see `Route::static_ttl`)
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
        crate::engine::types::KeyedQuestion {
            namespace: state.cache_namespace(pipeline),
            pipeline_id: pipeline,
            qname: b"example.com",
            qtype: RecordType::A,
            qclass: DNSClass::IN,
            flags: crate::proto_utils::QueryFlags::RECURSIVE,
            requester: crate::matcher::RequesterKey::NONE,
            client_ecs: None,
        }
        .slot()
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
    /// 回答的时间就和缓存一样长；两者冲突时以 cache_max_ttl 为准。回答检查之后响应动作转发拿到的回答，每条记录
    /// 还不比回答检查据的那份回答的 TTL 长（见 `Route::cache`）：那份回答就来自同一个上游，记录里最短的是 5
    /// 秒的那条，收进范围以后是 60、300 或 5。此前 min_ttl 只决定存不存，条目还是
    /// 照上游的 TTL 过期；cache_max_ttl 只限制条目存多久，客户端拿到的仍是上游的 TTL。
    /// The TTL of every record in an upstream answer is brought into min_ttl to
    /// cache_max_ttl and the cache keeps what was brought in, so a client keeps an
    /// answer as long as the cache does; cache_max_ttl wins when the two cross. An
    /// answer a response action's forward gets after an answer check carries no record
    /// longer than the TTL of the answer the check went by, either (see `Route::cache`):
    /// that answer comes from the same upstream, the least of its records the one of 5
    /// seconds, 60, 300 or 5 once brought into the range. min_ttl used to decide only
    /// whether an answer was cached, the entry still expiring by the upstream's TTL;
    /// cache_max_ttl only bounded how long an entry was kept, clients still getting the
    /// upstream's TTL.
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
                let carried = if *path == "response action" {
                    [*cached; 2]
                } else {
                    *carried
                };
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
                        ttls == carried || ttls == carried.map(|ttl| ttl - 1),
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
            engine.handle_refresh(
                &query().to_vec().unwrap(),
                client,
                target,
                engine.state.load_full(),
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

    /// continue 之后跳过去拿到的应答缓存在入口的键下（见 `Route::enter`），刷新拿它更新条目：静态应答和转发拿到的都一样
    /// What a jump after a continue gets is cached under the entry's key (see `Route::enter`), and
    /// the refresh renews the entry with it: a static answer and a forwarded one alike
    #[tokio::test]
    async fn a_refresh_renews_the_entry_with_what_a_jump_after_a_continue_reaches() {
        let answering = answering_upstream(FINAL, 300).await.address;
        for (target, renewed) in [
            (static_target(), STATIC.parse().unwrap()),
            (rule("target", forward(&answering), json!({})), FINAL),
        ] {
            let later = vec![rule("jump", jump_to("other"), json!({}))];
            let cached =
                refresh_with_actions_on_the_answer(json!({}), continue_(), later, target).await;
            assert_eq!(cached, Some(vec![renewed]));
        }
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
