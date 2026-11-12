use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::IpAddr;
#[cfg(unix)]
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use anyhow::Context;
use arc_swap::ArcSwap;
#[cfg(unix)]
use bytes::Bytes;
use dashmap::DashMap;
#[cfg(unix)]
use http_body_util::{BodyExt, Full, Limited};
#[cfg(unix)]
use hyper::body::Incoming;
#[cfg(unix)]
use hyper::header::{CACHE_CONTROL, CONTENT_TYPE, HeaderValue};
#[cfg(unix)]
use hyper::service::service_fn;
#[cfg(unix)]
use hyper::{Method, Request, Response, StatusCode};
#[cfg(unix)]
use hyper_util::rt::TokioIo;
use parking_lot::{Mutex, MutexGuard, RwLock};
use rustc_hash::FxHashMap;
#[cfg(unix)]
use serde::Deserialize;
#[cfg(unix)]
use serde_json::json;

use crate::engine::Engine;
use crate::observe::{
    CacheHit, CacheHitKind, ConfigLoaded, ConfigReloadFailed, DecisionMade, EngineObserver,
    RequestContext, RequestOutcome, RequestStatus, RuleAnswer, RuleCacheLookup, RuleEvaluated,
    RuleMatched, RulePhase, TracingObserver, UpstreamAttempt, UpstreamOutcome, UpstreamResult,
    UpstreamSkipReason, UpstreamSkipped,
};
use crate::panel_querylog::{self, OwnLines, QueryLog, WallClock};
use crate::panel_trace;
use sha2::{Digest, Sha256};

#[cfg(unix)]
const PROTOCOL_VERSION: u8 = 1;
const MAX_ERROR_LENGTH: usize = 2_048;
const MAX_METRIC_SERIES_PER_MAP: usize = 1_024;
const MAX_METRIC_KEY_BYTES: usize = 512;

#[cfg(unix)]
const MAX_CONFIG_BODY: usize = 4 * 1024 * 1024;
#[cfg(unix)]
const MAX_DIAGNOSTIC_BODY: usize = 2 * 1024;
/// 控制通道上请求头、请求正文各自最多等这么久，长连接上等下一个请求也算在请求头里。面板在同一台
/// 机器上，每个请求一下子就发完；以前只发了一半就不动的连接会一直占着一个任务和一个句柄。
/// How long the control socket waits for a request head, and again for a request
/// body; on a keep-alive connection the wait for the next request counts as the
/// head. The panel runs on the same host and sends each request at once; a
/// connection that stopped half way used to hold a task and a descriptor for good.
#[cfg(unix)]
const REQUEST_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const QUERY_STATS_BUCKET_SECONDS: u64 = 3_600;
const QUERY_STATS_BUCKETS: usize = 24;
/// 一个钟头最多记多少项。各线程分开记，同一个域名可能在几个线程里各占一项，所以留出两倍的地方
/// How many entries an hour holds at most. Threads count apart and one name may take an entry in several of
/// them, so there is twice the room
const QUERY_STATS_DOMAIN_CAP: usize = 8_192;
const QUERY_STATS_CLIENT_CAP: usize = 2_048;

thread_local! {
    /// 拼统计键的缓冲，每个线程一份、反复使用：已有的统计项按它直接查到，计数时不再为键分配内存
    /// The buffer metric keys are built in, one per thread and reused: an existing series is found
    /// by it directly, so counting allocates nothing for the key
    static METRIC_KEY: RefCell<String> = RefCell::new(String::with_capacity(MAX_METRIC_KEY_BYTES));
}

/// 在线程的缓冲里拼一个统计键，交给 `use_key`。缓冲正被占用时（不会发生，`use_key` 里不再拼键）
/// 退回一个临时字符串，不会因此出错
/// Builds a metric key in the thread's buffer and hands it to `use_key`. Should the buffer be in
/// use (it never is: `use_key` builds no key of its own) a temporary string is used instead, so
/// this cannot fail
fn with_metric_key<R>(build: impl FnOnce(&mut String), use_key: impl FnOnce(&str) -> R) -> R {
    METRIC_KEY.with(|cell| match cell.try_borrow_mut() {
        Ok(mut buffer) => {
            buffer.clear();
            build(&mut buffer);
            use_key(&buffer)
        }
        Err(_) => {
            let mut buffer = String::new();
            build(&mut buffer);
            use_key(&buffer)
        }
    })
}

/// 统计键的各段用 `\0` 隔开 / The parts of a metric key are separated by `\0`
fn push_key_parts(buffer: &mut String, parts: &[&str]) {
    for (index, part) in parts.iter().enumerate() {
        if index > 0 {
            buffer.push('\0');
        }
        buffer.push_str(part);
    }
}

#[derive(Clone, Default)]
struct ActiveConfig {
    generation: u64,
    sha256: String,
    loaded_at_unix: u64,
    last_reload_success: bool,
    last_reload_error: Option<String>,
    /// 当前配置改了、但要重启才生效的设置（见 `ConfigLoaded::restart_pending`）
    /// Settings the current configuration changes that take a restart to apply (see
    /// `ConfigLoaded::restart_pending`)
    restart_pending: Vec<String>,
}

/// 一个线程记下的一格 / What one thread has counted in a bucket
#[derive(Default)]
struct StatsShard {
    requests: u64,
    dropped_updates: u64,
    domains: HashMap<Arc<str>, u64>,
    clients: HashMap<IpAddr, u64>,
}

/// 一个钟头的排行。每个线程记自己那一份，读的时候合起来：每个查询都要记，放在一张表上就是所有核轮流抢它的锁和计数。
/// 只有新来一项才碰共用的条数
/// One hour of rankings. Each thread counts in its own share and reading merges them: every query is
/// counted, and on one table all cores would take turns fighting over its locks and counts. Only a new entry
/// touches the shared numbers of entries
struct QueryStatsBucket {
    epoch: AtomicU64,
    domain_entries: AtomicUsize,
    client_entries: AtomicUsize,
    rotate_lock: Mutex<()>,
    shards: Box<[OwnLines<Mutex<StatsShard>>]>,
}

impl QueryStatsBucket {
    fn new() -> Self {
        Self {
            epoch: AtomicU64::new(0),
            domain_entries: AtomicUsize::new(0),
            client_entries: AtomicUsize::new(0),
            rotate_lock: Mutex::new(()),
            shards: (0..COUNT_CELLS).map(|_| OwnLines::default()).collect(),
        }
    }

    /// 让这一格准备好记 `epoch` 那个钟头。别的线程正在换的话就等它换完：这个查询要记进新的钟头，不能丢
    /// Readies this bucket for the hour `epoch`. If another thread is changing it over this waits for that:
    /// the query belongs in the new hour and must not be lost
    fn prepare(&self, epoch: u64) {
        if self.epoch.load(Ordering::Acquire) == epoch {
            return;
        }
        let guard = self.rotate_lock.lock();
        if self.epoch.load(Ordering::Relaxed) != epoch {
            self.reset(guard, epoch);
        }
    }

    #[cfg_attr(not(unix), allow(dead_code))]
    fn clear(&self) {
        self.reset(self.rotate_lock.lock(), 0);
    }

    /// 清空这一格、换成 `epoch` 那个钟头。锁里只把旧内容取走，放开锁再释放：一张满的表要释放几百微秒，等着的线程不用陪它
    /// Empties this bucket for the hour `epoch`. Under the lock the old contents are only taken out, and they
    /// are freed once it is released: a full table takes some hundreds of microseconds to free, which the
    /// threads waiting need not sit through
    fn reset(&self, guard: MutexGuard<'_, ()>, epoch: u64) {
        let old = self
            .shards
            .iter()
            .map(|shard| std::mem::take(&mut *shard.lock()))
            .collect::<Vec<_>>();
        self.domain_entries.store(0, Ordering::Relaxed);
        self.client_entries.store(0, Ordering::Relaxed);
        self.epoch.store(epoch, Ordering::Release);
        drop(guard);
        drop(old);
    }

    /// 这个线程记一次 / This thread counts one query
    fn record(&self, domain: &str, client: IpAddr) {
        let mut shard = self.shards[thread_cell()].lock();
        let shard = &mut *shard;
        shard.requests += 1;
        let domain_recorded = record_capped(
            &mut shard.domains,
            &self.domain_entries,
            QUERY_STATS_DOMAIN_CAP,
            domain,
            || Arc::from(domain),
        );
        let client_recorded = record_capped(
            &mut shard.clients,
            &self.client_entries,
            QUERY_STATS_CLIENT_CAP,
            &client,
            || client,
        );
        if !domain_recorded || !client_recorded {
            shard.dropped_updates += 1;
        }
    }
}

/// 给 `map` 里的 `key` 记一次；没有这一项时新建，`entries` 记着各线程一共有几项，到了 `cap` 就不再新建，返回 false
/// Counts `key` once in `map`, adding it when absent; `entries` holds how many all threads have together,
/// and none is added once it reaches `cap`, which gives false
fn record_capped<K, Q>(
    map: &mut HashMap<K, u64>,
    entries: &AtomicUsize,
    cap: usize,
    key: &Q,
    owned: impl FnOnce() -> K,
) -> bool
where
    K: std::borrow::Borrow<Q> + Eq + std::hash::Hash,
    Q: Eq + std::hash::Hash + ?Sized,
{
    if let Some(count) = map.get_mut(key) {
        *count += 1;
        return true;
    }
    // 满了就不再为新的一项分配：随机子域名一多，这条路每个查询都会走
    // Full: no allocation for a new entry, a path every query takes once random subdomains pour in
    if entries.load(Ordering::Relaxed) >= cap {
        return false;
    }
    if entries.fetch_add(1, Ordering::Relaxed) >= cap {
        entries.fetch_sub(1, Ordering::Relaxed);
        return false;
    }
    map.insert(owned(), 1);
    true
}

/// 查询排行：开了控制通道就一直统计，客户端地址照原样记。配置里的 `statistics_enabled` 和
/// `statistics_anonymize_client_ip` 还能读，但不再起作用。
/// Query rankings: always collected while the control socket is open, with client
/// addresses as they are. The config's `statistics_enabled` and
/// `statistics_anonymize_client_ip` still load but no longer do anything.
struct QueryStats {
    buckets: Box<[QueryStatsBucket]>,
    wall: WallClock,
}

impl Default for QueryStats {
    fn default() -> Self {
        Self {
            buckets: (0..QUERY_STATS_BUCKETS)
                .map(|_| QueryStatsBucket::new())
                .collect(),
            wall: WallClock::default(),
        }
    }
}

#[cfg_attr(not(unix), allow(dead_code))]
struct TopStat {
    name: String,
    count: u64,
}

/// 把一格里 `counts` 的每一项加进 `totals` / Adds each entry of one bucket's `counts` into `totals`
#[cfg_attr(not(unix), allow(dead_code))]
fn add_counts<K: Clone + Eq + std::hash::Hash>(
    totals: &mut HashMap<K, u64>,
    counts: &HashMap<K, u64>,
) {
    for (key, count) in counts {
        let total = totals.entry(key.clone()).or_default();
        *total = total.saturating_add(*count);
    }
}

/// `totals` 里排在前 `limit` 的几项 / The top `limit` entries of `totals`
#[cfg_attr(not(unix), allow(dead_code))]
fn top<K: std::fmt::Display>(totals: HashMap<K, u64>, limit: usize) -> Vec<TopStat> {
    let mut rows = totals
        .into_iter()
        .map(|(key, count)| TopStat {
            name: key.to_string(),
            count,
        })
        .collect::<Vec<_>>();
    sort_and_truncate(&mut rows, limit);
    rows
}

#[cfg_attr(not(unix), allow(dead_code))]
struct QueryStatsSnapshot {
    requests_observed: u64,
    dropped_updates: u64,
    clients: Vec<TopStat>,
    domains: Vec<TopStat>,
}

impl QueryStats {
    #[cfg_attr(not(unix), allow(dead_code))]
    fn clear(&self) {
        for bucket in &self.buckets {
            bucket.clear();
        }
    }

    #[inline]
    fn record(&self, domain: &str, client: IpAddr, at: Instant) {
        self.record_at(domain, client, self.wall.unix_ms_at(at) / 1_000);
    }

    fn record_at(&self, domain: &str, client: IpAddr, now: u64) {
        let epoch = now - now % QUERY_STATS_BUCKET_SECONDS;
        let index = (epoch / QUERY_STATS_BUCKET_SECONDS) as usize % QUERY_STATS_BUCKETS;
        let bucket = &self.buckets[index];
        bucket.prepare(epoch);
        bucket.record(domain, client);
    }

    #[cfg_attr(not(unix), allow(dead_code))]
    fn snapshot(&self, now: u64, window_seconds: u64, limit: usize) -> QueryStatsSnapshot {
        let oldest = now.saturating_sub(window_seconds);
        let mut requests_observed = 0u64;
        let mut dropped_updates = 0u64;
        let mut domains = HashMap::<Arc<str>, u64>::new();
        let mut clients = HashMap::<IpAddr, u64>::new();
        for bucket in &self.buckets {
            let epoch = bucket.epoch.load(Ordering::Acquire);
            if epoch == 0
                || epoch > now
                || epoch.saturating_add(QUERY_STATS_BUCKET_SECONDS) <= oldest
            {
                continue;
            }
            for shard in &bucket.shards {
                let shard = shard.lock();
                requests_observed = requests_observed.saturating_add(shard.requests);
                dropped_updates = dropped_updates.saturating_add(shard.dropped_updates);
                add_counts(&mut domains, &shard.domains);
                add_counts(&mut clients, &shard.clients);
            }
        }

        QueryStatsSnapshot {
            requests_observed,
            dropped_updates,
            clients: top(clients, limit),
            domains: top(domains, limit),
        }
    }
}

#[cfg_attr(not(unix), allow(dead_code))]
fn sort_and_truncate(rows: &mut Vec<TopStat>, limit: usize) {
    rows.sort_unstable_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.name.cmp(&right.name))
    });
    rows.truncate(limit);
}

/// 请求端到端耗时的固定分桶上界（毫秒），最后一档为 +Inf。
const REQUEST_LATENCY_BUCKETS_MS: [u64; 5] = [10, 50, 100, 500, 1_000];

/// 累计耗时与次数，供面板计算平均值。/ Accumulated latency and count for averages.
#[derive(Default)]
struct LatencySum {
    micros: AtomicU64,
    count: AtomicU64,
}

impl LatencySum {
    #[inline]
    fn add(&self, latency: std::time::Duration) {
        let micros = u64::try_from(latency.as_micros()).unwrap_or(u64::MAX);
        self.micros.fetch_add(micros, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }
}

/// [`ThreadCount`] 分成几格，线程比这多时共用，照样数得对 / How many cells a [`ThreadCount`] has; threads
/// beyond that share one and the count stays right
const COUNT_CELLS: usize = 16;

static NEXT_COUNT_CELL: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    /// 这个线程写哪一格 / The cell this thread writes
    static COUNT_CELL: usize = NEXT_COUNT_CELL.fetch_add(1, Ordering::Relaxed) % COUNT_CELLS;
}

fn thread_cell() -> usize {
    COUNT_CELL.with(|cell| *cell)
}

/// 每个查询都要记的数：线程写自己那一格，读的时候加起来。放在一个数上，就是所有核轮流抢同一块内存
/// A number counted for every query: a thread writes its own cell, and reading adds them up. As one number
/// it would be a piece of memory all cores take turns fighting over
#[derive(Default)]
struct ThreadCount([OwnLines<AtomicU64>; COUNT_CELLS]);

impl ThreadCount {
    #[inline]
    fn fetch_add(&self, value: u64, order: Ordering) {
        self.0[thread_cell()].fetch_add(value, order);
    }

    fn load(&self, order: Ordering) -> u64 {
        self.0
            .iter()
            .fold(0, |total, cell| total.wrapping_add(cell.load(order)))
    }
}

/// 请求耗时直方图：固定分桶，零分配。/ Request latency histogram with fixed buckets.
#[derive(Default)]
struct RequestLatency {
    micros: ThreadCount,
    count: ThreadCount,
    buckets: [ThreadCount; REQUEST_LATENCY_BUCKETS_MS.len() + 1],
}

impl RequestLatency {
    #[inline]
    fn observe(&self, latency: std::time::Duration) {
        let micros = u64::try_from(latency.as_micros()).unwrap_or(u64::MAX);
        self.micros.fetch_add(micros, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
        let millis = u64::try_from(latency.as_millis()).unwrap_or(u64::MAX);
        let index = REQUEST_LATENCY_BUCKETS_MS
            .iter()
            .position(|bound| millis <= *bound)
            .unwrap_or(REQUEST_LATENCY_BUCKETS_MS.len());
        self.buckets[index].fetch_add(1, Ordering::Relaxed);
    }
}

/// 按名字分的一组统计项（每个 Pipeline、规则、上游各一项）。键只由配置里的名字、固定标签和上游回的
/// 响应码拼成，不来自客户端，所以用快的 FxHash 也没人能凑出冲突。计数只读表、不加锁；头一次出现的统计项
/// 才在 `metric_series_insert_lock` 里复制整张表、加上自己再换上去。表里存的是 `Arc`，经旧表和新表计的
/// 是同一个数。
/// Series keyed by name (one per pipeline, rule or upstream). Keys are made only of names in the
/// config, fixed labels and the response codes upstreams return, never of anything a client sends, so
/// the fast FxHash leaves nobody a way to force collisions.
/// Counting only reads the table and takes no lock; a series seen for the first time copies the table
/// under `metric_series_insert_lock`, adds itself and swaps the copy in. The table holds `Arc`s, so
/// counts made through the old table and the new one land on the same value.
struct Series<V> {
    table: ArcSwap<FxHashMap<Arc<str>, Arc<V>>>,
}

impl<V> Default for Series<V> {
    fn default() -> Self {
        Self {
            table: ArcSwap::from_pointee(FxHashMap::default()),
        }
    }
}

impl<V> Series<V> {
    /// 把 `key` 那一项交给 `read`；没有这一项时为 None / Hands the series under `key` to `read`; None
    /// when there is none
    #[inline]
    fn with<R>(&self, key: &str, read: impl FnOnce(&V) -> R) -> Option<R> {
        self.table.load().get(key).map(|value| read(value))
    }

    fn len(&self) -> usize {
        self.table.load().len()
    }

    /// 此刻的整张表，导出时用 / The whole table as it is now, for export
    fn snapshot(&self) -> Arc<FxHashMap<Arc<str>, Arc<V>>> {
        self.table.load_full()
    }

    /// 加上一项。`_locked` 是 `metric_series_insert_lock` 的锁：两个新项不会各拿一份旧表、互相覆盖
    /// Adds a series. `_locked` is the guard of `metric_series_insert_lock`: two new series never each
    /// copy the old table and overwrite each other
    fn insert(&self, _locked: &MutexGuard<'_, ()>, key: &str, value: V) {
        let mut table = (**self.table.load()).clone();
        table.insert(Arc::from(key), Arc::new(value));
        self.table.store(Arc::new(table));
    }
}

/// 同时在跟的请求按编号直接定位的槽位数，2 的幂 / Slots the running requests are placed in by number, a
/// power of two
const LOOKUP_SLOTS: usize = 4_096;

/// 已经计过一次缓存查找、还没结束的请求。请求跳转后会在目标 pipeline 下再查一次，而命中率按请求算
/// （一个请求最多命中一次），所以每个请求只计一次查找。请求编号直接定位一个槽位，里面存「编号 + 1」
/// （0 表示空），请求结束时清掉；槽位正被另一个还没结束的请求占着时（同时在处理的请求要多过槽位数），
/// 这个请求改记在共享表里。一个请求的几次查找前后相继、不会同时发生，查它在不在共享表里的也只有它自己。
/// Requests still running whose cache lookup is already counted. A request looks again under the
/// target pipeline after a jump, while the hit rate is per request (a request hits at most once), so
/// each request counts one lookup. The request number picks a slot directly, which holds the number
/// plus one (0 is empty) and is cleared when the request finishes; when another running request holds
/// that slot (more requests are in progress than there are slots), the request is noted in a shared
/// map instead. One request's lookups follow one another and never overlap, and only the request
/// itself asks whether it is in the shared map.
struct LookupsCounted {
    slots: Box<[AtomicU64]>,
    overflow: DashMap<u64, ()>,
    /// `overflow` 里有几条：为 0 时不碰共享表 / How many requests `overflow` holds: at 0 the map is not
    /// touched
    overflow_len: AtomicUsize,
}

impl Default for LookupsCounted {
    fn default() -> Self {
        Self::with_slots(LOOKUP_SLOTS)
    }
}

impl LookupsCounted {
    fn with_slots(slots: usize) -> Self {
        assert!(slots.is_power_of_two(), "the slot count is a power of two");
        Self {
            slots: (0..slots).map(|_| AtomicU64::new(0)).collect(),
            overflow: DashMap::new(),
            overflow_len: AtomicUsize::new(0),
        }
    }

    #[inline]
    fn slot(&self, request_id: u64) -> &AtomicU64 {
        &self.slots[request_id as usize & (self.slots.len() - 1)]
    }

    /// `request_id` 第一次查缓存时为真 / True on `request_id`'s first cache lookup
    #[inline]
    fn first(&self, request_id: u64) -> bool {
        let mark = request_id.wrapping_add(1);
        let slot = self.slot(request_id);
        let held = slot.load(Ordering::Relaxed);
        if held == mark {
            return false;
        }
        if self.overflow_len.load(Ordering::Relaxed) > 0 && self.overflow.contains_key(&request_id)
        {
            return false;
        }
        if held == 0
            && slot
                .compare_exchange(0, mark, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            return true;
        }
        self.overflow.insert(request_id, ());
        self.overflow_len.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// `request_id` 结束了 / `request_id` finished
    #[inline]
    fn finished(&self, request_id: u64) {
        let mark = request_id.wrapping_add(1);
        if self
            .slot(request_id)
            .compare_exchange(mark, 0, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return;
        }
        if self.overflow_len.load(Ordering::Relaxed) > 0
            && self.overflow.remove(&request_id).is_some()
        {
            self.overflow_len.fetch_sub(1, Ordering::Relaxed);
        }
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.slots
            .iter()
            .all(|slot| slot.load(Ordering::Relaxed) == 0)
            && self.overflow.is_empty()
            && self.overflow_len.load(Ordering::Relaxed) == 0
    }
}

pub struct PanelMetrics {
    #[cfg_attr(not(unix), allow(dead_code))]
    started_at_unix: u64,
    #[cfg_attr(not(unix), allow(dead_code))]
    started_at: Instant,
    requests_total: ThreadCount,
    requests_inflight: AtomicUsize,
    cache_lookups_total: ThreadCount,
    /// 每个请求只计一次缓存查找（见 `LookupsCounted`） / Each request counts one cache lookup (see
    /// `LookupsCounted`)
    cache_lookup_counted: LookupsCounted,
    cache_hits_fresh: ThreadCount,
    cache_hits_stale: AtomicU64,
    cache_stale_client_timeout: AtomicU64,
    cache_stale_upstream_failure: AtomicU64,
    requests_completed: ThreadCount,
    requests_failed: ThreadCount,
    requests_cancelled: ThreadCount,
    request_latency: RequestLatency,
    upstream_latency: Series<LatencySum>,
    /// 只算拿到响应的尝试（成功或被拒绝），超时与连接错误不计入。
    /// Only attempts that received a response (success or rejected); timeouts and
    /// connection errors are left out.
    upstream_response_latency: Series<LatencySum>,
    upstream_rcodes: Series<ThreadCount>,
    upstream_via: Series<ThreadCount>,
    pipeline_hits: Series<ThreadCount>,
    rule_matches: Series<ThreadCount>,
    upstream_attempts: Series<ThreadCount>,
    upstream_results: Series<ThreadCount>,
    metric_series_insert_lock: Mutex<()>,
    metric_series_dropped: AtomicU64,
    reload_success: AtomicU64,
    reload_failure: AtomicU64,
    reload_sequence: AtomicU64,
    active_config: RwLock<ActiveConfig>,
    query_stats: QueryStats,
    /// 面板观察者独占了引擎唯一的观察者槽位，所以 `--debug` 的参考观察者只能挂在这里转发；
    /// 否则增强版的 `--debug` 永远看不到 `kixdns::observe` 事件。
    /// The panel observer owns the engine's single observer slot, so the `--debug`
    /// reference observer can only live here and be forwarded to; otherwise the
    /// enhanced build's `--debug` never shows `kixdns::observe` events.
    debug_trace: Option<TracingObserver>,
    /// 查询日志的交接区：面板来取时才记 / The query log's hand-off ring: records only while the
    /// panel collects
    query_log: QueryLog,
}

impl Default for PanelMetrics {
    fn default() -> Self {
        Self {
            started_at_unix: unix_timestamp(),
            started_at: Instant::now(),
            requests_total: ThreadCount::default(),
            requests_inflight: AtomicUsize::new(0),
            cache_lookups_total: ThreadCount::default(),
            cache_lookup_counted: LookupsCounted::default(),
            cache_hits_fresh: ThreadCount::default(),
            cache_hits_stale: AtomicU64::new(0),
            cache_stale_client_timeout: AtomicU64::new(0),
            cache_stale_upstream_failure: AtomicU64::new(0),
            requests_completed: ThreadCount::default(),
            requests_failed: ThreadCount::default(),
            requests_cancelled: ThreadCount::default(),
            request_latency: RequestLatency::default(),
            upstream_latency: Series::default(),
            upstream_response_latency: Series::default(),
            upstream_rcodes: Series::default(),
            upstream_via: Series::default(),
            pipeline_hits: Series::default(),
            rule_matches: Series::default(),
            upstream_attempts: Series::default(),
            upstream_results: Series::default(),
            metric_series_insert_lock: Mutex::new(()),
            metric_series_dropped: AtomicU64::new(0),
            reload_success: AtomicU64::new(0),
            reload_failure: AtomicU64::new(0),
            reload_sequence: AtomicU64::new(0),
            active_config: RwLock::new(ActiveConfig::default()),
            query_stats: QueryStats::default(),
            debug_trace: None,
            query_log: QueryLog::default(),
        }
    }
}

impl PanelMetrics {
    /// `debug` 对应命令行的 `--debug`：为真时每个引擎事件同时进入上游的 `TracingObserver`。
    /// `debug` mirrors the `--debug` flag: when set, every engine event also reaches
    /// upstream's `TracingObserver`.
    pub fn new(debug: bool) -> Self {
        Self {
            debug_trace: debug.then_some(TracingObserver),
            ..Self::default()
        }
    }

    #[cfg_attr(not(unix), allow(dead_code))]
    #[inline]
    fn uptime_seconds(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    #[inline]
    fn record_query(&self, domain: &str, client: IpAddr, at: Instant) {
        self.query_stats.record(domain, client, at);
    }

    #[inline]
    fn record_cache_lookup(&self) {
        self.cache_lookups_total.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn record_cache_hit(&self, kind: CacheHitKind) {
        match kind {
            CacheHitKind::Fresh => {
                self.cache_hits_fresh.fetch_add(1, Ordering::Relaxed);
                return;
            }
            CacheHitKind::StaleClientTimeout => {
                self.cache_stale_client_timeout
                    .fetch_add(1, Ordering::Relaxed);
            }
            CacheHitKind::StaleUpstreamFailure => {
                self.cache_stale_upstream_failure
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
        self.cache_hits_stale.fetch_add(1, Ordering::Relaxed);
    }

    /// 累计一次上游耗时；序列数量与键长度受同一上限约束。
    fn record_upstream_latency(
        &self,
        series: &Series<LatencySum>,
        key: &str,
        latency: std::time::Duration,
    ) {
        self.update_series(series, key, |sum| sum.add(latency));
    }

    /// 一个请求结束：按结果记一次，算进耗时 / A request ended: counted by how, and its latency added
    #[inline]
    fn count_finished(&self, outcome: &RequestOutcome<'_>) {
        let counter = match outcome.status {
            RequestStatus::Completed => &self.requests_completed,
            RequestStatus::Failed => &self.requests_failed,
            RequestStatus::Cancelled => &self.requests_cancelled,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        self.request_latency.observe(outcome.latency);
    }

    #[inline]
    fn record_pipeline_hit(&self, pipeline: &str) {
        self.increment(&self.pipeline_hits, pipeline);
    }

    #[inline]
    fn record_rule_match(&self, pipeline: &str, rule: &str, phase: &str) {
        with_metric_key(
            |key| push_key_parts(key, &[pipeline, rule, phase]),
            |key| self.increment(&self.rule_matches, key),
        );
    }

    #[inline]
    fn record_upstream_attempt(&self, upstream: &str, transport: &str) {
        with_metric_key(
            |key| push_key_parts(key, &[upstream, transport]),
            |key| self.increment(&self.upstream_attempts, key),
        );
    }

    #[inline]
    fn record_upstream_result(&self, upstream: &str, transport: &str, result: &str) {
        with_metric_key(
            |key| push_key_parts(key, &[upstream, transport, result]),
            |key| self.increment(&self.upstream_results, key),
        );
    }

    /// 一份配置生效了：第一次加载时代数是 1；之后每次重载加一，并在写锁里计一次重载成功、加重载序号
    /// （见 `config_json`）
    /// A configuration became active: generation 1 on the first load; each reload after
    /// that adds one and, under the write lock, counts a reload success and bumps the
    /// reload sequence (see `config_json`)
    fn config_became_active(&self, sha256: String, initial: bool, restart_pending: Vec<String>) {
        let mut active = self.active_config.write();
        active.generation = if initial {
            1
        } else {
            active.generation.saturating_add(1)
        };
        active.sha256 = sha256;
        active.loaded_at_unix = unix_timestamp();
        active.last_reload_success = true;
        active.last_reload_error = None;
        active.restart_pending = restart_pending;
        if !initial {
            self.reload_success.fetch_add(1, Ordering::Relaxed);
            self.reload_sequence.fetch_add(1, Ordering::Release);
        }
    }

    /// 按借来的键计数，只有第一次出现的统计项才分配它的键
    /// Counts by a borrowed key; only a series seen for the first time allocates its key
    #[inline]
    fn increment(&self, series: &Series<ThreadCount>, key: &str) {
        self.update_series(series, key, |counter| {
            counter.fetch_add(1, Ordering::Relaxed);
        });
    }

    /// 把 `key` 那一项交给 `update`。头一次出现的统计项在锁里加上；键太长或这一组已满时不加，只计一次
    /// 丢弃。
    /// Hands the series under `key` to `update`. A series seen for the first time is added under the
    /// lock; a key too long or a full set adds nothing and counts one dropped series.
    #[inline]
    fn update_series<V: Default>(&self, series: &Series<V>, key: &str, update: impl Fn(&V)) {
        if series.with(key, &update).is_some() {
            return;
        }
        // 键太长，或者这一组已经满了：都加不进去，不必拿锁。满了的表不会再变小，而锁是全进程共用的：规则多过上限的
        // 配置下，命中表外规则的每个查询都拿一次的话，几个核就互相等
        // A key too long, or a set already full: neither can be added, so no lock is taken. A
        // full table never shrinks, and the lock is shared by the whole process: with more rules
        // than the limit, every query matching a rule outside the table taking it would have the
        // cores wait on one another
        if key.len() > MAX_METRIC_KEY_BYTES || series.len() >= MAX_METRIC_SERIES_PER_MAP {
            self.metric_series_dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let locked = self.metric_series_insert_lock.lock();
        // 等锁的时候别的线程可能已经加上了 / Another thread may have added it while this one waited
        if series.with(key, &update).is_some() {
            return;
        }
        if series.len() >= MAX_METRIC_SERIES_PER_MAP {
            self.metric_series_dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let value = V::default();
        update(&value);
        series.insert(&locked, key, value);
    }

    fn record_reload_failure(&self, error: &str) {
        let mut active = self.active_config.write();
        active.last_reload_success = false;
        active.last_reload_error = Some(truncate(error, MAX_ERROR_LENGTH));
        self.reload_failure.fetch_add(1, Ordering::Relaxed);
        self.reload_sequence.fetch_add(1, Ordering::Release);
    }

    /// 从观察者收到的配置原文更新摘要。/ Refresh the digest from the loaded source.
    fn record_config_loaded(&self, source: &str, restart_pending: Vec<String>) {
        let sha256 = format!("{:x}", Sha256::digest(source.as_bytes()));
        let initial = self.active_config.read().generation == 0;
        self.config_became_active(sha256, initial, restart_pending);
    }

    #[cfg(unix)]
    fn config_json(&self) -> serde_json::Value {
        // 重载序号和配置状态在同一把锁里读：重载在写锁里改状态、加序号，此前序号在锁外读，可能
        // 拿到新序号配旧状态，而面板正是按序号判断保存是否已经生效的
        // The reload sequence is read under the same lock as the state: a reload changes
        // the state and bumps the sequence under the write lock, and a sequence read
        // outside it could pair a new sequence with the old state, while the panel tells
        // by the sequence whether a save took effect
        let (active, reload_sequence) = {
            let active = self.active_config.read();
            (active.clone(), self.reload_sequence.load(Ordering::Acquire))
        };
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "generation": active.generation,
            "sha256": active.sha256,
            "loaded_at_unix": active.loaded_at_unix,
            "reload_sequence": reload_sequence,
            "last_reload": {
                "success": active.last_reload_success,
                "error": active.last_reload_error,
            },
            "restart_pending": active.restart_pending,
        })
    }

    #[cfg(unix)]
    fn health_json(&self) -> serde_json::Value {
        let active = self.active_config.read();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "status": "ok",
            "pid": std::process::id(),
            "version": env!("CARGO_PKG_VERSION"),
            // 发布流程编译时写进的身份：日期版本和这一版的提交。本地构建没有，报 null。
            // The identity the release workflow compiles in: the date version and the
            // commit of the release. A local build has neither and reports null.
            "release_version": option_env!("KIXDNS_RELEASE_VERSION"),
            "release_commit": option_env!("KIXDNS_RELEASE_COMMIT"),
            "upstream_commit": option_env!("KIXDNS_UPSTREAM_COMMIT").unwrap_or("unknown"),
            "patchset": option_env!("KIXDNS_PANEL_PATCHSET").unwrap_or("unknown"),
            "started_at_unix": self.started_at_unix,
            "uptime_seconds": self.uptime_seconds(),
            "config_generation": active.generation,
            "capabilities": [
                "stats_top_v1",
                "config_query_stats_v1",
                "diagnostics_trace_v1",
                "diagnostics_trace_client_v1",
                "diagnostics_trace_candidate_v1",
                "config_static_cname_response_v1",
                "metrics_upstream_precision_v1",
                "metrics_upstream_response_latency_v1",
                "querylog_v1",
                "querylog_wait_v1",
                "querylog_stored_v1",
                "querylog_until_v1",
                "querylog_records_v1"
            ],
        })
    }

    #[cfg(unix)]
    fn stats_json(&self, window_seconds: u64, limit: usize) -> serde_json::Value {
        let now = unix_timestamp();
        let snapshot = self.query_stats.snapshot(now, window_seconds, limit);
        let rows = |rows: Vec<TopStat>| {
            rows.into_iter()
                .map(|row| json!({"name": row.name, "count": row.count}))
                .collect::<Vec<_>>()
        };
        // The two fields stay for panels that read them: on whenever the control socket is
        // open, never anonymized / 这两个字段留给读它们的面板：开了控制通道就开着，从不脱敏
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "enabled": true,
            "anonymized_clients": false,
            "window_seconds": window_seconds,
            "retention_seconds": QUERY_STATS_BUCKET_SECONDS * QUERY_STATS_BUCKETS as u64,
            "generated_at_unix": now,
            "requests_observed": snapshot.requests_observed,
            "dropped_updates": snapshot.dropped_updates,
            "clients": rows(snapshot.clients),
            "domains": rows(snapshot.domains),
        })
    }

    #[cfg(unix)]
    fn clear_stats(&self) {
        self.query_stats.clear();
    }

    #[cfg(unix)]
    fn render_prometheus(&self, engine: &Engine) -> String {
        let mut output = String::with_capacity(8_192);
        // In the unit of `cache_capacity`, not slots: one question can hold answers for several
        // ECS networks, and an answer over 1 KB counts once per KB
        // 和 `cache_capacity` 同一个单位，而不是槽位数：一个问题可以存多个 ECS 网段的应答，超过 1 KB
        // 的应答每 1 KB 算一份
        metric(
            &mut output,
            "kixdns_cache_entries",
            engine.cache.weighted_size(),
        );
        self.render_counters(&mut output);
        output
    }

    /// 输出不依赖引擎状态的全部序列。/ Render every series that needs no engine state.
    fn render_counters(&self, output: &mut String) {
        metric(
            output,
            "kixdns_requests_total",
            self.requests_total.load(Ordering::Relaxed),
        );
        metric(
            output,
            "kixdns_requests_inflight",
            self.requests_inflight.load(Ordering::Relaxed),
        );
        metric(
            output,
            "kixdns_cache_lookups_total",
            self.cache_lookups_total.load(Ordering::Relaxed),
        );
        labeled_metric(
            output,
            "kixdns_cache_hits_total",
            &[("kind", "fresh")],
            self.cache_hits_fresh.load(Ordering::Relaxed),
        );
        labeled_metric(
            output,
            "kixdns_cache_hits_total",
            &[("kind", "stale")],
            self.cache_hits_stale.load(Ordering::Relaxed),
        );
        append_map(
            output,
            "kixdns_pipeline_hits_total",
            &self.pipeline_hits,
            &["pipeline"],
        );
        append_map(
            output,
            "kixdns_rule_matches_total",
            &self.rule_matches,
            &["pipeline", "rule", "phase"],
        );
        append_map(
            output,
            "kixdns_upstream_attempts_total",
            &self.upstream_attempts,
            &["upstream", "transport"],
        );
        append_map(
            output,
            "kixdns_upstream_results_total",
            &self.upstream_results,
            &["upstream", "transport", "result"],
        );
        labeled_metric(
            output,
            "kixdns_config_reload_total",
            &[("result", "success")],
            self.reload_success.load(Ordering::Relaxed),
        );
        labeled_metric(
            output,
            "kixdns_config_reload_total",
            &[("result", "failure")],
            self.reload_failure.load(Ordering::Relaxed),
        );
        metric(
            output,
            "kixdns_config_generation",
            self.active_config.read().generation,
        );
        labeled_metric(
            output,
            "kixdns_cache_stale_total",
            &[("reason", "expired")],
            self.cache_hits_stale
                .load(Ordering::Relaxed)
                .saturating_sub(self.cache_stale_client_timeout.load(Ordering::Relaxed))
                .saturating_sub(self.cache_stale_upstream_failure.load(Ordering::Relaxed)),
        );
        labeled_metric(
            output,
            "kixdns_cache_stale_total",
            &[("reason", "client_timeout")],
            self.cache_stale_client_timeout.load(Ordering::Relaxed),
        );
        labeled_metric(
            output,
            "kixdns_cache_stale_total",
            &[("reason", "upstream_failure")],
            self.cache_stale_upstream_failure.load(Ordering::Relaxed),
        );
        for (status, counter) in [
            ("completed", &self.requests_completed),
            ("failed", &self.requests_failed),
            ("cancelled", &self.requests_cancelled),
        ] {
            labeled_metric(
                output,
                "kixdns_requests_finished_total",
                &[("status", status)],
                counter.load(Ordering::Relaxed),
            );
        }
        let mut cumulative = 0u64;
        for (index, bound) in REQUEST_LATENCY_BUCKETS_MS.iter().enumerate() {
            cumulative += self.request_latency.buckets[index].load(Ordering::Relaxed);
            labeled_metric(
                output,
                "kixdns_request_latency_ms_bucket",
                &[("le", &bound.to_string())],
                cumulative,
            );
        }
        cumulative +=
            self.request_latency.buckets[REQUEST_LATENCY_BUCKETS_MS.len()].load(Ordering::Relaxed);
        labeled_metric(
            output,
            "kixdns_request_latency_ms_bucket",
            &[("le", "+Inf")],
            cumulative,
        );
        metric(
            output,
            "kixdns_request_latency_ms_sum",
            format_millis(self.request_latency.micros.load(Ordering::Relaxed)),
        );
        metric(
            output,
            "kixdns_request_latency_ms_count",
            self.request_latency.count.load(Ordering::Relaxed),
        );
        append_latency_map(
            output,
            "kixdns_upstream_latency_ms",
            &self.upstream_latency,
            &["upstream", "transport"],
        );
        append_latency_map(
            output,
            "kixdns_upstream_response_latency_ms",
            &self.upstream_response_latency,
            &["upstream", "transport"],
        );
        append_map(
            output,
            "kixdns_upstream_rcodes_total",
            &self.upstream_rcodes,
            &["upstream", "rcode"],
        );
        append_map(
            output,
            "kixdns_upstream_via_total",
            &self.upstream_via,
            &["upstream", "transport", "via"],
        );
        metric(
            output,
            "kixdns_panel_metric_series_dropped_total",
            self.metric_series_dropped.load(Ordering::Relaxed),
        );
    }
}

pub(crate) fn transport_label(transport: crate::config::Transport) -> &'static str {
    use crate::config::Transport;
    match transport {
        Transport::Udp => "udp",
        Transport::Tcp => "tcp",
        Transport::TcpUdp => "tcp_udp",
        Transport::Doh => "doh",
        Transport::Dot => "dot",
        Transport::Doq => "doq",
    }
}

/// 上游一次尝试的结果，写成面板认得的短名 / An upstream attempt's outcome in the short name the panel reads
pub(crate) fn outcome_label(outcome: UpstreamOutcome) -> &'static str {
    match outcome {
        UpstreamOutcome::Success => "success",
        UpstreamOutcome::Rejected => "rejected",
        UpstreamOutcome::Error => "error",
        UpstreamOutcome::Aborted => "aborted",
        UpstreamOutcome::Throttled => "throttled",
    }
}

/// 上游这次没问的原因，写成面板认得的短名 / Why an upstream was not asked, in the short name
/// the panel reads
pub(crate) fn skip_reason_label(reason: UpstreamSkipReason) -> &'static str {
    match reason {
        UpstreamSkipReason::Throttled => "throttled",
    }
}

/// 规则匹配的阶段，写成面板认得的短名 / A rule's matching phase in the short name the panel reads
pub(crate) fn phase_label(phase: RulePhase) -> &'static str {
    match phase {
        RulePhase::Request => "request",
        RulePhase::Response => "response",
    }
}

/// `--debug` 时把事件也交给 [`TracingObserver`] / With `--debug`, the event goes to the [`TracingObserver`] too
macro_rules! debug_forward {
    ($panel:ident.$event:ident($($arg:expr),*)) => {
        if let Some(trace) = &$panel.debug_trace {
            trace.$event($($arg),*);
        }
    };
}

impl EngineObserver for PanelMetrics {
    /// 和分开的事件记下一样的东西，只是一次记完。诊断查询和调试跟踪要一步步看，照旧走分开的事件
    /// Records what the separate events record, all at once. Diagnostic queries and the debug trace
    /// want every step, and take the separate events as ever
    fn answered_from_cache(
        &self,
        ctx: &RequestContext<'_>,
        pipeline: &str,
        hit: &CacheHit<'_>,
        outcome: &RequestOutcome<'_>,
    ) -> bool {
        if self.debug_trace.is_some() || panel_trace::active() {
            return false;
        }
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        self.record_query(ctx.qname, ctx.client.ip(), ctx.started);
        self.record_pipeline_hit(pipeline);
        self.record_cache_lookup();
        self.record_cache_hit(hit.kind);
        self.count_finished(outcome);
        self.query_log
            .answered_from_cache(ctx, pipeline, hit, outcome);
        true
    }

    /// 同 [`Self::answered_from_cache`]。命中的规则多到一条记录放不下的，照旧走分开的事件
    /// As [`Self::answered_from_cache`]. With more matched rules than a record has room for, the separate
    /// events go on as ever
    fn answered_by_rule(
        &self,
        ctx: &RequestContext<'_>,
        pipeline: &str,
        answer: &RuleAnswer<'_>,
        outcome: &RequestOutcome<'_>,
    ) -> bool {
        if self.debug_trace.is_some()
            || panel_trace::active()
            || !panel_querylog::fits_a_record(answer.rules.len())
        {
            return false;
        }
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        self.record_query(ctx.qname, ctx.client.ip(), ctx.started);
        self.record_pipeline_hit(pipeline);
        self.record_cache_lookup();
        for rule in answer.rules {
            self.record_rule_match(pipeline, rule, phase_label(RulePhase::Request));
        }
        self.count_finished(outcome);
        self.query_log
            .answered_by_rule(ctx, pipeline, answer, outcome);
        true
    }

    fn request_started(&self, ctx: &RequestContext<'_>) {
        debug_forward!(self.request_started(ctx));
        if !ctx.background_refresh {
            self.requests_total.fetch_add(1, Ordering::Relaxed);
            self.requests_inflight.fetch_add(1, Ordering::Relaxed);
            // 诊断查询照常计入请求指标，但不进查询排行：测试用的域名和指定的客户端 IP 不是真实流量
            // Diagnostic queries count toward request metrics but stay out of the query ranking:
            // test domains and an assigned client IP are not real traffic
            if !panel_trace::active() {
                self.record_query(ctx.qname, ctx.client.ip(), ctx.started);
            }
        }
        self.query_log.request_started(ctx, panel_trace::active());
        panel_trace::trace_step!(
            "request",
            "parsed",
            format!("{} {}", ctx.qtype, ctx.qname),
            Some(format!(
                "客户端：{}；监听器：{}",
                ctx.client.ip(),
                ctx.listener_label
            )),
        );
    }

    fn request_finished(&self, ctx: &RequestContext<'_>, outcome: &RequestOutcome) {
        debug_forward!(self.request_finished(ctx, outcome));
        self.query_log.request_finished(ctx, outcome);
        if ctx.background_refresh {
            return;
        }
        self.cache_lookup_counted.finished(ctx.request_id);
        self.requests_inflight.fetch_sub(1, Ordering::Relaxed);
        self.count_finished(outcome);
    }

    fn pipeline_selected(&self, ctx: &RequestContext<'_>, pipeline: &str) {
        debug_forward!(self.pipeline_selected(ctx, pipeline));
        if !ctx.background_refresh {
            self.record_pipeline_hit(pipeline);
        }
        self.query_log.pipeline_selected(ctx, pipeline);
        if let Some(previous) = panel_trace::current_pipeline()
            && previous != pipeline
        {
            panel_trace::trace_step!(
                "pipeline",
                "jump",
                format!("{previous} -> {pipeline}"),
                None,
            );
        }
        panel_trace::set_pipeline(pipeline);
        panel_trace::trace_step!("pipeline", "selected", pipeline, None);
    }

    fn rule_matched(&self, ctx: &RequestContext<'_>, event: &RuleMatched<'_>) {
        debug_forward!(self.rule_matched(ctx, event));
        // 规则命中和请求数、pipeline 命中一样只算客户端请求：后台刷新会照规则再走一遍，算进去
        // 命中数就会多于实际的查询，按命中数相减的请求分布也跟着偏
        // Rule matches, like request and pipeline counts, cover client queries only: a background
        // refresh walks the rules again, and counting it would put matches above the actual
        // queries and skew the request breakdown that subtracts them
        if !ctx.background_refresh {
            self.record_rule_match(event.pipeline, event.rule, phase_label(event.phase));
        }
        self.query_log.rule_matched(ctx, event);
    }

    fn rule_evaluated(&self, ctx: &RequestContext<'_>, event: &RuleEvaluated<'_>) {
        debug_forward!(self.rule_evaluated(ctx, event));
        self.query_log.rule_evaluated(ctx, event);
        let status = if event.matched { "matched" } else { "missed" };
        match event.phase {
            RulePhase::Request => panel_trace::trace_step!(
                "rule",
                status,
                event.rule,
                Some(format!(
                    "管线：{}；匹配器数：{}",
                    event.pipeline, event.matchers
                )),
            ),
            _ => panel_trace::trace_step!(
                "response_rule",
                status,
                format!(
                    "响应匹配器 {}",
                    if event.matched { "命中" } else { "未命中" }
                ),
                Some(format!("匹配器数：{}", event.matchers)),
            ),
        }
    }

    fn rule_cache_lookup(&self, ctx: &RequestContext<'_>, event: &RuleCacheLookup<'_>) {
        debug_forward!(self.rule_cache_lookup(ctx, event));
        if event.hit {
            panel_trace::trace_step!(
                "rule_cache",
                "hit",
                format!("命中管线 {} 的规则缓存", event.pipeline),
                Some(format!("已匹配规则：{}", event.matched_rules)),
            );
        } else {
            panel_trace::trace_step!(
                "rule_cache",
                "miss",
                format!("管线 {} 的规则缓存未命中", event.pipeline),
                None,
            );
        }
    }

    fn decision_made(&self, ctx: &RequestContext<'_>, event: &DecisionMade<'_>) {
        debug_forward!(self.decision_made(ctx, event));
        // 诊断的执行路径只写请求阶段的决定：回答后检查的结果已经由响应规则那一步说了
        // The diagnostics trace shows request-phase decisions only: an answer check's
        // outcome is already told by its response-rule step
        if event.phase == RulePhase::Request {
            panel_trace::record_decision(event);
        }
        self.query_log.decision_made(ctx, event);
    }

    fn cache_lookup(&self, ctx: &RequestContext<'_>) {
        debug_forward!(self.cache_lookup(ctx));
        if !ctx.background_refresh && self.cache_lookup_counted.first(ctx.request_id) {
            self.record_cache_lookup();
        }
    }

    fn cache_miss(&self, ctx: &RequestContext<'_>) {
        debug_forward!(self.cache_miss(ctx));
        self.query_log.cache_miss(ctx);
        let pipeline = panel_trace::current_pipeline();
        panel_trace::trace_step!(
            "response_cache",
            "miss",
            "响应缓存未命中",
            pipeline.map(|pipeline| format!("管线：{pipeline}")),
        );
    }

    fn cache_hit(&self, ctx: &RequestContext<'_>, event: &CacheHit) {
        debug_forward!(self.cache_hit(ctx, event));
        self.record_cache_hit(event.kind);
        self.query_log.cache_hit(ctx, event);
        let ttl = |value: Option<std::time::Duration>| value.map(|value| value.as_secs());
        match event.kind {
            CacheHitKind::Fresh => panel_trace::trace_step!(
                "response_cache",
                "fresh",
                "命中新鲜响应缓存",
                ttl(event.remaining_ttl).map(|seconds| format!("剩余 TTL：{seconds} 秒")),
            ),
            CacheHitKind::Stale => panel_trace::trace_step!(
                "response_cache",
                "stale",
                "命中过期响应缓存",
                ttl(event.original_ttl).map(|seconds| format!("原始 TTL：{seconds} 秒")),
            ),
            CacheHitKind::StaleClientTimeout => panel_trace::trace_step!(
                "response_cache",
                "stale",
                "客户端等待超时，返回过期缓存",
                None,
            ),
            _ => {
                panel_trace::trace_step!("response_cache", "stale", "上游失败，返回过期缓存", None)
            }
        }
    }

    fn inflight_joined(&self, ctx: &RequestContext<'_>) {
        debug_forward!(self.inflight_joined(ctx));
        self.query_log.inflight_joined(ctx);
        // 这次请求没有自己去问上游，等的是正在进行的同一个查询：诊断里不然就少了上游这一步
        // This request did not ask upstream itself but waited on the same query already in
        // flight: without this the diagnostics trace would show no upstream step at all
        panel_trace::trace_step!("upstream", "joined", "等候正在进行的同一个查询", None);
    }

    fn upstream_attempt(&self, ctx: &RequestContext<'_>, event: &UpstreamAttempt<'_>) {
        debug_forward!(self.upstream_attempt(ctx, event));
        let transport = transport_label(event.transport);
        self.record_upstream_attempt(event.upstream, transport);
        let (rule, decided_transport) = panel_trace::current_decision();
        panel_trace::trace_step!(
            "upstream",
            "started",
            format!("准备转发到 {}", event.upstream),
            Some(format!(
                "规则：{}；传输：{}",
                rule.as_deref().unwrap_or("default"),
                decided_transport.as_deref().unwrap_or(transport)
            )),
        );
    }

    fn upstream_result(&self, ctx: &RequestContext<'_>, event: &UpstreamResult<'_>) {
        debug_forward!(self.upstream_result(ctx, event));
        let transport = transport_label(event.transport);
        self.record_upstream_result(event.upstream, transport, outcome_label(event.outcome));
        self.query_log.upstream_result(ctx, event);
        // 取消的尝试没有回答；回了 429 的是服务器不肯答，不是 DNS 应答。两种都不计耗时、实际传输和响应码
        // A cancelled attempt has no answer; a 429 is the server declining to answer, not a
        // DNS reply. Neither counts towards latency, the transport used or response codes
        if !matches!(
            event.outcome,
            UpstreamOutcome::Aborted | UpstreamOutcome::Throttled
        ) {
            with_metric_key(
                |key| push_key_parts(key, &[event.upstream, transport]),
                |key| {
                    // 超时会把整段超时时长计入平均耗时；响应耗时只看真正回了包的尝试。
                    // A timeout adds its whole timeout to the average; the response latency
                    // only looks at attempts that actually got a reply.
                    if matches!(
                        event.outcome,
                        UpstreamOutcome::Success | UpstreamOutcome::Rejected
                    ) {
                        self.record_upstream_latency(
                            &self.upstream_response_latency,
                            key,
                            event.latency,
                        );
                    }
                    self.record_upstream_latency(&self.upstream_latency, key, event.latency);
                },
            );
            with_metric_key(
                |key| {
                    push_key_parts(
                        key,
                        &[event.upstream, transport, transport_label(event.via)],
                    )
                },
                |key| self.increment(&self.upstream_via, key),
            );
            if let Some(rcode) = event.rcode {
                with_metric_key(
                    |key| {
                        key.push_str(event.upstream);
                        key.push('\0');
                        let _ = write!(key, "{rcode:?}");
                    },
                    |key| self.increment(&self.upstream_rcodes, key),
                );
            }
        }
        match event.outcome {
            UpstreamOutcome::Success => panel_trace::trace_step!(
                "upstream",
                "succeeded",
                event.upstream,
                Some(format!(
                    "响应码：{}；耗时：{} ms；截断：{}",
                    event
                        .rcode
                        .map_or_else(|| "unknown".to_owned(), |rcode| rcode.to_string()),
                    event.latency.as_millis(),
                    event.truncated.unwrap_or(false)
                )),
            ),
            UpstreamOutcome::Throttled => panel_trace::trace_step!(
                "upstream",
                "throttled",
                event.upstream,
                Some(
                    match event.error.and_then(crate::engine::transport::throttle_of) {
                        Some(throttle) =>
                            format!("HTTP 状态码：429；暂停：{} 秒", throttle.pause.as_secs()),
                        None => "HTTP 状态码：429".to_owned(),
                    }
                ),
            ),
            _ => panel_trace::trace_step!(
                "upstream",
                "failed",
                event.upstream,
                event.error.map(|error| format!("{error:#}")),
            ),
        }
    }

    fn upstream_skipped(&self, ctx: &RequestContext<'_>, event: &UpstreamSkipped<'_>) {
        debug_forward!(self.upstream_skipped(ctx, event));
        // 没问就不是一次尝试，不进任何指标 / Not asked is no attempt, and counts in no metric
        self.query_log.upstream_skipped(ctx, event);
        let why = match event.reason {
            UpstreamSkipReason::Throttled => "正在限速，这次没问它",
        };
        panel_trace::trace_step!("upstream", "skipped", event.upstream, Some(why.to_owned()));
    }

    fn config_loaded(&self, event: &ConfigLoaded<'_>) {
        debug_forward!(self.config_loaded(event));
        let restart_pending = event
            .restart_pending
            .iter()
            .map(|setting| setting.to_string())
            .collect();
        match event.source {
            Some(source) => self.record_config_loaded(source, restart_pending),
            // 没带原文时摘要照旧；第一次加载（代数 1）不算重载
            // Without the text the digest stays; the first load (generation 1) is no reload
            None => {
                let sha256 = self.active_config.read().sha256.clone();
                self.config_became_active(sha256, event.generation <= 1, restart_pending);
            }
        }
    }

    fn config_reload_failed(&self, event: &ConfigReloadFailed<'_>) {
        debug_forward!(self.config_reload_failed(event));
        self.record_reload_failure(event.error);
    }
}

#[cfg(unix)]
pub async fn serve_admin(
    path: PathBuf,
    engine: Engine,
    metrics: Arc<PanelMetrics>,
) -> anyhow::Result<()> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use tokio::net::UnixListener;

    if let Ok(metadata) = std::fs::symlink_metadata(&path) {
        if !metadata.file_type().is_socket() {
            anyhow::bail!("管理 Socket 路径已存在且不是 Socket：{}", path.display());
        }
        std::fs::remove_file(&path).context("删除遗留管理 Socket 失败")?;
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context("创建管理 Socket 目录失败")?;
    }

    let listener = UnixListener::bind(&path).context("绑定管理 Socket 失败")?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660))
        .context("设置管理 Socket 权限失败")?;
    tracing::info!(target = "panel", path = %path.display(), "panel control socket started");

    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(err) => {
                // Never end the loop on an accept error (see accept_retry_delay)
                // 接受出错不退出循环（见 accept_retry_delay）
                tracing::warn!(target = "panel", error = %err, "control socket accept failed, retrying");
                tokio::time::sleep(crate::socket_utils::accept_retry_delay(&err)).await;
                continue;
            }
        };
        let engine = engine.clone();
        let metrics = Arc::clone(&metrics);
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            // hyper 只在装了 timer 时才执行 header_read_timeout（见 doh_server）
            // hyper enforces header_read_timeout only with a timer installed (see doh_server)
            if let Err(error) = hyper::server::conn::http1::Builder::new()
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(REQUEST_READ_TIMEOUT)
                .serve_connection(
                    io,
                    service_fn(move |request| {
                        handle_request(request, engine.clone(), Arc::clone(&metrics))
                    }),
                )
                .await
            {
                tracing::debug!(target = "panel", error = %error, "panel connection closed");
            }
        });
    }
}

#[cfg(not(unix))]
pub async fn trial_from_stdio() -> anyhow::Result<()> {
    anyhow::bail!("当前平台暂不支持草稿试跑")
}

#[cfg(not(unix))]
pub async fn serve_admin(
    _path: PathBuf,
    _engine: Engine,
    _metrics: Arc<PanelMetrics>,
) -> anyhow::Result<()> {
    anyhow::bail!("当前平台暂不支持 Unix Socket 管理接口")
}

#[cfg(unix)]
async fn handle_request(
    request: Request<Incoming>,
    engine: Engine,
    metrics: Arc<PanelMetrics>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let response = match (request.method(), request.uri().path()) {
        (&Method::GET, "/v1/health") => json_response(StatusCode::OK, metrics.health_json()),
        (&Method::GET, "/v1/config/active") => json_response(StatusCode::OK, metrics.config_json()),
        (&Method::GET, "/v1/metrics") => text_response(
            StatusCode::OK,
            "text/plain; version=0.0.4; charset=utf-8",
            metrics.render_prometheus(&engine),
        ),
        (&Method::GET, "/v1/stats/top") => match parse_stats_query(request.uri().query()) {
            Ok((window_seconds, limit)) => stats_response(&metrics, window_seconds, limit).await,
            Err(message) => json_response(
                StatusCode::BAD_REQUEST,
                error_json("stats_query_invalid", message),
            ),
        },
        (&Method::GET, "/v1/querylog") => querylog_response(&metrics, request.uri().query()).await,
        (&Method::POST, "/v1/stats/clear") => {
            metrics.clear_stats();
            json_response(
                StatusCode::OK,
                json!({"protocol_version": PROTOCOL_VERSION, "cleared": true}),
            )
        }
        (&Method::POST, "/v1/config/validate") => validate_config(request).await,
        (&Method::POST, "/v1/diagnostics/trace") => diagnostic_trace(request, engine).await,
        (&Method::POST, "/v1/diagnostics/trace-candidate") => {
            diagnostic_trace_candidate(request, engine).await
        }
        (&Method::POST, "/v1/cache/flush") => {
            let response_entries_before = engine.cache.weighted_size();
            let rule_entries_before = engine.rule_cache.entry_count();
            engine.cache.invalidate_all();
            engine.rule_cache.invalidate_all();
            json_response(
                StatusCode::OK,
                json!({
                    "protocol_version": PROTOCOL_VERSION,
                    "response_entries_before": response_entries_before,
                    "response_entries_after": engine.cache.weighted_size(),
                    "rule_entries_before": rule_entries_before,
                    "rule_entries_after": engine.rule_cache.entry_count(),
                }),
            )
        }
        (&Method::GET | &Method::POST, _) => {
            json_response(StatusCode::NOT_FOUND, error_json("not_found", "端点不存在"))
        }
        _ => json_response(
            StatusCode::METHOD_NOT_ALLOWED,
            error_json("method_not_allowed", "请求方法不受支持"),
        ),
    };
    Ok(response)
}

#[cfg(unix)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DiagnosticRequest {
    domain: String,
    record_type: String,
    /// 假装来自这个客户端 IP；不填时是本机回环地址 / Pretend the query comes from this client IP; loopback when omitted
    #[serde(default)]
    client_ip: Option<IpAddr>,
}

/// 草稿试跑的请求：同样的查询字段，加上一份候选配置 / A draft trial: the same query fields plus a candidate config
#[cfg(unix)]
#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct CandidateTraceRequest {
    domain: String,
    record_type: String,
    #[serde(default)]
    client_ip: Option<IpAddr>,
    config: serde_json::Value,
}

/// 交给试跑子进程的输入：请求本身，加上当前引擎的监听器标签 / Input for the trial child: the request plus the live engine's listener label
#[cfg(unix)]
#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct TrialInput {
    request: CandidateTraceRequest,
    listener_label: String,
}

/// 试跑子进程写回的结果：状态码和响应体 / What the trial child writes back: a status code and a body
#[cfg(unix)]
#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct TrialOutput {
    status: u16,
    body: serde_json::Value,
}

/// 草稿试跑的总时限：子进程启动、加载 Geo 数据、建引擎，再加查询自己的 6 秒
/// The draft trial's overall limit: child start-up, Geo data loading and engine construction, plus the query's own 6 seconds
#[cfg(unix)]
const TRIAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(12);
/// 试跑的请求体：一份配置（与校验同上限）加上查询字段 / A trial body: one config (the validation limit) plus the query fields
#[cfg(unix)]
const MAX_TRIAL_BODY: usize = MAX_CONFIG_BODY + 4 * 1024;
/// 试跑子进程的输出上限：轨迹最多 128 步，远小于这个数 / The trial child's output limit; a trace of at most 128 steps stays far below it
#[cfg(unix)]
const MAX_TRIAL_OUTPUT: usize = 1024 * 1024;

#[cfg(unix)]
type Rejection = (StatusCode, serde_json::Value);

/// 检查域名和记录类型，编出一个 DNS 查询包 / Check the domain and record type and encode a DNS query packet
#[cfg(unix)]
fn diagnostic_packet(domain: &str, record_type: &str) -> Result<(Vec<u8>, String), Rejection> {
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::RecordType;

    // 和查询日志、规则看到的名字是同一种写法（见 `proto_utils::name_text`）：`\DDD` 是三位十进制，
    // 和 RFC 1035 一样。hickory 自己的解析按八进制读，查询日志里的 `www\046matched.test` 拿来诊断
    // 就成了别的名字
    // The same text the query log and the rules show a name in (see
    // `proto_utils::name_text`): `\DDD` is three decimal digits, as in RFC 1035. hickory's own
    // parser reads them as octal, so `www\046matched.test` from the query log asked for
    // another name
    let invalid = || {
        (
            StatusCode::BAD_REQUEST,
            error_json(
                "diagnostic_domain_invalid",
                "域名无效：标签只能用可打印的 ASCII 字符，其余字节、标签里的点和反斜杠写成 \\DDD（三位十进制）",
            ),
        )
    };
    let labels = crate::proto_utils::labels_from_text(domain).ok_or_else(invalid)?;
    // RFC 1035 第 2.3.4 节：名字在线上最多 255 字节，每个标签带一个长度字节，最后是根。按文本长度量
    // 不对：\DDD 一个字节要写四个字符
    // RFC 1035 section 2.3.4: a name is at most 255 bytes on the wire, each label with its
    // length byte, then the root. Its text is no measure: \DDD writes one byte in four
    // characters
    if labels.iter().map(|label| label.len() + 1).sum::<usize>() + 1 > 255 {
        return Err((
            StatusCode::BAD_REQUEST,
            error_json("diagnostic_domain_invalid", "域名过长"),
        ));
    }
    let name = hickory_proto::rr::Name::from_labels(labels.iter().map(Vec::as_slice))
        .map_err(|_| invalid())?;
    let record_type = record_type.trim().to_ascii_uppercase();
    let parsed = match record_type.as_str() {
        "A" => RecordType::A,
        "AAAA" => RecordType::AAAA,
        "CNAME" => RecordType::CNAME,
        "MX" => RecordType::MX,
        "NS" => RecordType::NS,
        "PTR" => RecordType::PTR,
        "SOA" => RecordType::SOA,
        "SRV" => RecordType::SRV,
        "TXT" => RecordType::TXT,
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                error_json("diagnostic_record_type_invalid", "不支持的 DNS 记录类型"),
            ));
        }
    };
    let request_id = (unix_timestamp() as u16) ^ (std::process::id() as u16);
    let mut message = Message::new(request_id, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(name, parsed));
    let packet = message.to_vec().map_err(|error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            error_json(
                "diagnostic_encode_failed",
                &format!("编码 DNS 请求失败：{error}"),
            ),
        )
    })?;
    Ok((packet, record_type))
}

/// 在诊断作用域里让引擎处理一次查询，整理成诊断响应 / Run one query through an engine inside a diagnostic scope and shape the response
#[cfg(unix)]
async fn run_diagnostic(
    engine: &Engine,
    packet: &[u8],
    client_ip: Option<IpAddr>,
    domain: &str,
    record_type: &str,
) -> (StatusCode, serde_json::Value) {
    use hickory_proto::op::Message;

    // The engine judges an IPv4-mapped address by its IPv4 address, and the reply says so
    // 引擎按 IPv4 地址看待 IPv4 映射地址，回复里也这样写
    let client = std::net::SocketAddr::new(
        client_ip.map_or(IpAddr::V4(Ipv4Addr::LOCALHOST), |ip| ip.to_canonical()),
        0,
    );
    let started = Instant::now();
    let future = crate::panel_trace::capture(engine.handle_packet(packet, client));
    let (result, steps, trace_truncated) =
        match tokio::time::timeout(std::time::Duration::from_secs(6), future).await {
            Ok(result) => result,
            Err(_) => {
                return (
                    StatusCode::GATEWAY_TIMEOUT,
                    error_json("diagnostic_timeout", "DNS 诊断超过 6 秒"),
                );
            }
        };
    let response = match result.and_then(|bytes| Message::from_vec(&bytes).map_err(Into::into)) {
        Ok(response) => response,
        Err(error) => {
            return (
                StatusCode::BAD_GATEWAY,
                error_json(
                    "diagnostic_query_failed",
                    &truncate(&format!("{error:#}"), MAX_ERROR_LENGTH),
                ),
            );
        }
    };
    (
        StatusCode::OK,
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "domain": domain,
            "record_type": record_type,
            "client_ip": client.ip().to_string(),
            "response_code": response.metadata.response_code.to_string(),
            "elapsed_ms": u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            "truncated": response.metadata.truncation,
            "answers": response.answers.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "trace_truncated": trace_truncated,
            "trace": steps,
        }),
    )
}

/// 读请求正文为什么失败 / Why reading a request body failed
#[cfg(unix)]
enum BodyFailure {
    TooLarge,
    Unreadable,
    /// [`REQUEST_READ_TIMEOUT`] 之内没发完 / Not finished within [`REQUEST_READ_TIMEOUT`]
    Late,
}

/// 读请求正文，最多 `limit` 字节，最多等 [`REQUEST_READ_TIMEOUT`]
/// Read a request body of at most `limit` bytes, waiting at most [`REQUEST_READ_TIMEOUT`]
#[cfg(unix)]
async fn collect_body(request: Request<Incoming>, limit: usize) -> Result<Bytes, BodyFailure> {
    let body = Limited::new(request.into_body(), limit).collect();
    match tokio::time::timeout(REQUEST_READ_TIMEOUT, body).await {
        Ok(Ok(body)) => Ok(body.to_bytes()),
        Ok(Err(error)) if error.is::<http_body_util::LengthLimitError>() => {
            Err(BodyFailure::TooLarge)
        }
        Ok(Err(_)) => Err(BodyFailure::Unreadable),
        Err(_) => Err(BodyFailure::Late),
    }
}

#[cfg(unix)]
fn late_body_response() -> Response<Full<Bytes>> {
    json_response(
        StatusCode::REQUEST_TIMEOUT,
        error_json("request_body_late", "请求正文没有在 10 秒内发完"),
    )
}

/// 把一个拒绝写成回答 / A rejection written out as the answer
#[cfg(unix)]
fn respond((status, body): Rejection) -> Response<Full<Bytes>> {
    json_response(status, body)
}

/// 请求正文不是要的 JSON：400，「{what}无效：{error}」
/// A request body that is not the JSON asked for: 400, "{what}无效：{error}"
#[cfg(unix)]
fn request_invalid(what: &str, error: impl std::fmt::Display) -> Rejection {
    (
        StatusCode::BAD_REQUEST,
        error_json(
            "diagnostic_request_invalid",
            &format!("{what}无效：{error}"),
        ),
    )
}

/// 配置用不了：422，错误连同原因链，截到 [`MAX_ERROR_LENGTH`]
/// A configuration that cannot be used: 422, the error with its cause chain, cut to
/// [`MAX_ERROR_LENGTH`]
#[cfg(unix)]
fn config_invalid(error: &anyhow::Error) -> Rejection {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        error_json(
            "config_invalid",
            &truncate(&format!("{error:#}"), MAX_ERROR_LENGTH),
        ),
    )
}

#[cfg(unix)]
async fn diagnostic_trace(request: Request<Incoming>, engine: Engine) -> Response<Full<Bytes>> {
    let body = match collect_body(request, MAX_DIAGNOSTIC_BODY).await {
        Ok(body) => body,
        Err(BodyFailure::Late) => return late_body_response(),
        Err(BodyFailure::TooLarge | BodyFailure::Unreadable) => {
            return json_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                error_json("diagnostic_body_invalid", "诊断请求不能超过 2 KiB"),
            );
        }
    };
    let request = match serde_json::from_slice::<DiagnosticRequest>(&body) {
        Ok(request) => request,
        Err(error) => return respond(request_invalid("诊断请求", error)),
    };
    let (packet, record_type) = match diagnostic_packet(&request.domain, &request.record_type) {
        Ok(prepared) => prepared,
        Err(rejection) => return respond(rejection),
    };
    let (status, body) = run_diagnostic(
        &engine,
        &packet,
        request.client_ip,
        &request.domain,
        &record_type,
    )
    .await;
    json_response(status, body)
}

/// 同一时间只跑一个草稿试跑：每次都要起一个子进程、加载 Geo 数据 / One draft trial at a time: each starts a child process and loads Geo data
#[cfg(unix)]
static TRIAL_GATE: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);

/// 拿一份候选配置试跑一次查询，不碰正在用的配置、缓存和统计。
///
/// 试跑在子进程里做（`kixdns panel-trial`，从标准输入读请求、往标准输出写结果）：引擎建起来时会
/// 打开整池 UDP socket、为 GeoSite 文件起监视线程，这些都跟着进程一起结束，进程内建临时引擎会把
/// 它们留下来。子进程不绑定任何监听端口。
///
/// Run one query against a candidate config without touching the live config, caches or statistics.
///
/// The trial runs in a child process (`kixdns panel-trial`, request on stdin, result on stdout):
/// building an engine opens a whole pool of UDP sockets and starts a watcher thread per GeoSite
/// file, all of which end with the process, whereas a temporary engine inside this process would
/// leave them behind. The child binds no listening port.
#[cfg(unix)]
async fn diagnostic_trace_candidate(
    request: Request<Incoming>,
    engine: Engine,
) -> Response<Full<Bytes>> {
    let body = match collect_body(request, MAX_TRIAL_BODY).await {
        Ok(body) => body,
        Err(BodyFailure::Late) => return late_body_response(),
        Err(BodyFailure::TooLarge | BodyFailure::Unreadable) => {
            return json_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                error_json("diagnostic_body_invalid", "试跑请求不能超过 4 MiB"),
            );
        }
    };
    let request = match serde_json::from_slice::<CandidateTraceRequest>(&body) {
        Ok(request) => request,
        Err(error) => return respond(request_invalid("试跑请求", error)),
    };
    // 查询字段先在这里查，错了不必起子进程 / Check the query fields here first; a bad one needs no child
    if let Err(rejection) = diagnostic_packet(&request.domain, &request.record_type) {
        return respond(rejection);
    }
    let input = match serde_json::to_vec(&TrialInput {
        request,
        listener_label: engine.listener_label.to_string(),
    }) {
        Ok(input) => input,
        Err(error) => {
            return json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                error_json(
                    "diagnostic_encode_failed",
                    &format!("编码试跑请求失败：{error}"),
                ),
            );
        }
    };
    let Ok(_permit) = TRIAL_GATE.acquire().await else {
        return json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            error_json("diagnostic_trial_unavailable", "试跑暂时不可用"),
        );
    };
    let (status, body) = match tokio::time::timeout(TRIAL_TIMEOUT, run_trial_child(input)).await {
        Ok(Ok(output)) => (
            StatusCode::from_u16(output.status).unwrap_or(StatusCode::BAD_GATEWAY),
            output.body,
        ),
        Ok(Err(error)) => (
            StatusCode::SERVICE_UNAVAILABLE,
            error_json(
                "diagnostic_trial_unavailable",
                &truncate(&format!("试跑没能完成：{error:#}"), MAX_ERROR_LENGTH),
            ),
        ),
        // 超时：kill_on_drop 在这里把子进程收掉 / Timed out: kill_on_drop reaps the child here
        Err(_) => (
            StatusCode::GATEWAY_TIMEOUT,
            error_json("diagnostic_timeout", "试跑超过 12 秒"),
        ),
    };
    json_response(status, body)
}

/// 起子进程、喂请求、读结果 / Start the child, feed it the request, read its result
#[cfg(unix)]
async fn run_trial_child(input: Vec<u8>) -> anyhow::Result<TrialOutput> {
    use std::process::Stdio;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let exe = std::env::current_exe().context("找不到 kixdns 可执行文件")?;
    let mut child = tokio::process::Command::new(exe)
        .arg("panel-trial")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("启动试跑子进程失败")?;
    let mut stdin = child.stdin.take().context("试跑子进程没有标准输入")?;
    stdin.write_all(&input).await.context("写入试跑请求失败")?;
    drop(stdin);
    // 两路一起读，免得一路写满管道把子进程卡住 / Read both pipes together so neither fills up and stalls the child
    let mut stdout = child
        .stdout
        .take()
        .context("试跑子进程没有标准输出")?
        .take(MAX_TRIAL_OUTPUT as u64 + 1);
    let mut stderr = child
        .stderr
        .take()
        .context("试跑子进程没有标准错误")?
        .take(MAX_ERROR_LENGTH as u64);
    let mut output = Vec::new();
    let mut errors = Vec::new();
    let (read_out, read_err) = tokio::join!(
        stdout.read_to_end(&mut output),
        stderr.read_to_end(&mut errors),
    );
    read_out.context("读取试跑结果失败")?;
    read_err.context("读取试跑错误输出失败")?;
    let status = child.wait().await.context("等待试跑子进程失败")?;
    if output.len() > MAX_TRIAL_OUTPUT {
        anyhow::bail!("试跑结果超过 1 MiB");
    }
    match serde_json::from_slice::<TrialOutput>(&output) {
        Ok(result) => Ok(result),
        Err(_) => {
            let detail = String::from_utf8_lossy(&errors);
            let detail = detail.lines().next().unwrap_or("").trim();
            anyhow::bail!(
                "子进程{}退出，没有给出结果{}",
                status
                    .code()
                    .map(|code| format!("以 {code} "))
                    .unwrap_or_else(|| "被信号终止".to_owned()),
                if detail.is_empty() {
                    String::new()
                } else {
                    format!("：{detail}")
                }
            )
        }
    }
}

/// `kixdns panel-trial` 的入口：从标准输入读一份试跑请求，往标准输出写一份结果，不绑定任何端口。
/// Entry of `kixdns panel-trial`: read one trial request from stdin, write one result to stdout, bind no port.
#[cfg(unix)]
pub async fn trial_from_stdio() -> anyhow::Result<()> {
    use std::io::{Read, Write};

    let mut raw = Vec::new();
    std::io::stdin()
        .take(MAX_TRIAL_BODY as u64 + 1024)
        .read_to_end(&mut raw)
        .context("读取试跑请求失败")?;
    let (status, body) = match serde_json::from_slice::<TrialInput>(&raw) {
        Ok(input) => run_trial(input).await,
        Err(error) => request_invalid("试跑请求", error),
    };
    let output = serde_json::to_vec(&TrialOutput {
        status: status.as_u16(),
        body,
    })
    .context("编码试跑结果失败")?;
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&output).context("写出试跑结果失败")?;
    stdout.flush().context("写出试跑结果失败")?;
    Ok(())
}

/// 用候选配置建一个引擎，跑一次查询。校验路径与 `/v1/config/validate` 相同；试跑关掉后台刷新，
/// 观察者是一份独立的统计，跟着子进程一起丢掉。
/// Build an engine from the candidate config and run one query. Validation follows `/v1/config/validate`;
/// the trial turns background refresh off, and its observer is a separate set of statistics discarded with the child.
#[cfg(unix)]
async fn run_trial(input: TrialInput) -> (StatusCode, serde_json::Value) {
    let TrialInput {
        request,
        listener_label,
    } = input;
    let (packet, record_type) = match diagnostic_packet(&request.domain, &request.record_type) {
        Ok(prepared) => prepared,
        Err(rejection) => return rejection,
    };
    // 与 `kixdns run` 一样先装 rustls 的加密后端：子进程不走 run，不装的话第一个 DoH/DoT 上游就会 panic
    // Install rustls' crypto provider as `kixdns run` does: the child never goes through run, and
    // without it the first DoH/DoT upstream panics
    let _ = rustls::crypto::ring::default_provider().install_default();
    let raw = request.config.to_string();
    let built = crate::config::validate(&raw)
        .and_then(|_| crate::config::parse_config(&raw))
        .and_then(|mut config| {
            config.settings.cache_background_refresh = false;
            let runtime = crate::matcher::RuntimePipelineConfig::from_config(config)?;
            Engine::builder(runtime)
                .listener_label(listener_label)
                .observer(Arc::new(PanelMetrics::new(false)))
                .build()
        });
    let engine = match built {
        Ok(engine) => engine,
        Err(error) => return config_invalid(&error),
    };
    let (status, mut body) = run_diagnostic(
        &engine,
        &packet,
        request.client_ip,
        &request.domain,
        &record_type,
    )
    .await;
    if let Some(object) = body.as_object_mut() {
        object.insert("candidate".to_owned(), json!(true));
    }
    (status, body)
}

#[cfg(unix)]
fn parse_stats_query(query: Option<&str>) -> Result<(u64, usize), &'static str> {
    let mut window_seconds = 86_400;
    let mut limit = 20usize;
    for pair in query.into_iter().flat_map(|query| query.split('&')) {
        if pair.is_empty() {
            continue;
        }
        let Some((key, value)) = pair.split_once('=') else {
            return Err("查询参数格式无效");
        };
        match key {
            "window" => {
                window_seconds = value.parse().map_err(|_| "统计窗口无效")?;
                if !matches!(window_seconds, 3_600 | 21_600 | 86_400) {
                    return Err("统计窗口仅支持 3600、21600 或 86400 秒");
                }
            }
            "limit" => {
                limit = value.parse().map_err(|_| "排行数量无效")?;
                if !(1..=50).contains(&limit) {
                    return Err("排行数量必须在 1 到 50 之间");
                }
            }
            _ => return Err("包含不受支持的查询参数"),
        }
    }
    Ok((window_seconds, limit))
}

/// 交出一页查询日志：给了 `wait_ms` 先等着（见 `QueryLog::wait_for_page`），再在阻塞线程上拼 JSON——几千条
/// 要几毫秒，不能占着答 DNS 的线程
/// Hands over a page of the query log: with `wait_ms` it first waits (see
/// `QueryLog::wait_for_page`), then builds the JSON on a blocking thread, as thousands of records
/// take milliseconds that must not hold up a thread answering DNS
#[cfg(unix)]
async fn querylog_response(
    metrics: &Arc<PanelMetrics>,
    query: Option<&str>,
) -> Response<Full<Bytes>> {
    let take = match parse_querylog_query(query) {
        Ok(take) => take,
        Err(message) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                error_json("querylog_query_invalid", message),
            );
        }
    };
    if !take.wait.is_zero() {
        metrics
            .query_log
            .wait_for_page(take.after, take.limit, take.until, take.instance, take.wait)
            .await;
    }
    let collecting = Arc::clone(metrics);
    match tokio::task::spawn_blocking(move || {
        let page = collecting.query_log.take(
            take.after,
            take.limit,
            take.until,
            take.instance,
            take.stored,
            PROTOCOL_VERSION,
        );
        match take.format {
            QueryLogFormat::Json => ("application/json; charset=utf-8", page.json().into_bytes()),
            QueryLogFormat::Records => ("application/octet-stream", page.records()),
        }
    })
    .await
    {
        Ok((content_type, page)) => bytes_response(StatusCode::OK, content_type, page),
        Err(error) => json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            error_json("querylog_failed", &error.to_string()),
        ),
    }
}

/// 面板来取一页查询日志 / One take of the query log by the panel
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct QueryLogTake {
    /// 面板已经取到的最后一个序号，从没取过是 0 / The last sequence number the panel has taken, 0 before the first
    after: u64,
    /// 最多取几条，默认取满一页 / At most how many records, a full page by default
    limit: usize,
    /// 只取到这个序号为止（见 `QueryLog::take`）/ No record past this number (see `QueryLog::take`)
    until: Option<u64>,
    /// 游标是哪个内核进程的（见 `QueryLog::take`）/ The kernel process the cursor belongs to (see `QueryLog::take`)
    instance: Option<u64>,
    /// 面板存好到哪一条（见 `QueryLog::take`）/ The record the panel has stored up to (see `QueryLog::take`)
    stored: Option<u64>,
    /// 交成什么样（见 `TakenPage`）/ How the page is handed over (see `TakenPage`)
    format: QueryLogFormat,
    /// 攒不满一页时最多等多久（见 `QueryLog::wait_for_page`）/ How long to wait at most while a page has not filled
    /// (see `QueryLog::wait_for_page`)
    wait: std::time::Duration,
}

/// 一页查询日志交成什么样：JSON（`querylog_v1`），或者编好的记录原样交出（`querylog_records_v1`）
/// How a page of the query log is handed over: as JSON (`querylog_v1`), or as the encoded records
/// themselves (`querylog_records_v1`)
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QueryLogFormat {
    Json,
    Records,
}

/// 查询日志的游标：`after`、`limit`、`until`、`instance`、`stored`、`wait_ms`，含义见 [`QueryLogTake`]
/// The query log cursor: `after`, `limit`, `until`, `instance`, `stored` and `wait_ms`, as described at
/// [`QueryLogTake`], and `format` (`json` or `records1`)
#[cfg(unix)]
fn parse_querylog_query(query: Option<&str>) -> Result<QueryLogTake, &'static str> {
    let mut take = QueryLogTake {
        after: 0,
        limit: panel_querylog::MAX_PAGE,
        until: None,
        instance: None,
        stored: None,
        format: QueryLogFormat::Json,
        wait: std::time::Duration::ZERO,
    };
    for pair in query.into_iter().flat_map(|query| query.split('&')) {
        if pair.is_empty() {
            continue;
        }
        let Some((key, value)) = pair.split_once('=') else {
            return Err("查询参数格式无效");
        };
        match key {
            "after" => take.after = value.parse().map_err(|_| "游标无效")?,
            "limit" => {
                take.limit = value.parse().map_err(|_| "条数无效")?;
                if !(1..=panel_querylog::MAX_PAGE).contains(&take.limit) {
                    return Err("条数必须在 1 到 2000 之间");
                }
            }
            "until" => take.until = Some(value.parse().map_err(|_| "截止序号无效")?),
            "instance" => take.instance = Some(value.parse().map_err(|_| "内核进程无效")?),
            "stored" => take.stored = Some(value.parse().map_err(|_| "存好的序号无效")?),
            "format" => {
                take.format = match value {
                    "json" => QueryLogFormat::Json,
                    "records1" => QueryLogFormat::Records,
                    _ => return Err("格式只能是 json 或 records1"),
                };
            }
            "wait_ms" => {
                take.wait =
                    std::time::Duration::from_millis(value.parse().map_err(|_| "等待时间无效")?);
                if take.wait > panel_querylog::MAX_WAIT {
                    return Err("等待时间不能超过 5000 毫秒");
                }
            }
            _ => return Err("包含不受支持的查询参数"),
        }
    }
    Ok(take)
}

#[cfg(unix)]
async fn validate_config(request: Request<Incoming>) -> Response<Full<Bytes>> {
    let body = match collect_body(request, MAX_CONFIG_BODY).await {
        Ok(body) => body,
        Err(BodyFailure::Late) => return late_body_response(),
        Err(failure) => {
            let message = if matches!(failure, BodyFailure::TooLarge) {
                "配置不能超过 4 MiB"
            } else {
                "读取配置请求失败"
            };
            return json_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                error_json("config_body_invalid", message),
            );
        }
    };

    validate_body(body).await
}

/// 排行的回答。算排行要把窗口里每个钟头的每一项合起来再排序（24 小时的窗口最多二十万项），放到阻塞线程池里做，
/// 不占着处理 DNS 的线程
/// The answer with the rankings. Working them out merges every entry of every hour in the
/// window and sorts them (up to two hundred thousand entries for a 24-hour window), so it runs on
/// the blocking thread pool and holds no thread that serves DNS
#[cfg(unix)]
async fn stats_response(
    metrics: &Arc<PanelMetrics>,
    window_seconds: u64,
    limit: usize,
) -> Response<Full<Bytes>> {
    let counting = Arc::clone(metrics);
    match tokio::task::spawn_blocking(move || counting.stats_json(window_seconds, limit)).await {
        Ok(stats) => json_response(StatusCode::OK, stats),
        Err(error) => json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            error_json("stats_failed", &error.to_string()),
        ),
    }
}

/// 校验一份配置，给出回答。校验放到阻塞线程池里做，和取查询日志一样：它要解析整份配置、编译每条正则、读 DoH 的
/// 证书文件，规则多的配置要几十到几百毫秒，在处理请求的线程上做的话，排在这个线程上的 DNS 查询这期间都等着
/// Validates a configuration and gives the answer. The validation runs on the blocking thread
/// pool, as taking the query log does: it parses the whole configuration, compiles every regex
/// and reads the DoH certificate files, tens to hundreds of milliseconds for a configuration
/// with many rules, during which the DNS queries queued on a thread serving requests would wait
#[cfg(unix)]
async fn validate_body(body: Bytes) -> Response<Full<Bytes>> {
    // 与引擎启动完全相同的校验路径，含监听地址与 DoH 证书检查。
    // The exact validation the engine runs at startup, listener and DoH checks included.
    let validated = tokio::task::spawn_blocking(move || {
        crate::config::validate(std::str::from_utf8(&body).unwrap_or_default())
    })
    .await;
    match validated {
        Ok(Ok(report)) => json_response(
            StatusCode::OK,
            json!({
                "protocol_version": PROTOCOL_VERSION,
                "valid": true,
                "pipeline_count": report.pipeline_count,
                "rule_count": report.rule_count,
            }),
        ),
        Ok(Err(error)) => respond(config_invalid(&error)),
        Err(error) => json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            error_json("config_validate_failed", &error.to_string()),
        ),
    }
}

#[cfg(unix)]
fn json_response(status: StatusCode, value: serde_json::Value) -> Response<Full<Bytes>> {
    text_response(status, "application/json; charset=utf-8", value.to_string())
}

#[cfg(unix)]
fn text_response(
    status: StatusCode,
    content_type: &'static str,
    body: String,
) -> Response<Full<Bytes>> {
    bytes_response(status, content_type, body.into_bytes())
}

#[cfg(unix)]
fn bytes_response(
    status: StatusCode,
    content_type: &'static str,
    body: Vec<u8>,
) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(body)));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
}

#[cfg(unix)]
fn error_json(code: &str, message: &str) -> serde_json::Value {
    json!({ "protocol_version": PROTOCOL_VERSION, "error": { "code": code, "message": message } })
}

fn append_map(output: &mut String, name: &str, series: &Series<ThreadCount>, labels: &[&str]) {
    let mut rows = series
        .snapshot()
        .iter()
        .map(|(key, counter)| (key.to_string(), counter.load(Ordering::Relaxed)))
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| left.0.cmp(&right.0));
    for (key, value) in rows {
        let values = key.split('\0').collect::<Vec<_>>();
        if values.len() != labels.len() {
            continue;
        }
        let pairs = labels
            .iter()
            .zip(values)
            .map(|(label, value)| (*label, value))
            .collect::<Vec<_>>();
        labeled_metric(output, name, &pairs, value);
    }
}

fn append_latency_map(
    output: &mut String,
    name: &str,
    series: &Series<LatencySum>,
    labels: &[&str],
) {
    let mut rows = series
        .snapshot()
        .iter()
        .map(|(key, sum)| {
            (
                key.to_string(),
                sum.micros.load(Ordering::Relaxed),
                sum.count.load(Ordering::Relaxed),
            )
        })
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| left.0.cmp(&right.0));
    for (key, micros, count) in rows {
        let values = key.split('\0').collect::<Vec<_>>();
        if values.len() != labels.len() {
            continue;
        }
        let pairs = labels
            .iter()
            .zip(values)
            .map(|(label, value)| (*label, value))
            .collect::<Vec<_>>();
        labeled_metric(
            output,
            &format!("{name}_sum"),
            &pairs,
            format_millis(micros),
        );
        labeled_metric(output, &format!("{name}_count"), &pairs, count);
    }
}

/// 微秒累计值以毫秒输出，保留三位小数。/ Render accumulated microseconds as milliseconds.
fn format_millis(micros: u64) -> String {
    format!("{}.{:03}", micros / 1_000, micros % 1_000)
}

fn metric(output: &mut String, name: &str, value: impl std::fmt::Display) {
    let _ = writeln!(output, "{name} {value}");
}

fn labeled_metric(
    output: &mut String,
    name: &str,
    labels: &[(&str, &str)],
    value: impl std::fmt::Display,
) {
    let _ = write!(output, "{name}{{");
    for (index, (label, label_value)) in labels.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        let _ = write!(output, "{label}=\"{}\"", escape_label(label_value));
    }
    let _ = writeln!(output, "}} {value}");
}

fn escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('"', "\\\"")
}

fn truncate(value: &str, max_length: usize) -> String {
    value.chars().take(max_length).collect()
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::Ordering;

    use super::{
        MAX_METRIC_SERIES_PER_MAP, PanelMetrics, QUERY_STATS_BUCKET_SECONDS, QUERY_STATS_BUCKETS,
        QUERY_STATS_CLIENT_CAP, QUERY_STATS_DOMAIN_CAP, QueryStats, QueryStatsBucket, TopStat,
    };

    #[derive(Clone, Default)]
    struct SharedBuffer(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for SharedBuffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedBuffer {
        type Writer = SharedBuffer;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// `EngineObserver` 的全部 16 个方法，与 `TracingObserver` 写出的 `event` 字段值一一对应；
    /// 少转发任何一个，`--debug` 就会悄悄丢掉那一类事件日志。
    /// All 16 `EngineObserver` methods, paired with the `event` field value `TracingObserver`
    /// writes for each; dropping any single forward silently loses that event kind under `--debug`.
    const OBSERVER_EVENT_NAMES: [&str; 16] = [
        "request_started",
        "request_finished",
        "pipeline_selected",
        "rule_matched",
        "rule_evaluated",
        "rule_cache_lookup",
        "decision_made",
        "cache_lookup",
        "cache_miss",
        "cache_hit",
        "inflight_joined",
        "upstream_attempt",
        "upstream_result",
        "upstream_skipped",
        "config_loaded",
        "config_reload_failed",
    ];

    /// 测试用的一个请求：问 A / IN，不是后台刷新 / A test request: A / IN, not a background refresh
    fn request(
        request_id: u64,
        client: &str,
        qname: &'static str,
    ) -> crate::observe::RequestContext<'static> {
        crate::observe::RequestContext {
            request_id,
            listener_label: "default",
            client: client.parse().unwrap(),
            transport: None,
            qname,
            qtype: hickory_proto::rr::RecordType::A,
            qclass: hickory_proto::rr::DNSClass::IN,
            background_refresh: false,
            started: std::time::Instant::now(),
            reported_at_once: false,
        }
    }

    /// 命中一次交过来，和分开的事件记下的一样：计数、排行和查询日志
    /// A cache hit handed over whole records what the separate events record: the counters, the
    /// rankings and the query log
    #[test]
    fn a_cache_hit_taken_whole_records_what_the_separate_events_record() {
        use crate::observe::{
            CacheHit, CacheHitKind, EngineObserver, RequestContext, RequestOutcome, RequestStatus,
        };

        let by_events = PanelMetrics::new(false);
        let whole = PanelMetrics::new(false);
        let bytes = [
            0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1,
        ];
        let hit = CacheHit {
            kind: CacheHitKind::Fresh,
            remaining_ttl: Some(std::time::Duration::from_secs(30)),
            original_ttl: Some(std::time::Duration::from_secs(60)),
            source: Some("udp://192.0.2.53:53"),
        };
        let completed = RequestOutcome {
            latency: std::time::Duration::from_millis(3),
            status: RequestStatus::Completed,
            response: Some(&bytes),
            error: None,
        };
        let failed = RequestOutcome {
            latency: std::time::Duration::from_millis(7),
            status: RequestStatus::Failed,
            response: None,
            error: Some("engine failed"),
        };
        for (id, qname, outcome) in [
            (1, "a.example", &completed),
            (2, "b.example", &completed),
            (3, "a.example", &failed),
        ] {
            let ctx = RequestContext {
                reported_at_once: true,
                ..request(id, "192.168.1.9:5353", qname)
            };
            by_events.request_started(&ctx);
            by_events.pipeline_selected(&ctx, "main");
            by_events.cache_lookup(&ctx);
            by_events.cache_hit(&ctx, &hit);
            by_events.request_finished(&ctx, outcome);
            assert!(whole.answered_from_cache(&ctx, "main", &hit, outcome));
        }
        let counters = |metrics: &PanelMetrics| {
            let mut output = String::new();
            metrics.render_counters(&mut output);
            output
        };
        assert_eq!(counters(&by_events), counters(&whole));
        assert_eq!(by_events.stats_json(3_600, 20), whole.stats_json(3_600, 20));
        let log = |metrics: &PanelMetrics| {
            let page = metrics.query_log.collect(0, 10, None, None, None, 1);
            let mut page: serde_json::Value = serde_json::from_str(&page).unwrap();
            page.as_object_mut().unwrap().remove("instance");
            for entry in page["entries"].as_array_mut().unwrap() {
                entry.as_object_mut().unwrap().remove("time_unix_ms");
            }
            page
        };
        assert_eq!(log(&by_events)["entries"].as_array().unwrap().len(), 3);
        assert_eq!(log(&by_events), log(&whole));
    }

    /// 规则回答一次交过来，和分开的事件记下的一样：计数、排行和查询日志，一条规则定的和规则缓存里几条规则都算
    /// A rule's answer handed over whole records what the separate events record: the counters, the rankings
    /// and the query log, for one rule deciding and for several from the rule cache
    #[test]
    fn a_rule_answer_taken_whole_records_what_the_separate_events_record() {
        use crate::observe::{
            DecisionDetail, DecisionKind, DecisionMade, EngineObserver, RequestContext,
            RequestOutcome, RequestStatus, RuleAnswer, RuleCacheLookup, RuleMatched, RulePhase,
        };
        use hickory_proto::op::ResponseCode;

        let by_events = PanelMetrics::new(false);
        let whole = PanelMetrics::new(false);
        let bytes = [
            0x12, 0x34, 0x81, 0x83, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1,
        ];
        let completed = RequestOutcome {
            latency: std::time::Duration::from_millis(3),
            status: RequestStatus::Completed,
            response: Some(&bytes),
            error: None,
        };
        let failed = RequestOutcome {
            latency: std::time::Duration::from_millis(7),
            status: RequestStatus::Failed,
            response: None,
            error: Some("engine failed"),
        };
        // 编号、域名、命中的规则、是不是规则定的、怎么结束的、是不是规则缓存答的 / The number, name, matched rules, whether
        // a rule decided, how it ended and whether the rule cache answered
        type Shape<'a> = (
            u64,
            &'static str,
            &'a [&'a str],
            bool,
            &'a RequestOutcome<'a>,
            bool,
        );
        let shapes: [Shape<'_>; 4] = [
            (1, "a.example", &["block"], true, &completed, false),
            (2, "b.example", &["first", "block"], true, &completed, true),
            (3, "a.example", &["first"], false, &completed, true),
            (4, "c.example", &["block"], true, &failed, false),
        ];
        for (id, qname, rules, decided_by_rule, outcome, from_rule_cache) in shapes {
            let ctx = RequestContext {
                reported_at_once: true,
                ..request(id, "192.168.1.9:5353", qname)
            };
            let rcode = ResponseCode::NXDomain;
            by_events.request_started(&ctx);
            by_events.pipeline_selected(&ctx, "main");
            by_events.cache_lookup(&ctx);
            by_events.cache_miss(&ctx);
            if from_rule_cache {
                by_events.rule_cache_lookup(
                    &ctx,
                    &RuleCacheLookup {
                        pipeline: "main",
                        hit: true,
                        matched_rules: rules.len(),
                    },
                );
            }
            for (at, rule) in rules.iter().enumerate() {
                by_events.rule_matched(
                    &ctx,
                    &RuleMatched {
                        pipeline: "main",
                        rule,
                        phase: RulePhase::Request,
                        decision: if decided_by_rule && at + 1 == rules.len() {
                            DecisionKind::Static
                        } else {
                            DecisionKind::Continue
                        },
                        fast_path: true,
                    },
                );
            }
            by_events.decision_made(
                &ctx,
                &DecisionMade {
                    pipeline: "main",
                    rule: decided_by_rule.then(|| rules[rules.len() - 1]),
                    phase: RulePhase::Request,
                    detail: DecisionDetail::Static { rcode, answers: 0 },
                },
            );
            by_events.request_finished(&ctx, outcome);
            assert!(whole.answered_by_rule(
                &ctx,
                "main",
                &RuleAnswer {
                    rules,
                    decided_by_rule,
                    rcode,
                    answers: 0,
                },
                outcome,
            ));
        }
        let counters = |metrics: &PanelMetrics| {
            let mut output = String::new();
            metrics.render_counters(&mut output);
            output
        };
        assert_eq!(counters(&by_events), counters(&whole));
        assert_eq!(by_events.stats_json(3_600, 20), whole.stats_json(3_600, 20));
        let log = |metrics: &PanelMetrics| {
            let page = metrics.query_log.collect(0, 10, None, None, None, 1);
            let mut page: serde_json::Value = serde_json::from_str(&page).unwrap();
            page.as_object_mut().unwrap().remove("instance");
            for entry in page["entries"].as_array_mut().unwrap() {
                entry.as_object_mut().unwrap().remove("time_unix_ms");
            }
            page
        };
        assert_eq!(log(&by_events)["entries"].as_array().unwrap().len(), 4);
        assert_eq!(log(&by_events), log(&whole));
    }

    /// 诊断、调试跟踪和命中的规则多到一条记录放不下时，不一次接过来，也什么都不记
    /// Diagnostics, the debug trace and more matched rules than a record has room for are not taken whole, and
    /// nothing is recorded
    #[tokio::test]
    async fn a_rule_answer_is_not_taken_whole_when_it_should_not_be() {
        use crate::observe::{EngineObserver, RequestOutcome, RequestStatus, RuleAnswer};
        use hickory_proto::op::ResponseCode;
        use std::sync::atomic::Ordering;

        let outcome = RequestOutcome {
            latency: std::time::Duration::from_millis(3),
            status: RequestStatus::Completed,
            response: None,
            error: None,
        };
        let answer = |rules| RuleAnswer {
            rules,
            decided_by_rule: true,
            rcode: ResponseCode::NXDomain,
            answers: 0,
        };
        let ctx = request(1, "192.168.1.9:5353", "a.example");
        let one: &[&str] = &["block"];
        let traced = PanelMetrics::new(true);
        assert!(!traced.answered_by_rule(&ctx, "main", &answer(one), &outcome));
        let plain = PanelMetrics::new(false);
        let (taken, _, _) = crate::panel_trace::capture(async {
            plain.answered_by_rule(&ctx, "main", &answer(one), &outcome)
        })
        .await;
        assert!(!taken);
        let many = vec!["rule"; 62];
        assert!(!plain.answered_by_rule(&ctx, "main", &answer(&many), &outcome));
        assert_eq!(plain.requests_total.load(Ordering::Relaxed), 0);
        let most = vec!["rule"; 61];
        assert!(plain.answered_by_rule(&ctx, "main", &answer(&most), &outcome));
        assert_eq!(plain.requests_total.load(Ordering::Relaxed), 1);
    }

    /// 诊断查询和调试跟踪要一步步看，不一次接过来 / Diagnostic queries and the debug trace want every
    /// step, and a hit is not taken whole
    #[tokio::test]
    async fn a_hit_is_not_taken_whole_when_every_step_is_wanted() {
        use crate::observe::{
            CacheHit, CacheHitKind, EngineObserver, RequestOutcome, RequestStatus,
        };
        use std::sync::atomic::Ordering;

        let hit = CacheHit {
            kind: CacheHitKind::Fresh,
            remaining_ttl: None,
            original_ttl: None,
            source: None,
        };
        let outcome = RequestOutcome {
            latency: std::time::Duration::from_millis(3),
            status: RequestStatus::Completed,
            response: None,
            error: None,
        };
        let ctx = request(1, "192.168.1.9:5353", "a.example");
        let traced = PanelMetrics::new(true);
        assert!(!traced.answered_from_cache(&ctx, "main", &hit, &outcome));
        let plain = PanelMetrics::new(false);
        let (taken, _, _) = crate::panel_trace::capture(async {
            plain.answered_from_cache(&ctx, "main", &hit, &outcome)
        })
        .await;
        assert!(!taken);
        assert_eq!(plain.requests_total.load(Ordering::Relaxed), 0);
    }

    /// 正常结束，回了一个空应答 / Completed with an empty response
    fn completed(millis: u64) -> crate::observe::RequestOutcome<'static> {
        crate::observe::RequestOutcome {
            latency: std::time::Duration::from_millis(millis),
            status: crate::observe::RequestStatus::Completed,
            response: Some(&[]),
            error: None,
        }
    }

    /// 1.1.1.1:53 按 UDP 问的一次结果 / One attempt at 1.1.1.1:53 configured as UDP
    fn udp_result(
        outcome: crate::observe::UpstreamOutcome,
        via: crate::config::Transport,
        rcode: Option<hickory_proto::op::ResponseCode>,
        millis: u64,
    ) -> crate::observe::UpstreamResult<'static> {
        crate::observe::UpstreamResult {
            upstream: "1.1.1.1:53",
            transport: crate::config::Transport::Udp,
            via,
            outcome,
            latency: std::time::Duration::from_millis(millis),
            rcode,
            truncated: Some(false),
            error: None,
        }
    }

    /// 在带目标名的 tracing 订阅者下把 16 个观察者方法各驱动一次，返回它写出的全部日志文本。
    /// Drives each of the 16 observer methods once under a target-printing tracing subscriber
    /// and returns everything it logged.
    fn captured_observer_output(metrics: &PanelMetrics) -> String {
        use crate::config::Transport;
        use crate::observe::{
            CacheHit, CacheHitKind, ConfigLoaded, ConfigReloadFailed, DecisionDetail, DecisionKind,
            DecisionMade, EngineObserver, RequestContext, RuleCacheLookup, RuleEvaluated,
            RuleMatched, RulePhase, UpstreamAttempt, UpstreamOutcome, UpstreamSkipReason,
            UpstreamSkipped,
        };
        use hickory_proto::op::ResponseCode;
        use std::time::Duration;
        use tracing_subscriber::layer::SubscriberExt;

        let buffer = SharedBuffer::default();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .without_time()
                .with_ansi(false)
                .with_target(true)
                .with_writer(buffer.clone()),
        );
        let ctx = RequestContext {
            background_refresh: true,
            ..request(7, "127.0.0.1:53000", "example.com")
        };
        tracing::subscriber::with_default(subscriber, || {
            metrics.request_started(&ctx);
            metrics.pipeline_selected(&ctx, "main");
            metrics.rule_cache_lookup(
                &ctx,
                &RuleCacheLookup {
                    pipeline: "main",
                    hit: false,
                    matched_rules: 0,
                },
            );
            metrics.rule_evaluated(
                &ctx,
                &RuleEvaluated {
                    pipeline: "main",
                    rule: "forward-all",
                    phase: RulePhase::Request,
                    matched: true,
                    matchers: 1,
                },
            );
            metrics.rule_matched(
                &ctx,
                &RuleMatched {
                    pipeline: "main",
                    rule: "forward-all",
                    phase: RulePhase::Request,
                    decision: DecisionKind::Forward,
                    fast_path: false,
                },
            );
            metrics.decision_made(
                &ctx,
                &DecisionMade {
                    pipeline: "main",
                    rule: Some("forward-all"),
                    phase: RulePhase::Request,
                    detail: DecisionDetail::Forward {
                        upstream: "1.1.1.1:53",
                        transport: Some(Transport::Udp),
                    },
                },
            );
            metrics.cache_lookup(&ctx);
            metrics.cache_miss(&ctx);
            metrics.cache_hit(
                &ctx,
                &CacheHit {
                    kind: CacheHitKind::Fresh,
                    remaining_ttl: Some(Duration::from_secs(30)),
                    original_ttl: Some(Duration::from_secs(60)),
                    source: None,
                },
            );
            metrics.inflight_joined(&ctx);
            metrics.upstream_attempt(
                &ctx,
                &UpstreamAttempt {
                    upstream: "1.1.1.1:53",
                    transport: Transport::Udp,
                },
            );
            metrics.upstream_result(
                &ctx,
                &udp_result(
                    UpstreamOutcome::Success,
                    Transport::Udp,
                    Some(ResponseCode::NoError),
                    12,
                ),
            );
            metrics.upstream_skipped(
                &ctx,
                &UpstreamSkipped {
                    upstream: "doh.example/dns-query",
                    transport: Transport::Doh,
                    reason: UpstreamSkipReason::Throttled,
                },
            );
            metrics.request_finished(&ctx, &completed(13));
            metrics.config_loaded(&ConfigLoaded {
                path: None,
                generation: 1,
                source: Some("{}"),
                restart_pending: &[],
            });
            metrics.config_reload_failed(&ConfigReloadFailed {
                path: std::path::Path::new("pipeline.json"),
                error: "broken",
            });
        });
        let bytes = buffer.0.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }

    /// 第一次加载的配置没带原文时也不算一次重载：重载次数和重载序号不变，代数是 1；之后的加载才算
    /// The first configuration loaded without its text is no reload either: the reload
    /// count and sequence stay, the generation is 1; the loads after it are reloads
    #[test]
    fn the_first_load_without_its_text_is_no_reload() {
        use crate::observe::{ConfigLoaded, EngineObserver};
        use std::sync::atomic::Ordering;
        let metrics = PanelMetrics::default();
        let load = |generation| {
            metrics.config_loaded(&ConfigLoaded {
                path: None,
                generation,
                source: None,
                restart_pending: &[],
            })
        };
        load(1);
        assert_eq!(metrics.reload_success.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.reload_sequence.load(Ordering::Acquire), 0);
        assert_eq!(metrics.active_config.read().generation, 1);
        load(2);
        assert_eq!(metrics.reload_success.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.reload_sequence.load(Ordering::Acquire), 1);
        assert_eq!(metrics.active_config.read().generation, 2);
    }

    /// 跳转过的请求会在目标 pipeline 下再查一次缓存，但只计一次查找：命中率按请求算，
    /// 否则跳转过的请求命中时，看板上的命中率只有一半。请求结束后不再记着它。
    /// A request that jumps looks in the cache again under the target pipeline but
    /// counts one lookup: the hit rate is per request, or a jumped request's hit would
    /// show as half a hit on the dashboard. Nothing is kept once the request ends.
    #[test]
    fn a_request_that_looks_again_after_a_jump_counts_one_lookup() {
        use crate::observe::{CacheHit, CacheHitKind, EngineObserver};
        use std::sync::atomic::Ordering;
        use std::time::Duration;

        let metrics = PanelMetrics::default();
        let ctx = request(41, "192.0.2.10:53000", "jumped.example");
        metrics.request_started(&ctx);
        metrics.pipeline_selected(&ctx, "main");
        metrics.cache_lookup(&ctx);
        metrics.cache_miss(&ctx);
        metrics.pipeline_selected(&ctx, "upstream-default");
        metrics.cache_lookup(&ctx);
        metrics.cache_hit(
            &ctx,
            &CacheHit {
                kind: CacheHitKind::Fresh,
                remaining_ttl: Some(Duration::from_secs(30)),
                original_ttl: Some(Duration::from_secs(60)),
                source: None,
            },
        );
        metrics.request_finished(&ctx, &completed(1));

        assert_eq!(metrics.cache_lookups_total.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.cache_hits_fresh.load(Ordering::Relaxed), 1);
        assert!(metrics.cache_lookup_counted.is_empty());
    }

    /// `--debug` 必须把 16 个引擎事件（含后台刷新）逐一转发给上游参考观察者；
    /// 不带 `--debug` 时一条都不该出现。
    /// `--debug` must forward every one of the 16 engine events (background refresh included)
    /// to the upstream reference observer; without `--debug` none may appear.
    #[test]
    fn debug_forwards_engine_events_to_tracing_observer() {
        let output = captured_observer_output(&PanelMetrics::new(true));
        assert!(output.contains("kixdns::observe"), "{output}");
        for name in OBSERVER_EVENT_NAMES {
            let marker = format!("event=\"{name}\"");
            assert!(
                output.contains(&marker),
                "missing {marker} in --debug output:\n{output}"
            );
        }

        let silent = captured_observer_output(&PanelMetrics::new(false));
        assert!(silent.is_empty(), "{silent}");
        let default = captured_observer_output(&PanelMetrics::default());
        assert!(default.is_empty(), "{default}");
    }

    #[test]
    fn uptime_uses_monotonic_clock_after_wall_clock_rewind() {
        let metrics = PanelMetrics {
            started_at_unix: super::unix_timestamp().saturating_add(3_600),
            started_at: std::time::Instant::now() - std::time::Duration::from_secs(61),
            ..PanelMetrics::default()
        };

        assert!(metrics.uptime_seconds() >= 61);
    }

    #[cfg(unix)]
    #[test]
    fn escapes_prometheus_labels() {
        assert_eq!(super::escape_label("a\\b\n\"c"), "a\\\\b\\n\\\"c");
    }

    /// 一组统计项满了以后，再来的新名字只记一次丢弃，不去拿加统计项的那把锁。这把锁全进程共用；规则多过上限的配置下，
    /// 以前命中表外规则的每个查询都要拿它一次，几个核互相等
    /// Once a set of series is full, a further new name counts one dropped series and does not
    /// take the lock that adds a series. That lock is shared by the whole process; with more rules
    /// than the limit, every query matching a rule outside the table used to take it, the cores
    /// waiting on one another
    #[test]
    fn a_full_set_of_series_takes_no_lock_for_a_new_name() {
        let metrics = std::sync::Arc::new(PanelMetrics::default());
        for index in 0..MAX_METRIC_SERIES_PER_MAP {
            metrics.record_pipeline_hit(&format!("pipeline-{index}"));
        }
        let held = metrics.metric_series_insert_lock.lock();
        let (done, counted) = std::sync::mpsc::channel();
        let counting = std::sync::Arc::clone(&metrics);
        let worker = std::thread::spawn(move || {
            counting.record_pipeline_hit("one-more");
            let _ = done.send(());
        });
        let counted = counted.recv_timeout(std::time::Duration::from_secs(2));
        drop(held);
        worker.join().unwrap();
        assert!(counted.is_ok(), "counting a new name waited for the lock");
        assert_eq!(
            metrics.metric_series_dropped.load(super::Ordering::Relaxed),
            1
        );
        assert_eq!(metrics.pipeline_hits.len(), MAX_METRIC_SERIES_PER_MAP);
    }

    /// 校验配置的活不占着处理 DNS 的线程：校验一份大配置的时候，运行时照常干别的。以前校验就在收到请求的那个线程上
    /// 做，规则多的配置要几十到几百毫秒，这期间排在这个线程上的查询都等着；只有一个核的设备上所有查询都等着
    /// Validating a configuration does not hold a thread that serves DNS: while a large
    /// configuration is validated the runtime goes on with other work. Validation used to run on
    /// the thread that took the request, tens to hundreds of milliseconds for a configuration
    /// with many rules, with the queries queued on that thread waiting; on a single-core device,
    /// every query
    #[cfg(unix)]
    #[tokio::test]
    async fn validating_a_configuration_leaves_the_runtime_free() {
        let rules: Vec<serde_json::Value> = (0..1000)
            .map(|n| {
                serde_json::json!({
                    "name": format!("rule-{n}"),
                    "matchers": [{ "type": "domain_regex", "value": format!(r"^(ads?|track\d*)\.site{n}\.example$") }],
                    "actions": [{ "type": "forward", "upstream": "1.1.1.1:53" }]
                })
            })
            .collect();
        let config = serde_json::json!({
            "settings": { "default_upstream": "1.1.1.1:53" },
            "pipelines": [{ "id": "main", "rules": rules }]
        })
        .to_string();
        // 运行时上的另一件活：每轮到一次就数一下 / Other work on the runtime, counting each turn it gets
        let turns = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let counting = std::sync::Arc::clone(&turns);
        let other = tokio::spawn(async move {
            loop {
                counting.fetch_add(1, super::Ordering::Relaxed);
                tokio::task::yield_now().await;
            }
        });
        tokio::task::yield_now().await;

        let before = turns.load(super::Ordering::Relaxed);
        let response = super::validate_body(bytes::Bytes::from(config)).await;
        let during = turns.load(super::Ordering::Relaxed) - before;
        other.abort();
        assert_eq!(response.status(), hyper::StatusCode::OK);
        assert!(
            during > 1000,
            "the runtime had {during} turns for other work while validating"
        );
    }

    /// 算排行也不占着处理 DNS 的线程：几个钟头、几万个名字的排行在算的时候，运行时照常干别的
    /// Working out the rankings holds no thread that serves DNS either: with several hours and
    /// tens of thousands of names to rank, the runtime goes on with other work meanwhile
    #[cfg(unix)]
    #[tokio::test]
    async fn working_out_the_rankings_leaves_the_runtime_free() {
        let metrics = std::sync::Arc::new(PanelMetrics::default());
        let now = super::unix_timestamp();
        for hour in 0..6u64 {
            for n in 0..8_000u32 {
                metrics.query_stats.record_at(
                    &format!("name{n}.hour{hour}.example"),
                    std::net::IpAddr::from([10, 0, (n >> 8) as u8, n as u8]),
                    now - hour * 3_600,
                );
            }
        }
        let turns = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let counting = std::sync::Arc::clone(&turns);
        let other = tokio::spawn(async move {
            loop {
                counting.fetch_add(1, super::Ordering::Relaxed);
                tokio::task::yield_now().await;
            }
        });
        tokio::task::yield_now().await;

        let before = turns.load(super::Ordering::Relaxed);
        let response = super::stats_response(&metrics, 86_400, 20).await;
        let during = turns.load(super::Ordering::Relaxed) - before;
        other.abort();
        assert_eq!(response.status(), hyper::StatusCode::OK);
        assert!(
            during > 1000,
            "the runtime had {during} turns for other work while ranking"
        );
    }

    #[test]
    fn caps_metric_keys_and_counts_dropped_series() {
        let metrics = PanelMetrics::default();
        for index in 0..MAX_METRIC_SERIES_PER_MAP + 10 {
            metrics.record_pipeline_hit(&format!("pipeline-{index}"));
        }
        metrics.record_pipeline_hit("pipeline-0");

        assert_eq!(metrics.pipeline_hits.len(), MAX_METRIC_SERIES_PER_MAP);
        assert_eq!(
            metrics.metric_series_dropped.load(super::Ordering::Relaxed),
            10
        );
        assert_eq!(
            metrics.pipeline_hits.with("pipeline-0", |counter| counter
                .load(super::Ordering::Relaxed)),
            Some(2)
        );
    }

    /// 键在线程缓冲里拼：同一个统计项再计一次时累加在原来那条上，存下的键和以前拼出来的一样
    /// Keys are built in the thread's buffer: counting a series again adds to the same entry, and the
    /// stored key reads as it always did
    #[test]
    fn counting_again_adds_to_the_series_under_the_same_key() {
        let metrics = PanelMetrics::default();
        for _ in 0..3 {
            metrics.record_rule_match("main", "ads", "request");
            metrics.record_upstream_attempt("udp://192.0.2.1:53", "udp");
        }
        metrics.record_rule_match("main", "cn", "request");
        let count = |series: &super::Series<super::ThreadCount>, key: &str| {
            series.with(key, |counter| counter.load(super::Ordering::Relaxed))
        };
        assert_eq!(metrics.rule_matches.len(), 2);
        assert_eq!(count(&metrics.rule_matches, "main\0ads\0request"), Some(3));
        assert_eq!(count(&metrics.rule_matches, "main\0cn\0request"), Some(1));
        assert_eq!(metrics.upstream_attempts.len(), 1);
        assert_eq!(
            count(&metrics.upstream_attempts, "udp://192.0.2.1:53\0udp"),
            Some(3)
        );
    }

    /// 新的统计项换表时，正在计数的线程不会丢数：每个线程反复计一个公共项，同时各自加上新项
    /// Swapping the table for a new series loses no counts made meanwhile: every thread keeps counting a
    /// shared series while each adds new ones of its own
    #[test]
    fn counting_while_new_series_swap_the_table_loses_nothing() {
        let metrics = super::Arc::new(PanelMetrics::default());
        let threads: Vec<_> = (0..8)
            .map(|thread| {
                let metrics = metrics.clone();
                std::thread::spawn(move || {
                    for index in 0..1_000 {
                        metrics.record_pipeline_hit("shared");
                        if index % 20 == 0 {
                            metrics.record_pipeline_hit(&format!("thread-{thread}-{index}"));
                        }
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        let count = |key: &str| {
            metrics
                .pipeline_hits
                .with(key, |counter| counter.load(super::Ordering::Relaxed))
        };
        assert_eq!(count("shared"), Some(8_000));
        assert_eq!(metrics.pipeline_hits.len(), 1 + 8 * 50);
        assert_eq!(count("thread-7-980"), Some(1));
        assert_eq!(
            metrics.metric_series_dropped.load(super::Ordering::Relaxed),
            0
        );
    }

    /// 一个请求只在第一次查缓存时计数；结束后槽位清空
    /// A request counts only its first cache lookup; its slot is empty once it finishes
    #[test]
    fn a_request_counts_its_first_lookup_once() {
        let counted = super::LookupsCounted::default();
        assert!(counted.first(7));
        assert!(!counted.first(7));
        assert!(counted.first(8));
        counted.finished(7);
        counted.finished(8);
        assert!(counted.is_empty());
        // 没查过缓存的请求结束时什么都不动 / A request that never looked finishes without touching anything
        counted.finished(9);
        assert!(counted.is_empty());
    }

    /// 槽位被另一个还没结束的请求占着时，这个请求记在共享表里；之后槽位空出来，它再查一次也不重复计数
    /// When another running request holds the slot, the request is noted in the shared map; once the slot
    /// frees up, looking again still does not count twice
    #[test]
    fn a_request_whose_slot_is_taken_is_noted_aside() {
        let counted = super::LookupsCounted::with_slots(4);
        assert!(counted.first(1));
        assert!(counted.first(5), "slot 1 is taken by request 1");
        assert!(!counted.first(5));
        assert!(!counted.first(1));
        counted.finished(1);
        assert!(!counted.first(5), "request 5 is still counted aside");
        assert!(counted.first(9), "the freed slot goes to the next request");
        counted.finished(5);
        assert!(!counted.first(9));
        counted.finished(9);
        assert!(counted.is_empty());
    }

    #[test]
    fn observer_events_drive_counters_and_config_state() {
        use crate::observe::{
            ConfigLoaded, ConfigReloadFailed, DecisionKind, EngineObserver, RequestContext,
            RuleMatched, RulePhase,
        };

        let metrics = PanelMetrics::default();
        let source = r#"{"settings":{"statistics_enabled":true}}"#;
        metrics.config_loaded(&ConfigLoaded {
            path: Some(std::path::Path::new("pipeline.json")),
            generation: 1,
            source: Some(source),
            restart_pending: &[],
        });
        {
            let active = metrics.active_config.read();
            assert_eq!(active.generation, 1);
            assert_eq!(active.sha256.len(), 64);
            assert!(active.last_reload_success);
        }
        assert_eq!(metrics.reload_success.load(super::Ordering::Relaxed), 0);

        let ctx = request(1, "192.168.1.9:5353", "example.com");
        metrics.request_started(&ctx);
        metrics.pipeline_selected(&ctx, "main");
        metrics.cache_lookup(&ctx);
        metrics.rule_matched(
            &ctx,
            &RuleMatched {
                pipeline: "main",
                rule: "forward-all",
                phase: RulePhase::Request,
                decision: DecisionKind::Forward,
                fast_path: false,
            },
        );
        assert_eq!(metrics.requests_inflight.load(super::Ordering::Relaxed), 1);
        metrics.request_finished(&ctx, &completed(1));

        let background = RequestContext {
            background_refresh: true,
            ..ctx
        };
        metrics.request_started(&background);
        metrics.pipeline_selected(&background, "main");
        metrics.cache_lookup(&background);
        for phase in [RulePhase::Request, RulePhase::Response] {
            metrics.rule_matched(
                &background,
                &RuleMatched {
                    pipeline: "main",
                    rule: "forward-all",
                    phase,
                    decision: DecisionKind::Forward,
                    fast_path: false,
                },
            );
        }

        assert_eq!(metrics.requests_total.load(super::Ordering::Relaxed), 1);
        assert_eq!(metrics.requests_inflight.load(super::Ordering::Relaxed), 0);
        assert_eq!(
            metrics.cache_lookups_total.load(super::Ordering::Relaxed),
            1
        );
        let count = |series: &super::Series<super::ThreadCount>, key: &str| {
            series.with(key, |counter| counter.load(super::Ordering::Relaxed))
        };
        assert_eq!(count(&metrics.pipeline_hits, "main"), Some(1));
        assert_eq!(
            count(&metrics.rule_matches, "main\0forward-all\0request"),
            Some(1)
        );
        assert_eq!(
            count(&metrics.rule_matches, "main\0forward-all\0response"),
            None
        );
        let now = super::unix_timestamp();
        let snapshot = metrics.query_stats.snapshot(now, 3_600, 20);
        assert_eq!(snapshot.requests_observed, 1);
        assert_eq!(snapshot.domains[0].name, "example.com");

        metrics.config_reload_failed(&ConfigReloadFailed {
            path: std::path::Path::new("pipeline.json"),
            error: "broken",
        });
        metrics.config_loaded(&ConfigLoaded {
            path: Some(std::path::Path::new("pipeline.json")),
            generation: 2,
            source: Some("{}"),
            restart_pending: &[],
        });
        let active = metrics.active_config.read();
        assert_eq!(active.generation, 2);
        assert_eq!(metrics.reload_failure.load(super::Ordering::Relaxed), 1);
        assert_eq!(metrics.reload_success.load(super::Ordering::Relaxed), 1);
        // A reload leaves the rankings alone, whatever the config says about them
        // 重载不动排行，不管配置里怎么写
        assert_eq!(
            metrics
                .query_stats
                .snapshot(now, 3_600, 20)
                .requests_observed,
            1
        );
    }

    #[test]
    fn response_latency_counts_only_attempts_that_got_a_reply() {
        use crate::config::Transport;
        use crate::observe::{EngineObserver, UpstreamOutcome};
        use hickory_proto::op::ResponseCode;

        let metrics = PanelMetrics::default();
        let ctx = request(1, "127.0.0.1:5353", "example.com");
        let result = |outcome, rcode, millis| udp_result(outcome, Transport::Udp, rcode, millis);
        metrics.upstream_result(
            &ctx,
            &result(UpstreamOutcome::Success, Some(ResponseCode::NoError), 12),
        );
        metrics.upstream_result(
            &ctx,
            &result(UpstreamOutcome::Rejected, Some(ResponseCode::ServFail), 20),
        );
        // 超时：整段超时计入已结算耗时，但不计入响应耗时。
        // A timeout: the whole timeout counts toward the settled latency only.
        metrics.upstream_result(&ctx, &result(UpstreamOutcome::Error, None, 9_000));
        metrics.upstream_result(&ctx, &result(UpstreamOutcome::Aborted, None, 500));

        let mut output = String::new();
        metrics.render_counters(&mut output);
        let has = |line: &str| output.lines().any(|candidate| candidate == line);
        assert!(has(
            "kixdns_upstream_latency_ms_sum{upstream=\"1.1.1.1:53\",transport=\"udp\"} 9032.000"
        ));
        assert!(has(
            "kixdns_upstream_latency_ms_count{upstream=\"1.1.1.1:53\",transport=\"udp\"} 3"
        ));
        assert!(has(
            "kixdns_upstream_response_latency_ms_sum{upstream=\"1.1.1.1:53\",transport=\"udp\"} 32.000"
        ));
        assert!(has(
            "kixdns_upstream_response_latency_ms_count{upstream=\"1.1.1.1:53\",transport=\"udp\"} 2"
        ));
    }

    /// DoH 上游回了 429：算一次尝试和一个 `throttled` 结果，不进耗时、实际传输和响应码；暂停中没问的
    /// 上游不进任何指标
    /// A DoH upstream answering 429 counts one attempt and one `throttled` result, and stays
    /// out of latency, transport used and response codes; an upstream not asked during its
    /// pause is in no metric at all
    #[test]
    fn a_throttled_answer_counts_as_an_attempt_and_a_result_only() {
        use crate::config::Transport;
        use crate::observe::{
            EngineObserver, UpstreamAttempt, UpstreamOutcome, UpstreamResult, UpstreamSkipReason,
            UpstreamSkipped,
        };
        use std::time::Duration;

        let metrics = PanelMetrics::default();
        let ctx = request(1, "127.0.0.1:5353", "example.com");
        let upstream = "doh.example/dns-query";
        let error = anyhow::anyhow!("doh http status 429 Too Many Requests");
        metrics.upstream_attempt(
            &ctx,
            &UpstreamAttempt {
                upstream,
                transport: Transport::Doh,
            },
        );
        metrics.upstream_result(
            &ctx,
            &UpstreamResult {
                upstream,
                transport: Transport::Doh,
                via: Transport::Doh,
                outcome: UpstreamOutcome::Throttled,
                latency: Duration::from_millis(3),
                rcode: None,
                truncated: None,
                error: Some(&error),
            },
        );
        metrics.upstream_skipped(
            &ctx,
            &UpstreamSkipped {
                upstream,
                transport: Transport::Doh,
                reason: UpstreamSkipReason::Throttled,
            },
        );

        let mut output = String::new();
        metrics.render_counters(&mut output);
        let series: Vec<&str> = output
            .lines()
            .filter(|line| line.contains(upstream))
            .collect();
        assert_eq!(
            series,
            vec![
                "kixdns_upstream_attempts_total{upstream=\"doh.example/dns-query\",transport=\"doh\"} 1",
                "kixdns_upstream_results_total{upstream=\"doh.example/dns-query\",transport=\"doh\",result=\"throttled\"} 1",
            ],
            "{output}"
        );
    }

    #[test]
    fn latency_rcode_via_and_stale_reason_series_render() {
        use crate::config::Transport;
        use crate::observe::{
            CacheHit, CacheHitKind, EngineObserver, RequestOutcome, RequestStatus, UpstreamOutcome,
        };
        use hickory_proto::op::ResponseCode;
        use std::time::Duration;

        let metrics = PanelMetrics::default();
        let ctx = request(1, "127.0.0.1:5353", "example.com");
        metrics.upstream_result(
            &ctx,
            &udp_result(
                UpstreamOutcome::Success,
                Transport::Udp,
                Some(ResponseCode::NoError),
                12,
            ),
        );
        metrics.upstream_result(
            &ctx,
            &udp_result(
                UpstreamOutcome::Success,
                Transport::Tcp,
                Some(ResponseCode::NXDomain),
                30,
            ),
        );
        // 竞争落败不计入耗时、响应码和传输 / aborted attempts never reach latency, rcode or via
        metrics.upstream_result(
            &ctx,
            &udp_result(UpstreamOutcome::Aborted, Transport::Udp, None, 500),
        );

        for (kind, remaining) in [
            (CacheHitKind::Fresh, Some(Duration::from_secs(30))),
            (CacheHitKind::Stale, None),
            (CacheHitKind::StaleClientTimeout, None),
            (CacheHitKind::StaleUpstreamFailure, None),
        ] {
            metrics.cache_hit(
                &ctx,
                &CacheHit {
                    kind,
                    remaining_ttl: remaining,
                    original_ttl: None,
                    source: None,
                },
            );
        }

        metrics.request_started(&ctx);
        metrics.request_finished(&ctx, &completed(7));
        metrics.request_started(&ctx);
        metrics.request_finished(
            &ctx,
            &RequestOutcome {
                latency: Duration::from_millis(1_500),
                status: RequestStatus::Cancelled,
                response: None,
                error: None,
            },
        );

        let mut output = String::new();
        metrics.render_counters(&mut output);
        let has = |line: &str| output.lines().any(|candidate| candidate == line);
        assert!(has("kixdns_cache_hits_total{kind=\"stale\"} 3"));
        assert!(has("kixdns_cache_stale_total{reason=\"expired\"} 1"));
        assert!(has("kixdns_cache_stale_total{reason=\"client_timeout\"} 1"));
        assert!(has(
            "kixdns_cache_stale_total{reason=\"upstream_failure\"} 1"
        ));
        assert!(has(
            "kixdns_requests_finished_total{status=\"completed\"} 1"
        ));
        assert!(has(
            "kixdns_requests_finished_total{status=\"cancelled\"} 1"
        ));
        assert!(has("kixdns_request_latency_ms_bucket{le=\"10\"} 1"));
        assert!(has("kixdns_request_latency_ms_bucket{le=\"1000\"} 1"));
        assert!(has("kixdns_request_latency_ms_bucket{le=\"+Inf\"} 2"));
        assert!(has("kixdns_request_latency_ms_sum 1507.000"));
        assert!(has("kixdns_request_latency_ms_count 2"));
        assert!(has(
            "kixdns_upstream_latency_ms_sum{upstream=\"1.1.1.1:53\",transport=\"udp\"} 42.000"
        ));
        assert!(has(
            "kixdns_upstream_latency_ms_count{upstream=\"1.1.1.1:53\",transport=\"udp\"} 2"
        ));
        assert!(has(
            "kixdns_upstream_rcodes_total{upstream=\"1.1.1.1:53\",rcode=\"NoError\"} 1"
        ));
        assert!(has(
            "kixdns_upstream_rcodes_total{upstream=\"1.1.1.1:53\",rcode=\"NXDomain\"} 1"
        ));
        assert!(has(
            "kixdns_upstream_via_total{upstream=\"1.1.1.1:53\",transport=\"udp\",via=\"tcp\"} 1"
        ));
        assert!(has(
            "kixdns_upstream_results_total{upstream=\"1.1.1.1:53\",transport=\"udp\",result=\"aborted\"} 1"
        ));
        assert_eq!(super::format_millis(1_234_567), "1234.567");
    }

    #[test]
    fn ranks_domains_and_clients_by_their_full_address() {
        let stats = QueryStats::default();
        let now = 100 * super::QUERY_STATS_BUCKET_SECONDS + 120;
        for _ in 0..3 {
            stats.record_at("example.com", "192.168.1.42".parse().unwrap(), now);
        }
        stats.record_at("other.test", "192.168.1.9".parse().unwrap(), now);
        stats.record_at("other.test", "2001:db8::1".parse().unwrap(), now);

        let snapshot = stats.snapshot(now, 3_600, 20);
        assert_eq!(snapshot.requests_observed, 5);
        assert_eq!(snapshot.domains[0].name, "example.com");
        assert_eq!(snapshot.domains[0].count, 3);
        assert_eq!(snapshot.clients[0].name, "192.168.1.42");
        assert_eq!(snapshot.clients[0].count, 3);
        let mut others = snapshot.clients[1..]
            .iter()
            .map(|row| row.name.as_str())
            .collect::<Vec<_>>();
        others.sort_unstable();
        assert_eq!(others, ["192.168.1.9", "2001:db8::1"]);
    }

    /// 配置里关掉统计、打开脱敏的写法照样能读，但排行照常统计完整地址
    /// A config that switches statistics off and anonymization on still loads, and
    /// the rankings go on counting whole addresses
    #[test]
    fn old_statistics_settings_load_and_change_nothing() {
        let config = crate::config::parse_config(
            r#"{"settings":{"statistics_enabled":false,"statistics_anonymize_client_ip":true}}"#,
        )
        .expect("old settings still load");
        assert!(!config.settings.statistics_enabled);
        let metrics = PanelMetrics::new(false);
        metrics.record_config_loaded(
            r#"{"settings":{"statistics_enabled":false,"statistics_anonymize_client_ip":true}}"#,
            Vec::new(),
        );
        metrics.record_query(
            "example.com",
            "192.168.1.42".parse().unwrap(),
            std::time::Instant::now(),
        );
        let snapshot = metrics
            .query_stats
            .snapshot(super::unix_timestamp(), 3_600, 20);
        assert_eq!(snapshot.requests_observed, 1);
        assert_eq!(snapshot.clients[0].name, "192.168.1.42");
    }

    #[test]
    fn caps_unique_domains_and_reports_dropped_updates() {
        let stats = QueryStats::default();
        let client: IpAddr = "127.0.0.1".parse().unwrap();
        for index in 0..QUERY_STATS_DOMAIN_CAP + 8 {
            stats.record_at(&format!("{index}.example"), client, 3_600);
        }

        let snapshot = stats.snapshot(3_600, 3_600, QUERY_STATS_DOMAIN_CAP + 8);
        assert_eq!(snapshot.domains.len(), QUERY_STATS_DOMAIN_CAP);
        assert_eq!(snapshot.dropped_updates, 8);

        // 满了以后已经在榜上的名字照样计数 / Once full, names already ranked still count
        stats.record_at("0.example", client, 3_600);
        let snapshot = stats.snapshot(3_600, 3_600, QUERY_STATS_DOMAIN_CAP + 8);
        assert_eq!(snapshot.domains[0].name, "0.example");
        assert_eq!(snapshot.domains[0].count, 2);
        assert_eq!(snapshot.dropped_updates, 8);
    }

    #[test]
    fn caps_unique_clients_and_keeps_counting_ranked_ones() {
        let stats = QueryStats::default();
        let client = |index: usize| IpAddr::from(Ipv4Addr::from(0x0a00_0000 + index as u32));
        for index in 0..QUERY_STATS_CLIENT_CAP + 8 {
            stats.record_at("example.com", client(index), 3_600);
        }
        stats.record_at("example.com", client(0), 3_600);

        let snapshot = stats.snapshot(3_600, 3_600, QUERY_STATS_CLIENT_CAP + 8);
        assert_eq!(snapshot.clients.len(), QUERY_STATS_CLIENT_CAP);
        assert_eq!(snapshot.dropped_updates, 8);
        assert_eq!(snapshot.clients[0].name, "10.0.0.0");
        assert_eq!(snapshot.clients[0].count, 2);
    }

    /// 线程各写各的格子，读到的是总数；线程比格子多时共用一格，也一样
    /// Threads write cells of their own and reading gives the total; with more threads than cells some
    /// share one, and it is the same
    #[test]
    fn a_thread_count_adds_up_across_threads() {
        use super::{COUNT_CELLS, ThreadCount, thread_cell};
        let count = std::sync::Arc::new(ThreadCount::default());
        let threads = (0..COUNT_CELLS + 8)
            .map(|index| {
                let count = std::sync::Arc::clone(&count);
                std::thread::spawn(move || {
                    for _ in 0..1_000 {
                        count.fetch_add(1, super::Ordering::Relaxed);
                    }
                    count.fetch_add(index as u64, super::Ordering::Relaxed);
                    thread_cell()
                })
            })
            .collect::<Vec<_>>();
        let cells = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<std::collections::HashSet<_>>();
        let threads = COUNT_CELLS + 8;
        let extra = threads * (threads - 1) / 2;
        assert_eq!(
            count.load(super::Ordering::Relaxed),
            (threads * 1_000 + extra) as u64
        );
        assert!(cells.len() > 1, "threads write apart: {cells:?}");
    }

    /// 几个线程记同一个域名和客户端，合起来就是一项，数是总数；各记各的也都在
    /// Several threads counting one name and client make one entry with the total; what each counted alone
    /// is there too
    #[test]
    fn rankings_counted_on_several_threads_merge() {
        const THREADS: usize = super::COUNT_CELLS + 4;
        let stats = std::sync::Arc::new(QueryStats::default());
        let client: IpAddr = "192.0.2.1".parse().unwrap();
        let threads = (0..THREADS)
            .map(|index| {
                let stats = std::sync::Arc::clone(&stats);
                std::thread::spawn(move || {
                    for _ in 0..100 {
                        stats.record_at("shared.example", client, 3_600);
                    }
                    stats.record_at(&format!("own-{index}.example"), client, 3_600);
                })
            })
            .collect::<Vec<_>>();
        for thread in threads {
            thread.join().unwrap();
        }
        let snapshot = stats.snapshot(3_600, 3_600, THREADS + 8);
        assert_eq!(snapshot.requests_observed, (THREADS * 101) as u64);
        assert_eq!(snapshot.dropped_updates, 0);
        assert_eq!(snapshot.domains.len(), THREADS + 1);
        assert_eq!(snapshot.domains[0].name, "shared.example");
        assert_eq!(snapshot.domains[0].count, (THREADS * 100) as u64);
        assert_eq!(snapshot.clients.len(), 1);
        assert_eq!(snapshot.clients[0].count, (THREADS * 101) as u64);
    }

    /// 这一格正在换钟头时来的查询都等它换完再记，一条不丢，也不会有人把别人刚记下的又清掉
    /// Queries arriving while a bucket changes hour all wait and then count: none is lost, and none clears
    /// what another has just counted
    #[test]
    fn queries_during_the_change_of_hour_all_count() {
        const QUERIES: usize = 8;
        let stats = QueryStats::default();
        let client: IpAddr = "192.0.2.1".parse().unwrap();
        let changing = stats.buckets[1].rotate_lock.lock();
        std::thread::scope(|scope| {
            let queries = (0..QUERIES)
                .map(|_| scope.spawn(|| stats.record_at("a.example", client, 3_600)))
                .collect::<Vec<_>>();
            // 给它们时间走到锁那里；没走到也不会误报，只是这一次没测到
            // Time for them to reach the lock; one that has not cannot fail this, it just goes untested
            std::thread::sleep(std::time::Duration::from_millis(50));
            assert!(queries.iter().all(|query| !query.is_finished()));
            drop(changing);
        });
        let snapshot = stats.snapshot(3_600, 3_600, 10);
        assert_eq!(snapshot.requests_observed, QUERIES as u64);
        assert_eq!(snapshot.domains[0].count, QUERIES as u64);
    }

    /// 换钟头的线程一直拿着锁，换完才露出新的钟头：只有它一个在清空这一格，别人也不会记进还没清空的表
    /// The thread changing the hour holds the lock throughout and shows the new hour only once done: it alone
    /// empties the bucket, and nobody counts into a table not yet emptied
    #[test]
    fn a_change_of_hour_holds_the_lock_until_it_is_done() {
        let bucket = QueryStatsBucket::new();
        let last_shard = bucket.shards.last().unwrap().lock();
        std::thread::scope(|scope| {
            scope.spawn(|| bucket.prepare(3_600));
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while !bucket.rotate_lock.is_locked() && std::time::Instant::now() < deadline {
                std::thread::yield_now();
            }
            // 它现在卡在最后一个分片上，过一会儿还是这样 / It is stuck on the last shard, and still is a moment later
            std::thread::sleep(std::time::Duration::from_millis(20));
            assert!(bucket.rotate_lock.is_locked());
            assert_eq!(bucket.epoch.load(Ordering::Acquire), 0);
            drop(last_shard);
        });
        assert_eq!(bucket.epoch.load(Ordering::Acquire), 3_600);
    }

    /// 条数上限算的是所有线程加起来：一起来很多新名字也不会超，多出来的记成丢弃
    /// The cap on entries is across all threads: however many new names come at once it is not passed, and
    /// those beyond it count as dropped
    #[test]
    fn the_cap_on_entries_holds_across_threads() {
        const THREADS: usize = 8;
        let stats = std::sync::Arc::new(QueryStats::default());
        let client: IpAddr = "192.0.2.1".parse().unwrap();
        let each = QUERY_STATS_DOMAIN_CAP / THREADS + 100;
        let threads = (0..THREADS)
            .map(|thread| {
                let stats = std::sync::Arc::clone(&stats);
                std::thread::spawn(move || {
                    for index in 0..each {
                        stats.record_at(&format!("{thread}-{index}.example"), client, 3_600);
                    }
                })
            })
            .collect::<Vec<_>>();
        for thread in threads {
            thread.join().unwrap();
        }
        let snapshot = stats.snapshot(3_600, 3_600, QUERY_STATS_DOMAIN_CAP * 2);
        assert_eq!(snapshot.domains.len(), QUERY_STATS_DOMAIN_CAP);
        assert_eq!(
            snapshot.dropped_updates,
            (THREADS * each - QUERY_STATS_DOMAIN_CAP) as u64
        );
        assert_eq!(snapshot.requests_observed, (THREADS * each) as u64);
    }

    /// 同一格过了一天再用到时，客户端的条数上限也重新算 / When a bucket comes round a day later the cap on
    /// clients starts over too
    #[test]
    fn a_bucket_used_again_a_day_later_has_room_for_clients() {
        let stats = QueryStats::default();
        let hour = QUERY_STATS_BUCKET_SECONDS;
        let day = hour * QUERY_STATS_BUCKETS as u64;
        for index in 0..=QUERY_STATS_CLIENT_CAP {
            let client = IpAddr::from(Ipv4Addr::from(0x0a00_0000 + index as u32));
            stats.record_at("a.example", client, hour);
        }
        assert_eq!(stats.snapshot(hour, hour, 1).dropped_updates, 1);
        let new_client = IpAddr::from(Ipv4Addr::new(192, 0, 2, 1));
        stats.record_at("a.example", new_client, hour + day);
        let after = stats.snapshot(hour + day, day, 10);
        assert_eq!(after.dropped_updates, 0);
        assert_eq!(after.clients.len(), 1);
        assert_eq!(after.clients[0].name, "192.0.2.1");
    }

    /// 一个钟头一格，24 格轮着用：同一格过了一天再用到时，先清空再记，旧的计数、名字、客户端和丢弃数
    /// 都不留，满了的名字上限也重新算
    /// One bucket per hour, 24 used in turn: when a bucket comes round again a day later it
    /// is emptied before recording, keeping none of the old counts, names, clients or
    /// dropped updates, and the full name cap starts over
    #[test]
    fn a_bucket_used_again_a_day_later_starts_from_nothing() {
        let stats = QueryStats::default();
        let hour = QUERY_STATS_BUCKET_SECONDS;
        let day = hour * QUERY_STATS_BUCKETS as u64;
        let old_client = IpAddr::from(Ipv4Addr::new(10, 0, 0, 1));
        for index in 0..=QUERY_STATS_DOMAIN_CAP {
            stats.record_at(&format!("d{index}.example"), old_client, hour);
        }
        let before = stats.snapshot(hour, hour, 1);
        assert_eq!(before.requests_observed, QUERY_STATS_DOMAIN_CAP as u64 + 1);
        assert_eq!(before.dropped_updates, 1);

        let new_client = IpAddr::from(Ipv4Addr::new(10, 0, 0, 2));
        stats.record_at("new.example", new_client, hour + day);
        let after = stats.snapshot(hour + day, day, 10);
        assert_eq!(after.requests_observed, 1);
        assert_eq!(after.dropped_updates, 0);
        let rows = |rows: &[TopStat]| {
            rows.iter()
                .map(|row| (row.name.clone(), row.count))
                .collect::<Vec<_>>()
        };
        assert_eq!(rows(&after.domains), [("new.example".to_string(), 1)]);
        assert_eq!(rows(&after.clients), [("10.0.0.2".to_string(), 1)]);
    }

    /// 诊断只接受九种记录类型，大小写和两边的空白不论，编出的查询问的就是那种类型；别的类型一律拒绝
    /// A diagnostic takes nine record types only, whatever their case and surrounding
    /// blanks, and the query it encodes asks for that type; any other type is refused
    #[cfg(unix)]
    #[test]
    fn a_diagnostic_asks_one_of_nine_record_types() {
        use hickory_proto::rr::RecordType;
        for (written, expected) in [
            ("A", RecordType::A),
            (" aaaa ", RecordType::AAAA),
            ("cname", RecordType::CNAME),
            ("Mx", RecordType::MX),
            ("NS", RecordType::NS),
            ("ptr", RecordType::PTR),
            ("SOA", RecordType::SOA),
            ("srv", RecordType::SRV),
            ("TXT", RecordType::TXT),
        ] {
            let (packet, normalized) = super::diagnostic_packet("nas.example", written).unwrap();
            let message = hickory_proto::op::Message::from_vec(&packet).unwrap();
            assert_eq!(message.queries[0].query_type(), expected, "{written}");
            assert_eq!(normalized, written.trim().to_ascii_uppercase());
        }
        for written in ["HTTPS", "ANY", "AXFR", "", "A AAAA", "TYPE1"] {
            let (status, body) = super::diagnostic_packet("nas.example", written).unwrap_err();
            assert_eq!(status, super::StatusCode::BAD_REQUEST, "{written}");
            assert_eq!(body["error"]["code"], "diagnostic_record_type_invalid");
            assert_eq!(body["error"]["message"], "不支持的 DNS 记录类型");
        }
    }

    /// 同一个名字、同一个客户端分在几个钟头里记，窗口覆盖到的几格加起来算
    /// The same name and client recorded in several hours add up over the buckets the
    /// window covers
    #[test]
    fn counts_from_several_hours_add_up() {
        let stats = QueryStats::default();
        let hour = QUERY_STATS_BUCKET_SECONDS;
        let client = IpAddr::from(Ipv4Addr::new(10, 0, 0, 1));
        stats.record_at("a.example", client, hour);
        stats.record_at("a.example", client, 2 * hour);
        stats.record_at("a.example", client, 2 * hour + 1);
        let snapshot = stats.snapshot(2 * hour, 2 * hour, 10);
        assert_eq!(snapshot.requests_observed, 3);
        assert_eq!(snapshot.domains[0].count, 3);
        assert_eq!(snapshot.clients[0].count, 3);
    }

    /// 排行接口照旧带着 enabled 和 anonymized_clients，写的是一直开着、不脱敏；清空后从零开始
    /// The rankings endpoint still carries enabled and anonymized_clients, saying always
    /// on and not anonymized; after a clear it starts from zero
    #[cfg(unix)]
    #[test]
    fn stats_json_says_always_on_with_whole_addresses_and_clears() {
        let metrics = PanelMetrics::default();
        metrics.record_query(
            "example.com",
            "192.168.1.42".parse().unwrap(),
            std::time::Instant::now(),
        );
        let stats = metrics.stats_json(3_600, 20);
        assert_eq!(stats["enabled"], true);
        assert_eq!(stats["anonymized_clients"], false);
        assert_eq!(stats["requests_observed"], 1);
        assert_eq!(stats["clients"][0]["name"], "192.168.1.42");
        assert_eq!(stats["domains"][0]["name"], "example.com");

        metrics.clear_stats();
        let stats = metrics.stats_json(3_600, 20);
        assert_eq!(stats["requests_observed"], 0);
        assert_eq!(stats["clients"], serde_json::json!([]));
        assert_eq!(stats["domains"], serde_json::json!([]));
    }
}

#[cfg(all(test, unix))]
mod diagnostic_tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use hyper::StatusCode;
    use serde_json::json;

    use super::{
        CandidateTraceRequest, DiagnosticRequest, PanelMetrics, TrialInput, diagnostic_packet,
        run_diagnostic, run_trial,
    };
    use crate::engine::Engine;
    use crate::matcher::RuntimePipelineConfig;

    /// 家里网段回 10.0.0.1，其余回 10.0.0.2：只靠静态回答，不出网 / The home subnet gets 10.0.0.1 and everyone else 10.0.0.2: static answers only, no network
    fn client_split_config(home: &str) -> serde_json::Value {
        json!({
            "settings": { "default_upstream": "1.1.1.1:53", "udp_pool_size": 1 },
            "pipelines": [{
                "id": "main",
                "rules": [
                    {
                        "name": "home",
                        "matchers": [{ "type": "client_ip", "cidr": home }],
                        "actions": [{ "type": "static_ip_response", "ip": "10.0.0.1" }]
                    },
                    {
                        "name": "rest",
                        "matchers": [{ "type": "any" }],
                        "actions": [{ "type": "static_ip_response", "ip": "10.0.0.2" }]
                    }
                ]
            }]
        })
    }

    /// 真引擎上规则直接答的请求整个交给面板：记录、计数都对，也不留着「在处理」
    /// A rule's answer on a real engine reaches the panel whole: the record and the counters are right, and
    /// nothing stays in flight
    #[tokio::test]
    async fn a_rule_answer_reaches_the_panel_whole() {
        use crate::engine::FastPathResponse;
        use std::sync::atomic::Ordering;

        let raw = serde_json::json!({
            "settings": { "default_upstream": "127.0.0.1:9" },
            "pipelines": [{ "id": "main", "rules": [{
                "name": "block",
                "matchers": [{ "type": "domain_suffix", "value": "blocked.test" }],
                "actions": [{ "type": "static_ip_response", "ip": "0.0.0.0" }]
            }] }]
        });
        let metrics = Arc::new(PanelMetrics::new(false));
        let engine = engine_for(raw, Arc::clone(&metrics));
        let peer: std::net::SocketAddr = "192.0.2.7:53000".parse().unwrap();
        let mut query = hickory_proto::op::Message::new(
            0x1234,
            hickory_proto::op::MessageType::Query,
            hickory_proto::op::OpCode::Query,
        );
        query.metadata.recursion_desired = true;
        query.add_query(hickory_proto::op::Query::query(
            hickory_proto::rr::Name::from_ascii("a.blocked.test.").unwrap(),
            hickory_proto::rr::RecordType::A,
        ));
        assert!(matches!(
            engine
                .handle_packet_fast(&query.to_vec().unwrap(), peer)
                .unwrap(),
            Some(FastPathResponse::Direct(_))
        ));
        assert_eq!(metrics.requests_total.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.requests_inflight.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.requests_completed.load(Ordering::Relaxed), 1);
        let page: serde_json::Value =
            serde_json::from_str(&metrics.query_log.collect(0, 10, None, None, None, 1)).unwrap();
        let entries = page["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry["outcome"], "static");
        assert_eq!(entry["pipeline"], "main");
        assert_eq!(entry["rule"], "block");
        assert_eq!(entry["answers"][0], "0.0.0.0");
        let kinds: Vec<&str> = entry["steps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|step| step["kind"].as_str().unwrap())
            .collect();
        assert_eq!(kinds, ["pipeline", "cache", "rule"]);
        assert_eq!(entry["steps"][2]["decision"], "static");
    }

    /// 真引擎的快速路径命中整个交给面板：记录、计数都对，也不留着「在处理」
    /// A real engine's fast-path hit reaches the panel whole: the record and the counters are right,
    /// and nothing stays in flight
    #[tokio::test]
    async fn a_fast_path_hit_reaches_the_panel_whole() {
        use crate::engine::FastPathResponse;
        use std::sync::atomic::Ordering;

        let raw = serde_json::json!({
            "settings": { "default_upstream": "127.0.0.1:9", "min_ttl": 60 },
            "pipelines": [{ "id": "main", "rules": [{
                "name": "block",
                "matchers": [{ "type": "domain_suffix", "value": "blocked.test" }],
                "actions": [{ "type": "static_response", "rcode": "NXDOMAIN" }]
            }] }]
        });
        let metrics = Arc::new(PanelMetrics::new(false));
        let engine = engine_for(raw, Arc::clone(&metrics));
        let peer: std::net::SocketAddr = "192.0.2.7:53000".parse().unwrap();
        let mut query = hickory_proto::op::Message::new(
            0x1234,
            hickory_proto::op::MessageType::Query,
            hickory_proto::op::OpCode::Query,
        );
        query.metadata.recursion_desired = true;
        query.add_query(hickory_proto::op::Query::query(
            hickory_proto::rr::Name::from_ascii("a.blocked.test.").unwrap(),
            hickory_proto::rr::RecordType::A,
        ));
        let query = query.to_vec().unwrap();
        engine.handle_packet(&query, peer).await.unwrap();
        assert!(matches!(
            engine.handle_packet_fast(&query, peer).unwrap(),
            Some(FastPathResponse::CacheHit { .. })
        ));
        assert_eq!(metrics.requests_total.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.requests_inflight.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.requests_completed.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.cache_hits_fresh.load(Ordering::Relaxed), 1);
        let page: serde_json::Value =
            serde_json::from_str(&metrics.query_log.collect(0, 10, None, None, None, 1)).unwrap();
        let entries = page["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 2);
        let cached = &entries[1];
        assert_eq!(cached["outcome"], "cached");
        assert_eq!(cached["qname"], "a.blocked.test");
        assert_eq!(cached["pipeline"], "main");
        assert_eq!(cached["rcode"], "NXDOMAIN");
        assert_eq!(cached["steps"][0]["kind"], "pipeline");
        assert_eq!(cached["steps"][1]["kind"], "cache");
        assert_eq!(cached["steps"][1]["result"], "fresh");
    }

    /// 照启动和重载的路子读配置（`parse_config`）/ Reads a config the way startup and reload do
    /// (`parse_config`)
    fn runtime_for(raw: serde_json::Value) -> RuntimePipelineConfig {
        let config = crate::config::parse_config(&raw.to_string()).expect("parse config");
        RuntimePipelineConfig::from_config(config).expect("build runtime config")
    }

    fn engine_for(raw: serde_json::Value, metrics: Arc<PanelMetrics>) -> Engine {
        Engine::builder(runtime_for(raw))
            .listener_label("default")
            .observer(metrics)
            .build()
            .expect("build engine")
    }

    /// 控制通道的 config 列出改了但要重启才生效的设置；改回去以后不再列
    /// The control channel's config lists the settings changed that take a restart to
    /// apply; once changed back they are no longer listed
    #[tokio::test]
    async fn config_reports_the_settings_waiting_for_a_restart() {
        let raw = |bind: &str, timeout_ms: u64| {
            serde_json::json!({
                "settings": {
                    "bind_udp": bind,
                    "default_upstream": "127.0.0.1:9",
                    "upstream_timeout_ms": timeout_ms
                },
                "pipelines": [{ "id": "main", "rules": [{
                    "name": "rest", "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "static_ip_response", "ip": "10.0.0.2" }]
                }] }]
            })
        };
        let metrics = Arc::new(PanelMetrics::new(false));
        let engine = engine_for(raw("127.0.0.1:5353", 2000), Arc::clone(&metrics));
        assert_eq!(
            metrics.config_json()["restart_pending"],
            serde_json::json!([])
        );

        engine.reload(runtime_for(raw("127.0.0.1:5354", 3000)));
        assert_eq!(
            metrics.config_json()["restart_pending"],
            serde_json::json!(["bind_udp"]),
            "the listener only moves on a restart, the timeout applies at once"
        );
        engine.reload(runtime_for(raw("127.0.0.1:5353", 3000)));
        assert_eq!(
            metrics.config_json()["restart_pending"],
            serde_json::json!([])
        );
    }

    /// 诊断回复里有一条回答写着这个地址 / Some answer in the diagnostic reply names this address
    fn answered(body: &serde_json::Value, address: &str) -> bool {
        body["answers"]
            .as_array()
            .expect("answers")
            .iter()
            .any(|answer| answer.as_str().unwrap_or_default().contains(address))
    }

    /// 诊断的域名按查询日志写名字的方式读（见 `proto_utils::name_text`）：`\DDD` 是十进制，大小写
    /// 照写；查询日志写出的名字拿来诊断，问的就是同一个名字
    /// A diagnostic domain is read the way the query log writes names (see
    /// `proto_utils::name_text`): `\DDD` is decimal and the case is kept; a name taken from
    /// the query log asks for that same name
    #[test]
    fn a_diagnostic_domain_is_read_as_the_query_log_writes_it() {
        use hickory_proto::op::Message;
        let labels = |domain: &str| {
            let (packet, _) = diagnostic_packet(domain, "A").expect(domain);
            let message = Message::from_vec(&packet).expect("a readable query");
            message.queries[0]
                .name()
                .iter()
                .map(<[u8]>::to_vec)
                .collect::<Vec<_>>()
        };
        // Decimal 101 is `e`; read as octal it would be `A`
        // 十进制 101 是 `e`，按八进制读会是 `A`
        assert_eq!(labels(r"x\101y.example"), [&b"xey"[..], b"example"]);
        assert_eq!(
            labels(r"www\046matched.test"),
            [&b"www.matched"[..], b"test"]
        );
        assert_eq!(
            labels(r"caf\195\169.example"),
            [&b"caf\xc3\xa9"[..], b"example"]
        );
        assert_eq!(
            labels("WWW.Example.COM."),
            [&b"WWW"[..], b"Example", b"COM"]
        );
        for labels_in in [
            vec![&b"x\xffy"[..], b"blocked", b"test"],
            vec![&b"a b"[..], b"back\\slash", b"test"],
        ] {
            let name = hickory_proto::rr::Name::from_labels(labels_in.clone()).unwrap();
            assert_eq!(labels(&crate::proto_utils::name_text(&name)), labels_in);
        }
        for invalid in [
            "a..b",
            r"x\9y.test",
            r"x\256y.test",
            "caf\u{e9}.example",
            "a b.test",
        ] {
            let (status, body) = diagnostic_packet(invalid, "A").expect_err(invalid);
            assert_eq!(status, StatusCode::BAD_REQUEST, "{invalid}");
            assert_eq!(
                body["error"]["code"], "diagnostic_domain_invalid",
                "{invalid}"
            );
        }
    }

    /// 诊断域名的长度按线上字节算（最多 255），不按文本：每个字节都写成 \\DDD 的 255 字节名字，文本
    /// 有一千多个字符，也照收；多一个字节就是「域名过长」
    /// A diagnostic domain is measured on the wire (at most 255 bytes), not by its text: a
    /// 255-byte name with every byte written \\DDD, over a thousand characters, is taken; one
    /// byte more is 「域名过长」
    #[test]
    fn a_diagnostic_domain_is_measured_on_the_wire() {
        use hickory_proto::op::Message;
        let escaped = |sizes: &[usize]| {
            sizes
                .iter()
                .map(|&size| r"\255".repeat(size))
                .collect::<Vec<_>>()
                .join(".")
        };
        let plain = |sizes: &[usize]| {
            sizes
                .iter()
                .zip(b'a'..)
                .map(|(&size, letter)| (letter as char).to_string().repeat(size))
                .collect::<Vec<_>>()
                .join(".")
        };
        let longest = escaped(&[63, 63, 63, 61]);
        assert!(longest.len() > 1000);
        let plain_longest = plain(&[63, 63, 63, 61]);
        assert_eq!(plain_longest.len(), 253);
        for (domain, first) in [(&longest, 0xFF), (&plain_longest, b'a')] {
            let (packet, _) = diagnostic_packet(domain, "A").expect("a 255-byte name");
            let message = Message::from_vec(&packet).expect("a readable query");
            let name = message.queries[0].name();
            assert_eq!(
                name.iter().map(<[u8]>::len).collect::<Vec<_>>(),
                [63, 63, 63, 61]
            );
            assert_eq!(name.iter().next().unwrap()[0], first);
        }
        for too_long in [escaped(&[63, 63, 63, 62]), plain(&[63, 63, 63, 62])] {
            let (status, body) = diagnostic_packet(&too_long, "A").expect_err("256 bytes");
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(body["error"]["code"], "diagnostic_domain_invalid");
            assert_eq!(body["error"]["message"], "域名过长");
        }
        // A label of 64 bytes is invalid, whatever the length / 64 字节的标签无效，与总长无关
        let (_, body) = diagnostic_packet(&plain(&[64]), "A").expect_err("64-byte label");
        assert_eq!(body["error"]["code"], "diagnostic_domain_invalid");
    }

    #[tokio::test]
    async fn the_assigned_client_ip_drives_client_rules_and_shows_in_the_trace() {
        let engine = engine_for(
            client_split_config("192.168.1.0/24"),
            Arc::new(PanelMetrics::new(false)),
        );
        let (packet, record_type) = diagnostic_packet("nas.example", "A").expect("packet");

        let home: IpAddr = "192.168.1.9".parse().unwrap();
        let (status, body) =
            run_diagnostic(&engine, &packet, Some(home), "nas.example", &record_type).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["client_ip"], "192.168.1.9");
        assert!(answered(&body, "10.0.0.1"), "{body}");
        let parsed = body["trace"][0]["detail"].as_str().unwrap_or_default();
        assert!(parsed.contains("客户端：192.168.1.9"), "{parsed}");

        // 写成 IPv4 映射形式的地址按 IPv4 地址判断，回复里也这样写
        // An address in the IPv4-mapped form is judged, and reported, as the IPv4 address
        let mapped: IpAddr = "::ffff:192.168.1.9".parse().unwrap();
        let (status, body) =
            run_diagnostic(&engine, &packet, Some(mapped), "nas.example", &record_type).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["client_ip"], "192.168.1.9");
        assert!(answered(&body, "10.0.0.1"), "{body}");

        // 不填就是本机回环，落到「其余」 / Omitted means loopback, which lands on "rest"
        let (status, body) =
            run_diagnostic(&engine, &packet, None, "nas.example", &record_type).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["client_ip"], "127.0.0.1");
        assert!(answered(&body, "10.0.0.2"), "{body}");
    }

    #[tokio::test]
    async fn diagnostic_queries_stay_out_of_the_query_ranking() {
        let metrics = Arc::new(PanelMetrics::new(false));
        let engine = engine_for(client_split_config("192.168.1.0/24"), Arc::clone(&metrics));
        let (packet, record_type) = diagnostic_packet("probe.example", "A").expect("packet");
        let assigned: IpAddr = "192.168.1.77".parse().unwrap();
        let _ = run_diagnostic(
            &engine,
            &packet,
            Some(assigned),
            "probe.example",
            &record_type,
        )
        .await;
        let snapshot = metrics
            .query_stats
            .snapshot(super::unix_timestamp(), 3_600, 20);
        assert!(
            snapshot.domains.is_empty(),
            "diagnostic domain leaked into the ranking"
        );
        assert!(
            snapshot.clients.is_empty(),
            "assigned client IP leaked into the ranking"
        );

        // 同一个引擎上的普通查询照常计数 / A normal query on the same engine still counts
        let _ = engine
            .handle_packet(
                &packet,
                std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)), 5353),
            )
            .await
            .expect("normal query");
        let snapshot = metrics
            .query_stats
            .snapshot(super::unix_timestamp(), 3_600, 20);
        assert_eq!(snapshot.domains.len(), 1);
        assert_eq!(snapshot.clients.len(), 1);
    }

    #[tokio::test]
    async fn a_trial_answers_from_the_candidate_config_with_the_assigned_client() {
        let input = TrialInput {
            request: CandidateTraceRequest {
                domain: "nas.example".to_owned(),
                record_type: "a".to_owned(),
                client_ip: Some("10.8.0.3".parse().unwrap()),
                config: client_split_config("10.8.0.0/16"),
            },
            listener_label: "default".to_owned(),
        };
        let (status, body) = run_trial(input).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["candidate"], true);
        assert_eq!(body["record_type"], "A");
        assert_eq!(body["client_ip"], "10.8.0.3");
        assert!(answered(&body, "10.0.0.1"), "{body}");
    }

    /// 试跑和校验一样拒绝候选配置：解析得了、但有配置问题（读不懂的上游），或者监听设置不对，都回
    /// 422 config_invalid
    /// A trial refuses a candidate as validation does: one that parses but has a
    /// configuration problem (an upstream nothing can read), or whose listener settings
    /// are wrong, gets 422 config_invalid
    #[cfg(unix)]
    #[tokio::test]
    async fn a_trial_refuses_a_candidate_validation_would_refuse() {
        let configs = [
            json!({ "settings": { "default_upstream": "1.1.1.1:53" }, "pipelines": [{ "id": "main", "rules": [{ "name": "x", "matchers": [{ "type": "any" }], "actions": [{ "type": "forward", "upstream": "nonsense" }] }] }] }),
            json!({ "settings": { "default_upstream": "1.1.1.1:53", "bind_udp": "not an address" }, "pipelines": [{ "id": "main", "rules": [] }] }),
        ];
        for config in configs {
            let input = TrialInput {
                request: CandidateTraceRequest {
                    domain: "nas.example".to_owned(),
                    record_type: "A".to_owned(),
                    client_ip: None,
                    config: config.clone(),
                },
                listener_label: "default".to_owned(),
            };
            let (status, body) = run_trial(input).await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{config}: {body}");
            assert_eq!(body["error"]["code"], "config_invalid", "{body}");
        }
    }

    #[tokio::test]
    async fn a_trial_refuses_a_candidate_the_kernel_would_refuse() {
        let input = TrialInput {
            request: CandidateTraceRequest {
                domain: "nas.example".to_owned(),
                record_type: "A".to_owned(),
                client_ip: None,
                config: json!({ "settings": { "default_upstream": "1.1.1.1:53" }, "pipelines": [{ "id": "main", "rules": [{ "name": "x", "matchers": [{ "type": "no_such_matcher" }], "actions": [] }] }] }),
            },
            listener_label: "default".to_owned(),
        };
        let (status, body) = run_trial(input).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(body["error"]["code"], "config_invalid", "{body}");
    }

    #[test]
    fn requests_keep_rejecting_unknown_fields_and_accept_the_old_shape() {
        let old: DiagnosticRequest =
            serde_json::from_value(json!({ "domain": "a.example", "record_type": "A" }))
                .expect("old shape");
        assert!(old.client_ip.is_none());
        let with_client: DiagnosticRequest = serde_json::from_value(
            json!({ "domain": "a.example", "record_type": "A", "client_ip": "fd00::5" }),
        )
        .expect("client ip");
        assert_eq!(with_client.client_ip, Some("fd00::5".parse().unwrap()));
        assert!(
            serde_json::from_value::<DiagnosticRequest>(
                json!({ "domain": "a.example", "record_type": "A", "server": "8.8.8.8" })
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<DiagnosticRequest>(
                json!({ "domain": "a.example", "record_type": "A", "client_ip": "not-an-ip" })
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<CandidateTraceRequest>(
                json!({ "domain": "a.example", "record_type": "A" })
            )
            .is_err(),
            "a trial needs a config"
        );
    }

    /// 健康信息总带着发布身份这两个字段：发布的构建填上日期版本和提交，本地构建是 null，
    /// 面板据此区分，不会把缺字段当成别的版本。
    /// Health always carries the two release-identity fields: a released build fills in the
    /// date version and commit, a local build reports null, and the panel tells them apart
    /// instead of reading a missing field as some other version.
    #[test]
    fn health_reports_the_release_identity() {
        let health = PanelMetrics::new(false).health_json();
        assert_eq!(
            health.get("release_version"),
            Some(&serde_json::json!(option_env!("KIXDNS_RELEASE_VERSION")))
        );
        assert_eq!(
            health.get("release_commit"),
            Some(&serde_json::json!(option_env!("KIXDNS_RELEASE_COMMIT")))
        );
    }

    fn capabilities() -> Vec<String> {
        let health = PanelMetrics::new(false).health_json();
        health["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|value| value.as_str().map(str::to_owned))
            .collect()
    }

    #[test]
    fn health_declares_both_new_diagnostic_capabilities() {
        let capabilities = capabilities();
        assert!(
            capabilities
                .iter()
                .any(|name| name == "diagnostics_trace_client_v1")
        );
        assert!(
            capabilities
                .iter()
                .any(|name| name == "diagnostics_trace_candidate_v1")
        );
    }

    #[test]
    fn health_declares_the_query_log() {
        for capability in [
            "querylog_v1",
            "querylog_wait_v1",
            "querylog_stored_v1",
            "querylog_until_v1",
            "querylog_records_v1",
        ] {
            assert!(
                capabilities().iter().any(|name| name == capability),
                "{capability}"
            );
        }
    }

    #[test]
    fn the_query_log_cursor_is_checked() {
        use super::parse_querylog_query;
        use std::time::Duration;
        let take = |after, limit, instance, wait| super::QueryLogTake {
            after,
            limit,
            until: None,
            instance,
            stored: None,
            format: super::QueryLogFormat::Json,
            wait,
        };
        assert_eq!(
            parse_querylog_query(None),
            Ok(take(
                0,
                crate::panel_querylog::MAX_PAGE,
                None,
                Duration::ZERO
            ))
        );
        assert_eq!(
            parse_querylog_query(Some("after=42&limit=10")),
            Ok(take(42, 10, None, Duration::ZERO))
        );
        assert_eq!(
            parse_querylog_query(Some("after=42&limit=10&instance=7&wait_ms=5000")),
            Ok(take(42, 10, Some(7), Duration::from_secs(5)))
        );
        assert_eq!(
            parse_querylog_query(Some("after=42&instance=7&stored=40")),
            Ok(super::QueryLogTake {
                stored: Some(40),
                ..take(42, crate::panel_querylog::MAX_PAGE, Some(7), Duration::ZERO)
            })
        );
        assert!(parse_querylog_query(Some("instance=")).is_err());
        assert_eq!(
            parse_querylog_query(Some("after=42&until=542&instance=7&stored=40")),
            Ok(super::QueryLogTake {
                until: Some(542),
                stored: Some(40),
                ..take(42, crate::panel_querylog::MAX_PAGE, Some(7), Duration::ZERO)
            })
        );
        assert!(parse_querylog_query(Some("stored=soon")).is_err());
        assert!(parse_querylog_query(Some("until=soon")).is_err());
        assert_eq!(
            parse_querylog_query(Some("format=records1")).map(|take| take.format),
            Ok(super::QueryLogFormat::Records)
        );
        assert!(parse_querylog_query(Some("format=xml")).is_err());
        assert!(parse_querylog_query(Some("wait_ms=5001")).is_err());
        assert!(parse_querylog_query(Some("wait_ms=soon")).is_err());
        assert!(parse_querylog_query(Some("limit=0")).is_err());
        assert!(parse_querylog_query(Some("limit=2001")).is_err());
        assert!(parse_querylog_query(Some("after=-1")).is_err());
        assert!(parse_querylog_query(Some("since=1")).is_err());
    }

    /// 本机假上游：每个查询都回一条 A 1.2.3.4 / A local fake upstream answering every query with A 1.2.3.4
    async fn fake_upstream() -> (String, tokio::task::JoinHandle<()>) {
        use hickory_proto::op::{Message, MessageType, OpCode};
        use hickory_proto::rr::rdata::A;
        use hickory_proto::rr::{RData, Record};

        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap().to_string();
        let task = tokio::spawn(async move {
            let mut buffer = [0u8; 1500];
            while let Ok((size, peer)) = socket.recv_from(&mut buffer).await {
                let Ok(query) = Message::from_vec(&buffer[..size]) else {
                    continue;
                };
                let mut answer =
                    Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
                if let Some(question) = query.queries.first() {
                    answer.add_query(question.clone());
                    answer.add_answer(Record::from_rdata(
                        question.name().clone(),
                        60,
                        RData::A(A::new(1, 2, 3, 4)),
                    ));
                }
                if let Ok(bytes) = answer.to_vec() {
                    let _ = socket.send_to(&bytes, peer).await;
                }
            }
        });
        (address, task)
    }

    /// 回答后检查拦下、上游失败后按「否则」回答、检查后转去别的列表：都记成规则直接回应，不写上游
    /// An answer check denying, the miss actions answering a failed upstream, and a check jumping
    /// elsewhere: each is recorded as a rule's own answer, with no upstream named
    #[tokio::test]
    async fn the_query_log_follows_answer_checks_through_a_real_engine() {
        let (upstream, task) = fake_upstream().await;
        let metrics = Arc::new(PanelMetrics::new(false));
        let checked = |name: &str, actions: serde_json::Value| {
            json!({
                "name": name,
                "matchers": [{ "type": "domain_suffix", "value": format!("{name}.example") }],
                "actions": [{ "type": "forward", "upstream": upstream, "transport": "udp" }],
                "response_matchers": [{ "type": "response_answer_ip", "cidr": "1.2.3.0/24" }],
                "response_actions_on_match": actions
            })
        };
        let engine = engine_for(
            json!({
                "settings": { "default_upstream": "127.0.0.1:9", "udp_pool_size": 1, "upstream_timeout_ms": 200 },
                "pipelines": [
                    {
                        "id": "main",
                        "rules": [
                            checked("denied", json!([{ "type": "deny" }])),
                            checked("moved", json!([{ "type": "jump_to_pipeline", "pipeline": "local" }])),
                            {
                                "name": "rescued",
                                "matchers": [{ "type": "domain_suffix", "value": "rescued.example" }],
                                "actions": [{ "type": "forward", "upstream": "127.0.0.1:9", "transport": "udp" }],
                                "response_actions_on_miss": [{ "type": "static_ip_response", "ip": "10.9.9.9" }]
                            }
                        ]
                    },
                    {
                        "id": "local",
                        "rules": [{
                            "name": "answer",
                            "matchers": [{ "type": "any" }],
                            "actions": [{ "type": "static_ip_response", "ip": "10.0.0.1" }]
                        }]
                    }
                ]
            }),
            Arc::clone(&metrics),
        );
        let _ = metrics
            .query_log
            .collect(0, 10, None, None, None, super::PROTOCOL_VERSION);
        let client = std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)), 5353);
        for name in ["denied.example", "rescued.example", "moved.example"] {
            let (packet, _) = diagnostic_packet(name, "A").expect("packet");
            engine.handle_packet(&packet, client).await.expect("query");
        }
        task.abort();

        let page: serde_json::Value = serde_json::from_str(&metrics.query_log.collect(
            0,
            10,
            None,
            None,
            None,
            super::PROTOCOL_VERSION,
        ))
        .unwrap();
        let entries = page["entries"].as_array().expect("entries");
        assert_eq!(entries.len(), 3, "{page}");
        let (denied, rescued, moved) = (&entries[0], &entries[1], &entries[2]);
        for entry in entries {
            assert_eq!(entry["outcome"], "static", "{entry}");
            assert!(entry.get("upstream").is_none(), "{entry}");
        }
        assert_eq!(denied["rcode"], "REFUSED");
        let check = |entry: &serde_json::Value| {
            entry["steps"]
                .as_array()
                .unwrap()
                .iter()
                .find(|step| step["phase"] == "response")
                .cloned()
                .unwrap_or_default()
        };
        assert_eq!(check(denied)["matched"], true, "{denied}");
        assert_eq!(check(denied)["decision"], "static");
        assert_eq!(rescued["answers"], json!(["10.9.9.9"]));
        assert_eq!(check(rescued)["kind"], "decision", "{rescued}");
        assert_eq!(check(rescued)["decision"], "static");
        assert_eq!(check(moved)["decision"], "jump", "{moved}");
        assert_eq!(check(moved)["target"], "local");
        assert_eq!(moved["answers"], json!(["10.0.0.1"]));
        assert_eq!(moved["pipeline"], "local");
    }

    /// 控制口交出的一页：JSON 文本 / A page the control socket hands over, as JSON
    async fn querylog_page(metrics: &Arc<PanelMetrics>, query: &str) -> serde_json::Value {
        let response = super::querylog_response(metrics, Some(query)).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes();
        serde_json::from_slice(&body).unwrap()
    }

    /// 面板等着取：一页攒不满时控制口先挂着，查询一到就交出去；不带 `wait_ms` 时照旧马上回，拿着别的内核进程的
    /// 游标也马上回。下次带着这个进程的游标来取，之前的就删了
    /// A waiting panel: short of a page the control socket holds the request and hands the query over
    /// as soon as it arrives; without `wait_ms` it answers at once as before, and so it does for a
    /// cursor of another kernel process. The next take with a cursor of this process deletes what came
    /// before
    #[tokio::test]
    async fn the_control_socket_holds_a_query_log_take_until_records_arrive() {
        let metrics = Arc::new(PanelMetrics::new(false));
        let engine = engine_for(client_split_config("192.168.1.0/24"), Arc::clone(&metrics));
        let started = std::time::Instant::now();
        let empty = querylog_page(&metrics, "after=0&limit=1").await;
        assert_eq!(empty["entries"], json!([]));
        let instance = empty["instance"].as_u64().expect("instance");
        let other_run = format!("after=0&limit=1&instance={}&wait_ms=4000", instance + 1);
        let _ = querylog_page(&metrics, &other_run).await;
        assert!(started.elapsed() < std::time::Duration::from_secs(1));

        let (packet, _) = diagnostic_packet("nas.example", "A").expect("packet");
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            let home = std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)), 5353);
            engine.handle_packet(&packet, home).await.expect("query");
        });
        let started = std::time::Instant::now();
        let this_run = format!("after=0&limit=1&instance={instance}&wait_ms=4000");
        let page = querylog_page(&metrics, &this_run).await;
        let waited = started.elapsed();
        assert!(
            waited >= std::time::Duration::from_millis(100),
            "{waited:?}"
        );
        assert!(waited < std::time::Duration::from_secs(3), "{waited:?}");
        assert_eq!(page["entries"][0]["qname"], "nas.example");

        let _ = querylog_page(&metrics, &format!("after=1&limit=1&instance={instance}")).await;
        let from_the_start = querylog_page(&metrics, "after=0&limit=1").await;
        assert_eq!(from_the_start["entries"], json!([]), "stored, so deleted");
        assert_eq!(from_the_start["missed"], 1);
    }

    /// 经过控制口：`stored` 说存好到哪，只删到那里，取走了还没存好的照留
    /// Through the control socket: `stored` says how far is stored, and deletion stops there, keeping what was taken
    /// but not stored
    #[tokio::test]
    async fn the_control_socket_deletes_only_what_is_stored() {
        let metrics = Arc::new(PanelMetrics::new(false));
        let engine = engine_for(client_split_config("192.168.1.0/24"), Arc::clone(&metrics));
        let home = std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)), 5353);
        for name in ["a.example", "b.example", "c.example"] {
            let (packet, _) = diagnostic_packet(name, "A").expect("packet");
            engine.handle_packet(&packet, home).await.expect("query");
        }
        let first = querylog_page(&metrics, "after=0&limit=10").await;
        let instance = first["instance"].as_u64().expect("instance");
        assert_eq!(first["entries"].as_array().map(Vec::len), Some(3));
        let _ = querylog_page(
            &metrics,
            &format!("after=3&limit=1&instance={instance}&stored=1"),
        )
        .await;
        let left = querylog_page(&metrics, "after=0&limit=10").await;
        let seqs: Vec<u64> = left["entries"]
            .as_array()
            .expect("entries")
            .iter()
            .map(|entry| entry["seq"].as_u64().expect("seq"))
            .collect();
        assert_eq!(seqs, [2, 3]);
        assert_eq!(left["missed"], 1);
    }

    /// 经过控制口：带 `format=records1` 时交的是编好的记录（二进制），和 JSON 那一页是同样的记录；不认得的格式拒绝
    /// Through the control socket: with `format=records1` the encoded records come as binary, the same
    /// records as the JSON page; a format it does not know is refused
    #[tokio::test]
    async fn the_control_socket_hands_over_encoded_records() {
        let metrics = Arc::new(PanelMetrics::new(false));
        let engine = engine_for(client_split_config("192.168.1.0/24"), Arc::clone(&metrics));
        let home = std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)), 5353);
        for name in ["a.example", "b.example"] {
            let (packet, _) = diagnostic_packet(name, "A").expect("packet");
            engine.handle_packet(&packet, home).await.expect("query");
        }
        let response = super::querylog_response(&metrics, Some("after=0&format=records1")).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[hyper::header::CONTENT_TYPE],
            "application/octet-stream"
        );
        let body = http_body_util::BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert!(body.starts_with(b"KXQL\x01"), "{body:?}");
        for name in [b"a.example".as_slice(), b"b.example"] {
            assert!(
                body.windows(name.len()).any(|window| window == name),
                "{body:?}"
            );
        }
        let refused = super::querylog_response(&metrics, Some("after=0&format=xml")).await;
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    }

    /// 经过控制口：`until` 让一页只交到它为止；等着取时到它为止的都在了就回，不等攒满 `limit` 条
    /// Through the control socket: `until` stops a page there, and a waiting take returns once everything up to it is
    /// there, without waiting for `limit` records
    #[tokio::test]
    async fn the_control_socket_takes_a_range() {
        let metrics = Arc::new(PanelMetrics::new(false));
        let engine = engine_for(client_split_config("192.168.1.0/24"), Arc::clone(&metrics));
        let home = std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)), 5353);
        for name in ["a.example", "b.example", "c.example"] {
            let (packet, _) = diagnostic_packet(name, "A").expect("packet");
            engine.handle_packet(&packet, home).await.expect("query");
        }
        let started = std::time::Instant::now();
        let range = querylog_page(&metrics, "after=0&limit=10&until=2&wait_ms=5000").await;
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        let seqs: Vec<u64> = range["entries"]
            .as_array()
            .expect("entries")
            .iter()
            .map(|entry| entry["seq"].as_u64().expect("seq"))
            .collect();
        assert_eq!(seqs, [1, 2]);
        assert_eq!(range["more"], true);
    }

    /// 真引擎走一遍：面板取过一次以后，普通查询进日志（谁问的、哪条规则、回了什么），诊断查询不进
    /// Through a real engine: once the panel has collected, a normal query is recorded (who asked,
    /// which rule, what came back) and a diagnostic query is not
    #[tokio::test]
    async fn the_query_log_records_real_queries_and_leaves_diagnostics_out() {
        let metrics = Arc::new(PanelMetrics::new(false));
        let engine = engine_for(client_split_config("192.168.1.0/24"), Arc::clone(&metrics));
        let (packet, record_type) = diagnostic_packet("nas.example", "A").expect("packet");
        let _ = metrics
            .query_log
            .collect(0, 10, None, None, None, super::PROTOCOL_VERSION);

        let home = std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)), 5353);
        engine.handle_packet(&packet, home).await.expect("query");
        let assigned: IpAddr = "192.168.1.77".parse().unwrap();
        let _ = run_diagnostic(
            &engine,
            &packet,
            Some(assigned),
            "nas.example",
            &record_type,
        )
        .await;

        let page: serde_json::Value = serde_json::from_str(&metrics.query_log.collect(
            0,
            10,
            None,
            None,
            None,
            super::PROTOCOL_VERSION,
        ))
        .unwrap();
        let entries = page["entries"].as_array().expect("entries");
        assert_eq!(entries.len(), 1, "{page}");
        let entry = &entries[0];
        assert_eq!(entry["client"], "192.168.1.5");
        assert_eq!(entry["qname"], "nas.example");
        assert_eq!(entry["qtype"], "A");
        assert_eq!(entry["outcome"], "static");
        assert_eq!(entry["rcode"], "NOERROR");
        assert_eq!(entry["answers"], json!(["10.0.0.1"]));
        assert_eq!(entry["pipeline"], "main");
        assert_eq!(entry["rule"], "home");
        let steps = entry["steps"].as_array().expect("steps");
        assert_eq!(steps[0]["kind"], "pipeline");
        assert!(
            steps.iter().any(|step| step["kind"] == "rule"
                && step["rule"] == "home"
                && step["decision"] == "static"),
            "{entry}"
        );
    }

    /// 两个上游一起问、DoH 那个回了 429 的引擎，DoH 走明文 http / An engine asking two
    /// upstreams together, the DoH one answering 429, DoH over plain http
    async fn throttling_engine(
        metrics: &Arc<PanelMetrics>,
    ) -> (Engine, crate::engine::test_support::Throttling) {
        let udp = crate::engine::test_support::answering_upstream_after(
            Ipv4Addr::new(192, 0, 2, 1),
            300,
            std::time::Duration::from_millis(200),
        )
        .await;
        let doh = crate::engine::test_support::Throttling::spawn(Some("120")).await;
        let engine = engine_for(
            json!({
                "settings": { "default_upstream": "127.0.0.1:9", "upstream_timeout_ms": 3000 },
                "pipelines": [{ "id": "main", "rules": [{
                    "name": "both",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "forward", "upstream": [udp.address.clone(), doh.url.clone()] }]
                }] }]
            }),
            Arc::clone(metrics),
        );
        engine.doh_client.use_plain_http();
        (engine, doh)
    }

    /// 查询日志里，回了 429 的那次是 `upstream` 一步、结果 `throttled`，带耗时和错误原文；暂停中没问的
    /// 是单独的 `upstream_skipped` 一步，没有 `upstream` 那一步
    /// In the query log a 429 is an `upstream` step with result `throttled`, its latency and
    /// error text; an upstream not asked during its pause is an `upstream_skipped` step of its
    /// own, with no `upstream` step
    #[tokio::test]
    async fn the_query_log_shows_throttled_and_skipped_upstreams() {
        let metrics = Arc::new(PanelMetrics::new(false));
        let (engine, doh) = throttling_engine(&metrics).await;
        let _ = metrics
            .query_log
            .collect(0, 10, None, None, None, super::PROTOCOL_VERSION);
        let client = std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)), 5353);
        for name in ["first.example", "second.example"] {
            let (packet, _) = diagnostic_packet(name, "A").expect("packet");
            engine.handle_packet(&packet, client).await.expect("query");
        }

        let page: serde_json::Value = serde_json::from_str(&metrics.query_log.collect(
            0,
            10,
            None,
            None,
            None,
            super::PROTOCOL_VERSION,
        ))
        .unwrap();
        let entries = page["entries"].as_array().expect("entries");
        assert_eq!(entries.len(), 2, "{page}");
        let steps_at = |entry: &serde_json::Value| -> Vec<serde_json::Value> {
            entry["steps"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|step| step["upstream"] == doh.address.as_str())
                .map(|step| {
                    let mut step = step.clone();
                    step.as_object_mut().unwrap().remove("at_us");
                    step
                })
                .collect()
        };

        let first = steps_at(&entries[0]);
        assert_eq!(first.len(), 1, "{}", entries[0]);
        assert!(
            first[0]["latency_us"].as_u64().unwrap() > 0,
            "{}",
            entries[0]
        );
        let mut throttled = first[0].clone();
        throttled.as_object_mut().unwrap().remove("latency_us");
        assert_eq!(
            throttled,
            json!({
                "kind": "upstream",
                "upstream": doh.address,
                "transport": "doh",
                "via": "doh",
                "result": "throttled",
                "error": "doh http status 429 Too Many Requests"
            })
        );
        assert_eq!(
            steps_at(&entries[1]),
            vec![json!({
                "kind": "upstream_skipped",
                "upstream": doh.address,
                "transport": "doh",
                "reason": "throttled"
            })],
            "{}",
            entries[1]
        );
        assert_eq!(doh.asked(), 1);
    }

    /// 诊断里回了 429 的上游是 `throttled` 一步，写着 HTTP 状态码和实际暂停的秒数（Retry-After 120
    /// 收成 60）；暂停中没问的是 `skipped` 一步
    /// In diagnostics an upstream answering 429 is a `throttled` step naming the HTTP status
    /// and the pause actually applied (Retry-After 120 brought down to 60); one not asked
    /// during its pause is a `skipped` step
    #[tokio::test]
    async fn diagnostics_show_throttled_and_skipped_upstreams() {
        let metrics = Arc::new(PanelMetrics::new(false));
        let (engine, doh) = throttling_engine(&metrics).await;
        let mut traces = Vec::new();
        for name in ["first.example", "second.example"] {
            let (packet, record_type) = diagnostic_packet(name, "A").expect("packet");
            let (status, body) = run_diagnostic(&engine, &packet, None, name, &record_type).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let steps: Vec<serde_json::Value> = body["trace"]
                .as_array()
                .expect("trace")
                .iter()
                .filter(|step| {
                    step["label"]
                        .as_str()
                        .is_some_and(|label| label.contains(&doh.address))
                })
                .map(|step| json!([step["stage"], step["status"], step["label"], step["detail"]]))
                .collect();
            traces.push(steps);
        }
        assert_eq!(
            traces,
            vec![
                vec![
                    json!([
                        "upstream",
                        "started",
                        format!("准备转发到 {}", doh.address),
                        "规则：both；传输：doh"
                    ]),
                    json!([
                        "upstream",
                        "throttled",
                        doh.address,
                        "HTTP 状态码：429；暂停：60 秒"
                    ]),
                ],
                vec![json!([
                    "upstream",
                    "skipped",
                    doh.address,
                    "正在限速，这次没问它"
                ])],
            ]
        );
    }

    /// 几个上游都回 SERVFAIL、回答检查改问备用组时，查询日志里写着这一步：两个上游都被丢掉
    /// （rejected），回答检查通过、跳去备用组，答案来自备用组
    /// When several upstreams all answer SERVFAIL and the answer check falls back, the query
    /// log says so: both upstreams rejected, the check passed and jumped to the fallback group,
    /// whose upstream gave the answer
    #[tokio::test]
    async fn the_query_log_shows_a_fallback_after_failure_replies() {
        let failing = || {
            crate::engine::test_support::upstream(|query| {
                let mut reply = hickory_proto::op::Message::new(
                    query.metadata.id,
                    hickory_proto::op::MessageType::Response,
                    hickory_proto::op::OpCode::Query,
                );
                reply.metadata.recursion_desired = query.metadata.recursion_desired;
                reply.metadata.response_code = hickory_proto::op::ResponseCode::ServFail;
                reply.add_queries(query.queries.iter().cloned());
                vec![(std::time::Duration::ZERO, reply.to_vec().unwrap())]
            })
        };
        let (first, second) = (failing().await, failing().await);
        let backup =
            crate::engine::test_support::answering_upstream(Ipv4Addr::new(192, 0, 2, 53), 300)
                .await;
        let metrics = Arc::new(PanelMetrics::new(false));
        let engine = engine_for(
            json!({
                "settings": { "default_upstream": "127.0.0.1:9", "upstream_timeout_ms": 3000 },
                "pipelines": [
                    { "id": "main", "rules": [{
                        "name": "group",
                        "matchers": [{ "type": "any" }],
                        "actions": [{ "type": "forward", "upstream": [first.address.clone(), second.address.clone()] }],
                        "response_matchers": [
                            { "type": "response_rcode", "value": "SERVFAIL" },
                            { "type": "response_rcode", "value": "REFUSED" }
                        ],
                        "response_matcher_operator": "or",
                        "response_actions_on_match": [{ "type": "jump_to_pipeline", "pipeline": "fallback" }]
                    }] },
                    { "id": "fallback", "rules": [{
                        "name": "backup",
                        "matchers": [{ "type": "any" }],
                        "actions": [{ "type": "forward", "upstream": backup.address.clone() }]
                    }] }
                ]
            }),
            Arc::clone(&metrics),
        );
        let _ = metrics
            .query_log
            .collect(0, 10, None, None, None, super::PROTOCOL_VERSION);
        let client = std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)), 5353);
        let (packet, _) = diagnostic_packet("broken.example", "A").expect("packet");
        engine.handle_packet(&packet, client).await.expect("query");

        let page: serde_json::Value = serde_json::from_str(&metrics.query_log.collect(
            0,
            10,
            None,
            None,
            None,
            super::PROTOCOL_VERSION,
        ))
        .unwrap();
        let entry = &page["entries"][0];
        assert_eq!(entry["answers"], json!(["192.0.2.53"]), "{entry}");
        assert_eq!(entry["pipeline"], "fallback", "{entry}");
        let steps = entry["steps"].as_array().expect("steps");
        let upstream_steps = |result: &str| {
            let mut upstreams: Vec<String> = steps
                .iter()
                .filter(|step| step["kind"] == "upstream" && step["result"] == result)
                .map(|step| step["upstream"].as_str().unwrap().to_string())
                .collect();
            upstreams.sort();
            upstreams
        };
        let mut both = vec![first.address.clone(), second.address.clone()];
        both.sort();
        assert_eq!(upstream_steps("rejected"), both, "{entry}");
        assert_eq!(
            upstream_steps("success"),
            vec![backup.address.clone()],
            "{entry}"
        );
        assert!(
            steps.iter().any(|step| step["kind"] == "rule"
                && step["rule"] == "group"
                && step["phase"] == "response"
                && step["matched"] == true
                && step["decision"] == "jump"
                && step["target"] == "fallback"),
            "{entry}"
        );
    }
}
