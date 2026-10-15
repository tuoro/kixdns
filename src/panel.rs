use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use anyhow::Context;
#[cfg(unix)]
use bytes::Bytes;
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use dashmap::try_result::TryResult;
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
use parking_lot::{Mutex, RwLock};
#[cfg(unix)]
use serde::Deserialize;
#[cfg(unix)]
use serde_json::json;

use crate::engine::Engine;
use crate::observe::{
    CacheHit, CacheHitKind, ConfigLoaded, ConfigReloadFailed, DecisionMade, EngineObserver,
    RequestContext, RequestOutcome, RequestStatus, RuleCacheLookup, RuleEvaluated, RuleMatched,
    RulePhase, TracingObserver, UpstreamAttempt, UpstreamOutcome, UpstreamResult,
};
use crate::panel_querylog::{self, QueryLog};
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
const QUERY_STATS_BUCKET_SECONDS: u64 = 3_600;
const QUERY_STATS_BUCKETS: usize = 24;
const QUERY_STATS_SHARDS: usize = 16;
const QUERY_STATS_DOMAIN_CAP: usize = 4_096;
const QUERY_STATS_CLIENT_CAP: usize = 1_024;
const QUERY_STATS_CONFIGURED: u8 = 0b100;
const QUERY_STATS_ENABLED: u8 = 0b001;
const QUERY_STATS_ANONYMIZED: u8 = 0b010;

#[derive(Clone, Default)]
struct ActiveConfig {
    generation: u64,
    sha256: String,
    loaded_at_unix: u64,
    last_reload_success: bool,
    last_reload_error: Option<String>,
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
enum ClientKey {
    V4(u32, bool),
    V6(u64, u64, bool),
}

impl ClientKey {
    fn new(address: IpAddr, anonymized: bool) -> Self {
        match address {
            IpAddr::V4(address) => {
                let mut value = u32::from(address);
                if anonymized {
                    value &= u32::MAX << 8;
                }
                Self::V4(value, anonymized)
            }
            IpAddr::V6(address) => {
                let value = u128::from(address);
                let high = (value >> 64) as u64;
                let low = if anonymized { 0 } else { value as u64 };
                Self::V6(high, low, anonymized)
            }
        }
    }

    #[cfg_attr(not(unix), allow(dead_code))]
    fn label(self) -> String {
        match self {
            Self::V4(value, anonymized) => {
                let address = Ipv4Addr::from(value).to_string();
                if anonymized {
                    format!("{address}/24")
                } else {
                    address
                }
            }
            Self::V6(high, low, anonymized) => {
                let address = Ipv6Addr::from(((high as u128) << 64) | low as u128).to_string();
                if anonymized {
                    format!("{address}/64")
                } else {
                    address
                }
            }
        }
    }
}

struct QueryStatsBucket {
    epoch: AtomicU64,
    requests: AtomicU64,
    dropped_updates: AtomicU64,
    domain_entries: AtomicUsize,
    client_entries: AtomicUsize,
    rotate_lock: Mutex<()>,
    domains: DashMap<Arc<str>, AtomicU64>,
    clients: DashMap<ClientKey, AtomicU64>,
}

impl QueryStatsBucket {
    fn new() -> Self {
        Self {
            epoch: AtomicU64::new(0),
            requests: AtomicU64::new(0),
            dropped_updates: AtomicU64::new(0),
            domain_entries: AtomicUsize::new(0),
            client_entries: AtomicUsize::new(0),
            rotate_lock: Mutex::new(()),
            domains: DashMap::with_shard_amount(QUERY_STATS_SHARDS),
            clients: DashMap::with_shard_amount(QUERY_STATS_SHARDS),
        }
    }

    fn prepare(&self, epoch: u64) -> bool {
        if self.epoch.load(Ordering::Acquire) == epoch {
            return true;
        }
        let Some(_guard) = self.rotate_lock.try_lock() else {
            return false;
        };
        if self.epoch.load(Ordering::Relaxed) != epoch {
            self.domains.clear();
            self.clients.clear();
            self.requests.store(0, Ordering::Relaxed);
            self.dropped_updates.store(0, Ordering::Relaxed);
            self.domain_entries.store(0, Ordering::Relaxed);
            self.client_entries.store(0, Ordering::Relaxed);
            self.epoch.store(epoch, Ordering::Release);
        }
        true
    }

    fn clear(&self) {
        let _guard = self.rotate_lock.lock();
        self.domains.clear();
        self.clients.clear();
        self.requests.store(0, Ordering::Relaxed);
        self.dropped_updates.store(0, Ordering::Relaxed);
        self.domain_entries.store(0, Ordering::Relaxed);
        self.client_entries.store(0, Ordering::Relaxed);
        self.epoch.store(0, Ordering::Release);
    }

    fn record_domain(&self, domain: &str) -> bool {
        match self.domains.try_get(domain) {
            TryResult::Present(counter) => {
                counter.fetch_add(1, Ordering::Relaxed);
                return true;
            }
            TryResult::Locked => return false,
            TryResult::Absent => {}
        }
        let Some(entry) = self.domains.try_entry(Arc::from(domain)) else {
            return false;
        };
        match entry {
            Entry::Occupied(entry) => {
                entry.get().fetch_add(1, Ordering::Relaxed);
                true
            }
            Entry::Vacant(entry) => {
                let index = self.domain_entries.fetch_add(1, Ordering::Relaxed);
                if index >= QUERY_STATS_DOMAIN_CAP {
                    self.domain_entries.fetch_sub(1, Ordering::Relaxed);
                    return false;
                }
                entry.insert(AtomicU64::new(1));
                true
            }
        }
    }

    fn record_client(&self, client: ClientKey) -> bool {
        match self.clients.try_get(&client) {
            TryResult::Present(counter) => {
                counter.fetch_add(1, Ordering::Relaxed);
                return true;
            }
            TryResult::Locked => return false,
            TryResult::Absent => {}
        }
        let Some(entry) = self.clients.try_entry(client) else {
            return false;
        };
        match entry {
            Entry::Occupied(entry) => {
                entry.get().fetch_add(1, Ordering::Relaxed);
                true
            }
            Entry::Vacant(entry) => {
                let index = self.client_entries.fetch_add(1, Ordering::Relaxed);
                if index >= QUERY_STATS_CLIENT_CAP {
                    self.client_entries.fetch_sub(1, Ordering::Relaxed);
                    return false;
                }
                entry.insert(AtomicU64::new(1));
                true
            }
        }
    }
}

struct QueryStats {
    settings: AtomicU8,
    settings_lock: Mutex<()>,
    buckets: Box<[QueryStatsBucket]>,
}

impl Default for QueryStats {
    fn default() -> Self {
        Self {
            settings: AtomicU8::new(0),
            settings_lock: Mutex::new(()),
            buckets: (0..QUERY_STATS_BUCKETS)
                .map(|_| QueryStatsBucket::new())
                .collect(),
        }
    }
}

#[cfg_attr(not(unix), allow(dead_code))]
struct TopStat {
    name: String,
    count: u64,
}

#[cfg_attr(not(unix), allow(dead_code))]
struct QueryStatsSnapshot {
    enabled: bool,
    anonymized_clients: bool,
    requests_observed: u64,
    dropped_updates: u64,
    clients: Vec<TopStat>,
    domains: Vec<TopStat>,
}

impl QueryStats {
    fn configure(&self, enabled: bool, anonymized: bool) {
        let desired = QUERY_STATS_CONFIGURED
            | (u8::from(enabled) * QUERY_STATS_ENABLED)
            | (u8::from(anonymized) * QUERY_STATS_ANONYMIZED);
        if self.settings.load(Ordering::Relaxed) == desired {
            return;
        }
        let _guard = self.settings_lock.lock();
        if self.settings.load(Ordering::Relaxed) != desired {
            self.clear();
            self.settings.store(desired, Ordering::Release);
        }
    }

    fn clear(&self) {
        for bucket in &self.buckets {
            bucket.clear();
        }
    }

    #[inline]
    fn record(&self, domain: &str, client: IpAddr) {
        let settings = self.settings.load(Ordering::Acquire);
        if settings & QUERY_STATS_ENABLED == 0 {
            return;
        }
        let anonymized = settings & QUERY_STATS_ANONYMIZED != 0;
        self.record_at(domain, client, anonymized, unix_timestamp());
    }

    fn record_at(&self, domain: &str, client: IpAddr, anonymized: bool, now: u64) {
        let epoch = now - now % QUERY_STATS_BUCKET_SECONDS;
        let index = (epoch / QUERY_STATS_BUCKET_SECONDS) as usize % QUERY_STATS_BUCKETS;
        let bucket = &self.buckets[index];
        if !bucket.prepare(epoch) {
            return;
        }
        bucket.requests.fetch_add(1, Ordering::Relaxed);
        let domain_recorded = bucket.record_domain(domain);
        let client_recorded = bucket.record_client(ClientKey::new(client, anonymized));
        if !domain_recorded || !client_recorded {
            bucket.dropped_updates.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[cfg_attr(not(unix), allow(dead_code))]
    fn snapshot(&self, now: u64, window_seconds: u64, limit: usize) -> QueryStatsSnapshot {
        let settings = self.settings.load(Ordering::Acquire);
        let enabled = settings & QUERY_STATS_ENABLED != 0;
        let anonymized_clients = settings & QUERY_STATS_ANONYMIZED != 0;
        if !enabled {
            return QueryStatsSnapshot {
                enabled,
                anonymized_clients,
                requests_observed: 0,
                dropped_updates: 0,
                clients: Vec::new(),
                domains: Vec::new(),
            };
        }

        let oldest = now.saturating_sub(window_seconds);
        let mut requests_observed = 0u64;
        let mut dropped_updates = 0u64;
        let mut domains = HashMap::<Arc<str>, u64>::new();
        let mut clients = HashMap::<ClientKey, u64>::new();
        for bucket in &self.buckets {
            let epoch = bucket.epoch.load(Ordering::Acquire);
            if epoch == 0
                || epoch > now
                || epoch.saturating_add(QUERY_STATS_BUCKET_SECONDS) <= oldest
            {
                continue;
            }
            requests_observed =
                requests_observed.saturating_add(bucket.requests.load(Ordering::Relaxed));
            dropped_updates =
                dropped_updates.saturating_add(bucket.dropped_updates.load(Ordering::Relaxed));
            for entry in &bucket.domains {
                let total = domains.entry(Arc::clone(entry.key())).or_default();
                *total = total.saturating_add(entry.value().load(Ordering::Relaxed));
            }
            for entry in &bucket.clients {
                let total = clients.entry(*entry.key()).or_default();
                *total = total.saturating_add(entry.value().load(Ordering::Relaxed));
            }
        }

        let mut domains = domains
            .into_iter()
            .map(|(name, count)| TopStat {
                name: name.to_string(),
                count,
            })
            .collect::<Vec<_>>();
        let mut clients = clients
            .into_iter()
            .map(|(client, count)| TopStat {
                name: client.label(),
                count,
            })
            .collect::<Vec<_>>();
        sort_and_truncate(&mut domains, limit);
        sort_and_truncate(&mut clients, limit);

        QueryStatsSnapshot {
            enabled,
            anonymized_clients,
            requests_observed,
            dropped_updates,
            clients,
            domains,
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

/// 请求耗时直方图：固定分桶，零分配。/ Request latency histogram with fixed buckets.
#[derive(Default)]
struct RequestLatency {
    total: LatencySum,
    buckets: [AtomicU64; REQUEST_LATENCY_BUCKETS_MS.len() + 1],
}

impl RequestLatency {
    #[inline]
    fn observe(&self, latency: std::time::Duration) {
        self.total.add(latency);
        let millis = u64::try_from(latency.as_millis()).unwrap_or(u64::MAX);
        let index = REQUEST_LATENCY_BUCKETS_MS
            .iter()
            .position(|bound| millis <= *bound)
            .unwrap_or(REQUEST_LATENCY_BUCKETS_MS.len());
        self.buckets[index].fetch_add(1, Ordering::Relaxed);
    }
}

pub struct PanelMetrics {
    #[cfg_attr(not(unix), allow(dead_code))]
    started_at_unix: u64,
    #[cfg_attr(not(unix), allow(dead_code))]
    started_at: Instant,
    requests_total: AtomicU64,
    requests_inflight: AtomicUsize,
    cache_lookups_total: AtomicU64,
    /// 已经计过一次缓存查找、还没结束的请求。请求跳转后会在目标 pipeline 下再查一次，
    /// 而命中率按请求算（一个请求最多命中一次），所以每个请求只计一次查找。
    /// Requests still running whose cache lookup is already counted. A request looks again
    /// under the target pipeline after a jump, while the hit rate is per request (a request
    /// hits at most once), so each request counts one lookup.
    cache_lookup_counted: DashMap<u64, ()>,
    cache_hits_fresh: AtomicU64,
    cache_hits_stale: AtomicU64,
    cache_stale_client_timeout: AtomicU64,
    cache_stale_upstream_failure: AtomicU64,
    requests_completed: AtomicU64,
    requests_failed: AtomicU64,
    requests_cancelled: AtomicU64,
    request_latency: RequestLatency,
    upstream_latency: DashMap<Arc<str>, LatencySum>,
    /// 只算拿到响应的尝试（成功或被拒绝），超时与连接错误不计入。
    /// Only attempts that received a response (success or rejected); timeouts and
    /// connection errors are left out.
    upstream_response_latency: DashMap<Arc<str>, LatencySum>,
    upstream_rcodes: DashMap<Arc<str>, AtomicU64>,
    upstream_via: DashMap<Arc<str>, AtomicU64>,
    pipeline_hits: DashMap<Arc<str>, AtomicU64>,
    rule_matches: DashMap<Arc<str>, AtomicU64>,
    upstream_attempts: DashMap<Arc<str>, AtomicU64>,
    upstream_results: DashMap<Arc<str>, AtomicU64>,
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
            requests_total: AtomicU64::new(0),
            requests_inflight: AtomicUsize::new(0),
            cache_lookups_total: AtomicU64::new(0),
            cache_lookup_counted: DashMap::new(),
            cache_hits_fresh: AtomicU64::new(0),
            cache_hits_stale: AtomicU64::new(0),
            cache_stale_client_timeout: AtomicU64::new(0),
            cache_stale_upstream_failure: AtomicU64::new(0),
            requests_completed: AtomicU64::new(0),
            requests_failed: AtomicU64::new(0),
            requests_cancelled: AtomicU64::new(0),
            request_latency: RequestLatency::default(),
            upstream_latency: DashMap::new(),
            upstream_response_latency: DashMap::new(),
            upstream_rcodes: DashMap::new(),
            upstream_via: DashMap::new(),
            pipeline_hits: DashMap::new(),
            rule_matches: DashMap::new(),
            upstream_attempts: DashMap::new(),
            upstream_results: DashMap::new(),
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
    pub fn record_request(&self) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn record_query(&self, domain: &str, client: IpAddr) {
        self.query_stats.record(domain, client);
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
        map: &DashMap<Arc<str>, LatencySum>,
        key: Arc<str>,
        latency: std::time::Duration,
    ) {
        if let Some(entry) = map.get(&key) {
            entry.add(latency);
            return;
        }
        if key.len() > MAX_METRIC_KEY_BYTES {
            self.metric_series_dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let _guard = self.metric_series_insert_lock.lock();
        if let Some(entry) = map.get(&key) {
            entry.add(latency);
        } else if map.len() < MAX_METRIC_SERIES_PER_MAP {
            let sum = LatencySum::default();
            sum.add(latency);
            map.insert(key, sum);
        } else {
            self.metric_series_dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[inline]
    fn record_pipeline_hit(&self, pipeline: &str) {
        self.increment(&self.pipeline_hits, Arc::from(pipeline));
    }

    #[inline]
    fn record_rule_match(&self, pipeline: &str, rule: &str, phase: &str) {
        self.increment(
            &self.rule_matches,
            Arc::from(format!("{pipeline}\0{rule}\0{phase}")),
        );
    }

    #[inline]
    fn record_upstream_attempt(&self, upstream: &str, transport: &str) {
        self.increment(
            &self.upstream_attempts,
            Arc::from(format!("{upstream}\0{transport}")),
        );
    }

    #[inline]
    fn record_upstream_result(&self, upstream: &str, transport: &str, result: &str) {
        self.increment(
            &self.upstream_results,
            Arc::from(format!("{upstream}\0{transport}\0{result}")),
        );
    }

    fn record_initial_config(&self, sha256: String) {
        let mut active = self.active_config.write();
        active.generation = 1;
        active.sha256 = sha256;
        active.loaded_at_unix = unix_timestamp();
        active.last_reload_success = true;
        active.last_reload_error = None;
    }

    fn record_reload_success(&self, sha256: String) {
        let mut active = self.active_config.write();
        active.generation = active.generation.saturating_add(1).max(1);
        active.sha256 = sha256;
        active.loaded_at_unix = unix_timestamp();
        active.last_reload_success = true;
        active.last_reload_error = None;
        self.reload_success.fetch_add(1, Ordering::Relaxed);
        self.reload_sequence.fetch_add(1, Ordering::Release);
    }

    #[inline]
    fn increment(&self, map: &DashMap<Arc<str>, AtomicU64>, key: Arc<str>) {
        if let Some(counter) = map.get(&key) {
            counter.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if key.len() > MAX_METRIC_KEY_BYTES {
            self.metric_series_dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }

        let _guard = self.metric_series_insert_lock.lock();
        if let Some(counter) = map.get(&key) {
            counter.fetch_add(1, Ordering::Relaxed);
        } else if map.len() < MAX_METRIC_SERIES_PER_MAP {
            map.insert(key, AtomicU64::new(1));
        } else {
            self.metric_series_dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn record_reload_failure(&self, error: &str) {
        let mut active = self.active_config.write();
        active.last_reload_success = false;
        active.last_reload_error = Some(truncate(error, MAX_ERROR_LENGTH));
        self.reload_failure.fetch_add(1, Ordering::Relaxed);
        self.reload_sequence.fetch_add(1, Ordering::Release);
    }

    /// 从观察者收到的配置原文更新摘要与查询统计开关。/ Refresh digest and query-stats switches from the loaded source.
    fn record_config_loaded(&self, source: &str) {
        if let Ok(config) = crate::config::parse_config(source) {
            self.query_stats.configure(
                config.settings.statistics_enabled,
                config.settings.statistics_anonymize_client_ip,
            );
        }
        let sha256 = format!("{:x}", Sha256::digest(source.as_bytes()));
        let initial = self.active_config.read().generation == 0;
        if initial {
            self.record_initial_config(sha256);
        } else {
            self.record_reload_success(sha256);
        }
    }

    #[cfg(unix)]
    fn config_json(&self) -> serde_json::Value {
        let active = self.active_config.read().clone();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "generation": active.generation,
            "sha256": active.sha256,
            "loaded_at_unix": active.loaded_at_unix,
            "reload_sequence": self.reload_sequence.load(Ordering::Acquire),
            "last_reload": {
                "success": active.last_reload_success,
                "error": active.last_reload_error,
            }
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
                "querylog_v1"
            ],
        })
    }

    #[cfg(unix)]
    fn stats_json(&self, engine: &Engine, window_seconds: u64, limit: usize) -> serde_json::Value {
        let state = engine.state.load();
        let enabled = state.pipeline.settings.statistics_enabled;
        let anonymized = state.pipeline.settings.statistics_anonymize_client_ip;
        self.query_stats.configure(enabled, anonymized);
        let now = unix_timestamp();
        let snapshot = self.query_stats.snapshot(now, window_seconds, limit);
        let clients = snapshot
            .clients
            .into_iter()
            .map(|row| json!({"name": row.name, "count": row.count}))
            .collect::<Vec<_>>();
        let domains = snapshot
            .domains
            .into_iter()
            .map(|row| json!({"name": row.name, "count": row.count}))
            .collect::<Vec<_>>();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "enabled": snapshot.enabled,
            "anonymized_clients": snapshot.anonymized_clients,
            "window_seconds": window_seconds,
            "retention_seconds": QUERY_STATS_BUCKET_SECONDS * QUERY_STATS_BUCKETS as u64,
            "generated_at_unix": now,
            "requests_observed": snapshot.requests_observed,
            "dropped_updates": snapshot.dropped_updates,
            "clients": clients,
            "domains": domains,
        })
    }

    #[cfg(unix)]
    fn clear_stats(&self, engine: &Engine) {
        let state = engine.state.load();
        self.query_stats.configure(
            state.pipeline.settings.statistics_enabled,
            state.pipeline.settings.statistics_anonymize_client_ip,
        );
        self.query_stats.clear();
    }

    #[cfg(unix)]
    fn render_prometheus(&self, engine: &Engine) -> String {
        let mut output = String::with_capacity(8_192);
        // Answers, not slots: one question can hold answers for several ECS networks
        // 按应答份数计，而不是槽位数：一个问题可以存多个 ECS 网段的应答
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
            format_millis(self.request_latency.total.micros.load(Ordering::Relaxed)),
        );
        metric(
            output,
            "kixdns_request_latency_ms_count",
            self.request_latency.total.count.load(Ordering::Relaxed),
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

fn transport_label(transport: crate::config::Transport) -> &'static str {
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

impl EngineObserver for PanelMetrics {
    fn request_started(&self, ctx: &RequestContext<'_>) {
        if let Some(trace) = &self.debug_trace {
            trace.request_started(ctx);
        }
        if !ctx.background_refresh {
            self.requests_total.fetch_add(1, Ordering::Relaxed);
            self.requests_inflight.fetch_add(1, Ordering::Relaxed);
            // 诊断查询照常计入请求指标，但不进查询排行：测试用的域名和指定的客户端 IP 不是真实流量
            // Diagnostic queries count toward request metrics but stay out of the query ranking:
            // test domains and an assigned client IP are not real traffic
            if !panel_trace::active() {
                self.record_query(ctx.qname, ctx.client.ip());
            }
        }
        self.query_log.request_started(ctx, panel_trace::active());
        panel_trace::record(
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
        if let Some(trace) = &self.debug_trace {
            trace.request_finished(ctx, outcome);
        }
        self.query_log.request_finished(ctx, outcome);
        if ctx.background_refresh {
            return;
        }
        self.cache_lookup_counted.remove(&ctx.request_id);
        self.requests_inflight.fetch_sub(1, Ordering::Relaxed);
        let counter = match outcome.status {
            RequestStatus::Completed => &self.requests_completed,
            RequestStatus::Failed => &self.requests_failed,
            _ => &self.requests_cancelled,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        self.request_latency.observe(outcome.latency);
    }

    fn pipeline_selected(&self, ctx: &RequestContext<'_>, pipeline: &str) {
        if let Some(trace) = &self.debug_trace {
            trace.pipeline_selected(ctx, pipeline);
        }
        if !ctx.background_refresh {
            self.record_pipeline_hit(pipeline);
        }
        self.query_log.pipeline_selected(ctx, pipeline);
        if let Some(previous) = panel_trace::current_pipeline()
            && previous != pipeline
        {
            panel_trace::record(
                "pipeline",
                "jump",
                format!("{previous} -> {pipeline}"),
                None,
            );
        }
        panel_trace::set_pipeline(pipeline);
        panel_trace::record("pipeline", "selected", pipeline, None);
    }

    fn rule_matched(&self, ctx: &RequestContext<'_>, event: &RuleMatched<'_>) {
        if let Some(trace) = &self.debug_trace {
            trace.rule_matched(ctx, event);
        }
        // 规则命中和请求数、pipeline 命中一样只算客户端请求：后台刷新会照规则再走一遍，算进去
        // 命中数就会多于实际的查询，按命中数相减的请求分布也跟着偏
        // Rule matches, like request and pipeline counts, cover client queries only: a background
        // refresh walks the rules again, and counting it would put matches above the actual
        // queries and skew the request breakdown that subtracts them
        if !ctx.background_refresh {
            let phase = match event.phase {
                RulePhase::Request => "request",
                _ => "response",
            };
            self.record_rule_match(event.pipeline, event.rule, phase);
        }
        self.query_log.rule_matched(ctx, event);
    }

    fn rule_evaluated(&self, ctx: &RequestContext<'_>, event: &RuleEvaluated<'_>) {
        if let Some(trace) = &self.debug_trace {
            trace.rule_evaluated(ctx, event);
        }
        self.query_log.rule_evaluated(ctx, event);
        let status = if event.matched { "matched" } else { "missed" };
        match event.phase {
            RulePhase::Request => panel_trace::record(
                "rule",
                status,
                event.rule,
                Some(format!(
                    "管线：{}；匹配器数：{}",
                    event.pipeline, event.matchers
                )),
            ),
            _ => panel_trace::record(
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
        if let Some(trace) = &self.debug_trace {
            trace.rule_cache_lookup(ctx, event);
        }
        if event.hit {
            panel_trace::record(
                "rule_cache",
                "hit",
                format!("命中管线 {} 的规则缓存", event.pipeline),
                Some(format!("已匹配规则：{}", event.matched_rules)),
            );
        } else {
            panel_trace::record(
                "rule_cache",
                "miss",
                format!("管线 {} 的规则缓存未命中", event.pipeline),
                None,
            );
        }
    }

    fn decision_made(&self, ctx: &RequestContext<'_>, event: &DecisionMade<'_>) {
        if let Some(trace) = &self.debug_trace {
            trace.decision_made(ctx, event);
        }
        // 诊断的执行路径只写请求阶段的决定：回答后检查的结果已经由响应规则那一步说了
        // The diagnostics trace shows request-phase decisions only: an answer check's
        // outcome is already told by its response-rule step
        if event.phase == RulePhase::Request {
            panel_trace::record_decision(event);
        }
        self.query_log.decision_made(ctx, event);
    }

    fn cache_lookup(&self, ctx: &RequestContext<'_>) {
        if let Some(trace) = &self.debug_trace {
            trace.cache_lookup(ctx);
        }
        if !ctx.background_refresh
            && self
                .cache_lookup_counted
                .insert(ctx.request_id, ())
                .is_none()
        {
            self.record_cache_lookup();
        }
    }

    fn cache_miss(&self, ctx: &RequestContext<'_>) {
        if let Some(trace) = &self.debug_trace {
            trace.cache_miss(ctx);
        }
        self.query_log.cache_miss(ctx);
        let pipeline = panel_trace::current_pipeline();
        panel_trace::record(
            "response_cache",
            "miss",
            "响应缓存未命中",
            pipeline.map(|pipeline| format!("管线：{pipeline}")),
        );
    }

    fn cache_hit(&self, ctx: &RequestContext<'_>, event: &CacheHit) {
        if let Some(trace) = &self.debug_trace {
            trace.cache_hit(ctx, event);
        }
        self.record_cache_hit(event.kind);
        self.query_log.cache_hit(ctx, event);
        let ttl = |value: Option<std::time::Duration>| value.map(|value| value.as_secs());
        match event.kind {
            CacheHitKind::Fresh => panel_trace::record(
                "response_cache",
                "fresh",
                "命中新鲜响应缓存",
                ttl(event.remaining_ttl).map(|seconds| format!("剩余 TTL：{seconds} 秒")),
            ),
            CacheHitKind::Stale => panel_trace::record(
                "response_cache",
                "stale",
                "命中过期响应缓存",
                ttl(event.original_ttl).map(|seconds| format!("原始 TTL：{seconds} 秒")),
            ),
            CacheHitKind::StaleClientTimeout => panel_trace::record(
                "response_cache",
                "stale",
                "客户端等待超时，返回过期缓存",
                None,
            ),
            _ => panel_trace::record("response_cache", "stale", "上游失败，返回过期缓存", None),
        }
    }

    fn inflight_joined(&self, ctx: &RequestContext<'_>) {
        if let Some(trace) = &self.debug_trace {
            trace.inflight_joined(ctx);
        }
        self.query_log.inflight_joined(ctx);
        // 这次请求没有自己去问上游，等的是正在进行的同一个查询：诊断里不然就少了上游这一步
        // This request did not ask upstream itself but waited on the same query already in
        // flight: without this the diagnostics trace would show no upstream step at all
        panel_trace::record("upstream", "joined", "等候正在进行的同一个查询", None);
    }

    fn upstream_attempt(&self, ctx: &RequestContext<'_>, event: &UpstreamAttempt<'_>) {
        if let Some(trace) = &self.debug_trace {
            trace.upstream_attempt(ctx, event);
        }
        let transport = transport_label(event.transport);
        self.record_upstream_attempt(event.upstream, transport);
        let (rule, decided_transport) = panel_trace::current_decision();
        panel_trace::record(
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
        if let Some(trace) = &self.debug_trace {
            trace.upstream_result(ctx, event);
        }
        let transport = transport_label(event.transport);
        let result = match event.outcome {
            UpstreamOutcome::Success => "success",
            UpstreamOutcome::Rejected => "rejected",
            UpstreamOutcome::Aborted => "aborted",
            _ => "error",
        };
        self.record_upstream_result(event.upstream, transport, result);
        self.query_log.upstream_result(ctx, event);
        if !matches!(event.outcome, UpstreamOutcome::Aborted) {
            let key: Arc<str> = Arc::from(format!("{}\0{}", event.upstream, transport));
            // 超时会把整段超时时长计入平均耗时；响应耗时只看真正回了包的尝试。
            // A timeout adds its whole timeout to the average; the response latency
            // only looks at attempts that actually got a reply.
            if matches!(
                event.outcome,
                UpstreamOutcome::Success | UpstreamOutcome::Rejected
            ) {
                self.record_upstream_latency(
                    &self.upstream_response_latency,
                    Arc::clone(&key),
                    event.latency,
                );
            }
            self.record_upstream_latency(&self.upstream_latency, key, event.latency);
            self.increment(
                &self.upstream_via,
                Arc::from(format!(
                    "{}\0{}\0{}",
                    event.upstream,
                    transport,
                    transport_label(event.via)
                )),
            );
            if let Some(rcode) = event.rcode {
                self.increment(
                    &self.upstream_rcodes,
                    Arc::from(format!("{}\0{:?}", event.upstream, rcode)),
                );
            }
        }
        match event.outcome {
            UpstreamOutcome::Success => panel_trace::record(
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
            _ => panel_trace::record(
                "upstream",
                "failed",
                event.upstream,
                event.error.map(|error| format!("{error:#}")),
            ),
        }
    }

    fn config_loaded(&self, event: &ConfigLoaded<'_>) {
        if let Some(trace) = &self.debug_trace {
            trace.config_loaded(event);
        }
        match event.source {
            Some(source) => self.record_config_loaded(source),
            None => {
                let sha256 = self.active_config.read().sha256.clone();
                self.record_reload_success(sha256);
            }
        }
    }

    fn config_reload_failed(&self, event: &ConfigReloadFailed<'_>) {
        if let Some(trace) = &self.debug_trace {
            trace.config_reload_failed(event);
        }
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
        let (stream, _) = listener.accept().await?;
        let engine = engine.clone();
        let metrics = Arc::clone(&metrics);
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            if let Err(error) = hyper::server::conn::http1::Builder::new()
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
            Ok((window_seconds, limit)) => json_response(
                StatusCode::OK,
                metrics.stats_json(&engine, window_seconds, limit),
            ),
            Err(message) => json_response(
                StatusCode::BAD_REQUEST,
                error_json("stats_query_invalid", message),
            ),
        },
        (&Method::GET, "/v1/querylog") => match parse_querylog_query(request.uri().query()) {
            Ok((after, limit)) => text_response(
                StatusCode::OK,
                "application/json; charset=utf-8",
                metrics.query_log.collect(after, limit, PROTOCOL_VERSION),
            ),
            Err(message) => json_response(
                StatusCode::BAD_REQUEST,
                error_json("querylog_query_invalid", message),
            ),
        },
        (&Method::POST, "/v1/stats/clear") => {
            metrics.clear_stats(&engine);
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
            engine.cache.run_pending_tasks();
            let response_entries_before = engine.cache.weighted_size();
            let rule_entries_before = engine.rule_cache.entry_count();
            engine.cache.invalidate_all();
            engine.rule_cache.invalidate_all();
            engine.cache.run_pending_tasks();
            engine.rule_cache.run_pending_tasks();
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
    use hickory_proto::rr::{Name, RecordType};
    use std::str::FromStr;

    if domain.len() > 253 {
        return Err((
            StatusCode::BAD_REQUEST,
            error_json("diagnostic_domain_invalid", "域名过长"),
        ));
    }
    let name = Name::from_ascii(domain).map_err(|error| {
        (
            StatusCode::BAD_REQUEST,
            error_json("diagnostic_domain_invalid", &format!("域名无效：{error}")),
        )
    })?;
    let record_type = record_type.trim().to_ascii_uppercase();
    if !matches!(
        record_type.as_str(),
        "A" | "AAAA" | "CNAME" | "MX" | "NS" | "PTR" | "SOA" | "SRV" | "TXT"
    ) {
        return Err((
            StatusCode::BAD_REQUEST,
            error_json("diagnostic_record_type_invalid", "不支持的 DNS 记录类型"),
        ));
    }
    let parsed = RecordType::from_str(&record_type).map_err(|error| {
        (
            StatusCode::BAD_REQUEST,
            error_json(
                "diagnostic_record_type_invalid",
                &format!("记录类型无效：{error}"),
            ),
        )
    })?;
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

#[cfg(unix)]
async fn diagnostic_trace(request: Request<Incoming>, engine: Engine) -> Response<Full<Bytes>> {
    let body = match Limited::new(request.into_body(), MAX_DIAGNOSTIC_BODY)
        .collect()
        .await
    {
        Ok(body) => body.to_bytes(),
        Err(_) => {
            return json_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                error_json("diagnostic_body_invalid", "诊断请求不能超过 2 KiB"),
            );
        }
    };
    let request = match serde_json::from_slice::<DiagnosticRequest>(&body) {
        Ok(request) => request,
        Err(error) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                error_json(
                    "diagnostic_request_invalid",
                    &format!("诊断请求无效：{error}"),
                ),
            );
        }
    };
    let (packet, record_type) = match diagnostic_packet(&request.domain, &request.record_type) {
        Ok(prepared) => prepared,
        Err((status, body)) => return json_response(status, body),
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
    let body = match Limited::new(request.into_body(), MAX_TRIAL_BODY)
        .collect()
        .await
    {
        Ok(body) => body.to_bytes(),
        Err(_) => {
            return json_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                error_json("diagnostic_body_invalid", "试跑请求不能超过 4 MiB"),
            );
        }
    };
    let request = match serde_json::from_slice::<CandidateTraceRequest>(&body) {
        Ok(request) => request,
        Err(error) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                error_json(
                    "diagnostic_request_invalid",
                    &format!("试跑请求无效：{error}"),
                ),
            );
        }
    };
    // 查询字段先在这里查，错了不必起子进程 / Check the query fields here first; a bad one needs no child
    if let Err((status, body)) = diagnostic_packet(&request.domain, &request.record_type) {
        return json_response(status, body);
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
        Err(error) => (
            StatusCode::BAD_REQUEST,
            error_json(
                "diagnostic_request_invalid",
                &format!("试跑请求无效：{error}"),
            ),
        ),
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
    if let Err(error) = crate::config::validate(&raw) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            error_json(
                "config_invalid",
                &truncate(&format!("{error:#}"), MAX_ERROR_LENGTH),
            ),
        );
    }
    let built = crate::config::parse_config(&raw).and_then(|mut config| {
        config.settings.cache_background_refresh = false;
        let runtime = crate::matcher::RuntimePipelineConfig::from_config(config)?;
        Engine::builder(runtime)
            .listener_label(listener_label)
            .observer(Arc::new(PanelMetrics::new(false)))
            .build()
    });
    let engine = match built {
        Ok(engine) => engine,
        Err(error) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                error_json(
                    "config_invalid",
                    &truncate(&format!("{error:#}"), MAX_ERROR_LENGTH),
                ),
            );
        }
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

/// 查询日志的游标：`after` 是面板已经取到的最后一个序号（从没取过是 0），`limit` 默认取满一页
/// The query log cursor: `after` is the last sequence number the panel has taken (0 before the first),
/// and `limit` defaults to a full page
#[cfg(unix)]
fn parse_querylog_query(query: Option<&str>) -> Result<(u64, usize), &'static str> {
    let mut after = 0u64;
    let mut limit = panel_querylog::MAX_PAGE;
    for pair in query.into_iter().flat_map(|query| query.split('&')) {
        if pair.is_empty() {
            continue;
        }
        let Some((key, value)) = pair.split_once('=') else {
            return Err("查询参数格式无效");
        };
        match key {
            "after" => after = value.parse().map_err(|_| "游标无效")?,
            "limit" => {
                limit = value.parse().map_err(|_| "条数无效")?;
                if !(1..=panel_querylog::MAX_PAGE).contains(&limit) {
                    return Err("条数必须在 1 到 2000 之间");
                }
            }
            _ => return Err("包含不受支持的查询参数"),
        }
    }
    Ok((after, limit))
}

#[cfg(unix)]
async fn validate_config(request: Request<Incoming>) -> Response<Full<Bytes>> {
    let body = match Limited::new(request.into_body(), MAX_CONFIG_BODY)
        .collect()
        .await
    {
        Ok(body) => body.to_bytes(),
        Err(error) => {
            let message = if error.is::<http_body_util::LengthLimitError>() {
                "配置不能超过 4 MiB".to_owned()
            } else {
                "读取配置请求失败".to_owned()
            };
            return json_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                error_json("config_body_invalid", &message),
            );
        }
    };

    // 与引擎启动完全相同的校验路径，含监听地址与 DoH 证书检查。
    // The exact validation the engine runs at startup, listener and DoH checks included.
    match crate::config::validate(std::str::from_utf8(&body).unwrap_or_default()) {
        Ok(report) => json_response(
            StatusCode::OK,
            json!({
                "protocol_version": PROTOCOL_VERSION,
                "valid": true,
                "pipeline_count": report.pipeline_count,
                "rule_count": report.rule_count,
            }),
        ),
        Err(error) => json_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            error_json(
                "config_invalid",
                &truncate(&format!("{error:#}"), MAX_ERROR_LENGTH),
            ),
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

fn append_map(
    output: &mut String,
    name: &str,
    map: &DashMap<Arc<str>, AtomicU64>,
    labels: &[&str],
) {
    let mut rows = map
        .iter()
        .map(|entry| {
            (
                entry.key().to_string(),
                entry.value().load(Ordering::Relaxed),
            )
        })
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
    map: &DashMap<Arc<str>, LatencySum>,
    labels: &[&str],
) {
    let mut rows = map
        .iter()
        .map(|entry| {
            (
                entry.key().to_string(),
                entry.value().micros.load(Ordering::Relaxed),
                entry.value().count.load(Ordering::Relaxed),
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
    use std::fmt::Write;
    let _ = writeln!(output, "{name} {value}");
}

fn labeled_metric(
    output: &mut String,
    name: &str,
    labels: &[(&str, &str)],
    value: impl std::fmt::Display,
) {
    use std::fmt::Write;
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
    use std::net::IpAddr;

    use super::{MAX_METRIC_SERIES_PER_MAP, PanelMetrics, QUERY_STATS_DOMAIN_CAP, QueryStats};

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

    /// `EngineObserver` 的全部 15 个方法，与 `TracingObserver` 写出的 `event` 字段值一一对应；
    /// 少转发任何一个，`--debug` 就会悄悄丢掉那一类事件日志。
    /// All 15 `EngineObserver` methods, paired with the `event` field value `TracingObserver`
    /// writes for each; dropping any single forward silently loses that event kind under `--debug`.
    const OBSERVER_EVENT_NAMES: [&str; 15] = [
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
        "config_loaded",
        "config_reload_failed",
    ];

    /// 在带目标名的 tracing 订阅者下把 15 个观察者方法各驱动一次，返回它写出的全部日志文本。
    /// Drives each of the 15 observer methods once under a target-printing tracing subscriber
    /// and returns everything it logged.
    fn captured_observer_output(metrics: &PanelMetrics) -> String {
        use crate::config::Transport;
        use crate::observe::{
            CacheHit, CacheHitKind, ConfigLoaded, ConfigReloadFailed, DecisionDetail, DecisionKind,
            DecisionMade, EngineObserver, RequestContext, RequestOutcome, RequestStatus,
            RuleCacheLookup, RuleEvaluated, RuleMatched, RulePhase, UpstreamAttempt,
            UpstreamOutcome, UpstreamResult,
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
            request_id: 7,
            listener_label: "default",
            client: "127.0.0.1:53000".parse().unwrap(),
            transport: None,
            qname: "example.com",
            qtype: hickory_proto::rr::RecordType::A,
            qclass: hickory_proto::rr::DNSClass::IN,
            background_refresh: true,
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
                &UpstreamResult {
                    upstream: "1.1.1.1:53",
                    transport: Transport::Udp,
                    via: Transport::Udp,
                    outcome: UpstreamOutcome::Success,
                    latency: Duration::from_millis(12),
                    rcode: Some(ResponseCode::NoError),
                    truncated: Some(false),
                    error: None,
                },
            );
            metrics.request_finished(
                &ctx,
                &RequestOutcome {
                    latency: Duration::from_millis(13),
                    status: RequestStatus::Completed,
                    response: Some(&[]),
                    error: None,
                },
            );
            metrics.config_loaded(&ConfigLoaded {
                path: None,
                generation: 1,
                source: Some("{}"),
            });
            metrics.config_reload_failed(&ConfigReloadFailed {
                path: std::path::Path::new("pipeline.json"),
                error: "broken",
            });
        });
        let bytes = buffer.0.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }

    /// `--debug` 必须把 15 个引擎事件（含后台刷新）逐一转发给上游参考观察者；
    /// 不带 `--debug` 时一条都不该出现。
    /// `--debug` must forward every one of the 15 engine events (background refresh included)
    /// to the upstream reference observer; without `--debug` none may appear.
    /// 跳转过的请求会在目标 pipeline 下再查一次缓存，但只计一次查找：命中率按请求算，
    /// 否则跳转过的请求命中时，看板上的命中率只有一半。请求结束后不再记着它。
    /// A request that jumps looks in the cache again under the target pipeline but
    /// counts one lookup: the hit rate is per request, or a jumped request's hit would
    /// show as half a hit on the dashboard. Nothing is kept once the request ends.
    #[test]
    fn a_request_that_looks_again_after_a_jump_counts_one_lookup() {
        use crate::observe::{
            CacheHit, CacheHitKind, EngineObserver, RequestContext, RequestOutcome, RequestStatus,
        };
        use hickory_proto::rr::{DNSClass, RecordType};
        use std::sync::atomic::Ordering;
        use std::time::Duration;

        let metrics = PanelMetrics::default();
        let ctx = RequestContext {
            request_id: 41,
            listener_label: "default",
            client: "192.0.2.10:53000".parse().unwrap(),
            transport: None,
            qname: "jumped.example",
            qtype: RecordType::A,
            qclass: DNSClass::IN,
            background_refresh: false,
        };
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
        metrics.request_finished(
            &ctx,
            &RequestOutcome {
                latency: Duration::from_millis(1),
                status: RequestStatus::Completed,
                response: Some(&[]),
                error: None,
            },
        );

        assert_eq!(metrics.cache_lookups_total.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.cache_hits_fresh.load(Ordering::Relaxed), 1);
        assert!(metrics.cache_lookup_counted.is_empty());
    }

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
            metrics
                .pipeline_hits
                .get("pipeline-0")
                .unwrap()
                .load(super::Ordering::Relaxed),
            2
        );
    }

    #[test]
    fn observer_events_drive_counters_and_config_state() {
        use crate::observe::{
            ConfigLoaded, ConfigReloadFailed, DecisionKind, EngineObserver, RequestContext,
            RequestOutcome, RequestStatus, RuleMatched, RulePhase,
        };
        use hickory_proto::rr::{DNSClass, RecordType};

        let metrics = PanelMetrics::default();
        let source = r#"{"settings":{"statistics_enabled":true}}"#;
        metrics.config_loaded(&ConfigLoaded {
            path: Some(std::path::Path::new("pipeline.json")),
            generation: 1,
            source: Some(source),
        });
        {
            let active = metrics.active_config.read();
            assert_eq!(active.generation, 1);
            assert_eq!(active.sha256.len(), 64);
            assert!(active.last_reload_success);
        }
        assert_eq!(metrics.reload_success.load(super::Ordering::Relaxed), 0);

        let ctx = RequestContext {
            request_id: 1,
            listener_label: "default",
            client: "192.168.1.9:5353".parse().unwrap(),
            transport: None,
            qname: "example.com",
            qtype: RecordType::A,
            qclass: DNSClass::IN,
            background_refresh: false,
        };
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
        metrics.request_finished(
            &ctx,
            &RequestOutcome {
                latency: std::time::Duration::from_millis(1),
                status: RequestStatus::Completed,
                response: Some(&[]),
                error: None,
            },
        );

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
        assert_eq!(
            metrics
                .pipeline_hits
                .get("main")
                .unwrap()
                .load(super::Ordering::Relaxed),
            1
        );
        assert_eq!(
            metrics
                .rule_matches
                .get("main\0forward-all\0request")
                .unwrap()
                .load(super::Ordering::Relaxed),
            1
        );
        assert!(
            metrics
                .rule_matches
                .get("main\0forward-all\0response")
                .is_none()
        );
        let now = super::unix_timestamp();
        let snapshot = metrics.query_stats.snapshot(now, 3_600, 20);
        assert!(snapshot.enabled);
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
        });
        let active = metrics.active_config.read();
        assert_eq!(active.generation, 2);
        assert_eq!(metrics.reload_failure.load(super::Ordering::Relaxed), 1);
        assert_eq!(metrics.reload_success.load(super::Ordering::Relaxed), 1);
        assert!(!metrics.query_stats.snapshot(now, 3_600, 20).enabled);
    }

    #[test]
    fn response_latency_counts_only_attempts_that_got_a_reply() {
        use crate::config::Transport;
        use crate::observe::{EngineObserver, RequestContext, UpstreamOutcome, UpstreamResult};
        use hickory_proto::op::ResponseCode;
        use hickory_proto::rr::{DNSClass, RecordType};
        use std::time::Duration;

        let metrics = PanelMetrics::default();
        let ctx = RequestContext {
            request_id: 1,
            listener_label: "default",
            client: "127.0.0.1:5353".parse().unwrap(),
            transport: None,
            qname: "example.com",
            qtype: RecordType::A,
            qclass: DNSClass::IN,
            background_refresh: false,
        };
        let result = |outcome, rcode, millis| UpstreamResult {
            upstream: "1.1.1.1:53",
            transport: Transport::Udp,
            outcome,
            via: Transport::Udp,
            latency: Duration::from_millis(millis),
            rcode,
            truncated: Some(false),
            error: None,
        };
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

    #[test]
    fn latency_rcode_via_and_stale_reason_series_render() {
        use crate::config::Transport;
        use crate::observe::{
            CacheHit, CacheHitKind, EngineObserver, RequestContext, RequestOutcome, RequestStatus,
            UpstreamOutcome, UpstreamResult,
        };
        use hickory_proto::op::ResponseCode;
        use hickory_proto::rr::{DNSClass, RecordType};
        use std::time::Duration;

        let metrics = PanelMetrics::default();
        let ctx = RequestContext {
            request_id: 1,
            listener_label: "default",
            client: "127.0.0.1:5353".parse().unwrap(),
            transport: None,
            qname: "example.com",
            qtype: RecordType::A,
            qclass: DNSClass::IN,
            background_refresh: false,
        };
        let result = |outcome, via, rcode, millis| UpstreamResult {
            upstream: "1.1.1.1:53",
            transport: Transport::Udp,
            outcome,
            via,
            latency: Duration::from_millis(millis),
            rcode,
            truncated: Some(false),
            error: None,
        };
        metrics.upstream_result(
            &ctx,
            &result(
                UpstreamOutcome::Success,
                Transport::Udp,
                Some(ResponseCode::NoError),
                12,
            ),
        );
        metrics.upstream_result(
            &ctx,
            &result(
                UpstreamOutcome::Success,
                Transport::Tcp,
                Some(ResponseCode::NXDomain),
                30,
            ),
        );
        // 竞争落败不计入耗时、响应码和传输 / aborted attempts never reach latency, rcode or via
        metrics.upstream_result(
            &ctx,
            &result(UpstreamOutcome::Aborted, Transport::Udp, None, 500),
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
        metrics.request_finished(
            &ctx,
            &RequestOutcome {
                latency: Duration::from_millis(7),
                status: RequestStatus::Completed,
                response: Some(&[]),
                error: None,
            },
        );
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
    fn ranks_domains_and_clients_with_anonymization() {
        let stats = QueryStats::default();
        stats.configure(true, true);
        let now = 100 * super::QUERY_STATS_BUCKET_SECONDS + 120;
        for _ in 0..3 {
            stats.record_at("example.com", "192.168.1.42".parse().unwrap(), true, now);
        }
        stats.record_at("other.test", "192.168.2.9".parse().unwrap(), true, now);

        let snapshot = stats.snapshot(now, 3_600, 20);
        assert!(snapshot.enabled);
        assert!(snapshot.anonymized_clients);
        assert_eq!(snapshot.requests_observed, 4);
        assert_eq!(snapshot.domains[0].name, "example.com");
        assert_eq!(snapshot.domains[0].count, 3);
        assert_eq!(snapshot.clients[0].name, "192.168.1.0/24");
        assert_eq!(snapshot.clients[0].count, 3);
    }

    #[test]
    fn clears_rankings_when_collection_is_disabled() {
        let stats = QueryStats::default();
        let client: IpAddr = "127.0.0.1".parse().unwrap();
        stats.configure(true, false);
        stats.record_at("example.com", client, false, 3_600);
        assert_eq!(stats.snapshot(3_600, 3_600, 20).requests_observed, 1);

        stats.configure(false, false);
        let snapshot = stats.snapshot(3_600, 3_600, 20);
        assert!(!snapshot.enabled);
        assert!(snapshot.domains.is_empty());
        assert!(snapshot.clients.is_empty());
    }

    #[test]
    fn caps_unique_domains_and_reports_dropped_updates() {
        let stats = QueryStats::default();
        stats.configure(true, false);
        let client: IpAddr = "127.0.0.1".parse().unwrap();
        for index in 0..QUERY_STATS_DOMAIN_CAP + 8 {
            stats.record_at(&format!("{index}.example"), client, false, 3_600);
        }

        let snapshot = stats.snapshot(3_600, 3_600, QUERY_STATS_DOMAIN_CAP + 8);
        assert_eq!(snapshot.domains.len(), QUERY_STATS_DOMAIN_CAP);
        assert_eq!(snapshot.dropped_updates, 8);
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
            "settings": { "default_upstream": "1.1.1.1:53", "udp_pool_size": 1, "statistics_enabled": true },
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

    fn engine_for(raw: serde_json::Value, metrics: Arc<PanelMetrics>) -> Engine {
        let config: crate::config::PipelineConfig =
            serde_json::from_value(raw).expect("parse config");
        let runtime = RuntimePipelineConfig::from_config(config).expect("build runtime config");
        Engine::builder(runtime)
            .listener_label("default")
            .observer(metrics)
            .build()
            .expect("build engine")
    }

    fn answers(body: &serde_json::Value) -> Vec<String> {
        body["answers"]
            .as_array()
            .expect("answers")
            .iter()
            .map(|answer| answer.as_str().unwrap_or_default().to_owned())
            .collect()
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
        assert!(
            answers(&body)
                .iter()
                .any(|answer| answer.contains("10.0.0.1")),
            "{body}"
        );
        let parsed = body["trace"][0]["detail"].as_str().unwrap_or_default();
        assert!(parsed.contains("客户端：192.168.1.9"), "{parsed}");

        // 写成 IPv4 映射形式的地址按 IPv4 地址判断，回复里也这样写
        // An address in the IPv4-mapped form is judged, and reported, as the IPv4 address
        let mapped: IpAddr = "::ffff:192.168.1.9".parse().unwrap();
        let (status, body) =
            run_diagnostic(&engine, &packet, Some(mapped), "nas.example", &record_type).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["client_ip"], "192.168.1.9");
        assert!(
            answers(&body)
                .iter()
                .any(|answer| answer.contains("10.0.0.1")),
            "{body}"
        );

        // 不填就是本机回环，落到「其余」 / Omitted means loopback, which lands on "rest"
        let (status, body) =
            run_diagnostic(&engine, &packet, None, "nas.example", &record_type).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["client_ip"], "127.0.0.1");
        assert!(
            answers(&body)
                .iter()
                .any(|answer| answer.contains("10.0.0.2")),
            "{body}"
        );
    }

    #[tokio::test]
    async fn diagnostic_queries_stay_out_of_the_query_ranking() {
        let metrics = Arc::new(PanelMetrics::new(false));
        metrics.query_stats.configure(true, false);
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
        assert!(
            answers(&body)
                .iter()
                .any(|answer| answer.contains("10.0.0.1")),
            "{body}"
        );
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

    #[test]
    fn health_declares_both_new_diagnostic_capabilities() {
        let health = PanelMetrics::new(false).health_json();
        let capabilities: Vec<&str> = health["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|value| value.as_str())
            .collect();
        assert!(capabilities.contains(&"diagnostics_trace_client_v1"));
        assert!(capabilities.contains(&"diagnostics_trace_candidate_v1"));
    }

    #[test]
    fn health_declares_the_query_log() {
        let health = PanelMetrics::new(false).health_json();
        assert!(
            health["capabilities"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == "querylog_v1")
        );
    }

    #[test]
    fn the_query_log_cursor_is_checked() {
        use super::parse_querylog_query;
        assert_eq!(
            parse_querylog_query(None),
            Ok((0, crate::panel_querylog::MAX_PAGE))
        );
        assert_eq!(
            parse_querylog_query(Some("after=42&limit=10")),
            Ok((42, 10))
        );
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
        let _ = metrics.query_log.collect(0, 10, super::PROTOCOL_VERSION);
        let client = std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)), 5353);
        for name in ["denied.example", "rescued.example", "moved.example"] {
            let (packet, _) = diagnostic_packet(name, "A").expect("packet");
            engine.handle_packet(&packet, client).await.expect("query");
        }
        task.abort();

        let page: serde_json::Value =
            serde_json::from_str(&metrics.query_log.collect(0, 10, super::PROTOCOL_VERSION))
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

    /// 真引擎走一遍：面板取过一次以后，普通查询进日志（谁问的、哪条规则、回了什么），诊断查询不进
    /// Through a real engine: once the panel has collected, a normal query is recorded (who asked,
    /// which rule, what came back) and a diagnostic query is not
    #[tokio::test]
    async fn the_query_log_records_real_queries_and_leaves_diagnostics_out() {
        let metrics = Arc::new(PanelMetrics::new(false));
        let engine = engine_for(client_split_config("192.168.1.0/24"), Arc::clone(&metrics));
        let (packet, record_type) = diagnostic_packet("nas.example", "A").expect("packet");
        let _ = metrics.query_log.collect(0, 10, super::PROTOCOL_VERSION);

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

        let page: serde_json::Value =
            serde_json::from_str(&metrics.query_log.collect(0, 10, super::PROTOCOL_VERSION))
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
}
