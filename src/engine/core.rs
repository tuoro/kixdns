use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::Context;
use arc_swap::ArcSwap;
use dashmap::{DashMap, DashSet};
use moka::sync::Cache;
use parking_lot::Mutex;
use rustc_hash::{FxBuildHasher, FxHashMap};

use super::geo::GeoSources;
use crate::cache::{CacheEntry, CacheSlot, CachedQuestion, DnsCache, new_cache};
use crate::ecs_scope::EcsView;
use crate::engine::refresh::RefreshTarget;
use crate::lock::RwLock;
use crate::matcher::RuntimePipelineConfig;
use crate::matcher::advanced_rule::compile_pipelines;
use crate::matcher::geoip::GeoIpManager;
use crate::matcher::geosite::GeoSiteManager;
use crate::observe::{ClientTransport, ConfigLoaded, ConfigReloadFailed, EngineObserver};
use moka::ops::compute::Op;

use super::concurrency::{FlowControlState, PermitManager};
use super::rules::RuleCacheRecord;
use super::transport::{DohClient, DoqClient, DotMultiplexer, TcpMultiplexer, UdpClient};
use super::types::{EngineInner, InflightMap, build_cache_namespaces};

#[derive(Clone)]
pub struct Engine {
    pub(crate) state: Arc<ArcSwap<EngineInner>>,
    pub(crate) cache: DnsCache,
    /// The cache's `time_to_live` (`cache_max_ttl`), which each answer in a slot keeps
    /// to on its own (see `CacheEntry::stored_at`)
    /// 缓存的 `time_to_live`（`cache_max_ttl`），槽位里的每份应答各自遵守（见 `CacheEntry::stored_at`）
    pub(crate) cache_max_age: Option<Duration>,
    pub(crate) udp_client: Arc<UdpClient>,
    pub(crate) tcp_mux: Arc<TcpMultiplexer>,
    pub(crate) doh_client: Arc<DohClient>,
    pub(crate) dot_mux: Arc<DotMultiplexer>,
    pub(crate) doq_client: Arc<DoqClient>,
    pub listener_label: Arc<str>,
    // Transport this handle's requests arrive over, set by the listener that owns the handle.
    // 本句柄的请求经由的传输，由持有该句柄的监听器设置。
    pub(crate) client_transport: Option<ClientTransport>,
    // Optional event sink; None keeps the request path free of event construction.
    // 可选事件接收器；None 时请求路径不构造任何事件。
    pub(crate) observer: Option<Arc<dyn EngineObserver>>,
    // Active configuration generation: 1 at startup, +1 per reload / 当前配置代数：启动为 1，每次重载 +1
    pub(crate) config_generation: Arc<AtomicU64>,
    // The settings the process started with: those read only at startup keep
    // these values until a restart / 进程启动时的设置：只在启动时读取的那些，到重启前一直是这些值
    pub(crate) running_settings: Arc<crate::config::GlobalSettings>,
    // Serialises reloads so the stored state, the generation and the
    // config_loaded event of one reload cannot interleave with another's. It
    // also keeps where the Geo data came from, which only a reload changes.
    // 串行化重载，使一次重载的状态存储、代数分配与 config_loaded 事件不与另一次交错；
    // 同时保管 Geo 数据的来源，只有重载会改它。
    pub(crate) reload_lock: Arc<Mutex<GeoSources>>,
    // Rule execution result cache: Hash -> (Key, Decision) / 规则执行结果缓存：哈希 -> (键, 决策)
    // Key is stored to verify collisions / 存储键以验证冲突
    pub(crate) rule_cache: Cache<u64, RuleCacheRecord>,
    // Per-request id generator for tracing / 每个请求的 ID 生成器用于追踪
    pub request_id_counter: Arc<AtomicU64>,
    /// In-flight request deduplication map using tokio::watch for lock-free concurrent waiting
    /// 使用 tokio::watch 实现无锁并发等待的进行中请求去重 map
    /// Key: the hash of the question asked (see `InflightQuestion::key`)
    /// Value: watch sender that will be notified when upstream query completes
    /// 键：所问问题的哈希（见 `InflightQuestion::key`）；值：上游查询结束时通知的 watch sender
    pub inflight: Arc<InflightMap>,
    /// 正在刷新的条目的刷新标记（见 `RefreshingGuard`）：同一条同时只刷新一次
    /// The refresh marks of the entries being refreshed (see `RefreshingGuard`): one
    /// refresh of an entry at a time
    pub refreshing_set: Arc<DashSet<u64>>,
    // Semaphore to limit concurrent handle_packet async tasks / 用于限制并发 handle_packet 异步任务数量
    pub permit_manager: Arc<PermitManager>,
    // Latest upstream latency for adaptive flow control / 用于自适应流控的最新上游延迟
    pub metrics_last_upstream_latency_ns: Arc<AtomicU64>,
    // Adaptive flow control state (None when flow control is disabled) / 自适应流控状态（禁用流控时为None）
    pub flow_control_state: Option<Arc<FlowControlState>>,
    // GeoIP manager for geographic IP-based routing / GeoIP 管理器用于基于地理位置的 IP 路由
    pub geoip_manager: Arc<RwLock<GeoIpManager>>,
    // GeoSite manager for domain category-based routing / GeoSite 管理器用于域名分类路由
    // 使用 RwLock 允许并发读操作，写操作独占 / Uses RwLock for concurrent reads, exclusive writes
    pub geosite_manager: Arc<RwLock<GeoSiteManager>>,
}

/// Configures and constructs an [`Engine`]. Obtain one via [`Engine::builder`].
pub struct EngineBuilder {
    cfg: RuntimePipelineConfig,
    listener_label: String,
    observer: Option<Arc<dyn EngineObserver>>,
    config_source: Option<(PathBuf, String)>,
}

impl EngineBuilder {
    /// Listener label used for `listener_label` pipeline selectors (default: `"default"`).
    pub fn listener_label(mut self, label: impl Into<String>) -> Self {
        self.listener_label = label.into();
        self
    }

    /// Install an [`EngineObserver`] that receives engine events.
    pub fn observer(mut self, observer: Arc<dyn EngineObserver>) -> Self {
        self.observer = Some(observer);
        self
    }

    /// Record where the initial configuration came from, so the
    /// `config_loaded` event reported by [`build`] carries the path and text.
    ///
    /// [`build`]: EngineBuilder::build
    pub fn config_source(mut self, path: impl Into<PathBuf>, source: impl Into<String>) -> Self {
        self.config_source = Some((path.into(), source.into()));
        self
    }

    /// Build the engine, initialising transports, caches and GeoIP/GeoSite
    /// data, and report the initial configuration (generation `1`) to the
    /// observer.
    pub fn build(self) -> anyhow::Result<Engine> {
        let engine = Engine::build(self.cfg, self.listener_label, self.observer)?;
        let source = self.config_source.as_ref();
        engine.report_config_loaded(
            1,
            source.map(|(path, _)| path.as_path()),
            source.map(|(_, text)| text.as_str()),
        );
        Ok(engine)
    }
}

impl Engine {
    /// 应答带的、缓存用的 TTL 最长多少：`cache_max_ttl`
    /// The longest TTL an answer may carry or be cached with: `cache_max_ttl`
    pub(crate) fn ttl_cap(&self) -> u32 {
        self.cache_max_age.map_or(u32::MAX, |age| {
            crate::proto_utils::saturating_u64_to_u32(age.as_secs())
        })
    }

    /// Start configuring an engine for `cfg`.
    pub fn builder(cfg: RuntimePipelineConfig) -> EngineBuilder {
        EngineBuilder {
            cfg,
            listener_label: "default".to_string(),
            observer: None,
            config_source: None,
        }
    }

    /// Build an engine without an observer. Equivalent to
    /// `Engine::builder(cfg).listener_label(listener_label).build()`.
    pub fn new(cfg: RuntimePipelineConfig, listener_label: String) -> anyhow::Result<Self> {
        Self::builder(cfg).listener_label(listener_label).build()
    }

    /// Tag this handle with the transport its requests arrive over, reported
    /// to observers as [`RequestContext::transport`]. Each listener tags a
    /// handle of its own; the engine behind it (configuration, caches,
    /// metrics, observer) stays shared, and pipeline selection is unaffected.
    ///
    /// The tag travels with [`Clone`], and tagging again replaces it: clone
    /// the untagged engine for each listener, or re-tag the clone, rather
    /// than serving one transport with a handle tagged for another.
    ///
    /// [`RequestContext::transport`]: crate::observe::RequestContext::transport
    pub fn with_client_transport(mut self, transport: ClientTransport) -> Self {
        self.client_transport = Some(transport);
        self
    }

    fn build(
        cfg: RuntimePipelineConfig,
        listener_label: String,
        observer: Option<Arc<dyn EngineObserver>>,
    ) -> anyhow::Result<Self> {
        // moka 缓存：容量由配置控制（默认 10000 条），最大生存时间由 cache_max_ttl 控制
        // moka cache capacity and max TTL are configurable via settings
        let running_settings = Arc::new(cfg.settings.clone());
        let cache_capacity = cfg.settings.cache_capacity;
        let cache_max_ttl = cfg.settings.cache_max_ttl;
        let cache = new_cache(cache_capacity, cache_max_ttl);
        // Rule cache: 10k entries, long default TTL (managed manually per-entry)
        // 规则缓存：1万条，默认长 TTL（通过条目内部 expires_at 手动管理）
        let rule_cache = Cache::builder()
            .max_capacity(10_000)
            .time_to_live(Duration::from_secs(60))
            .build();

        // Extract flow control settings before moving cfg / 在 move cfg 之前提取流控设置
        let udp_pool_size = cfg.settings.udp_pool_size;
        let tcp_pool_size = cfg.settings.tcp_pool_size;
        let doh_pool_size = cfg.settings.doh_pool_size;
        let doh_health_error_threshold = cfg.settings.doh_health_check_error_threshold;
        let dot_pool_size = cfg.settings.dot_pool_size;
        let doq_pool_size = cfg.settings.doq_pool_size;
        let doq_idle_timeout_secs = cfg.settings.doq_connection_idle_timeout_seconds;
        let doq_keepalive_interval_ms = cfg.settings.doq_keepalive_interval_ms;
        let doq_enable_0rtt = cfg.settings.doq_enable_0rtt;
        let flow_control_enabled = cfg.settings.flow_control_enabled;
        let flow_control_initial_permits = cfg.settings.flow_control_initial_permits;
        let flow_control_min_permits = cfg.settings.flow_control_min_permits;
        let flow_control_max_permits = cfg.settings.flow_control_max_permits;
        let flow_control_latency_threshold_ms = cfg.settings.flow_control_latency_threshold_ms;
        let flow_control_adjustment_interval_secs =
            cfg.settings.flow_control_adjustment_interval_secs;
        let dashmap_shards = cfg.settings.dashmap_shards;

        // Extract TCP health check settings / 提取 TCP 健康检查配置
        let tcp_health_error_threshold = cfg.settings.tcp_health_check_error_threshold;
        let tcp_max_age_secs = cfg.settings.tcp_connection_max_age_seconds;
        let tcp_idle_timeout_secs = cfg.settings.tcp_connection_idle_timeout_seconds;

        let geoip_manager = Arc::new(RwLock::new(
            GeoIpManager::new(None).expect("GeoIpManager::new(None) should always succeed"),
        ));
        let geosite_manager = Arc::new(RwLock::new(GeoSiteManager::new()));
        let geo_sources = GeoSources::load(&cfg, &geosite_manager, &geoip_manager);

        let compiled = compile_pipelines(&cfg);

        // Build O(1) compiled pipeline lookup index / 构建 O(1) 编译管道查找索引
        let pipeline_index: FxHashMap<Arc<str>, usize> = compiled
            .iter()
            .enumerate()
            .map(|(i, p)| (p.id.clone(), i))
            .collect();

        let state = Arc::new(ArcSwap::from_pointee(EngineInner {
            cache_namespaces: build_cache_namespaces(&cfg),
            pipeline: cfg,
            compiled_pipelines: compiled,
            pipeline_index,
        }));

        // 根据配置决定是否启用流控 / Decide whether to enable flow control based on configuration
        // 如果禁用流控，使用usize::MAX作为max_permits，实现"无限制"模式
        // When flow control is disabled, use usize::MAX as max_permits for "unlimited" mode
        let (permit_manager, flow_control_state) = if flow_control_enabled {
            // PermitManager.max_permits 是"当前上限"，FlowControlState.max_permits
            // 是天花板。此前紧接着的一行把当前上限直接写成天花板，
            // flow_control_initial_permits 当场失效，开了流控的部署实际从 800
            // 起步而不是文档写的 500。现在按初始值起步，由 adjust 往天花板爬。
            // PermitManager.max_permits is the *current* limit while
            // FlowControlState.max_permits is the ceiling. The next line used to
            // overwrite the current limit with the ceiling, which made
            // flow_control_initial_permits dead on arrival and started a
            // flow-controlled deployment at 800 rather than the documented 500.
            // It now starts at the initial value and adjust climbs toward the
            // ceiling.
            let pm = Arc::new(PermitManager::new(flow_control_initial_permits));
            (
                pm,
                Some(Arc::new(FlowControlState {
                    max_permits: AtomicUsize::new(flow_control_max_permits),
                    min_permits: flow_control_min_permits,
                    last_adjustment_ms: AtomicU64::new(0),
                    critical_latency_threshold_ns: flow_control_latency_threshold_ms * 1_000_000,
                    adjustment_interval_ms: flow_control_adjustment_interval_secs * 1000,
                })),
            )
        } else {
            // 无限制模式：创建一个max_permits=usize::MAX的PermitManager
            // Unlimited mode: create a PermitManager with max_permits=usize::MAX
            let pm = Arc::new(PermitManager::new_unlimited());
            (pm, None)
        };

        // TCP pool size is per-upstream; each upstream gets its own permit manager
        // TCP 连接池大小为"每个 upstream"独立配置；每个 upstream 有各自的 permit manager

        // Collect TCP upstreams for warmup / 收集 TCP upstream 用于预热
        let tcp_upstreams = state.load().pipeline.collect_tcp_upstreams();

        let tcp_mux = Arc::new(TcpMultiplexer::new(
            tcp_pool_size,
            tcp_health_error_threshold,
            tcp_max_age_secs,
            tcp_idle_timeout_secs,
        ));

        let dot_mux = Arc::new(
            DotMultiplexer::new(
                dot_pool_size,
                tcp_health_error_threshold,
                tcp_max_age_secs,
                tcp_idle_timeout_secs,
            )
            .context("initialize DoT multiplexer")?,
        );

        let doh_client = Arc::new(
            DohClient::new(doh_pool_size, doh_health_error_threshold)
                .context("initialize DoH client")?,
        );
        let doq_client = Arc::new(
            DoqClient::new(
                doq_pool_size,
                doq_idle_timeout_secs,
                doq_keepalive_interval_ms,
                doq_enable_0rtt,
            )
            .context("initialize DoQ client")?,
        );

        // Warm up TCP connection pools (see `TcpMultiplexer::warm_up_pools`)
        // 预热 TCP 连接池（见 `TcpMultiplexer::warm_up_pools`）
        tcp_mux.warm_up_pools(&tcp_upstreams);

        Ok(Self {
            state,
            cache_max_age: cache.policy().time_to_live(),
            cache,
            udp_client: Arc::new(UdpClient::new(udp_pool_size).context("initialize UDP client")?),
            tcp_mux,
            doh_client,
            dot_mux,
            doq_client,
            listener_label: Arc::from(listener_label),
            client_transport: None,
            observer,
            config_generation: Arc::new(AtomicU64::new(1)),
            running_settings,
            reload_lock: Arc::new(Mutex::new(geo_sources)),
            rule_cache,
            metrics_last_upstream_latency_ns: Arc::new(AtomicU64::new(0)),
            request_id_counter: Arc::new(AtomicU64::new(1)),
            // DashMap configuration: shard count and initial capacity
            // If dashmap_shards is 0, use DashMap default (num_cpus * 4)
            // More shards = less lock contention but more memory overhead
            inflight: if dashmap_shards == 0 {
                Arc::new(DashMap::with_capacity_and_hasher(128, FxBuildHasher))
            } else {
                Arc::new(DashMap::with_capacity_and_hasher_and_shard_amount(
                    128,
                    FxBuildHasher,
                    dashmap_shards,
                ))
            },
            refreshing_set: Arc::new(DashSet::new()),
            permit_manager,
            flow_control_state,
            // Cache background refresh settings / 缓存后台刷新设置

            // RFC 8767: Serve stale cache settings / RFC 8767: 过期缓存设置

            // GeoIP manager / GeoIP 管理器
            geoip_manager,
            // GeoSite manager / GeoSite 管理器
            geosite_manager,
        })
    }

    /// 槽位 `slot` 里 `question` 的、适用于 `view` 的那份应答（见 `CacheSlot::select`）
    /// The answer to `question` in slot `slot` that applies to `view` (see
    /// `CacheSlot::select`)
    /// `now` 是查找的时刻，调用方用同一个时刻算应答已经存了多久，免得每次命中多读一次时钟。
    /// `now` is the time of the lookup; callers age the answer from the same instant,
    /// so a hit reads the clock once.
    pub(crate) fn cache_get(
        &self,
        slot: u64,
        view: &EcsView,
        question: &CachedQuestion<'_>,
        now: std::time::Instant,
    ) -> Option<Arc<CacheEntry>> {
        self.cache.get(&slot)?.select(
            view,
            |entry| question.matches(entry),
            self.cache_max_age,
            now,
        )
    }

    /// 从槽位 `slot` 去掉 `remove` 选中的应答 / Remove from slot `slot` the answers `remove` picks
    pub(crate) fn cache_remove(&self, slot: u64, remove: impl Fn(&CacheEntry) -> bool) {
        self.cache
            .entry(slot)
            .and_compute_with(|current| match current {
                None => Op::Nop,
                Some(current) => match current.value().without(&remove) {
                    None => Op::Nop,
                    Some(rest) if rest.is_empty() => Op::Remove,
                    Some(rest) => Op::Put(Arc::new(rest)),
                },
            });
    }

    /// 从槽位 `slot` 去掉这一份应答 / Remove this one answer from slot `slot`
    pub(crate) fn cache_invalidate(&self, slot: u64, entry: &Arc<CacheEntry>) {
        self.cache_remove(slot, |cached| std::ptr::eq(cached, entry.as_ref()));
    }

    /// 把槽位 `slot` 里的 `old` 这一份换成 `new`；`old` 已经不在（被取代或去掉）时什么都不做。
    /// 过期应答续期用它，不碰槽位里的其他应答。
    /// Replace `old` itself in slot `slot` with `new`; nothing happens when `old` is
    /// gone (replaced or removed). Renewing a stale answer uses it, leaving the
    /// slot's other answers alone.
    pub(crate) fn cache_replace(&self, slot: u64, old: &Arc<CacheEntry>, new: CacheEntry) {
        let new = Arc::new(new);
        self.cache
            .entry(slot)
            .and_compute_with(|current| match current {
                None => Op::Nop,
                Some(current) => match current.value().replacing(old, new) {
                    None => Op::Nop,
                    Some(slot) => Op::Put(Arc::new(slot)),
                },
            });
    }

    /// 去掉后台刷新发现已和规则对不上的条目：刷新的就是这个槽位时，去掉它要更新的那条；
    /// 否则（刷新走到了别的 pipeline）去掉这个槽位里适用于它的请求方、在刷新开始之前取得的
    /// 条目；之后取得的来自别的请求，不动。
    /// Drop the entry a background refresh found no longer matches the rules: the
    /// one it renews when it renews this slot, otherwise (the refresh went to
    /// another pipeline) the ones in this slot for its requester fetched before
    /// the refresh started; later ones come from other requests and stay.
    pub(crate) fn drop_refreshed(
        &self,
        slot: u64,
        question: &CachedQuestion<'_>,
        view: &EcsView,
        target: &RefreshTarget,
    ) {
        self.cache_remove(slot, |entry| {
            question.matches(entry)
                && if target.slot == slot {
                    // The renewed answer itself, whatever renewed or copied it since
                    // 就是被刷新的那份应答，不论之后被续用或复制过
                    entry.reach == target.reach && entry.fetched_at == target.fetched_at
                } else {
                    entry.reach.admits(view) && entry.fetched_at < target.started
                }
        });
    }

    /// 后台刷新成功之后整理它刷新的槽位（见 `CacheSlot::after_refresh`）
    /// Tidy the slot a background refresh renewed once it succeeded (see
    /// `CacheSlot::after_refresh`)
    pub(crate) fn settle_refresh(
        &self,
        target: &RefreshTarget,
        written: &crate::ecs_scope::EcsReach,
        qname: &str,
        qtype: u16,
        flags: crate::proto_utils::QueryFlags,
    ) {
        let question = CachedQuestion {
            qname,
            pipeline_id: &target.pipeline,
            qtype,
            flags,
        };
        self.cache
            .entry(target.slot)
            .and_compute_with(|current| match current {
                None => Op::Nop,
                Some(current) => {
                    match current.value().after_refresh(
                        &question,
                        &target.reach,
                        target.fetched_at,
                        written,
                        target.started,
                    ) {
                        None => Op::Nop,
                        Some(rest) if rest.is_empty() => Op::Remove,
                        Some(rest) => Op::Put(Arc::new(rest)),
                    }
                }
            });
    }

    /// 把一份应答存进槽位 `slot`（见 `CacheSlot::with`）。写入只经过这里和
    /// `insert_dns_cache_entry`。
    /// Store an answer in slot `slot` (see `CacheSlot::with`). Writes go through
    /// here and `insert_dns_cache_entry` only.
    pub(crate) fn cache_insert(&self, slot: u64, entry: Arc<CacheEntry>) {
        let max_age = self.cache_max_age;
        self.cache.entry(slot).and_compute_with(|current| {
            let slot = match current {
                Some(current) => current.into_value().with(entry, max_age),
                None => CacheSlot::default().with(entry, max_age),
            };
            Op::Put(Arc::new(slot))
        });
    }

    /// 测试用：槽位 `slot` 里的所有应答 / For tests: every answer in slot `slot`
    #[cfg(test)]
    pub(crate) fn cached_entries(&self, slot: u64) -> Vec<Arc<CacheEntry>> {
        self.cache
            .get(&slot)
            .map(|slot| slot.entries().cloned().collect())
            .unwrap_or_default()
    }

    /// 测试用：刷新槽位 `slot` 里唯一那份应答的目标；槽位为空时是一个什么都不指的目标
    /// For tests: the target of a refresh of the one answer in slot `slot`; one
    /// naming nothing when the slot is empty
    #[cfg(test)]
    pub(crate) fn refresh_of(&self, slot: u64) -> RefreshTarget {
        match self.cached(slot) {
            Some(entry) => RefreshTarget::new(
                slot,
                entry.pipeline_id.clone(),
                entry.reach.clone(),
                entry.fetched_at,
            ),
            None => RefreshTarget::new(
                slot,
                Arc::from(""),
                Default::default(),
                std::time::Instant::now(),
            ),
        }
    }

    /// 测试用：槽位 `slot` 里唯一的那份应答；不止一份时 panic
    /// For tests: the one answer in slot `slot`; panics when it holds more
    #[cfg(test)]
    pub(crate) fn cached(&self, slot: u64) -> Option<Arc<CacheEntry>> {
        let entries = self.cached_entries(slot);
        assert!(entries.len() <= 1, "slot holds {} answers", entries.len());
        entries.into_iter().next()
    }

    /// The observer installed via [`EngineBuilder::observer`], if any.
    pub fn observer(&self) -> Option<&dyn EngineObserver> {
        self.observer.as_deref()
    }

    /// Generation of the active configuration: `1` for the configuration the
    /// engine was built with, incremented by every [`Engine::reload`].
    pub fn config_generation(&self) -> u64 {
        self.config_generation.load(Ordering::Relaxed)
    }

    /// Report a configuration that just became active under `generation`.
    /// 上报刚以 `generation` 生效的配置。
    pub(crate) fn report_config_loaded(
        &self,
        generation: u64,
        path: Option<&Path>,
        source: Option<&str>,
    ) {
        if let Some(observer) = &self.observer {
            let restart_pending = self
                .state
                .load()
                .pipeline
                .settings
                .restart_pending(&self.running_settings);
            observer.config_loaded(&ConfigLoaded {
                path,
                generation,
                source,
                restart_pending: &restart_pending,
            });
        }
    }

    /// Report to the observer that reloading `path` failed with `error` and
    /// the previous configuration stays active.
    pub fn notify_config_reload_failed(&self, path: &Path, error: &str) {
        if let Some(observer) = &self.observer {
            observer.config_reload_failed(&ConfigReloadFailed { path, error });
        }
    }
}
