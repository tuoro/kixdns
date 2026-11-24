use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Context;
use arc_swap::ArcSwap;
use dashmap::DashMap;
use parking_lot::Mutex;
use rustc_hash::FxBuildHasher;

use super::geo::{GeoSources, GeoStatus};
use crate::cache::{CacheEntry, CacheSlot, CachedQuestion, DnsCache, new_cache};
use crate::cache_store::{CacheStore, Op};
use crate::ecs_scope::EcsView;
use crate::engine::refresh::RefreshTarget;
use crate::matcher::RuntimePipelineConfig;
use crate::matcher::geoip::GeoIpManager;
use crate::matcher::geosite::GeoSiteManager;
use crate::observe::{ClientTransport, ConfigLoaded, ConfigReloadFailed, EngineObserver};
use parking_lot::RwLock;

use super::bootstrap::Bootstrap;
use super::concurrency::{FlowControlState, PermitManager};
use super::rules::RuleCacheRecord;
use super::transport::{DohClient, DoqClient, DotMultiplexer, TcpMultiplexer, UdpClient};
use super::types::{EngineInner, InflightMap};

#[derive(Clone)]
pub struct Engine {
    pub(crate) state: Arc<ArcSwap<EngineInner>>,
    pub(crate) cache: DnsCache,
    /// 应答带的 TTL 的上限，只在启动时读 / The cap on the TTLs answers carry, read at startup only
    pub(crate) cache_max_ttl: u64,
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
    // Geo 数据眼下的问题（见 `Engine::geo_data_warnings`）/ What is wrong with the Geo data right
    // now (see `Engine::geo_data_warnings`)
    pub(crate) geo_status: Arc<GeoStatus>,
    // Rule execution result cache: Hash -> (Key, Decision) / 规则执行结果缓存：哈希 -> (键, 决策)
    // Key is stored to verify collisions / 存储键以验证冲突
    /// 一条记录一个 `Arc`：取一次只动一个引用计数，几个核反复读同一条时不用轮流抢好几个
    /// One `Arc` per record: taking one touches a single reference count, so cores reading the same record
    /// over and over do not take turns on several
    pub(crate) rule_cache: Arc<CacheStore<Arc<RuleCacheRecord>>>,
    /// In-flight request deduplication map using tokio::watch for lock-free concurrent waiting
    /// 使用 tokio::watch 实现无锁并发等待的进行中请求去重 map
    /// Key: the hash of the question asked (see `InflightQuestion::key`)
    /// Value: watch sender that will be notified when upstream query completes
    /// 键：所问问题的哈希（见 `InflightQuestion::key`）；值：上游查询结束时通知的 watch sender
    pub inflight: Arc<InflightMap>,
    /// 正在刷新的条目的刷新标记（见 `RefreshingGuard`）：同一条同时只刷新一次
    /// The refresh marks of the entries being refreshed (see `RefreshingGuard`): one
    /// refresh of an entry at a time
    pub refreshing: Arc<super::utils::Refreshing>,
    /// 最近刷新失败的应答（见 `RefreshFailures`）/ The answers whose refresh failed lately (see `RefreshFailures`)
    pub(crate) refresh_failures: Arc<super::refresh::RefreshFailures>,
    // Semaphore to limit concurrent handle_packet async tasks / 用于限制并发 handle_packet 异步任务数量
    pub permit_manager: Arc<PermitManager>,
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
        crate::proto_utils::saturating_u64_to_u32(self.cache_max_ttl)
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
        // 响应缓存：容量由配置控制（默认 10000 份，见 `new_cache`），应答留到没用为止（见 `phases::kept_past_ttl`）
        // Response cache: capacity from the settings, answers kept until of no use (see
        // `phases::kept_past_ttl`)
        let running_settings = Arc::new(cfg.settings.clone());
        let settings = Arc::clone(&running_settings);
        let cache = new_cache(
            settings.cache_capacity,
            super::phases::kept_past_ttl(&settings),
        );
        // 规则缓存：1 万条，每条按自己的 expires_at 过期（见 `RULE_CACHE_MAX_AGE`），过期以后不再多留：它的
        // `Cached::outlived` 不看存储的 kept
        // Rule cache: 10k entries, each expiring at its own expires_at (see `RULE_CACHE_MAX_AGE`)
        // and kept no longer: its `Cached::outlived` does not look at the store's kept
        let rule_cache = Arc::new(CacheStore::new(10_000, std::time::Duration::ZERO));

        let geoip_manager = Arc::new(RwLock::new(GeoIpManager::default()));
        let geosite_manager = Arc::new(RwLock::new(GeoSiteManager::default()));
        let state = Arc::new(ArcSwap::from_pointee(EngineInner::new(cfg)));
        let geo_sources = GeoSources::load(
            &state.load_full().pipeline,
            &geosite_manager,
            &geoip_manager,
            &state,
        );

        let permit_manager = Arc::new(PermitManager::new());
        let flow_control_state = settings.flow_control_enabled.then(|| {
            Arc::new(FlowControlState::new(
                super::memory_watermark::MemoryWatermark::of_this_machine(),
            ))
        });

        // TCP pool size is per upstream: each upstream keeps up to that many connections
        // TCP 连接池大小按每个 upstream 算：每个 upstream 最多保留这么多条连接

        // Collect TCP upstreams for warmup / 收集 TCP upstream 用于预热
        let tcp_upstreams = super::upstream::tcp_upstreams(&state.load().pipeline);

        let udp_client =
            Arc::new(UdpClient::new(settings.udp_pool_size).context("initialize UDP client")?);
        // 上游的主机名经 bootstrap 的服务器解析，用的是上面这个 UDP 客户端 / Upstream host names are
        // resolved through the bootstrap servers, by the UDP client above
        let bootstrap = Bootstrap::new(&settings.bootstrap, Arc::clone(&udp_client));

        let tcp_mux = Arc::new(TcpMultiplexer::new(
            settings.tcp_pool_size,
            settings.tcp_connection_max_age_seconds,
            settings.tcp_connection_idle_timeout_seconds,
            Arc::clone(&bootstrap),
        ));

        let dot_mux = Arc::new(
            DotMultiplexer::new(
                settings.dot_pool_size,
                settings.tcp_connection_max_age_seconds,
                settings.tcp_connection_idle_timeout_seconds,
                Arc::clone(&bootstrap),
            )
            .context("initialize DoT multiplexer")?,
        );

        let doh_client = Arc::new(
            DohClient::new(
                settings.doh_pool_size,
                settings.doh_health_check_error_threshold,
                Arc::clone(&bootstrap),
            )
            .context("initialize DoH client")?,
        );
        let doq_client = Arc::new(
            DoqClient::new(
                settings.doq_pool_size,
                settings.doq_connection_idle_timeout_seconds,
                settings.doq_keepalive_interval_ms,
                settings.doq_enable_0rtt,
                bootstrap,
            )
            .context("initialize DoQ client")?,
        );

        // Warm up TCP connection pools (see `TcpMultiplexer::warm_up_pools`)
        // 预热 TCP 连接池（见 `TcpMultiplexer::warm_up_pools`）
        tcp_mux.warm_up_pools(&tcp_upstreams);

        Ok(Self {
            state,
            cache_max_ttl: settings.cache_max_ttl,
            cache,
            udp_client,
            tcp_mux,
            doh_client,
            dot_mux,
            doq_client,
            listener_label: Arc::from(listener_label),
            client_transport: None,
            observer,
            config_generation: Arc::new(AtomicU64::new(1)),
            running_settings,
            geo_status: geo_sources.status(),
            reload_lock: Arc::new(Mutex::new(geo_sources)),
            rule_cache,
            // DashMap configuration: shard count and initial capacity
            // If dashmap_shards is 0, use DashMap default (num_cpus * 4)
            // More shards = less lock contention but more memory overhead
            inflight: if settings.dashmap_shards == 0 {
                Arc::new(DashMap::with_capacity_and_hasher(128, FxBuildHasher))
            } else {
                Arc::new(DashMap::with_capacity_and_hasher_and_shard_amount(
                    128,
                    FxBuildHasher,
                    settings.dashmap_shards,
                ))
            },
            refreshing: Arc::default(),
            refresh_failures: Arc::default(),
            permit_manager,
            flow_control_state,
            // GeoIP manager / GeoIP 管理器
            geoip_manager,
            // GeoSite manager / GeoSite 管理器
            geosite_manager,
        })
    }

    /// 槽位 `slot` 里 `question` 的、适用于 `view` 的那份应答（见 `CacheSlot::select`）
    /// The answer to `question` in slot `slot` that applies to `view` (see
    /// `CacheSlot::select`)
    pub(crate) fn cache_get(
        &self,
        slot: u64,
        view: &EcsView,
        question: &CachedQuestion<'_>,
    ) -> Option<Arc<CacheEntry>> {
        self.cache
            .get_with(slot, |cached| {
                cached.select(view, |entry| question.matches(entry))
            })
            .flatten()
    }

    /// 从槽位 `slot` 去掉 `remove` 选中的应答 / Remove from slot `slot` the answers `remove` picks
    pub(crate) fn cache_remove(&self, slot: u64, remove: impl Fn(&CacheEntry) -> bool) {
        self.cache.compute(slot, |current| match current {
            None => Op::Nop,
            Some(current) => match current.without(&remove) {
                None => Op::Nop,
                Some(rest) if rest.is_empty() => Op::Remove,
                Some(rest) => Op::Put(Arc::new(rest)),
            },
        });
    }

    /// 把槽位 `slot` 里的 `old` 这一份换成 `new`；`old` 已经不在（被取代或去掉）时什么都不做。
    /// 过期应答续期用它，不碰槽位里的其他应答。
    /// Replace `old` itself in slot `slot` with `new`; nothing happens when `old` is
    /// gone (replaced or removed). Renewing a stale answer uses it, leaving the
    /// slot's other answers alone.
    pub(crate) fn cache_replace(&self, slot: u64, old: &Arc<CacheEntry>, new: CacheEntry) {
        let new = Arc::new(new);
        self.cache.compute(slot, |current| match current {
            None => Op::Nop,
            Some(current) => match current.replacing(old, new) {
                None => Op::Nop,
                Some(slot) => Op::Put(Arc::new(slot)),
            },
        });
    }

    /// 从后台刷新要更新的槽位里去掉被刷新的那份应答（见 `RefreshTarget`），不论之后被续用或复制过；已经被取代、
    /// 不在了的什么都不做
    /// Drop the answer a background refresh renews from its slot (see `RefreshTarget`),
    /// whatever renewed or copied it since; nothing happens when it was replaced and is gone
    pub(crate) fn drop_refreshed(&self, question: &CachedQuestion<'_>, target: &RefreshTarget) {
        self.cache_remove(target.slot, |entry| {
            question.matches(entry)
                && entry.reach == target.reach
                && entry.fetched_at == target.fetched_at
        });
    }

    /// 把一份应答存进槽位 `slot`（见 `CacheSlot::with`）。新应答只经过这里写入，先过
    /// `insert_dns_cache_entry` 那一关；已有的应答由 `cache_replace` 续期、由 `cache_remove` 去掉。
    /// Store an answer in slot `slot` (see `CacheSlot::with`). New answers are written through
    /// here alone, past `insert_dns_cache_entry` first; answers already there are renewed by
    /// `cache_replace` and removed by `cache_remove`.
    pub(crate) fn cache_insert(&self, slot: u64, entry: Arc<CacheEntry>) {
        let kept = self.cache.kept();
        let heaviest = self.cache.heaviest_value();
        self.cache.compute(slot, |current| {
            let slot = match current {
                Some(current) => current.with(entry, kept),
                None => CacheSlot::default().with(entry, kept),
            };
            Op::Put(Arc::new(slot.fitting(heaviest)))
        });
    }

    /// 测试用：槽位 `slot` 里的所有应答 / For tests: every answer in slot `slot`
    #[cfg(test)]
    pub(crate) fn cached_entries(&self, slot: u64) -> Vec<Arc<CacheEntry>> {
        self.cache
            .get(slot)
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
        let state = self.state.load();
        // 照样生效、值得知道的写法（见 `config::warnings`），配置每生效一次各记一条
        // What takes effect all the same yet is worth knowing (see `config::warnings`), each
        // logged every time a configuration takes effect
        for warning in &state.pipeline.warnings {
            tracing::warn!(%warning, "configuration warning");
        }
        if let Some(observer) = &self.observer {
            let config = &state.pipeline;
            // 没有 pipeline 时请求报的是 `NO_PIPELINE` / With no pipelines requests report `NO_PIPELINE`
            let pipelines: Vec<&str> = if config.pipelines.is_empty() {
                vec![super::pipeline::NO_PIPELINE]
            } else {
                config
                    .pipelines
                    .iter()
                    .map(|pipeline| &*pipeline.id)
                    .collect()
            };
            let rules: Vec<(&str, &str)> = config
                .pipelines
                .iter()
                .flat_map(|pipeline| {
                    pipeline
                        .rules
                        .iter()
                        .map(|rule| (&*pipeline.id, &*rule.name))
                })
                .collect();
            let upstreams: Vec<_> = super::upstream::upstreams(config).into_iter().collect();
            observer.config_loaded(&ConfigLoaded {
                path,
                generation,
                source,
                restart_pending: &config.settings.restart_pending(&self.running_settings),
                warnings: &config.warnings,
                pipelines: &pipelines,
                rules: &rules,
                upstreams: &upstreams,
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
