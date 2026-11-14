use crate::config::{Action, EcsMode, GlobalSettings, MatchOperator};
use crate::ecs::EcsKey;
use crate::engine::Engine;
use crate::engine::geo::GeoGeneration;
use crate::matcher::advanced_rule::{CompiledPipeline, compile_pipelines};
use crate::matcher::{
    RequesterKey, RuntimeMatcher, RuntimePipeline, RuntimePipelineConfig, RuntimeResponseMatcher,
};
use crate::proto_utils::QueryFlags;
use bytes::Bytes;
use dashmap::DashMap;
use hickory_proto::rr::{DNSClass, RecordType};
use rustc_hash::{FxBuildHasher, FxHashMap};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::mem::discriminant;
use std::sync::{Arc, LazyLock};
use tokio::sync::watch;

pub type InflightMap = DashMap<u64, InflightEntry, FxBuildHasher>;

/// 合并查询的结果：领头请求拿到的应答，或它失败的原因 / The result of a merged query: the answer the
/// leading request got, or why it failed
pub type InflightResult = Result<Bytes, Arc<anyhow::Error>>;

/// 一个请求在 inflight 表里登记或等待时问的是什么：算它的 inflight 键用到的全部输入（见
/// `Engine::cache_keys`）。键只是这些输入的哈希，而且不带密钥，落在同一个键上的两个不同问题可以算出来；
/// 所以登记时把问题存进条目，等待之前先核对（见 `InflightEntry::asks`），对不上就自己转发。
/// What a request registers or waits under in the inflight map: everything its inflight key is
/// computed from (see `Engine::cache_keys`). The key is only a hash of these, and an unkeyed one, so
/// two different questions landing on one key can be computed; the question is therefore stored in the
/// entry when it is registered and checked before waiting (see `InflightEntry::asks`), and a request
/// whose question differs forwards by itself.
#[derive(Debug, Clone, Copy)]
pub(crate) struct InflightQuestion<'a> {
    pub namespace: u64,
    pub pipeline_id: &'a str,
    pub qname: &'a [u8],
    pub qtype: RecordType,
    pub qclass: DNSClass,
    pub flags: QueryFlags,
    pub requester: RequesterKey,
    pub client_ecs: Option<EcsKey>,
}

impl InflightQuestion<'_> {
    /// 它的 inflight 键 / Its inflight key
    pub(crate) fn key(&self) -> u64 {
        Engine::cache_keys(
            self.namespace,
            self.pipeline_id,
            self.qname,
            self.qtype,
            self.qclass,
            self.flags,
            &self.requester,
            self.client_ecs.as_ref(),
        )
        .inflight
    }
}

/// inflight 表里的条目：领头请求发出结果的通道，和它问的是什么
/// An entry of the inflight map: the channel the leading request sends its result on, and what it
/// asked
#[derive(Debug)]
pub struct InflightEntry {
    /// 结果从这里发给等着的请求。第一个来等的请求才建：绝大多数查询没人等，这样它们既不用建通道，放下
    /// 条目时也不用通知谁
    /// The result goes out here to the requests waiting. The first to wait builds it: nearly
    /// every query has none waiting, and so neither builds a channel nor notifies anyone
    /// when its entry goes
    tx: Option<watch::Sender<InflightResult>>,
    namespace: u64,
    pipeline_id: Arc<str>,
    qname: Arc<[u8]>,
    qtype: RecordType,
    qclass: DNSClass,
    flags: QueryFlags,
    requester: RequesterKey,
    client_ecs: Option<EcsKey>,
}

impl InflightEntry {
    /// `question` 的条目 / The entry of `question`
    pub(crate) fn new(question: &InflightQuestion<'_>) -> Self {
        Self::sharing(
            question,
            &Arc::from(question.pipeline_id),
            Arc::from(question.qname),
        )
    }

    /// `question` 的条目，`pipeline_id` 和 `qname` 就是它问的，请求手里已经有一份，不再另存
    /// The entry of `question`, whose `pipeline_id` and `qname` the request already holds a
    /// copy of, so that no other is made
    pub(crate) fn sharing(
        question: &InflightQuestion<'_>,
        pipeline_id: &Arc<str>,
        qname: Arc<[u8]>,
    ) -> Self {
        Self {
            tx: None,
            namespace: question.namespace,
            pipeline_id: Arc::clone(pipeline_id),
            qname,
            qtype: question.qtype,
            qclass: question.qclass,
            flags: question.flags,
            requester: question.requester,
            client_ecs: question.client_ecs,
        }
    }

    /// 等这个条目的结果 / Wait for this entry's result
    pub(crate) fn subscribe(&mut self) -> watch::Receiver<InflightResult> {
        self.tx
            .get_or_insert_with(|| watch::channel(inflight_pending()).0)
            .subscribe()
    }

    /// 有请求在等时，结果从这里发给它们 / Where the result goes out, when any request waits
    pub(crate) fn waiting(&self) -> Option<&watch::Sender<InflightResult>> {
        self.tx.as_ref().filter(|tx| tx.receiver_count() > 0)
    }

    /// 测试用：结果从 `tx` 发出的条目 / For tests: the entry whose result goes out on `tx`
    #[cfg(test)]
    pub(crate) fn with_channel(mut self, tx: watch::Sender<InflightResult>) -> Self {
        self.tx = Some(tx);
        self
    }

    /// 条目是不是 `question` 的：只有问的完全一样，才能等它的结果
    /// Whether the entry is `question`'s: only a request asking exactly the same may wait on its
    /// result
    pub(crate) fn asks(&self, question: &InflightQuestion<'_>) -> bool {
        self.namespace == question.namespace
            && *self.pipeline_id == *question.pipeline_id
            && *self.qname == *question.qname
            && self.qtype == question.qtype
            && self.qclass == question.qclass
            && self.flags == question.flags
            && self.requester == question.requester
            && self.client_ecs == question.client_ecs
    }
}

/// 合并查询的通道在领头请求拿到结果之前的值。等待的请求只在领头请求发出结果之后才读
/// （`changed()`），从来读不到它，所以所有通道共用这一个：每次缓存没命中都新建一个错误要分配内存，
/// 设了 `RUST_BACKTRACE` 时还要抓一份完整的调用栈（实测新名字的吞吐因此低 18%）。
/// The value an in-flight channel holds until the leading request has its result. Waiting requests
/// read only after the leader sends one (`changed()`) and never see it, so every channel shares this
/// one: building a new error on each cache miss allocates, and with `RUST_BACKTRACE` set it also
/// captures a whole backtrace (measured at 18% less throughput for new names).
pub(crate) fn inflight_pending() -> InflightResult {
    static PENDING: LazyLock<Arc<anyhow::Error>> =
        LazyLock::new(|| Arc::new(anyhow::anyhow!("Pending")));
    Err(Arc::clone(&PENDING))
}

#[cfg(test)]
mod inflight_entry_tests {
    use super::{InflightEntry, InflightQuestion};
    use crate::ecs::EcsKey;
    use crate::matcher::RequesterKey;
    use hickory_proto::rr::{DNSClass, RecordType};

    /// 条目只认问得完全一样的请求：问题的任何一部分不同都不算 / An entry is only for a request asking
    /// exactly the same: any part of the question differing rules it out
    /// 这些测试问的问题 / The question these tests ask
    fn asked<'a>(pipeline_id: &'a str, qname: &'a [u8]) -> InflightQuestion<'a> {
        InflightQuestion {
            flags: crate::proto_utils::QueryFlags::RECURSIVE,
            namespace: 1,
            pipeline_id,
            qname,
            qtype: RecordType::A,
            qclass: DNSClass::IN,
            requester: RequesterKey::NONE,
            client_ecs: None,
        }
    }

    /// 没人等时没有通道；第一个来等的请求建通道，之后来的等同一个
    /// No channel while nobody waits; the first to wait builds it and later ones wait on the same
    #[tokio::test]
    async fn the_channel_is_built_by_the_first_to_wait() {
        let mut entry = InflightEntry::new(&asked("main", b"example.com"));
        assert!(entry.waiting().is_none(), "nobody waits");
        let mut first = entry.subscribe();
        let mut second = entry.subscribe();
        let tx = entry.waiting().expect("two wait");
        assert_eq!(tx.receiver_count(), 2);
        tx.send(Ok(bytes::Bytes::from_static(b"answer"))).unwrap();
        for rx in [&mut first, &mut second] {
            rx.changed().await.unwrap();
            let got = rx.borrow().as_ref().map(bytes::Bytes::clone).unwrap();
            assert_eq!(&got[..], b"answer");
        }
        drop((first, second));
        assert!(entry.waiting().is_none(), "nobody waits any more");
    }

    /// 放下条目时没发结果，等着的请求会知道，好自己去转发
    /// An entry going without a result tells those waiting, who then forward themselves
    #[tokio::test]
    async fn an_entry_going_without_a_result_ends_the_wait() {
        let mut entry = InflightEntry::new(&asked("main", b"example.com"));
        let mut rx = entry.subscribe();
        drop(entry);
        assert!(rx.changed().await.is_err());
    }

    /// 共用请求手里那份时，比的还是问题本身，不多存一份
    /// Sharing what the request holds, the entry still compares the question itself and keeps
    /// no copy of its own
    #[test]
    fn an_entry_can_share_what_the_request_holds() {
        let pipeline: std::sync::Arc<str> = "main".into();
        let qname: std::sync::Arc<str> = "example.com".into();
        let question = asked(&pipeline, qname.as_bytes());
        let entry = InflightEntry::sharing(
            &question,
            &pipeline,
            std::sync::Arc::<[u8]>::from(std::sync::Arc::clone(&qname)),
        );
        assert!(entry.asks(&question));
        assert!(!entry.asks(&asked("main", b"example.org")));
        assert!(!entry.asks(&asked("other", b"example.com")));
        assert_eq!(std::sync::Arc::strong_count(&pipeline), 2);
        assert_eq!(std::sync::Arc::strong_count(&qname), 2);
    }

    #[test]
    fn an_entry_is_only_for_its_own_question() {
        let question = InflightQuestion {
            flags: crate::proto_utils::QueryFlags::RECURSIVE,
            namespace: 1,
            pipeline_id: "main",
            qname: b"example.com",
            qtype: RecordType::A,
            qclass: DNSClass::IN,
            requester: RequesterKey::NONE,
            client_ecs: None,
        };
        let entry = InflightEntry::new(&question);
        assert!(entry.asks(&question));
        let others = [
            InflightQuestion {
                namespace: 2,
                ..question
            },
            InflightQuestion {
                pipeline_id: "other",
                ..question
            },
            InflightQuestion {
                qname: b"example.org",
                ..question
            },
            InflightQuestion {
                qtype: RecordType::AAAA,
                ..question
            },
            InflightQuestion {
                qclass: DNSClass::CH,
                ..question
            },
            InflightQuestion {
                flags: crate::proto_utils::QueryFlags::new(true, false, true),
                ..question
            },
            InflightQuestion {
                requester: RequesterKey {
                    class: Some(1),
                    ..RequesterKey::NONE
                },
                ..question
            },
            InflightQuestion {
                client_ecs: Some(EcsKey {
                    family: 1,
                    source_prefix: 24,
                    addr: [198, 51, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    addr_len: 3,
                }),
                ..question
            },
        ];
        for other in others {
            assert!(!entry.asks(&other), "{other:?}");
        }
    }
}

#[cfg(test)]
mod inflight_pending_tests {
    use super::inflight_pending;
    use std::sync::Arc;

    /// 每个通道拿到的都是同一份占位值，没命中时不再新建错误
    /// Every channel gets the same placeholder, so a miss builds no new error
    #[test]
    fn every_channel_shares_one_placeholder() {
        let (Err(first), Err(second)) = (inflight_pending(), inflight_pending()) else {
            panic!("the placeholder is an error");
        };
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(first.to_string(), "Pending");
    }
}

// ============================================================================
// Fast-path Response / 快速路径响应
// ============================================================================
///
/// - `Direct`: already has correct TXID and can be sent as-is.
/// - `CacheHit`: carries cached bytes (with an old TXID) and the request TXID to patch.
///   Also includes how long it sat in the cache, to age its TTLs (RFC 1035 §5.2).
/// - `AsyncNeeded`: cache miss, needs async processing. Contains pre-parsed data to avoid re-parsing.
#[derive(Debug, Clone)]
pub enum FastPathResponse {
    Direct(Bytes),
    CacheHit {
        cached: Bytes,
        tx_id: u16,
        /// Whole seconds it sat in the cache, for TTL calculation / 在缓存里停留的整秒数，用于计算 TTL
        elapsed_secs: u32,
    },
    /// Cache miss, needs async processing, with what the fast path already parsed and the
    /// pipeline it picked, to pass on to `handle_packet_internal_with_pre_parsed`.
    /// 缓存未命中，需要异步处理；带着快速路径已经解析出的内容和选好的 pipeline，交给
    /// `handle_packet_internal_with_pre_parsed`。
    AsyncNeeded(super::PreParsedData),
}

pub struct EngineInner {
    pub pipeline: RuntimePipelineConfig,
    pub compiled_pipelines: Vec<CompiledPipeline>,
    /// O(1) pipeline lookup index: pipeline_id -> index in compiled_pipelines / O(1) 管道查找索引：pipeline_id -> compiled_pipelines 中的索引
    pub pipeline_index: FxHashMap<Arc<str>, usize>,
    /// Response-affecting configuration fingerprint for each pipeline.
    /// It namespaces response/rule/inflight caches across hot reloads while
    /// allowing unchanged pipelines to keep their warm cache entries.
    /// 每个 pipeline 影响应答的配置指纹，加上它用到的 Geo 数据的代数（见 [`Self::at_geo`]）
    /// Each pipeline's response-affecting configuration fingerprint, combined with the
    /// generations of the Geo data it uses (see [`Self::at_geo`])
    pub cache_namespaces: FxHashMap<Arc<str>, u64>,
    /// 只按配置算出的指纹 / The fingerprints from the configuration alone
    config_namespaces: FxHashMap<Arc<str>, u64>,
    /// `cache_namespaces` 算进去的 Geo 数据代数 / The Geo data generations `cache_namespaces` takes in
    geo: GeoGeneration,
    /// 不在任何一个配置了的 pipeline 下的请求用的命名空间（没写 pipeline 的配置里所有请求都是）：只有全局设置的指纹。
    /// 以前这样的请求恒用 0，重载改了全局设置也分不开新旧
    /// The namespace of requests under no configured pipeline (every request of a configuration
    /// with none written): the fingerprint of the global settings alone. Such requests used to
    /// take 0 always, and a reload changing a global setting told old from new by nothing
    no_pipeline_namespace: u64,
}

impl EngineInner {
    /// 从运行时配置建：编译各 pipeline，建按 id 的查找索引，算出缓存命名空间
    /// Built from a runtime configuration: the pipelines compiled, the lookup index by
    /// id, and the cache namespaces
    pub(crate) fn new(cfg: RuntimePipelineConfig) -> Self {
        let compiled_pipelines = compile_pipelines(&cfg);
        // Build O(1) compiled pipeline lookup index / 构建 O(1) 编译管道查找索引
        let pipeline_index = compiled_pipelines
            .iter()
            .enumerate()
            .map(|(i, p)| (p.id.clone(), i))
            .collect();
        let config_namespaces = build_cache_namespaces(&cfg);
        let geo = GeoGeneration::default();
        let no_pipeline_namespace = {
            let mut hasher = DefaultHasher::new();
            hash_global_settings_semantics(&cfg.settings, &mut hasher);
            hasher.finish()
        };
        Self {
            cache_namespaces: with_geo(&cfg, &config_namespaces, geo),
            config_namespaces,
            geo,
            no_pipeline_namespace,
            pipeline: cfg,
            compiled_pipelines,
            pipeline_index,
        }
    }

    /// 命名空间就地换成 Geo 数据第 `geo` 代的（见 [`Self::at_geo`]），给还没存进去的新状态用
    /// Moves the namespaces to Geo data generation `geo` in place (see [`Self::at_geo`]),
    /// for a new state not stored yet
    pub(crate) fn set_geo(&mut self, geo: GeoGeneration) {
        self.cache_namespaces = with_geo(&self.pipeline, &self.config_namespaces, geo);
        self.geo = geo;
    }

    /// 同样的配置，命名空间换成 Geo 数据第 `geo` 代的：用到某份 Geo 数据的 pipeline，那份数据每换一代就换一个命名空间，
    /// 按旧数据得出的应答和规则决定不再查到；没用到的 pipeline 不变。已经是这一代的就原样交回
    /// The same configuration with the namespaces of Geo data generation `geo`: a pipeline
    /// using some Geo data moves to a new namespace with every generation of that data, so
    /// answers and rule decisions reached with the old data are no longer found; pipelines
    /// not using it stay as they are. A state already at this generation is handed back as
    /// it is.
    ///
    /// 换代时整份复制：Geo 数据一天换几次，请求路径上的状态因此保持原来的布局，不多一层间接
    /// A new generation copies the whole state: Geo data changes a few times a day, and the
    /// state on the request path keeps its layout this way, without another indirection
    pub(crate) fn at_geo(self: &Arc<Self>, geo: GeoGeneration) -> Arc<Self> {
        if self.geo == geo {
            return Arc::clone(self);
        }
        Arc::new(Self {
            cache_namespaces: with_geo(&self.pipeline, &self.config_namespaces, geo),
            config_namespaces: self.config_namespaces.clone(),
            geo,
            no_pipeline_namespace: self.no_pipeline_namespace,
            pipeline: self.pipeline.clone(),
            compiled_pipelines: self.compiled_pipelines.clone(),
            pipeline_index: self.pipeline_index.clone(),
        })
    }

    #[inline]
    pub(crate) fn cache_namespace(&self, pipeline_id: &str) -> u64 {
        self.cache_namespaces
            .get(pipeline_id)
            .copied()
            .unwrap_or(self.no_pipeline_namespace)
    }
}

/// 配置指纹加上各 pipeline 用到的 Geo 数据的代数 / The configuration fingerprints combined with the
/// generations of the Geo data each pipeline uses
fn with_geo(
    cfg: &RuntimePipelineConfig,
    config_namespaces: &FxHashMap<Arc<str>, u64>,
    geo: GeoGeneration,
) -> FxHashMap<Arc<str>, u64> {
    cfg.pipelines
        .iter()
        .map(|pipeline| {
            let base = config_namespaces
                .get(&pipeline.id)
                .copied()
                .unwrap_or_default();
            let uses = pipeline.geo_data;
            let namespace = if uses.site || uses.ip {
                let mut hasher = DefaultHasher::new();
                base.hash(&mut hasher);
                uses.site.then_some(geo.site).hash(&mut hasher);
                uses.ip.then_some(geo.ip).hash(&mut hasher);
                hasher.finish()
            } else {
                base
            };
            (pipeline.id.clone(), namespace)
        })
        .collect()
}

pub(crate) fn build_cache_namespaces(cfg: &RuntimePipelineConfig) -> FxHashMap<Arc<str>, u64> {
    cfg.pipelines
        .iter()
        .map(|pipeline| {
            let mut hasher = DefaultHasher::new();
            // Global settings can affect forwarding, TTL handling and response
            // processing, so they are part of every pipeline namespace.
            hash_global_settings_semantics(&cfg.settings, &mut hasher);
            hash_pipeline_semantics(pipeline, &mut hasher);
            (pipeline.id.clone(), hasher.finish())
        })
        .collect()
}

fn hash_global_settings_semantics(settings: &GlobalSettings, hasher: &mut impl Hasher) {
    let GlobalSettings {
        min_ttl,
        default_upstream,
        default_upstream_pre_split: _,
        default_upstream_shared: _,
        upstream_timeout_ms,
        request_timeout_ms,
        response_jump_limit,
        serve_stale,
        serve_stale_ttl,
        serve_stale_expire_ttl,
        serve_stale_ttl_reset,
        serve_stale_client_timeout_ms,
        cache_background_refresh,
        cache_refresh_threshold_percent,
        cache_refresh_min_ttl,
        // Geo 数据的设置决定读进哪些名单和网段。应答取决于它们的只有读 Geo 数据的 pipeline，那些 pipeline 按数据的代数换命名
        // 空间（见 `with_geo`；配置重载换了文件也是新的一代），其余的不必跟着换。以前它们算进了每个 pipeline 的命名空间：面板
        // 按内容给 Geo 数据和拦截列表的文件起名，每次更新都换一个文件，名单一更新整份缓存就作废。后两个现在什么也不做
        // The Geo settings decide which lists and networks are read in. Only the pipelines
        // reading Geo data have answers that depend on them, and those move namespace with
        // the data's generation (see `with_geo`; a reload changing the files is a new
        // generation too), so the rest need not follow. They used to go into every
        // pipeline's namespace: the panel names the files of Geo data and blocklists by their
        // content, every update brings another file, and every list update dropped the whole
        // cache. The last two do nothing at present
        geoip_db_path: _,
        geoip_dat_path: _,
        geoip_auto_convert: _,
        geoip_filter_countries: _,
        geosite_data_paths: _,
        enable_tcp_fallback,
        // 只在启动时读（见 `GlobalSettings::restart_pending`）：重载改了也不生效，应答不变，不让缓存换代
        // Read at startup only (see `GlobalSettings::restart_pending`): a reload changing them
        // applies nothing and the answers stay the same, so they leave the caches alone
        bind_udp: _,
        bind_tcp: _,
        bind_doh: _,
        doh_tls_cert: _,
        doh_tls_key: _,
        doh_path: _,
        cache_capacity: _,
        cache_max_ttl: _,
        dashmap_shards: _,
        udp_pool_size: _,
        tcp_pool_size: _,
        doh_pool_size: _,
        doh_health_check_error_threshold: _,
        dot_pool_size: _,
        doq_pool_size: _,
        tcp_health_check_error_threshold: _,
        tcp_connection_max_age_seconds: _,
        tcp_connection_idle_timeout_seconds: _,
        doq_connection_idle_timeout_seconds: _,
        doq_keepalive_interval_ms: _,
        doq_enable_0rtt: _,
        flow_control_enabled: _,
        // No longer have any effect (see `GlobalSettings`), so they leave the caches alone
        // 已不起作用（见 `GlobalSettings`），不让缓存换代
        statistics_enabled: _,
        statistics_anonymize_client_ip: _,
        flow_control_initial_permits: _,
        flow_control_min_permits: _,
        flow_control_max_permits: _,
        flow_control_latency_threshold_ms: _,
        flow_control_adjustment_interval_secs: _,
    } = settings;

    (
        min_ttl,
        default_upstream,
        upstream_timeout_ms,
        request_timeout_ms,
        response_jump_limit,
    )
        .hash(hasher);
    (
        serve_stale,
        serve_stale_ttl,
        serve_stale_expire_ttl,
        serve_stale_ttl_reset,
        serve_stale_client_timeout_ms,
        cache_background_refresh,
        cache_refresh_threshold_percent,
        cache_refresh_min_ttl,
    )
        .hash(hasher);
    enable_tcp_fallback.hash(hasher);
}

fn hash_pipeline_semantics(pipeline: &RuntimePipeline, hasher: &mut impl Hasher) {
    pipeline.id.hash(hasher);
    hash_ecs_mode(pipeline.ecs.as_ref(), hasher);
    pipeline.rules.len().hash(hasher);
    for rule in &pipeline.rules {
        rule.name.hash(hasher);
        hash_match_operator(rule.matcher_operator, hasher);
        rule.matchers.len().hash(hasher);
        for matcher in &rule.matchers {
            hash_match_operator(matcher.operator, hasher);
            hash_runtime_matcher(&matcher.matcher, hasher);
        }
        rule.actions.len().hash(hasher);
        for action in &rule.actions {
            hash_action(action, hasher);
        }
        rule.response_matchers.len().hash(hasher);
        for matcher in &rule.response_matchers {
            hash_match_operator(matcher.operator, hasher);
            hash_runtime_response_matcher(&matcher.matcher, hasher);
        }
        hash_match_operator(rule.response_matcher_operator, hasher);
        rule.response_actions_on_match.len().hash(hasher);
        for action in &rule.response_actions_on_match {
            hash_action(action, hasher);
        }
        rule.response_actions_on_miss.len().hash(hasher);
        for action in &rule.response_actions_on_miss {
            hash_action(action, hasher);
        }
    }
}

fn hash_match_operator(operator: MatchOperator, hasher: &mut impl Hasher) {
    discriminant(&operator).hash(hasher);
}

fn hash_ecs_mode(mode: Option<&EcsMode>, hasher: &mut impl Hasher) {
    mode.is_some().hash(hasher);
    let Some(mode) = mode else {
        return;
    };
    discriminant(mode).hash(hasher);
    match mode {
        EcsMode::Clear => {}
        EcsMode::FromClientIp {
            prefix_v4,
            prefix_v6,
        } => {
            prefix_v4.hash(hasher);
            prefix_v6.hash(hasher);
        }
        EcsMode::Static { ip, prefix } => {
            ip.hash(hasher);
            prefix.hash(hasher);
        }
    }
}

fn hash_action(action: &Action, hasher: &mut impl Hasher) {
    discriminant(action).hash(hasher);
    match action {
        Action::Log { level } => level.hash(hasher),
        Action::StaticResponse { rcode } => rcode.hash(hasher),
        Action::StaticIpResponse { ip } => ip.hash(hasher),
        Action::StaticCnameResponse { target, ttl } => {
            target.hash(hasher);
            ttl.hash(hasher);
        }
        Action::StaticTxtResponse { text, ttl } => {
            text.hash(hasher);
            ttl.hash(hasher);
        }
        Action::JumpToPipeline { pipeline } => pipeline.hash(hasher),
        Action::Forward {
            upstream,
            transport,
            ecs,
            ..
        } => {
            upstream.hash(hasher);
            transport.hash(hasher);
            hash_ecs_mode(ecs.as_ref(), hasher);
        }
        Action::ReplaceTxtResponse { text } => text.hash(hasher),
        Action::Allow | Action::Deny | Action::Continue => {}
    }
}

fn hash_runtime_matcher(matcher: &RuntimeMatcher, hasher: &mut impl Hasher) {
    discriminant(matcher).hash(hasher);
    match matcher {
        RuntimeMatcher::Any => {}
        RuntimeMatcher::DomainExact { value } | RuntimeMatcher::DomainSuffix { value } => {
            value.hash(hasher)
        }
        RuntimeMatcher::ClientIp { net } => net.hash(hasher),
        RuntimeMatcher::DomainRegex { regex } => regex.as_str().hash(hasher),
        RuntimeMatcher::GeoipCountry { country_codes } => country_codes.hash(hasher),
        RuntimeMatcher::GeoipPrivate { expect } | RuntimeMatcher::EdnsPresent { expect } => {
            expect.hash(hasher)
        }
        RuntimeMatcher::Qclass { value } => u16::from(*value).hash(hasher),
        RuntimeMatcher::GeoSite { tag } | RuntimeMatcher::GeoSiteNot { tag } => tag.hash(hasher),
        RuntimeMatcher::Qtype { value } => u16::from(*value).hash(hasher),
    }
}

fn hash_runtime_response_matcher(matcher: &RuntimeResponseMatcher, hasher: &mut impl Hasher) {
    discriminant(matcher).hash(hasher);
    match matcher {
        RuntimeResponseMatcher::UpstreamEquals { value, .. }
        | RuntimeResponseMatcher::RequestDomainSuffix { value }
        | RuntimeResponseMatcher::RequestDomainExact { value }
        | RuntimeResponseMatcher::ResponseRequestDomainGeoSite { value }
        | RuntimeResponseMatcher::ResponseRequestDomainGeoSiteNot { value } => value.hash(hasher),
        RuntimeResponseMatcher::RequestDomainRegex { regex } => regex.as_str().hash(hasher),
        RuntimeResponseMatcher::ResponseUpstreamIp { nets }
        | RuntimeResponseMatcher::ResponseAnswerIp { nets } => nets.hash(hasher),
        RuntimeResponseMatcher::ResponseType { value } => u16::from(*value).hash(hasher),
        RuntimeResponseMatcher::ResponseRcode { value } => value.hash(hasher),
        RuntimeResponseMatcher::ResponseQclass { value } => u16::from(*value).hash(hasher),
        RuntimeResponseMatcher::ResponseEdnsPresent { expect }
        | RuntimeResponseMatcher::ResponseAnswerIpGeoipPrivate { expect } => expect.hash(hasher),
        RuntimeResponseMatcher::ResponseAnswerIpGeoipCountry { country_codes } => {
            country_codes.hash(hasher)
        }
        RuntimeResponseMatcher::ResponseTxtContent { mode, value, .. } => {
            discriminant(mode).hash(hasher);
            value.hash(hasher);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::build_cache_namespaces;
    use crate::config::PipelineConfig;
    use crate::matcher::RuntimePipelineConfig;
    use std::sync::Arc;

    fn runtime_config(first_upstream: &str, second_upstream: &str) -> RuntimePipelineConfig {
        let raw = serde_json::json!({
            "settings": { "default_upstream": "1.1.1.1:53" },
            "pipelines": [
                {
                    "id": "first",
                    "rules": [
                        {
                            "name": "forward-first-indexed",
                            "matchers": [
                                { "type": "domain_suffix", "value": "www.example.com" },
                                { "type": "qtype", "value": "A" }
                            ],
                            "actions": [{ "type": "forward", "upstream": first_upstream }]
                        },
                        {
                            "name": "forward-first-suffix",
                            "matchers": [{ "type": "domain_suffix", "value": "example.com" }],
                            "actions": [{ "type": "forward", "upstream": first_upstream }]
                        },
                        {
                            "name": "forward-first-regex",
                            "matchers": [{ "type": "domain_regex", "value": "^api[0-9]+\\.example\\.com$" }],
                            "actions": [{ "type": "forward", "upstream": first_upstream }]
                        }
                    ]
                },
                {
                    "id": "second",
                    "rules": [{
                        "name": "forward-second",
                        "matchers": [{ "type": "any" }],
                        "actions": [{ "type": "forward", "upstream": second_upstream }]
                    }]
                }
            ]
        });
        let config: PipelineConfig = serde_json::from_value(raw).expect("parse config");
        RuntimePipelineConfig::from_config(config).expect("build runtime config")
    }

    #[test]
    fn namespace_is_stable_for_identical_configuration() {
        let first = runtime_config("8.8.8.8:53", "9.9.9.9:53");
        let mut second = runtime_config("8.8.8.8:53", "9.9.9.9:53");
        // Derived data is deliberately excluded from the semantic fingerprint.
        // Mutating it must not rotate a cache namespace.
        second.settings.default_upstream_pre_split = Some(Arc::new(vec![Arc::from("derived")]));

        assert_eq!(
            build_cache_namespaces(&first),
            build_cache_namespaces(&second)
        );
    }

    #[test]
    fn changing_one_pipeline_only_changes_its_namespace() {
        let before = build_cache_namespaces(&runtime_config("8.8.8.8:53", "9.9.9.9:53"));
        let after = build_cache_namespaces(&runtime_config("8.8.4.4:53", "9.9.9.9:53"));

        assert_ne!(before.get("first"), after.get("first"));
        assert_eq!(before.get("second"), after.get("second"));
    }

    #[test]
    fn global_response_setting_changes_all_namespaces() {
        let before_config = runtime_config("8.8.8.8:53", "9.9.9.9:53");
        let mut after_config = before_config.clone();
        after_config.settings.default_upstream = "1.0.0.1:53".to_string();
        let before = build_cache_namespaces(&before_config);
        let after = build_cache_namespaces(&after_config);

        assert_ne!(before.get("first"), after.get("first"));
        assert_ne!(before.get("second"), after.get("second"));
    }

    /// 重载即生效、又影响应答的设置，改哪一个都让所有 pipeline 换命名空间
    /// Each setting that applies on a reload and affects the answers moves every pipeline to
    /// a new namespace when changed
    #[test]
    fn every_setting_applied_on_reload_changes_all_namespaces() {
        type Change = fn(&mut crate::config::GlobalSettings);
        let changes: [(&str, Change); 14] = [
            ("min_ttl", |s| s.min_ttl += 1),
            ("default_upstream", |s| {
                s.default_upstream = "1.0.0.1:53".into()
            }),
            ("upstream_timeout_ms", |s| s.upstream_timeout_ms += 1),
            ("request_timeout_ms", |s| {
                s.request_timeout_ms = Some(s.request_timeout_ms.unwrap_or(1000) + 1)
            }),
            ("response_jump_limit", |s| s.response_jump_limit += 1),
            ("serve_stale", |s| s.serve_stale = !s.serve_stale),
            ("serve_stale_ttl", |s| s.serve_stale_ttl += 1),
            ("serve_stale_expire_ttl", |s| s.serve_stale_expire_ttl += 1),
            ("serve_stale_ttl_reset", |s| {
                s.serve_stale_ttl_reset = !s.serve_stale_ttl_reset
            }),
            ("serve_stale_client_timeout_ms", |s| {
                s.serve_stale_client_timeout_ms += 1
            }),
            ("cache_background_refresh", |s| {
                s.cache_background_refresh = !s.cache_background_refresh
            }),
            ("cache_refresh_threshold_percent", |s| {
                s.cache_refresh_threshold_percent = s.cache_refresh_threshold_percent % 99 + 1
            }),
            ("cache_refresh_min_ttl", |s| s.cache_refresh_min_ttl += 1),
            ("enable_tcp_fallback", |s| {
                s.enable_tcp_fallback = !s.enable_tcp_fallback
            }),
        ];
        let before_config = runtime_config("8.8.8.8:53", "9.9.9.9:53");
        let before = build_cache_namespaces(&before_config);
        for (name, change) in changes {
            let mut after_config = before_config.clone();
            change(&mut after_config.settings);
            let after = build_cache_namespaces(&after_config);
            assert_ne!(before.get("first"), after.get("first"), "{name}");
            assert_ne!(before.get("second"), after.get("second"), "{name}");
        }
    }

    /// Geo 数据的设置不进命名空间的哈希：读 Geo 数据的 pipeline 按数据的代数换命名空间（见 `with_geo`），其余的不跟着换。
    /// 以前改哪一个都让所有 pipeline 换命名空间
    /// The Geo settings stay out of the namespace hash: the pipelines reading Geo data move
    /// namespace with the data's generation (see `with_geo`), and the rest do not follow.
    /// Changing any of them used to move every pipeline
    #[test]
    fn geo_settings_leave_namespaces_to_the_geo_generation() {
        type Change = fn(&mut crate::config::GlobalSettings);
        let changes: [(&str, Change); 5] = [
            ("geoip_db_path", |s| {
                s.geoip_db_path = Some("/geo/a.mmdb".into())
            }),
            ("geoip_dat_path", |s| {
                s.geoip_dat_path = Some("/geo/a.dat".into())
            }),
            ("geoip_auto_convert", |s| {
                s.geoip_auto_convert = !s.geoip_auto_convert
            }),
            ("geoip_filter_countries", |s| {
                s.geoip_filter_countries.push("ZZ".into())
            }),
            ("geosite_data_paths", |s| {
                s.geosite_data_paths.push("/geo/site.dat".into())
            }),
        ];
        let before_config = runtime_config("8.8.8.8:53", "9.9.9.9:53");
        let before = build_cache_namespaces(&before_config);
        for (name, change) in changes {
            let mut after_config = before_config.clone();
            change(&mut after_config.settings);
            assert_eq!(before, build_cache_namespaces(&after_config), "{name}");
        }
    }

    /// 统计的两个设置已不起作用，改它们不让缓存换代
    /// The two statistics settings no longer do anything, so changing them leaves
    /// the caches alone
    #[test]
    fn panel_statistics_settings_leave_namespaces_alone() {
        let before_config = runtime_config("8.8.8.8:53", "9.9.9.9:53");
        let mut after_config = before_config.clone();
        after_config.settings.statistics_enabled = true;
        after_config.settings.statistics_anonymize_client_ip = true;
        let before = build_cache_namespaces(&before_config);
        let after = build_cache_namespaces(&after_config);

        assert_eq!(before.get("first"), after.get("first"));
        assert_eq!(before.get("second"), after.get("second"));
    }

    /// 流控的几个旧数字已被智能流控替代、不起作用，改它们不让缓存换代
    /// Flow control's old numbers were replaced by smart flow control and do nothing, so
    /// changing them leaves the caches alone
    #[test]
    fn flow_control_old_numbers_leave_namespaces_alone() {
        let before_config = runtime_config("8.8.8.8:53", "9.9.9.9:53");
        let mut after_config = before_config.clone();
        let settings = &mut after_config.settings;
        settings.flow_control_initial_permits += 1;
        settings.flow_control_min_permits += 1;
        settings.flow_control_max_permits += 1;
        settings.flow_control_latency_threshold_ms += 1;
        settings.flow_control_adjustment_interval_secs += 1;
        let before = build_cache_namespaces(&before_config);
        let after = build_cache_namespaces(&after_config);

        assert_eq!(before.get("first"), after.get("first"));
        assert_eq!(before.get("second"), after.get("second"));
    }

    /// 只在启动时读的设置（见 `GlobalSettings::restart_pending`）重载时改了也不让缓存换代：重载不让它们生效，应答也就
    /// 不会变。以前它们都进了命名空间的哈希，热重载改一个（比如 flow_control_enabled）就作废所有缓存，设置本身却要重启
    /// 才生效
    /// The settings read at startup only (see `GlobalSettings::restart_pending`) leave the
    /// caches alone when a reload changes them: a reload does not apply them, so the answers do
    /// not change. They all used to go into the namespace hash, so a hot reload changing one
    /// (flow_control_enabled, say) dropped every cache while the setting itself waited for a
    /// restart
    #[test]
    fn settings_read_at_startup_leave_namespaces_alone() {
        let before_config = runtime_config("8.8.8.8:53", "9.9.9.9:53");
        let mut after_config = before_config.clone();
        let settings = &mut after_config.settings;
        settings.bind_udp = "127.0.0.1:5353".into();
        settings.bind_tcp = "127.0.0.1:5354".into();
        settings.bind_doh = Some("127.0.0.1:8443".into());
        settings.doh_tls_cert = Some("/etc/kixdns/cert.pem".into());
        settings.doh_tls_key = Some("/etc/kixdns/key.pem".into());
        settings.doh_path = "/resolve".into();
        settings.cache_capacity += 1;
        settings.cache_max_ttl += 1;
        settings.dashmap_shards += 1;
        settings.udp_pool_size += 1;
        settings.tcp_pool_size += 1;
        settings.doh_pool_size += 1;
        settings.doh_health_check_error_threshold += 1;
        settings.dot_pool_size += 1;
        settings.doq_pool_size += 1;
        settings.tcp_health_check_error_threshold += 1;
        settings.tcp_connection_max_age_seconds += 1;
        settings.tcp_connection_idle_timeout_seconds += 1;
        settings.doq_connection_idle_timeout_seconds += 1;
        settings.doq_keepalive_interval_ms += 1;
        settings.doq_enable_0rtt = !settings.doq_enable_0rtt;
        settings.flow_control_enabled = !settings.flow_control_enabled;
        assert_eq!(
            after_config
                .settings
                .restart_pending(&before_config.settings)
                .len(),
            22,
            "every setting read at startup changed"
        );
        let before = build_cache_namespaces(&before_config);
        let after = build_cache_namespaces(&after_config);

        assert_eq!(before.get("first"), after.get("first"));
        assert_eq!(before.get("second"), after.get("second"));
    }
}
