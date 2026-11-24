use crate::cache::CachedQuestion;
use crate::config::{Action, EcsMode, GlobalSettings, MatchOperator};
use crate::ecs::EcsKey;
use crate::engine::Engine;
use crate::matcher::{
    GeoManagers, Requester, RequesterKey, ResponsePhase, RuntimeMatcher, RuntimePipeline,
    RuntimePipelineConfig, RuntimeResponseMatcher,
};
use crate::proto_utils::QueryFlags;
use bytes::Bytes;
use dashmap::DashMap;
use hickory_proto::rr::{DNSClass, RecordType};
use rustc_hash::{FxBuildHasher, FxHashMap};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::mem::discriminant;
use std::sync::Arc;
use tokio::sync::watch;

pub type InflightMap = DashMap<u64, InflightEntry, FxBuildHasher>;

/// 合并查询的通道里的值：领头请求交出的应答，交出之前是 None。领头请求失败时不交任何东西，放下条目，等着的请求
/// 各自转发（见 `InflightCleanupGuard`）
/// The value on a merged query's channel: the answer the leading request hands over, None until it
/// does. A leading request that fails hands over nothing and lets the entry go, the waiting
/// requests then forwarding themselves (see `InflightCleanupGuard`)
pub type InflightResult = Option<Bytes>;

/// 一个请求在一个 pipeline 下问的问题：算它的响应缓存槽位和 inflight 键用到的全部输入（见 [`Self::keys`]）。请求和快速路径
/// 都只照它算键（见 `EngineInner::question`），转发也照路线算键时的那一份在 inflight 表里登记、等待（见
/// `Route::question`）。键只是这些输入的哈希，带了密钥也难免有两个不同问题落在同一个键上；所以登记时把问题存进条目，等待
/// 之前先核对（见 `InflightEntry::asks`），对不上就自己转发
/// The question a request asks under one pipeline: everything its response cache slot and its
/// inflight key are computed from (see [`Self::keys`]). The request and the fast path compute
/// keys from it alone (see `EngineInner::question`), and a forward registers and waits in the
/// inflight map under the one its route's keys came from (see `Route::question`). The key is
/// only a hash of these, keyed or not, and two different questions may still land on one key;
/// the question is therefore stored in the entry when it is registered and checked before
/// waiting (see `InflightEntry::asks`), and a request whose question differs forwards by itself
#[derive(Debug, Clone, Copy)]
pub(crate) struct KeyedQuestion<'a> {
    pub namespace: u64,
    pub pipeline_id: &'a str,
    pub qname: &'a [u8],
    pub qtype: RecordType,
    pub qclass: DNSClass,
    pub flags: QueryFlags,
    pub requester: RequesterKey,
    pub client_ecs: Option<EcsKey>,
}

impl KeyedQuestion<'_> {
    /// 写进了问题和查询位的哈希（见 `Engine::question_hasher`）/ The hasher with the question and
    /// the query bits written in (see `Engine::question_hasher`)
    fn hasher(&self) -> DefaultHasher {
        let mut h = Engine::question_hasher(
            self.namespace,
            self.pipeline_id,
            self.qname,
            self.qtype,
            self.qclass,
        );
        self.flags.bits().hash(&mut h);
        h
    }

    /// 响应缓存槽位和 inflight 键。槽位存放这个问题的所有应答，每份标着它适用的 ECS 子网（见 `CacheEntry::reach`），所以
    /// 它的键不含子网；请求只有发送相同的子网才能互相等待，所以 inflight 键带上转发会为这个请求方发送的子网，以及客户端自己
    /// 带的 ECS。请求方只在 pipeline 的应答取决于它时写入（见 `RuntimePipeline::requester`），否则键不变
    /// The response cache slot and the inflight key. The slot holds every answer to the
    /// question, each tagged with the ECS subnets it applies to (see `CacheEntry::reach`), so
    /// its key carries no subnet; requests wait on one another only when they send the same, so
    /// the inflight key carries the subnets the forwards would send for the requester and the
    /// client's own ECS. The requester goes in only for a pipeline whose answer depends on it
    /// (see `RuntimePipeline::requester`), the keys unchanged otherwise
    pub(crate) fn keys(&self) -> CacheKeys {
        let mut slot = self.hasher();
        let mut inflight = slot.clone();
        self.requester.hash_into(&mut slot);
        self.requester
            .hash_inflight_into(self.client_ecs.as_ref(), &mut inflight);
        CacheKeys {
            slot: slot.finish(),
            inflight: inflight.finish(),
            namespace: self.namespace,
            requester: self.requester,
        }
    }

    /// 只算 [`Self::keys`] 的槽位，用于不登记 inflight 条目的查找 / The slot of [`Self::keys`]
    /// alone, for a lookup that registers no inflight entry
    pub(crate) fn slot(&self) -> u64 {
        let mut slot = self.hasher();
        self.requester.hash_into(&mut slot);
        slot.finish()
    }
}

/// 一个请求在一个 pipeline 下的键（见 [`KeyedQuestion::keys`]），连同问题里随路线而定的两样：命名空间和请求方部分。
/// 它们和请求自己的那几样一起就是这些键所依据的问题（见 `Route::question`）
/// The keys of one request under one pipeline (see [`KeyedQuestion::keys`]), with the two parts
/// of the question that go by the route: the namespace and the requester's part. With the
/// request's own parts they make up the question the keys came from (see `Route::question`)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheKeys {
    /// Response cache slot / 响应缓存槽位
    pub slot: u64,
    /// Inflight entry / inflight 条目
    pub inflight: u64,
    /// The cache namespace the keys were computed in / 算这些键时用的缓存命名空间
    pub namespace: u64,
    /// The requester's part the keys were computed with / 算这些键时用的请求方部分
    pub requester: RequesterKey,
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
    #[cfg(test)]
    pub(crate) fn new(question: &KeyedQuestion<'_>) -> Self {
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
        question: &KeyedQuestion<'_>,
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
            .get_or_insert_with(|| watch::channel(None).0)
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
    pub(crate) fn asks(&self, question: &KeyedQuestion<'_>) -> bool {
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

#[cfg(test)]
mod inflight_entry_tests {
    use super::{InflightEntry, KeyedQuestion};
    use crate::ecs::EcsKey;
    use crate::matcher::RequesterKey;
    use hickory_proto::rr::{DNSClass, RecordType};

    /// 条目只认问得完全一样的请求：问题的任何一部分不同都不算 / An entry is only for a request asking
    /// exactly the same: any part of the question differing rules it out
    /// 这些测试问的问题 / The question these tests ask
    fn asked<'a>(pipeline_id: &'a str, qname: &'a [u8]) -> KeyedQuestion<'a> {
        KeyedQuestion {
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
        tx.send(Some(bytes::Bytes::from_static(b"answer"))).unwrap();
        for rx in [&mut first, &mut second] {
            rx.changed().await.unwrap();
            let got = rx.borrow().clone().unwrap();
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
        let question = KeyedQuestion {
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
            KeyedQuestion {
                namespace: 2,
                ..question
            },
            KeyedQuestion {
                pipeline_id: "other",
                ..question
            },
            KeyedQuestion {
                qname: b"example.org",
                ..question
            },
            KeyedQuestion {
                qtype: RecordType::AAAA,
                ..question
            },
            KeyedQuestion {
                qclass: DNSClass::CH,
                ..question
            },
            KeyedQuestion {
                flags: crate::proto_utils::QueryFlags::new(true, false, true),
                ..question
            },
            KeyedQuestion {
                requester: RequesterKey {
                    class: Some(1),
                    ..RequesterKey::NONE
                },
                ..question
            },
            KeyedQuestion {
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

// ============================================================================
// Fast-path Response / 快速路径响应
// ============================================================================
///
/// - `Direct`: already has correct TXID and can be sent as-is.
/// - `CacheHit`: carries cached bytes (with an old TXID) and the request TXID to patch.
///   Also includes how long it sat in the cache, to age its TTLs (RFC 1035 §5.2).
/// - `AsyncNeeded`: not answered on the spot, goes on to the async path with what the fast path
///   read, parsed no second time.
#[derive(Debug, Clone)]
pub enum FastPathResponse {
    Direct(Bytes),
    CacheHit {
        cached: Bytes,
        tx_id: u16,
        /// Whole seconds it sat in the cache, for TTL calculation / 在缓存里停留的整秒数，用于计算 TTL
        elapsed_secs: u32,
    },
    /// 快速路径答不上（要问上游、要先等上游的过期应答、跳到了头，或者规则当场决定不了）：交给异步路径，带着读好的查询、
    /// 选中的 pipeline 和选它的那份配置，不再解析一遍（见 `Engine::handle_packet_full`）
    /// Not answered on the fast path (an upstream to ask, a stale answer to wait on the upstream
    /// first, the jumps followed as far as they go, or rules that cannot decide on the spot): on
    /// to the async path with the query as read, the pipeline picked and the configuration that
    /// picked it, parsed no second time (see `Engine::handle_packet_full`)
    AsyncNeeded(super::PreParsedData),
}

pub struct EngineInner {
    pub pipeline: RuntimePipelineConfig,
    /// 每个 pipeline 影响应答的配置指纹，加上它用到的 Geo 数据的指纹（见 [`Self::at_geo`]）
    /// Each pipeline's response-affecting configuration fingerprint, combined with the
    /// fingerprints of the Geo data it uses (see [`Self::at_geo`])
    pub cache_namespaces: FxHashMap<Arc<str>, u64>,
    /// 只按配置算出的指纹 / The fingerprints from the configuration alone
    config_namespaces: FxHashMap<Arc<str>, u64>,
    /// 匹配器判断时读的 Geo 数据，`cache_namespaces` 按它算：请求 load 一次状态，判断和命名空间就是同一份数据（见
    /// [`GeoManagers`]）
    /// The Geo data matchers judge by, from which `cache_namespaces` is worked out: a request
    /// loads the state once, and its judgements and namespaces go by the same data (see
    /// [`GeoManagers`])
    pub(crate) geo: GeoManagers,
    /// 不在任何一个配置了的 pipeline 下的请求用的命名空间（没写 pipeline 的配置里所有请求都是）：只有全局设置的指纹。
    /// 以前这样的请求恒用 0，重载改了全局设置也分不开新旧
    /// The namespace of requests under no configured pipeline (every request of a configuration
    /// with none written): the fingerprint of the global settings alone. Such requests used to
    /// take 0 always, and a reload changing a global setting told old from new by nothing
    no_pipeline_namespace: u64,
}

impl EngineInner {
    /// 从运行时配置建，算出各 pipeline 的缓存命名空间；还没有 Geo 数据，存进去之前由 `GeoSources` 带上 / Built from a
    /// runtime configuration, with the cache namespaces of its pipelines; it has no Geo data yet,
    /// which `GeoSources` gives it before it is stored
    pub(crate) fn new(cfg: RuntimePipelineConfig) -> Self {
        let config_namespaces = build_cache_namespaces(&cfg);
        let geo = GeoManagers::default();
        let no_pipeline_namespace = {
            let mut hasher = DefaultHasher::new();
            hash_global_settings_semantics(&cfg.settings, &mut hasher);
            hasher.finish()
        };
        Self {
            cache_namespaces: with_geo(&cfg, &config_namespaces, &geo),
            config_namespaces,
            geo,
            no_pipeline_namespace,
            pipeline: cfg,
        }
    }

    /// 就地换成 Geo 数据 `geo`，命名空间跟着换（见 [`Self::at_geo`]），给还没存进去的新状态用
    /// Takes the Geo data `geo` in place, the namespaces with it (see [`Self::at_geo`]), for a
    /// new state not stored yet
    pub(crate) fn set_geo(&mut self, geo: GeoManagers) {
        self.cache_namespaces = with_geo(&self.pipeline, &self.config_namespaces, &geo);
        self.geo = geo;
    }

    /// 同样的配置，换成 Geo 数据 `geo` 和按它算的命名空间：用到某个标签的 pipeline，那个标签的数据换了样子就换一个
    /// 命名空间，按旧数据得出的应答和规则决定不再查到；没用到的 pipeline 不变。已经是这份数据的就原样交回
    /// The same configuration with the Geo data `geo` and the namespaces worked out from it: a
    /// pipeline using some tag moves to a new namespace once that tag's data changes, so
    /// answers and rule decisions reached with the old data are no longer found; pipelines
    /// not using it stay as they are. A state already holding this data is handed back as it
    /// is.
    ///
    /// 换数据时整份复制：Geo 数据一天换几次，请求路径上的状态因此保持原来的布局，不多一层间接
    /// New data copies the whole state: Geo data changes a few times a day, and the state on
    /// the request path keeps its layout this way, without another indirection
    pub(crate) fn at_geo(self: &Arc<Self>, geo: GeoManagers) -> Arc<Self> {
        if self.geo.is(&geo) {
            return Arc::clone(self);
        }
        Arc::new(Self {
            cache_namespaces: with_geo(&self.pipeline, &self.config_namespaces, &geo),
            config_namespaces: self.config_namespaces.clone(),
            geo,
            no_pipeline_namespace: self.no_pipeline_namespace,
            pipeline: self.pipeline.clone(),
        })
    }

    #[inline]
    pub(crate) fn cache_namespace(&self, pipeline_id: &str) -> u64 {
        self.cache_namespaces
            .get(pipeline_id)
            .copied()
            .unwrap_or(self.no_pipeline_namespace)
    }

    /// `requester` 在 `asked` 所属的 pipeline（`pipeline` 是它，选不到时为 None）下问的问题（见 [`KeyedQuestion`]）：命名
    /// 空间是这份配置给那个 pipeline 的，请求方部分按它的规则分辨 `requester`。快速路径和请求的键都照它算
    /// The question `requester` asks under the pipeline `asked` is of (`pipeline` being it, None
    /// when none was picked; see [`KeyedQuestion`]): the namespace this configuration gives that
    /// pipeline, the requester's part as its rules tell `requester` apart. The fast path and
    /// the request compute their keys from it
    pub(crate) fn question<'q>(
        &self,
        pipeline: Option<&RuntimePipeline>,
        asked: &CachedQuestion<'q>,
        requester: Requester,
    ) -> KeyedQuestion<'q> {
        KeyedQuestion {
            namespace: self.cache_namespace(asked.pipeline_id),
            pipeline_id: asked.pipeline_id,
            qname: asked.qname.as_bytes(),
            qtype: RecordType::from(asked.qtype),
            qclass: DNSClass::from(asked.qclass),
            flags: asked.flags,
            requester: pipeline.map_or(RequesterKey::NONE, |p| {
                p.requester.key(requester, &self.geo.geoip)
            }),
            client_ecs: requester.ecs,
        }
    }
}

/// 配置指纹加上各 pipeline 读的 Geo 标签的数据的指纹 / The configuration fingerprints combined with
/// the fingerprints of the data of the Geo tags each pipeline reads
fn with_geo(
    cfg: &RuntimePipelineConfig,
    config_namespaces: &FxHashMap<Arc<str>, u64>,
    geo: &GeoManagers,
) -> FxHashMap<Arc<str>, u64> {
    cfg.pipelines
        .iter()
        .map(|pipeline| {
            let base = config_namespaces
                .get(&pipeline.id)
                .copied()
                .unwrap_or_default();
            let namespace = if pipeline.geo_data.is_empty() {
                base
            } else {
                let mut hasher = DefaultHasher::new();
                base.hash(&mut hasher);
                geo.hash_data(&pipeline.geo_data, &mut hasher);
                hasher.finish()
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
            // 据过上游的回答以后跳过去拿到的应答也缓存在这个 pipeline 的键下（见 `RuntimePipeline::answered_through`）
            // The answers jumps get once an upstream's answer has been gone by are cached under this
            // pipeline's key too (see `RuntimePipeline::answered_through`)
            for &reached in &pipeline.answered_through {
                hash_pipeline_semantics(&cfg.pipelines[reached], &mut hasher);
            }
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
        response_jump_limit,
        // 怎样用缓存（等上游多久、过期了还续用多久、提前多久刷新），不改变缓存里的应答：改了不让缓存换代。以前算了进去，
        // 在面板上调一下超时或预取的百分比，响应缓存和规则缓存就全都冷掉，上游被一下子问一遍
        // How the cache is used (how long upstreams are waited for, how long an expired answer
        // stands in, how early a refresh comes) changes no answer in it: a change leaves the
        // caches alone. They used to count, and nudging a timeout or the prefetch percentage in
        // the panel turned the response and rule caches cold at once, the upstreams asked
        // everything over again
        upstream_timeout_ms: _,
        request_timeout_ms: _,
        serve_stale: _,
        serve_stale_ttl: _,
        serve_stale_expire_ttl: _,
        serve_stale_ttl_reset: _,
        serve_stale_client_timeout_ms: _,
        cache_background_refresh: _,
        cache_refresh_threshold_percent: _,
        cache_refresh_min_ttl: _,
        // Geo 数据的设置决定读进哪些名单和网段。应答取决于它们的只有读 Geo 数据的 pipeline，那些 pipeline 按数据的指纹换命名
        // 空间（见 `with_geo`；配置重载换了文件、读出来的数据不同，指纹也就不同），其余的不必跟着换。以前它们算进了每个 pipeline 的命名空间：面板
        // 按内容给 Geo 数据和拦截列表的文件起名，每次更新都换一个文件，名单一更新整份缓存就作废。后两个现在什么也不做
        // The Geo settings decide which lists and networks are read in. Only the pipelines
        // reading Geo data have answers that depend on them, and those move namespace with
        // the data's fingerprints (see `with_geo`; a reload changing the files to other data
        // changes them too), so the rest need not follow. They used to go into every
        // pipeline's namespace: the panel names the files of Geo data and blocklists by their
        // content, every update brings another file, and every list update dropped the whole
        // cache. The last two do nothing at present
        geoip_db_path: _,
        geoip_dat_path: _,
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
        tcp_connection_max_age_seconds: _,
        tcp_connection_idle_timeout_seconds: _,
        doq_connection_idle_timeout_seconds: _,
        doq_keepalive_interval_ms: _,
        doq_enable_0rtt: _,
        bootstrap: _,
        flow_control_enabled: _,
        // No longer have any effect (see `GlobalSettings`), so they leave the caches alone
        // 已不起作用（见 `GlobalSettings`），不让缓存换代
    } = settings;

    (
        min_ttl,
        default_upstream,
        response_jump_limit,
        enable_tcp_fallback,
    )
        .hash(hasher);
}

/// pipeline 里决定应答的部分。规则级的运算符编译时已经定进每个匹配器的运算符里，起作用的部分随匹配器算进来；pipeline 级
/// 的 `ecs` 不起作用（缓存按上游返回的作用范围区分应答，见 `CacheEntry::reach`），不在运行时配置里，改了它缓存不换代。
/// 以前两样都另算一遍，改一个不起作用的 `ecs` 也丢掉整个缓存
/// The part of a pipeline that decides its answers. The rule-level operators are settled into
/// each matcher's operator as it compiles, and what they do counts with the matchers; the
/// pipeline-level `ecs` does nothing (the cache tells answers apart by the scope the upstream
/// returns, see `CacheEntry::reach`), is not in the runtime configuration, and changing it
/// leaves the caches alone. Both used to count on their own, so changing an `ecs` that did
/// nothing dropped the whole cache
fn hash_pipeline_semantics(pipeline: &RuntimePipeline, hasher: &mut impl Hasher) {
    pipeline.id.hash(hasher);
    pipeline.rules.len().hash(hasher);
    for rule in &pipeline.rules {
        rule.name.hash(hasher);
        rule.matchers.len().hash(hasher);
        for matcher in rule.matchers.iter() {
            hash_match_operator(matcher.operator, hasher);
            hash_runtime_matcher(&matcher.matcher, hasher);
        }
        rule.actions.len().hash(hasher);
        for action in &rule.actions {
            hash_action(action, hasher);
        }
        let (response_matchers, on_match, on_miss) =
            ResponsePhase::parts(rule.response_phase.as_deref());
        response_matchers.len().hash(hasher);
        for matcher in response_matchers {
            hash_match_operator(matcher.operator, hasher);
            hash_runtime_response_matcher(&matcher.matcher, hasher);
        }
        on_match.len().hash(hasher);
        for action in on_match {
            hash_action(action, hasher);
        }
        on_miss.len().hash(hasher);
        for action in on_miss {
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
        Action::StaticResponse { rcode, .. } => rcode.hash(hasher),
        Action::StaticIpResponse { ip, .. } => ip.hash(hasher),
        Action::StaticCnameResponse { target, ttl, .. } => {
            target.hash(hasher);
            ttl.hash(hasher);
        }
        Action::StaticTxtResponse { text, ttl, .. } => {
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
        Action::ReplaceTxtResponse { text, .. } => text.hash(hasher),
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

    /// pipeline 级的 `ecs` 不起作用，改了它命名空间不变：缓存按上游返回的作用范围区分应答（见 `CacheEntry::reach`）。
    /// 以前它也算进命名空间，改一个不起作用的设置就丢掉这个 pipeline 的整个缓存
    /// The pipeline-level `ecs` does nothing, and changing it leaves the namespace as it was:
    /// the cache tells answers apart by the scope the upstream returns (see
    /// `CacheEntry::reach`). It used to count, so changing a setting that did nothing dropped
    /// the pipeline's whole cache
    #[test]
    fn the_pipeline_level_ecs_leaves_the_namespace_alone() {
        let namespaces = |ecs: serde_json::Value| {
            let config: PipelineConfig = serde_json::from_value(serde_json::json!({
                "settings": { "default_upstream": "1.1.1.1:53" },
                "pipelines": [{
                    "id": "main",
                    "ecs": ecs,
                    "rules": [{
                        "name": "forward",
                        "matchers": [{ "type": "any" }],
                        "actions": [{ "type": "forward", "upstream": "8.8.8.8:53" }]
                    }]
                }]
            }))
            .expect("parse config");
            build_cache_namespaces(&RuntimePipelineConfig::from_config(config).expect("build"))
        };
        assert_eq!(
            namespaces(serde_json::Value::Null),
            namespaces(serde_json::json!({ "mode": "from_client_ip", "prefix_v4": 16 }))
        );
    }

    #[test]
    fn changing_one_pipeline_only_changes_its_namespace() {
        let before = build_cache_namespaces(&runtime_config("8.8.8.8:53", "9.9.9.9:53"));
        let after = build_cache_namespaces(&runtime_config("8.8.4.4:53", "9.9.9.9:53"));

        assert_ne!(before.get("first"), after.get("first"));
        assert_eq!(before.get("second"), after.get("second"));
    }

    /// 回答检查 continue 之后规则跳到的 pipeline 算进入口的命名空间：跳过去拿到的应答缓存在入口的键下（见
    /// `Route::enter`），它一改，那些应答就不再用。直接跳过去的 pipeline 不算，那里的应答缓存在它自己的键下。以前只算回答检查
    /// 的跳转，目标改了，入口键下按旧配置得出的应答照用到过期
    /// A pipeline the rules jump to after an answer check continued goes into the entry's
    /// namespace: what is got over there is cached under the entry's key (see `Route::enter`),
    /// and once it changes those answers are used no more. One jumped to outright does not, its
    /// answers cached under its own key. Only answer checks' jumps used to count, the answers
    /// under the entry's key from the old configuration served on after the target changed,
    /// until they expired
    #[test]
    fn a_jump_target_after_a_continue_goes_into_the_namespace() {
        let namespaces = |target_upstream: &str| {
            let jump = serde_json::json!({
                "name": "jump",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "jump_to_pipeline", "pipeline": "target" }]
            });
            let config: PipelineConfig = serde_json::from_value(serde_json::json!({
                "settings": { "default_upstream": "1.1.1.1:53" },
                "pipelines": [
                    { "id": "continued", "rules": [
                        {
                            "name": "check",
                            "matchers": [{ "type": "any" }],
                            "actions": [{ "type": "forward", "upstream": "8.8.8.8:53" }],
                            "response_actions_on_match": [{ "type": "continue" }]
                        },
                        jump
                    ]},
                    { "id": "outright", "rules": [jump] },
                    { "id": "target", "rules": [{
                        "name": "forward",
                        "matchers": [{ "type": "any" }],
                        "actions": [{ "type": "forward", "upstream": target_upstream }]
                    }]}
                ]
            }))
            .expect("parse config");
            build_cache_namespaces(&RuntimePipelineConfig::from_config(config).expect("build"))
        };
        let (before, after) = (namespaces("9.9.9.9:53"), namespaces("9.9.9.10:53"));
        assert_ne!(before.get("continued"), after.get("continued"));
        assert_eq!(before.get("outright"), after.get("outright"));
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
        let changes: [(&str, Change); 4] = [
            ("min_ttl", |s| s.min_ttl += 1),
            ("default_upstream", |s| {
                s.default_upstream = "1.0.0.1:53".into()
            }),
            ("response_jump_limit", |s| s.response_jump_limit += 1),
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

    /// 怎样用缓存的设置（等上游多久、过期了续用多久、提前多久刷新）不改变缓存里的应答，改了不让缓存换代。以前改哪一个都让
    /// 所有 pipeline 换命名空间，在面板上调一下超时，整个缓存就冷了
    /// The settings for how the cache is used (how long upstreams are waited for, how long an
    /// expired answer stands in, how early a refresh comes) change no answer in it and leave the
    /// caches alone. Changing any of them used to move every pipeline, nudging a timeout in the
    /// panel turning the whole cache cold
    #[test]
    fn settings_for_using_the_cache_leave_namespaces_alone() {
        type Change = fn(&mut crate::config::GlobalSettings);
        let changes: [(&str, Change); 10] = [
            ("upstream_timeout_ms", |s| s.upstream_timeout_ms += 1),
            ("request_timeout_ms", |s| {
                s.request_timeout_ms = Some(s.request_timeout_ms.unwrap_or(1000) + 1)
            }),
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
        ];
        let before_config = runtime_config("8.8.8.8:53", "9.9.9.9:53");
        let before = build_cache_namespaces(&before_config);
        for (name, change) in changes {
            let mut after_config = before_config.clone();
            change(&mut after_config.settings);
            assert_eq!(before, build_cache_namespaces(&after_config), "{name}");
        }
    }

    /// Geo 数据的设置不进命名空间的哈希：读 Geo 数据的 pipeline 按数据的指纹换命名空间（见 `with_geo`），其余的不跟着换。
    /// 以前改哪一个都让所有 pipeline 换命名空间
    /// The Geo settings stay out of the namespace hash: the pipelines reading Geo data move
    /// namespace with the data's fingerprints (see `with_geo`), and the rest do not follow.
    /// Changing any of them used to move every pipeline
    #[test]
    fn geo_settings_leave_namespaces_to_the_geo_data() {
        type Change = fn(&mut crate::config::GlobalSettings);
        let changes: [(&str, Change); 3] = [
            ("geoip_db_path", |s| {
                s.geoip_db_path = Some("/geo/a.mmdb".into())
            }),
            ("geoip_dat_path", |s| {
                s.geoip_dat_path = Some("/geo/a.dat".into())
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
        settings.tcp_connection_max_age_seconds += 1;
        settings.tcp_connection_idle_timeout_seconds += 1;
        settings.doq_connection_idle_timeout_seconds += 1;
        settings.doq_keepalive_interval_ms += 1;
        settings.doq_enable_0rtt = !settings.doq_enable_0rtt;
        settings.bootstrap = "192.0.2.53:53".into();
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
