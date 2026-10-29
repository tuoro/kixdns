use crate::config::{Action, EcsMode, GlobalSettings, MatchOperator};
use crate::ecs::EcsKey;
use crate::engine::Engine;
use crate::matcher::advanced_rule::CompiledPipeline;
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
use std::time::Instant;
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
    pub(crate) tx: watch::Sender<InflightResult>,
    namespace: u64,
    pipeline_id: Box<str>,
    qname: Box<[u8]>,
    qtype: RecordType,
    qclass: DNSClass,
    flags: QueryFlags,
    requester: RequesterKey,
    client_ecs: Option<EcsKey>,
}

impl InflightEntry {
    /// `question` 的条目，结果从 `tx` 发出 / The entry of `question`, whose result goes out on `tx`
    pub(crate) fn new(question: &InflightQuestion<'_>, tx: watch::Sender<InflightResult>) -> Self {
        Self {
            tx,
            namespace: question.namespace,
            pipeline_id: question.pipeline_id.into(),
            qname: question.qname.into(),
            qtype: question.qtype,
            qclass: question.qclass,
            flags: question.flags,
            requester: question.requester,
            client_ecs: question.client_ecs,
        }
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
    use super::{InflightEntry, InflightQuestion, inflight_pending};
    use crate::ecs::EcsKey;
    use crate::matcher::RequesterKey;
    use hickory_proto::rr::{DNSClass, RecordType};

    /// 条目只认问得完全一样的请求：问题的任何一部分不同都不算 / An entry is only for a request asking
    /// exactly the same: any part of the question differing rules it out
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
        let (tx, _rx) = tokio::sync::watch::channel(inflight_pending());
        let entry = InflightEntry::new(&question, tx);
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
///   Also includes the insertion time, to age its TTLs (RFC 1035 §5.2).
/// - `AsyncNeeded`: cache miss, needs async processing. Contains pre-parsed data to avoid re-parsing.
#[derive(Debug, Clone)]
pub enum FastPathResponse {
    Direct(Bytes),
    CacheHit {
        cached: Bytes,
        tx_id: u16,
        /// Insertion time for TTL calculation / 用于TTL计算的插入时间
        inserted_at: Instant,
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
    pub cache_namespaces: FxHashMap<Arc<str>, u64>,
}

impl EngineInner {
    #[inline]
    pub(crate) fn cache_namespace(&self, pipeline_id: &str) -> u64 {
        self.cache_namespaces
            .get(pipeline_id)
            .copied()
            .unwrap_or_default()
    }
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
        bind_udp,
        bind_tcp,
        bind_doh,
        doh_tls_cert,
        doh_tls_key,
        doh_path,
        cache_capacity,
        cache_max_ttl,
        dashmap_shards,
        default_upstream,
        default_upstream_pre_split: _,
        upstream_timeout_ms,
        request_timeout_ms,
        response_jump_limit,
        udp_pool_size,
        tcp_pool_size,
        doh_pool_size,
        doh_health_check_error_threshold,
        dot_pool_size,
        doq_pool_size,
        tcp_health_check_error_threshold,
        tcp_connection_max_age_seconds,
        tcp_connection_idle_timeout_seconds,
        doq_connection_idle_timeout_seconds,
        doq_keepalive_interval_ms,
        doq_enable_0rtt,
        flow_control_enabled,
        flow_control_initial_permits,
        flow_control_min_permits,
        flow_control_max_permits,
        flow_control_latency_threshold_ms,
        flow_control_adjustment_interval_secs,
        serve_stale,
        serve_stale_ttl,
        serve_stale_expire_ttl,
        serve_stale_ttl_reset,
        serve_stale_client_timeout_ms,
        cache_background_refresh,
        cache_refresh_threshold_percent,
        cache_refresh_min_ttl,
        geoip_db_path,
        geoip_dat_path,
        geoip_auto_convert,
        geoip_filter_countries,
        geosite_data_paths,
        enable_tcp_fallback,
        // No longer have any effect (see `GlobalSettings`), so they leave the caches alone
        // 已不起作用（见 `GlobalSettings`），不让缓存换代
        statistics_enabled: _,
        statistics_anonymize_client_ip: _,
    } = settings;

    (
        min_ttl,
        bind_udp,
        bind_tcp,
        bind_doh,
        doh_tls_cert,
        doh_tls_key,
        doh_path,
        cache_capacity,
        cache_max_ttl,
        dashmap_shards,
        default_upstream,
    )
        .hash(hasher);
    (
        upstream_timeout_ms,
        request_timeout_ms,
        response_jump_limit,
        udp_pool_size,
        tcp_pool_size,
        doh_pool_size,
        doh_health_check_error_threshold,
        dot_pool_size,
        doq_pool_size,
    )
        .hash(hasher);
    (
        tcp_health_check_error_threshold,
        tcp_connection_max_age_seconds,
        tcp_connection_idle_timeout_seconds,
        doq_connection_idle_timeout_seconds,
        doq_keepalive_interval_ms,
        doq_enable_0rtt,
        flow_control_enabled,
        flow_control_initial_permits,
        flow_control_min_permits,
        flow_control_max_permits,
        flow_control_latency_threshold_ms,
    )
        .hash(hasher);
    (
        flow_control_adjustment_interval_secs,
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
    (
        geoip_db_path,
        geoip_dat_path,
        geoip_auto_convert,
        geoip_filter_countries,
        geosite_data_paths,
        enable_tcp_fallback,
    )
        .hash(hasher);
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
        RuntimeResponseMatcher::UpstreamEquals { value }
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
}
