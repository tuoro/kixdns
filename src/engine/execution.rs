use rustc_hash::{FxHashMap, FxHashSet, FxHasher};
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use anyhow::Context;

use bytes::Bytes;

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::DNSClass;
#[cfg(test)]
use hickory_proto::rr::Name;
#[cfg(test)]
use hickory_proto::rr::rdata::A;

use hickory_proto::serialize::binary::BinDecodable;
use tracing::warn;

use crate::cache::CacheEntry;
use crate::config::Transport;
use crate::matcher::RuntimePipelineConfig;
use crate::matcher::advanced_rule::{compile_pipelines, fast_static_match_with_rule};
use crate::observe::{
    CacheHit, CacheHitKind, DecisionDetail, DecisionKind, DecisionMade, EngineObserver,
    RequestContext, RequestOutcome, RequestStatus, RuleCacheLookup, RuleMatched, RulePhase,
};
use crate::proto_utils::parse_quick;

use super::observation::{ObservedRequest, cached_source, report_decision, report_matched_rules};
use super::response::build_fast_static_response;
use super::response_log::{ResponseInfo, ResponseLog};
use super::rules::RuleCacheRecord;
use super::types::{EngineInner, FastPathResponse, build_cache_namespaces};
use super::utils::{InflightCleanupGuard, engine_helpers, is_refreshing};
#[cfg(test)]
use crate::engine::rules::calculate_rule_hash;
use crate::engine::rules::{Decision, ResponseContext};

/// Pre-parsed data from handle_packet_fast to avoid re-parsing
/// 来自 handle_packet_fast 的预解析数据，避免重新解析
#[derive(Debug)]
pub struct PreParsedData {
    qname: String,
    qtype: hickory_proto::rr::RecordType,
    qclass: DNSClass,
    tx_id: u16,
    edns_present: bool,
    pipeline_id: Arc<str>,
    /// Pre-computed ECS cache key from fast path (avoids recomputation)
    /// 快速路径预计算的 ECS 缓存键（避免重算）
    ecs_key: Option<crate::ecs::EcsKey>,
}
impl PreParsedData {
    pub fn new(
        qname: String,
        qtype: u16,
        qclass: u16,
        tx_id: u16,
        edns_present: bool,
        pipeline_id: Arc<str>,
        ecs_key: Option<crate::ecs::EcsKey>,
    ) -> Self {
        Self {
            qname,
            qtype: hickory_proto::rr::RecordType::from(qtype),
            qclass: DNSClass::from(qclass),
            tx_id,
            edns_present,
            pipeline_id,
            ecs_key,
        }
    }
}

/// What answered a request on the synchronous fast path, for observer reporting.
/// 快速路径上应答请求的来源，用于观察者上报。
enum FastPathAnswer<'a> {
    /// Fresh response cache entry / 新鲜的响应缓存条目
    Cache {
        original_ttl: u32,
        elapsed_secs: u32,
        source: Option<&'a str>,
    },
    /// Compiled static rule matched directly / 编译后的静态规则直接命中
    StaticRule {
        rule: &'a str,
        rcode: ResponseCode,
        answers: usize,
    },
    /// Rule cache entry holding a static decision / 规则缓存中的静态决策
    CachedRules { record: &'a RuleCacheRecord },
}

// ============================================================================
// Constants / 常量
// ============================================================================

use super::core::Engine;
use super::pipeline::{PipelineSelectionContext, RuleEvaluationContext, select_pipeline};

// ============================================================================
// Refreshing Bitmap Helpers / 刷新位图辅助函数
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
fn request_timeout_ms(settings: &crate::config::GlobalSettings) -> u64 {
    settings
        .request_timeout_ms
        .unwrap_or(settings.upstream_timeout_ms * 5 / 2)
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
        let compiled = compile_pipelines(&new_cfg);
        // Build O(1) compiled pipeline lookup index / 构建 O(1) 编译管道查找索引
        let pipeline_index: FxHashMap<Arc<str>, usize> = compiled
            .iter()
            .enumerate()
            .map(|(i, p)| (p.id.clone(), i))
            .collect();
        // Store, generation and event stay together under the reload lock, so
        // the reported generation is the one this reload allocated.
        // 存储、代数与事件在重载锁内一起完成，事件中的代数就是本次分配的值。
        let _reload_guard = self.reload_lock.lock();
        self.state.store(Arc::new(EngineInner {
            cache_namespaces: build_cache_namespaces(&new_cfg),
            pipeline: new_cfg,
            compiled_pipelines: compiled,
            pipeline_index,
        }));
        let generation = self.config_generation.fetch_add(1, Ordering::Relaxed) + 1;
        self.report_config_loaded(generation, path, source);
        // Cache keys include a per-pipeline configuration namespace. Changed
        // pipelines become unreachable immediately, while unchanged pipelines
        // keep their warm response and rule caches.
        // Reset background refresh rule to allow re-initialization with new config
        // 重置后台刷新规则以允许使用新配置重新初始化
        // Note: OnceLock cannot be reset, so we rely on the fact that the rule is
        // initialized from the current pipeline config via get_background_refresh_rule()
        // 注意：OnceLock 无法重置，所以我们依赖规则通过 get_background_refresh_rule()
        // 从当前 pipeline 配置初始化的事实
    }

    /// Get or initialize the background refresh dedicated rule
    /// 获取或初始化后台刷新专用规则
    ///
    /// Design: Uses OnceLock for thread-safe lazy initialization
    /// 设计：使用 OnceLock 实现线程安全的延迟初始化
    /// - First call: Creates rule from config or default
    /// - Subsequent calls: Returns cached rule
    /// - 首次调用：从配置或默认创建规则
    /// - 后续调用：返回缓存的规则
    #[allow(dead_code)]
    fn get_background_refresh_rule(&self) -> Option<Arc<crate::matcher::RuntimeRule>> {
        // 暂时返回 None，等待 RuntimePipelineConfig 结构更新
        // Temporarily return None, waiting for RuntimePipelineConfig structure update
        None
    }

    /// 动态调整 flow control permits 基于系统负载和延迟 / Adaptively adjust flow control permits based on system load and latency
    pub fn adjust_flow_control(&self) {
        if let Some(state) = &self.flow_control_state {
            let latest_latency = self
                .metrics_last_upstream_latency_ns
                .load(Ordering::Relaxed);
            state.adjust(&self.permit_manager, latest_latency);
        }
    }

    /// Get the configured upstream timeout in milliseconds
    /// 获取配置的上游超时时间（毫秒）
    #[inline]
    pub fn get_upstream_timeout_ms(&self) -> u64 {
        self.state.load().pipeline.settings.upstream_timeout_ms
    }

    /// Get the overall request timeout in milliseconds (including hedge + TCP fallback)
    /// 获取整体请求超时时间（毫秒），包含 hedge + TCP fallback
    ///
    /// 如果用户显式配置了 request_timeout_ms，使用配置值
    /// 否则自动计算为 upstream_timeout_ms * 2.5
    /// If request_timeout_ms is explicitly configured, use that value
    /// Otherwise auto-calculate as upstream_timeout_ms * 2.5
    #[inline]
    pub fn get_request_timeout_ms(&self) -> u64 {
        request_timeout_ms(&self.state.load().pipeline.settings)
    }

    /// Get parse_quick failure statistics
    /// 获取快速解析失败统计信息
    ///
    /// Returns (total_requests, parse_quick_failures, failure_rate)
    /// 返回 (总请求数, 快速解析失败数, 失败率)
    #[inline]
    pub fn get_parse_quick_stats(&self) -> (u64, u64, f64) {
        let total = self.metrics_total_requests.load(Ordering::Relaxed);
        let failures = self.metrics_parse_quick_failures.load(Ordering::Relaxed);
        let rate = if total > 0 {
            (failures as f64) / (total as f64) * 100.0
        } else {
            0.0
        };
        (total, failures, rate)
    }

    /// Increment total_requests counter using simple atomic operation
    #[inline]
    fn incr_total_requests(&self) {
        self.metrics_total_requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment fastpath_hits counter using simple atomic operation
    #[inline]
    fn incr_fastpath_hits(&self) {
        self.metrics_fastpath_hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment parse_quick_failures counter using simple atomic operation
    #[inline]
    fn incr_parse_quick_failures(&self) {
        self.metrics_parse_quick_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn calculate_cache_hash_for_dedupe(
        cache_namespace: u64,
        pipeline_id: &str,
        qname: &[u8],
        qtype: hickory_proto::rr::RecordType,
        qclass: hickory_proto::rr::DNSClass,
        ecs_key: Option<&crate::ecs::EcsKey>,
    ) -> u64 {
        let mut h = FxHasher::default();
        cache_namespace.hash(&mut h);
        pipeline_id.hash(&mut h);
        // Hash qname case-insensitively without allocation / 不分配内存地进行不区分大小写的 qname 哈希
        // qname is already lowercased from parse_quick() / qname 已经在 parse_quick() 中转为小写
        for b in qname {
            h.write_u8(*b);
        }
        // RecordType implements Copy+Debug, hash by its u16 representation / RecordType 实现了 Copy+Debug，使用其 u16 表示进行哈希
        u16::from(qtype).hash(&mut h);
        // DNSClass implements Copy+Debug, hash by its u16 representation / DNSClass 实现了 Copy+Debug，使用其 u16 表示进行哈希
        u16::from(qclass).hash(&mut h);
        // ECS key for cache isolation by client subnet (RFC 7871)
        // ECS key 用于按客户端子网隔离缓存 (RFC 7871)
        if let Some(ecs) = ecs_key {
            ecs.hash_into(&mut h);
        }
        h.finish()
    }

    /// Helper: create and insert DNS cache entry / 辅助函数：创建并插入 DNS 缓存条目
    /// Eliminate duplicate CacheEntry construction code / 消除重复的 CacheEntry 构造代码
    #[inline]
    pub(crate) fn insert_dns_cache_entry(&self, cache_hash: u64, entry: CacheEntry) {
        self.cache.insert(cache_hash, Arc::new(entry));
    }

    /// Observer context for a request answered on the fast path.
    /// 快速路径应答请求的观察者上下文。
    fn fast_path_context<'a>(
        &'a self,
        peer: SocketAddr,
        qname: &'a str,
        qtype: hickory_proto::rr::RecordType,
        qclass: DNSClass,
    ) -> RequestContext<'a> {
        RequestContext {
            request_id: self.request_id_counter.fetch_add(1, Ordering::Relaxed),
            listener_label: &self.listener_label,
            client: peer,
            transport: self.client_transport,
            qname,
            qtype,
            qclass,
            background_refresh: false,
        }
    }

    /// Report a request that `handle_packet_fast` answered without the async
    /// path: the whole lifecycle is emitted in one batch at the answering site.
    /// `response` is the answer, or the error that stopped the engine from
    /// building one; the listener then answers SERVFAIL by itself.
    /// 上报由 handle_packet_fast 直接应答的请求：整个生命周期在应答处一次性上报。
    /// `response` 是应答，或者引擎没能构造出应答的错误；此时由监听器自己回 SERVFAIL。
    fn observe_fast_path(
        &self,
        observer: &dyn EngineObserver,
        start: Instant,
        ctx: &RequestContext<'_>,
        pipeline_id: &str,
        answer: FastPathAnswer<'_>,
        response: Result<&[u8], &anyhow::Error>,
    ) {
        observer.request_started(ctx);
        observer.pipeline_selected(ctx, pipeline_id);
        observer.cache_lookup(ctx);
        match answer {
            FastPathAnswer::Cache {
                original_ttl,
                elapsed_secs,
                source,
            } => observer.cache_hit(
                ctx,
                &CacheHit {
                    kind: CacheHitKind::Fresh,
                    remaining_ttl: Some(Duration::from_secs(
                        original_ttl.saturating_sub(elapsed_secs) as u64,
                    )),
                    original_ttl: Some(Duration::from_secs(original_ttl as u64)),
                    source,
                },
            ),
            FastPathAnswer::StaticRule {
                rule,
                rcode,
                answers,
            } => {
                observer.cache_miss(ctx);
                observer.rule_matched(
                    ctx,
                    &RuleMatched {
                        pipeline: pipeline_id,
                        rule,
                        phase: RulePhase::Request,
                        decision: DecisionKind::Static,
                        fast_path: true,
                    },
                );
                observer.decision_made(
                    ctx,
                    &DecisionMade {
                        pipeline: pipeline_id,
                        rule: Some(rule),
                        phase: RulePhase::Request,
                        detail: DecisionDetail::Static { rcode, answers },
                    },
                );
            }
            FastPathAnswer::CachedRules { record } => {
                observer.cache_miss(ctx);
                let recorded = record.matched_rules.as_deref();
                observer.rule_cache_lookup(
                    ctx,
                    &RuleCacheLookup {
                        pipeline: pipeline_id,
                        hit: true,
                        matched_rules: recorded.map_or(0, <[Arc<str>]>::len),
                    },
                );
                let deciding_rule = record.decided_by_rule.then(|| recorded?.last()).flatten();
                if let Some(rules) = recorded {
                    report_matched_rules(
                        observer,
                        ctx,
                        pipeline_id,
                        rules,
                        deciding_rule.map(|_| DecisionKind::Static),
                        true,
                    );
                }
                report_decision(
                    observer,
                    ctx,
                    pipeline_id,
                    deciding_rule.map(AsRef::as_ref),
                    &record.entry.decision,
                );
            }
        }
        let error = response.as_ref().err().map(|error| format!("{error:#}"));
        observer.request_finished(
            ctx,
            &RequestOutcome {
                latency: start.elapsed(),
                status: if error.is_some() {
                    RequestStatus::Failed
                } else {
                    RequestStatus::Completed
                },
                response: response.ok(),
                error: error.as_deref(),
            },
        );
    }

    #[allow(dead_code)]
    pub fn metrics_snapshot(&self) -> String {
        let inflight = self.metrics_inflight.load(Ordering::Relaxed);
        let total = self.metrics_total_requests.load(Ordering::Relaxed);
        let fast = self.metrics_fastpath_hits.load(Ordering::Relaxed);
        let up_ns = self.metrics_upstream_ns_total.load(Ordering::Relaxed);
        let up_calls = self.metrics_upstream_calls.load(Ordering::Relaxed);
        let avg_up_ns = up_ns.checked_div(up_calls).unwrap_or(0);
        format!(
            "inflight={} total={} fastpath_hits={} upstream_avg_us={}",
            inflight,
            total,
            fast,
            avg_up_ns as f64 / 1000.0
        )
    }

    /// Fast path: synchronous cache hit attempt / 快速路径：同步尝试缓存命中
    /// Return Ok(Some(bytes)) means cache hit, can return directly / 返回 Ok(Some(bytes)) 表示缓存命中，可直接返回
    /// Return Ok(None) means async processing needed (upstream forwarding) / 返回 Ok(None) 表示需要异步处理（上游转发）
    /// Return Err means parsing error / 返回 Err 表示解析错误
    #[inline]
    pub fn handle_packet_fast(
        &self,
        packet: &[u8],
        peer: SocketAddr,
    ) -> anyhow::Result<Option<FastPathResponse>> {
        let log_start = Instant::now();
        // Quick parsing, avoiding full Message parsing and massive allocations / 快速解析，避免完整 Message 解析和大量分配
        // Use stack buffer to avoid String allocation / 使用栈上缓冲区避免 String 分配
        let mut qname_buf = [0u8; 256];
        let q = match parse_quick(packet, &mut qname_buf) {
            Some(q) => q,
            None => {
                // Quick parse failed, fallback to async path / 快速解析失败，回退到异步路径
                self.incr_parse_quick_failures();
                return Ok(None);
            }
        };
        // Count incoming quick-parsed requests / 计数进入的快速解析请求
        self.incr_total_requests();
        // Observer: requests answered here are reported in one batch at the
        // answering site; requests that fall through are reported by the async path.
        // 观察者：在此应答的请求在应答处一次性上报；回落的请求由异步路径上报。
        let observed = self
            .observer
            .as_deref()
            .map(|observer| (observer, Instant::now()));

        // Get pipeline ID / 获取 pipeline ID
        let state = self.state.load_full();
        let cfg = &state.pipeline;
        let qclass = DNSClass::from(q.qclass);
        let qtype = hickory_proto::rr::RecordType::from(q.qtype);
        // GeoSiteManager uses FxHashMap protected by RwLock, no additional locks needed
        // GeoSiteManager 使用 FxHashMap + RwLock 保护，无需额外锁
        // Use unchecked conversion for performance (qname_bytes is validated UTF-8)
        // 使用未检查转换以提高性能（qname_bytes 是已验证的 UTF-8）
        let qname_str = q.qname_str_unchecked();
        let (pipeline_opt, pipeline_id) = select_pipeline(
            cfg,
            &PipelineSelectionContext {
                qname: qname_str,
                client_ip: peer.ip(),
                qclass,
                edns_present: q.edns_present,
                qtype,
                listener_label: &self.listener_label,
                geosite_manager: Some(&self.geosite_manager),
                geoip_manager: Some(&self.geoip_manager),
            },
        );

        // 1. Check Response Cache (L2) / 1. 检查响应缓存（L2）
        // Compute ECS cache key from pipeline config + peer IP (RFC 7871)
        // 从 Pipeline ECS 配置 + peer IP 计算 ECS 缓存键 (RFC 7871)
        let ecs_key = pipeline_opt.and_then(|p| {
            p.ecs
                .as_ref()
                .and_then(|mode| crate::ecs::EcsKey::from_pipeline_config(mode, peer.ip()))
        });
        let cache_namespace = state.cache_namespace(&pipeline_id);
        let cache_hash = Self::calculate_cache_hash_for_dedupe(
            cache_namespace,
            &pipeline_id,
            q.qname_bytes,
            qtype,
            qclass,
            ecs_key.as_ref(),
        );

        if let Some(hit) = self.cache.get(&cache_hash) {
            // Verify collision / 验证冲突
            if hit.qtype == u16::from(qtype)
                && q.qname_matches(hit.qname.as_ref())
                && hit.pipeline_id == pipeline_id
            {
                // Check if expired / 检查是否已过期
                let elapsed_secs =
                    crate::proto_utils::saturating_u64_to_u32(hit.inserted_at.elapsed().as_secs());
                if elapsed_secs >= hit.original_ttl {
                    // RFC 8767: When serve_stale is enabled, keep stale entries for fallback
                    // RFC 8767: 当 serve_stale 启用时，保留过期条目以便 fallback
                    if !cfg.settings.serve_stale {
                        self.cache.invalidate(&cache_hash);
                    }
                } else {
                    // Cache background refresh: trigger async refresh when TTL < threshold percentage
                    // 缓存后台刷新：当TTL < 阈值百分比时，触发异步刷新
                    // Only refresh cache entries that came from an upstream server
                    // 只有来自 upstream 的缓存条目才进行预取刷新
                    if cfg.settings.cache_background_refresh
                        && hit.upstream.is_some()
                        && hit.refresh_ttl >= cfg.settings.cache_refresh_min_ttl
                    {
                        // Calculate remaining TTL and refresh threshold
                        // 计算剩余 TTL 和刷新阈值
                        let remaining_ttl = hit.refresh_ttl.saturating_sub(elapsed_secs);
                        let threshold = (hit.refresh_ttl as u64
                            * cfg.settings.cache_refresh_threshold_percent as u64)
                            / 100;

                        // OPTIMIZATION: Hybrid bloom filter + DashSet check / 优化：混合布隆过滤器 + DashSet 检查
                        let is_refreshing = is_refreshing(
                            &self.refreshing_bitmap,
                            &self.refreshing_set,
                            cache_hash,
                        );

                        tracing::debug!(
                            original_ttl = hit.original_ttl,
                            refresh_ttl = hit.refresh_ttl,
                            elapsed_secs = elapsed_secs,
                            remaining_ttl = remaining_ttl,
                            threshold_percent = cfg.settings.cache_refresh_threshold_percent,
                            threshold_value = threshold,
                            min_ttl = cfg.settings.cache_refresh_min_ttl,
                            is_refreshing = is_refreshing,
                            should_trigger = !is_refreshing && remaining_ttl as u64 <= threshold,
                            upstream = ?hit.upstream,
                            qname = %q.qname_str_unchecked(),  // Use unchecked for performance / 使用未检查版本以提高性能
                            "cache background refresh check"
                        );

                        if !is_refreshing && remaining_ttl as u64 <= threshold {
                            // Trigger background refresh (async, don't block current request)
                            // 触发后台刷新（异步，不阻塞当前请求）
                            // Note: RefreshingGuard inside spawn_background_refresh will handle cleanup
                            // 注意：spawn_background_refresh 内部的 RefreshingGuard 将处理清理
                            let qname_str = q.qname_str_unchecked(); // Zero-allocation / 零分配
                            tracing::debug!(
                                qname = %qname_str,
                                original_ttl = hit.original_ttl,
                                refresh_ttl = hit.refresh_ttl,
                                remaining_ttl = remaining_ttl,
                                "triggering background cache refresh"
                            );
                            self.spawn_background_refresh(
                                state.clone(),
                                cache_hash,
                                &pipeline_id,
                                qname_str,
                                qtype,
                                qclass,
                                peer.ip(),
                            );
                        }
                    }

                    // Return current cache immediately, don't wait for refresh to complete
                    // 直接返回当前缓存，不等待刷新完成
                    // Next query will automatically use refreshed new cache (if completed)
                    // 下次查询时会自动使用刷新后的新缓存（如果已完成）
                    self.incr_fastpath_hits();
                    if let Some((observer, start)) = observed {
                        self.observe_fast_path(
                            observer,
                            start,
                            &self.fast_path_context(peer, qname_str, qtype, qclass),
                            &pipeline_id,
                            FastPathAnswer::Cache {
                                original_ttl: hit.original_ttl,
                                elapsed_secs,
                                source: cached_source(hit.upstream.as_deref()),
                            },
                            Ok(&hit.bytes),
                        );
                    }
                    let mut log = ResponseLog::new(
                        qname_str,
                        qtype,
                        peer,
                        pipeline_id.clone(),
                        log_start,
                        false,
                    );
                    log.info.cache_hit = true;
                    log.info.upstream =
                        Some(hit.upstream.clone().unwrap_or_else(|| Arc::from("static")));
                    log.answered(&hit.bytes);
                    return Ok(Some(FastPathResponse::CacheHit {
                        cached: hit.bytes.clone(),
                        tx_id: q.tx_id,
                        inserted_at: hit.inserted_at,
                    }));
                }
            }
        }

        // 2. Compiled rule fast-path for static decisions / 2. 编译规则的静态决策快速路径
        if let Some(compiled) = self.compiled_for(&state, &pipeline_id) {
            let qclass = DNSClass::from(q.qclass);
            let qname_str = q.qname_str_unchecked(); // Zero-allocation / 零分配
            if let Some((Decision::Static { rcode, answers }, rule_name)) =
                fast_static_match_with_rule(
                    compiled,
                    qname_str,
                    qtype,
                    qclass,
                    peer.ip(),
                    q.edns_present,
                )
            {
                // Report before `?`: a response that cannot be built still ends the
                // request here, and the listener answers SERVFAIL by itself.
                // 在 `?` 之前上报：构造不出应答的请求也在这里结束，由监听器自己回 SERVFAIL。
                let built = build_fast_static_response(
                    q.tx_id, qname_str, q.qtype, q.qclass, rcode, &answers,
                );
                if let Some((observer, start)) = observed {
                    self.observe_fast_path(
                        observer,
                        start,
                        &self.fast_path_context(peer, qname_str, qtype, qclass),
                        &pipeline_id,
                        FastPathAnswer::StaticRule {
                            rule: rule_name,
                            rcode,
                            answers: answers.len(),
                        },
                        built.as_deref(),
                    );
                }
                let resp = built?;
                self.incr_fastpath_hits();
                let mut log = ResponseLog::new(
                    qname_str,
                    qtype,
                    peer,
                    pipeline_id.clone(),
                    log_start,
                    false,
                );
                log.info.upstream = Some(Arc::from("static"));
                log.answered(&resp);
                return Ok(Some(FastPathResponse::Direct(resp)));
            }
        }

        // 3. Check Rule Cache (L1) for Static Responses / 3. 检查规则缓存（L1）的静态响应
        // Zero-allocation lookup using hash / 使用哈希的零分配查找
        if let Some(p) = pipeline_opt {
            // Optimization: only include IP in hash when rule uses client_ip matcher or config requires it
            // 优化：仅当规则使用client_ip匹配器或配置要求时才包含IP在哈希中
            let include_ip_in_hash = p.uses_client_ip || cfg.settings.cache_background_refresh;
            let rule_hash = crate::engine::rules::calculate_rule_hash(
                cache_namespace,
                &pipeline_id,
                qname_str,
                qtype,
                qclass,
                peer.ip(),
                include_ip_in_hash,
            );
            if let Some(record) = self.rule_cache.get(&rule_hash) {
                let entry = &record.entry;
                // Check if entry is valid before using
                // 在使用前检查条目是否有效
                if !entry.is_valid() {
                    // Remove expired entry
                    // 删除过期条目
                    self.rule_cache.remove(&rule_hash);
                } else if entry.matches(
                    &pipeline_id,
                    qname_str,
                    qtype,
                    qclass,
                    peer.ip(),
                    include_ip_in_hash,
                ) && let Decision::Static { rcode, answers } = entry.decision.as_ref()
                {
                    // Report before `?`, as for the compiled static rule above.
                    // 在 `?` 之前上报，同上面的编译静态规则。
                    let built = build_fast_static_response(
                        q.tx_id, qname_str, q.qtype, q.qclass, *rcode, answers,
                    );
                    if let Some((observer, start)) = observed {
                        self.observe_fast_path(
                            observer,
                            start,
                            &self.fast_path_context(peer, qname_str, qtype, qclass),
                            &pipeline_id,
                            FastPathAnswer::CachedRules { record: &record },
                            built.as_deref(),
                        );
                    }
                    let resp = built?;
                    self.incr_fastpath_hits();
                    let mut log = ResponseLog::new(
                        qname_str,
                        qtype,
                        peer,
                        pipeline_id.clone(),
                        log_start,
                        false,
                    );
                    log.info.upstream = Some(Arc::from("static"));
                    log.answered(&resp);
                    return Ok(Some(FastPathResponse::Direct(resp)));
                }
            }
        }

        // Cache miss, need async processing / 缓存未命中，需要异步处理
        // Return AsyncNeeded with pre-parsed data to avoid re-parsing in handle_packet
        // 返回 AsyncNeeded 包含预解析数据，避免在 handle_packet 中重新解析
        Ok(Some(FastPathResponse::AsyncNeeded {
            qname: qname_str.to_string(),
            qtype: q.qtype,
            qclass: q.qclass,
            tx_id: q.tx_id,
            edns_present: q.edns_present,
            pipeline_id,
            ecs_key, // Pass pre-computed ECS key to avoid recomputation / 传递预计算的 ECS key 避免重算
        }))
    }

    pub async fn handle_packet(&self, packet: &[u8], peer: SocketAddr) -> anyhow::Result<Bytes> {
        self.handle_packet_internal(packet, peer, false, None, None, None)
            .await
    }

    /// Public wrapper for handle_packet_internal with pre-parsed data
    /// handle_packet_internal 的公共包装，接受预解析数据
    ///
    /// This method is used by UDP worker to avoid re-parsing when cache miss occurs
    /// 此方法由 UDP worker 使用，在缓存未命中时避免重新解析
    pub async fn handle_packet_internal_with_pre_parsed(
        &self,
        packet: &[u8],
        peer: SocketAddr,
        skip_cache: bool,
        pre_parsed: PreParsedData,
    ) -> anyhow::Result<Bytes> {
        self.handle_packet_internal(packet, peer, skip_cache, Some(pre_parsed), None, None)
            .await
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
        let settings = &lookup.state.pipeline.settings;
        if let Some((observer, ctx)) = lookup.observed {
            observer.cache_lookup(ctx);
        }
        if let Some(resp_bytes) = phases::check_cache_logged(self, lookup, info) {
            return Some(resp_bytes);
        }

        // RFC 8767 Client Timeout: When serve_stale is enabled with client_timeout > 0,
        // try upstream for client_timeout_ms before falling back to stale data.
        // RFC 8767 客户端超时：当 serve_stale 启用且 client_timeout > 0 时，
        // 先尝试上游查询 client_timeout_ms 毫秒，超时后返回过期数据。
        // Corresponds to Unbound serve-expired-client-timeout
        //
        // Design: check_cache() already triggers spawn_background_refresh() for expired entries
        // when client_timeout > 0. Here we poll the cache with 5ms intervals to detect
        // when the background refresh completes. If client_timeout expires, serve stale.
        // 设计：check_cache() 在 client_timeout > 0 且缓存过期时已触发 spawn_background_refresh。
        // 这里以 5ms 间隔轮询缓存，检测后台刷新是否完成。超时则返回过期数据。
        if settings.serve_stale && settings.serve_stale_client_timeout_ms > 0 {
            let has_stale = self
                .cache
                .get(&lookup.dedupe_hash)
                .filter(|h| {
                    h.qtype == u16::from(lookup.qtype)
                        && h.pipeline_id.as_ref() == lookup.pipeline_id
                        && h.qname.as_ref() == lookup.qname
                        && h.inserted_at.elapsed().as_secs() >= h.original_ttl as u64
                        && h.rcode != ResponseCode::ServFail
                        && h.rcode != ResponseCode::Refused
                })
                .is_some();

            if has_stale {
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
                let client_timeout = Duration::from_millis(settings.serve_stale_client_timeout_ms)
                    .min(
                        budget
                            .saturating_sub(lookup.start.elapsed())
                            .saturating_sub(STALE_SERVE_RESERVE),
                    );
                let poll_interval = std::time::Duration::from_millis(5);
                let wait_start = Instant::now();

                // Poll cache for fresh data from background refresh
                // 轮询缓存等待后台刷新带来的新鲜数据
                while wait_start.elapsed() < client_timeout {
                    tokio::time::sleep(poll_interval).await;
                    // Check if background refresh put fresh data in cache
                    let Some(fresh_hit) = self.cache.get(&lookup.dedupe_hash) else {
                        break;
                    };
                    if fresh_hit.inserted_at.elapsed().as_secs() < fresh_hit.original_ttl as u64 {
                        // Fresh data available! Serve it.
                        if let Some(fresh_bytes) = phases::check_cache_logged(self, lookup, info) {
                            tracing::debug!(
                                event = "serve_fresh_after_client_wait",
                                qname = %lookup.qname,
                                wait_ms = wait_start.elapsed().as_millis() as u64,
                                "background refresh completed within client_timeout"
                            );
                            return Some(fresh_bytes);
                        }
                    }
                }

                // Client timeout expired - serve stale response
                // 客户端超时 - 返回过期缓存响应
                if let Some(stale_bytes) = phases::check_stale_cache_logged(
                    self,
                    lookup,
                    CacheHitKind::StaleClientTimeout,
                    info,
                ) {
                    tracing::debug!(
                        event = "serve_stale_on_client_timeout",
                        qname = %lookup.qname,
                        qtype = ?lookup.qtype,
                        waited_ms = client_timeout.as_millis() as u64,
                        configured_timeout_ms = settings.serve_stale_client_timeout_ms,
                        client_ip = %lookup.peer.ip(),
                        pipeline = %lookup.pipeline_id,
                        "RFC 8767: client timeout expired, serving stale"
                    );
                    return Some(stale_bytes);
                }
                // Stale entry evicted by moka - fall through to normal processing
            }
        }

        // The response cache had nothing usable for this request
        // 响应缓存中没有本请求可用的条目
        if let Some((observer, ctx)) = lookup.observed {
            observer.cache_miss(ctx);
        }
        None
    }

    /// Internal handle_packet implementation with skip_cache option
    /// 内部 handle_packet 实现，支持跳过缓存选项
    ///
    /// Design: Background refresh calls this with skip_cache=true to:
    /// 设计：后台刷新使用 skip_cache=true 调用以：
    /// 1. Skip cache lookup (avoid returning stale cache)
    /// 2. Skip cache hit metrics (avoid inflating hit rate)
    /// 3. Always query upstream (get fresh data)
    /// 1. 跳过缓存查找（避免返回陈旧缓存）
    /// 2. 跳过缓存命中指标（避免虚高命中率）
    /// 3. 始终查询上游（获取最新数据）
    ///
    /// pre_parsed: Optional pre-parsed data from handle_packet_fast to avoid re-parsing
    /// pre_parsed: 来自 handle_packet_fast 的可选预解析数据，避免重新解析
    ///
    /// explicit_cache_hash: Optional pre-computed cache hash for background refresh.
    /// When provided, skips ECS key computation to ensure the same hash as the original request.
    /// explicit_cache_hash: 后台刷新用的预计算 cache hash。
    /// 提供时跳过 ECS key 计算，确保与原始请求的 hash 一致。
    pub(crate) async fn handle_packet_internal(
        &self,
        packet: &[u8],
        peer: SocketAddr,
        skip_cache: bool,
        pre_parsed: Option<PreParsedData>,
        explicit_cache_hash: Option<u64>,
        state_override: Option<Arc<EngineInner>>,
    ) -> anyhow::Result<Bytes> {
        // Track requests and inflight concurrency for diagnostics. / 跟踪请求和进行中的并发以进行诊断
        let request_id = self.request_id_counter.fetch_add(1, Ordering::Relaxed);
        self.incr_total_requests();
        struct InflightGuard<'a>(&'a AtomicUsize);
        impl<'a> Drop for InflightGuard<'a> {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::Relaxed);
            }
        }
        self.metrics_inflight.fetch_add(1, Ordering::Relaxed);
        let _inflight_guard = InflightGuard(&self.metrics_inflight);
        // A request uses one immutable configuration snapshot from selection
        // through response actions and cache writes. Background refresh passes
        // the snapshot that produced its cache key via `state_override`.
        let state = state_override.unwrap_or_else(|| self.state.load_full());
        let cfg = &state.pipeline;
        let min_ttl = cfg.min_ttl();
        let upstream_timeout = cfg.upstream_timeout();
        let response_jump_limit = cfg.settings.response_jump_limit as usize;

        // Use pre-parsed data if available, otherwise parse / 如果有预解析数据则使用，否则解析
        let (qname_cow, qtype, qclass, tx_id, edns_present, pipeline_id, pre_ecs_key) =
            if let Some(pre) = pre_parsed {
                (
                    std::borrow::Cow::Owned(pre.qname),
                    pre.qtype,
                    pre.qclass,
                    pre.tx_id,
                    pre.edns_present,
                    pre.pipeline_id,
                    pre.ecs_key,
                )
            } else {
                // Lazy Parse: Use quick parse first / 延迟解析：首先使用快速解析
                // Allocate qname_buf outside the if-else to extend lifetime
                // 在 if-else 外部分配 qname_buf 以延长生命周期
                let mut qname_buf = [0u8; 256];
                let q = parse_quick(packet, &mut qname_buf);

                let (qname_cow, qtype, qclass, tx_id, edns_present) = if let Some(q) = q {
                    // Use unchecked conversion to avoid double allocation / 使用未检查转换避免双重分配
                    // SAFETY: qname_bytes is validated ASCII from parse_quick()
                    // ASCII is always valid UTF-8, so this is safe
                    // 安全性：qname_bytes 在 parse_quick() 中已验证为 ASCII
                    // ASCII 始终是有效的 UTF-8，所以这是安全的
                    let qname_str = unsafe { std::str::from_utf8_unchecked(q.qname_bytes) };
                    (
                        std::borrow::Cow::Owned(qname_str.to_string()),
                        hickory_proto::rr::RecordType::from(q.qtype),
                        DNSClass::from(q.qclass),
                        q.tx_id,
                        q.edns_present,
                    )
                } else {
                    // Fallback to full parse if quick parse fails (unlikely for standard queries) / 如果快速解析失败则回退到完整解析（对于标准查询不太可能）
                    let req = Message::from_bytes(packet).context("parse request")?;
                    let question = req.queries.first().context("empty question")?;
                    (
                        // Name::to_lowercase() returns Name, .to_string() converts to String
                        // Name::to_lowercase() 返回 Name，.to_string() 转换为 String
                        std::borrow::Cow::Owned(question.name().to_lowercase().to_string()),
                        question.query_type(),
                        question.query_class(),
                        req.metadata.id,
                        req.edns.is_some(),
                    )
                };

                // Scope geosite_mgr to ensure lock is released before await
                // 限制 geosite_mgr 的作用域，确保在 await 之前释放锁
                let pipeline_id = {
                    // GeoSiteManager now uses DashMap, no Mutex lock needed
                    // GeoSiteManager 现在使用 DashMap，无需 Mutex 锁
                    let (_, pipeline_id) = select_pipeline(
                        cfg,
                        &PipelineSelectionContext {
                            qname: &qname_cow,
                            client_ip: peer.ip(),
                            qclass,
                            edns_present,
                            qtype,
                            listener_label: &self.listener_label,
                            geosite_manager: Some(&self.geosite_manager),
                            geoip_manager: Some(&self.geoip_manager),
                        },
                    );
                    pipeline_id
                }; // geosite_mgr 在这里释放 / geosite_mgr released here

                (
                    qname_cow,
                    qtype,
                    qclass,
                    tx_id,
                    edns_present,
                    pipeline_id,
                    None,
                )
            };

        let qname_ref = &qname_cow;
        let start = std::time::Instant::now();
        let mut response_log = ResponseLog::new(
            qname_ref,
            qtype,
            peer,
            pipeline_id.clone(),
            start,
            skip_cache,
        );

        // Observer handle for this request: borrows the parsed query and
        // reports request_finished when dropped, so cancelled requests
        // (listener timeouts drop the future) are reported as well.
        // 本请求的观察者句柄：借用已解析的查询，drop 时上报 request_finished，
        // 因此被取消的请求（监听器超时会丢弃 future）同样会上报。
        // In this crate only background refresh skips the cache (see the design
        // note on handle_packet_internal). Both fields below follow this one
        // flag, so a new use of skip_cache has to decide on it here.
        // 本 crate 里只有后台刷新跳过缓存（见 handle_packet_internal 的设计说明）。
        // 下面两个字段都跟着这一个判断；skip_cache 有了新用法，要在这里一起定。
        let background_refresh = skip_cache;
        let mut observed = self.observer.as_deref().map(|observer| {
            ObservedRequest::new(
                observer,
                RequestContext {
                    request_id,
                    listener_label: &self.listener_label,
                    client: peer,
                    // A refresh is the engine's own query, whichever listener's request scheduled it.
                    // 刷新是引擎自己的查询，与安排它的请求来自哪个监听器无关。
                    transport: if background_refresh {
                        None
                    } else {
                        self.client_transport
                    },
                    qname: qname_ref,
                    qtype,
                    qclass,
                    background_refresh,
                },
                start,
            )
        });
        let observed_ctx = observed
            .as_ref()
            .map(|observed| (observed.observer, &observed.ctx));
        if let Some(observed) = &observed {
            observed.observer.request_started(&observed.ctx);
            observed
                .observer
                .pipeline_selected(&observed.ctx, &pipeline_id);
        }

        // Everything below may return the response from several places.
        // The async block funnels every exit through one point so the
        // observer learns the outcome; the block is awaited immediately.
        // 以下代码在多处返回响应；用 async 块包裹使所有出口汇聚到一处，便于观察者
        // 获得请求结果。该块会被立即 await。
        // Inflight entry the request still holds after a rule continued (see
        // `ForwardDecisionContext::held_inflight`)
        // 规则 continue 后本请求仍持有的 inflight 条目
        let mut held_inflight: Option<InflightCleanupGuard> = None;
        let result: anyhow::Result<Bytes> = async {
            // Find pipeline_opt from pipeline_id / 从 pipeline_id 查找 pipeline_opt
            let pipeline_opt = cfg
                .pipeline_id_index
                .get(pipeline_id.as_ref())
                .and_then(|&idx| cfg.pipelines.get(idx));

            // Convert qname_ref to bytes for hash calculation / 将 qname_ref 转换为 bytes 进行哈希计算
            let qname_bytes = qname_ref.as_bytes();
            // Compute dedupe hash: use explicit hash for background refresh, or pre-computed ECS key,
            // otherwise compute with ECS key from pipeline config
            // 计算 dedupe hash：后台刷新用显式 hash，或用预计算 ECS key，否则从 pipeline 配置计算
            let ecs_key = if explicit_cache_hash.is_some() {
                None // explicit hash overrides; ecs_key not needed / 显式 hash 优先；不需要 ecs_key
            } else {
                pre_ecs_key.or_else(|| {
                    pipeline_opt.and_then(|p| {
                        p.ecs.as_ref().and_then(|mode| {
                            crate::ecs::EcsKey::from_pipeline_config(mode, peer.ip())
                        })
                    })
                })
            };
            let dedupe_hash = if let Some(h) = explicit_cache_hash {
                h
            } else {
                Self::calculate_cache_hash_for_dedupe(
                    state.cache_namespace(&pipeline_id),
                    &pipeline_id,
                    qname_bytes,
                    qtype,
                    qclass,
                    ecs_key.as_ref(),
                )
            };

            // Background refresh: Skip cache lookup when skip_cache=true
            // 后台刷新：当 skip_cache=true 时跳过缓存查找
            if !skip_cache
                && let Some(resp_bytes) = self
                    .answer_from_cache(
                        &phases::CacheLookupContext {
                            state: &state,
                            qname: qname_ref,
                            qtype,
                            qclass,
                            pipeline_id: &pipeline_id,
                            dedupe_hash,
                            tx_id,
                            start,
                            peer: &peer,
                            observed: observed_ctx,
                        },
                        &mut response_log.info,
                    )
                    .await
            {
                return Ok(resp_bytes);
            }

            // 优化：保持 Cow<str> 以延迟分配，避免不必要的 String 分配
            // Optimization: Keep Cow<str> to defer allocation, avoid unnecessary String allocation
            // 大部分情况下 qname_cow 是 Borrowed（零拷贝），只有快速解析失败时才是 Owned
            // In most cases qname_cow is Borrowed (zero-copy), only Owned when quick parse fails
            let qname: &str = qname_ref;
            let mut skip_rules: FxHashSet<Arc<str>> = FxHashSet::default();
            let mut current_pipeline_id = pipeline_id.clone();
            let mut current_uses_client_ip =
                pipeline_opt.map(|p| p.uses_client_ip).unwrap_or(false);
            // 这条路线上有没有按 EDNS 判断的 pipeline（见跳转后的缓存查找）/ Whether a pipeline on the route so far matches on EDNS (see the lookup after a jump)
            let mut route_matches_edns = pipeline_opt.is_some_and(|p| p.matches_edns);
            // Convert qname to bytes for hash calculation / 将 qname 转换为 bytes 进行哈希计算
            let qname_bytes = qname.as_bytes();
            // Reuse dedupe_hash from earlier computation (includes ECS key isolation)
            // 复用之前计算的 dedupe_hash（已含 ECS key 隔离维度）
            let mut dedupe_hash = dedupe_hash;
            let mut reused_response: Option<ResponseContext> = None;

            let mut decision = match pipeline_opt {
                Some(p) => self.apply_rules(
                    &state,
                    p,
                    &RuleEvaluationContext::new(
                        peer.ip(),
                        qname,
                        qtype,
                        qclass,
                        edns_present,
                        None,
                        skip_cache,
                    )
                    .with_observed(observed_ctx),
                ),
                None => {
                    // 使用预分割的默认 upstream 以支持并发查询 / Use pre-split default upstream for concurrent queries
                    let (upstream, pre_split) =
                        if let Some(pre) = &cfg.settings.default_upstream_pre_split {
                            (
                                Arc::from(cfg.settings.default_upstream.as_str()),
                                Some(pre.clone()),
                            )
                        } else {
                            (Arc::from(cfg.settings.default_upstream.as_str()), None)
                        };

                    let decision = Decision::Forward {
                        upstream,
                        pre_split_upstreams: pre_split,
                        response_matchers: Vec::new(),
                        response_matcher_operator: crate::config::MatchOperator::And,
                        response_actions_on_match: Vec::new(),
                        response_actions_on_miss: Vec::new(),
                        rule_name: Arc::from("default"),
                        transport: Some(Transport::Udp),
                        ecs: None,
                        continue_on_match: false,
                        continue_on_miss: false,
                        allow_reuse: false,
                    };
                    if let Some((observer, ctx)) = observed_ctx {
                        report_decision(observer, ctx, &pipeline_id, None, &decision);
                    }
                    decision
                }
            };

            // DESIGN NOTE: InflightCleanupGuard safety analysis
            // 设计说明：InflightCleanupGuard 安全性分析
            //
            // Safety Guarantee: No race condition exists
            // 安全性保证：不存在竞态条件
            //
            // The guard is always used as a local stack variable (never shared via Arc/Mutex).
            // Rust's ownership model guarantees that:
            // - Mutable borrow via as_mut() (for defuse()) and Drop execution are mutually exclusive
            // - The compiler prevents concurrent access at compile time
            //
            // 该守卫始终作为局部栈变量使用（从不通过 Arc/Mutex 共享）。
            // Rust 所有权模型保证：
            // - 通过 as_mut() 的可变借用（用于 defuse()）和 Drop 执行互斥
            // - 编译器在编译期阻止并发访问
            //
            // This is a standard Rust RAII pattern that is safe and idiomatic.
            // 这是标准的 Rust RAII 模式，安全且符合惯用法。

            // jump_count must live outside 'decision_loop so it is not reset
            // when Forward returns Continue and we re-enter the outer loop.
            // Without this, the response_jump_limit could be bypassed via:
            //   Jump → Forward(Continue) → [jump_count reset to 0] → Jump → …
            let mut jump_count = 0;
            // A refresh renews the entry under `refresh_key`. Once a rule has continued
            // past an answer, the outcome may be a static answer or come from a jump
            // target, which do not renew it: see the Static branch and the Success arm.
            // 刷新更新的是 `refresh_key` 下的条目。规则越过一个应答之后，结果可能是静态
            // 应答或来自跳转目标，它们不会更新这条：见 Static 分支和 Success 分支。
            let refresh_key = dedupe_hash;
            let mut refresh_passed_an_answer = false;
            // 决策循环的第几轮：第一轮在任何转发之前 / Which pass of the decision loop: the first runs before anything is forwarded
            let mut pass = 0u32;
            'decision_loop: loop {
                pass += 1;
                while let Decision::Jump { pipeline } = &decision {
                    jump_count += 1;
                    if jump_count > response_jump_limit {
                        warn!("max jump limit reached");
                        decision = Decision::Static {
                            rcode: ResponseCode::ServFail,
                            answers: Vec::new(),
                        };
                        break;
                    }
                    if let Some(&idx) = cfg.pipeline_id_index.get(pipeline.as_ref()) {
                        let p = &cfg.pipelines[idx];
                        current_pipeline_id = p.id.clone();
                        response_log.info.pipeline = Some(current_pipeline_id.clone());
                        current_uses_client_ip = p.uses_client_ip;
                        route_matches_edns |= p.matches_edns;
                        if let Some(observed) = &observed {
                            observed
                                .observer
                                .pipeline_selected(&observed.ctx, &current_pipeline_id);
                        }
                        // Must recompute ECS key + dedupe_hash: pipeline changed via Jump,
                        // so the target pipeline's ECS config may differ from the source.
                        // 必须重算 ECS key + dedupe_hash：pipeline 因 Jump 改变，
                        // 目标 pipeline 的 ECS 配置可能与源 pipeline 不同。
                        let jump_ecs_key = p.ecs.as_ref().and_then(|mode| {
                            crate::ecs::EcsKey::from_pipeline_config(mode, peer.ip())
                        });
                        dedupe_hash = Self::calculate_cache_hash_for_dedupe(
                            state.cache_namespace(&current_pipeline_id),
                            &current_pipeline_id,
                            qname_bytes,
                            qtype,
                            qclass,
                            jump_ecs_key.as_ref(),
                        );
                        // 跳转后按目标 pipeline 的键再查一次响应缓存。转发回来的应答存在这个键下，而入口
                        // 那次查找用的是入口 pipeline 的键，所以以前跳转过的请求永远查不到它，每次都去问
                        // 上游。以下情况不查，保持原样：
                        // - 不在第一轮：continue 之后，请求已经越过了一个应答，后面的规则可能复用它；
                        // - 目标的应答因「谁在问」而不同：它给别的请求方的应答不一定是给这一个的；
                        // - 后台刷新走不回这条路线：刷新重放的请求不带 EDNS、类别固定是 IN，路线上（含
                        //   pipeline 的选择）按 EDNS 判断，或者查询类别不是 IN 时，刷新可能走另一条路线，
                        //   把别处的应答写进这个键，或者写进另一个键。
                        // After a jump, look in the response cache again under the target pipeline's
                        // key. A forwarded answer is stored under that key, while the entry lookup used
                        // the entry pipeline's, so a request that jumped never found it and went upstream
                        // every time. These cases do not look and keep the current behaviour:
                        // - after the first pass: past a continue the request has passed over an answer
                        //   that later rules may reuse;
                        // - a target whose answer differs by who is asking: its answer to another
                        //   requester is not necessarily its answer to this one;
                        // - a route a background refresh cannot repeat: the refresh replays the query
                        //   without EDNS and in class IN, so when the route (pipeline selection included)
                        //   matches on EDNS, or the query class is not IN, it may take another route and
                        //   write another answer under this key, or write under another key.
                        if !skip_cache
                            && pass == 1
                            && !p.depends_on_requester
                            && !route_matches_edns
                            && qclass == DNSClass::IN
                            && !cfg.selection_matches_edns()
                            && let Some(resp_bytes) = self
                                .answer_from_cache(
                                    &phases::CacheLookupContext {
                                        state: &state,
                                        qname,
                                        qtype,
                                        qclass,
                                        pipeline_id: &current_pipeline_id,
                                        dedupe_hash,
                                        tx_id,
                                        start,
                                        peer: &peer,
                                        observed: observed_ctx,
                                    },
                                    &mut response_log.info,
                                )
                                .await
                        {
                            return Ok(resp_bytes);
                        }
                        skip_rules.clear();
                        decision = self.apply_rules(
                            &state,
                            p,
                            &RuleEvaluationContext::new(
                                peer.ip(),
                                qname,
                                qtype,
                                qclass,
                                edns_present,
                                None,
                                skip_cache,
                            )
                            .with_observed(observed_ctx),
                        );
                    } else {
                        warn!("jump target pipeline not found: {}", pipeline);
                        decision = Decision::Static {
                            rcode: ResponseCode::ServFail,
                            answers: Vec::new(),
                        };
                        break;
                    }
                }

                match decision {
                    Decision::Jump { .. } => {
                        anyhow::bail!("unresolved pipeline jump");
                    }
                    Decision::Static { rcode, answers } => {
                        // A static answer from a pipeline that matches on the client
                        // is that client's alone: let the waiters run the rules
                        // themselves rather than hand it to them.
                        // 按客户端匹配的 pipeline 给出的静态应答只属于这个客户端：让
                        // 等待者自己走规则，不把它交给它们。
                        if current_uses_client_ip {
                            drop(held_inflight.take());
                        }
                        response_log.info.upstream = Some(Arc::from("static"));
                        // After a refresh continued past an answer: a SERVFAIL here (a
                        // jump target that does not exist, the jump limit, or a static
                        // SERVFAIL the rules configure) ends the refresh as a failure
                        // and the entry stays; any other static answer replaces the
                        // entry, which handle_static_decision stores again when it
                        // caches the answer there.
                        // 刷新越过一个应答之后：这里的 SERVFAIL（跳转目标不存在、到了跳转
                        // 上限，或规则配置的静态 SERVFAIL）让刷新以失败结束，条目保留；其他
                        // 静态应答取代这条，handle_static_decision 在那里缓存应答时会重新写入。
                        if refresh_passed_an_answer {
                            if rcode == ResponseCode::ServFail {
                                return Err(phases::refresh_found_no_answer(
                                    "no answer after a continue",
                                ));
                            }
                            self.cache_invalidate(&refresh_key);
                        }
                        return phases::handle_static_decision(
                            self,
                            &phases::StaticDecisionContext {
                                packet,
                                qname,
                                qtype,
                                pipeline_id: &current_pipeline_id,
                                dedupe_hash,
                                min_ttl,
                                start,
                                peer: &peer,
                                uses_client_ip: current_uses_client_ip,
                            },
                            rcode,
                            answers,
                        );
                    }
                    Decision::Forward {
                        upstream,
                        pre_split_upstreams,
                        response_matchers,
                        response_matcher_operator: _,
                        response_actions_on_match,
                        response_actions_on_miss,
                        rule_name,
                        transport,
                        ecs,
                        continue_on_match: _,
                        continue_on_miss: _,
                        allow_reuse,
                    } => {
                        let res = phases::handle_forward_decision_logged(
                            self,
                            phases::ForwardDecisionContext {
                                state: &state,
                                packet,
                                qname,
                                qtype,
                                qclass,
                                tx_id,
                                pipeline_id: &current_pipeline_id,
                                rule_name: &rule_name,
                                dedupe_hash,
                                min_ttl,
                                upstream_timeout,
                                start,
                                peer: &peer,
                                skip_cache,
                                upstream: &upstream,
                                pre_split_upstreams: pre_split_upstreams.as_ref(),
                                response_matchers: &response_matchers,
                                response_actions_on_match: &response_actions_on_match,
                                response_actions_on_miss: &response_actions_on_miss,
                                transport,
                                ecs: ecs.as_ref(),
                                allow_reuse,
                                reused_response: &mut reused_response,
                                held_inflight: &mut held_inflight,
                                observed: observed_ctx,
                            },
                            &mut response_log.info,
                        )
                        .await;

                        match res {
                            Ok(phases::ForwardResult::Success(bytes)) => {
                                // After a refresh continued past an answer and then
                                // jumped, the answer is not stored under `refresh_key`:
                                // unless it is a failure (SERVFAIL, or the target's
                                // stale answer served on one, the only cache hit a
                                // refresh can have), the entry there no longer matches
                                // the rules.
                                // 刷新越过一个应答又跳转之后，应答不会存进 `refresh_key`：
                                // 只要不是失败（SERVFAIL，或失败时返回的目标旧结果，也是
                                // 刷新唯一可能的缓存命中），那里的条目就已经和规则对不上。
                                if refresh_passed_an_answer
                                    && dedupe_hash != refresh_key
                                    && !phases::is_servfail(&bytes)
                                    && !response_log.info.cache_hit
                                {
                                    self.cache_invalidate(&refresh_key);
                                }
                                return Ok(bytes);
                            }
                            Ok(phases::ForwardResult::Continue(ctx)) => {
                                refresh_passed_an_answer |= skip_cache && ctx.is_some();
                                reused_response = *ctx;
                                skip_rules.insert(rule_name.clone());
                                let skip_ref = if skip_rules.is_empty() {
                                    None
                                } else {
                                    Some(&skip_rules)
                                };

                                let pipeline = if let Some(&idx) =
                                    cfg.pipeline_id_index.get(current_pipeline_id.as_ref())
                                {
                                    &cfg.pipelines[idx]
                                } else {
                                    warn!(
                                        "pipeline missing while continuing: {}",
                                        current_pipeline_id
                                    );
                                    let req =
                                        Message::from_bytes(packet).context("parse request")?;
                                    return engine_helpers::build_servfail_response(&req);
                                };

                                decision = self.apply_rules(
                                    &state,
                                    pipeline,
                                    &RuleEvaluationContext::new(
                                        peer.ip(),
                                        qname,
                                        qtype,
                                        qclass,
                                        edns_present,
                                        skip_ref,
                                        skip_cache,
                                    )
                                    .with_observed(observed_ctx),
                                );
                                continue 'decision_loop;
                            }
                            Err(e) => {
                                // A background refresh answers no client: it gets the
                                // failure itself, which refresh.rs logs.
                                // 后台刷新没有要应答的客户端：失败原样交回，由 refresh.rs 记录。
                                if skip_cache {
                                    return Err(e);
                                }
                                // A rule continued (response_actions_on_match: [continue])
                                // and the next Forward attempt failed. The client must
                                // receive a definitive answer, never silence: DNS clients
                                // treat a missing reply as TIMEOUT. Return SERVFAIL so the
                                // stub resolver can retry (RFC 1035).
                                // 规则 continue 后，下一条 Forward 查询失败。必须给客户端
                                // 一个确定性的响应而非静默：DNS 客户端会把无响应视为
                                // TIMEOUT。返回 SERVFAIL 以便 stub resolver 重试。
                                warn!(
                                    event = "continue_reforward_failed",
                                    error = %e,
                                    rule = %rule_name,
                                    "continue re-forward failed, returning SERVFAIL"
                                );
                                let req = Message::from_bytes(packet)
                                    .context("parse request for SERVFAIL")?;
                                return engine_helpers::build_servfail_response(&req);
                            }
                        }
                    }
                }
            }
        }
        .await;
        // A request that continued still holds its entry here: its waiters get the
        // final answer. On failure, or if the request is cancelled, the guard drops
        // and removes the entry, and the waiters forward themselves.
        // continue 过的请求走到这里仍持有条目：等待者拿到最终应答。失败或请求被
        // 取消时，守卫被丢弃并移除条目，等待者自己转发。
        if let Some(mut guard) = held_inflight.take()
            && let Ok(bytes) = &result
        {
            guard.defuse();
            self.notify_inflight_waiters(guard.hash, bytes).await;
        }
        response_log.finish(&result);
        if let Some(observed) = observed.as_mut() {
            observed.finish(&result);
        }
        result
    }

    pub(crate) async fn notify_inflight_waiters(&self, dedupe_hash: u64, bytes: &Bytes) {
        // ========== NEW: Use tokio::watch for lock-free notification ==========
        // 使用 tokio::watch 实现无锁通知
        // Remove the watch sender from inflight map and send result
        // 从 inflight map 移除 watch sender 并发送结果
        if let Some((_, tx)) = self.inflight.remove(&dedupe_hash) {
            // Send result to all waiters (lock-free)
            // 向所有等待者发送结果 (无锁)
            let _ = tx.send(Ok(bytes.clone()));
        }
    }

    /// 缓存后台刷新：当TTL即将过期时，异步刷新缓存条目
    /// Cache background refresh: asynchronously refresh cache entry when TTL is about to expire
    ///
    /// 防止无限循环的保护措施：
    /// Protection against infinite loops:
    /// 1. 检查 refresh_ttl >= cache_refresh_min_ttl（默认5秒）
    /// 2. 使用与正常请求相同的 Singleflight 机制（inflight map）
    /// 3. 刷新失败不会删除现有缓存条目
    pub(crate) fn spawn_background_refresh(
        &self,
        state: Arc<EngineInner>,
        cache_hash: u64,
        pipeline_id: &str,
        qname: &str,
        qtype: hickory_proto::rr::RecordType,
        qclass: DNSClass,
        peer_ip: std::net::IpAddr,
    ) {
        crate::engine::refresh::spawn_background_refresh(
            self,
            state,
            cache_hash,
            pipeline_id,
            qname,
            qtype,
            qclass,
            peer_ip,
        )
    }

    /// Construct standard DNS query packet using hickory_proto
    /// 使用 hickory_proto 构造标准 DNS 查询包
    ///
    /// Design: Use hickory-proto to ensure RFC compliance
    /// 设计：使用 hickory-proto 确保 RFC 合规性
    /// - Generates valid TXID (not 0)
    /// - Sets proper flags (recursion desired)
    /// - Encodes QNAME correctly
    /// - 生成有效的 TXID（不是 0）
    /// - 设置正确的标志（需要递归）
    /// - 正确编码 QNAME
    pub(crate) fn construct_dns_packet(
        &self,
        qname: &str,
        qtype: hickory_proto::rr::RecordType,
        _qclass: DNSClass, // Currently defaults to IN class, parameter reserved for future use
    ) -> anyhow::Result<Bytes> {
        use hickory_proto::op::{Message, MessageType, Query};
        use hickory_proto::rr::Name;

        // Generate unique TXID (not 0!)
        // 生成唯一的 TXID（不是 0！）
        let tx_id = self.request_id_counter.fetch_add(1, Ordering::Relaxed) as u16;

        // Build DNS query message
        // 构建 DNS 查询消息
        // hickory-proto 0.26: Message::new() defaults RD=false (was true in 0.24).
        // Upstream queries MUST set RD=true for recursive resolution.
        // hickory-proto 0.26: Message::new() 默认 RD=false（0.24 中为 true）。
        // 上游查询必须设置 RD=true 以获得递归解析。
        let mut msg = Message::new(tx_id, MessageType::Query, hickory_proto::op::OpCode::Query);
        msg.metadata.recursion_desired = true;

        // Add question section
        // 添加问题部分
        let name = Name::from_str(qname)?;
        let query = Query::query(name.clone(), qtype);
        msg.add_query(query);

        // Serialize to bytes
        // 序列化为字节
        let bytes = msg.to_vec()?;

        Ok(Bytes::from(bytes))
    }
}

use super::phases;

#[cfg(test)]
#[allow(unnameable_test_items)]
mod tests {
    use super::*;
    use crate::config::{Action, GlobalSettings, MatchOperator};
    use crate::engine::response::*;
    use crate::engine::rules::*;
    use crate::matcher::RuntimeResponseMatcherWithOp;
    use hickory_proto::op::{Message, MessageType, OpCode, Query, UpdateMessage};
    use hickory_proto::rr::RecordType;
    use hickory_proto::rr::{RData, Record};
    use std::net::IpAddr;
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

    fn runtime_with_static_ip(ip: &str) -> RuntimePipelineConfig {
        let raw = serde_json::json!({
            "settings": {
                "default_upstream": "1.1.1.1:53",
                "min_ttl": 60
            },
            "pipelines": [{
                "id": "main",
                "rules": [{
                    "name": "static",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "static_ip_response", "ip": ip }]
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
        let old_key = Engine::calculate_cache_hash_for_dedupe(
            original_namespace,
            "main",
            b"example.com",
            RecordType::A,
            DNSClass::IN,
            None,
        );
        engine.insert_dns_cache_entry(
            old_key,
            CacheEntry::from_response(
                Bytes::from_static(b"cached response"),
                ResponseCode::NoError,
                Some(Arc::from("8.8.8.8:53")),
                "example.com",
                Arc::from("main"),
                u16::from(RecordType::A),
                (60, 60),
            ),
        );

        engine.reload(original);
        assert_eq!(
            original_namespace,
            engine.state.load().cache_namespace("main"),
            "an unchanged pipeline should retain its cache namespace"
        );
        assert!(engine.cache_get(&old_key).is_some());

        engine.reload(runtime_with_upstream("8.8.4.4:53"));
        let changed_namespace = engine.state.load().cache_namespace("main");
        assert_ne!(
            original_namespace, changed_namespace,
            "a changed pipeline must stop addressing entries from the old configuration"
        );

        let new_key = Engine::calculate_cache_hash_for_dedupe(
            changed_namespace,
            "main",
            b"example.com",
            RecordType::A,
            DNSClass::IN,
            None,
        );
        assert_ne!(old_key, new_key);
        assert!(
            engine.cache_get(&new_key).is_none(),
            "the changed pipeline must not address the previous response cache entry"
        );
    }

    #[tokio::test]
    async fn request_snapshot_cannot_write_into_the_active_generation_after_reload() {
        let engine = Engine::new(runtime_with_static_ip("192.0.2.1"), "test".to_string())
            .expect("create engine");
        let old_state = engine.state.load_full();
        let old_namespace = old_state.cache_namespace("main");
        let old_key = Engine::calculate_cache_hash_for_dedupe(
            old_namespace,
            "main",
            b"example.com",
            RecordType::A,
            DNSClass::IN,
            None,
        );

        engine.reload(runtime_with_static_ip("192.0.2.2"));
        let new_namespace = engine.state.load().cache_namespace("main");
        let new_key = Engine::calculate_cache_hash_for_dedupe(
            new_namespace,
            "main",
            b"example.com",
            RecordType::A,
            DNSClass::IN,
            None,
        );

        let mut request = Message::new(0xCAFE, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(
            Name::from_str("example.com").unwrap(),
            RecordType::A,
        ));
        let response = engine
            .handle_packet_internal(
                &request.to_vec().unwrap(),
                "127.0.0.1:53000".parse().unwrap(),
                true,
                None,
                Some(old_key),
                Some(old_state),
            )
            .await
            .expect("complete request from old snapshot");
        let response = Message::from_bytes(&response).expect("parse response");

        assert!(matches!(
            response.answers.first().map(|record| &record.data),
            Some(RData::A(address)) if address.0 == "192.0.2.1".parse::<std::net::Ipv4Addr>().unwrap()
        ));
        assert!(engine.cache_get(&old_key).is_some());
        assert!(
            engine.cache_get(&new_key).is_none(),
            "work from the old snapshot must not populate the active generation"
        );
    }

    /// Minimal UDP upstream that echoes each query back as a NOERROR response
    /// with a single A record, so the forward path completes without network
    /// access. / 最小 UDP 上游：把查询回显为带一条 A 记录的 NOERROR 响应。
    async fn spawn_echo_upstream() -> String {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                let query = match Message::from_bytes(&buf[..n]) {
                    Ok(q) => q,
                    Err(_) => continue,
                };
                let Some(question) = query.queries.first().cloned() else {
                    continue;
                };
                let mut resp = Message::new(query.id(), MessageType::Response, OpCode::Query);
                resp.add_query(question.clone());
                resp.add_answer(Record::from_rdata(
                    question.name().clone(),
                    300,
                    RData::A(hickory_proto::rr::rdata::A(std::net::Ipv4Addr::LOCALHOST)),
                ));
                let _ = sock.send_to(&resp.to_vec().unwrap(), peer).await;
            }
        });
        addr
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

    #[tokio::test]
    async fn response_jump_writes_only_into_its_own_generation() {
        let upstream = spawn_echo_upstream().await;
        let engine =
            Engine::new(jump_config(&upstream, "192.0.2.1"), "test".to_string()).expect("engine");
        let old_state = engine.state.load_full();
        let old_target_key = Engine::calculate_cache_hash_for_dedupe(
            old_state.cache_namespace("target"),
            "target",
            b"example.com",
            RecordType::A,
            DNSClass::IN,
            None,
        );

        // Reload changes only the jump target, so "target" rotates its
        // namespace while the entry pipeline stays warm.
        engine.reload(jump_config(&upstream, "192.0.2.2"));
        let new_state = engine.state.load_full();
        let new_target_key = Engine::calculate_cache_hash_for_dedupe(
            new_state.cache_namespace("target"),
            "target",
            b"example.com",
            RecordType::A,
            DNSClass::IN,
            None,
        );

        let mut request = Message::new(0xBEEF, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(
            Name::from_str("example.com").unwrap(),
            RecordType::A,
        ));
        // No explicit cache hash: the jump-path key must be recomputed from
        // the request snapshot, exercising the phases.rs threading.
        let response = engine
            .handle_packet_internal(
                &request.to_vec().unwrap(),
                "127.0.0.1:53000".parse().unwrap(),
                false,
                None,
                None,
                Some(old_state),
            )
            .await
            .expect("complete forwarded request with response jump");
        let response = Message::from_bytes(&response).expect("parse response");

        // The jump must execute the target pipeline of the request snapshot
        // (192.0.2.1), not the reloaded one (192.0.2.2).
        assert!(matches!(
            response.answers.first().map(|record| &record.data),
            Some(RData::A(address)) if address.0 == "192.0.2.1".parse::<std::net::Ipv4Addr>().unwrap()
        ));
        assert!(
            engine.cache_get(&old_target_key).is_some(),
            "the response jump must cache under the snapshot generation's key"
        );
        assert!(
            engine.cache_get(&new_target_key).is_none(),
            "the response jump must not populate the active generation"
        );
    }

    /// 用一条 A 记录 `answer` 回应每个查询的本机 UDP 上游，并数收到了多少个查询。
    /// A local UDP upstream that answers every query with one A record `answer`,
    /// counting the queries it receives.
    async fn spawn_answering_upstream(
        answer: std::net::Ipv4Addr,
    ) -> (String, Arc<std::sync::atomic::AtomicUsize>) {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap().to_string();
        let queries = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = queries.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                let Ok(query) = Message::from_bytes(&buf[..n]) else {
                    continue;
                };
                let Some(question) = query.queries.first().cloned() else {
                    continue;
                };
                counted.fetch_add(1, Ordering::Relaxed);
                let mut resp = Message::new(query.id(), MessageType::Response, OpCode::Query);
                resp.add_query(question.clone());
                resp.add_answer(Record::from_rdata(
                    question.name().clone(),
                    300,
                    RData::A(hickory_proto::rr::rdata::A(answer)),
                ));
                let _ = sock.send_to(&resp.to_vec().unwrap(), peer).await;
            }
        });
        (addr, queries)
    }

    /// 只收不答的本机 UDP 上游，数收到了多少个数据包。
    /// A local UDP upstream that never answers, counting the datagrams it receives.
    async fn spawn_silent_upstream() -> (String, Arc<std::sync::atomic::AtomicUsize>) {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap().to_string();
        let datagrams = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = datagrams.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while sock.recv_from(&mut buf).await.is_ok() {
                counted.fetch_add(1, Ordering::Relaxed);
            }
        });
        (addr, datagrams)
    }

    fn continue_config(
        pipeline_select: serde_json::Value,
        pipelines: serde_json::Value,
    ) -> RuntimePipelineConfig {
        let raw = serde_json::json!({
            "settings": {
                "default_upstream": "127.0.0.1:9",
                "upstream_timeout_ms": 100,
                "enable_tcp_fallback": false
            },
            "pipeline_select": pipeline_select,
            "pipelines": pipelines
        });
        let config: crate::config::PipelineConfig =
            serde_json::from_value(raw).expect("parse config");
        RuntimePipelineConfig::from_config(config).expect("build runtime config")
    }

    fn example_query() -> Vec<u8> {
        let mut request = Message::new(0xBEEF, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(
            Name::from_str("example.com").unwrap(),
            RecordType::A,
        ));
        request.to_vec().unwrap()
    }

    fn first_a_record(response: anyhow::Result<Bytes>) -> Option<std::net::Ipv4Addr> {
        let response = Message::from_bytes(&response.expect("answer")).expect("parse");
        match response.answers.first().map(|record| &record.data) {
            Some(RData::A(address)) => Some(address.0),
            _ => None,
        }
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
            tokio::join!(
                engine.handle_packet(&packet, first),
                engine.handle_packet(&packet, second)
            )
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
    fn continue_on_miss_to(first_upstream: &str, next: serde_json::Value) -> RuntimePipelineConfig {
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
        let (alone, sent_alone) = spawn_silent_upstream().await;
        let engine = Engine::new(
            continue_on_miss_to(&alone, next.clone()),
            "test".to_string(),
        )
        .expect("engine");
        tokio::time::timeout(
            Duration::from_secs(5),
            engine.handle_packet(&example_query(), ONE_CLIENT[0].parse().unwrap()),
        )
        .await
        .expect("a request after a continue must not hang")
        .expect("answer");

        let (silent, sent) = spawn_silent_upstream().await;
        let engine =
            Engine::new(continue_on_miss_to(&silent, next), "test".to_string()).expect("engine");
        let answers = ask_at_once(&engine, ONE_CLIENT).await;
        (
            sent_alone.load(Ordering::Relaxed),
            sent.load(Ordering::Relaxed),
            answers,
        )
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
        let (answering, _) = spawn_answering_upstream(answer).await;
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
        let (silent, _) = spawn_silent_upstream().await;
        let engine = Engine::new(
            continue_on_miss_to(
                &silent,
                serde_json::json!({
                    "name": "next",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "forward", "upstream": silent }]
                }),
            ),
            "test".to_string(),
        )
        .expect("engine");

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
        let (checked, _) = spawn_answering_upstream("192.0.2.10".parse().unwrap()).await;
        let answer = "192.0.2.20".parse().unwrap();
        let (answering, _) = spawn_answering_upstream(answer).await;
        let engine = Engine::new(
            continue_config(
                serde_json::json!([]),
                serde_json::json!([{
                    "id": "main",
                    "rules": continue_on_match_rules(&checked, serde_json::json!([{
                        "name": "next",
                        "matchers": [{ "type": "any" }],
                        "actions": [{ "type": "forward", "upstream": answering }]
                    }]))
                }]),
            ),
            "test".to_string(),
        )
        .expect("engine");

        assert_eq!(ask_at_once(&engine, ONE_CLIENT).await, [Some(answer); 2]);
    }

    /// 按客户端匹配的 pipeline 在 continue 之后给出的静态应答只属于那个客户端（例如
    /// 只对某台设备屏蔽），不能交给等在它上面的另一个客户端。
    /// A static answer a client-matching pipeline gives after a continue belongs to
    /// that client alone (such as blocking one device) and must not reach another
    /// client waiting on it.
    #[tokio::test]
    async fn a_client_specific_static_answer_is_not_handed_to_another_client() {
        let (checked, _) = spawn_answering_upstream("192.0.2.10".parse().unwrap()).await;
        let answer = "192.0.2.20".parse().unwrap();
        let (answering, _) = spawn_answering_upstream(answer).await;
        let engine = Engine::new(
            continue_config(
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
            ),
            "test".to_string(),
        )
        .expect("engine");

        let blocked = std::net::Ipv4Addr::UNSPECIFIED;
        assert_eq!(
            ask_at_once(&engine, ["10.0.0.1:53000", "10.0.0.2:53000"]).await,
            [Some(blocked), Some(answer)]
        );
    }

    /// 两个 pipeline 都在 continue 之后按客户端跳进对方。持有条目的请求如果还会去等
    /// 别人，两个请求就各自持有对方在等的条目，互相等到监听器超时。
    /// Two pipelines that each continue and then jump into the other by client. If
    /// a request holding an entry still waited on others, each request would hold
    /// what the other waits on, and both would wait until the listener timeout.
    #[tokio::test]
    async fn requests_holding_entries_never_wait_on_each_other() {
        let (checked, _) = spawn_answering_upstream("192.0.2.10".parse().unwrap()).await;
        let answer = "192.0.2.20".parse().unwrap();
        let (answering, _) = spawn_answering_upstream(answer).await;
        let pipeline = |id: &str, client: &str, other: &str| {
            serde_json::json!({
                "id": id,
                "rules": continue_on_match_rules(&checked, serde_json::json!([
                    {
                        "name": "cross",
                        "matchers": [{ "type": "client_ip", "cidr": client }],
                        "actions": [{ "type": "jump_to_pipeline", "pipeline": other }]
                    },
                    {
                        "name": "next",
                        "matchers": [{ "type": "any" }],
                        "actions": [{ "type": "forward", "upstream": answering }]
                    }
                ]))
            })
        };
        let engine = Engine::new(
            continue_config(
                serde_json::json!([
                    { "pipeline": "p1", "matchers": [{ "type": "client_ip", "cidr": "10.0.0.1/32" }] },
                    { "pipeline": "p2", "matchers": [{ "type": "client_ip", "cidr": "10.0.0.2/32" }] }
                ]),
                serde_json::json!([
                    pipeline("p1", "10.0.0.1/32", "p2"),
                    pipeline("p2", "10.0.0.2/32", "p1")
                ]),
            ),
            "test".to_string(),
        )
        .expect("engine");

        assert_eq!(
            ask_at_once(&engine, ["10.0.0.1:53000", "10.0.0.2:53000"]).await,
            [Some(answer); 2]
        );
    }

    // ========================================================================
    // Engine Helper Functions Unit Tests / 引擎辅助函数单元测试
    // ========================================================================

    #[test]
    fn test_engine_helpers_build_servfail_response() {
        // Arrange: Create test request
        let mut req = Message::new(12345, hickory_proto::op::MessageType::Query, OpCode::Query);
        req.metadata.recursion_desired = true;
        let query = Query::query(Name::from_str("example.com").unwrap(), RecordType::A);
        req.add_query(query);

        // Act: Build ServFail response
        let result = engine_helpers::build_servfail_response(&req);

        // Assert: Verify response
        assert!(
            result.is_ok(),
            "Should successfully build ServFail response"
        );
        let bytes = result.unwrap();
        assert!(!bytes.is_empty(), "Response should not be empty");

        // Verify it's a valid DNS message
        let msg = Message::from_bytes(&bytes).unwrap();
        assert_eq!(msg.metadata.id, 12345, "TXID should be preserved");
        assert_eq!(
            msg.metadata.response_code,
            ResponseCode::ServFail,
            "Should be ServFail"
        );
        assert_eq!(
            msg.metadata.op_code,
            OpCode::Query,
            "Should be Query opcode"
        );
        assert!(
            msg.metadata.recursion_desired,
            "RD flag should be preserved"
        );
        assert_eq!(msg.queries.len(), 1, "Should have one query");
    }

    #[test]
    fn test_engine_helpers_build_servfail_response_from_wire() {
        let mut req = Message::new(0xBEEF, MessageType::Query, OpCode::Query);
        req.metadata.recursion_desired = true;
        req.add_query(Query::query(
            Name::from_str("data.xiaoheihe.cn").unwrap(),
            RecordType::AAAA,
        ));
        let request = req.to_vec().unwrap();

        let response = engine_helpers::build_servfail_response_from_wire(&request);
        let decoded = Message::from_bytes(&response).unwrap();

        assert_eq!(decoded.metadata.id, 0xBEEF);
        assert_eq!(decoded.metadata.response_code, ResponseCode::ServFail);
        assert!(decoded.metadata.recursion_desired);
        assert!(decoded.metadata.recursion_available);
        assert_eq!(decoded.queries.len(), 1);
        assert_eq!(decoded.queries[0].name().to_utf8(), "data.xiaoheihe.cn.");
        assert_eq!(decoded.queries[0].query_type(), RecordType::AAAA);
    }

    #[test]
    fn test_engine_helpers_build_servfail_response_from_malformed_wire() {
        let response = engine_helpers::build_servfail_response_from_wire(&[0x12, 0x34, 0x01, 0x10]);

        assert_eq!(response.len(), 12);
        assert_eq!(&response[..2], &[0x12, 0x34]);
        assert_ne!(response[2] & 0x80, 0, "QR must be set");
        assert_ne!(response[3] & 0x80, 0, "RA must be set");
        assert_eq!(response[3] & 0x0F, 2, "RCODE must be SERVFAIL");
        assert_ne!(response[2] & 0x01, 0, "RD must be preserved");
        assert_ne!(response[3] & 0x10, 0, "CD must be preserved");
    }

    #[test]
    fn test_listener_servfail_rejects_non_queries_and_malformed_packets() {
        assert!(engine_helpers::try_build_servfail_response_from_wire(&[0x12, 0x34]).is_none());

        let mut no_question = vec![0u8; 12];
        no_question[..2].copy_from_slice(&0x1234u16.to_be_bytes());
        assert!(
            engine_helpers::try_build_servfail_response_from_wire(&no_question).is_none(),
            "QDCOUNT=0 must not receive a response"
        );

        let mut response_packet = vec![0u8; 12];
        response_packet[2] = 0x80;
        response_packet[5] = 1;
        response_packet.extend_from_slice(&[0, 0, 1, 0, 1]);
        assert!(
            engine_helpers::try_build_servfail_response_from_wire(&response_packet).is_none(),
            "QR=1 packets must not receive a response"
        );

        let mut invalid_name = vec![0u8; 12];
        invalid_name[5] = 1;
        invalid_name.extend_from_slice(&[0x3f, b'a', 0, 0, 1, 0, 1]);
        assert!(
            engine_helpers::try_build_servfail_response_from_wire(&invalid_name).is_none(),
            "malformed names must not receive a response"
        );
    }

    #[test]
    fn test_engine_helpers_build_refused_response() {
        // Arrange: Create test request
        let mut req = Message::new(54321, MessageType::Query, OpCode::Query);
        let query = Query::query(Name::from_str("example.com").unwrap(), RecordType::A);
        req.add_query(query);

        // Act: Build Refused response
        let result = engine_helpers::build_refused_response(&req);

        // Assert: Verify response
        assert!(result.is_ok(), "Should successfully build Refused response");
        let bytes = result.unwrap();
        assert!(!bytes.is_empty(), "Response should not be empty");

        // Verify it's a valid DNS message
        let msg = Message::from_bytes(&bytes).unwrap();
        assert_eq!(msg.metadata.id, 54321, "TXID should be preserved");
        assert_eq!(
            msg.metadata.response_code,
            ResponseCode::Refused,
            "Should be Refused"
        );
        assert_eq!(msg.queries.len(), 1, "Should have one query");
    }

    #[test]
    fn test_engine_helpers_build_servfail_vs_refused_different() {
        // Arrange: Create test request
        let mut req = Message::new(11111, MessageType::Query, OpCode::Query);
        let query = Query::query(Name::from_str("test.com").unwrap(), RecordType::A);
        req.add_query(query);

        // Act: Build both response types
        let servfail = engine_helpers::build_servfail_response(&req).unwrap();
        let refused = engine_helpers::build_refused_response(&req).unwrap();

        // Assert: Should produce different responses
        assert_ne!(
            servfail, refused,
            "ServFail and Refused should be different"
        );

        // Verify different response codes
        let sf_msg = Message::from_bytes(&servfail).unwrap();
        let ref_msg = Message::from_bytes(&refused).unwrap();
        assert_eq!(sf_msg.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(ref_msg.metadata.response_code, ResponseCode::Refused);
    }

    // ========================================================================
    // Original Engine Tests / 原有引擎测试
    // ========================================================================
    use crate::matcher::RuntimeResponseMatcher;
    use std::net::Ipv4Addr;
    use tokio::time::Duration;

    #[test]
    fn make_static_ip_answer_returns_ipv4_record() {
        // Arrange: Define test domain and IPv4 address
        let domain = "example.com";
        let ipv4 = "1.2.3.4";

        // Act: Generate static IP answer
        let (rcode, answers) = make_static_ip_answer(domain, RecordType::A, ipv4);

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
        let (rcode, answers) = make_static_ip_answer(domain, RecordType::AAAA, ipv6);

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

        let (a_rcode, a_answers) = make_static_ip_answer("example.com", RecordType::A, ips);
        assert_eq!(a_rcode, ResponseCode::NoError);
        assert_eq!(a_answers.len(), 2);
        assert!(
            a_answers
                .iter()
                .all(|answer| answer.record_type() == RecordType::A)
        );

        let (aaaa_rcode, aaaa_answers) =
            make_static_ip_answer("example.com", RecordType::AAAA, ips);
        assert_eq!(aaaa_rcode, ResponseCode::NoError);
        assert_eq!(aaaa_answers.len(), 1);
        assert_eq!(aaaa_answers[0].record_type(), RecordType::AAAA);
    }

    #[test]
    fn make_static_ip_answer_returns_nodata_for_unconfigured_query_family() {
        let (rcode, answers) = make_static_ip_answer("example.com", RecordType::AAAA, "192.0.2.1");

        assert_eq!(rcode, ResponseCode::NoError);
        assert!(answers.is_empty());
    }

    #[test]
    fn make_static_ip_answer_returns_nodata_for_https_query() {
        let (rcode, answers) =
            make_static_ip_answer("example.com", RecordType::HTTPS, "192.0.2.1,2001:db8::1");

        assert_eq!(rcode, ResponseCode::NoError);
        assert!(answers.is_empty());
    }

    #[test]
    fn make_static_ip_answer_returns_both_families_for_any_query() {
        let (rcode, answers) =
            make_static_ip_answer("example.com", RecordType::ANY, "192.0.2.1,2001:db8::1");

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
            let (rcode, answers) = make_static_ip_answer("example.com", RecordType::A, ips);
            assert_eq!(rcode, ResponseCode::ServFail, "input: {ips:?}");
            assert!(answers.is_empty(), "input: {ips:?}");
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
        let cfg: crate::config::PipelineConfig = serde_json::from_value(raw).expect("parse config");
        let runtime = RuntimePipelineConfig::from_config(cfg).expect("runtime config");
        let engine = Engine::new(runtime, "test".to_string()).expect("initialize engine");
        let peer = "127.0.0.1:53000".parse().unwrap();

        let assert_response = |qtype, expected_ips: &[IpAddr]| {
            let mut request = Message::new(0xCAFE, MessageType::Query, OpCode::Query);
            request.metadata.recursion_desired = true;
            request.add_query(Query::query(
                Name::from_str("www.example.com").unwrap(),
                qtype,
            ));

            let response = match engine
                .handle_packet_fast(&request.to_vec().unwrap(), peer)
                .expect("fast path")
            {
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
        let cfg: crate::config::PipelineConfig = serde_json::from_value(raw).expect("parse config");
        let runtime = RuntimePipelineConfig::from_config(cfg).expect("runtime config");
        let engine = Engine::new(runtime, "test".to_string()).expect("initialize engine");
        let peer = "127.0.0.1:53000".parse().unwrap();

        let mut request = Message::new(0xCAFE, MessageType::Query, OpCode::Query);
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(
            Name::from_str("alias.example").unwrap(),
            RecordType::A,
        ));

        let response = match engine
            .handle_packet_fast(&request.to_vec().unwrap(), peer)
            .expect("fast path")
        {
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
        let (opt, id) = select_pipeline(
            &runtime,
            &PipelineSelectionContext {
                qname: "any.example.com",
                client_ip: "127.0.0.1".parse().unwrap(),
                qclass: hickory_proto::rr::DNSClass::IN,
                edns_present: false,
                qtype: hickory_proto::rr::RecordType::A,
                listener_label: "edge",
                geosite_manager: None,
                geoip_manager: None,
            },
        );

        // Assert: Verify correct pipeline was selected
        assert!(opt.is_some(), "Should find matching pipeline");
        assert_eq!(
            id.as_ref(),
            "p2",
            "Should select p2 pipeline for edge listener"
        );
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
        let (opt, id) = select_pipeline(
            &runtime,
            &PipelineSelectionContext {
                qname: "example.com",
                client_ip: "127.0.0.1".parse().unwrap(),
                qclass: hickory_proto::rr::DNSClass::IN,
                edns_present: false,
                qtype: hickory_proto::rr::RecordType::A,
                listener_label: "edge",
                geosite_manager: None,
                geoip_manager: None,
            },
        );

        // Assert: Verify correct pipeline was selected
        assert!(opt.is_some(), "Should find matching pipeline");
        assert_eq!(
            id.as_ref(),
            "p2",
            "Should select p2 pipeline for edge listener"
        );
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
            &RuleEvaluationContext::new(
                "127.0.0.1".parse().unwrap(),
                "a.example.com",
                hickory_proto::rr::RecordType::A,
                hickory_proto::rr::DNSClass::IN,
                false,
                None,
                false, // skip_cache
            ),
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
            &RuleEvaluationContext::new(
                "127.0.0.1".parse().unwrap(),
                "x.example.com",
                hickory_proto::rr::RecordType::A,
                hickory_proto::rr::DNSClass::IN,
                false,
                None,
                false, // skip_cache
            ),
        );

        // Assert: Verify Forward action returns correct upstream and matchers
        match decision2 {
            Decision::Forward {
                upstream,
                response_matchers,
                response_matcher_operator,
                ..
            } => {
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
                    response_matcher_operator,
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
            &RuleEvaluationContext::new(
                "127.0.0.1".parse().unwrap(),
                "y.example.com",
                hickory_proto::rr::RecordType::A,
                hickory_proto::rr::DNSClass::IN,
                false,
                None,
                false, // skip_cache
            ),
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
            &RuleEvaluationContext::new(
                "127.0.0.1".parse().unwrap(),
                "z.example.com",
                hickory_proto::rr::RecordType::A,
                hickory_proto::rr::DNSClass::IN,
                false,
                None,
                false, // skip_cache
            ),
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

    fn build_test_engine() -> Engine {
        let runtime = RuntimePipelineConfig {
            settings: GlobalSettings {
                default_upstream: TEST_UPSTREAM.to_string(),
                ..Default::default()
            },
            pipeline_select: Vec::new(),
            pipelines: Vec::new(),
            pipeline_id_index: FxHashMap::default(),
        };
        Engine::new(runtime, "lbl".to_string()).expect("initialize test engine")
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
            transport: Transport::Udp,
        }
    }

    #[tokio::test]
    async fn response_actions_allow_returns_upstream_on_match() {
        // Arrange: Build test engine and response context
        let engine = build_test_engine();
        let ctx = build_response_context();
        let req = Message::new(0, MessageType::Query, OpCode::Query);
        let actions = [Action::Allow];
        let response_matchers = vec![RuntimeResponseMatcherWithOp {
            operator: MatchOperator::And,
            matcher: RuntimeResponseMatcher::ResponseType {
                value: RecordType::A,
            },
        }];
        let packet = [0u8];
        let client_ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Act: Apply response actions with Allow action
        let ctx = crate::engine::rules::ApplyResponseActionsContext {
            engine: &engine,
            actions: &actions,
            ctx_opt: Some(ctx),
            req: &req,
            packet: &packet,
            upstream_timeout: Duration::from_secs(1),
            response_matchers: &response_matchers,
            qname: "example.com",
            qtype: RecordType::A,
            qclass: DNSClass::IN,
            client_ip,
            upstream_default: TEST_UPSTREAM,
            pipeline_id: "pipeline",
            rule_name: "rule",
            remaining_jumps: 10,
        };
        let result = apply_response_actions(ctx)
            .await
            .expect("response actions allow should succeed");

        // Assert: Verify Allow action returns upstream result with match=true
        match result {
            ResponseActionResult::Upstream { ctx, resp_match } => {
                assert!(resp_match, "Allow action should match response type");
                assert_eq!(
                    ctx.upstream.as_ref(),
                    TEST_UPSTREAM,
                    "Allow should use test upstream"
                );
            }
            _ => panic!("expected upstream result"),
        }
    }

    #[tokio::test]
    async fn response_actions_continue_returns_continue_with_context() {
        // Arrange: Build test engine, response context, and Continue action
        let engine = build_test_engine();
        let ctx = build_response_context();
        let req = Message::new(0, MessageType::Query, OpCode::Query);
        let actions = [Action::Continue];
        let packet = [0u8];
        let client_ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Act: Apply response actions with Continue action
        let ctx = crate::engine::rules::ApplyResponseActionsContext {
            engine: &engine,
            actions: &actions,
            ctx_opt: Some(ctx),
            req: &req,
            packet: &packet,
            upstream_timeout: Duration::from_secs(1),
            response_matchers: &[],
            qname: "example.com",
            qtype: RecordType::A,
            qclass: DNSClass::IN,
            client_ip,
            upstream_default: TEST_UPSTREAM,
            pipeline_id: "pipeline",
            rule_name: "rule",
            remaining_jumps: 10,
        };
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
    async fn response_actions_allow_reports_miss_when_matchers_fail() {
        // Arrange: Build test engine and response context with non-matching response matcher
        let engine = build_test_engine();
        let ctx = build_response_context();
        let req = Message::new(0, MessageType::Query, OpCode::Query);
        let actions = [Action::Allow];
        let response_matchers = vec![RuntimeResponseMatcherWithOp {
            operator: MatchOperator::And,
            matcher: RuntimeResponseMatcher::ResponseType {
                value: RecordType::AAAA,
            },
        }];
        let packet = [0u8];
        let client_ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Act: Apply response actions with Allow action and non-matching matcher
        let ctx = crate::engine::rules::ApplyResponseActionsContext {
            engine: &engine,
            actions: &actions,
            ctx_opt: Some(ctx),
            req: &req,
            packet: &packet,
            upstream_timeout: Duration::from_secs(1),
            response_matchers: &response_matchers,
            qname: "example.com",
            qtype: RecordType::A,
            qclass: DNSClass::IN,
            client_ip,
            upstream_default: TEST_UPSTREAM,
            pipeline_id: "pipeline",
            rule_name: "rule",
            remaining_jumps: 10,
        };
        let result = apply_response_actions(ctx)
            .await
            .expect("response actions allow should succeed even on miss");

        // Assert: Verify Allow action reports match failure
        match result {
            ResponseActionResult::Upstream { resp_match, .. } => {
                assert!(!resp_match, "Allow should report matcher miss")
            }
            _ => panic!("expected upstream result"),
        }
    }

    #[tokio::test]
    async fn response_actions_deny_returns_refused() {
        // Arrange: Build test engine with Deny action
        let engine = build_test_engine();
        let req = Message::new(0, MessageType::Query, OpCode::Query);
        let actions = [Action::Deny];
        let response_matchers: Vec<RuntimeResponseMatcherWithOp> = Vec::new();
        let packet = [0u8];
        let client_ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Act: Apply response actions with Deny action
        let ctx = crate::engine::rules::ApplyResponseActionsContext {
            engine: &engine,
            actions: &actions,
            ctx_opt: None,
            req: &req,
            packet: &packet,
            upstream_timeout: Duration::from_secs(1),
            response_matchers: &response_matchers,
            qname: "example.com",
            qtype: RecordType::A,
            qclass: DNSClass::IN,
            client_ip,
            upstream_default: TEST_UPSTREAM,
            pipeline_id: "pipeline",
            rule_name: "rule",
            remaining_jumps: 10,
        };
        let result = apply_response_actions(ctx)
            .await
            .expect("response actions deny should return static");

        // Assert: Verify Deny action returns Refused response code
        match result {
            ResponseActionResult::Static { rcode, source, .. } => {
                assert_eq!(rcode, ResponseCode::Refused, "Deny should return Refused");
                assert_eq!(
                    source, "response_action",
                    "Source should be response_action"
                );
            }
            _ => panic!("expected static refused"),
        }
    }

    #[tokio::test]
    async fn response_actions_static_ip_filters_answers_by_query_type() {
        // Arrange: Build test engine with a multi-address static IP response action
        let engine = build_test_engine();
        let req = Message::new(0, MessageType::Query, OpCode::Query);
        let actions = [Action::StaticIpResponse {
            ip: "192.0.2.1,2001:db8::1,192.0.2.2".to_string(),
        }];
        let response_matchers: Vec<RuntimeResponseMatcherWithOp> = Vec::new();
        let packet = [0u8];
        let client_ip: IpAddr = "10.0.0.1".parse().unwrap();

        let run = |qtype: RecordType| {
            let ctx = crate::engine::rules::ApplyResponseActionsContext {
                engine: &engine,
                actions: &actions,
                ctx_opt: None,
                req: &req,
                packet: &packet,
                upstream_timeout: Duration::from_secs(1),
                response_matchers: &response_matchers,
                qname: "example.com",
                qtype,
                qclass: DNSClass::IN,
                client_ip,
                upstream_default: TEST_UPSTREAM,
                pipeline_id: "pipeline",
                rule_name: "rule",
                remaining_jumps: 10,
            };
            apply_response_actions(ctx)
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
        let mut req = Message::new(0xCAFE, MessageType::Query, OpCode::Query);
        req.add_query(Query::query(
            Name::from_str("alias.example").unwrap(),
            RecordType::A,
        ));
        let actions = [Action::StaticCnameResponse {
            target: "origin.example.".to_string(),
            ttl: Some(60),
        }];
        let response_matchers: Vec<RuntimeResponseMatcherWithOp> = Vec::new();
        let packet = req.to_vec().unwrap();
        let ctx = crate::engine::rules::ApplyResponseActionsContext {
            engine: &engine,
            actions: &actions,
            ctx_opt: None,
            req: &req,
            packet: &packet,
            upstream_timeout: Duration::from_secs(1),
            response_matchers: &response_matchers,
            qname: "alias.example",
            qtype: RecordType::A,
            qclass: DNSClass::IN,
            client_ip: "10.0.0.1".parse().unwrap(),
            upstream_default: TEST_UPSTREAM,
            pipeline_id: "pipeline",
            rule_name: "rule",
            remaining_jumps: 10,
        };

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

    #[tokio::test]
    async fn static_decision_skips_dns_cache_when_pipeline_uses_client_ip() {
        // Arrange: Build engine, request packet, and a static IP answer
        let engine = build_test_engine();
        let mut request = Message::new(0xBE, MessageType::Query, OpCode::Query);
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(
            Name::from_str("example.com").unwrap(),
            RecordType::A,
        ));
        let packet = request.to_vec().unwrap();
        let peer = "10.0.0.1:53000".parse().unwrap();
        let (rcode, answers) = make_static_ip_answer("example.com", RecordType::A, "192.0.2.1");

        // Act: uses_client_ip=true must NOT write into dns_cache (client isolation)
        let ctx = phases::StaticDecisionContext {
            packet: &packet,
            qname: "example.com",
            qtype: RecordType::A,
            pipeline_id: &Arc::from("p1"),
            dedupe_hash: 4242,
            min_ttl: Duration::from_secs(60),
            start: Instant::now(),
            peer: &peer,
            uses_client_ip: true,
        };
        phases::handle_static_decision(&engine, &ctx, rcode, answers.clone())
            .expect("static decision");

        // Assert: no dns_cache entry written
        assert!(
            engine.cache_get(&4242).is_none(),
            "static decision with client_ip matcher must not pollute dns_cache"
        );

        // Control: uses_client_ip=false DOES write into dns_cache
        let ctx_plain = phases::StaticDecisionContext {
            packet: &packet,
            qname: "example.com",
            qtype: RecordType::A,
            pipeline_id: &Arc::from("p1"),
            dedupe_hash: 4243,
            min_ttl: Duration::from_secs(60),
            start: Instant::now(),
            peer: &peer,
            uses_client_ip: false,
        };
        phases::handle_static_decision(&engine, &ctx_plain, rcode, answers)
            .expect("static decision");

        assert!(
            engine.cache_get(&4243).is_some(),
            "static decision without client_ip matcher should still be cached"
        );
    }

    #[test]
    fn test_calculate_rule_hash_respects_uses_client_ip() {
        // Arrange: Define test data with different IPs
        let pipeline_id = "test_p";
        let qname = "example.com";
        let qtype = RecordType::A;
        let qclass = DNSClass::IN;
        let ip1 = "1.2.3.4".parse::<IpAddr>().unwrap();
        let ip2 = "5.6.7.8".parse::<IpAddr>().unwrap();

        // Act & Assert: When uses_client_ip is false, both IPs should result in the same hash
        let h1_no_ip = calculate_rule_hash(0, pipeline_id, qname, qtype, qclass, ip1, false);
        let h2_no_ip = calculate_rule_hash(0, pipeline_id, qname, qtype, qclass, ip2, false);
        assert_eq!(h1_no_ip, h2_no_ip, "Hashes should match when IP is ignored");

        // Act & Assert: When uses_client_ip is true, different IPs should result in different hashes
        let h1_with_ip = calculate_rule_hash(0, pipeline_id, qname, qtype, qclass, ip1, true);
        let h2_with_ip = calculate_rule_hash(0, pipeline_id, qname, qtype, qclass, ip2, true);
        assert_ne!(
            h1_with_ip, h2_with_ip,
            "Hashes should differ when IP is included"
        );

        // Assert: Hash with IP should differ from hash without IP
        assert_ne!(
            h1_no_ip, h1_with_ip,
            "Hash with IP should differ from hash without IP"
        );
    }

    #[tokio::test]
    async fn test_cache_expiration_triggers_requery() {
        // Arrange: Build engine and insert expired cache entry
        let engine = build_test_engine();
        let pipeline_id = Arc::from("default");
        let qname = "expire.com";
        let qtype = RecordType::A;
        let qclass = DNSClass::IN;
        let dedupe_hash = Engine::calculate_cache_hash_for_dedupe(
            0,
            &pipeline_id,
            qname.as_bytes(),
            qtype,
            qclass,
            None,
        );

        // Insert an entry that expired 5 seconds ago
        let entry = CacheEntry {
            bytes: Bytes::from_static(b"old_resp"),
            rcode: ResponseCode::NoError,
            upstream: None,
            qname: Arc::from(qname),
            pipeline_id: pipeline_id.clone(),
            qtype: u16::from(qtype),
            inserted_at: Instant::now() - Duration::from_secs(10),
            original_ttl: 5, // Expired 5 seconds ago
            refresh_ttl: 5,
        };
        engine.cache.insert(dedupe_hash, Arc::new(entry));

        // Act: Create DNS query packet and check fast path
        let mut packet = vec![0u8; 12];
        packet[0] = 0xAA;
        packet[1] = 0xBB; // TXID
        packet[5] = 1; // QDCOUNT
        packet.extend_from_slice(b"\x06expire\x03com\x00\x00\x01\x00\x01");

        let peer = "127.0.0.1:12345".parse().unwrap();
        let fast_res = engine.handle_packet_fast(&packet, peer).unwrap();

        // Assert: Expired cache should NOT be served — should fall through to AsyncNeeded
        // (None means parse_quick failed; AsyncNeeded means "parsed OK, need upstream query")
        match &fast_res {
            Some(FastPathResponse::CacheHit { .. }) => {
                panic!("Expired cache entry should not be served as CacheHit");
            }
            Some(FastPathResponse::AsyncNeeded { .. }) => { /* correct: requery needed */ }
            Some(FastPathResponse::Direct(_)) => {
                panic!("Expired cache should not produce a Direct response");
            }
            None => {
                panic!(
                    "parse_quick should succeed for valid packet; expected AsyncNeeded, got None"
                );
            }
        }

        // Assert: Verify cache entry was invalidated (serve_stale disabled in build_test_engine)
        assert!(
            engine.cache.get(&dedupe_hash).is_none(),
            "Cache entry should be removed after expiration check"
        );
    }

    /// flow_control_initial_permits 曾在构造 Engine 时被下一行的天花板当场覆盖，
    /// 配置项完全不生效：开了流控的部署从天花板起步，而不是文档写的初始值。
    /// flow_control_initial_permits used to be overwritten by the ceiling on the
    /// very next line when the Engine was built, so the setting never applied and
    /// a flow-controlled deployment started at the ceiling instead of the
    /// documented initial value.
    #[tokio::test]
    async fn flow_control_starts_at_the_configured_initial_permits() {
        let engine = Engine::new(
            RuntimePipelineConfig {
                settings: GlobalSettings {
                    default_upstream: TEST_UPSTREAM.to_string(),
                    flow_control_enabled: true,
                    flow_control_min_permits: 100,
                    flow_control_initial_permits: 500,
                    flow_control_max_permits: 800,
                    ..Default::default()
                },
                pipeline_select: Vec::new(),
                pipelines: Vec::new(),
                pipeline_id_index: FxHashMap::default(),
            },
            "lbl".to_string(),
        )
        .expect("initialize engine");

        assert_eq!(
            engine.permit_manager.max_permits(),
            500,
            "the current limit must start at flow_control_initial_permits, not the ceiling"
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
        engine.reload(RuntimePipelineConfig {
            settings: GlobalSettings {
                // TEST-NET-1：可路由地发出去、永远没有应答
                // TEST-NET-1: the datagram leaves and nothing ever answers
                default_upstream: "192.0.2.1:53".to_string(),
                serve_stale: true,
                serve_stale_client_timeout_ms: CLIENT_WAIT_MS,
                upstream_timeout_ms: UPSTREAM_TIMEOUT_MS,
                ..Default::default()
            },
            pipeline_select: Vec::new(),
            pipelines: Vec::new(),
            pipeline_id_index: FxHashMap::default(),
        });

        let pipeline_id: Arc<str> = Arc::from("default");
        let qname = "stale.com";
        let dedupe_hash = Engine::calculate_cache_hash_for_dedupe(
            engine.state.load().cache_namespace(&pipeline_id),
            &pipeline_id,
            qname.as_bytes(),
            RecordType::A,
            DNSClass::IN,
            None,
        );
        engine.cache.insert(
            dedupe_hash,
            Arc::new(CacheEntry {
                bytes: Bytes::from_static(b"old_resp"),
                rcode: ResponseCode::NoError,
                upstream: None,
                qname: Arc::from(qname),
                pipeline_id: pipeline_id.clone(),
                qtype: u16::from(RecordType::A),
                inserted_at: Instant::now() - Duration::from_secs(10),
                original_ttl: 5,
                refresh_ttl: 5,
            }),
        );

        let mut packet = vec![0u8; 12];
        packet[0] = 0xAA;
        packet[1] = 0xBB;
        packet[5] = 1;
        packet.extend_from_slice(b"\x05stale\x03com\x00\x00\x01\x00\x01");
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
        engine.reload(RuntimePipelineConfig {
            settings: GlobalSettings {
                default_upstream: TEST_UPSTREAM.to_string(),
                serve_stale: true,
                ..Default::default()
            },
            pipeline_select: Vec::new(),
            pipelines: Vec::new(),
            pipeline_id_index: FxHashMap::default(),
        });

        let pipeline_id: Arc<str> = Arc::from("default");
        let qname = "stale.com";
        let dedupe_hash = Engine::calculate_cache_hash_for_dedupe(
            engine.state.load().cache_namespace(&pipeline_id),
            &pipeline_id,
            qname.as_bytes(),
            RecordType::A,
            DNSClass::IN,
            None,
        );
        engine.cache.insert(
            dedupe_hash,
            Arc::new(CacheEntry {
                bytes: Bytes::from_static(b"old_resp"),
                rcode: ResponseCode::NoError,
                upstream: None,
                qname: Arc::from(qname),
                pipeline_id: pipeline_id.clone(),
                qtype: u16::from(RecordType::A),
                inserted_at: Instant::now() - Duration::from_secs(10),
                original_ttl: 5,
                refresh_ttl: 5,
            }),
        );

        let mut packet = vec![0u8; 12];
        packet[0] = 0xAA;
        packet[1] = 0xBB;
        packet[5] = 1;
        packet.extend_from_slice(b"\x05stale\x03com\x00\x00\x01\x00\x01");
        let peer = "127.0.0.1:12345".parse().unwrap();
        engine
            .handle_packet_fast(&packet, peer)
            .expect("parse query");

        assert!(
            engine.cache.get(&dedupe_hash).is_some(),
            "serve_stale enabled by the reload must keep the expired entry"
        );
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
            RuntimePipelineConfig {
                settings: GlobalSettings {
                    default_upstream: DEAD_UPSTREAM.to_string(),
                    upstream_timeout_ms: 100,
                    serve_stale,
                    serve_stale_ttl_reset: true,
                    ..Default::default()
                },
                pipeline_select: Vec::new(),
                pipelines: Vec::new(),
                pipeline_id_index: FxHashMap::default(),
            },
            "lbl".to_string(),
        )
        .expect("initialize engine");

        let pipeline_id: Arc<str> = Arc::from("default");
        let dedupe_hash = Engine::calculate_cache_hash_for_dedupe(
            engine.state.load().cache_namespace(&pipeline_id),
            &pipeline_id,
            b"stale.com",
            RecordType::A,
            DNSClass::IN,
            None,
        );
        (engine, dedupe_hash)
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
            bytes: Bytes::from_static(b"old_resp"),
            rcode: ResponseCode::NoError,
            upstream: None,
            qname: Arc::from("stale.com"),
            pipeline_id: Arc::from(pipeline_id),
            qtype: u16::from(RecordType::A),
            inserted_at: Instant::now() - Duration::from_secs(10),
            original_ttl: 5,
            refresh_ttl: 5,
        })
    }

    /// 以后台刷新的身份处理 `stale.com` 查询，结果写入 `cache_hash`。
    /// Handle the `stale.com` query as a background refresh writing to `cache_hash`.
    async fn refresh(engine: &Engine, cache_hash: u64) -> anyhow::Result<Bytes> {
        let peer = "127.0.0.1:12345".parse().unwrap();
        engine
            .handle_packet_internal(&stale_com_query(), peer, true, None, Some(cache_hash), None)
            .await
    }

    fn assert_upstream_failure(err: &anyhow::Error) {
        assert!(
            err.downcast_ref::<crate::engine::upstream::UpstreamFailure>()
                .is_some(),
            "the refresh must get the upstream failure itself, got: {err:#}"
        );
    }

    /// 所有上游都失败时，后台刷新要把失败原样交回刷新任务，由它记录。以前刷新会拿
    /// 过期应答（或合成的 SERVFAIL）当成功返回：任务不告警，开着
    /// serve_stale_ttl_reset 时还会给一条没有任何客户端拿到的过期条目重新计时。
    /// When every upstream fails, a background refresh must hand the failure back to
    /// the refresh task, which logs it. It used to return the stale answer (or a
    /// synthesized SERVFAIL) as a success: the task did not warn, and with
    /// serve_stale_ttl_reset it re-armed an entry no client was served.
    #[tokio::test]
    async fn a_failed_background_refresh_reports_the_failure_and_leaves_the_entry_alone() {
        let (engine, dedupe_hash) = engine_without_an_answering_upstream(true);
        let stale = stale_entry("default");
        engine.cache.insert(dedupe_hash, stale.clone());

        let err = refresh(&engine, dedupe_hash)
            .await
            .expect_err("a refresh whose upstreams all failed must not report success");

        assert_upstream_failure(&err);
        let cached = engine
            .cache
            .get(&dedupe_hash)
            .expect("a failed refresh must keep the stale entry");
        assert!(
            Arc::ptr_eq(&cached, &stale),
            "a refresh serves no client, so it must not re-arm the stale entry"
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
        let (tx, rx) = tokio::sync::watch::channel(Err(Arc::new(anyhow::anyhow!("Pending"))));
        engine.inflight.insert(dedupe_hash, tx);

        let result = refresh(&engine, dedupe_hash).await;

        assert!(
            result.is_err(),
            "a refresh whose upstreams all failed must fail"
        );
        assert!(
            engine.inflight.contains_key(&dedupe_hash),
            "the other request's inflight entry must stay registered"
        );
        assert!(
            matches!(rx.has_changed(), Ok(false)),
            "the other request's waiters must not receive anything from the refresh"
        );
    }

    /// 失败的刷新一结束就释放刷新标记。开着 serve_stale_client_timeout_ms 时，请求
    /// 要等下一次过期命中发起的刷新；标记一直占着，它们只能等到超时再拿过期应答。
    /// A failed refresh releases its mark as soon as it ends. With
    /// serve_stale_client_timeout_ms, requests wait for the refresh the next stale
    /// hit starts; a mark held on would leave them waiting out the timeout instead.
    #[tokio::test]
    async fn a_failed_background_refresh_releases_its_mark_when_it_ends() {
        let (engine, dedupe_hash) = engine_without_an_answering_upstream(false);
        let marked = || {
            is_refreshing(
                &engine.refreshing_bitmap,
                &engine.refreshing_set,
                dedupe_hash,
            )
        };
        engine.spawn_background_refresh(
            engine.state.load_full(),
            dedupe_hash,
            "default",
            "stale.com",
            RecordType::A,
            DNSClass::IN,
            "127.0.0.1".parse().unwrap(),
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
        engine.cache.insert(1, stale.clone());

        let err = refresh(&engine, 1)
            .await
            .expect_err("a refresh whose on-miss forward also failed must not report success");

        assert_upstream_failure(&err);
        let cached = engine
            .cache
            .get(&1)
            .expect("a failed refresh must keep the stale entry");
        assert!(
            Arc::ptr_eq(&cached, &stale),
            "a failed refresh must not cache SERVFAIL over the stale entry"
        );
    }

    #[test]
    fn test_rule_cache_entry_matches_respects_uses_client_ip() {
        // Arrange: Define test data with different IPs
        let pipeline_id: Arc<str> = Arc::from("test_p");
        let qname = "example.com";
        let qtype = RecordType::A;
        let qclass = DNSClass::IN;
        let ip1 = "1.2.3.4".parse::<IpAddr>().unwrap();
        let ip2 = "5.6.7.8".parse::<IpAddr>().unwrap();
        let decision = Arc::new(Decision::Static {
            rcode: ResponseCode::NoError,
            answers: vec![],
        });

        // Arrange: Entry created WITHOUT IP
        let entry_no_ip = RuleCacheEntry {
            pipeline_id: pipeline_id.clone(),
            qname_hash: fast_hash_str(qname),
            qtype: u16::from(qtype),
            qclass: u16::from(qclass),
            client_ip: None,
            decision: decision.clone(),
            expires_at: None,
        };

        // Act & Assert: Should match any IP if we don't care about it
        assert!(
            entry_no_ip.matches("test_p", qname, qtype, qclass, ip1, false),
            "Entry without IP should match any IP when uses_client_ip is false"
        );
        assert!(
            entry_no_ip.matches("test_p", qname, qtype, qclass, ip2, false),
            "Entry without IP should match any IP when uses_client_ip is false"
        );

        // Act & Assert: Should NOT match if we now care about IP (since entry doesn't have it)
        assert!(
            !entry_no_ip.matches("test_p", qname, qtype, qclass, ip1, true),
            "Entry without IP should not match when uses_client_ip is true"
        );

        // Arrange: Entry created WITH IP
        let entry_with_ip = RuleCacheEntry {
            pipeline_id: pipeline_id.clone(),
            qname_hash: fast_hash_str(qname),
            qtype: u16::from(qtype),
            qclass: u16::from(qclass),
            client_ip: Some(ip1),
            decision,
            expires_at: None,
        };

        // Act & Assert: Should match same IP if we care
        assert!(
            entry_with_ip.matches("test_p", qname, qtype, qclass, ip1, true),
            "Entry with IP should match same IP when uses_client_ip is true"
        );
        // Act & Assert: Should NOT match different IP if we care
        assert!(
            !entry_with_ip.matches("test_p", qname, qtype, qclass, ip2, true),
            "Entry with IP should not match different IP when uses_client_ip is true"
        );
        // Act & Assert: Should NOT match even same IP if we don't care now (safety check)
        assert!(
            !entry_with_ip.matches("test_p", qname, qtype, qclass, ip1, false),
            "Entry with IP should not match when uses_client_ip is false"
        );
    }

    #[test]
    fn test_rule_cache_expiration() {
        // Arrange: Define test data
        let pipeline_id: Arc<str> = Arc::from("test_p");
        let qname = "expire.com";
        let qtype = RecordType::A;
        let qclass = DNSClass::IN;
        let ip = "1.2.3.4".parse::<IpAddr>().unwrap();
        let decision = Arc::new(Decision::Static {
            rcode: ResponseCode::NoError,
            answers: vec![],
        });

        // Arrange: Expired entry
        let entry_expired = RuleCacheEntry {
            pipeline_id: pipeline_id.clone(),
            qname_hash: fast_hash_str(qname),
            qtype: u16::from(qtype),
            qclass: u16::from(qclass),
            client_ip: None,
            decision: decision.clone(),
            expires_at: Some(Instant::now() - Duration::from_secs(1)),
        };

        // Act & Assert: Expired entry should not match
        assert!(
            !entry_expired.matches("test_p", qname, qtype, qclass, ip, false),
            "Expired entry should not match"
        );

        // Arrange: Fresh entry
        let entry_fresh = RuleCacheEntry {
            pipeline_id: pipeline_id.clone(),
            qname_hash: fast_hash_str(qname),
            qtype: u16::from(qtype),
            qclass: u16::from(qclass),
            client_ip: None,
            decision,
            expires_at: Some(Instant::now() + Duration::from_secs(60)),
        };

        // Act & Assert: Fresh entry should match
        assert!(
            entry_fresh.matches("test_p", qname, qtype, qclass, ip, false),
            "Fresh entry should match"
        );
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
        let hash_in = Engine::calculate_cache_hash_for_dedupe(
            0,
            pipeline_id,
            qname.as_bytes(),
            qtype,
            qclass_in,
            None,
        );
        let hash_ch = Engine::calculate_cache_hash_for_dedupe(
            0,
            pipeline_id,
            qname.as_bytes(),
            qtype,
            qclass_ch,
            None,
        );

        // Assert: Verify different QCLASS produces different hashes
        assert_ne!(
            hash_in, hash_ch,
            "Different QCLASS should produce different cache hashes"
        );

        // Act: Calculate hash for same QCLASS to verify consistency
        let hash_in2 = Engine::calculate_cache_hash_for_dedupe(
            0,
            pipeline_id,
            qname.as_bytes(),
            qtype,
            qclass_in,
            None,
        );

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
        let hash1 = Engine::calculate_cache_hash_for_dedupe(
            0,
            pipeline_id,
            qname_lower.to_lowercase().as_bytes(),
            qtype,
            qclass,
            None,
        );
        let hash2 = Engine::calculate_cache_hash_for_dedupe(
            0,
            pipeline_id,
            qname_upper.to_lowercase().as_bytes(),
            qtype,
            qclass,
            None,
        );
        let hash3 = Engine::calculate_cache_hash_for_dedupe(
            0,
            pipeline_id,
            qname_mixed.to_lowercase().as_bytes(),
            qtype,
            qclass,
            None,
        );

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
        let hash_a = Engine::calculate_cache_hash_for_dedupe(
            0,
            pipeline_id,
            qname.as_bytes(),
            qtype_a,
            qclass,
            None,
        );
        let hash_aaaa = Engine::calculate_cache_hash_for_dedupe(
            0,
            pipeline_id,
            qname.as_bytes(),
            qtype_aaaa,
            qclass,
            None,
        );

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
        let hash1 = Engine::calculate_cache_hash_for_dedupe(
            0,
            pipeline_id,
            qname1.as_bytes(),
            qtype,
            qclass,
            None,
        );
        let hash2 = Engine::calculate_cache_hash_for_dedupe(
            0,
            pipeline_id,
            qname2.as_bytes(),
            qtype,
            qclass,
            None,
        );

        // Assert: Verify different QNAME produces different hashes
        assert_ne!(
            hash1, hash2,
            "Different QNAME should produce different cache hashes"
        );
    }

    /// 测试 fast_static_match 不会跳过不可预计算的规则
    ///
    /// 这是一个回归测试，用于验证以下场景：
    /// - 规则1：domain_regex("^_acme") → forward（不可预计算）
    /// - 规则2：domain_suffix("mydomain.com") → static_ip（可预计算）
    /// - 查询：_acme-challenge.mydomain.com
    ///
    /// 预期行为：第一条规则应该生效（forward），而不是第二条规则（static_ip）
    ///
    /// 修复前：fast_static_match 会跳过不可预计算的规则，直接返回可预计算的规则结果
    /// 修复后：fast_static_match 在遇到第一个匹配但不可预计算的规则时放弃快速路径
    #[test]
    fn test_fast_static_match_preserves_rule_order() {
        use crate::matcher::advanced_rule::{compile_pipelines, fast_static_match};

        // Arrange: 构建一个配置，模拟用户的问题场景
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
        let compiled = compile_pipelines(&runtime);

        // Act: 调用 fast_static_match 查询 _acme-challenge.mydomain.com
        let result = fast_static_match(
            &compiled[0],
            "_acme-challenge.mydomain.com",
            hickory_proto::rr::RecordType::TXT,
            hickory_proto::rr::DNSClass::IN,
            "127.0.0.1".parse().unwrap(),
            false,
        );

        // Assert: fast_static_match 应该返回 None
        // 原因：第一条规则（domain_regex("^_acme")）匹配但不可预计算，
        // 所以 fast_static_match 应该放弃快速路径，让规则走正常路径
        assert!(
            result.is_none(),
            "fast_static_match 应该返回 None，因为第一个匹配的规则不可预计算"
        );

        // 验证：如果查询一个只匹配第二条规则的域名，应该返回静态 IP
        let result2 = fast_static_match(
            &compiled[0],
            "other.mydomain.com",
            hickory_proto::rr::RecordType::A,
            hickory_proto::rr::DNSClass::IN,
            "127.0.0.1".parse().unwrap(),
            false,
        );

        assert!(
            result2.is_some(),
            "fast_static_match 应该返回 Some，因为第一个匹配的规则可预计算"
        );

        // 验证返回的是静态 IP 决策
        match result2.unwrap() {
            Decision::Static { rcode, answers } => {
                assert_eq!(rcode, ResponseCode::NoError);
                assert!(!answers.is_empty(), "应该有静态 IP 答案");
            }
            _ => panic!("应该返回 Static 决策"),
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
    use hickory_proto::serialize::binary::BinDecodable;

    use crate::config::PipelineConfig;
    use crate::engine::Engine;
    use crate::matcher::RuntimePipelineConfig;

    /// UDP 上游：每个查询都答 `ip`（TTL 为 `ttl` 秒），并数一共收到几个查询
    /// UDP upstream that answers every query with `ip` (TTL `ttl` seconds) and counts the queries it receives
    async fn counting_upstream(ip: Ipv4Addr, ttl: u32) -> (String, Arc<AtomicUsize>) {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap().to_string();
        let queries = Arc::new(AtomicUsize::new(0));
        let counter = queries.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
                let Ok(request) = Message::from_bytes(&buf[..n]) else {
                    continue;
                };
                let Some(question) = request.queries.first().cloned() else {
                    continue;
                };
                counter.fetch_add(1, Ordering::SeqCst);
                let mut response =
                    Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
                response.add_query(question.clone());
                response.add_answer(Record::from_rdata(
                    question.name().clone(),
                    ttl,
                    RData::A(A(ip)),
                ));
                let _ = socket.send_to(&response.to_vec().unwrap(), peer).await;
            }
        });
        (addr, queries)
    }

    fn engine(raw: serde_json::Value) -> Engine {
        let config: PipelineConfig = serde_json::from_value(raw).expect("parse config");
        let runtime = RuntimePipelineConfig::from_config(config).expect("runtime config");
        Engine::new(runtime, "test".to_string()).expect("engine")
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
        let (upstream, queries) = counting_upstream(Ipv4Addr::new(192, 0, 2, 1), 300).await;
        let engine = engine(serde_json::json!({
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
                { "id": "group", "rules": [forward_rule("fwd", &upstream)] }
            ]
        }));

        for _ in 0..3 {
            assert_eq!(
                answer(&engine, "jumped.example", "192.0.2.10").await,
                Ipv4Addr::new(192, 0, 2, 1)
            );
        }
        assert_eq!(queries.load(Ordering::SeqCst), 1);
    }

    /// 入口按客户端地址跳到不同的目标时，每个目标的应答只给跳到它的请求：
    /// 两个客户端查同一个名字，各自拿到自己目标的地址，每个上游各收到一次。
    /// When the entry jumps to different targets by client address, each target's
    /// answer only serves requests that jumped to it: two clients asking for one name
    /// each get their own target's address, and each upstream is asked once.
    #[tokio::test]
    async fn cached_answers_stay_with_the_target_they_came_from() {
        let (first_upstream, first_queries) =
            counting_upstream(Ipv4Addr::new(192, 0, 2, 1), 300).await;
        let (second_upstream, second_queries) =
            counting_upstream(Ipv4Addr::new(192, 0, 2, 2), 300).await;
        let engine = engine(serde_json::json!({
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
                { "id": "first", "rules": [forward_rule("fwd", &first_upstream)] },
                { "id": "second", "rules": [forward_rule("fwd", &second_upstream)] }
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
        assert_eq!(first_queries.load(Ordering::SeqCst), 1);
        assert_eq!(second_queries.load(Ordering::SeqCst), 1);
    }

    /// continue 之后才遇到的跳转不查缓存，照常转发：那时请求已经越过了一个应答（可能被后面的
    /// 规则复用），查缓存提前返回会绕开这些。只有还没转发过的第一轮才查。两次查询来自两个客户端：
    /// 入口按客户端地址判断，规则缓存因此按客户端分开，两次都重新走 `try-first`。
    /// A jump reached only after a continue is not looked up in the cache and forwards
    /// as before: by then the request has passed over an answer (which later rules may
    /// reuse), and returning early from the cache would bypass that. Only the first
    /// pass, before anything was forwarded, looks up. The two queries come from two
    /// clients: the entry matches on client address, so the rule cache keeps them apart
    /// and both run `try-first` again.
    #[tokio::test]
    async fn a_jump_reached_after_a_continue_still_forwards() {
        let (first_upstream, first_queries) =
            counting_upstream(Ipv4Addr::new(192, 0, 2, 1), 300).await;
        let (group_upstream, group_queries) =
            counting_upstream(Ipv4Addr::new(192, 0, 2, 2), 300).await;
        let engine = engine(serde_json::json!({
            "settings": { "default_upstream": "127.0.0.1:9", "min_ttl": 0 },
            "pipelines": [
                {
                    "id": "main",
                    "rules": [
                        {
                            "name": "try-first",
                            "matchers": [{ "type": "client_ip", "cidr": "192.0.2.0/24" }],
                            "actions": [{ "type": "forward", "upstream": first_upstream, "transport": "udp" }],
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
                { "id": "group", "rules": [forward_rule("fwd", &group_upstream)] }
            ]
        }));

        for client in ["192.0.2.10", "192.0.2.11"] {
            assert_eq!(
                answer(&engine, "continued.example", client).await,
                Ipv4Addr::new(192, 0, 2, 2)
            );
        }
        assert_eq!(first_queries.load(Ordering::SeqCst), 2);
        assert_eq!(group_queries.load(Ordering::SeqCst), 2);
    }

    /// 同一个客户端重复查询也一样：continue 之后得出的决策不进规则缓存（olicesx/kixdns#70），
    /// 每次都从 `try-first` 开始，跳转发生在第二轮，照常转发。
    /// The same holds for one client asking again: a decision reached after a continue
    /// is not rule-cached (olicesx/kixdns#70), so every request starts at `try-first`,
    /// jumps on its second pass and forwards as before.
    #[tokio::test]
    async fn a_repeated_request_that_continues_still_forwards_after_the_jump() {
        let (first_upstream, first_queries) =
            counting_upstream(Ipv4Addr::new(192, 0, 2, 1), 300).await;
        let (group_upstream, group_queries) =
            counting_upstream(Ipv4Addr::new(192, 0, 2, 2), 300).await;
        let engine = engine(serde_json::json!({
            "settings": { "default_upstream": "127.0.0.1:9", "min_ttl": 0 },
            "pipelines": [
                {
                    "id": "main",
                    "rules": [
                        {
                            "name": "try-first",
                            "matchers": [{ "type": "any" }],
                            "actions": [{ "type": "forward", "upstream": first_upstream, "transport": "udp" }],
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
                { "id": "group", "rules": [forward_rule("fwd", &group_upstream)] }
            ]
        }));

        for _ in 0..2 {
            assert_eq!(
                answer(&engine, "continued.example", "192.0.2.10").await,
                Ipv4Addr::new(192, 0, 2, 2)
            );
        }
        assert_eq!(first_queries.load(Ordering::SeqCst), 2);
        assert_eq!(group_queries.load(Ordering::SeqCst), 2);
    }

    /// 目标 pipeline 按客户端判断时，跳转后不从缓存给应答：这个客户端该被拦下，
    /// 不能拿到另一个客户端转发回来、存在目标键下的应答。
    /// A target that matches on the client is not answered from the cache after a
    /// jump: a client that its rules block must not get the answer another client's
    /// forward stored under the target's key.
    #[tokio::test]
    async fn a_target_that_matches_on_the_client_is_not_served_from_the_cache() {
        let (upstream, _queries) = counting_upstream(Ipv4Addr::new(192, 0, 2, 1), 300).await;
        let engine = engine(serde_json::json!({
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
                        forward_rule("fwd", &upstream)
                    ]
                }
            ]
        }));

        assert_eq!(
            answer(&engine, "ads.example", "10.0.0.2").await,
            Ipv4Addr::new(192, 0, 2, 1)
        );
        assert_eq!(
            answer(&engine, "ads.example", "10.0.0.1").await,
            Ipv4Addr::UNSPECIFIED
        );
    }

    /// 路线上有按 EDNS 判断的 pipeline 时，跳转后不查缓存：后台刷新重放的请求不带 EDNS，
    /// 可能走另一条路线，把别处的应答写进目标的键。
    /// A route through a pipeline that matches on EDNS does not look in the cache after
    /// the jump: a background refresh replays the query without EDNS, may take another
    /// route and write another answer under the target's key.
    #[tokio::test]
    async fn a_route_through_an_edns_rule_is_not_looked_up_after_the_jump() {
        let (upstream, queries) = counting_upstream(Ipv4Addr::new(192, 0, 2, 1), 300).await;
        let engine = engine(serde_json::json!({
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
                { "id": "group", "rules": [forward_rule("fwd", &upstream)] }
            ]
        }));

        for _ in 0..3 {
            assert_eq!(
                answer(&engine, "edns.example", "192.0.2.10").await,
                Ipv4Addr::new(192, 0, 2, 1)
            );
        }
        assert_eq!(queries.load(Ordering::SeqCst), 3);
    }

    /// 跳转后找到的过期应答由后台刷新，刷新写回同一个目标键：之后的请求拿到新鲜应答，
    /// 不再去问上游，也不再拿过期应答。
    /// An expired answer found after a jump is refreshed in the background, and the
    /// refresh writes back under the same target key: the next request gets a fresh
    /// answer, with no further upstream query and no stale answer.
    #[tokio::test]
    async fn a_refresh_started_after_a_jump_renews_the_target_entry() {
        let (upstream, queries) = counting_upstream(Ipv4Addr::new(192, 0, 2, 1), 1).await;
        let engine = engine(serde_json::json!({
            "settings": {
                "default_upstream": "127.0.0.1:9",
                "min_ttl": 0,
                "serve_stale": true,
                "serve_stale_ttl": 30,
                "serve_stale_client_timeout_ms": 0
            },
            "pipelines": [
                {
                    "id": "main",
                    "rules": [{
                        "name": "to-group",
                        "matchers": [{ "type": "any" }],
                        "actions": [{ "type": "jump_to_pipeline", "pipeline": "group" }]
                    }]
                },
                { "id": "group", "rules": [forward_rule("fwd", &upstream)] }
            ]
        }));

        answer(&engine, "renew.example", "192.0.2.10").await;
        assert_eq!(queries.load(Ordering::SeqCst), 1);
        tokio::time::sleep(Duration::from_millis(1200)).await;

        // 过期：立刻给过期应答，后台刷新去问上游 / Expired: the stale answer goes out at once and a background refresh asks upstream
        answer(&engine, "renew.example", "192.0.2.10").await;
        let refreshed = tokio::time::timeout(Duration::from_secs(3), async {
            while queries.load(Ordering::SeqCst) < 2 {
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
        assert_eq!(queries.load(Ordering::SeqCst), 2);
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

    /// pipeline 的选择按 EDNS 判断时，跳转后也不查缓存：刷新重放的请求不带 EDNS，可能选到别的 pipeline。
    /// Selection that matches on EDNS also turns off the lookup after a jump: the refresh
    /// replays the query without EDNS and may select another pipeline.
    #[tokio::test]
    async fn edns_in_pipeline_selection_turns_off_the_lookup_after_a_jump() {
        let (upstream, queries) = counting_upstream(Ipv4Addr::new(192, 0, 2, 1), 300).await;
        let engine = engine(serde_json::json!({
            "settings": { "default_upstream": "127.0.0.1:9", "min_ttl": 0 },
            "pipeline_select": [{
                "pipeline": "main",
                "matchers": [{ "type": "edns_present", "expect": false }]
            }],
            "pipelines": jump_to_group(serde_json::json!([forward_rule("fwd", &upstream)]))
        }));

        for _ in 0..2 {
            answer(&engine, "selected.example", "192.0.2.10").await;
        }
        assert_eq!(queries.load(Ordering::SeqCst), 2);
    }

    /// 类别不是 IN 的查询跳转后不查缓存：刷新重放的请求固定是 IN，算出的是另一个键。
    /// A query in a class other than IN does not look after a jump: the refresh replays
    /// in class IN and computes another key.
    #[tokio::test]
    async fn a_query_outside_class_in_is_not_looked_up_after_a_jump() {
        let (upstream, queries) = counting_upstream(Ipv4Addr::new(192, 0, 2, 1), 300).await;
        let engine = engine(serde_json::json!({
            "settings": { "default_upstream": "127.0.0.1:9", "min_ttl": 0 },
            "pipelines": jump_to_group(serde_json::json!([forward_rule("fwd", &upstream)]))
        }));

        for _ in 0..2 {
            ask(&engine, "chaos.example", "192.0.2.10", DNSClass::CH).await;
        }
        assert_eq!(queries.load(Ordering::SeqCst), 2);
    }

    /// 目标的转发按客户端地址带 ECS 子网、缓存键却不分子网时，跳转后不查缓存：
    /// 按一个子网定制的应答不能给另一个子网的客户端。
    /// A target whose forward sends the client's ECS subnet, while its cache key does not
    /// carry the subnet, does not look after a jump: an answer tailored to one subnet must
    /// not go to a client in another.
    #[tokio::test]
    async fn a_target_forwarding_the_client_subnet_is_not_served_across_subnets() {
        let (upstream, queries) = counting_upstream(Ipv4Addr::new(192, 0, 2, 1), 300).await;
        let engine = engine(serde_json::json!({
            "settings": { "default_upstream": "127.0.0.1:9", "min_ttl": 0 },
            "pipelines": jump_to_group(serde_json::json!([{
                "name": "fwd",
                "matchers": [{ "type": "any" }],
                "actions": [{
                    "type": "forward",
                    "upstream": upstream,
                    "transport": "udp",
                    "ecs": { "mode": "from_client_ip" }
                }]
            }]))
        }));

        answer(&engine, "cdn.example", "198.51.100.10").await;
        answer(&engine, "cdn.example", "203.0.113.10").await;
        assert_eq!(queries.load(Ordering::SeqCst), 2);
    }

    /// 按「谁在问」判断的四种请求匹配会让 pipeline 带上标记，按问题本身判断的不会；
    /// 只有按 EDNS 判断的带上 `matches_edns`。
    /// The four request matchers that look at who is asking flag the pipeline, and
    /// those that look at the question do not; only the EDNS one sets `matches_edns`.
    #[test]
    fn pipelines_that_match_on_the_requester_are_flagged() {
        let forward = |ecs: serde_json::Value| {
            serde_json::json!({
                "name": "fwd",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": "127.0.0.1:9", "ecs": ecs }]
            })
        };
        let ecs_cases = [
            // 转发按客户端带子网，pipeline 级不按客户端区分 / A forward sends the client subnet; the pipeline level does not key by it
            (
                serde_json::json!({ "id": "p", "rules": [forward(serde_json::json!({ "mode": "from_client_ip" }))] }),
                true,
            ),
            // pipeline 级也按客户端子网区分缓存 / The pipeline level keys the cache by the client subnet too
            (
                serde_json::json!({
                    "id": "p",
                    "ecs": { "mode": "from_client_ip" },
                    "rules": [forward(serde_json::json!({ "mode": "from_client_ip" }))]
                }),
                false,
            ),
            // pipeline 级按客户端区分，但前缀比转发的短：按 /24 定制的应答在整个 /16 里共用
            // The pipeline level keys by the client, but with a shorter prefix than the forward:
            // answers tailored per /24 would be shared across the whole /16
            (
                serde_json::json!({
                    "id": "p",
                    "ecs": { "mode": "from_client_ip", "prefix_v4": 16 },
                    "rules": [forward(serde_json::json!({ "mode": "from_client_ip" }))]
                }),
                true,
            ),
            // 固定子网与客户端无关 / A fixed subnet does not depend on the client
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
                runtime.pipelines[0].depends_on_requester, requester,
                "{pipeline}"
            );
        }

        let cases = [
            (
                serde_json::json!({ "type": "client_ip", "cidr": "10.0.0.0/8" }),
                true,
                false,
            ),
            (
                serde_json::json!({ "type": "geoip_country", "country_codes": ["cn"] }),
                true,
                false,
            ),
            (
                serde_json::json!({ "type": "geoip_private", "expect": true }),
                true,
                false,
            ),
            (
                serde_json::json!({ "type": "edns_present", "expect": true }),
                true,
                true,
            ),
            (
                serde_json::json!({ "type": "domain_suffix", "value": "example.com" }),
                false,
                false,
            ),
            (
                serde_json::json!({ "type": "qtype", "value": "A" }),
                false,
                false,
            ),
            (serde_json::json!({ "type": "any" }), false, false),
        ];
        for (matcher, requester, edns) in cases {
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
            assert_eq!(pipeline.depends_on_requester, requester, "{matcher}");
            assert_eq!(pipeline.matches_edns, edns, "{matcher}");
        }
    }
}
