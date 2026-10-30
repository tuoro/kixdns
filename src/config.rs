use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use anyhow::Result;
use ipnet::IpNet;
use serde::Deserialize;

use crate::matcher::RuntimePipelineConfig;
use tracing::{info, warn};

#[derive(Debug, Clone, Deserialize)]
pub struct PipelineConfig {
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub settings: GlobalSettings,
    /// 多维优先级的 pipeline 选择规则（按顺序评估）。 / Multi-dimensional priority selection rules (evaluated in order)
    #[serde(default)]
    pub pipeline_select: Vec<PipelineSelectRule>,
    #[serde(default)]
    pub pipelines: Vec<Pipeline>,

    /// 旧配置里的后台刷新专用规则。照样能读，但不会生效：后台刷新按原请求走过的规则重放（见
    /// `engine::refresh`）。写了它，启动和每次重载时各记一条 warn（见 [`warn_ignored_settings`]）。
    /// The background refresh rule of older configurations. It is still read but never
    /// takes effect: a background refresh replays the original request through the rules
    /// it went through (see `engine::refresh`). When present, startup and every reload log
    /// a warn (see [`warn_ignored_settings`]).
    #[serde(default)]
    pub background_refresh_rule: Option<Rule>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GlobalSettings {
    /// 最小TTL秒数，缺省0。 / Minimum TTL in seconds, defaults to 0
    #[serde(default = "default_min_ttl")]
    pub min_ttl: u32,
    /// UDP监听地址，缺省0.0.0.0:5353，避免1024以下端口权限问题。 / UDP listen address, defaults to 0.0.0.0:5353, avoiding port permission issues below 1024
    #[serde(default = "default_bind_udp")]
    pub bind_udp: String,
    /// TCP监听地址，缺省0.0.0.0:5353。 / TCP listen address, defaults to 0.0.0.0:5353
    #[serde(default = "default_bind_tcp")]
    pub bind_tcp: String,
    /// DoH 监听地址（留空则不启用）。 / DoH listen address (empty/null = disabled)
    #[serde(default)]
    pub bind_doh: Option<String>,
    /// DoH TLS 证书路径（PEM）。 / TLS certificate path for DoH (PEM)
    #[serde(default)]
    pub doh_tls_cert: Option<String>,
    /// DoH TLS 私钥路径（PEM）。 / TLS private key path for DoH (PEM)
    #[serde(default)]
    pub doh_tls_key: Option<String>,
    /// DoH 查询路径，默认 /dns-query。可自定义为任意路径以避免探测。
    /// / DoH query path, defaults to /dns-query. Can be customized to any path to avoid detection.
    #[serde(default = "default_doh_path")]
    pub doh_path: String,
    /// Moka 缓存最大条目数（默认 10000） / Moka cache max entries (default 10000)
    #[serde(default = "default_cache_capacity")]
    pub cache_capacity: u64,
    /// Moka 缓存最大生存时间（秒，默认 86400） / Moka cache max TTL (seconds, default 86400)
    #[serde(default = "default_cache_max_ttl")]
    pub cache_max_ttl: u64,
    /// DashMap shard 数量（0=自动，默认 0）。更多 shards=更少锁竞争但更多内存开销 / DashMap shard count (0=auto, default 0). More shards=less lock contention but more memory overhead
    #[serde(default = "default_dashmap_shards")]
    pub dashmap_shards: usize,
    /// 默认上游DNS。 / Default upstream DNS
    #[serde(default = "default_upstream")]
    pub default_upstream: String,
    /// 预分割的默认上游列表（性能优化） / Pre-split default upstream list (performance optimization)
    #[serde(skip)]
    pub default_upstream_pre_split: Option<Arc<Vec<Arc<str>>>>,
    /// 上游超时（毫秒）。 / Upstream timeout (milliseconds)
    /// 单次上游请求的超时时间
    #[serde(default = "default_upstream_timeout_ms")]
    pub upstream_timeout_ms: u64,
    /// 整体请求超时（毫秒）。 / Overall request timeout (milliseconds)
    /// 包含 hedge + TCP fallback 的总超时时间。如果未设置，自动计算为 upstream_timeout_ms * 2.5
    /// Total timeout including hedge + TCP fallback. If not set, auto-calculated as upstream_timeout_ms * 2.5
    #[serde(default)]
    pub request_timeout_ms: Option<u64>,
    /// 响应阶段 Pipeline 跳转上限。 / Response phase pipeline jump limit
    #[serde(default = "default_response_jump_limit")]
    pub response_jump_limit: u32,
    /// UDP 上游连接池大小。 / UDP upstream connection pool size
    #[serde(default = "default_udp_pool_size")]
    pub udp_pool_size: usize,
    /// TCP 上游连接池大小。 / TCP upstream connection pool size
    #[serde(default = "default_tcp_pool_size")]
    pub tcp_pool_size: usize,
    /// DoH 上游连接池大小（每个 upstream 的最大空闲连接数）。 / DoH upstream pool size (max idle per host)
    #[serde(default = "default_doh_pool_size")]
    pub doh_pool_size: usize,
    /// DoH 健康检查错误阈值（连续传输错误多少次后重建连接池以驱逐死连接）。 / DoH health check error threshold (rebuild pool after N consecutive transport errors to evict dead connections)
    /// 默认 3 次，0 表示禁用健康检查 / Default 3, 0 means disable health check
    #[serde(default = "default_doh_health_check_error_threshold")]
    pub doh_health_check_error_threshold: usize,
    /// DoT 上游连接池大小。 / DoT upstream connection pool size
    #[serde(default = "default_dot_pool_size")]
    pub dot_pool_size: usize,
    /// DoQ 上游连接池大小。 / DoQ upstream connection pool size
    #[serde(default = "default_doq_pool_size")]
    pub doq_pool_size: usize,
    /// TCP 健康检查错误阈值（连续失败多少次后重置连接） / TCP health check error threshold (reset connection after N consecutive failures)
    /// 默认 3 次，0 表示禁用健康检查 / Default 3, 0 means disable health check
    #[serde(default = "default_tcp_health_check_error_threshold")]
    pub tcp_health_check_error_threshold: usize,
    /// TCP 连接最大存活时间（秒，超过强制重置） / TCP connection max age (seconds, force reset after this time)
    /// 0 表示禁用连接老化检查 / 0 means disable connection aging check
    #[serde(default = "default_tcp_connection_max_age_seconds")]
    pub tcp_connection_max_age_seconds: u64,
    /// TCP 连接空闲超时（秒，无请求超过此时间重置） / TCP connection idle timeout (seconds, reset if no requests for this time)
    /// 0 表示禁用空闲超时检查 / 0 means disable idle timeout check
    #[serde(default = "default_tcp_connection_idle_timeout_seconds")]
    pub tcp_connection_idle_timeout_seconds: u64,
    /// DoQ 连接空闲超时（秒）。 / DoQ connection idle timeout (seconds)
    #[serde(default = "default_doq_idle_timeout_seconds")]
    pub doq_connection_idle_timeout_seconds: u64,
    /// DoQ keepalive 间隔（毫秒）。0 表示禁用。 / DoQ keepalive interval (ms). 0 disables.
    #[serde(default = "default_doq_keepalive_interval_ms")]
    pub doq_keepalive_interval_ms: u64,
    /// 是否启用 DoQ 0-RTT（默认 true）。 / Enable DoQ 0-RTT (default true)
    #[serde(default = "default_doq_enable_0rtt")]
    pub doq_enable_0rtt: bool,
    /// 是否启用自适应流控（默认false，推荐禁用以获得更好的性能和更简单的行为）
    /// Enable adaptive flow control (default false, recommended disabled for better performance and simpler behavior)
    ///
    /// 禁用后采用rustdns风格：不限制并发，依赖tokio runtime调度和超时保护
    /// When disabled, use rustdns style: no concurrency limit, rely on tokio runtime scheduling and timeout protection
    #[serde(default = "default_flow_control_enabled")]
    pub flow_control_enabled: bool,
    /// 自适应流控初始 permits 数量（仅在flow_control_enabled=true时有效） / Initial permits for adaptive flow control (only effective when flow_control_enabled=true)
    #[serde(default = "default_flow_control_initial_permits")]
    pub flow_control_initial_permits: usize,
    /// 自适应流控最小 permits 数量（仅在flow_control_enabled=true时有效） / Minimum permits for adaptive flow control (only effective when flow_control_enabled=true)
    #[serde(default = "default_flow_control_min_permits")]
    pub flow_control_min_permits: usize,
    /// 自适应流控最大 permits 数量（仅在flow_control_enabled=true时有效） / Maximum permits for adaptive flow control (only effective when flow_control_enabled=true)
    #[serde(default = "default_flow_control_max_permits")]
    pub flow_control_max_permits: usize,
    /// 上游延迟告急阈值（毫秒，仅在flow_control_enabled=true时有效） / Critical latency threshold (milliseconds, only effective when flow_control_enabled=true)
    #[serde(default = "default_flow_control_latency_threshold_ms")]
    pub flow_control_latency_threshold_ms: u64,
    /// 流控调整间隔（秒，仅在flow_control_enabled=true时有效） / Flow control adjustment interval (seconds, only effective when flow_control_enabled=true)
    #[serde(default = "default_flow_control_adjustment_interval_secs")]
    pub flow_control_adjustment_interval_secs: u64,
    /// RFC 8767: 上游不可用时返回过期缓存（默认 false）/ RFC 8767: Serve stale cached data when upstream is unavailable (default false)
    #[serde(default = "default_serve_stale")]
    pub serve_stale: bool,
    /// RFC 8767: 过期缓存响应的 TTL（秒，默认 30）/ RFC 8767: TTL for stale responses (seconds, default 30)
    /// 对应 Unbound serve-expired-reply-ttl / Corresponds to Unbound serve-expired-reply-ttl
    #[serde(default = "default_serve_stale_ttl")]
    pub serve_stale_ttl: u32,
    /// RFC 8767: 过期缓存可被服务的最大时间窗口（秒，默认 86400）
    /// 当缓存过期超过此时间后不再返回 stale 数据。0 表示无限制。
    /// RFC 8767: Maximum time window for serving stale cache (seconds, default 86400)
    /// Don't serve stale data after the entry has been expired for longer than this. 0 means no limit.
    /// 对应 Unbound serve-expired-ttl / Corresponds to Unbound serve-expired-ttl
    #[serde(default = "default_serve_stale_expire_ttl")]
    pub serve_stale_expire_ttl: u64,
    /// RFC 8767: 提供过期缓存后重置过期计时器（默认 true）
    /// 启用后，每次返回 stale 数据时重置过期时间窗口，确保频繁访问的域名不会因 serve_stale_expire_ttl 超时。
    /// RFC 8767: Reset the stale expiry timer after serving stale (default true)
    /// When enabled, resets the stale age counter each time stale data is served.
    /// 对应 Unbound serve-expired-ttl-reset / Corresponds to Unbound serve-expired-ttl-reset
    #[serde(default = "default_serve_stale_ttl_reset")]
    pub serve_stale_ttl_reset: bool,
    /// RFC 8767: 返回过期缓存前尝试上游查询的超时（毫秒，默认 0）
    /// 0 = 立即返回过期缓存（乐观模式）。 > 0 = 先尝试上游查询，超时后返回过期缓存。
    /// RFC 8767: Client timeout before serving stale (ms, default 0)
    /// 0 = serve stale immediately (optimistic mode). > 0 = try upstream first, serve stale on timeout.
    /// 对应 Unbound serve-expired-client-timeout / Corresponds to Unbound serve-expired-client-timeout
    #[serde(default = "default_serve_stale_client_timeout_ms")]
    pub serve_stale_client_timeout_ms: u64,
    /// 缓存后台刷新是否启用（默认false） / Enable cache background refresh (default false)
    #[serde(default = "default_cache_background_refresh")]
    pub cache_background_refresh: bool,
    /// 缓存后台刷新阈值（百分比，默认10）。当剩余TTL低于此百分比时触发后台刷新 / Cache background refresh threshold (percentage, default 10). Trigger background refresh when remaining TTL below this percentage
    #[serde(default = "default_cache_refresh_threshold_percent")]
    pub cache_refresh_threshold_percent: u8,
    /// 缓存后台刷新最小TTL（秒，默认5）。防止TTL过短导致无限循环刷新 / Cache background refresh minimum TTL (seconds, default 5). Prevent infinite refresh loop for very short TTLs
    #[serde(default = "default_cache_refresh_min_ttl")]
    pub cache_refresh_min_ttl: u32,
    /// GeoIP 数据库文件路径（MMDB 格式） / GeoIP database file path (MMDB format)
    #[serde(default)]
    pub geoip_db_path: Option<String>,
    /// GeoIP 数据文件路径（V2Ray .dat 格式） / GeoIP data file path (V2Ray .dat format)
    #[serde(default)]
    pub geoip_dat_path: Option<String>,
    /// 是否自动转换 .dat 为 MMDB（默认 false）/ Auto-convert .dat to MMDB (default false)
    #[serde(default)]
    pub geoip_auto_convert: bool,
    /// GeoIP 转换时过滤的国家代码列表 / Country codes to filter during GeoIP conversion
    #[serde(default)]
    pub geoip_filter_countries: Vec<String>,
    /// GeoSite 数据文件路径列表（V2Ray 格式，支持多个文件） / GeoSite data file paths (V2Ray format, supports multiple files)
    #[serde(default)]
    pub geosite_data_paths: Vec<String>,
    /// UDP 失败时是否自动 fallback 到 TCP（默认 true）。 / UDP failure automatically fallbacks to TCP (default true)
    #[serde(default = "default_enable_tcp_fallback")]
    pub enable_tcp_fallback: bool,
    /// 已不起作用：开了控制通道，面板的查询排行就一直在统计。留着字段，旧配置照样能读。
    /// No longer has any effect: with the control socket open, the panel's query
    /// rankings are always collected. The field stays so older configs still load.
    #[serde(default)]
    pub statistics_enabled: bool,
    /// 已不起作用：排行记完整的客户端地址。留着字段，旧配置照样能读。
    /// No longer has any effect: rankings record whole client addresses. The field
    /// stays so older configs still load.
    #[serde(default)]
    pub statistics_anonymize_client_ip: bool,
}

impl Default for GlobalSettings {
    fn default() -> Self {
        Self {
            min_ttl: default_min_ttl(),
            bind_udp: default_bind_udp(),
            bind_tcp: default_bind_tcp(),
            bind_doh: None,
            doh_tls_cert: None,
            doh_tls_key: None,
            doh_path: default_doh_path(),
            default_upstream: default_upstream(),
            default_upstream_pre_split: None,
            upstream_timeout_ms: default_upstream_timeout_ms(),
            request_timeout_ms: None, // 默认自动计算 / Auto-calculated by default
            response_jump_limit: default_response_jump_limit(),
            udp_pool_size: default_udp_pool_size(),
            tcp_pool_size: default_tcp_pool_size(),
            doh_pool_size: default_doh_pool_size(),
            doh_health_check_error_threshold: default_doh_health_check_error_threshold(),
            dot_pool_size: default_dot_pool_size(),
            doq_pool_size: default_doq_pool_size(),
            tcp_health_check_error_threshold: default_tcp_health_check_error_threshold(),
            tcp_connection_max_age_seconds: default_tcp_connection_max_age_seconds(),
            tcp_connection_idle_timeout_seconds: default_tcp_connection_idle_timeout_seconds(),
            doq_connection_idle_timeout_seconds: default_doq_idle_timeout_seconds(),
            doq_keepalive_interval_ms: default_doq_keepalive_interval_ms(),
            doq_enable_0rtt: default_doq_enable_0rtt(),
            flow_control_enabled: default_flow_control_enabled(),
            flow_control_initial_permits: default_flow_control_initial_permits(),
            flow_control_min_permits: default_flow_control_min_permits(),
            flow_control_max_permits: default_flow_control_max_permits(),
            flow_control_latency_threshold_ms: default_flow_control_latency_threshold_ms(),
            flow_control_adjustment_interval_secs: default_flow_control_adjustment_interval_secs(),
            cache_capacity: default_cache_capacity(),
            cache_max_ttl: default_cache_max_ttl(),
            dashmap_shards: default_dashmap_shards(),
            serve_stale: default_serve_stale(),
            serve_stale_ttl: default_serve_stale_ttl(),
            serve_stale_expire_ttl: default_serve_stale_expire_ttl(),
            serve_stale_ttl_reset: default_serve_stale_ttl_reset(),
            serve_stale_client_timeout_ms: default_serve_stale_client_timeout_ms(),
            cache_background_refresh: default_cache_background_refresh(),
            cache_refresh_threshold_percent: default_cache_refresh_threshold_percent(),
            cache_refresh_min_ttl: default_cache_refresh_min_ttl(),
            geoip_db_path: None,
            geoip_dat_path: None,
            geoip_auto_convert: false,
            geoip_filter_countries: Vec::new(),
            geosite_data_paths: Vec::new(),
            enable_tcp_fallback: default_enable_tcp_fallback(),
            statistics_enabled: false,
            statistics_anonymize_client_ip: false,
        }
    }
}

fn default_cache_capacity() -> u64 {
    10_000
}

fn default_cache_max_ttl() -> u64 {
    86400
}

fn default_dashmap_shards() -> usize {
    0 // 0 means use DashMap default (num_cpus * 4)
}

#[derive(Debug, Clone, Deserialize)]
pub struct Pipeline {
    pub id: String,
    #[serde(default)]
    pub rules: Vec<Rule>,
    /// Pipeline 级 ECS 配置，决定缓存隔离维度（RFC 7871）。
    /// Pipeline-level ECS config, determines cache isolation dimension (RFC 7871).
    ///
    /// When set, cache entries are isolated by client subnet so that different
    /// geographic regions get distinct cached responses.
    /// 设置后，缓存条目按客户端子网隔离，不同地理区域获得不同的缓存响应。
    #[serde(default)]
    pub ecs: Option<EcsMode>,
}

/// Pre-computed merged upstream list for rules with multiple Forward actions.
/// Computed at config load time to avoid per-request allocation of 5 FxHashSets + format!/join.
/// 多 Forward action 规则的预计算合并上游列表。
/// 在配置加载时计算，避免每请求分配 5 个 FxHashSet + format!/join。
#[derive(Debug, Clone)]
pub struct MergedForward {
    /// Comma-joined upstream string (for Decision::Forward.upstream)
    /// 逗号连接的上游字符串（用于 Decision::Forward.upstream）
    pub upstream_str: Arc<str>,
    /// Pre-split upstream list with transport prefixes (for Decision::Forward.pre_split_upstreams)
    /// 预分割的带协议前缀的上游列表（用于 Decision::Forward.pre_split_upstreams）
    pub upstream_list: Arc<Vec<Arc<str>>>,
    /// 合并后这一次转发发出的 ECS：几个 forward 的 ecs 写得一样时就是它，写得不一样时为 None，
    /// 和不写 ecs 一样（见 `Rule::shared_forward_ecs`）
    /// The ECS this one merged forward sends: the forwards' ecs when they all write the
    /// same, None when they differ, as without ecs (see `Rule::shared_forward_ecs`)
    pub ecs: Option<EcsMode>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub name: String,
    #[serde(default)]
    pub matchers: Vec<MatcherWithOp>,
    #[serde(default = "default_match_operator")]
    pub matcher_operator: MatchOperator,
    #[serde(default)]
    pub actions: Vec<Action>,
    /// 响应阶段匹配器，可根据上游、响应类型、rcode等进行判断。 / Response phase matchers, can determine based on upstream, response type, rcode, etc.
    #[serde(default)]
    pub response_matchers: Vec<ResponseMatcherWithOp>,
    #[serde(default = "default_match_operator")]
    pub response_matcher_operator: MatchOperator,
    /// 响应匹配成功后执行的动作序列。 / Action sequence to execute after successful response matching
    #[serde(default)]
    pub response_actions_on_match: Vec<Action>,
    /// 响应匹配失败后执行的动作序列。 / Action sequence to execute after failed response matching
    #[serde(default)]
    pub response_actions_on_miss: Vec<Action>,
    /// Pre-computed merge result for multiple Forward actions (None if <=1 Forward action).
    /// Computed at load time to eliminate per-request FxHashSet + format! + join overhead.
    /// 多个 Forward action 的预计算合并结果（<=1 个 Forward 时为 None）。
    /// 在加载时计算以消除每请求的 FxHashSet + format! + join 开销。
    #[serde(skip)]
    pub merged_forward: Option<MergedForward>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Matcher {
    Any,
    /// 匹配域名后缀，大小写不敏感。 / Match domain suffix, case insensitive
    DomainSuffix {
        value: String,
    },
    /// 只匹配这个域名本身，不含子域名，大小写不敏感。 / Match this domain name itself, not its
    /// subdomains, case insensitive
    DomainExact {
        value: String,
    },
    /// 域名正则匹配（Rust 正则语法，默认大小写不敏感请自行使用 (?i)）。 / Domain regex matching (Rust regex syntax, use (?i) for case insensitivity by default)
    DomainRegex {
        value: String,
    },
    /// 匹配客户端IP的CIDR。 / Match client IP CIDR
    ClientIp {
        cidr: String,
    },
    /// 匹配客户端 IP 的 GeoIP 国家代码或命名标签（大小写不敏感）。 / Match client IP GeoIP country code or named tag (case insensitive)
    GeoipCountry {
        #[serde(deserialize_with = "deserialize_string_or_vec")]
        country_codes: Vec<String>,
    },
    /// 匹配客户端IP是否为私有IP（内网）。 / Match whether client IP is private (internal network)
    GeoipPrivate {
        expect: bool,
    },
    /// 匹配查询 QCLASS（如 IN/CH/HS）。 / Match query QCLASS (e.g., IN/CH/HS)
    Qclass {
        value: String,
    },
    /// 是否存在 EDNS 伪记录。 / Whether EDNS pseudo-record exists
    EdnsPresent {
        expect: bool,
    },
    /// GeoSite 分类匹配（如 "cn", "google", "category-ads"）。 / GeoSite category matching (e.g., "cn", "google", "category-ads")
    GeoSite {
        value: String,
    },
    /// GeoSite 否定匹配（匹配不在该分类的域名）。 / GeoSite negation matching (match domains NOT in category)
    GeoSiteNot {
        value: String,
    },
    /// 请求 QTYPE（如 A/AAAA/CNAME/TXT/MX 等）。 / Request QTYPE (e.g., A/AAAA/CNAME/TXT/MX, etc.)
    Qtype {
        value: String,
    },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PipelineSelectorMatcher {
    /// 入口标签匹配（来自启动参数 listener_label）。 / Entry label matching (from listener_label startup parameter)
    ListenerLabel { value: String },
    /// 客户端IP CIDR。 / Client IP CIDR
    ClientIp { cidr: String },
    /// 请求域名后缀。 / Request domain suffix
    DomainSuffix { value: String },
    /// 请求域名本身，不含子域名。 / The request domain itself, not its subdomains
    DomainExact { value: String },
    /// 请求域名正则。 / Request domain regex
    DomainRegex { value: String },
    /// 任意请求（总是匹配）。 / Any request (always matches)
    Any,
    /// 请求 QCLASS（如 IN/CH/HS）。 / Request QCLASS (e.g., IN/CH/HS)
    Qclass { value: String },
    /// 请求是否携带 EDNS。 / Whether request carries EDNS
    EdnsPresent { expect: bool },
    /// GeoSite 分类匹配（如 "cn", "google", "category-ads"）。 / GeoSite category matching (e.g., "cn", "google", "category-ads")
    GeoSite { value: String },
    /// GeoSite 否定匹配（匹配不在该分类的域名）。 / GeoSite negation matching (match domains NOT in category)
    GeoSiteNot { value: String },
    /// 匹配客户端 IP 的 GeoIP 国家代码或命名标签（大小写不敏感）。 / Match client IP GeoIP country code or named tag (case insensitive)
    GeoipCountry {
        #[serde(deserialize_with = "deserialize_string_or_vec")]
        country_codes: Vec<String>,
    },
    /// 匹配客户端IP是否为私有IP（内网）。 / Match whether client IP is private (internal network)
    GeoipPrivate { expect: bool },
    /// 请求 QTYPE（如 A/AAAA/CNAME/TXT/MX 等）。 / Request QTYPE (e.g., A/AAAA/CNAME/TXT/MX, etc.)
    Qtype { value: String },
}

#[derive(Debug, Clone, Deserialize)]
pub struct PipelineSelectRule {
    pub pipeline: String,
    #[serde(default)]
    pub matchers: Vec<PipelineSelectorMatcherWithOp>,
    #[serde(default = "default_match_operator")]
    pub matcher_operator: MatchOperator,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MatcherWithOp {
    #[serde(default = "default_match_operator")]
    pub operator: MatchOperator,
    #[serde(flatten)]
    pub matcher: Matcher,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PipelineSelectorMatcherWithOp {
    #[serde(default = "default_match_operator")]
    pub operator: MatchOperator,
    #[serde(flatten)]
    pub matcher: PipelineSelectorMatcher,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ResponseMatcherWithOp {
    #[serde(default = "default_match_operator")]
    pub operator: MatchOperator,
    #[serde(flatten)]
    pub matcher: ResponseMatcher,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResponseMatcher {
    /// 匹配使用的上游（字符串相等）。 / Match the upstream used (string equality)
    UpstreamEquals { value: String },
    /// 复用请求域名后缀匹配（便于上游+域名组合策略）。 / Reuse request domain suffix matching (convenient for upstream+domain combination strategy)
    RequestDomainSuffix { value: String },
    /// 请求域名本身，不含子域名。 / The request domain itself, not its subdomains
    RequestDomainExact { value: String },
    /// 请求域名正则匹配。 / Request domain regex matching
    RequestDomainRegex { value: String },
    /// 匹配响应所来自的上游 IP（支持 CIDR）。 / Match the upstream IP from which the response originated (supports CIDR)
    ResponseUpstreamIp { cidr: String },
    /// 匹配响应 Answer 中的 IP 地址（A/AAAA 记录，支持 CIDR）。 / Match IP addresses in response Answer (A/AAAA records, supports CIDR)
    ResponseAnswerIp { cidr: String },
    /// 匹配响应记录类型（如 A/AAAA/CNAME/TXT/MX 等）。 / Match response record type (e.g., A/AAAA/CNAME/TXT/MX, etc.)
    ResponseType { value: String },
    /// 匹配响应的RCode（如 NOERROR/NXDOMAIN/SERVFAIL）。 / Match response RCode (e.g., NOERROR/NXDOMAIN/SERVFAIL)
    ResponseRcode { value: String },
    /// 匹配请求 QCLASS（如 IN/CH/HS）。 / Match request QCLASS (e.g., IN/CH/HS)
    ResponseQclass { value: String },
    /// 响应是否携带 EDNS。 / Whether response carries EDNS
    ResponseEdnsPresent { expect: bool },
    /// 匹配响应中 IP 的 GeoIP 国家代码或命名标签（大小写不敏感）/ Match GeoIP country code or named tag of response IPs (case insensitive)
    ResponseAnswerIpGeoipCountry {
        #[serde(deserialize_with = "deserialize_string_or_vec")]
        country_codes: Vec<String>,
    },
    /// 匹配响应中 IP 是否为私有 IP / Match whether IPs in response are private IPs
    ResponseAnswerIpGeoipPrivate { expect: bool },
    /// 匹配响应中的请求域名是否属于指定 GeoSite 分类 / Match if request domain in response belongs to specified GeoSite category
    ResponseRequestDomainGeoSite { value: String },
    /// 匹配响应中的请求域名是否不属于指定 GeoSite 分类 / Match if request domain in response does NOT belong to specified GeoSite category
    ResponseRequestDomainGeoSiteNot { value: String },
    /// 匹配响应中 TXT 记录的内容 / Match TXT record content in response
    ResponseTxtContent {
        /// 匹配模式: exact(精确), prefix(前缀), regex(正则) / Match mode: exact, prefix, or regex
        mode: String,
        /// 要匹配的文本 / Text to match
        value: String,
    },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Action {
    /// 记录日志，level可选：trace/debug/info/warn/error / Log action, level options: trace/debug/info/warn/error
    Log { level: Option<String> },
    /// 固定响应rcode（如 NXDOMAIN/NOERROR）。 / Static response rcode (e.g., NXDOMAIN/NOERROR)
    StaticResponse { rcode: String },
    /// 返回一个或逗号分隔的多个固定 IPv4/IPv6 地址。 / Return one or more comma-separated static IPv4/IPv6 addresses.
    StaticIpResponse { ip: String },
    /// 返回固定 CNAME 记录。 / Return a static CNAME record.
    StaticCnameResponse {
        /// CNAME 目标域名 / Canonical target domain name
        target: String,
        /// TTL (可选，默认 300) / TTL (optional, default 300)
        #[serde(default)]
        ttl: Option<u32>,
    },
    /// 返回固定 TXT 记录。支持单个字符串或字符串数组。 / Return static TXT record. Supports single string or string array.
    StaticTxtResponse {
        /// TXT 记录内容 / TXT record content
        #[serde(deserialize_with = "deserialize_txt_text")]
        text: Vec<String>,
        /// TTL (可选，默认 300) / TTL (optional, default 300)
        #[serde(default)]
        ttl: Option<u32>,
    },
    /// 跳转到指定 Pipeline 继续处理。 / Jump to specified Pipeline to continue processing
    JumpToPipeline { pipeline: String },
    /// 终止匹配。请求阶段使用默认上游，响应阶段使用当前响应。 / Terminate matching. Request phase uses default upstream, response phase uses current response
    Allow,
    /// 终止并丢弃（返回 REFUSED）。 / Terminate and drop (return REFUSED)
    Deny,
    /// 透传上游；upstream为空则使用全局默认；支持逗号分隔或数组格式的多个上游（并发请求取最快结果）；transport缺省udp。
    /// 支持 udp/tcp/tcp_udp/doh/dot/doq。/ Forward to upstream; use global default if upstream is empty; supports comma-separated or array format for multiple upstreams (concurrent requests, take fastest result); transport defaults to udp; supports udp/tcp/tcp_udp/doh/dot/doq.
    Forward {
        #[serde(deserialize_with = "deserialize_upstream")]
        upstream: Option<String>,
        #[serde(default)]
        transport: Option<Transport>,
        /// EDNS Client Subnet (RFC 7871) 请求改写，缺省 None = 不修改。
        /// EDNS Client Subnet (RFC 7871) request rewriting, default None = no modification.
        #[serde(default)]
        ecs: Option<EcsMode>,
        /// 预分割的 upstream 列表（性能优化）/ Pre-split upstream list (performance optimization)
        #[serde(skip)]
        pre_split_upstreams: Option<Arc<Vec<Arc<str>>>>,
    },
    /// 继续匹配后续规则。响应阶段会复用当前响应结果。 / Continue matching subsequent rules. Response phase will reuse current response result
    Continue,
    /// 修改响应中的 TXT 记录 / Modify TXT records in response
    ReplaceTxtResponse {
        /// 新的 TXT 内容 / New TXT content
        #[serde(deserialize_with = "deserialize_txt_text")]
        text: Vec<String>,
    },
}

/// Action 辅助函数 / Action helper functions
impl Action {
    /// 预分割 upstream 字符串以优化性能（在配置加载时调用）/ Pre-split upstream string for performance (call during config loading)
    #[inline]
    pub fn pre_split_upstreams(&mut self) {
        if let Action::Forward {
            upstream: Some(upstream_str),
            pre_split_upstreams,
            ..
        } = self
        {
            *pre_split_upstreams = Some(Arc::new(
                split_upstreams(upstream_str).map(Arc::from).collect(),
            ));
        }
    }
}

/// Rule helper functions / Rule 辅助函数
impl Rule {
    /// 合并转发时问的那几个 forward（写了 upstream 的）共用的 ecs：写得一样时就是它，
    /// 写得不一样时为 Err。合并后只有一次转发，只能发一个 ECS
    /// The ecs shared by the forwards a merged forward asks (those with an upstream
    /// written): it when they all write the same, Err when they differ. The merge is a
    /// single forward and can send only one ECS
    pub(crate) fn shared_forward_ecs(&self) -> Result<Option<&EcsMode>, ()> {
        let mut ecs = self.actions.iter().filter_map(|action| match action {
            Action::Forward {
                upstream: Some(_),
                ecs,
                ..
            } => Some(ecs.as_ref()),
            _ => None,
        });
        let first = ecs.next().flatten();
        if ecs.all(|other| other == first) {
            Ok(first)
        } else {
            Err(())
        }
    }

    /// Pre-compute merged upstream list for rules with multiple Forward actions.
    /// Extracts the transport-aware merge logic from the runtime hot path into a one-time
    /// computation at config load, eliminating per-request FxHashSet + format! + join overhead.
    /// 预计算多 Forward action 规则的合并上游列表。
    /// 将传输层感知的合并逻辑从运行时热路径提取到配置加载时的一次性计算，
    /// 消除每请求的 FxHashSet + format! + join 开销。
    #[inline]
    pub fn compute_merged_forward(&mut self) {
        use rustc_hash::FxHashSet;

        let forward_count = self
            .actions
            .iter()
            .filter(|a| matches!(a, Action::Forward { .. }))
            .count();

        if forward_count <= 1 {
            return;
        }

        // 每种传输一组，各组按这里的顺序排进合并后的列表 / One set per transport, each going
        // into the merged list in this order
        const SCHEMES: [(Transport, &str); 6] = [
            (Transport::Tcp, "tcp"),
            (Transport::Udp, "udp"),
            (Transport::TcpUdp, "tcp+udp"),
            (Transport::Doh, "doh"),
            (Transport::Dot, "dot"),
            (Transport::Doq, "doq"),
        ];
        let mut sets: [FxHashSet<String>; 6] = Default::default();

        for action in &self.actions {
            if let Action::Forward {
                upstream: Some(upstream),
                transport,
                ..
            } = action
            {
                let action_transport = transport.unwrap_or(Transport::Udp);
                for addr in split_upstreams(upstream) {
                    // 前缀照单个转发那样认（不分大小写，见 `upstream::parse_upstream_addr`），
                    // 没有前缀或前缀不认识时用这个动作的传输。TCP 和 UDP 双发的上游只记一份，
                    // 合并后仍然双发
                    // The prefix is read as for a single forward (ignoring case, see
                    // `upstream::parse_upstream_addr`), the action's transport taken without
                    // one or for one it does not know. An upstream asked over TCP and UDP at
                    // once is recorded once and still asked both ways after the merge
                    let (address, transport) = match addr.find("://") {
                        Some(idx) => (
                            &addr[idx + 3..],
                            crate::engine::upstream::transport_for_scheme(&addr[..idx])
                                .unwrap_or(action_transport),
                        ),
                        None => (addr, action_transport),
                    };
                    let slot = SCHEMES
                        .iter()
                        .position(|(scheme_transport, _)| *scheme_transport == transport)
                        .expect("every transport has a set");
                    sets[slot].insert(format!("{}://{address}", SCHEMES[slot].1));
                }
            }
        }

        let all_upstreams: Vec<Arc<str>> = sets
            .iter()
            .flat_map(|set| set.iter().map(|s| Arc::from(s.as_str())))
            .collect();

        if all_upstreams.is_empty() {
            tracing::info!(
                rule = %self.name,
                forward_count,
                "all forward actions have empty upstream, merged_forward not set"
            );
            self.merged_forward = None;
        } else {
            tracing::info!(
                rule = %self.name,
                forward_count,
                tcp_count = sets[0].len(),
                udp_count = sets[1].len(),
                tcp_udp_count = sets[2].len(),
                doh_count = sets[3].len(),
                dot_count = sets[4].len(),
                doq_count = sets[5].len(),
                total_upstreams = all_upstreams.len(),
                "pre-computed merged forward actions with transport-specific deduplication"
            );
            let merged_str: String = all_upstreams
                .iter()
                .map(|s| s.as_ref())
                .collect::<Vec<_>>()
                .join(",");
            self.merged_forward = Some(MergedForward {
                upstream_str: Arc::from(merged_str.as_str()),
                upstream_list: Arc::new(all_upstreams),
                // 写得不一样时不发，启动时 `problems` 记一条警告 / None when they differ;
                // at startup `problems` logs a warning
                ecs: self.shared_forward_ecs().ok().flatten().cloned(),
            });
        }
    }
}

/// Listener endpoints resolved from [`GlobalSettings`], exactly as the server
/// binds them. / 从 [`GlobalSettings`] 解析出的监听端点，与服务器实际绑定的一致。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerConfig {
    /// UDP listener address (`bind_udp`).
    pub udp: SocketAddr,
    /// TCP listener address (`bind_tcp`).
    pub tcp: SocketAddr,
    /// DoH listener, present when `bind_doh` is set.
    pub doh: Option<DohListenerConfig>,
}

/// Inbound DoH listener settings with the TLS material it requires.
/// 入站 DoH 监听设置及其所需的 TLS 材料。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DohListenerConfig {
    /// DoH listener address (`bind_doh`).
    pub bind: SocketAddr,
    /// PEM certificate path (`doh_tls_cert`).
    pub tls_cert: String,
    /// PEM private key path (`doh_tls_key`).
    pub tls_key: String,
    /// HTTP path served (`doh_path`).
    pub path: String,
}

impl GlobalSettings {
    /// 和 `running`（进程启动时的设置）相比，改了以后要重启 KixDNS 才生效的设置名。这些设置只在启动时
    /// 读一次：监听地址、连接池、各传输的连接参数、缓存容量、自动限流；其余设置重载即生效。这里逐项列出
    /// 全部字段，新增设置时编译会要求决定它属于哪一类。
    /// The names of the settings that differ from `running` (those the process started
    /// with) and take a restart of KixDNS to apply. They are read once at startup:
    /// listener addresses, connection pools, per-transport connection parameters, cache
    /// capacity and flow control; every other setting applies on a reload. Every field is
    /// listed here, so a new setting forces a decision on which kind it is.
    pub fn restart_pending(&self, running: &GlobalSettings) -> Vec<&'static str> {
        // 每个字段只写一次：解构不带 `..`，新增设置时编译会要求把它放进其中一张表；只在启动时读取的
        // 逐个和 `running` 比较，按表里的顺序记下
        // Each field is written once: the destructuring has no `..`, so a new setting must
        // go into one of the lists to compile; those read at startup only are compared
        // with `running` one by one and noted in list order
        macro_rules! restart_pending {
            (reload: [$($reload:ident),* $(,)?], startup: [$($startup:ident),* $(,)?] $(,)?) => {{
                let GlobalSettings {
                    $($reload: _,)*
                    $($startup,)*
                } = self;
                let mut pending = Vec::new();
                $(
                    if *$startup != running.$startup {
                        pending.push(stringify!($startup));
                    }
                )*
                pending
            }};
        }
        restart_pending!(
            // 重载即生效（统计开关和 GeoIP 自动转换、国家过滤已经不起作用）
            // Applied on a reload (the statistics switches, GeoIP auto-conversion and
            // country filter no longer do anything)
            reload: [
                min_ttl,
                default_upstream,
                default_upstream_pre_split,
                upstream_timeout_ms,
                request_timeout_ms,
                response_jump_limit,
                enable_tcp_fallback,
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
                statistics_enabled,
                statistics_anonymize_client_ip,
            ],
            // 只在启动时读取 / Read at startup only
            startup: [
                bind_udp,
                bind_tcp,
                bind_doh,
                doh_tls_cert,
                doh_tls_key,
                doh_path,
                cache_capacity,
                cache_max_ttl,
                dashmap_shards,
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
            ],
        )
    }

    /// Parse the listener addresses and check the DoH prerequisites the way
    /// server startup does; a configuration that fails here cannot be served.
    /// Both the server and [`validate`] call this.
    /// 按服务器启动的方式解析监听地址并检查 DoH 前置条件；此处失败的配置无法启动。
    /// 服务器与 [`validate`] 都调用它。
    pub fn listeners(&self) -> anyhow::Result<ListenerConfig> {
        let udp: SocketAddr = self.bind_udp.parse().context("parse bind addr")?;
        let tcp: SocketAddr = self.bind_tcp.parse().context("parse tcp bind addr")?;
        let doh = match &self.bind_doh {
            Some(bind_doh) => {
                let bind: SocketAddr = bind_doh.parse().context("parse doh bind addr")?;
                let tls_cert = self
                    .doh_tls_cert
                    .clone()
                    .context("doh_tls_cert is required when bind_doh is set")?;
                let tls_key = self
                    .doh_tls_key
                    .clone()
                    .context("doh_tls_key is required when bind_doh is set")?;
                Some(DohListenerConfig {
                    bind,
                    tls_cert,
                    tls_key,
                    path: self.doh_path.clone(),
                })
            }
            None => None,
        };
        Ok(ListenerConfig { udp, tcp, doh })
    }

    /// 预分割默认 upstream 字符串以优化性能（在配置加载时调用）/ Pre-split default upstream string for performance (call during config loading)
    #[inline]
    pub fn pre_split_default_upstream(&mut self) {
        let split: Vec<Arc<str>> = split_upstreams(&self.default_upstream)
            .map(Arc::from)
            .collect();
        if split.len() > 1 {
            self.default_upstream_pre_split = Some(Arc::new(split));
        }
    }

    /// Validate timeout configuration sanity
    /// 验证超时配置的合理性
    pub fn validate_timeouts(&self) -> anyhow::Result<()> {
        // Validate request_timeout >= upstream_timeout
        // 验证 request_timeout >= upstream_timeout
        if let Some(request_timeout) = self.request_timeout_ms {
            if request_timeout < self.upstream_timeout_ms {
                anyhow::bail!(
                    "Configuration error: request_timeout_ms ({request_timeout}) must be >= upstream_timeout_ms ({upstream})\n\
                     配置错误: request_timeout_ms ({request_timeout}) 必须大于等于 upstream_timeout_ms ({upstream})",
                    upstream = self.upstream_timeout_ms
                );
            }

            // Recommended value check (warning only, doesn't block)
            // 建议值检查（警告但不阻止）
            // Recommended value should be at least upstream * 2.5 to allow hedge + TCP fallback to complete
            // 建议值应至少为 upstream * 2.5，以允许 hedge + TCP fallback 完成
            let recommended = self.upstream_timeout_ms * 5 / 2;
            if request_timeout < recommended {
                tracing::warn!(
                    upstream_timeout_ms = self.upstream_timeout_ms,
                    request_timeout_ms = request_timeout,
                    recommended = recommended,
                    "request_timeout_ms may be too short, may interrupt hedge and TCP fallback\n\
                     request_timeout_ms 可能太短，可能会中断 hedge 和 TCP fallback"
                );
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Udp,
    Tcp,
    /// Send both TCP and UDP concurrently, use first response (hedged request)
    /// 同时发送 TCP 和 UDP，使用第一个响应（对冲请求）
    TcpUdp,
    /// DNS over HTTPS (DoH)
    /// DNS over HTTPS（DoH）
    Doh,
    /// DNS over TLS (DoT)
    /// DNS over TLS（DoT）
    Dot,
    /// DNS over QUIC (DoQ)
    /// DNS over QUIC（DoQ）
    Doq,
}

#[derive(Debug, Clone, Deserialize, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MatchOperator {
    And,
    Or,
    #[serde(alias = "not", alias = "and_not", alias = "and-not", alias = "andnot")]
    AndNot,
    #[serde(alias = "or_not", alias = "or-not", alias = "ornot")]
    OrNot,
}

fn default_match_operator() -> MatchOperator {
    MatchOperator::And
}

/// Load the configuration file at `path` and return it together with the
/// text it was parsed from, so callers can fingerprint the active
/// configuration. / 加载配置文件并连同原始文本一起返回，便于调用方计算指纹。
pub fn load_config_with_source(path: &Path) -> Result<(PipelineConfig, String)> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("read config file: {}", path.display()))?;
    let cfg =
        parse_config(&raw).with_context(|| format!("parse config file: {}", path.display()))?;

    if let Some(version) = cfg.version.as_ref() {
        info!(target = "config", version = %version, "config loaded");
    }

    Ok((cfg, raw))
}

/// Parse and normalize a configuration from its JSON text without touching
/// the filesystem. Errors from the JSON layer carry line/column positions.
/// 从 JSON 文本解析并规范化配置，不访问文件系统。JSON 层错误带行列位置。
pub fn parse_config(raw: &str) -> Result<PipelineConfig> {
    let mut cfg: PipelineConfig = serde_json::from_str(raw).context("parse config JSON")?;

    // 预分割上游字符串，转发时不必每次再拆；默认上游有几个时同时问 / Pre-split the upstream
    // strings so a forward does not split them each time; several default upstreams are
    // asked at once
    cfg.settings.pre_split_default_upstream();

    for pipeline in &mut cfg.pipelines {
        for rule in &mut pipeline.rules {
            for action in &mut rule.actions {
                action.pre_split_upstreams();
            }
            // Pre-compute merged Forward upstreams for multi-Forward rules (performance optimization).
            // Eliminates per-request FxHashSet + format! + join overhead on the hot path.
            // 预计算多 Forward 规则的合并上游（性能优化）。
            // 消除热路径上每请求的 FxHashSet + format! + join 开销。
            rule.compute_merged_forward();
            // 下面的 CIDR 只在这里先解析一遍，好早点报出写错的；匹配器建好时会再解析
            // The CIDRs below are parsed here only to report a bad one early; the matchers
            // parse them again when built
            for matcher in &rule.matchers {
                if let Matcher::ClientIp { cidr } = &matcher.matcher {
                    let _parsed: IpNet = cidr.parse()?;
                }
            }
            for matcher in &rule.response_matchers {
                if let ResponseMatcher::RequestDomainSuffix { value } = &matcher.matcher
                    && value.is_empty()
                {
                    anyhow::bail!("response_matcher request_domain_suffix empty");
                }
                if let ResponseMatcher::ResponseUpstreamIp { cidr }
                | ResponseMatcher::ResponseAnswerIp { cidr } = &matcher.matcher
                {
                    for part in cidr.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                        let _parsed: IpNet = part.parse()?;
                    }
                }
            }
        }
    }

    for sel in &cfg.pipeline_select {
        for m in &sel.matchers {
            if let PipelineSelectorMatcher::ClientIp { cidr } = &m.matcher {
                let _parsed: IpNet = cidr.parse()?;
            }
        }
    }

    Ok(cfg)
}

fn default_min_ttl() -> u32 {
    0
}

fn default_bind_udp() -> String {
    "0.0.0.0:5353".to_string()
}

fn default_bind_tcp() -> String {
    "0.0.0.0:5353".to_string()
}

fn default_upstream() -> String {
    "1.1.1.1:53".to_string()
}

fn default_upstream_timeout_ms() -> u64 {
    // Increased from 2000ms to 9000ms to align with idoq library best practices
    // DoQ servers (especially Alibaba DNS) may require longer response times
    // 从 2000ms 增加到 9000ms，以对齐 idoq 库的最佳实践
    // DoQ 服务器（特别是阿里 DNS）可能需要更长的响应时间
    9000
}

fn default_response_jump_limit() -> u32 {
    10
}

fn default_udp_pool_size() -> usize {
    64
}

fn default_tcp_pool_size() -> usize {
    64
}

fn default_doh_pool_size() -> usize {
    8
}

fn default_doh_health_check_error_threshold() -> usize {
    3 // 连续 3 次传输错误后重建连接池 / Rebuild pool after 3 consecutive transport errors
}

/// Default DoH query path (RFC 8484 standard) / 默认 DoH 查询路径（RFC 8484 标准）
fn default_doh_path() -> String {
    "/dns-query".to_string()
}

fn default_dot_pool_size() -> usize {
    64
}

fn default_doq_pool_size() -> usize {
    16
}

fn default_tcp_health_check_error_threshold() -> usize {
    3 // 连续 3 次失败后重置连接 / Reset connection after 3 consecutive failures
}

fn default_tcp_connection_max_age_seconds() -> u64 {
    300 // 5 分钟 / 5 minutes
}

fn default_tcp_connection_idle_timeout_seconds() -> u64 {
    60 // 1 分钟 / 1 minute
}

fn default_doq_idle_timeout_seconds() -> u64 {
    60 // 1 分钟 / 1 minute
}

fn default_doq_keepalive_interval_ms() -> u64 {
    15_000
}

fn default_doq_enable_0rtt() -> bool {
    true // 默认启用 0-RTT，系统会自动检测并回退不支持的服务器
    // Enabled by default - system automatically detects and falls back for unsupported servers
}

fn default_flow_control_enabled() -> bool {
    false // 默认禁用，采用rustdns风格 / Default disabled, use rustdns style
}

fn default_flow_control_initial_permits() -> usize {
    500
}

fn default_flow_control_min_permits() -> usize {
    100
}

fn default_flow_control_max_permits() -> usize {
    800
}

fn default_flow_control_latency_threshold_ms() -> u64 {
    100
}

fn default_flow_control_adjustment_interval_secs() -> u64 {
    5
}

fn default_serve_stale() -> bool {
    false
}

fn default_serve_stale_ttl() -> u32 {
    30
}

fn default_serve_stale_expire_ttl() -> u64 {
    86400
}

fn default_serve_stale_ttl_reset() -> bool {
    true
}

fn default_serve_stale_client_timeout_ms() -> u64 {
    0
}

fn default_cache_background_refresh() -> bool {
    false
}

fn default_cache_refresh_threshold_percent() -> u8 {
    10
}

fn default_cache_refresh_min_ttl() -> u32 {
    5
}

/// 反序列化 upstream 字段，支持字符串、逗号分隔字符串或数组格式
/// Deserialize upstream field, supports string, comma-separated string, or array format
fn deserialize_upstream<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum UpstreamInput {
        String(String),
        Array(Vec<String>),
    }

    let input = Option::<UpstreamInput>::deserialize(deserializer)?;

    match input {
        None => Ok(None),
        Some(UpstreamInput::String(s)) => Ok(Some(s)),
        Some(UpstreamInput::Array(arr)) => {
            if arr.is_empty() {
                Ok(None)
            } else {
                Ok(Some(arr.join(",")))
            }
        }
    }
}

/// Deserialize a string field that also accepts an array of strings.
fn deserialize_string_or_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrVec {
        String(String),
        Array(Vec<String>),
    }

    match StringOrVec::deserialize(deserializer)? {
        StringOrVec::String(value) => Ok(value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect()),
        StringOrVec::Array(values) => Ok(values
            .into_iter()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .collect()),
    }
}

/// 反序列化TXT文本字段，支持单个字符串或字符串数组 / Deserialize TXT text field, supports single string or string array
fn deserialize_txt_text<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum TxtTextInput {
        String(String),
        Array(Vec<String>),
    }

    match TxtTextInput::deserialize(deserializer)? {
        TxtTextInput::String(value) => Ok(vec![value]),
        TxtTextInput::Array(values) => Ok(values),
    }
}

fn default_enable_tcp_fallback() -> bool {
    true
}

/// EDNS Client Subnet (RFC 7871) 操作模式，用于 Forward 动作的请求改写。
/// EDNS Client Subnet (RFC 7871) operation mode, used by the Forward action for request rewriting.
///
/// 三种模式覆盖典型场景：
/// Three modes cover typical scenarios:
/// - `Clear`: 剥离客户端自带的 ECS（隐私保护）/ Strip client-provided ECS (privacy)
/// - `FromClientIp`: 从客户端来源 IP 推导 ECS 子网 / Derive ECS subnet from client source IP
/// - `Static`: 使用固定 IP/前缀（伪装特定地理位置）/ Use fixed IP/prefix (spoof geo-location)
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum EcsMode {
    /// 剥离查询中的 ECS OPT 选项。
    /// Strip the ECS OPT option from the query.
    Clear,

    /// 从客户端来源 IP（peer address）推导 ECS 子网。
    /// Derive ECS subnet from the client source IP (peer address).
    ///
    /// 私有 IP（RFC 1918/ULA/loopback）不注入 ECS。客户端自己带了 ECS 时，转发它自己的
    /// 子网，前缀比这里的长就截短，前缀为 0 的原样转发（RFC 7871 第 7.1 节）。
    /// Private IPs (RFC 1918/ULA/loopback) are not injected with ECS. A client that
    /// sent ECS itself has its own subnet forwarded, cut to these prefixes when
    /// longer, and a prefix of 0 forwarded as it is (RFC 7871 section 7.1).
    FromClientIp {
        /// IPv4 source prefix length (default: 24)
        #[serde(default = "default_ecs_prefix_v4")]
        prefix_v4: u8,
        /// IPv6 source prefix length (default: 56)
        #[serde(default = "default_ecs_prefix_v6")]
        prefix_v6: u8,
    },

    /// 使用固定 IP 地址和前缀注入 ECS。
    /// Inject ECS with a fixed IP address and prefix.
    ///
    /// 用于伪装特定地理位置，忽略真实客户端 IP。
    /// Used to spoof a specific geo-location, ignoring the real client IP.
    Static {
        /// 固定 IP 地址（IPv4 或 IPv6）/ Fixed IP address (IPv4 or IPv6)
        ip: String,
        /// Source prefix length (default: 24)
        #[serde(default = "default_ecs_prefix_v4")]
        prefix: u8,
    },
}

fn default_ecs_prefix_v4() -> u8 {
    crate::ecs::DEFAULT_PREFIX_V4
}

fn default_ecs_prefix_v6() -> u8 {
    crate::ecs::DEFAULT_PREFIX_V6
}

/// Summary of a configuration that passed [`validate`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ValidationReport {
    /// The configuration's `version` field, if present.
    pub version: Option<String>,
    /// Number of pipelines.
    pub pipeline_count: usize,
    /// Total number of rules across all pipelines.
    pub rule_count: usize,
}

/// Validate configuration text exactly as the server loads it: JSON parsing,
/// normalisation, runtime compilation (matchers, regexes, CIDRs, timeout
/// sanity) and the listener checks done at startup
/// ([`GlobalSettings::listeners`]: bind addresses and DoH TLS material).
/// Errors carry their cause chain; JSON syntax errors include the line and
/// column. / 按服务器加载配置的方式校验文本：JSON 解析、规范化、运行时编译以及
/// 启动时的监听检查（绑定地址与 DoH TLS 材料）。错误带完整原因链；JSON 语法错误包含行列位置。
pub fn validate(raw: &str) -> Result<ValidationReport> {
    let cfg = parse_config(raw)?;
    refuse_problems(&cfg)?;
    let version = cfg.version.clone();
    let runtime = RuntimePipelineConfig::from_config(cfg).context("compile configuration")?;
    runtime.settings.listeners().context("validate listeners")?;
    Ok(ValidationReport {
        version,
        pipeline_count: runtime.pipelines.len(),
        rule_count: runtime.pipelines.iter().map(|p| p.rules.len()).sum(),
    })
}

/// 配置里会悄悄做成别的事的写法：读不懂的上游地址、拼错的 rcode、无效的静态 IP 或 CNAME 目标、
/// 装不进一条记录的 TXT、跳到不存在的 pipeline、会匹配所有域名的空域名匹配器。以前这些都照常加载：
/// 上游一直失败、rcode 变成 NXDOMAIN、静态应答变成 SERVFAIL、空后缀什么都匹配。
///
/// 启动时只记警告、照旧加载，已经在用的配置升级以后行为不变；热重载和面板的校验（见 [`validate`]）
/// 拒绝它们，下一次改配置时就得改掉。
///
/// Ways of writing a configuration that silently do something else: an upstream
/// address nothing can read, a misspelt rcode, an invalid static IP or CNAME target,
/// TXT content that does not fit a record, a jump to a pipeline that does not exist,
/// an empty domain matcher that matches every name. These all used to load as
/// usual: the upstream kept failing, the rcode became NXDOMAIN, the static answer
/// became SERVFAIL, the empty suffix matched everything.
///
/// Startup only logs them and loads as before, so a configuration in use keeps its
/// behaviour across an upgrade; a reload and the panel's validation (see
/// [`validate`]) refuse them, so the next change has to fix them.
pub fn problems(cfg: &PipelineConfig) -> Vec<String> {
    let pipelines: rustc_hash::FxHashSet<&str> =
        cfg.pipelines.iter().map(|p| p.id.as_str()).collect();
    let mut found = Vec::new();
    if split_upstreams(&cfg.settings.default_upstream)
        .next()
        .is_none()
    {
        found.push(format!("default_upstream: {NO_UPSTREAM}"));
    }
    for upstream in split_upstreams(&cfg.settings.default_upstream) {
        if let Some(problem) = crate::engine::upstream::upstream_problem(upstream, Transport::Udp) {
            found.push(format!("default_upstream: {problem}"));
        }
    }
    for (index, select) in cfg.pipeline_select.iter().enumerate() {
        let place = format!("pipeline_select {}", index + 1);
        if !pipelines.contains(select.pipeline.as_str()) {
            found.push(format!("{place}: no pipeline \"{}\"", select.pipeline));
        }
        for matcher in &select.matchers {
            if let PipelineSelectorMatcher::DomainSuffix { value }
            | PipelineSelectorMatcher::DomainRegex { value } = &matcher.matcher
                && value.is_empty()
            {
                found.push(format!("{place}: {EMPTY_DOMAIN_MATCHER}"));
            }
            if let PipelineSelectorMatcher::DomainExact { value } = &matcher.matcher
                && value.is_empty()
            {
                found.push(format!("{place}: {EMPTY_EXACT_MATCHER}"));
            }
        }
    }
    for pipeline in &cfg.pipelines {
        for rule in &pipeline.rules {
            let place = format!("pipeline \"{}\" rule \"{}\"", pipeline.id, rule.name);
            rule_problems(rule, &pipelines, |problem| {
                found.push(format!("{place}: {problem}"))
            });
        }
    }
    found
}

/// 照样能读、但不会生效的配置项：启动和每次重载时各记一条 warn，不算 [`problems`]
/// Settings still read but never in effect: each gets a warn at startup and on every
/// reload, and none counts among [`problems`]
pub fn warn_ignored_settings(cfg: &PipelineConfig) {
    if cfg.background_refresh_rule.is_some() {
        warn!(
            "background_refresh_rule has no effect: a background refresh replays the original request through its own rules; the entry can be removed"
        );
    }
}

/// [`problems`] 有一条就失败，列出全部 / Fail on any of [`problems`], listing them all
pub fn refuse_problems(cfg: &PipelineConfig) -> Result<()> {
    let found = problems(cfg);
    anyhow::ensure!(found.is_empty(), "{}", found.join("; "));
    Ok(())
}

const EMPTY_DOMAIN_MATCHER: &str = "an empty domain matcher matches every name";

/// 一条规则里几个 forward 的 ecs 写得不一样：它们合成一次转发，只能发一个 ECS，所以一个也不发
/// A rule whose forwards write different ecs: they merge into one forward, which can send
/// one ECS only, so none is sent
const MERGED_ECS_DIFFER: &str = "its forward actions are asked together as one forward, which sends one ECS, but their ecs settings differ, so none of them is sent; write the same ecs on each, or split them into separate rules";
const EMPTY_EXACT_MATCHER: &str = "an empty domain_exact matches only the root name";

/// 一个上游也没写：每个查询都会失败 / Not a single upstream written: every query would fail
const NO_UPSTREAM: &str = "no upstream is written, so every query it gets would fail";

/// 逗号分隔的上游，和转发时的拆法一样 / Comma-separated upstreams, split as a forward splits them
fn split_upstreams(upstreams: &str) -> impl Iterator<Item = &str> {
    upstreams
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn rule_problems(
    rule: &Rule,
    pipelines: &rustc_hash::FxHashSet<&str>,
    mut report: impl FnMut(String),
) {
    use crate::engine::response::{static_cname_target, static_ips, txt_size_problem};

    let forwards = rule
        .actions
        .iter()
        .filter(|action| matches!(action, Action::Forward { .. }))
        .count();
    if forwards > 1 && rule.shared_forward_ecs().is_err() {
        report(MERGED_ECS_DIFFER.to_string());
    }
    for matcher in &rule.matchers {
        if let Matcher::DomainSuffix { value } | Matcher::DomainRegex { value } = &matcher.matcher
            && value.is_empty()
        {
            report(EMPTY_DOMAIN_MATCHER.to_string());
        }
        if let Matcher::DomainExact { value } = &matcher.matcher
            && value.is_empty()
        {
            report(EMPTY_EXACT_MATCHER.to_string());
        }
    }
    for matcher in &rule.response_matchers {
        if let ResponseMatcher::RequestDomainRegex { value } = &matcher.matcher
            && value.is_empty()
        {
            report(EMPTY_DOMAIN_MATCHER.to_string());
        }
        if let ResponseMatcher::RequestDomainExact { value } = &matcher.matcher
            && value.is_empty()
        {
            report(EMPTY_EXACT_MATCHER.to_string());
        }
    }
    let actions = rule
        .actions
        .iter()
        .chain(&rule.response_actions_on_match)
        .chain(&rule.response_actions_on_miss);
    for action in actions {
        match action {
            Action::Forward {
                upstream: Some(upstreams),
                transport,
                ..
            } => {
                if split_upstreams(upstreams).next().is_none() {
                    report(NO_UPSTREAM.to_string());
                }
                for upstream in split_upstreams(upstreams) {
                    if let Some(problem) = crate::engine::upstream::upstream_problem(
                        upstream,
                        transport.unwrap_or(Transport::Udp),
                    ) {
                        report(problem);
                    }
                }
            }
            Action::StaticResponse { rcode }
                if crate::engine::utils::parse_rcode(rcode).is_none() =>
            {
                report(format!(
                    "rcode \"{rcode}\" is none of NOERROR, FORMERR, SERVFAIL, NXDOMAIN, NOTIMP, REFUSED"
                ));
            }
            Action::StaticIpResponse { ip } if static_ips(ip).is_none() => {
                report(format!(
                    "ip \"{ip}\" is not a comma-separated list of IP addresses"
                ));
            }
            Action::StaticCnameResponse { target, .. } if static_cname_target(target).is_none() => {
                report(format!("cname target \"{target}\" is not a domain name"));
            }
            Action::StaticTxtResponse { text, .. } | Action::ReplaceTxtResponse { text } => {
                if let Some(problem) = txt_size_problem(text) {
                    report(problem);
                }
            }
            Action::JumpToPipeline { pipeline } if !pipelines.contains(pipeline.as_str()) => {
                report(format!(
                    "jump to pipeline \"{pipeline}\", which does not exist"
                ));
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Matcher, PipelineSelectorMatcher, ResponseMatcher};

    #[test]
    fn geoip_country_codes_accept_string_or_array() {
        let Matcher::GeoipCountry { country_codes } =
            serde_json::from_str(r#"{"type":"geoip_country","country_codes":"cloudflare"}"#)
                .expect("request matcher should accept a string")
        else {
            panic!("unexpected request matcher variant");
        };
        assert_eq!(country_codes, ["cloudflare"]);

        let PipelineSelectorMatcher::GeoipCountry { country_codes } =
            serde_json::from_str(r#"{"type":"geoip_country","country_codes":"CN, cloudflare"}"#)
                .expect("pipeline selector should accept a comma-separated string")
        else {
            panic!("unexpected pipeline selector matcher variant");
        };
        assert_eq!(country_codes, ["CN", "cloudflare"]);

        let ResponseMatcher::ResponseAnswerIpGeoipCountry { country_codes } = serde_json::from_str(
            r#"{"type":"response_answer_ip_geoip_country","country_codes":[" CN ",""," cloudflare"]}"#,
        )
        .expect("response matcher should accept an array") else {
            panic!("unexpected response matcher variant");
        };
        assert_eq!(country_codes, ["CN", "cloudflare"]);
    }
}

#[cfg(test)]
mod merged_forward_tests {
    use super::Rule;
    use serde_json::json;

    /// 一条规则的几个转发动作合并出的上游列表，排好序 / The upstream list a rule's forward
    /// actions merge into, sorted
    fn merged(actions: serde_json::Value) -> Vec<String> {
        let mut rule: Rule = serde_json::from_value(json!({
            "name": "r", "matchers": [{ "type": "any" }], "actions": actions
        }))
        .expect("parse rule");
        rule.compute_merged_forward();
        let mut list: Vec<String> = rule
            .merged_forward
            .expect("several forwards merge")
            .upstream_list
            .iter()
            .map(|upstream| upstream.to_string())
            .collect();
        list.sort();
        list
    }

    /// 合并后的这一次转发只能发一个 ECS：几个 forward 的 ecs 写得一样时就是它；写得不一样（包括有的写、
    /// 有的不写）时为 None，和不写 ecs 一样。没写 upstream 的 forward 不在合并里，它的 ecs 不算
    /// The one merged forward can send one ECS only: the forwards' ecs when they all write
    /// the same; None when they differ (some written and some not, too), as without ecs. A
    /// forward without an upstream is not in the merge, and its ecs does not count
    #[test]
    fn a_merged_forward_sends_the_ecs_its_forwards_share() {
        let ecs_of = |actions: serde_json::Value| {
            let mut rule: Rule = serde_json::from_value(json!({
                "name": "r", "matchers": [{ "type": "any" }], "actions": actions
            }))
            .expect("parse rule");
            rule.compute_merged_forward();
            rule.merged_forward.expect("several forwards merge").ecs
        };
        let from_client = json!({ "mode": "from_client_ip", "prefix_v4": 24, "prefix_v6": 56 });
        let forward = |upstream: &str, ecs: &serde_json::Value| json!({ "type": "forward", "upstream": upstream, "ecs": ecs });
        let shared = Some(super::EcsMode::FromClientIp {
            prefix_v4: 24,
            prefix_v6: 56,
        });
        assert_eq!(
            ecs_of(json!([
                forward("192.0.2.1:53", &from_client),
                forward("192.0.2.2:53", &from_client)
            ])),
            shared
        );
        assert_eq!(
            ecs_of(json!([
                forward("192.0.2.1:53", &from_client),
                forward("192.0.2.2:53", &json!({ "mode": "clear" }))
            ])),
            None
        );
        assert_eq!(
            ecs_of(json!([
                forward("192.0.2.1:53", &from_client),
                { "type": "forward", "upstream": "192.0.2.2:53" }
            ])),
            None
        );
        assert_eq!(
            ecs_of(json!([
                forward("192.0.2.1:53", &from_client),
                forward("192.0.2.2:53", &from_client),
                { "type": "forward", "upstream": null, "ecs": { "mode": "clear" } }
            ])),
            shared
        );
    }

    /// 合并后的列表按传输分组排：tcp、udp、tcp+udp、doh、dot、doq。几个上游是同时发出的，但这个顺序
    /// 看得见：按它逐个发出，观察者按它收到每次尝试，转发决定里的上游列表也照它排。组内是集合的遍历
    /// 顺序；这里钉住分组的先后和每组有哪些
    /// The merged list is grouped by transport: tcp, udp, tcp+udp, doh, dot, doq. The
    /// upstreams are asked at once, yet the order shows: they are sent one by one in it,
    /// observers get each attempt in it, and the forward decision lists the upstreams in
    /// it. Within a group it is the set's iteration order; this pins the group order and
    /// what each group holds
    #[test]
    fn a_merged_list_is_grouped_by_transport_in_a_fixed_order() {
        let mut rule: Rule = serde_json::from_value(json!({
            "name": "r", "matchers": [{ "type": "any" }], "actions": [
                { "type": "forward", "upstream": "doq://192.0.2.6:853, dot://192.0.2.5:853" },
                { "type": "forward", "upstream": "doh://dns.example/dns-query" },
                { "type": "forward", "upstream": "192.0.2.3:53, 192.0.2.4:53", "transport": "tcp_udp" },
                { "type": "forward", "upstream": "udp://192.0.2.2:53, 192.0.2.7:53" },
                { "type": "forward", "upstream": "tcp://192.0.2.1:53, tcp://192.0.2.8:53" }
            ]
        }))
        .expect("parse rule");
        rule.compute_merged_forward();
        let merged = rule.merged_forward.expect("several forwards merge");
        let list: Vec<String> = merged
            .upstream_list
            .iter()
            .map(|upstream| upstream.to_string())
            .collect();
        assert_eq!(merged.upstream_str.as_ref(), list.join(","));
        let mut groups: Vec<&str> = list
            .iter()
            .map(|upstream| upstream.split("://").next().unwrap())
            .collect();
        groups.dedup();
        assert_eq!(
            groups,
            ["tcp", "udp", "tcp+udp", "doh", "dot", "doq"],
            "{list:?}"
        );
        let mut members = list.clone();
        members.sort();
        assert_eq!(
            members,
            [
                "doh://dns.example/dns-query",
                "doq://192.0.2.6:853",
                "dot://192.0.2.5:853",
                "tcp+udp://192.0.2.3:53",
                "tcp+udp://192.0.2.4:53",
                "tcp://192.0.2.1:53",
                "tcp://192.0.2.8:53",
                "udp://192.0.2.2:53",
                "udp://192.0.2.7:53",
            ]
        );
    }

    /// TCP 和 UDP 双发的上游合并后只出现一次，仍然双发，和只有一个转发时一样：写成 `tcp+udp://`
    /// 前缀和写成 `tcp_udp` 传输都是
    /// An upstream asked over TCP and UDP at once appears once after the merge and is still
    /// asked both ways, as with a single forward, whether written with the `tcp+udp://` prefix
    /// or the `tcp_udp` transport
    #[test]
    fn a_tcp_and_udp_upstream_is_merged_once() {
        assert_eq!(
            merged(json!([
                { "type": "forward", "upstream": "tcp+udp://192.0.2.1:53" },
                { "type": "forward", "upstream": "udp+tcp://192.0.2.1:53" },
                { "type": "forward", "upstream": "192.0.2.2:53", "transport": "tcp_udp" }
            ])),
            ["tcp+udp://192.0.2.1:53", "tcp+udp://192.0.2.2:53"]
        );
    }

    /// 前缀不分大小写，和单个转发一样；以前写成大写的上游合并时被丢掉
    /// Prefixes ignore case, as for a single forward; an upstream written in capitals used
    /// to be dropped by the merge
    #[test]
    fn a_prefix_in_capitals_is_kept() {
        assert_eq!(
            merged(json!([
                { "type": "forward", "upstream": "TCP://192.0.2.1:53" },
                { "type": "forward", "upstream": "Udp://192.0.2.2:53" }
            ])),
            ["tcp://192.0.2.1:53", "udp://192.0.2.2:53"]
        );
    }
}

#[cfg(test)]
mod validation_tests {
    use super::validate;

    #[test]
    fn validate_reports_counts_for_a_valid_config() {
        let raw = r#"{
            "version": "t1",
            "settings": { "default_upstream": "1.1.1.1:53" },
            "pipelines": [
                {
                    "id": "main",
                    "rules": [
                        { "name": "a", "matchers": [{ "type": "any" }], "actions": [{ "type": "allow" }] },
                        {
                            "name": "b",
                            "matchers": [{ "type": "domain_suffix", "value": "example.com" }],
                            "actions": [{ "type": "static_response", "rcode": "NXDOMAIN" }]
                        }
                    ]
                },
                { "id": "other", "rules": [] }
            ]
        }"#;
        let report = validate(raw).expect("valid config");
        assert_eq!(report.version.as_deref(), Some("t1"));
        assert_eq!(report.pipeline_count, 2);
        assert_eq!(report.rule_count, 2);
    }

    #[test]
    fn validate_locates_json_syntax_errors() {
        let err = validate("{\n  \"pipelines\": [\n").expect_err("truncated JSON");
        let text = format!("{err:#}");
        assert!(
            text.contains("line 3"),
            "error should carry a position: {text}"
        );
    }

    #[test]
    fn validate_rejects_invalid_selector_cidr() {
        let raw = r#"{
            "pipeline_select": [{
                "pipeline": "default",
                "matchers": [{ "type": "client_ip", "cidr": "invalid" }]
            }]
        }"#;
        assert!(validate(raw).is_err());
    }

    #[test]
    fn validate_rejects_configs_the_server_cannot_bind() {
        // Each row: settings JSON and whether the server would start with it
        // 每行：settings JSON 以及服务器能否以此启动
        let cases = [
            (r#"{ "bind_udp": "not-an-address" }"#, false),
            (r#"{ "bind_tcp": "999.999.999.999:53" }"#, false),
            (
                r#"{ "bind_doh": "::not::an::ip::", "doh_tls_cert": "c.pem", "doh_tls_key": "k.pem" }"#,
                false,
            ),
            (r#"{ "bind_udp": "127.0.0.1:99999" }"#, false),
            (r#"{ "bind_udp": "127.0.0.1:5353" }"#, true),
            (r#"{ "bind_doh": "127.0.0.1:8443" }"#, false),
            (
                r#"{ "bind_doh": "127.0.0.1:8443", "doh_tls_cert": "c.pem", "doh_tls_key": "k.pem" }"#,
                true,
            ),
        ];
        for (settings, expected_ok) in cases {
            let raw = format!(r#"{{ "settings": {settings} }}"#);
            let validated = validate(&raw);
            let started = crate::matcher::RuntimePipelineConfig::from_config(
                super::parse_config(&raw).expect("parse"),
            )
            .and_then(|runtime| runtime.settings.listeners());
            assert_eq!(validated.is_ok(), expected_ok, "validate({settings})");
            assert_eq!(
                validated.is_ok(),
                started.is_ok(),
                "validate() and startup must agree on {settings}"
            );
        }
    }

    #[test]
    fn validate_rejects_runtime_compilation_errors() {
        let err =
            validate(r#"{ "settings": { "cache_capacity": 0 } }"#).expect_err("zero capacity");
        assert!(format!("{err:#}").contains("cache_capacity"));
    }

    /// 一条规则，带上给定的匹配器和动作 / One rule with the given matchers and actions
    fn rule(
        name: &str,
        matchers: serde_json::Value,
        actions: serde_json::Value,
    ) -> serde_json::Value {
        serde_json::json!({ "name": name, "matchers": matchers, "actions": actions })
    }

    fn problems_of(config: serde_json::Value) -> Vec<String> {
        super::problems(&super::parse_config(&config.to_string()).expect("parses"))
    }

    /// 空的 domain_exact 只命中根域名，不是「匹配所有名字」，提示照实说
    /// An empty domain_exact matches only the root name, not every name, and the problem says so
    #[test]
    fn an_empty_domain_exact_is_named_for_what_it_does() {
        let config = serde_json::json!({
            "settings": { "default_upstream": "1.1.1.1:53" },
            "pipeline_select": [{ "pipeline": "main", "matchers": [{ "type": "domain_exact", "value": "" }] }],
            "pipelines": [{ "id": "main", "rules": [
                rule("exact", serde_json::json!([{ "type": "domain_exact", "value": "" }]), serde_json::json!([{ "type": "allow" }])),
                {
                    "name": "late",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "forward", "upstream": "1.1.1.1:53" }],
                    "response_matchers": [{ "type": "request_domain_exact", "value": "" }],
                    "response_actions_on_match": [{ "type": "allow" }]
                }
            ]}]
        });
        let found = problems_of(config);
        for place in ["pipeline_select 1", "rule \"exact\"", "rule \"late\""] {
            assert!(
                found.iter().any(|problem| problem.contains(place)
                    && problem.contains("empty domain_exact matches only the root name")),
                "missing {place} in {found:#?}"
            );
        }
        assert!(
            !found
                .iter()
                .any(|problem| problem.contains("matches every name")),
            "{found:#?}"
        );
    }

    /// ECS 没写前缀时的默认值：from_client_ip 是 IPv4 24、IPv6 56，static 是 24
    /// The ECS prefixes when none is written: 24 for IPv4 and 56 for IPv6 with
    /// from_client_ip, 24 with static
    #[test]
    fn ecs_prefixes_default_to_24_and_56() {
        let from_client: super::EcsMode =
            serde_json::from_value(serde_json::json!({ "mode": "from_client_ip" })).unwrap();
        assert!(
            matches!(
                from_client,
                super::EcsMode::FromClientIp {
                    prefix_v4: 24,
                    prefix_v6: 56
                }
            ),
            "{from_client:?}"
        );
        let fixed: super::EcsMode =
            serde_json::from_value(serde_json::json!({ "mode": "static", "ip": "192.0.2.1" }))
                .unwrap();
        assert!(
            matches!(fixed, super::EcsMode::Static { prefix: 24, .. }),
            "{fixed:?}"
        );
    }

    /// 旧配置里的 background_refresh_rule 不会生效，所以不算问题：配置照样通过检查，规则本身写得
    /// 对不对都一样（这里它跳去一个不存在的 pipeline）
    /// A background_refresh_rule from an older configuration never takes effect, so it is
    /// no problem: the configuration passes the check whether or not the rule itself is
    /// written right (here it jumps to a pipeline that does not exist)
    #[test]
    fn a_background_refresh_rule_is_no_problem() {
        let config = serde_json::json!({
            "settings": { "default_upstream": "1.1.1.1:53" },
            "pipelines": [],
            "background_refresh_rule": rule(
                "refresh",
                serde_json::json!([{ "type": "any" }]),
                serde_json::json!([{ "type": "jump_to_pipeline", "pipeline": "gone" }])
            )
        });
        assert_eq!(problems_of(config), Vec::<String>::new());
    }

    /// 一个上游也没写的转发（`upstream` 写成空的）、空的 default_upstream，每个查询都必然失败，改配置
    /// 时就报出来
    /// A forward naming no upstream at all (`upstream` written empty) and an empty
    /// default_upstream would fail every query, so they are named when the config changes
    #[test]
    fn a_forward_or_default_with_no_upstream_is_named() {
        let any = serde_json::json!([{ "type": "any" }]);
        let config = serde_json::json!({
            "settings": { "default_upstream": " , " },
            "pipelines": [{ "id": "main", "rules": [
                rule("empty", any.clone(), serde_json::json!([{ "type": "forward", "upstream": "" }])),
                rule("commas", any.clone(), serde_json::json!([{ "type": "forward", "upstream": " , " }]))
            ]}]
        });
        let found = problems_of(config);
        for place in ["default_upstream", "rule \"empty\"", "rule \"commas\""] {
            assert!(
                found
                    .iter()
                    .any(|problem| problem.contains(place) && problem.contains("no upstream")),
                "missing {place} in {found:#?}"
            );
        }
    }

    /// 会悄悄做成别的事的写法，每一种都报出来，带上在哪条规则
    /// Every way of writing that silently does something else is named, with where it is
    /// 一条规则里几个 forward 的 ecs 写得不一样时（包括有的写、有的不写），是一条配置问题：写明规则，说清怎么改。
    /// 写得一样、都不写、只有一个 forward 时不算
    /// A rule whose forwards write different ecs (some written and some not, too) is a
    /// configuration problem naming the rule and saying how to fix it. The same ecs on
    /// each, none at all, or a single forward is no problem
    #[test]
    fn forwards_with_different_ecs_in_one_rule_are_a_problem() {
        let any = serde_json::json!([{ "type": "any" }]);
        let from_client = serde_json::json!({ "mode": "from_client_ip" });
        let forward = |upstream: &str, ecs: &serde_json::Value| serde_json::json!({ "type": "forward", "upstream": upstream, "ecs": ecs });
        let plain = |upstream: &str| serde_json::json!({ "type": "forward", "upstream": upstream });
        let config = serde_json::json!({
            "settings": { "default_upstream": "1.1.1.1:53" },
            "pipelines": [{ "id": "main", "rules": [
                rule("mixed", any.clone(), serde_json::json!([
                    forward("1.1.1.1:53", &from_client),
                    forward("8.8.8.8:53", &serde_json::json!({ "mode": "clear" }))
                ])),
                rule("half", any.clone(), serde_json::json!([
                    forward("1.1.1.1:53", &from_client),
                    plain("8.8.8.8:53")
                ])),
                rule("same", any.clone(), serde_json::json!([
                    forward("1.1.1.1:53", &from_client),
                    forward("8.8.8.8:53", &serde_json::json!({ "mode": "from_client_ip", "prefix_v4": 24, "prefix_v6": 56 }))
                ])),
                rule("none", any.clone(), serde_json::json!([plain("1.1.1.1:53"), plain("8.8.8.8:53")])),
                rule("single", any.clone(), serde_json::json!([forward("1.1.1.1:53", &from_client)]))
            ]}]
        });
        let found = problems_of(config);
        assert_eq!(found.len(), 2, "{found:?}");
        for place in ["mixed", "half"] {
            assert!(
                found.iter().any(|problem| {
                    problem.starts_with(&format!("pipeline \"main\" rule \"{place}\": "))
                        && problem.contains("ecs settings differ")
                        && problem.contains("separate rules")
                }),
                "{place}: {found:?}"
            );
        }
    }

    /// 读配置时就拦下写错的 CIDR：响应规则的 response_upstream_ip、response_answer_ip 两种都是
    /// A CIDR written wrong is refused as the configuration is read, in both
    /// response_upstream_ip and response_answer_ip
    #[test]
    fn a_bad_response_cidr_is_refused_as_the_configuration_is_read() {
        for kind in ["response_upstream_ip", "response_answer_ip"] {
            let config = serde_json::json!({
                "settings": { "default_upstream": "1.1.1.1:53" },
                "pipelines": [{ "id": "main", "rules": [{
                    "name": "r",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "forward", "upstream": "1.1.1.1:53" }],
                    "response_matchers": [{ "type": kind, "cidr": "10.0.0.0/8, nonsense" }],
                    "response_actions_on_match": [{ "type": "allow" }]
                }] }]
            });
            assert!(super::parse_config(&config.to_string()).is_err(), "{kind}");
        }
    }

    /// 默认上游写了几个时，读配置时就拆好（各项去掉空白、空项跳过）；只有一个时不拆
    /// Several default upstreams are split as the configuration is read (each trimmed,
    /// empty ones skipped); a single one is not
    #[test]
    fn several_default_upstreams_are_split_ahead() {
        let split = |default_upstream: &str| {
            let config = serde_json::json!({
                "settings": { "default_upstream": default_upstream },
                "pipelines": [{ "id": "main", "rules": [] }]
            });
            super::parse_config(&config.to_string())
                .expect("parses")
                .settings
                .default_upstream_pre_split
                .map(|list| {
                    list.iter()
                        .map(|upstream| upstream.to_string())
                        .collect::<Vec<_>>()
                })
        };
        assert_eq!(
            split(" 1.1.1.1:53 ,, 8.8.8.8:53"),
            Some(vec!["1.1.1.1:53".to_string(), "8.8.8.8:53".to_string()])
        );
        assert_eq!(split("1.1.1.1:53"), None);
    }

    #[test]
    fn problems_name_what_would_silently_do_something_else() {
        let any = serde_json::json!([{ "type": "any" }]);
        let config = serde_json::json!({
            "settings": { "default_upstream": "dns.example:53" },
            "pipeline_select": [{ "pipeline": "gone", "matchers": [{ "type": "domain_suffix", "value": "" }] }],
            "pipelines": [{ "id": "main", "rules": [
                rule("port", any.clone(), serde_json::json!([{ "type": "forward", "upstream": "1.1.1.1:99999" }])),
                rule("name", any.clone(), serde_json::json!([{ "type": "forward", "upstream": "nonsense" }])),
                rule("scheme", any.clone(), serde_json::json!([{ "type": "forward", "upstream": "http://1.1.1.1:53" }])),
                rule("doq", any.clone(), serde_json::json!([{ "type": "forward", "upstream": "doq://223.5.5.5:853" }])),
                rule("rcode", any.clone(), serde_json::json!([{ "type": "static_response", "rcode": "WHATEVER" }])),
                rule("ip", any.clone(), serde_json::json!([{ "type": "static_ip_response", "ip": "192.0.2.1, nope" }])),
                rule("noip", any.clone(), serde_json::json!([{ "type": "static_ip_response", "ip": "" }])),
                rule("cname", any.clone(), serde_json::json!([{ "type": "static_cname_response", "target": "" }])),
                rule("txt", any.clone(), serde_json::json!([{ "type": "static_txt_response", "text": "x".repeat(256) }])),
                rule("jump", any.clone(), serde_json::json!([{ "type": "jump_to_pipeline", "pipeline": "gone" }])),
                rule("suffix", serde_json::json!([{ "type": "domain_suffix", "value": "" }]), serde_json::json!([{ "type": "allow" }])),
                rule("regex", serde_json::json!([{ "type": "domain_regex", "value": "" }]), serde_json::json!([{ "type": "allow" }])),
                {
                    "name": "late",
                    "matchers": any,
                    "actions": [{ "type": "forward", "upstream": "1.1.1.1:53" }],
                    "response_matchers": [{ "type": "request_domain_regex", "value": "" }],
                    "response_actions_on_miss": [{ "type": "forward", "upstream": "udp+tcp://dns.example:53" }]
                }
            ]}]
        });
        let found = problems_of(config);
        for (place, fragment) in [
            ("default_upstream", "dns.example:53"),
            ("pipeline_select 1", "no pipeline \"gone\""),
            ("pipeline_select 1", "empty domain matcher"),
            ("rule \"port\"", "1.1.1.1:99999"),
            ("rule \"name\"", "nonsense"),
            ("rule \"scheme\"", "unknown prefix \"http://\""),
            ("rule \"doq\"", "sni"),
            ("rule \"rcode\"", "WHATEVER"),
            ("rule \"ip\"", "192.0.2.1, nope"),
            ("rule \"noip\"", "ip \"\""),
            ("rule \"cname\"", "cname target"),
            ("rule \"txt\"", "256 bytes"),
            ("rule \"jump\"", "\"gone\", which does not exist"),
            ("rule \"suffix\"", "empty domain matcher"),
            ("rule \"regex\"", "empty domain matcher"),
            ("rule \"late\"", "empty domain matcher"),
            ("rule \"late\"", "udp+tcp://dns.example:53"),
        ] {
            assert!(
                found
                    .iter()
                    .any(|problem| problem.contains(place) && problem.contains(fragment)),
                "missing {place} / {fragment} in {found:#?}"
            );
        }
        assert_eq!(found.len(), 17, "{found:#?}");
    }

    /// 平常的正确写法一条都不报 / The ordinary right ways of writing raise nothing
    #[test]
    fn problems_leave_the_right_ways_of_writing_alone() {
        let any = serde_json::json!([{ "type": "any" }]);
        let forward = |upstream: &str, transport: Option<&str>| {
            let mut action = serde_json::json!({ "type": "forward", "upstream": upstream });
            if let Some(transport) = transport {
                action["transport"] = serde_json::json!(transport);
            }
            serde_json::json!([action])
        };
        let config = serde_json::json!({
            "settings": { "default_upstream": "1.1.1.1:53, [2001:db8::1]:53" },
            "pipeline_select": [{ "pipeline": "other", "matchers": [{ "type": "domain_suffix", "value": "example.com" }] }],
            "pipelines": [
                { "id": "main", "rules": [
                    rule("udp", any.clone(), forward("udp://9.9.9.9:53", None)),
                    rule("tcp name", any.clone(), forward("dns.example:53", Some("tcp"))),
                    rule("tcp prefix", any.clone(), forward("tcp://dns.example:53", None)),
                    rule("doh", any.clone(), forward("https://dns.example/dns-query, doh://dns.example", None)),
                    rule("dot", any.clone(), forward("tls://1.1.1.1?sni=one.one.one.one", None)),
                    rule("doq", any.clone(), forward("dns.example:853", Some("doq"))),
                    rule("ips", any.clone(), serde_json::json!([{ "type": "static_ip_response", "ip": "192.0.2.1, 2001:db8::1" }])),
                    rule("cname", any.clone(), serde_json::json!([{ "type": "static_cname_response", "target": "target.example" }])),
                    rule("txt", any.clone(), serde_json::json!([{ "type": "static_txt_response", "text": ["a", "b"] }])),
                    rule("rcode", any.clone(), serde_json::json!([{ "type": "static_response", "rcode": "refused" }])),
                    rule("jump", serde_json::json!([{ "type": "domain_suffix", "value": ".example" }]), serde_json::json!([{ "type": "jump_to_pipeline", "pipeline": "other" }]))
                ]},
                { "id": "other", "rules": [] }
            ]
        });
        assert_eq!(problems_of(config), Vec::<String>::new());
    }

    /// 面板的校验拒绝这些写法，一次列出全部 / The panel's validation refuses these, listing them all at once
    #[test]
    fn validate_refuses_the_problems_and_lists_them_all() {
        let config = serde_json::json!({
            "pipelines": [{ "id": "main", "rules": [
                rule("rcode", serde_json::json!([{ "type": "any" }]), serde_json::json!([{ "type": "static_response", "rcode": "WHATEVER" }])),
                rule("jump", serde_json::json!([{ "type": "any" }]), serde_json::json!([{ "type": "jump_to_pipeline", "pipeline": "gone" }]))
            ]}]
        });
        let err = validate(&config.to_string()).expect_err("refused");
        let message = format!("{err:#}");
        assert!(
            message.contains("WHATEVER") && message.contains("\"gone\""),
            "{message}"
        );
    }

    /// 只列出启动时才读的设置；重载即生效的改了不算，改回去以后也不再列
    /// Only settings read at startup are listed; ones applied on a reload do not count,
    /// and a setting changed back is no longer listed
    #[test]
    fn restart_pending_names_only_settings_read_at_startup() {
        let running = super::GlobalSettings::default();
        let mut configured = running.clone();
        assert!(configured.restart_pending(&running).is_empty());

        configured.bind_udp = "0.0.0.0:5300".to_string();
        configured.cache_capacity += 1;
        configured.flow_control_enabled = !configured.flow_control_enabled;
        configured.upstream_timeout_ms += 1;
        configured.serve_stale = !configured.serve_stale;
        configured.default_upstream = "9.9.9.9:53".to_string();
        assert_eq!(
            configured.restart_pending(&running),
            ["bind_udp", "cache_capacity", "flow_control_enabled"]
        );

        configured.bind_udp = running.bind_udp.clone();
        assert_eq!(
            configured.restart_pending(&running),
            ["cache_capacity", "flow_control_enabled"]
        );
    }
}
