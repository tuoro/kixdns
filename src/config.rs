use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use anyhow::Result;
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};

use crate::matcher::RuntimePipelineConfig;
use crate::matcher::advanced_rule::StaticAnswer;

#[derive(Debug, Clone, Deserialize, Serialize)]
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
    /// `engine::refresh`）。写了它算一条 [`warnings`]。
    /// The background refresh rule of older configurations. It is still read but never
    /// takes effect: a background refresh replays the original request through the rules
    /// it went through (see `engine::refresh`). When present, it counts among [`warnings`].
    #[serde(default)]
    pub background_refresh_rule: Option<Rule>,

    /// 配置里写了、内核却不读的键，解析时找出来（见 [`unread_keys`]），写成 `pipelines[0].rules[2].matcher`、
    /// `pipelines[0].rules[2].actions[0].upstrem` 这样的路径，按写的顺序排。退役的旧设置（见 [`RETIRED_SETTINGS`]）只记
    /// warn，其余的算 [`problems`]
    /// The keys a configuration writes that the kernel does not read, found while parsing (see
    /// [`unread_keys`]), as paths like `pipelines[0].rules[2].matcher` and
    /// `pipelines[0].rules[2].actions[0].upstrem`, in the order written. Retired settings (see
    /// [`RETIRED_SETTINGS`]) only get a warn, and the rest count among [`problems`]
    #[serde(skip)]
    pub unread_keys: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct GlobalSettings {
    /// 最小TTL秒数，缺省0。 / Minimum TTL in seconds, defaults to 0
    pub min_ttl: u32,
    /// UDP 监听地址，缺省 0.0.0.0:5533：1024 以下的端口要权限；5353 是 mDNS 的端口，常被系统的 mDNSResponder、avahi
    /// 占着；5533 在 IANA 没有分配，常见的本地 DNS 软件也都不默认用它（Pi-hole 指南里的 Unbound 和 luci-app-mosdns
    /// 用 5335，OpenWrt 上的 SmartDNS 用 6053）
    /// UDP listen address, defaulting to 0.0.0.0:5533: ports below 1024 take privileges; 5353 is
    /// the mDNS port, often held by the system's mDNSResponder or avahi; 5533 is unassigned at
    /// IANA and the default of no common local DNS software (Unbound in the Pi-hole guide and
    /// luci-app-mosdns use 5335, SmartDNS on OpenWrt 6053)
    pub bind_udp: String,
    /// TCP 监听地址，缺省 0.0.0.0:5533 / TCP listen address, defaulting to 0.0.0.0:5533
    pub bind_tcp: String,
    /// DoH 监听地址（留空则不启用）。 / DoH listen address (empty/null = disabled)
    pub bind_doh: Option<String>,
    /// DoH TLS 证书路径（PEM）。 / TLS certificate path for DoH (PEM)
    pub doh_tls_cert: Option<String>,
    /// DoH TLS 私钥路径（PEM）。 / TLS private key path for DoH (PEM)
    pub doh_tls_key: Option<String>,
    /// DoH 查询路径，默认 /dns-query。可自定义为任意路径以避免探测。
    /// / DoH query path, defaults to /dns-query. Can be customized to any path to avoid detection.
    pub doh_path: String,
    /// 响应缓存最多存放的应答份数（默认 10000），超过 1 KB 的应答每 1 KB 算一份
    /// / Most answers the response cache holds (default 10000), one over 1 KB counting once per KB
    pub cache_capacity: u64,
    /// 应答 TTL 的上限（秒，默认 86400）：上游回答里每条记录的 TTL、缓存把一份应答当作新鲜的时间都不超过它；过了 TTL
    /// 还能当过期应答用的另外再留（见 `serve_stale_expire_ttl`）
    /// The cap on an answer's TTL (seconds, default 86400): neither the TTL of any record in an
    /// upstream answer nor how long the cache holds an answer fresh goes past it; one still of
    /// use past its TTL is kept on beyond that (see `serve_stale_expire_ttl`)
    pub cache_max_ttl: u64,
    /// DashMap shard 数量（0=自动，默认 0）。更多 shards=更少锁竞争但更多内存开销 / DashMap shard count (0=auto, default 0). More shards=less lock contention but more memory overhead
    pub dashmap_shards: usize,
    /// 默认上游DNS。 / Default upstream DNS
    pub default_upstream: String,
    /// 预分割的默认上游列表（性能优化） / Pre-split default upstream list (performance optimization)
    #[serde(skip)]
    pub default_upstream_pre_split: Option<Arc<Vec<Arc<str>>>>,
    /// `default_upstream` 的一份共用的副本（性能优化） / A shared copy of `default_upstream` (performance optimization)
    #[serde(skip)]
    pub default_upstream_shared: Option<Arc<str>>,
    /// 解析写成主机名的上游（TCP、DoT、DoH、DoQ）用的明文 DNS 服务器，逗号分隔的 `IP:端口`，同时问、取先答的；
    /// 空的（默认）就交给系统的解析器，系统的解析器要是 KixDNS 自己，解析就会绕回来（见 `engine::bootstrap`）
    /// The plain DNS servers that resolve the upstreams written with a host name (TCP, DoT, DoH,
    /// DoQ), comma-separated `IP:port`, asked at once with the first answer taken; empty (the
    /// default) leaves it to the system resolver, which loops back should it be KixDNS itself
    /// (see `engine::bootstrap`)
    pub bootstrap: String,
    /// 上游超时（毫秒）。 / Upstream timeout (milliseconds)
    /// 单次上游请求的超时时间
    pub upstream_timeout_ms: u64,
    /// 整体请求超时（毫秒）。 / Overall request timeout (milliseconds)
    /// 包含 hedge + TCP fallback 的总超时时间。如果未设置，自动计算为 upstream_timeout_ms * 2.5
    /// Total timeout including hedge + TCP fallback. If not set, auto-calculated as upstream_timeout_ms * 2.5
    pub request_timeout_ms: Option<u64>,
    /// 一个查询最多跳转几次 Pipeline：请求阶段规则的跳转最多这么多次，回答动作的头一次跳转起（连同之后规则级的跳转）
    /// 另算这么多次，不超过 [`MAX_JUMP_LIMIT`]
    /// How many pipeline jumps a query may make: the request phase's rules this many, and from an
    /// answer action's first jump on (the rule-level jumps after it included) this many again, at
    /// most [`MAX_JUMP_LIMIT`]
    pub response_jump_limit: u32,
    /// UDP 上游连接池大小。 / UDP upstream connection pool size
    pub udp_pool_size: usize,
    /// TCP 上游连接池大小。 / TCP upstream connection pool size
    pub tcp_pool_size: usize,
    /// DoH 上游连接池大小（每个 upstream 的最大空闲连接数）。 / DoH upstream pool size (max idle per host)
    pub doh_pool_size: usize,
    /// DoH 健康检查错误阈值（连续传输错误多少次后重建连接池以驱逐死连接）。 / DoH health check error threshold (rebuild pool after N consecutive transport errors to evict dead connections)
    /// 默认 3 次，0 表示禁用健康检查 / Default 3, 0 means disable health check
    pub doh_health_check_error_threshold: usize,
    /// DoT 上游连接池大小。 / DoT upstream connection pool size
    pub dot_pool_size: usize,
    /// DoQ 上游连接池大小。 / DoQ upstream connection pool size
    pub doq_pool_size: usize,
    /// TCP 连接最大存活时间（秒，超过强制重置） / TCP connection max age (seconds, force reset after this time)
    /// 0 表示禁用连接老化检查 / 0 means disable connection aging check
    pub tcp_connection_max_age_seconds: u64,
    /// TCP 连接空闲超时（秒，无请求超过此时间重置） / TCP connection idle timeout (seconds, reset if no requests for this time)
    /// 0 表示禁用空闲超时检查 / 0 means disable idle timeout check
    pub tcp_connection_idle_timeout_seconds: u64,
    /// DoQ 连接空闲超时（秒）。 / DoQ connection idle timeout (seconds)
    pub doq_connection_idle_timeout_seconds: u64,
    /// DoQ keepalive 间隔（毫秒）。0 表示禁用。 / DoQ keepalive interval (ms). 0 disables.
    pub doq_keepalive_interval_ms: u64,
    /// 是否启用 DoQ 0-RTT（默认 true）。 / Enable DoQ 0-RTT (default true)
    pub doq_enable_0rtt: bool,
    /// 智能流控（默认关）：不用填数字，内核运行时自己判断，见 `engine::concurrency`。以前的
    /// `flow_control_initial_permits` 等五个数字已经删掉，旧配置里留着也照常加载，不起作用
    /// Smart flow control (off by default): no numbers to fill in, the kernel judges at run time,
    /// see `engine::concurrency`. The five numbers such as `flow_control_initial_permits` it used
    /// to have are gone; an old configuration still holding them loads as before, to no effect
    pub flow_control_enabled: bool,
    /// RFC 8767: 上游不可用时返回过期缓存（默认 false）/ RFC 8767: Serve stale cached data when upstream is unavailable (default false)
    pub serve_stale: bool,
    /// RFC 8767: 过期缓存响应的 TTL（秒，默认 30）/ RFC 8767: TTL for stale responses (seconds, default 30)
    /// 对应 Unbound serve-expired-reply-ttl / Corresponds to Unbound serve-expired-reply-ttl
    pub serve_stale_ttl: u32,
    /// RFC 8767: 过期缓存可被服务的最大时间窗口（秒，默认 86400）
    /// 当缓存过期超过此时间后不再返回 stale 数据。0 表示无限制。
    /// RFC 8767: Maximum time window for serving stale cache (seconds, default 86400)
    /// Don't serve stale data after the entry has been expired for longer than this. 0 means no limit.
    /// 对应 Unbound serve-expired-ttl / Corresponds to Unbound serve-expired-ttl
    pub serve_stale_expire_ttl: u64,
    /// RFC 8767：过期应答的后台刷新失败以后，从这次失败起重新算它还能续用多久（默认 false）。上游一直取不到新的、又一直
    /// 有人问的名字，就一直交出过期应答，不受 serve_stale_expire_ttl 限制。对应 Unbound 的 serve-expired-ttl-reset，
    /// 那边默认也关
    /// RFC 8767: once the background refresh of a stale answer fails, how long it may still be
    /// served counts afresh from that failure (default false). A name the upstream keeps giving
    /// nothing new for, and that keeps being asked, then goes out stale beyond
    /// serve_stale_expire_ttl. Corresponds to Unbound's serve-expired-ttl-reset, off there too
    pub serve_stale_ttl_reset: bool,
    /// RFC 8767: 返回过期缓存前尝试上游查询的超时（毫秒，默认 0）
    /// 0 = 立即返回过期缓存（乐观模式）。 > 0 = 先尝试上游查询，超时后返回过期缓存。
    /// RFC 8767: Client timeout before serving stale (ms, default 0)
    /// 0 = serve stale immediately (optimistic mode). > 0 = try upstream first, serve stale on timeout.
    /// 对应 Unbound serve-expired-client-timeout / Corresponds to Unbound serve-expired-client-timeout
    pub serve_stale_client_timeout_ms: u64,
    /// 缓存后台刷新是否启用（默认false） / Enable cache background refresh (default false)
    pub cache_background_refresh: bool,
    /// 缓存后台刷新阈值（百分比，默认10）。当剩余TTL低于此百分比时触发后台刷新 / Cache background refresh threshold (percentage, default 10). Trigger background refresh when remaining TTL below this percentage
    pub cache_refresh_threshold_percent: u8,
    /// 缓存后台刷新最小TTL（秒，默认5）。防止TTL过短导致无限循环刷新 / Cache background refresh minimum TTL (seconds, default 5). Prevent infinite refresh loop for very short TTLs
    pub cache_refresh_min_ttl: u32,
    /// GeoIP 数据库文件路径（MMDB 格式） / GeoIP database file path (MMDB format)
    pub geoip_db_path: Option<String>,
    /// GeoIP 数据文件路径（V2Ray .dat 格式） / GeoIP data file path (V2Ray .dat format)
    pub geoip_dat_path: Option<String>,
    /// GeoSite 数据文件路径列表（V2Ray 格式，支持多个文件） / GeoSite data file paths (V2Ray format, supports multiple files)
    pub geosite_data_paths: Vec<String>,
    /// UDP 失败时是否自动 fallback 到 TCP（默认 true）。 / UDP failure automatically fallbacks to TCP (default true)
    pub enable_tcp_fallback: bool,
}

/// 全局设置的默认值只写在这里：配置里没写的设置照这里取（见 `GlobalSettings` 上的 `#[serde(default)]`）。以前每个字段
/// 另有一个默认值函数，同一个数写两遍，还得靠测试守着两边一致
/// The global settings' defaults are written here alone: a setting a configuration leaves out
/// takes its value from here (see `#[serde(default)]` on `GlobalSettings`). Every field used to
/// have a default function of its own besides, the same number written twice, with a test to
/// keep the two in step
impl Default for GlobalSettings {
    fn default() -> Self {
        Self {
            min_ttl: 0,
            bind_udp: "0.0.0.0:5533".to_string(),
            bind_tcp: "0.0.0.0:5533".to_string(),
            bind_doh: None,
            doh_tls_cert: None,
            doh_tls_key: None,
            // RFC 8484 用的路径 / The path RFC 8484 uses
            doh_path: "/dns-query".to_string(),
            default_upstream: "1.1.1.1:53".to_string(),
            default_upstream_pre_split: None,
            default_upstream_shared: None,
            bootstrap: String::new(),
            // 9 秒：DoQ 服务器（特别是阿里 DNS）可能要等更久才回，和 idoq 库的建议一致
            // 9 seconds: DoQ servers (Alibaba DNS especially) may take longer to answer, as the
            // idoq library advises
            upstream_timeout_ms: 9000,
            request_timeout_ms: None, // 默认自动计算 / Auto-calculated by default
            response_jump_limit: 10,
            udp_pool_size: 64,
            tcp_pool_size: 64,
            doh_pool_size: 8,
            // 连续 3 次传输错误后重建连接池 / Rebuild pool after 3 consecutive transport errors
            doh_health_check_error_threshold: 3,
            dot_pool_size: 64,
            doq_pool_size: 16,
            tcp_connection_max_age_seconds: 300, // 5 分钟 / 5 minutes
            tcp_connection_idle_timeout_seconds: 60, // 1 分钟 / 1 minute
            doq_connection_idle_timeout_seconds: 60, // 1 分钟 / 1 minute
            doq_keepalive_interval_ms: 15_000,
            // 默认启用 0-RTT，系统会自动检测并回退不支持的服务器
            // Enabled by default - system automatically detects and falls back for unsupported servers
            doq_enable_0rtt: true,
            flow_control_enabled: false,
            cache_capacity: 10_000,
            cache_max_ttl: 86400,
            dashmap_shards: 0, // 0 means use DashMap default (num_cpus * 4)
            serve_stale: false,
            serve_stale_ttl: 30,
            serve_stale_expire_ttl: 86400,
            serve_stale_ttl_reset: false,
            serve_stale_client_timeout_ms: 0,
            cache_background_refresh: false,
            cache_refresh_threshold_percent: 10,
            cache_refresh_min_ttl: 5,
            geoip_db_path: None,
            geoip_dat_path: None,
            geosite_data_paths: Vec::new(),
            enable_tcp_fallback: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
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

#[derive(Debug, Clone, Deserialize, Serialize)]
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

/// 请求匹配器：规则和 pipeline_select 用的是同一套，pipeline_select 另外认 `listener_label`
/// A request matcher: rules and pipeline_select share the one set, pipeline_select also taking
/// `listener_label`
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Matcher {
    Any,
    /// 入口标签（启动参数 `--listener-label`），不分大小写。只有 pipeline_select 看得到是哪个入口收的查询，规则里
    /// 写了编译不过 / The entry label (the `--listener-label` startup argument), ignoring case.
    /// Only pipeline_select sees which entry took the query; written in a rule it does not
    /// compile
    ListenerLabel {
        value: String,
    },
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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PipelineSelectRule {
    pub pipeline: String,
    #[serde(default)]
    pub matchers: Vec<MatcherWithOp>,
    #[serde(default = "default_match_operator")]
    pub matcher_operator: MatchOperator,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MatcherWithOp {
    #[serde(default = "default_match_operator")]
    pub operator: MatchOperator,
    #[serde(flatten)]
    pub matcher: Matcher,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ResponseMatcherWithOp {
    #[serde(default = "default_match_operator")]
    pub operator: MatchOperator,
    #[serde(flatten)]
    pub matcher: ResponseMatcher,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
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

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Action {
    /// 记录日志，level可选：trace/debug/info/warn/error / Log action, level options: trace/debug/info/warn/error
    Log { level: Option<String> },
    /// 固定响应rcode（如 NXDOMAIN/NOERROR）。 / Static response rcode (e.g., NXDOMAIN/NOERROR)
    StaticResponse {
        rcode: String,
        /// 编好的应答（见 [`Action::compile_answer`]）/ The answer compiled (see [`Action::compile_answer`])
        #[serde(skip)]
        answer: StaticAnswer,
    },
    /// 返回一个或逗号分隔的多个固定 IPv4/IPv6 地址。 / Return one or more comma-separated static IPv4/IPv6 addresses.
    StaticIpResponse {
        ip: String,
        /// 编好的应答（见 [`Action::compile_answer`]）/ The answer compiled (see [`Action::compile_answer`])
        #[serde(skip)]
        answer: StaticAnswer,
    },
    /// 返回固定 CNAME 记录。 / Return a static CNAME record.
    StaticCnameResponse {
        /// CNAME 目标域名 / Canonical target domain name
        target: String,
        /// TTL（可选，默认 [`StaticAnswer::DEFAULT_TTL`]）/ TTL (optional, [`StaticAnswer::DEFAULT_TTL`] by default)
        #[serde(default)]
        ttl: Option<u32>,
        /// 编好的应答（见 [`Action::compile_answer`]）/ The answer compiled (see [`Action::compile_answer`])
        #[serde(skip)]
        answer: StaticAnswer,
    },
    /// 返回固定 TXT 记录。支持单个字符串或字符串数组。 / Return static TXT record. Supports single string or string array.
    StaticTxtResponse {
        /// TXT 记录内容 / TXT record content
        #[serde(deserialize_with = "deserialize_txt_text")]
        text: Vec<String>,
        /// TTL（可选，默认 [`StaticAnswer::DEFAULT_TTL`]）/ TTL (optional, [`StaticAnswer::DEFAULT_TTL`] by default)
        #[serde(default)]
        ttl: Option<u32>,
        /// 编好的应答（见 [`Action::compile_answer`]）/ The answer compiled (see [`Action::compile_answer`])
        #[serde(skip)]
        answer: StaticAnswer,
    },
    /// 跳转到指定 Pipeline 继续处理。目标名字读进来就是共用的一份，每次跳转不再各复制一份
    /// Jump to specified Pipeline to continue processing. The target's name is read in as one
    /// shared copy, so no jump makes a copy of its own
    JumpToPipeline { pipeline: Arc<str> },
    /// 终止匹配。请求阶段使用默认上游，响应阶段使用当前响应。 / Terminate matching. Request phase uses default upstream, response phase uses current response
    Allow,
    /// 终止并丢弃（返回 REFUSED）。 / Terminate and drop (return REFUSED)
    Deny,
    /// 透传上游；不写 upstream（或写成 null、[]）时用全局默认上游，写成空字符串不算，那是一个也没写的上游
    /// （见 `problems`）；支持逗号分隔或数组格式的多个上游（并发请求取最快结果）；transport缺省udp。
    /// 支持 udp/tcp/tcp_udp/doh/dot/doq。/ Forward to upstream; without upstream (or with
    /// null or []) the global default upstream is used, while an empty string is not, being an
    /// upstream list that names none (see `problems`); supports comma-separated or array
    /// format for multiple upstreams (concurrent requests, take fastest result); transport
    /// defaults to udp; supports udp/tcp/tcp_udp/doh/dot/doq.
    Forward {
        #[serde(default, deserialize_with = "deserialize_upstream")]
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
        /// `upstream` 的一份共用的副本（性能优化）/ A shared copy of `upstream` (performance optimization)
        #[serde(skip)]
        upstream_shared: Option<Arc<str>>,
    },
    /// 继续匹配后续规则。响应阶段会复用当前响应结果。 / Continue matching subsequent rules. Response phase will reuse current response result
    Continue,
    /// 修改响应中的 TXT 记录 / Modify TXT records in response
    ReplaceTxtResponse {
        /// 新的 TXT 内容 / New TXT content
        #[serde(deserialize_with = "deserialize_txt_text")]
        text: Vec<String>,
        /// 换成的应答，编好的（见 [`Action::compile_answer`]）/ The answer it replaces with,
        /// compiled (see [`Action::compile_answer`])
        #[serde(skip)]
        answer: StaticAnswer,
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
            upstream_shared,
            ..
        } = self
        {
            *pre_split_upstreams = Some(Arc::new(
                split_upstreams(upstream_str).map(Arc::from).collect(),
            ));
            *upstream_shared = Some(Arc::from(upstream_str.as_str()));
        }
    }

    /// 把作答动作写的应答编好存在它身上（配置加载时调用）：RCODE、地址、CNAME 目标、TXT 文本和 TTL 都读好，每个查询照它给
    /// 记录（见 [`StaticAnswer`]）
    /// Compile the answer an answering action writes and keep it on the action (called at
    /// config load): the RCODE, addresses, CNAME target, TXT text and TTL read once, every query
    /// given its records by it (see [`StaticAnswer`])
    pub fn compile_answer(&mut self) {
        match self {
            Action::StaticResponse { rcode, answer } => *answer = StaticAnswer::rcode(rcode),
            Action::StaticIpResponse { ip, answer } => *answer = StaticAnswer::addresses(ip),
            Action::StaticCnameResponse {
                target,
                ttl,
                answer,
            } => *answer = StaticAnswer::cname(target, *ttl),
            Action::StaticTxtResponse { text, ttl, answer } => {
                *answer = StaticAnswer::txt(text, *ttl);
            }
            Action::ReplaceTxtResponse { text, answer } => *answer = StaticAnswer::txt(text, None),
            _ => {}
        }
    }

    /// 这个动作作答时给的静态应答（static_response、static_ip_response、static_cname_response、static_txt_response、
    /// deny），别的动作为 None。replace_txt_response 不算：它要换掉手上的应答，没有就不作答
    /// The static answer this action gives when it answers (static_response,
    /// static_ip_response, static_cname_response, static_txt_response, deny), None for any other
    /// action. replace_txt_response does not count: it replaces the answer in hand, and with none
    /// it gives no answer
    pub fn static_answer(&self) -> Option<&StaticAnswer> {
        static DENY: StaticAnswer = StaticAnswer::DENY;
        match self {
            Action::StaticResponse { answer, .. }
            | Action::StaticIpResponse { answer, .. }
            | Action::StaticCnameResponse { answer, .. }
            | Action::StaticTxtResponse { answer, .. } => Some(answer),
            Action::Deny => Some(&DENY),
            _ => None,
        }
    }
}

/// Rule helper functions / Rule 辅助函数
impl Rule {
    /// 合并转发时问的那几个 forward（写了地址的，见 `compute_merged_forward`）共用的 ecs：写得一样
    /// 时就是它，写得不一样时为 Err。合并后只有一次转发，只能发一个 ECS
    /// The ecs shared by the forwards a merged forward asks (those naming an address, see
    /// `compute_merged_forward`): it when they all write the same, Err when they differ. The
    /// merge is a single forward and can send only one ECS
    pub(crate) fn shared_forward_ecs(&self) -> Result<Option<&EcsMode>, ()> {
        let mut ecs = self.actions.iter().filter_map(|action| match action {
            Action::Forward {
                upstream: Some(upstream),
                ecs,
                ..
            } if names_an_address(upstream) => Some(ecs.as_ref()),
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
        // 动作按写的顺序执行，合并只在轮到 forward 时才算：forward 前面已经写了别的作决定的动作（日志不作决定）
        // 时，规则给的是那个动作的结果，后面的 forward 轮不到。不这样的话，这条规则走完整路径时去转发，走
        // 快速路径时照第一个动作回静态应答
        // Actions run in the order written, and the merge counts only when a forward's turn
        // comes: with another deciding action written before the forwards (a log decides
        // nothing), what the rule gives is that action's outcome and the forwards never have
        // their turn. Otherwise the rule forwards on the full path while the fast path answers
        // its static first action
        let first_to_decide = self
            .actions
            .iter()
            .find(|action| !matches!(action, Action::Log { .. }));
        if !matches!(first_to_decide, Some(Action::Forward { .. })) {
            return;
        }

        // 每种传输一组，各组按 `Transport::ALL` 的顺序排进合并后的列表 / One set per transport, each
        // going into the merged list in the order of `Transport::ALL`
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
                    // 前缀照单个转发那样认，没有前缀或前缀不认识时用这个动作的传输。TCP 和 UDP 双发的
                    // 上游只记一份，合并后仍然双发
                    // The prefix is read as for a single forward, the action's transport taken
                    // without one or for one it does not know. An upstream asked over TCP and
                    // UDP at once is recorded once and still asked both ways after the merge
                    let (address, transport) = parse_upstream_addr(addr, action_transport);
                    sets[transport as usize].insert(format!("{}://{address}", transport.label()));
                }
            }
        }

        let all_upstreams: Vec<Arc<str>> = Transport::ALL
            .iter()
            .flat_map(|&transport| {
                sets[transport as usize]
                    .iter()
                    .map(|s| Arc::from(s.as_str()))
            })
            .collect();

        if all_upstreams.is_empty() {
            tracing::debug!(
                rule = %self.name,
                forward_count,
                "all forward actions have empty upstream, merged_forward not set"
            );
            self.merged_forward = None;
        } else {
            tracing::debug!(
                rule = %self.name,
                forward_count,
                tcp_count = sets[Transport::Tcp as usize].len(),
                udp_count = sets[Transport::Udp as usize].len(),
                tcp_udp_count = sets[Transport::TcpUdp as usize].len(),
                doh_count = sets[Transport::Doh as usize].len(),
                dot_count = sets[Transport::Dot as usize].len(),
                doq_count = sets[Transport::Doq as usize].len(),
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
                // 写得不一样时不发，启动时 `problems` 记一条错误 / None when they differ;
                // at startup `problems` logs an error
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

/// `dashmap_shards` 的上限。每个分片启动时就占六百来字节（缓存行对齐的锁，加上容量摊到每片至少一条时的四格小表），
/// 65536 片四十来 MB，再翻一倍就是八十来 MB，同时在途的查询也用不了那么多片。超过的按它截断（见
/// [`GlobalSettings::hold_to_limits`]）
/// The most `dashmap_shards` may be. Each shard takes some six hundred bytes from startup (a
/// cache-padded lock and a four-slot table, the capacity spread to at least one entry a
/// shard), so 65536 shards are some forty MB, and twice as many some eighty MB, more shards
/// than the queries in flight together could ever use. More is held to it (see
/// [`GlobalSettings::hold_to_limits`])
pub const MAX_DASHMAP_SHARDS: usize = 65_536;

/// 每个连接池（`udp_pool_size`、`tcp_pool_size`、`doh_pool_size`、`dot_pool_size`、`doq_pool_size`）最多多大，
/// 默认值最大的也只有 64。UDP 池启动时就给每个地址族各开这么多 socket，两族最多 2048 个，在文档里的 systemd 服务和
/// 面板的 OpenWrt 包设的 65536 个描述符以内；其余的池给每个上游备好这么多客户端。超过的按它截断（见
/// [`GlobalSettings::hold_to_limits`]）。以前不设上限：多到开不出来的 socket，热重载和面板保存照样收下，下次启动才起
/// 不来；大到 2^64 的数建池时分配不出内存，内核直接退出
/// How large each connection pool (`udp_pool_size`, `tcp_pool_size`, `doh_pool_size`,
/// `dot_pool_size`, `doq_pool_size`) may be, the largest default being 64. The UDP pool opens
/// this many sockets per address family at startup, at most 2048 for both, within the 65536
/// descriptors the systemd service in the docs and the panel's `OpenWrt` package allow; the
/// other pools set up this many clients per upstream. More is held to it (see
/// [`GlobalSettings::hold_to_limits`]). There used to be no limit: more sockets than could be
/// opened were accepted by a hot reload and a panel save and failed only at the next start,
/// and a number as large as 2^64 could not be allocated as the pool was built, taking the
/// kernel down
pub const MAX_POOL_SIZE: usize = 1024;

/// `response_jump_limit` 的上限。每跳一次都要再走一遍目标的规则（快速路径还要记下这一跳），几个 Pipeline 互相跳转时，
/// 一个查询要跳满上限才回 SERVFAIL：上限是五百万时一个查询要 7.8 秒、六百多 MB。回答阶段绕圈更贵：跳过去的规则又转发，
/// 每跳一次再问一次上游，跳满 64 次的查询问了上游 65 次。64 次远多于正经配置串起来的 Pipeline，请求阶段跳满也只是把
/// 规则多走几十遍；绕成圈的跳转在配置生效时报一条告警（见 [`warnings`]）。超过的按它截断（见
/// [`GlobalSettings::hold_to_limits`]）
/// The most `response_jump_limit` may be. Each jump runs the target's rules again (and the fast
/// path keeps a record of it), and with pipelines jumping to each other a query jumps the whole
/// limit before it answers SERVFAIL: at five million one query takes 7.8 seconds and over six
/// hundred MB. Going round in the answer phase costs more: the rules jumped to forward again,
/// asking an upstream once more on every jump, and a query that jumps all 64 times has asked
/// upstreams 65 times. 64 jumps are far more than any sound configuration chains pipelines, and
/// in the request phase jumping them all is no more than running the rules some tens of times;
/// jumps that go round in a circle are warned about as the configuration takes effect (see
/// [`warnings`]). More is held to it (see [`GlobalSettings::hold_to_limits`])
pub const MAX_JUMP_LIMIT: u32 = 64;

/// 有上限的设置，每项写一次：字段和它的上限。说哪些超了的 `over_limits`（算 [`problems`]）和把它们截到上限的
/// `hold_to_limits` 都由这张表生成
/// The settings with a limit, each written once: the field and its limit. Both `over_limits`
/// (among [`problems`]), telling which are over, and `hold_to_limits`, holding them to their
/// limits, are made from this table
macro_rules! limited_settings {
    ($($setting:ident: $most:expr),* $(,)?) => {
        impl GlobalSettings {
            /// 超过上限的设置（见 `limited_settings!`），每项一句，值不动。它们算 [`problems`]：启动时记一条错误、按上限照常
            /// 起来（见 [`Self::hold_to_limits`]），没有上限时能用的配置（`tcp_pool_size: 2048`）升级以后照样起得来；重载和
            /// 面板保存拒绝
            /// The settings over their limits (see `limited_settings!`), a sentence each, the
            /// values left as they are. They count among [`problems`]: startup logs an error and
            /// starts at the limit (see [`Self::hold_to_limits`]), so a configuration that worked
            /// before there were limits (`tcp_pool_size: 2048`) still starts after an upgrade,
            /// while a reload and a panel save refuse it
            fn over_limits(&self) -> Vec<String> {
                let mut over = Vec::new();
                $(
                    if self.$setting > $most {
                        over.push(format!(
                            "settings.{}: {} is more than {most}, the most it may be; startup uses {most} instead",
                            stringify!($setting),
                            self.$setting,
                            most = $most,
                        ));
                    }
                )*
                over
            }

            /// 把超过上限的设置截到上限（见 `limited_settings!`；说它们的是 `over_limits`，算 [`problems`]）。编译配置时
            /// 先截（见 `RuntimePipelineConfig::from_config`）
            /// Holds the settings over their limits to them (see `limited_settings!`;
            /// `over_limits` names them, among [`problems`]). Compiling a configuration holds
            /// them first (see `RuntimePipelineConfig::from_config`)
            pub fn hold_to_limits(&mut self) {
                $(self.$setting = self.$setting.min($most);)*
            }
        }
    };
}

limited_settings!(
    dashmap_shards: MAX_DASHMAP_SHARDS,
    udp_pool_size: MAX_POOL_SIZE,
    tcp_pool_size: MAX_POOL_SIZE,
    doh_pool_size: MAX_POOL_SIZE,
    dot_pool_size: MAX_POOL_SIZE,
    doq_pool_size: MAX_POOL_SIZE,
    response_jump_limit: MAX_JUMP_LIMIT,
);

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
            // 重载即生效（统计开关、GeoIP 自动转换和国家过滤已经不起作用）
            // Applied on a reload (the statistics switches, GeoIP auto-conversion and
            // country filter no longer do anything)
            reload: [
                min_ttl,
                default_upstream,
                default_upstream_pre_split,
                default_upstream_shared,
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
                geosite_data_paths,
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
                tcp_connection_max_age_seconds,
                tcp_connection_idle_timeout_seconds,
                doq_connection_idle_timeout_seconds,
                doq_keepalive_interval_ms,
                doq_enable_0rtt,
                bootstrap,
                flow_control_enabled,
            ],
        )
    }

    /// Parse the listener addresses and check the DoH prerequisites the way
    /// server startup does; a configuration that fails here cannot be served.
    /// Both the server and [`validate`] call this. Each error starts with the
    /// setting it is about, as `settings.bind_udp: "localhost:53" …`.
    /// 按服务器启动的方式解析监听地址并检查 DoH 前置条件；此处失败的配置无法启动。
    /// 服务器与 [`validate`] 都调用它。每个错误开头写着说的是哪个设置，如 `settings.bind_udp: "localhost:53" …`。
    pub fn listeners(&self) -> anyhow::Result<ListenerConfig> {
        let address = |setting: &str, value: &str| {
            value.parse::<SocketAddr>().with_context(|| {
                format!("settings.{setting}: \"{value}\" is not an IP address and port")
            })
        };
        let udp = address("bind_udp", &self.bind_udp)?;
        let tcp = address("bind_tcp", &self.bind_tcp)?;
        let doh = match &self.bind_doh {
            Some(bind_doh) => {
                let required = |setting: &str, value: &Option<String>| {
                    value.clone().with_context(|| {
                        format!(
                            "settings.{setting}: not set, though settings.bind_doh is \"{bind_doh}\" and DoH needs it"
                        )
                    })
                };
                Some(DohListenerConfig {
                    bind: address("bind_doh", bind_doh)?,
                    tls_cert: required("doh_tls_cert", &self.doh_tls_cert)?,
                    tls_key: required("doh_tls_key", &self.doh_tls_key)?,
                    path: self.doh_path.clone(),
                })
            }
            None => None,
        };
        Ok(ListenerConfig { udp, tcp, doh })
    }

    /// 不写 `request_timeout_ms` 时的整体超时（毫秒）：上游超时的两倍半，三分之一处重发、等满一段、失败了再用 TCP 等一段，
    /// 再留一点余量；算出来超出 u64 时取 u64::MAX
    /// The overall timeout (milliseconds) when `request_timeout_ms` is not written: two and a
    /// half upstream timeouts, for the resend at a third, a whole wait, one more over TCP on
    /// failure and a little margin; u64::MAX when that is more than a u64 holds
    pub(crate) fn default_request_timeout_ms(&self) -> u64 {
        let upstream = self.upstream_timeout_ms;
        upstream.saturating_mul(2).saturating_add(upstream / 2)
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

    /// `default_upstream`，配置加载时算好的那份，转发不用为它分配内存 / `default_upstream`, the copy
    /// made at config load, so that a forward allocates nothing for it
    pub(crate) fn default_upstream_arc(&self) -> Arc<str> {
        self.default_upstream_shared
            .clone()
            .unwrap_or_else(|| Arc::from(self.default_upstream.as_str()))
    }

    /// 设置自身是否说得通：取值范围、相互之间的关系，以及只在启动时读、却得和建引擎时的前提一致的那几项。编译配置的第一步，
    /// 启动、热重载和面板校验都经过这里。每个错误是一行英文，开头写着设置和它的值，如 `settings.cache_capacity: 0 …`，
    /// 和 [`problems`] 的写法一样
    /// Whether the settings make sense on their own: their ranges, how they relate, and the few read
    /// only at startup that must agree with what building the engine needs. The first step of
    /// compiling a configuration, which startup, hot reloads and panel validation all go through.
    /// Each error is a line in English starting with the setting and its value, as
    /// `settings.cache_capacity: 0 …`, written as [`problems`] are
    pub fn validate(&self) -> anyhow::Result<()> {
        // Validate cache_capacity configuration
        if self.cache_capacity == 0 {
            anyhow::bail!(
                "settings.cache_capacity: 0 leaves the cache no room for any answer; it must be greater than 0"
            );
        }
        // cache_max_ttl = 0 会让每条应答的缓存 TTL 归零，等于静默关掉缓存，
        // 与 cache_capacity = 0 同样不是有效配置。
        // cache_max_ttl = 0 clamps every entry's TTL to zero, silently disabling
        // the cache, which is no more a valid configuration than cache_capacity = 0.
        if self.cache_max_ttl == 0 {
            anyhow::bail!(
                "settings.cache_max_ttl: 0 holds the TTL of every answer cached to 0, leaving the cache unused; it must be greater than 0"
            );
        }
        // 阈值是条目 TTL 的百分比，刷新条件是剩余 TTL 低于它。取 100 时阈值等于
        // 条目自身的 TTL，任何时间一过就满足，和超过 100 一样每次缓存命中都触发
        // 后台刷新，上游负载等于客户端负载；要关闭刷新请用 cache_background_refresh。
        // The threshold is a percentage of the entry's TTL and a refresh happens
        // once the remaining TTL falls below it. At 100 the threshold equals the
        // entry's own TTL, so any elapsed time satisfies it and, like a value
        // above 100, every cache hit triggers a refresh and the upstream carries
        // the client's full load. Use cache_background_refresh to turn it off.
        if self.cache_refresh_threshold_percent >= 100 {
            anyhow::bail!(
                "settings.cache_refresh_threshold_percent: {} makes every cache hit refresh upstream; it must be below 100",
                self.cache_refresh_threshold_percent
            );
        }
        // upstream_timeout_ms = 0 让每次上游请求在发出的同一刻就超时，任何查询
        // 都不可能拿到应答。它没有"不限时"的含义，那是 request_timeout_ms 留空
        // 时的自动推导在管的事。
        // upstream_timeout_ms = 0 expires every upstream request the instant it
        // is issued, so no query can ever be answered. It does not mean "no
        // limit"; leaving request_timeout_ms unset is what derives a budget.
        if self.upstream_timeout_ms == 0 {
            anyhow::bail!(
                "settings.upstream_timeout_ms: 0 expires every upstream request as it is sent; it must be greater than 0"
            );
        }
        // 只在启动时读的设置，校验得和建引擎时的前提一致：校验放过了、建引擎时才出错的值，热重载和面板保存都会
        // 收下，到下次重启内核就起不来。DashMap 要求分片数是大于 1 的 2 的幂，不是的从来起不来；分片太多、连接池太大
        // 一次就要分配太多，那是按上限截断（见 `hold_to_limits`）
        // Settings read only at startup are checked against what building the engine needs: a value
        // the check lets through and the build then fails on is accepted by a hot reload and a panel
        // save, and the kernel does not start at the next restart. DashMap needs a power of two
        // above 1 for its shards, and with any other number it never started; too many shards or
        // too large a pool take too much at once, which is held to the limits instead (see
        // `hold_to_limits`)
        let shards = self.dashmap_shards;
        if shards != 0 && !(shards.is_power_of_two() && shards >= 2) {
            anyhow::bail!(
                "settings.dashmap_shards: {shards} is neither 0 (the default) nor a power of two from 2 to {MAX_DASHMAP_SHARDS}"
            );
        }
        let doq_idle = self.doq_connection_idle_timeout_seconds;
        if doq_idle > 0
            && quinn::IdleTimeout::try_from(std::time::Duration::from_secs(doq_idle)).is_err()
        {
            anyhow::bail!(
                "settings.doq_connection_idle_timeout_seconds: {doq_idle} is more than QUIC can carry"
            );
        }

        // Validate request_timeout >= upstream_timeout
        // 验证 request_timeout >= upstream_timeout
        if let Some(request_timeout) = self.request_timeout_ms
            && request_timeout < self.upstream_timeout_ms
        {
            anyhow::bail!(
                "settings.request_timeout_ms: {request_timeout} is less than settings.upstream_timeout_ms ({upstream}); it must be at least that",
                upstream = self.upstream_timeout_ms
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Copy, PartialEq, Eq, Hash)]
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

impl Transport {
    /// 每种传输，按合并的转发给上游分组的顺序（见 [`Rule::compute_merged_forward`]）/ Every transport, in
    /// the order a merged forward groups its upstreams by (see [`Rule::compute_merged_forward`])
    pub(crate) const ALL: [Self; 6] = [
        Self::Tcp,
        Self::Udp,
        Self::TcpUdp,
        Self::Doh,
        Self::Dot,
        Self::Doq,
    ];

    /// 传输的名字：上游地址的前缀（`tcp://1.1.1.1:53`）和作答上游的名字（`tcp:1.1.1.1:53`，见 [`split_answered`]）都这样
    /// 写，写出来的和读回去的（见 [`Self::from_label`]）是这同一份
    /// The transport's name, as an upstream address's prefix (`tcp://1.1.1.1:53`) and an
    /// answering upstream's name (`tcp:1.1.1.1:53`, see [`split_answered`]) write it alike, the
    /// one table both writing and reading (see [`Self::from_label`]) go by
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::TcpUdp => "tcp+udp",
            Self::Doh => "doh",
            Self::Dot => "dot",
            Self::Doq => "doq",
        }
    }

    /// 名字是 `label` 的传输（见 [`Self::label`]），不分大小写；前缀另外还认 udp+tcp、https、tls、quic。不认识的为 None
    /// （[`parse_upstream_addr`] 这时用默认传输）
    /// The transport named `label` (see [`Self::label`]), in any case; a prefix may also be
    /// udp+tcp, https, tls or quic. None for one it does not know ([`parse_upstream_addr`] then
    /// takes the default transport)
    pub(crate) fn from_label(label: &str) -> Option<Self> {
        const ALIASES: [(&str, Transport); 4] = [
            ("udp+tcp", Transport::TcpUdp),
            ("https", Transport::Doh),
            ("tls", Transport::Dot),
            ("quic", Transport::Doq),
        ];
        // 每个转发都要看一次，不为大小写分配内存 / Every forward looks once, so case costs no allocation
        Self::ALL
            .into_iter()
            .map(|transport| (transport.label(), transport))
            .chain(ALIASES)
            .find_map(|(name, transport)| label.eq_ignore_ascii_case(name).then_some(transport))
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Copy, PartialEq, Eq)]
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
    Ok((cfg, raw))
}

/// 从 JSON 文本解析配置，找出写了却不读的键（见 [`unread_keys`]），不访问文件系统。JSON 层的错误带行列位置。
/// 预先算好的东西（拆好的上游、合并的转发）编译时才算（见 `RuntimePipelineConfig::from_config`），只算一遍；编译不了的
/// 写法（比如写错的网段）也在编译时连同位置报出来
/// Parse a configuration from its JSON text, finding the keys it writes that are not read (see
/// [`unread_keys`]), without touching the filesystem. Errors from the JSON layer carry
/// line/column positions. What is worked out ahead of time (the upstreams split, the merged
/// forwards) is worked out once, as it compiles (see `RuntimePipelineConfig::from_config`), and
/// what cannot be compiled (a mistyped network, say) is reported there with its place
pub fn parse_config(raw: &str) -> Result<PipelineConfig> {
    let mut cfg: PipelineConfig = serde_json::from_str(raw).context("parse config JSON")?;
    cfg.unread_keys = unread_keys(raw, &serde_json::to_value(&cfg)?)?;
    Ok(cfg)
}

/// 写成一个字符串或者一个字符串数组的值，读的时候不先缓冲下来逐种试：两种写法各个调用方自己再处理（拆逗号、去掉空白、
/// 连起来）；都不是时报「expected a string or an array of strings」，说清要的是什么
/// A value written as one string or as an array of strings, read without buffering it to try
/// each way in turn: each caller handles the two ways on its own (splitting at commas, trimming,
/// joining); anything else is refused as "expected a string or an array of strings", saying
/// what is wanted
enum StringOrList {
    String(String),
    List(Vec<String>),
}

impl<'de> Deserialize<'de> for StringOrList {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Expecting;

        impl<'de> Visitor<'de> for Expecting {
            type Value = StringOrList;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a string or an array of strings")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<StringOrList, E> {
                Ok(StringOrList::String(value.to_owned()))
            }

            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<StringOrList, E> {
                Ok(StringOrList::String(value))
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<StringOrList, A::Error> {
                let mut list = Vec::new();
                while let Some(value) = seq.next_element()? {
                    list.push(value);
                }
                Ok(StringOrList::List(list))
            }
        }

        deserializer.deserialize_any(Expecting)
    }
}

/// 反序列化 upstream 字段，支持字符串、逗号分隔字符串或数组格式；数组连成逗号分隔的一串，空数组和 null 一样是没写
/// Deserialize upstream field, supports string, comma-separated string, or array format; an
/// array is joined into one comma-separated string, and an empty one is as unwritten as null
fn deserialize_upstream<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(match Option::<StringOrList>::deserialize(deserializer)? {
        None => None,
        Some(StringOrList::String(upstreams)) => Some(upstreams),
        Some(StringOrList::List(upstreams)) => (!upstreams.is_empty()).then(|| upstreams.join(",")),
    })
}

/// 反序列化也可以写成数组的逗号分隔字符串：每一项去掉两头的空白，空的不要
/// Deserialize a comma-separated string field that also accepts an array of strings: each item
/// trimmed, and empty ones dropped
fn deserialize_string_or_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(match StringOrList::deserialize(deserializer)? {
        StringOrList::String(value) => value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect(),
        StringOrList::List(values) => values
            .into_iter()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .collect(),
    })
}

/// 反序列化TXT文本字段，支持单个字符串或字符串数组 / Deserialize TXT text field, supports single string or string array
fn deserialize_txt_text<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(match StringOrList::deserialize(deserializer)? {
        StringOrList::String(text) => vec![text],
        StringOrList::List(texts) => texts,
    })
}

/// EDNS Client Subnet (RFC 7871) 操作模式，用于 Forward 动作的请求改写。
/// EDNS Client Subnet (RFC 7871) operation mode, used by the Forward action for request rewriting.
///
/// 三种模式覆盖典型场景：
/// Three modes cover typical scenarios:
/// - `Clear`: 剥离客户端自带的 ECS（隐私保护）/ Strip client-provided ECS (privacy)
/// - `FromClientIp`: 从客户端来源 IP 推导 ECS 子网 / Derive ECS subnet from client source IP
/// - `Static`: 使用固定 IP/前缀（伪装特定地理位置）/ Use fixed IP/prefix (spoof geo-location)
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
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
        ip: crate::ecs::StaticEcsIp,
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
    /// 照样加载、值得知道的写法（见 [`warnings`]）/ What loads all the same yet is worth
    /// knowing (see [`warnings`])
    pub warnings: Vec<String>,
}

/// 一份配置编译成运行时配置，热重载、面板的校验和试用都走这里，拒掉的和启动时会让内核起不来的一样：会悄悄做成
/// 别的事的写法（见 [`problems`]，一条不落地放在错误 [`Problems`] 里）、编译不了的匹配器和正则，以及监听地址和 DoH 的
/// 前提（见 [`GlobalSettings::listeners`]）。以前热重载不查监听地址，`bind_udp` 写错了照样重载成功，等到重启内核才起不来。
/// 错误开头就写着是哪个设置或匹配器（`settings.bind_udp: …`、`pipelines[0].rules[2].matchers[1]: …`），不另加前缀，
/// 和启动时起不来的错误一样。启动不走这里：那时 [`problems`] 记成错误、照样加载
/// A configuration compiled into its runtime form, which hot reload and the panel's validation
/// and trial all go through, refusing what would stop the kernel at startup: what silently does
/// something else (see [`problems`], every one of them in the error, a [`Problems`]), matchers
/// and regexes that do not compile, and the listener addresses and DoH prerequisites (see
/// [`GlobalSettings::listeners`]). Hot reload used not to check the listeners, so a mistyped
/// `bind_udp` reloaded fine and the kernel then failed to start at the next restart. An error
/// starts with the setting or matcher it is about (`settings.bind_udp: …`,
/// `pipelines[0].rules[2].matchers[1]: …`) with no prefix added, as one stopping startup does.
/// Startup does not come here: there [`problems`] are logged as errors and loaded all the same
pub fn compile(cfg: PipelineConfig) -> Result<RuntimePipelineConfig> {
    refuse_problems(&cfg)?;
    let runtime = RuntimePipelineConfig::from_config(cfg)?;
    runtime.settings.listeners()?;
    Ok(runtime)
}

/// 按热重载的方式校验配置文本（见 [`compile`]）：JSON 解析、配置问题（见 [`problems`]，启动时只记错误、照样加载，
/// 这里和重载一样拒绝）、运行时编译（匹配器、正则、网段、超时）以及监听地址和 DoH 的前提（见
/// [`GlobalSettings::listeners`]：写了证书和私钥的路径）。不读证书、不绑端口：证书读不了、端口绑不上，到启动时才
/// 知道，那时 DNS 照常答，入站 DoH 不开，控制通道 `config` 结果的 `doh_error` 写着原因。错误带完整原因链；JSON 语法
/// 错误包含行列位置
/// Validate configuration text as a hot reload takes it (see [`compile`]): JSON parsing, the
/// configuration problems (see [`problems`], which startup only logs and loads all the same, refused
/// here as on a reload), runtime compilation (matchers, regexes, CIDRs, timeouts) and the
/// listener addresses and DoH prerequisites (see [`GlobalSettings::listeners`]: paths written
/// for the certificate and key). No certificate is read and no port bound: one that cannot be
/// read, or a port that cannot be bound, shows at startup, when DNS answers as usual without
/// inbound DoH and the control channel's `config` result gives the reason as `doh_error`.
/// Errors carry their cause chain; JSON syntax errors include the line and column
pub fn validate(raw: &str) -> Result<ValidationReport> {
    let cfg = parse_config(raw)?;
    let version = cfg.version.clone();
    let runtime = compile(cfg)?;
    Ok(ValidationReport {
        version,
        pipeline_count: runtime.pipelines.len(),
        rule_count: runtime.pipelines.iter().map(|p| p.rules.len()).sum(),
        warnings: runtime.warnings,
    })
}

/// 配置里会悄悄做成别的事的写法：读不懂的上游地址、拼错的 rcode、无效的静态 IP 或 CNAME 目标、
/// 装不进一条记录的 TXT、跳到不存在的 pipeline、值写成空而什么都匹配的匹配器（见
/// `AnyMatcher::written_empty`）、几个 pipeline 写了同一个 id、不是 IP 的静态 ECS 地址。以前这些都照常加载：
/// 上游一直失败、rcode 变成 NXDOMAIN、静态应答变成 SERVFAIL、空后缀什么都匹配。
///
/// 启动时记成错误、照样加载（超过上限的设置按上限用），已经在用的配置升级以后照样起得来；热重载和面板的校验
/// （见 [`validate`]）拒绝它们，下一次改配置时就得改掉。
///
/// Ways of writing a configuration that silently do something else: an upstream
/// address nothing can read, a misspelt rcode, an invalid static IP or CNAME target,
/// TXT content that does not fit a record, a jump to a pipeline that does not exist,
/// a matcher written empty that so matches everything (see `AnyMatcher::written_empty`),
/// several pipelines written with one id, a static ECS address that is no IP. These all used to load as
/// usual: the upstream kept failing, the rcode became NXDOMAIN, the static answer
/// became SERVFAIL, the empty suffix matched everything.
///
/// Startup only logs them and loads all the same (a setting over its limit held to it), so a
/// configuration in use still starts after an upgrade; a reload and the panel's validation
/// (see [`validate`]) refuse them, so the next change has to fix them.
pub fn problems(cfg: &PipelineConfig) -> Vec<String> {
    let pipelines: rustc_hash::FxHashSet<&str> =
        cfg.pipelines.iter().map(|p| p.id.as_str()).collect();
    let mut found = Vec::new();
    if split_upstreams(&cfg.settings.default_upstream)
        .next()
        .is_none()
    {
        found.push(format!("settings.default_upstream: {NO_UPSTREAM}"));
    }
    for upstream in split_upstreams(&cfg.settings.default_upstream) {
        if let Some(problem) = upstream_problem(upstream, Transport::Udp) {
            found.push(format!("settings.default_upstream: {problem}"));
        }
    }
    // bootstrap 自己就是解析上游名字的，只能写成 IP 和端口，经 UDP 问 / bootstrap is what resolves
    // upstream names, so it is written as an IP and a port only, asked over UDP
    for server in split_upstreams(&cfg.settings.bootstrap) {
        if let Err(error) = crate::engine::transport::check_upstream_address(server, Transport::Udp)
        {
            found.push(format!(
                "settings.bootstrap: server \"{server}\" is not usable: {error:#}"
            ));
        }
    }
    // 请求的路径总以 `/` 开头，不以它开头的 doh_path 谁也对不上，DoH 对每个请求都回 404 / A request
    // path always starts with `/`, so a doh_path not starting with it matches no request and DoH
    // answers 404 to every one
    if !cfg.settings.doh_path.starts_with('/') {
        found.push(format!(
            "settings.doh_path: \"{}\" does not start with \"/\", so it matches no request and DoH answers every query with 404",
            cfg.settings.doh_path
        ));
    }
    found.extend(cfg.settings.over_limits());
    // 一个 id 写了几次，在它第一次出现的地方报一次 / An id written several times is raised once,
    // where it first appears
    let mut written: rustc_hash::FxHashMap<&str, usize> = rustc_hash::FxHashMap::default();
    for pipeline in &cfg.pipelines {
        *written.entry(pipeline.id.as_str()).or_default() += 1;
    }
    for (place, entry) in entries(cfg) {
        let mut report = |problem: String| found.push(format!("{place}: {problem}"));
        match entry {
            Entry::Select(select) => {
                if !pipelines.contains(select.pipeline.as_str()) {
                    report(format!("no pipeline \"{}\"", select.pipeline));
                }
                if let Some(problem) = ignored_negation(
                    "matchers",
                    select.matchers.iter().map(|m| m.operator),
                    select.matcher_operator,
                ) {
                    report(problem);
                }
            }
            Entry::Pipeline(pipeline) => {
                if let Some(times) = written.remove(pipeline.id.as_str())
                    && times > 1
                {
                    report(format!(
                        "{times} pipelines are written with the id \"{}\"; a jump or pipeline_select finds only one of them by it, and the rules of the others do not run as written; give each pipeline its own id",
                        pipeline.id
                    ));
                }
            }
            Entry::Rule(rule) => rule_problems(rule, &pipelines, report),
        }
        for (within, matcher) in entry.matchers() {
            if let Some(problem) = matcher.problem() {
                found.push(format!("{place}.{within}: {problem}"));
            }
        }
    }
    for key in cfg.unread_keys.iter().filter(|key| !retired(key)) {
        found.push(format!(
            "{key}: the kernel does not read this key, so what it says has no effect; check its spelling and where it is written"
        ));
    }
    found
}

/// 照样加载、照写的做，却值得知道的写法：不再起作用的旧设置（见 [`RETIRED_SETTINGS`]）和后台刷新专用规则，值写成空而
/// 永远不命中的匹配器（见 `AnyMatcher::written_empty`），大得可能占掉很多内存的缓存，短得来不及重发和改用 TCP 的整体
/// 超时，绕成圈的跳转（见 [`jump_cycles`]），还有规则编译以后才知道的两种：没设 bootstrap 却有写成主机名的上游（系统的解析器
/// 要是 KixDNS 自己，解析就绕回来，见 [`host_names_without_bootstrap`]），规则用到、却没配可读的数据的 Geo 标签（见
/// [`geo_tags_without_data`]）。启动、重载和面板的校验都
/// 不拒绝，也不算 [`problems`]；编译时找出来（见 `RuntimePipelineConfig::warnings`），校验的回答和控制通道 `config` 结果的
/// `warnings` 列出它们，配置每生效一次各记一条 warn。每条和 [`problems`] 一样，开头写着说的是哪个设置、匹配器或规则的路径。
/// 以前只记 warn，默认日志级别看不到，校验也不说
/// What loads and runs as written yet is worth knowing: settings no longer in effect (see
/// [`RETIRED_SETTINGS`]) and the background refresh rule, a matcher written empty that so never
/// matches (see `AnyMatcher::written_empty`), a cache so large it may take a lot of memory, an
/// overall timeout too short for the resend and the TCP fallback, jumps that go round in a circle
/// (see [`jump_cycles`]), and two known once the rules compile: upstreams written with a host name
/// while bootstrap is unset (resolving comes back round should the system resolver be KixDNS
/// itself, see [`host_names_without_bootstrap`]), and Geo tags rules use with no data configured
/// to read them from (see [`geo_tags_without_data`]).
/// Startup, reloads and the panel's validation refuse none of them, nor do they count among
/// [`problems`]; they are found as the configuration compiles (see
/// `RuntimePipelineConfig::warnings`), listed in the validation answer and as `warnings` in the
/// control channel's `config` result, and each is logged as a warn every time the configuration
/// takes effect. Each starts, as [`problems`] do, with the path of the setting, matcher or rule
/// it is about. They used to be logged only, out of sight at the default log level, and validation
/// said nothing of them
pub fn warnings(cfg: &PipelineConfig) -> Vec<String> {
    let mut found = Vec::new();
    if cfg.background_refresh_rule.is_some() {
        found.push("background_refresh_rule: has no effect, as a background refresh replays the original request through its own rules; the entry can be removed".to_owned());
    }
    for key in cfg.unread_keys.iter().filter(|key| retired(key)) {
        found.push(format!(
            "{key}: no longer read, so it has no effect; the entry can be removed"
        ));
    }
    let settings = &cfg.settings;
    if settings.cache_capacity > 1_000_000 {
        found.push(format!(
            "settings.cache_capacity: {} is very large and may take a lot of memory",
            settings.cache_capacity
        ));
    }
    // UDP 转发在三分之一处重发，等满一段上游超时，失败了再用 TCP 等一段：整体超时短过两段半就可能把它们掐断
    // A UDP forward resends at a third of the upstream timeout, waits it out and on failure
    // waits once more over TCP: an overall timeout under two and a half of them may cut that short
    if let Some(request_timeout) = settings.request_timeout_ms
        && request_timeout < settings.default_request_timeout_ms()
    {
        found.push(format!(
            "settings.request_timeout_ms: {request_timeout} is under 2.5 times upstream_timeout_ms ({}), which may cut the resend and the TCP fallback short",
            settings.upstream_timeout_ms
        ));
    }
    for (place, entry) in entries(cfg) {
        for (within, matcher) in entry.matchers() {
            if let Some(warning) = matcher.warning() {
                found.push(format!("{place}.{within}: {warning}"));
            }
        }
    }
    found.extend(jump_cycles(cfg));
    found
}

/// 绕成圈的 jump_to_pipeline，每个圈在合上它的那条规则报一条 [`warnings`]：从这条规则跳过去，一路跳下去能回到它所在的
/// pipeline。规则的跳转和回答动作的跳转都算。规则有匹配条件，不一定每个查询都绕得上，所以只告警、不拒绝；绕上的查询跳满
/// `response_jump_limit` 才回 SERVFAIL，回答阶段每跳一次还要再问一次上游（见 [`MAX_JUMP_LIMIT`]）
/// The jump_to_pipeline actions that go round in a circle, each circle one of the [`warnings`]
/// at the rule that closes it: jumping on from that rule comes back round to its own pipeline.
/// Rule jumps and answer-action jumps alike count. Rules have matchers, so not every query need
/// go round, which is why this warns and refuses nothing; a query that does jumps the whole
/// `response_jump_limit` before it is answered SERVFAIL, and in the answer phase asks an upstream
/// again on every jump (see [`MAX_JUMP_LIMIT`])
fn jump_cycles(cfg: &PipelineConfig) -> Vec<String> {
    // 一个 id 写了几次时跳转找到最后那个，和运行时一样（见 `RuntimePipelineConfig::pipeline`）；跳到不存在的
    // pipeline 是一条 [`problems`]，不算在这里 / With an id written several times a jump finds the
    // last, as at run time (see `RuntimePipelineConfig::pipeline`); a jump to a pipeline that does
    // not exist is one of the [`problems`] and counts for nothing here
    let by_id: rustc_hash::FxHashMap<&str, usize> = cfg
        .pipelines
        .iter()
        .enumerate()
        .map(|(i, pipeline)| (pipeline.id.as_str(), i))
        .collect();
    // 每个 pipeline 的跳转：（规则序号，目标），一条规则跳到同一个目标的只算一次
    // Each pipeline's jumps: (rule index, target), a rule jumping to one target counted once
    let jumps: Vec<Vec<(usize, usize)>> = cfg
        .pipelines
        .iter()
        .map(|pipeline| {
            let mut jumps = Vec::new();
            for (j, rule) in pipeline.rules.iter().enumerate() {
                for action in rule
                    .actions
                    .iter()
                    .chain(&rule.response_actions_on_match)
                    .chain(&rule.response_actions_on_miss)
                {
                    if let Action::JumpToPipeline { pipeline } = action
                        && let Some(&target) = by_id.get(&**pipeline)
                    {
                        jumps.push((j, target));
                    }
                }
            }
            jumps.sort_unstable();
            jumps.dedup();
            jumps
        })
        .collect();
    // 深度优先地走：跳到还在路上的 pipeline 就合上一个圈。路用栈记着，不递归，pipeline 再多也不会把栈用完
    // Depth first: a jump to a pipeline still on the path closes a circle. The path is a stack
    // of its own rather than recursion, so no number of pipelines runs out of stack
    #[derive(Clone, Copy, PartialEq)]
    enum Visit {
        Not,
        OnPath,
        Done,
    }
    let mut visit = vec![Visit::Not; jumps.len()];
    let mut found = Vec::new();
    for root in 0..jumps.len() {
        if visit[root] != Visit::Not {
            continue;
        }
        visit[root] = Visit::OnPath;
        // 路上的 pipeline，和它下一个要看的跳转 / The pipelines on the path, each with its next jump to look at
        let mut path = vec![(root, 0)];
        while let Some((at, next)) = path.last_mut() {
            let at = *at;
            let Some(&(rule, target)) = jumps[at].get(*next) else {
                visit[at] = Visit::Done;
                path.pop();
                continue;
            };
            *next += 1;
            match visit[target] {
                Visit::Not => {
                    visit[target] = Visit::OnPath;
                    path.push((target, 0));
                }
                Visit::OnPath => found.push(format!(
                    "pipelines[{at}].rules[{rule}]: jumping to \"{}\" comes back round to \"{}\", so a query that keeps going round is answered SERVFAIL once it has jumped response_jump_limit times, and in the answer phase asks an upstream again on every jump",
                    cfg.pipelines[target].id, cfg.pipelines[at].id
                )),
                Visit::Done => {}
            }
        }
    }
    found
}

/// 规则用到（`geosite`、`geoip` 是它们用到的标签）、却没配可读的数据的 Geo 标签，每种一条 [`warnings`]：没写
/// `geosite_data_paths` 时的 GeoSite 标签，没写 `geoip_dat_path` 时 MMDB 也答不了的 GeoIP 标签（MMDB 只有两个字母的
/// 国家代码）。配置照样加载，用它们的规则却从不按数据判断：geo_site 和 geoip_country 永远不命中，geo_site_not 永远命中。
/// 以前只在读了数据文件、文件里没有某个标签时才记一条告警，一个数据文件都没配时什么都不说
/// The Geo tags rules use (`geosite` and `geoip` being those they use) with no data
/// configured to read them from, one of the [`warnings`] for each kind: GeoSite tags without
/// `geosite_data_paths`, and without `geoip_dat_path` the GeoIP tags the MMDB cannot answer
/// either (it holds two-letter country codes alone). The configuration loads all the same,
/// yet rules using them never judge by any data: geo_site and geoip_country never match, and
/// geo_site_not always does. A warning used to be logged only once a data file was read and
/// lacked a tag, and with no data file configured nothing was said at all
pub(crate) fn geo_tags_without_data(
    settings: &GlobalSettings,
    geosite: &[String],
    geoip: &[String],
) -> Vec<String> {
    let mut found = Vec::new();
    if settings.geosite_data_paths.is_empty() && !geosite.is_empty() {
        found.push(format!(
            "settings.geosite_data_paths: empty, so the GeoSite tags {} have no data to match against: geo_site never matches them and geo_site_not always does",
            geosite.join(", ")
        ));
    }
    let unanswered: Vec<&str> = geoip
        .iter()
        .map(String::as_str)
        .filter(|tag| {
            settings.geoip_db_path.is_none() || !crate::matcher::geoip::is_country_tag(tag)
        })
        .collect();
    if settings.geoip_dat_path.is_none() && !unanswered.is_empty() {
        let mmdb = match settings.geoip_db_path {
            Some(_) => ", and settings.geoip_db_path answers two-letter country codes alone",
            None => " and neither is settings.geoip_db_path",
        };
        found.push(format!(
            "settings.geoip_dat_path: not set{mmdb}, so the GeoIP tags {} have no data to match against: geoip_country never matches them",
            unanswered.join(", ")
        ));
    }
    found
}

/// 没设 bootstrap、却有写成主机名的上游时的那条 [`warnings`]：这些名字交给系统的解析器（见 `engine::bootstrap`），它要是
/// KixDNS 自己，解析就绕回来问 KixDNS，上游连不上。上游是 `runtime` 可能转发到的每一个，和转发时一样算（见
/// `engine::upstream::upstreams`）；不写 upstream 的 forward 问的是默认上游，按它自己的 transport 连
/// The one of the [`warnings`] for upstreams written with a host name while bootstrap is unset:
/// those names go to the system resolver (see `engine::bootstrap`), and should that be KixDNS
/// itself, resolving one comes back round to KixDNS and the upstream cannot be reached. The
/// upstreams are every one `runtime` may forward to, worked out as a forward does (see
/// `engine::upstream::upstreams`); a forward naming no upstream asks the default one, connected
/// to by its own transport
pub(crate) fn host_names_without_bootstrap(
    runtime: &crate::matcher::RuntimePipelineConfig,
) -> Option<String> {
    if names_an_address(&runtime.settings.bootstrap) {
        return None;
    }
    let host = crate::engine::upstream::upstreams(runtime)
        .into_iter()
        .filter_map(|(address, transport)| crate::engine::transport::host_name(address, transport))
        .min()?;
    Some(format!(
        "settings.bootstrap: not set, so upstream host names such as \"{host}\" are resolved by the system resolver; should that be KixDNS itself, resolving one comes back round to KixDNS and the upstream cannot be reached: set bootstrap to plain DNS servers written as IP:port"
    ))
}

/// 以前有、后来删掉的设置：老配置里留着的照样能读，各算一条 [`warnings`]（配置每生效一次列出来、记一条 warn），不算
/// [`problems`]，升级以后不必先改配置。智能流控的五个数字在流控改为自己判断以后不再用；`prefetch` 随它的实现撤掉了；
/// `tcp_health_check_error_threshold` 从来数不到：TCP/DoT 连接一出错就重建，不按次数；排行的两个设置在排行改为一直统计、
/// 照原样记客户端地址以后不再起作用，`geoip_auto_convert`、`geoip_filter_countries` 从来没被读过。以前这四个静默接受，
/// 配了 `statistics_anonymize_client_ip` 的人以为地址打了码
/// Settings there used to be and were taken out: an older configuration still writing them
/// reads as before, each counting among [`warnings`], listed and logged whenever the
/// configuration takes effect, and none among [`problems`], so an upgrade needs no
/// change first. The five numbers of flow control went out of use once it judged by itself;
/// `prefetch` went with its implementation; `tcp_health_check_error_threshold` was never
/// counted up to, a TCP/DoT connection being rebuilt on its first failure, not by count; the two
/// ranking settings stopped doing anything once rankings were always kept with whole client
/// addresses, and `geoip_auto_convert` and `geoip_filter_countries` were never read. These four
/// used to be taken in silence, and whoever set `statistics_anonymize_client_ip` took the
/// addresses for masked
const RETIRED_SETTINGS: [&str; 11] = [
    "flow_control_initial_permits",
    "flow_control_min_permits",
    "flow_control_max_permits",
    "flow_control_latency_threshold_ms",
    "flow_control_adjustment_interval_secs",
    "prefetch",
    "tcp_health_check_error_threshold",
    "statistics_enabled",
    "statistics_anonymize_client_ip",
    "geoip_auto_convert",
    "geoip_filter_countries",
];

/// `key` 是不是一个退役的设置（见 [`RETIRED_SETTINGS`]）/ Whether `key` is a retired setting (see [`RETIRED_SETTINGS`])
fn retired(key: &str) -> bool {
    key.strip_prefix("settings.")
        .is_some_and(|setting| RETIRED_SETTINGS.contains(&setting))
}

/// 配置原文 `raw` 里内核不读的键：读出来的配置写回成 JSON（`read`）里没有的键，按写的顺序列出路径（见
/// [`PipelineConfig::unread_keys`]）。不问 serde 解析时跳过了哪些键：动作、匹配器和 ECS 按 `type` 或 `mode` 分种类，
/// serde 先把整个对象缓冲下来再读，那里跳过的键谁也看不到，拼错的可选字段（`upstrem`、`operater`）就悄悄丢了
/// The keys of the configuration text `raw` the kernel does not read: those the configuration
/// read, written back as JSON (`read`), lacks, listed by path in the order written (see
/// [`PipelineConfig::unread_keys`]). It does not ask which keys serde skipped while parsing:
/// actions, matchers and ECS are told apart by `type` or `mode`, which serde reads by buffering
/// the whole object first, and the keys skipped there are seen by nobody, so a misspelt optional
/// field (`upstrem`, `operater`) used to be dropped without a word
fn unread_keys(raw: &str, read: &serde_json::Value) -> serde_json::Result<Vec<String>> {
    let mut found = Vec::new();
    Unread {
        read,
        path: String::new(),
        found: &mut found,
    }
    .deserialize(&mut serde_json::Deserializer::from_str(raw))?;
    Ok(found)
}

/// 照着读出来的配置里对应的那一块（`read`）走一遍写下的一个值，`path` 是它的路径：对象的键用点隔开，数组的下标写在
/// 方括号里（从 0 数）
/// Walks one value as written against its counterpart in the configuration read (`read`),
/// `path` being where it sits: an object's keys joined by dots, an array's index in brackets
/// (counting from 0)
struct Unread<'a> {
    read: &'a serde_json::Value,
    path: String,
    found: &'a mut Vec<String>,
}

impl<'de> DeserializeSeed<'de> for Unread<'_> {
    type Value = ();

    fn deserialize<D: serde::Deserializer<'de>>(self, written: D) -> Result<(), D::Error> {
        written.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Unread<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while let Some(key) = map.next_key::<String>()? {
            let read = self.read.get(&key);
            let path = if self.path.is_empty() {
                key
            } else {
                format!("{}.{key}", self.path)
            };
            match read {
                Some(read) => map.next_value_seed(Unread {
                    read,
                    path,
                    found: &mut *self.found,
                })?,
                None => {
                    map.next_value::<IgnoredAny>()?;
                    self.found.push(path);
                }
            }
        }
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        // 写下的数组读出来可能不是数组（写成数组的 upstream 读成一个字符串），那里的元素没有对应的一块
        // An array written may not be read as one (an upstream written as an array is read as one
        // string), its elements then having no counterpart
        const NOTHING: &serde_json::Value = &serde_json::Value::Null;
        for index in 0.. {
            let element = Unread {
                read: self.read.get(index).unwrap_or(NOTHING),
                path: format!("{}[{index}]", self.path),
                found: &mut *self.found,
            };
            if seq.next_element_seed(element)?.is_none() {
                break;
            }
        }
        Ok(())
    }

    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }

    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }

    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }

    fn visit_f64<E>(self, _: f64) -> Result<(), E> {
        Ok(())
    }

    fn visit_str<E>(self, _: &str) -> Result<(), E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }
}

/// 一份配置因为 [`problems`] 被拒（见 [`refuse_problems`]）：那些问题，每条一句。显示成用 `; ` 连起来的一句；要逐条列出的
/// （控制通道校验的回答和 `config` 结果的 `last_reload`）用 [`Problems::of`] 从错误里取出来
/// A configuration refused for its [`problems`] (see [`refuse_problems`]): those problems, a
/// sentence each. It displays as one sentence, the problems joined by `; `; what lists them one
/// by one (the control channel's validation answer and the `config` result's `last_reload`)
/// takes them out of the error with [`Problems::of`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problems(pub Vec<String>);

impl Problems {
    /// `error` 是因为这些问题拒掉配置时的那些问题，别的错误时为空 / The problems `error` refused a
    /// configuration for, empty for any other error
    pub fn of(error: &anyhow::Error) -> &[String] {
        error
            .downcast_ref::<Self>()
            .map(|problems| problems.0.as_slice())
            .unwrap_or_default()
    }
}

impl std::fmt::Display for Problems {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0.join("; "))
    }
}

impl std::error::Error for Problems {}

/// [`problems`] 有一条就失败，列出全部（见 [`Problems`]）/ Fail on any of [`problems`], listing
/// them all (see [`Problems`])
pub fn refuse_problems(cfg: &PipelineConfig) -> Result<()> {
    let found = problems(cfg);
    if found.is_empty() {
        Ok(())
    } else {
        Err(Problems(found).into())
    }
}

/// 一条规则里几个 forward 的 ecs 写得不一样：它们合成一次转发，只能发一个 ECS，所以一个也不发
/// A rule whose forwards write different ecs: they merge into one forward, which can send
/// one ECS only, so none is sent
const MERGED_ECS_DIFFER: &str = "its forward actions are asked together as one forward, which sends one ECS, but their ecs settings differ, so none of them is sent; write the same ecs on each, or split them into separate rules";

/// 一个上游也没写：每个查询都会失败 / Not a single upstream written: every query would fail
const NO_UPSTREAM: &str = "no upstream is written, so every query it gets would fail";

/// 逗号分隔的上游，转发时就这样拆 / Comma-separated upstreams, split as a forward splits them
pub(crate) fn split_upstreams(upstreams: &str) -> impl Iterator<Item = &str> {
    upstreams
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// 拆得出至少一个地址 / Splits into at least one address
fn names_an_address(upstreams: &str) -> bool {
    split_upstreams(upstreams).next().is_some()
}

/// 上游地址的前缀（`tcp://` 里的 `tcp`）和它后面的部分，没有前缀时为 None。上游带不带前缀、带的是什么，都只这样看
/// An upstream address's prefix (the `tcp` of `tcp://`) and what follows it, None without one.
/// Whether an upstream has a prefix, and which, is only ever told so
pub(crate) fn split_scheme(upstream: &str) -> Option<(&str, &str)> {
    upstream.split_once("://")
}

/// 一个上游去掉 `传输://` 前缀的地址和问它用的传输：前缀不认识（见 [`Transport::from_label`]）或者没有前缀时用
/// `default_transport`
/// - "tcp://1.1.1.1:53" -> ("1.1.1.1:53", Transport::Tcp)
/// - "https://dns.example.com/dns-query" -> ("dns.example.com/dns-query", Transport::Doh)
/// - "1.1.1.1:53" -> ("1.1.1.1:53", default_transport)
///
/// The address of one upstream short of its `transport://` prefix, and the transport it is
/// asked over: `default_transport` for a prefix it does not know (see
/// [`Transport::from_label`]) or none
pub(crate) fn parse_upstream_addr(addr: &str, default_transport: Transport) -> (&str, Transport) {
    match split_scheme(addr) {
        Some((scheme, address)) => (
            address,
            Transport::from_label(scheme).unwrap_or(default_transport),
        ),
        None => (addr, default_transport),
    }
}

/// 一个上游写得对不对：前缀认识，地址是它的传输读得懂的。说明为什么不对
/// Whether one upstream is written right: a known prefix, and an address its transport can
/// read. Says why not
fn upstream_problem(upstream: &str, default_transport: Transport) -> Option<String> {
    if let Some((scheme, _)) = split_scheme(upstream)
        && Transport::from_label(scheme).is_none()
    {
        return Some(format!(
            "upstream \"{upstream}\" starts with an unknown prefix \"{scheme}://\""
        ));
    }
    let (address, transport) = parse_upstream_addr(upstream, default_transport);
    crate::engine::transport::check_upstream_address(address, transport)
        .err()
        .map(|error| format!("upstream \"{upstream}\" is not usable: {error:#}"))
}

/// 一串上游各自的地址（去掉前缀），`PermitManager::note_answer_took` 就是按它记的 / The address
/// (short of its prefix) of each of a list of upstreams, which is what
/// `PermitManager::note_answer_took` notes by
pub(crate) fn upstream_addresses(upstreams: &str) -> impl Iterator<Item = &str> {
    split_upstreams(upstreams).map(|upstream| parse_upstream_addr(upstream, Transport::Udp).0)
}

/// 作答上游的名字（`udp:1.1.1.1:53`，见 `engine::upstream::upstream_label`）里的传输和地址，传输名照
/// [`Transport::label`] 读。不带传输名的，传输为 None，地址是整个名字
/// The transport and the address in an answering upstream's name (`udp:1.1.1.1:53`, see
/// `engine::upstream::upstream_label`), the transport's name read by [`Transport::label`]. One
/// without a transport's name has None for it, the address being the whole name
pub(crate) fn split_answered(name: &str) -> (Option<Transport>, &str) {
    name.split_once(':')
        .and_then(|(label, address)| {
            Transport::from_label(label).map(|transport| (Some(transport), address))
        })
        .unwrap_or((None, name))
}

/// 作答上游的名字里的地址（见 [`split_answered`]）。回答检查拿它和配置里写的上游地址比（见
/// `RuntimeResponseMatcher::UpstreamEquals`）
/// The address in an answering upstream's name (see [`split_answered`]). The answer check
/// compares it with the upstream addresses a configuration writes (see
/// `RuntimeResponseMatcher::UpstreamEquals`)
pub(crate) fn answered_address(name: &str) -> &str {
    split_answered(name).1
}

/// `log` 动作认的级别 / The levels a `log` action takes
const LOG_LEVELS: [&str; 5] = ["trace", "debug", "info", "warn", "error"];

/// 一串匹配器里白写的取反。第一个匹配器是起点，它身上的 `and_not`、`or_not`（`not`）前面没有东西可合，也不把它取反；只有
/// 一个匹配器时，规则级的取反也只落在它身上，一样白写。以前悄悄当成正向匹配：写着 `not` 的规则整个反过来。要匹配它不成立
/// 的，前面放一个 `{"type": "any"}`。`matchers` 是这串匹配器在配置里的键
/// A negation written for nothing in a chain of matchers. The first matcher is where the result
/// starts: an `and_not` or `or_not` (`not`) on it has nothing before it to join and does not
/// negate it; with a single matcher a chain-level negation lands on it alone, written for
/// nothing just the same. It used to pass for a plain match, a rule written with `not` turning
/// right round. To match what it does not, put an `{"type": "any"}` first. `matchers` is the
/// chain's key in the configuration
fn ignored_negation(
    matchers: &str,
    mut operators: impl ExactSizeIterator<Item = MatchOperator>,
    chain: MatchOperator,
) -> Option<String> {
    let negation = |operator| match operator {
        MatchOperator::AndNot => Some("and_not"),
        MatchOperator::OrNot => Some("or_not"),
        MatchOperator::And | MatchOperator::Or => None,
    };
    let single = operators.len() == 1;
    let first = operators.next()?;
    let operator = negation(first).or_else(|| {
        (single && first == MatchOperator::And)
            .then(|| negation(chain))
            .flatten()
    })?;
    Some(format!(
        "{operator} on the first of {matchers} has nothing before it and does not negate it; to match what it does not, put {{\"type\": \"any\"}} first"
    ))
}

/// 配置里按位置排的每一项：pipeline_select 的每一条、每个 pipeline 和它的每条规则，各带着自己的路径，写法和读不懂的键
/// 一样（`pipeline_select[0]`、`pipelines[1]`、`pipelines[1].rules[2]`）。[`problems`] 和 [`warnings`] 都照它说在哪：规则名
/// 可以重复，按名字说不清是哪一条
/// Every entry of a configuration by place: each pipeline_select entry, each pipeline and each
/// of its rules, with its path written as for the keys not read (`pipeline_select[0]`,
/// `pipelines[1]`, `pipelines[1].rules[2]`). Both [`problems`] and [`warnings`] say where by
/// it: rule names may repeat, and a name may not tell which rule it is
fn entries(cfg: &PipelineConfig) -> impl Iterator<Item = (String, Entry<'_>)> {
    let selects = cfg
        .pipeline_select
        .iter()
        .enumerate()
        .map(|(i, select)| (format!("pipeline_select[{i}]"), Entry::Select(select)));
    let pipelines = cfg.pipelines.iter().enumerate().flat_map(|(i, pipeline)| {
        let rules = pipeline
            .rules
            .iter()
            .enumerate()
            .map(move |(j, rule)| (format!("pipelines[{i}].rules[{j}]"), Entry::Rule(rule)));
        std::iter::once((format!("pipelines[{i}]"), Entry::Pipeline(pipeline))).chain(rules)
    });
    selects.chain(pipelines)
}

/// [`entries`] 给出的一项 / An entry [`entries`] gives
#[derive(Clone, Copy)]
enum Entry<'a> {
    Select(&'a PipelineSelectRule),
    Pipeline(&'a Pipeline),
    Rule(&'a Rule),
}

impl<'a> Entry<'a> {
    /// 这一项的匹配器，各带着在这一项里的路径（`matchers[1]`、`response_matchers[0]`）/ This entry's
    /// matchers, each with its path within the entry (`matchers[1]`, `response_matchers[0]`)
    fn matchers(self) -> impl Iterator<Item = (String, AnyMatcher<'a>)> {
        let (request, response): (&[MatcherWithOp], &[ResponseMatcherWithOp]) = match self {
            Entry::Select(select) => (&select.matchers, &[]),
            Entry::Pipeline(_) => (&[], &[]),
            Entry::Rule(rule) => (&rule.matchers, &rule.response_matchers),
        };
        let request = request
            .iter()
            .enumerate()
            .map(|(k, m)| (format!("matchers[{k}]"), AnyMatcher::Request(&m.matcher)));
        let response = response.iter().enumerate().map(|(k, m)| {
            (
                format!("response_matchers[{k}]"),
                AnyMatcher::Response(&m.matcher),
            )
        });
        request.chain(response)
    }
}

/// 请求或回答的一个匹配器 / A request or answer matcher
#[derive(Clone, Copy)]
enum AnyMatcher<'a> {
    Request(&'a Matcher),
    Response(&'a ResponseMatcher),
}

impl AnyMatcher<'_> {
    /// 这个匹配器会悄悄做成别的事的写法（见 [`problems`]）/ How this matcher is written to
    /// silently do something else (see [`problems`])
    fn problem(self) -> Option<String> {
        if let Some((Weight::Problem, problem)) = self.written_empty() {
            return Some(problem);
        }
        // 以前写错的 rcode 悄悄当成 OTHER，匹配所有不常见的 RCODE，这条规则几乎永远不中
        // A misspelt rcode used to pass for OTHER, matching every uncommon RCODE, so the rule
        // hardly ever matched
        match self {
            Self::Response(ResponseMatcher::ResponseRcode { value })
                if !value.eq_ignore_ascii_case("OTHER")
                    && crate::matcher::parse_rcode(value).is_none() =>
            {
                Some(format!(
                    "response_rcode \"{value}\" is none of NOERROR, FORMERR, SERVFAIL, NXDOMAIN, NOTIMP, REFUSED, OTHER"
                ))
            }
            _ => None,
        }
    }

    /// 这个匹配器照样加载、却值得知道的写法（见 [`warnings`]）：值写成空、永远不命中的，和域名正则里照写永远命不中的
    /// 大写字母（见 `matcher::capitals_warning`）/ How this matcher is written that loads all
    /// the same yet is worth knowing (see [`warnings`]): with its value written empty never
    /// matching, or with capitals in a name regex that never match as written (see
    /// `matcher::capitals_warning`)
    fn warning(self) -> Option<String> {
        if let Some((weight, warning)) = self.written_empty() {
            return (weight == Weight::Warning).then_some(warning);
        }
        match self {
            Self::Request(Matcher::DomainRegex { value }) => {
                crate::matcher::capitals_warning("domain_regex", value)
            }
            Self::Response(ResponseMatcher::RequestDomainRegex { value }) => {
                crate::matcher::capitals_warning("request_domain_regex", value)
            }
            _ => None,
        }
    }

    /// 值写成空的这个匹配器做成了什么，按它的意思分：它看的每一样都匹配的（每个名字，或者每份带 TXT 记录的回答）
    /// 和只匹配根名字的空 domain_exact 算 [`problems`]，永远不匹配的算 [`warnings`]。域名按读进来的样子看，单独一个点
    /// 是根（见 `matcher::domain_value`），所以 domain_suffix 写成 `.` 和写成空的一样，domain_exact 写成 `.` 正是要根；
    /// 逗号分隔的列表一项也没写算空。值写成空的编译不过（网段、qclass、qtype）、另有检查（rcode）或者根本没有值的，为
    /// None。逐个列出每一种，新加的匹配器编译时就得决定
    /// What this matcher comes to with its value written empty, by what it means: one matching
    /// everything it looks at (every name, or every answer carrying a TXT record) and an empty
    /// domain_exact, matching only the root name, count among [`problems`], one never matching
    /// among [`warnings`]. A domain is looked at as read, a lone dot being the root (see
    /// `matcher::domain_value`), so domain_suffix written `.` is as written empty, and
    /// domain_exact written `.` means the root indeed; a comma-separated list naming nothing
    /// counts as empty. None for one that written empty does not compile (a network, a qclass, a
    /// qtype), is checked otherwise (an rcode) or has no value at all. Every kind is listed, so a
    /// new matcher has to be decided on to compile
    fn written_empty(self) -> Option<(Weight, String)> {
        use crate::matcher::domain_value;
        let every_name = |kind: &str, value: &str| {
            (
                Weight::Problem,
                format!("{kind} \"{value}\" matches every name"),
            )
        };
        let root = |kind: &str| {
            (
                Weight::Problem,
                format!("{kind} \"\" matches only the root name; write \".\" to mean the root"),
            )
        };
        let never = |kind: &str, value: &str| {
            (Weight::Warning, format!("{kind} \"{value}\" never matches"))
        };
        let no_country = |kind: &str| {
            (
                Weight::Warning,
                format!("{kind} with no country code never matches"),
            )
        };
        let lists_nothing = |list: &str| split_upstreams(list).next().is_none();
        match self {
            Self::Request(matcher) => match matcher {
                Matcher::DomainSuffix { value } if domain_value(value).is_empty() => {
                    Some(every_name("domain_suffix", value))
                }
                Matcher::DomainRegex { value } if value.is_empty() => {
                    Some(every_name("domain_regex", value))
                }
                Matcher::GeoSiteNot { value } if value.is_empty() => {
                    Some(every_name("geo_site_not", value))
                }
                Matcher::DomainExact { value } if value.is_empty() => Some(root("domain_exact")),
                Matcher::ListenerLabel { value } if value.is_empty() => {
                    Some(never("listener_label", value))
                }
                Matcher::GeoSite { value } if value.is_empty() => Some(never("geo_site", value)),
                Matcher::GeoipCountry { country_codes } if country_codes.is_empty() => {
                    Some(no_country("geoip_country"))
                }
                Matcher::Any
                | Matcher::ListenerLabel { .. }
                | Matcher::DomainSuffix { .. }
                | Matcher::DomainExact { .. }
                | Matcher::DomainRegex { .. }
                | Matcher::ClientIp { .. }
                | Matcher::GeoipCountry { .. }
                | Matcher::GeoipPrivate { .. }
                | Matcher::Qclass { .. }
                | Matcher::EdnsPresent { .. }
                | Matcher::GeoSite { .. }
                | Matcher::GeoSiteNot { .. }
                | Matcher::Qtype { .. } => None,
            },
            Self::Response(matcher) => match matcher {
                ResponseMatcher::RequestDomainSuffix { value }
                    if domain_value(value).is_empty() =>
                {
                    Some(every_name("request_domain_suffix", value))
                }
                ResponseMatcher::RequestDomainRegex { value } if value.is_empty() => {
                    Some(every_name("request_domain_regex", value))
                }
                ResponseMatcher::ResponseRequestDomainGeoSiteNot { value } if value.is_empty() => {
                    Some(every_name("response_request_domain_geo_site_not", value))
                }
                ResponseMatcher::RequestDomainExact { value } if value.is_empty() => {
                    Some(root("request_domain_exact"))
                }
                // 空的前缀和正则对什么文字都成立；精确比较空文字的是有意要空的 TXT 记录
                // An empty prefix or regex holds for any text; an exact match on empty text
                // means an empty TXT record indeed
                ResponseMatcher::ResponseTxtContent { mode, value }
                    if value.is_empty()
                        && !matches!(
                            crate::matcher::TxtMatchMode::from_str(mode),
                            Ok(crate::matcher::TxtMatchMode::Exact) | Err(_)
                        ) =>
                {
                    Some((
                        Weight::Problem,
                        format!(
                            "response_txt_content in {} mode with an empty value matches every answer carrying a TXT record",
                            mode.to_ascii_lowercase()
                        ),
                    ))
                }
                ResponseMatcher::UpstreamEquals { value } if lists_nothing(value) => {
                    Some(never("upstream_equals", value))
                }
                ResponseMatcher::ResponseUpstreamIp { cidr } if lists_nothing(cidr) => {
                    Some(never("response_upstream_ip", cidr))
                }
                ResponseMatcher::ResponseAnswerIp { cidr } if lists_nothing(cidr) => {
                    Some(never("response_answer_ip", cidr))
                }
                ResponseMatcher::ResponseRequestDomainGeoSite { value } if value.is_empty() => {
                    Some(never("response_request_domain_geo_site", value))
                }
                ResponseMatcher::ResponseAnswerIpGeoipCountry { country_codes }
                    if country_codes.is_empty() =>
                {
                    Some(no_country("response_answer_ip_geoip_country"))
                }
                ResponseMatcher::UpstreamEquals { .. }
                | ResponseMatcher::RequestDomainSuffix { .. }
                | ResponseMatcher::RequestDomainExact { .. }
                | ResponseMatcher::RequestDomainRegex { .. }
                | ResponseMatcher::ResponseUpstreamIp { .. }
                | ResponseMatcher::ResponseAnswerIp { .. }
                | ResponseMatcher::ResponseType { .. }
                | ResponseMatcher::ResponseRcode { .. }
                | ResponseMatcher::ResponseQclass { .. }
                | ResponseMatcher::ResponseEdnsPresent { .. }
                | ResponseMatcher::ResponseAnswerIpGeoipCountry { .. }
                | ResponseMatcher::ResponseAnswerIpGeoipPrivate { .. }
                | ResponseMatcher::ResponseRequestDomainGeoSite { .. }
                | ResponseMatcher::ResponseRequestDomainGeoSiteNot { .. }
                | ResponseMatcher::ResponseTxtContent { .. } => None,
            },
        }
    }
}

/// 一种写法算 [`problems`] 还是 [`warnings`] / Whether a way of writing counts among
/// [`problems`] or [`warnings`]
#[derive(PartialEq)]
enum Weight {
    Problem,
    Warning,
}

fn rule_problems(
    rule: &Rule,
    pipelines: &rustc_hash::FxHashSet<&str>,
    mut report: impl FnMut(String),
) {
    for problem in [
        ignored_negation(
            "matchers",
            rule.matchers.iter().map(|m| m.operator),
            rule.matcher_operator,
        ),
        ignored_negation(
            "response_matchers",
            rule.response_matchers.iter().map(|m| m.operator),
            rule.response_matcher_operator,
        ),
    ]
    .into_iter()
    .flatten()
    {
        report(problem);
    }
    use crate::engine::response::txt_size_problem;
    use crate::matcher::static_cname_target;
    use crate::matcher::static_ips;

    let forwards = rule
        .actions
        .iter()
        .filter(|action| matches!(action, Action::Forward { .. }))
        .count();
    if forwards > 1 && rule.shared_forward_ecs().is_err() {
        report(MERGED_ECS_DIFFER.to_string());
    }
    // 几个 forward 合成一次转发、其中有写了地址的：写成空的那个只是被跳过，查询照样有上游作答
    // Several forwards merged into one with an address among them: one written empty is only
    // skipped, and the query still has upstreams to answer it
    let merge_has_an_address = forwards > 1
        && rule.actions.iter().any(|action| {
            matches!(action, Action::Forward { upstream: Some(upstreams), .. } if names_an_address(upstreams))
        });
    // 回答动作里的 forward 各自转发，不合并 / The forwards among the answer actions forward
    // each on its own and do not merge
    let actions = rule
        .actions
        .iter()
        .map(|action| (action, merge_has_an_address))
        .chain(
            rule.response_actions_on_match
                .iter()
                .chain(&rule.response_actions_on_miss)
                .map(|action| (action, false)),
        );
    for (action, skipped_when_empty) in actions {
        if let Action::Forward {
            ecs:
                Some(EcsMode::Static {
                    ip: crate::ecs::StaticEcsIp::NotAnIp(ip),
                    ..
                }),
            ..
        } = action
        {
            report(format!(
                "ecs ip \"{ip}\" is not an IP address, so no subnet is set and the client's own ECS, if any, goes upstream"
            ));
        }
        match action {
            Action::Forward {
                upstream: Some(upstreams),
                transport,
                ..
            } => {
                if !names_an_address(upstreams) && !skipped_when_empty {
                    report(NO_UPSTREAM.to_string());
                }
                for upstream in split_upstreams(upstreams) {
                    if let Some(problem) =
                        upstream_problem(upstream, transport.unwrap_or(Transport::Udp))
                    {
                        report(problem);
                    }
                }
            }
            Action::StaticResponse { rcode, .. }
                if crate::matcher::parse_rcode(rcode).is_none() =>
            {
                report(format!(
                    "rcode \"{rcode}\" is none of NOERROR, FORMERR, SERVFAIL, NXDOMAIN, NOTIMP, REFUSED"
                ));
            }
            Action::StaticIpResponse { ip, .. } if static_ips(ip).is_none() => {
                report(format!(
                    "ip \"{ip}\" is not a comma-separated list of IP addresses"
                ));
            }
            Action::StaticCnameResponse { target, .. } if static_cname_target(target).is_none() => {
                report(format!("cname target \"{target}\" is not a domain name"));
            }
            Action::StaticTxtResponse { text, .. } | Action::ReplaceTxtResponse { text, .. } => {
                // 不知道会问什么名字，按最短的根名字算 / What will be asked is unknown, so the
                // shortest name, the root, is taken
                if let Some(problem) = txt_size_problem(text, 1) {
                    report(problem);
                }
            }
            // 以前写错的级别（比如大写的 `WARN`）悄悄当成 info / A misspelt level (an uppercase
            // `WARN`, say) used to pass for info
            Action::Log { level: Some(level) } if !LOG_LEVELS.contains(&level.as_str()) => {
                report(format!(
                    "log level \"{level}\" is none of {}",
                    LOG_LEVELS.join(", ")
                ));
            }
            Action::JumpToPipeline { pipeline } if !pipelines.contains(&**pipeline) => {
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
    use super::{Action, Matcher, ResponseMatcher, parse_config};

    #[test]
    fn geoip_country_codes_accept_string_or_array() {
        let Matcher::GeoipCountry { country_codes } =
            serde_json::from_str(r#"{"type":"geoip_country","country_codes":"cloudflare"}"#)
                .expect("request matcher should accept a string")
        else {
            panic!("unexpected request matcher variant");
        };
        assert_eq!(country_codes, ["cloudflare"]);

        let Matcher::GeoipCountry { country_codes } =
            serde_json::from_str(r#"{"type":"geoip_country","country_codes":"CN, cloudflare"}"#)
                .expect("request matcher should accept a comma-separated string")
        else {
            panic!("unexpected request matcher variant");
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

    /// 上游、国家代码和 TXT 文本写成一个字符串或者一个字符串数组都行，各按自己的办法读：上游的数组连成一串，空数组算没写；
    /// 国家代码拆开逗号、去掉空白；TXT 一个字符串就是一段。写成别的时，错误说要的是什么、拿到的是什么
    /// Upstreams, country codes and TXT text may each be written as a string or as an array of
    /// strings, read each its own way: upstreams in an array are joined into one string, an
    /// empty array counting as none written; country codes are split at commas and trimmed; a
    /// TXT string is one piece. Written any other way, the error says what is wanted and what
    /// was found
    #[test]
    fn a_string_or_a_list_is_read_by_each_field_its_own_way() {
        let forward = |upstream: serde_json::Value| match serde_json::from_value(
            serde_json::json!({ "type": "forward", "upstream": upstream }),
        ) {
            Ok(Action::Forward { upstream, .. }) => Ok(upstream),
            Ok(other) => panic!("{other:?}"),
            Err(error) => Err(error.to_string()),
        };
        assert_eq!(
            forward(serde_json::json!("a:53, b:53")),
            Ok(Some("a:53, b:53".to_owned()))
        );
        assert_eq!(
            forward(serde_json::json!(["a:53", "b:53"])),
            Ok(Some("a:53,b:53".to_owned()))
        );
        assert_eq!(forward(serde_json::json!([])), Ok(None));
        assert_eq!(forward(serde_json::json!(null)), Ok(None));
        let txt = |text: serde_json::Value| match serde_json::from_value(
            serde_json::json!({ "type": "static_txt_response", "text": text }),
        ) {
            Ok(Action::StaticTxtResponse { text, .. }) => Ok(text),
            Ok(other) => panic!("{other:?}"),
            Err(error) => Err(error.to_string()),
        };
        assert_eq!(txt(serde_json::json!("a, b")), Ok(vec!["a, b".to_owned()]));
        assert_eq!(
            txt(serde_json::json!(["a", " b"])),
            Ok(vec!["a".to_owned(), " b".to_owned()])
        );

        let wanted = "expected a string or an array of strings";
        for (written, found) in [
            (serde_json::json!(53), "invalid type: integer `53`"),
            (serde_json::json!({ "a": "b" }), "invalid type: map"),
        ] {
            assert_eq!(forward(written.clone()), Err(format!("{found}, {wanted}")));
            assert_eq!(txt(written.clone()), Err(format!("{found}, {wanted}")));
            let config = serde_json::json!({ "pipelines": [{ "id": "main", "rules": [{
                "name": "r",
                "matchers": [{ "type": "geoip_country", "country_codes": written }],
                "actions": [{ "type": "allow" }]
            }] }] });
            let refused = format!("{:#}", parse_config(&config.to_string()).unwrap_err());
            assert!(refused.contains(&format!("{found}, {wanted}")), "{refused}");
        }
        assert_eq!(
            forward(serde_json::json!(["a:53", 53])),
            Err("invalid type: integer `53`, expected a string".to_owned())
        );
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

    /// 不经 `parse_config`、直接拿一份 `PipelineConfig` 编译的配置，几个 forward 也合成一次转发、上游也先拆好：这些都在
    /// 编译时算。以前只有 `parse_config` 算，公开的 `RuntimePipelineConfig::from_config` 拿到别处建的配置时不合并，
    /// 规则只问第一个 forward 的上游
    /// A configuration compiled from a `PipelineConfig` straight, not through `parse_config`, merges
    /// its forwards and splits their upstreams too, both being worked out as it compiles. Only
    /// `parse_config` used to, so the public `RuntimePipelineConfig::from_config` given a
    /// configuration built elsewhere merged nothing, and the rule asked the first forward's
    /// upstream alone
    #[test]
    fn a_configuration_compiled_without_parse_config_merges_its_forwards() {
        let config: super::PipelineConfig = serde_json::from_value(json!({
            "pipelines": [{ "id": "main", "rules": [{
                "name": "r",
                "matchers": [{ "type": "any" }],
                "actions": [
                    { "type": "forward", "upstream": "1.1.1.1:53, 1.0.0.1:53" },
                    { "type": "forward", "upstream": "8.8.8.8:53" }
                ]
            }] }]
        }))
        .expect("parse config");
        let runtime = crate::matcher::RuntimePipelineConfig::from_config(config).expect("compiles");
        let rule = &runtime.pipelines[0].rules[0];
        let merged = rule
            .merged_forward
            .as_ref()
            .expect("several forwards merge");
        assert_eq!(merged.upstream_list.len(), 3);
        assert!(matches!(
            &rule.actions[0],
            super::Action::Forward { pre_split_upstreams: Some(split), .. } if split.len() == 2
        ));
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
        // 写成空的（或者只有逗号）的 upstream 也一样：合并时跳过它，它的 ecs 不算
        // An upstream written empty (or commas only) is the same: the merge skips it, and its
        // ecs does not count
        for empty in ["", " , "] {
            assert_eq!(
                ecs_of(json!([
                    forward("192.0.2.1:53", &from_client),
                    forward("192.0.2.2:53", &from_client),
                    forward(empty, &json!({ "mode": "clear" }))
                ])),
                shared,
                "{empty:?}"
            );
        }
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

    /// 没设 bootstrap 时，写成主机名的 TCP、DoT、DoH、DoQ 上游算一条 warning：默认上游、请求和回答阶段的 forward 都算，
    /// 不写 upstream 的 forward 按它的 transport 连默认上游。都写成 IP、只有 UDP 上游或者设了 bootstrap 时没有。以前只在
    /// 第一次经系统解析时记一条 warn，默认日志级别看不到
    /// Without bootstrap, a TCP, DoT, DoH or DoQ upstream written with a host name counts as a
    /// warning: the default upstream and request- and answer-phase forwards alike, a forward naming
    /// no upstream connecting to the default one by its transport. None with every upstream an IP,
    /// with UDP upstreams only, or with bootstrap set. It used to be a warn logged the first time
    /// the system resolved a name, out of sight at the default log level
    #[test]
    fn a_named_upstream_without_bootstrap_is_a_warning() {
        let any = serde_json::json!([{ "type": "any" }]);
        let warned = |settings: serde_json::Value, actions: serde_json::Value| {
            let config = serde_json::json!({
                "settings": settings,
                "pipelines": [{ "id": "main", "rules": [rule("r", any.clone(), actions)] }]
            });
            let config = super::parse_config(&config.to_string()).expect("parses");
            crate::matcher::RuntimePipelineConfig::from_config(config)
                .expect("compiles")
                .warnings
                .iter()
                .any(|warning| warning.starts_with("settings.bootstrap: not set"))
        };
        let udp = serde_json::json!({ "default_upstream": "1.1.1.1:53" });
        let forward =
            |upstream: &str| serde_json::json!([{ "type": "forward", "upstream": upstream }]);
        for named in [
            "tcp://dns.example:53",
            "tls://dns.example",
            "https://dns.example/dns-query",
            "quic://dns.example?sni=dns.example",
        ] {
            assert!(warned(udp.clone(), forward(named)), "{named}");
            assert!(
                !warned(
                    serde_json::json!({ "default_upstream": "1.1.1.1:53", "bootstrap": "223.5.5.5:53" }),
                    forward(named)
                ),
                "{named} with bootstrap"
            );
        }
        assert!(warned(
            serde_json::json!({ "default_upstream": "tls://dns.example" }),
            serde_json::json!([{ "type": "allow" }])
        ));
        assert!(warned(
            serde_json::json!({ "default_upstream": "dns.example:53" }),
            serde_json::json!([{ "type": "forward", "transport": "tcp" }])
        ));
        for ip in [
            "1.1.1.1:53",
            "tcp://1.1.1.1:53",
            "tcp://[2606:4700::1111]:53",
            "tls://1.1.1.1?sni=one.one.one.one",
            "https://1.1.1.1/dns-query",
            "https://[2606:4700::1111]/dns-query",
        ] {
            assert!(!warned(udp.clone(), forward(ip)), "{ip}");
        }
    }

    /// 警告和问题一样按位置说在哪：`pipeline_select[i].matchers[k]`、`pipelines[i].rules[j].matchers[k]`、
    /// `.response_matchers[k]`。三条都叫 r 的规则也分得清。以前警告写成 `pipeline_select 1`（从 1 数）、
    /// `pipeline "main" rule "r"`，和问题的写法不一样，重名的规则分不清
    /// Warnings say where as problems do: `pipeline_select[i].matchers[k]`,
    /// `pipelines[i].rules[j].matchers[k]`, `.response_matchers[k]`, which tells apart three rules
    /// all named r. Warnings used to be placed as `pipeline_select 1` (counting from 1) and
    /// `pipeline "main" rule "r"`, unlike problems, and rules sharing a name were not told apart
    #[test]
    fn warnings_are_placed_as_problems_are() {
        let no_country = serde_json::json!([{ "type": "geoip_country", "country_codes": [] }]);
        let any = serde_json::json!([{ "type": "any" }]);
        let allow = serde_json::json!([{ "type": "allow" }]);
        let config = serde_json::json!({
            "settings": { "default_upstream": "1.1.1.1:53" },
            "pipeline_select": [
                { "pipeline": "main", "matchers": any },
                { "pipeline": "main", "matchers": [{ "type": "any" }, no_country[0]] }
            ],
            "pipelines": [{ "id": "main", "rules": [
                rule("r", any.clone(), allow.clone()),
                rule("r", no_country.clone(), allow.clone()),
                {
                    "name": "r",
                    "matchers": any,
                    "actions": [{ "type": "forward" }],
                    "response_matchers": [{ "type": "response_answer_ip_geoip_country", "country_codes": "" }],
                    "response_actions_on_match": allow
                }
            ] }]
        });
        let warned = super::warnings(&super::parse_config(&config.to_string()).expect("parses"));
        assert_eq!(
            warned,
            [
                "pipeline_select[1].matchers[1]: geoip_country with no country code never matches",
                "pipelines[0].rules[1].matchers[0]: geoip_country with no country code never matches",
                "pipelines[0].rules[2].response_matchers[0]: response_answer_ip_geoip_country with no country code never matches",
            ]
        );
    }

    /// 跳转绕成的圈在合上它的规则报一条告警：请求阶段的跳转和回答动作的跳转连起来也算，跳回自己的也算；一个圈只报一次，
    /// 不成圈的（一条链、两条路汇到一处、跳到不存在的 pipeline）不报。配置照样通过校验。以前一条都不报，回答阶段绕圈的
    /// 查询每跳一次问一次上游，跳满上限才 SERVFAIL
    /// A circle of jumps is warned about at the rule that closes it: request-phase jumps and
    /// answer-action jumps joined up count, as does a jump back to its own pipeline; each circle
    /// once, and nothing for what is no circle (a chain, two ways meeting at one pipeline, a jump
    /// to a pipeline that does not exist). The configuration still passes validation. None used to
    /// be raised, and a query going round in the answer phase asked an upstream on every jump
    /// until the limit answered SERVFAIL
    #[test]
    fn jumps_that_come_back_round_are_a_warning() {
        let any = serde_json::json!([{ "type": "any" }]);
        let jump = |to: &str| serde_json::json!([{ "type": "jump_to_pipeline", "pipeline": to }]);
        let forward = serde_json::json!([{ "type": "forward" }]);
        let pipeline = |id: &str, rules: Vec<serde_json::Value>| serde_json::json!({ "id": id, "rules": rules });
        let warned = |pipelines: Vec<serde_json::Value>| {
            let config = serde_json::json!({
                "settings": { "default_upstream": "1.1.1.1:53" },
                "pipelines": pipelines
            });
            let report = super::validate(&config.to_string()).expect("a circle is no problem");
            report
                .warnings
                .into_iter()
                .filter(|warning| warning.contains("comes back round"))
                .collect::<Vec<_>>()
        };
        let back = |place: &str, to: &str, from: &str| {
            format!(
                "{place}: jumping to \"{to}\" comes back round to \"{from}\", so a query that keeps going round is answered SERVFAIL once it has jumped response_jump_limit times, and in the answer phase asks an upstream again on every jump"
            )
        };

        // a 的规则跳到 b，b 的回答动作跳回 a / a's rule jumps to b, and b's answer action back to a
        assert_eq!(
            warned(vec![
                pipeline("a", vec![rule("to b", any.clone(), jump("b"))]),
                pipeline(
                    "b",
                    vec![serde_json::json!({
                        "name": "back",
                        "matchers": any,
                        "actions": forward,
                        "response_matchers": [{ "type": "response_rcode", "value": "SERVFAIL" }],
                        "response_actions_on_match": jump("a"),
                        "response_actions_on_miss": jump("a")
                    })]
                ),
            ]),
            [back("pipelines[1].rules[0]", "a", "b")]
        );
        // 跳回自己 / A jump back to its own pipeline
        assert_eq!(
            warned(vec![pipeline(
                "a",
                vec![
                    rule("ok", any.clone(), forward.clone()),
                    rule("again", any.clone(), jump("a"))
                ]
            )]),
            [back("pipelines[0].rules[1]", "a", "a")]
        );
        // 两个圈经过同一个 pipeline，各在合上它的规则报 / Two circles through one pipeline, each
        // at the rule that closes it
        assert_eq!(
            warned(vec![
                pipeline("a", vec![rule("to b", any.clone(), jump("b"))]),
                pipeline(
                    "b",
                    vec![
                        rule("to c", any.clone(), jump("c")),
                        rule("back", any.clone(), jump("a"))
                    ]
                ),
                pipeline("c", vec![rule("back", any.clone(), jump("a"))]),
            ]),
            [
                back("pipelines[2].rules[0]", "a", "c"),
                back("pipelines[1].rules[1]", "a", "b"),
            ]
        );
        // 一条链、两条路汇到 d、跳到不存在的 pipeline：都不成圈 / A chain, two ways meeting at d,
        // a jump to a pipeline that does not exist: no circle
        let done = pipeline("d", vec![rule("done", any.clone(), forward.clone())]);
        assert_eq!(
            warned(vec![
                pipeline("a", vec![rule("to b", any.clone(), jump("b"))]),
                pipeline("b", vec![rule("to c", any.clone(), jump("c"))]),
                pipeline(
                    "c",
                    vec![
                        rule(
                            "to d",
                            serde_json::json!([{ "type": "domain_suffix", "value": ".example" }]),
                            jump("d")
                        ),
                        rule("to d too", any.clone(), jump("d"))
                    ]
                ),
                done.clone(),
            ]),
            Vec::<String>::new()
        );
        assert_eq!(
            warned(vec![
                pipeline(
                    "a",
                    vec![
                        rule(
                            "to b",
                            serde_json::json!([{ "type": "domain_suffix", "value": ".example" }]),
                            jump("b")
                        ),
                        rule("to c", any.clone(), jump("c"))
                    ]
                ),
                pipeline("b", vec![rule("to d", any.clone(), jump("d"))]),
                pipeline("c", vec![rule("to d", any.clone(), jump("d"))]),
                done,
            ]),
            Vec::<String>::new()
        );
        let config = serde_json::json!({
            "settings": { "default_upstream": "1.1.1.1:53" },
            "pipelines": [pipeline("a", vec![rule("gone", any.clone(), jump("gone"))])]
        });
        let parsed = super::parse_config(&config.to_string()).expect("parses");
        assert!(
            !super::warnings(&parsed)
                .iter()
                .any(|warning| warning.contains("comes back round")),
            "a jump to a pipeline that does not exist is a problem, not a circle"
        );
    }

    /// 白写的取反报出来：第一个匹配器上的 `not`，只有一个匹配器时规则级的 `not`，入口、请求和回答的匹配器都一样。第一个上
    /// 的 `or`、规则级的取反配几个匹配器（第一个起头，后面的取反）照常
    /// A negation written for nothing is raised: `not` on the first matcher, or a chain-level
    /// `not` with a single matcher, for entry, request and answer matchers alike. `or` on the
    /// first, and a chain-level negation over several matchers (the first starting, the rest
    /// negated), pass
    #[test]
    fn a_negation_on_the_first_matcher_is_a_problem() {
        let config = |matchers: serde_json::Value, operator: &str| {
            serde_json::json!({
                "settings": { "default_upstream": "1.1.1.1:53" },
                "pipeline_select": [{ "pipeline": "main", "matchers": matchers, "matcher_operator": operator }],
                "pipelines": [{ "id": "main", "rules": [{
                    "name": "r",
                    "matchers": matchers,
                    "matcher_operator": operator,
                    "actions": [{ "type": "forward" }],
                    "response_matchers": [{ "type": "response_rcode", "value": "NOERROR", "operator": "or_not" }],
                }] }]
            })
        };
        let one = serde_json::json!([{ "type": "domain_suffix", "value": "cn" }]);
        let first_not =
            serde_json::json!([{ "type": "domain_suffix", "value": "cn", "operator": "not" }]);
        let two = serde_json::json!([
            { "type": "domain_suffix", "value": "cn" },
            { "type": "domain_suffix", "value": "com" },
        ]);
        let rule = "pipelines[0].rules[0]: ";
        let raised = |what: &str, matchers: &str| {
            format!(
                "{what} on the first of {matchers} has nothing before it and does not negate it; to match what it does not, put {{\"type\": \"any\"}} first"
            )
        };
        let answer = format!("{rule}{}", raised("or_not", "response_matchers"));
        for (matchers, operator) in [(&one, "not"), (&first_not, "and")] {
            assert_eq!(
                problems_of(config(matchers.clone(), operator)),
                [
                    format!("pipeline_select[0]: {}", raised("and_not", "matchers")),
                    format!("{rule}{}", raised("and_not", "matchers")),
                    answer.clone(),
                ],
                "{matchers} {operator}"
            );
        }
        for (matchers, operator) in [(&two, "not"), (&one, "or")] {
            assert_eq!(
                problems_of(config(matchers.clone(), operator)),
                std::slice::from_ref(&answer),
                "{matchers} {operator}"
            );
        }
    }

    /// 回答检查里写错的 rcode、`log` 动作写错的级别都报出来；`OTHER`、小写的 rcode 和认得的级别照常。以前前者悄悄当成
    /// OTHER，后者悄悄当成 info
    /// A misspelt rcode in an answer check and a misspelt level of a `log` action are raised;
    /// `OTHER`, lowercase rcodes and known levels pass. The first used to pass for OTHER, the
    /// second for info
    #[test]
    fn misspelt_rcodes_and_log_levels_are_problems() {
        let rule = |rcode: &str, level: &str| {
            serde_json::json!({
                "settings": { "default_upstream": "1.1.1.1:53" },
                "pipelines": [{ "id": "main", "rules": [{
                    "name": "r",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "log", "level": level }, { "type": "forward" }],
                    "response_matchers": [{ "type": "response_rcode", "value": rcode }],
                    "response_actions_on_match": [{ "type": "static_response", "rcode": "NXDOMAIN" }]
                }] }]
            })
        };
        assert_eq!(
            problems_of(rule("SERVFAILL", "WARN")),
            [
                "pipelines[0].rules[0]: log level \"WARN\" is none of trace, debug, info, warn, error",
                "pipelines[0].rules[0].response_matchers[0]: response_rcode \"SERVFAILL\" is none of NOERROR, FORMERR, SERVFAIL, NXDOMAIN, NOTIMP, REFUSED, OTHER",
            ]
        );
        for (rcode, level) in [("OTHER", "warn"), ("other", "debug"), ("servfail", "error")] {
            assert!(
                problems_of(rule(rcode, level)).is_empty(),
                "{rcode} {level}"
            );
        }
    }

    /// 编译配置时查监听地址和 DoH 的前提，和启动时一样：热重载以前不查，`bind_udp` 写错了照样重载成功，等到重启内核才
    /// 起不来
    /// Compiling a configuration checks the listener addresses and the DoH prerequisites as
    /// startup does: hot reload used not to, so a mistyped `bind_udp` reloaded fine and the
    /// kernel failed to start at the next restart
    #[test]
    fn compiling_refuses_what_would_stop_the_kernel_at_startup() {
        for (settings, cause) in [
            (
                serde_json::json!({ "bind_udp": "0.0.0.0:5353x" }),
                "settings.bind_udp: \"0.0.0.0:5353x\" is not an IP address and port",
            ),
            (
                serde_json::json!({ "bind_doh": "0.0.0.0:443" }),
                "settings.doh_tls_cert: not set",
            ),
        ] {
            let config = serde_json::json!({ "settings": settings, "pipelines": [] });
            let err = super::compile(super::parse_config(&config.to_string()).expect("parses"))
                .expect_err("refused");
            assert!(format!("{err:#}").contains(cause), "{err:#}");
        }
    }

    /// 设置本身说不通时，错误是一行英文，开头写着设置和它的值，和配置问题的写法一样：监听地址、DoH 的前提、取值范围和
    /// 相互关系都是，看得出是哪个设置、写的什么；没有换行，journald 不会拆成两条。前面不另加前缀，和启动时起不来的错误
    /// 一样：以前重载和校验时前面多了 `validate listeners: ` 或 `compile configuration: `，启动时监听地址那条没有
    /// Settings that make no sense on their own are refused with a line in English starting with
    /// the setting and its value, as configuration problems are written: the listener addresses,
    /// the DoH prerequisites, the ranges and how settings relate alike, so that which setting it
    /// is and what it says can be seen; with no line break, journald keeps it one entry. No prefix
    /// goes before it, as none goes before the error stopping startup: on a reload and in
    /// validation `validate listeners: ` or `compile configuration: ` used to go first, while at
    /// startup the listener one had none
    #[test]
    fn settings_errors_start_with_the_setting_and_its_value() {
        let doh = |more: serde_json::Value| {
            let mut settings = serde_json::json!({ "bind_doh": "0.0.0.0:443" });
            settings
                .as_object_mut()
                .unwrap()
                .extend(more.as_object().unwrap().clone());
            settings
        };
        for (settings, error) in [
            (
                serde_json::json!({ "bind_udp": "localhost:53" }),
                "settings.bind_udp: \"localhost:53\" is not an IP address and port: invalid socket address syntax",
            ),
            (
                serde_json::json!({ "bind_tcp": "0.0.0.0" }),
                "settings.bind_tcp: \"0.0.0.0\" is not an IP address and port: invalid socket address syntax",
            ),
            (
                serde_json::json!({ "bind_doh": ":443", "doh_tls_cert": "c.pem", "doh_tls_key": "k.pem" }),
                "settings.bind_doh: \":443\" is not an IP address and port: invalid socket address syntax",
            ),
            (
                doh(serde_json::json!({ "doh_tls_key": "k.pem" })),
                "settings.doh_tls_cert: not set, though settings.bind_doh is \"0.0.0.0:443\" and DoH needs it",
            ),
            (
                doh(serde_json::json!({ "doh_tls_cert": "c.pem" })),
                "settings.doh_tls_key: not set, though settings.bind_doh is \"0.0.0.0:443\" and DoH needs it",
            ),
            (
                serde_json::json!({ "cache_capacity": 0 }),
                "settings.cache_capacity: 0 leaves the cache no room for any answer; it must be greater than 0",
            ),
            (
                serde_json::json!({ "cache_max_ttl": 0 }),
                "settings.cache_max_ttl: 0 holds the TTL of every answer cached to 0, leaving the cache unused; it must be greater than 0",
            ),
            (
                serde_json::json!({ "cache_refresh_threshold_percent": 100 }),
                "settings.cache_refresh_threshold_percent: 100 makes every cache hit refresh upstream; it must be below 100",
            ),
            (
                serde_json::json!({ "upstream_timeout_ms": 0 }),
                "settings.upstream_timeout_ms: 0 expires every upstream request as it is sent; it must be greater than 0",
            ),
            (
                serde_json::json!({ "dashmap_shards": 3 }),
                "settings.dashmap_shards: 3 is neither 0 (the default) nor a power of two from 2 to 65536",
            ),
            (
                serde_json::json!({ "doq_connection_idle_timeout_seconds": u64::MAX }),
                "settings.doq_connection_idle_timeout_seconds: 18446744073709551615 is more than QUIC can carry",
            ),
            (
                serde_json::json!({ "upstream_timeout_ms": 2000, "request_timeout_ms": 1000 }),
                "settings.request_timeout_ms: 1000 is less than settings.upstream_timeout_ms (2000); it must be at least that",
            ),
        ] {
            let config = serde_json::json!({ "settings": settings, "pipelines": [] });
            let refused = super::compile(super::parse_config(&config.to_string()).expect("parses"))
                .expect_err("refused");
            let refused = format!("{refused:#}");
            assert_eq!(refused, error);
            assert!(!refused.contains('\n'), "{refused}");
        }
    }

    /// 不写 request_timeout_ms 时整体超时是上游超时的两倍半，算出来超出 u64 时取 u64::MAX；比它短的 request_timeout_ms
    /// 算一条警告，大到这样的上游超时也照样比，不会溢出
    /// The overall timeout without request_timeout_ms is two and a half upstream timeouts, u64::MAX
    /// when that is more than a u64 holds; a request_timeout_ms under it is a warning, an upstream
    /// timeout that large compared all the same, with no overflow
    #[test]
    fn the_default_request_timeout_is_two_and_a_half_upstream_timeouts() {
        let settings =
            |upstream_timeout_ms: u64, request_timeout_ms: Option<u64>| super::GlobalSettings {
                upstream_timeout_ms,
                request_timeout_ms,
                ..super::GlobalSettings::default()
            };
        for (upstream, request) in [
            (9000, 22_500),
            (3, 7),
            (u64::MAX / 2, u64::MAX),
            (u64::MAX, u64::MAX),
        ] {
            assert_eq!(
                settings(upstream, None).default_request_timeout_ms(),
                request,
                "{upstream}"
            );
        }
        let warned = |request_timeout_ms: u64| {
            let config = super::PipelineConfig {
                settings: settings(u64::MAX, Some(request_timeout_ms)),
                ..serde_json::from_value::<super::PipelineConfig>(serde_json::json!({})).unwrap()
            };
            super::warnings(&config)
                .iter()
                .any(|warning| warning.starts_with("settings.request_timeout_ms:"))
        };
        assert!(warned(u64::MAX - 1));
        assert!(!warned(u64::MAX));
    }

    /// 内核不读的键按路径报出来：拼错的设置、写错名字的匹配器（`matcher` 少了 s，规则就没有匹配器，匹配所有查询）、
    /// 选择规则和规则里多出来的键都算；退役的旧设置不算，只记 warn。以前这些都悄悄忽略，一条拦截规则写错一个字母就拦下
    /// 所有查询
    /// The keys the kernel does not read are raised by path: a misspelt setting, matchers written
    /// under the wrong name (`matcher` without its s leaves the rule with no matcher, so it matches
    /// every query), and extra keys of selector rules and rules all count; retired settings do not,
    /// getting only a warn. These used to be ignored without a word, a block rule one letter off
    /// blocking every query
    #[test]
    fn keys_the_kernel_does_not_read_are_problems() {
        let found = problems_of(serde_json::json!({
            "settings": {
                "default_upstream": "1.1.1.1:53",
                "min_tll": 30,
                "flow_control_max_permits": 500,
                "prefetch": { "prefetch_enabled": true },
                "tcp_health_check_error_threshold": 3
            },
            "pipeline_select": [{ "pipeline": "main", "matcher": [] }],
            "pipelines": [{ "id": "main", "rules": [
                {
                    "name": "block-ads",
                    "matcher": [{ "type": "domain_suffix", "value": "ads.example" }],
                    "actions": [{ "type": "static_response", "rcode": "NXDOMAIN", "ttl": 60 }]
                },
                {
                    "name": "late",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "allow" }],
                    "response_matcher": [{ "type": "response_rcode", "value": "NXDOMAIN" }]
                }
            ] }]
        }));
        let unread: Vec<&str> = found
            .iter()
            .filter_map(|problem| problem.split_once(": the kernel does not read this key"))
            .map(|(key, _)| key)
            .collect();
        assert_eq!(
            unread,
            [
                "pipeline_select[0].matcher",
                "pipelines[0].rules[0].actions[0].ttl",
                "pipelines[0].rules[0].matcher",
                "pipelines[0].rules[1].response_matcher",
                "settings.min_tll",
            ],
            "{found:#?}"
        );
    }

    /// 动作、匹配器和 ECS 里内核不读的键一样按路径、按写的顺序报出来：入口、请求和回答的匹配器，请求和回答的动作，转发和
    /// pipeline 的 ECS 都算，写在 `type`、`mode` 前面的也算；写成数组的上游照常。以前这些对象按 `type` 或 `mode` 分种类，
    /// 整个先缓冲下来再读，多出来的键悄悄丢掉：拼错 `upstream` 的转发问的是默认上游，拼错 `operator` 的取反成了正向匹配
    /// The keys the kernel does not read inside actions, matchers and ECS are raised by path, in
    /// the order written, just the same: entry, request and answer matchers, request and answer
    /// actions, and the ECS of forwards and pipelines all count, as do keys written before `type`
    /// or `mode`; an upstream written as an array passes. These objects are told apart by `type`
    /// or `mode` and used to be buffered whole before being read, extra keys dropped without a
    /// word: a forward with `upstream` misspelt asked the default upstream, and a negation with
    /// `operator` misspelt became a plain match
    #[test]
    fn keys_the_kernel_does_not_read_inside_actions_matchers_and_ecs_are_found() {
        let config = r#"{
            "settings": { "default_upstream": "1.1.1.1:53" },
            "pipeline_select": [{ "pipeline": "main", "matchers": [{ "type": "any", "operater": "or" }] }],
            "pipelines": [{ "id": "main", "ecs": { "mode": "clear", "prefix": 24 }, "rules": [{
                "name": "r",
                "matchers": [
                    { "type": "any" },
                    { "operater": "and_not", "type": "domain_suffix", "value": "ads.example" }
                ],
                "actions": [{
                    "type": "forward",
                    "upstream": ["9.9.9.9:53"],
                    "upstrem": "8.8.8.8:53",
                    "ecs": { "prefix4": 16, "mode": "from_client_ip" }
                }],
                "response_matchers": [{ "type": "response_rcode", "value": "NXDOMAIN", "values": "SERVFAIL" }],
                "response_actions_on_match": [{ "type": "allow", "upstream": "8.8.8.8:53" }]
            }] }]
        }"#;
        assert_eq!(
            super::parse_config(config).expect("parses").unread_keys,
            [
                "pipeline_select[0].matchers[0].operater",
                "pipelines[0].ecs.prefix",
                "pipelines[0].rules[0].matchers[1].operater",
                "pipelines[0].rules[0].actions[0].upstrem",
                "pipelines[0].rules[0].actions[0].ecs.prefix4",
                "pipelines[0].rules[0].response_matchers[0].values",
                "pipelines[0].rules[0].response_actions_on_match[0].upstream",
            ]
        );
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
        for place in [
            "pipeline_select[0].matchers[0]",
            "pipelines[0].rules[0].matchers[0]",
            "pipelines[0].rules[1].response_matchers[0]",
        ] {
            assert!(
                found
                    .iter()
                    .any(|problem| problem.starts_with(&format!("{place}: "))
                        && problem.contains("exact \"\" matches only the root name")),
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

    /// 每种带值的匹配器，值写成空的都按它的意思报出来：对每个名字都成立的（domain_suffix、domain_regex、geo_site_not 和
    /// 回答阶段对应的几种，以及 prefix、regex 模式的 response_txt_content，对每份带 TXT 记录的回答成立）算问题；永远不成立
    /// 的（geo_site、listener_label、upstream_equals，一个网段也没写的 response_upstream_ip、response_answer_ip，一个国家代码
    /// 也没写的 geoip 匹配器）算警告。精确比较空文字的 response_txt_content 是有意要空的 TXT 记录，不报。以前只查了域名类
    /// 和 geoip，geo_site_not 写成空的对所有名字都成立，也不算问题
    /// Every matcher with a value is raised, written empty, by what it then means: one holding
    /// for every name (domain_suffix, domain_regex, geo_site_not and their answer-phase
    /// counterparts, and response_txt_content in prefix or regex mode, holding for every answer
    /// carrying a TXT record) is a problem; one never holding (geo_site, listener_label,
    /// upstream_equals, response_upstream_ip and response_answer_ip naming no network, a geoip
    /// matcher naming no country code) is a warning. response_txt_content comparing exactly with
    /// empty text means an empty TXT record and is not raised. Only domains and geoip used to be
    /// checked, and geo_site_not written empty held for every name without being a problem
    #[test]
    fn every_matcher_written_empty_is_raised_by_what_it_means() {
        let config = serde_json::json!({
            "settings": { "default_upstream": "1.1.1.1:53" },
            "pipeline_select": [{ "pipeline": "main", "matchers": [
                { "type": "listener_label", "value": "" },
                { "type": "geo_site_not", "value": "" }
            ] }],
            "pipelines": [{ "id": "main", "rules": [{
                "name": "r",
                "matchers": [
                    { "type": "geo_site", "value": "" },
                    { "type": "domain_suffix", "value": "." },
                    { "type": "geoip_country", "country_codes": [] }
                ],
                "actions": [{ "type": "forward" }],
                "response_matchers": [
                    { "type": "upstream_equals", "value": "" },
                    { "type": "response_upstream_ip", "cidr": "" },
                    { "type": "response_answer_ip", "cidr": " , " },
                    { "type": "response_request_domain_geo_site", "value": "" },
                    { "type": "response_request_domain_geo_site_not", "value": "" },
                    { "type": "response_txt_content", "mode": "prefix", "value": "" },
                    { "type": "response_txt_content", "mode": "Regex", "value": "" },
                    { "type": "response_txt_content", "mode": "exact", "value": "" }
                ],
                "response_actions_on_match": [{ "type": "allow" }]
            }] }]
        });
        let parsed = super::parse_config(&config.to_string()).expect("parses");
        assert_eq!(
            super::problems(&parsed),
            [
                "pipeline_select[0].matchers[1]: geo_site_not \"\" matches every name",
                "pipelines[0].rules[0].matchers[1]: domain_suffix \".\" matches every name",
                "pipelines[0].rules[0].response_matchers[4]: response_request_domain_geo_site_not \"\" matches every name",
                "pipelines[0].rules[0].response_matchers[5]: response_txt_content in prefix mode with an empty value matches every answer carrying a TXT record",
                "pipelines[0].rules[0].response_matchers[6]: response_txt_content in regex mode with an empty value matches every answer carrying a TXT record",
            ]
        );
        assert_eq!(
            super::warnings(&parsed),
            [
                "pipeline_select[0].matchers[0]: listener_label \"\" never matches",
                "pipelines[0].rules[0].matchers[0]: geo_site \"\" never matches",
                "pipelines[0].rules[0].matchers[2]: geoip_country with no country code never matches",
                "pipelines[0].rules[0].response_matchers[0]: upstream_equals \"\" never matches",
                "pipelines[0].rules[0].response_matchers[1]: response_upstream_ip \"\" never matches",
                "pipelines[0].rules[0].response_matchers[2]: response_answer_ip \" , \" never matches",
                "pipelines[0].rules[0].response_matchers[3]: response_request_domain_geo_site \"\" never matches",
            ]
        );
    }

    /// 单独一个点是根：domain_exact 写成 `.` 不算问题，只命中根名字（拦对根的 ANY、NS 放大查询就这样写），写成空的才
    /// 算问题；domain_suffix 写成 `.` 和写成空的一样匹配每个名字，算问题。以前 `.` 原样留着，名字文本里没有它，两种都什么
    /// 也不匹配，也不报
    /// A lone dot is the root: domain_exact written `.` is no problem and matches the root name
    /// alone (as a rule blocking ANY or NS amplification at the root is written), and only one
    /// written empty is a problem; domain_suffix written `.` matches every name as one written
    /// empty does, a problem. The dot used to stay as written, which no name text holds, so both
    /// matched nothing and nothing was raised
    #[tokio::test]
    async fn a_lone_dot_is_the_root() {
        let upstream = crate::engine::test_support::answering_upstream(
            std::net::Ipv4Addr::new(192, 0, 2, 7),
            300,
        )
        .await;
        let config = serde_json::json!({
            "settings": { "default_upstream": upstream.address, "upstream_timeout_ms": 3000 },
            "pipelines": [{ "id": "main", "rules": [
                rule(
                    "root",
                    serde_json::json!([{ "type": "domain_exact", "value": "." }]),
                    serde_json::json!([{ "type": "static_response", "rcode": "REFUSED" }])
                ),
                rule("rest", serde_json::json!([{ "type": "any" }]), serde_json::json!([{ "type": "forward" }]))
            ] }]
        });
        assert_eq!(problems_of(config.clone()), Vec::<String>::new());
        let engine = crate::engine::test_support::engine_from(config);
        for (name, answered) in [
            (".", hickory_proto::op::ResponseCode::Refused),
            ("example.com.", hickory_proto::op::ResponseCode::NoError),
        ] {
            let mut query = hickory_proto::op::Message::new(
                0x5151,
                hickory_proto::op::MessageType::Query,
                hickory_proto::op::OpCode::Query,
            );
            query.add_query(hickory_proto::op::Query::query(
                hickory_proto::rr::Name::from_ascii(name).unwrap(),
                hickory_proto::rr::RecordType::NS,
            ));
            let reply = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                engine.handle_packet(&query.to_vec().unwrap(), "127.0.0.1:53000".parse().unwrap()),
            )
            .await
            .expect("answer in time")
            .expect("answer");
            let reply = hickory_proto::op::Message::from_vec(&reply).unwrap();
            assert_eq!(reply.metadata.response_code, answered, "{name}");
        }

        let suffix = serde_json::json!({
            "settings": { "default_upstream": "1.1.1.1:53" },
            "pipelines": [{ "id": "main", "rules": [rule(
                "all",
                serde_json::json!([{ "type": "domain_suffix", "value": "." }]),
                serde_json::json!([{ "type": "allow" }])
            )] }]
        });
        assert_eq!(
            problems_of(suffix),
            ["pipelines[0].rules[0].matchers[0]: domain_suffix \".\" matches every name"]
        );
    }

    /// 分片数、连接池和跳转上限超过上限时，启动照常起来、按上限用，算一条配置问题（启动时记错误），重载和面板保存拒绝：
    /// 没有上限时能用的 `tcp_pool_size: 2048` 升级以后照样起得来，互相跳转的两个 Pipeline 写上五百万的跳转上限，一个查询
    /// 也只跳 64 次
    /// A shard count, connection pool or jump limit over its limit starts as usual at the limit
    /// and counts as a configuration problem (logged as an error at startup), which a reload and a
    /// panel save refuse: a `tcp_pool_size: 2048` that worked before there were limits still
    /// starts after an upgrade, and with a jump limit of five million two pipelines jumping to
    /// each other still take a query no more than 64 jumps
    #[tokio::test]
    async fn settings_over_their_limits_start_held_to_them() {
        use super::{MAX_DASHMAP_SHARDS, MAX_JUMP_LIMIT, MAX_POOL_SIZE};
        let (shards, pools, jumps) = (
            MAX_DASHMAP_SHARDS as u64,
            MAX_POOL_SIZE as u64,
            u64::from(MAX_JUMP_LIMIT),
        );
        for (setting, over, most) in [
            ("dashmap_shards", shards * 2, shards),
            ("udp_pool_size", u64::MAX, pools),
            ("tcp_pool_size", 2048, pools),
            ("doh_pool_size", 2048, pools),
            ("dot_pool_size", pools + 1, pools),
            ("doq_pool_size", 2048, pools),
            ("response_jump_limit", 5_000_000, jumps),
            ("response_jump_limit", jumps + 1, jumps),
        ] {
            let config = serde_json::json!({
                "settings": { "default_upstream": "1.1.1.1:53", setting: over },
                "pipelines": []
            });
            let parsed = super::parse_config(&config.to_string()).expect("parses");
            assert_eq!(
                super::problems(&parsed),
                [format!(
                    "settings.{setting}: {over} is more than {most}, the most it may be; startup uses {most} instead"
                )]
            );
            let runtime = crate::matcher::RuntimePipelineConfig::from_config(parsed.clone())
                .unwrap_or_else(|error| panic!("{setting} {over} starts: {error:#}"));
            assert_eq!(
                serde_json::to_value(&runtime.settings).unwrap()[setting],
                most,
                "{setting}"
            );
            crate::engine::Engine::new(runtime, "test".to_string()).expect("engine builds");
            super::compile(parsed).expect_err("a reload refuses it");
        }
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
        for place in [
            "settings.default_upstream",
            "pipelines[0].rules[0]",
            "pipelines[0].rules[1]",
        ] {
            assert!(
                found
                    .iter()
                    .any(|problem| problem.starts_with(&format!("{place}: "))
                        && problem.contains("no upstream")),
                "missing {place} in {found:#?}"
            );
        }
    }

    /// forward 不写 upstream 时用 default_upstream，和文档说的一样。以前缺了这个字段整份配置读不进来
    /// （「missing field `upstream`」），启动直接失败；写成 null 或 [] 时才用默认上游
    /// A forward without upstream uses default_upstream, as the documentation says. A missing
    /// field used to make the whole configuration unreadable ("missing field `upstream`") and
    /// startup fail; only null or [] used the default upstream
    #[tokio::test]
    async fn a_forward_without_upstream_uses_the_default() {
        let default = crate::engine::test_support::answering_upstream(
            std::net::Ipv4Addr::new(192, 0, 2, 7),
            300,
        )
        .await;
        let config = serde_json::json!({
            "settings": { "default_upstream": default.address, "upstream_timeout_ms": 3000 },
            "pipelines": [{ "id": "main", "rules": [
                rule("plain", serde_json::json!([{ "type": "any" }]), serde_json::json!([{ "type": "forward" }]))
            ]}]
        });
        let parsed =
            super::parse_config(&config.to_string()).expect("a forward without upstream parses");
        assert!(matches!(
            parsed.pipelines[0].rules[0].actions[0],
            super::Action::Forward { upstream: None, .. }
        ));
        assert_eq!(super::problems(&parsed), Vec::<String>::new());

        let engine = crate::engine::test_support::engine_from(config);
        let mut query = hickory_proto::op::Message::new(
            0x7777,
            hickory_proto::op::MessageType::Query,
            hickory_proto::op::OpCode::Query,
        );
        query.metadata.recursion_desired = true;
        query.add_query(hickory_proto::op::Query::query(
            hickory_proto::rr::Name::from_ascii("plain.test.").unwrap(),
            hickory_proto::rr::RecordType::A,
        ));
        let reply = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            engine.handle_packet(&query.to_vec().unwrap(), "127.0.0.1:53000".parse().unwrap()),
        )
        .await
        .expect("answer in time")
        .expect("answer");
        let reply = hickory_proto::op::Message::from_vec(&reply).unwrap();
        assert_eq!(
            reply.answers.first().map(|record| record.data.clone()),
            Some(hickory_proto::rr::RData::A(
                hickory_proto::rr::rdata::A::new(192, 0, 2, 7)
            ))
        );
    }

    /// 一条规则里几个 forward 合成一次转发时，写成空的那个只是被跳过，查询照样由别的上游作答：不算问题，
    /// 它的 ecs 也不算进「ecs 写得不一样」。全都是空的、或者回答动作里的空 forward，照旧要报
    /// When a rule's forwards merge into one, one written empty is only skipped and the
    /// others answer the query: no problem, and its ecs does not count towards "ecs settings
    /// differ". All of them empty, or an empty forward among the answer actions, is named as
    /// before
    #[test]
    fn an_empty_forward_beside_real_ones_is_no_problem() {
        let any = serde_json::json!([{ "type": "any" }]);
        let forward =
            |upstream: &str| serde_json::json!({ "type": "forward", "upstream": upstream });
        let with_ecs = |upstream: &str, mode: &str| serde_json::json!({ "type": "forward", "upstream": upstream, "ecs": { "mode": mode } });
        let config = |rules: serde_json::Value| {
            serde_json::json!({
                "settings": { "default_upstream": "1.1.1.1:53" },
                "pipelines": [{ "id": "main", "rules": rules }]
            })
        };
        for empty in ["", " , "] {
            assert_eq!(
                problems_of(config(serde_json::json!([
                    rule(
                        "beside",
                        any.clone(),
                        serde_json::json!([forward(empty), forward("127.0.0.1:53")])
                    ),
                    rule(
                        "shared",
                        any.clone(),
                        serde_json::json!([
                            with_ecs(empty, "clear"),
                            with_ecs("127.0.0.1:53", "from_client_ip"),
                            with_ecs("127.0.0.2:53", "from_client_ip")
                        ])
                    )
                ]))),
                Vec::<String>::new(),
                "{empty:?}"
            );
        }

        let found = problems_of(config(serde_json::json!([
            rule("all empty", any.clone(), serde_json::json!([forward(""), forward(" , ")])),
            {
                "name": "answer",
                "matchers": any,
                "actions": [forward("127.0.0.1:53"), forward("127.0.0.2:53")],
                "response_actions_on_miss": [forward("")]
            }
        ])));
        for place in ["pipelines[0].rules[0]", "pipelines[0].rules[1]"] {
            assert!(
                found
                    .iter()
                    .any(|problem| problem.starts_with(&format!("{place}: "))
                        && problem.contains("no upstream")),
                "missing {place} in {found:#?}"
            );
        }
    }

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
        for place in ["pipelines[0].rules[0]", "pipelines[0].rules[1]"] {
            assert!(
                found.iter().any(|problem| {
                    problem.starts_with(&format!("{place}: "))
                        && problem.contains("ecs settings differ")
                        && problem.contains("separate rules")
                }),
                "{place}: {found:?}"
            );
        }
    }

    /// 写错的网段拒掉，报出写的是什么、在哪：规则的 client_ip、response_upstream_ip、response_answer_ip，以及
    /// pipeline_select 的 client_ip。以前只说「invalid IP address syntax」，规则一多就不知道是哪一条的哪一项
    /// A mistyped network is refused naming what was written and where: a rule's client_ip,
    /// response_upstream_ip and response_answer_ip, and pipeline_select's client_ip. It used to
    /// say only "invalid IP address syntax", leaving which item of which rule to guess
    #[test]
    fn a_mistyped_network_is_refused_naming_it_and_its_place() {
        let any = serde_json::json!([{ "type": "any" }]);
        let config =
            |select: serde_json::Value, matchers: serde_json::Value, answer: serde_json::Value| {
                serde_json::json!({
                    "settings": { "default_upstream": "1.1.1.1:53" },
                    "pipeline_select": [{ "pipeline": "main", "matchers": select }],
                    "pipelines": [{ "id": "main", "rules": [
                        rule("first", any.clone(), serde_json::json!([{ "type": "allow" }])),
                        {
                            "name": "r",
                            "matchers": matchers,
                            "actions": [{ "type": "forward", "upstream": "1.1.1.1:53" }],
                            "response_matchers": answer,
                            "response_actions_on_match": [{ "type": "allow" }]
                        }
                    ] }]
                })
            };
        let client = |cidr: &str| serde_json::json!([{ "type": "client_ip", "cidr": cidr }]);
        let answer =
            |kind: &str| serde_json::json!([{ "type": kind, "cidr": "10.0.0.0/8, nonsense" }]);
        let no_answer = serde_json::json!([]);
        for (config, place, written) in [
            (
                config(any.clone(), client("10.0.0.0/33"), no_answer.clone()),
                "pipelines[0].rules[1].matchers[0]",
                "10.0.0.0/33",
            ),
            (
                config(any.clone(), any.clone(), answer("response_upstream_ip")),
                "pipelines[0].rules[1].response_matchers[0]",
                "nonsense",
            ),
            (
                config(any.clone(), any.clone(), answer("response_answer_ip")),
                "pipelines[0].rules[1].response_matchers[0]",
                "nonsense",
            ),
            (
                config(client("nonsense"), any.clone(), no_answer.clone()),
                "pipeline_select[0].matchers[0]",
                "nonsense",
            ),
        ] {
            let error = format!(
                "{:#}",
                super::validate(&config.to_string()).expect_err("refused")
            );
            assert!(
                error.contains(&format!("{place}: \"{written}\" is not an IP network")),
                "{error}"
            );
        }
    }

    /// listener_label 只有 pipeline_select 认：写在规则里编译不过，报出写在哪；写在 pipeline_select 里照常。两边读的是
    /// 同一套请求匹配器
    /// listener_label is pipeline_select's alone: written in a rule it does not compile, naming
    /// where it is written; in pipeline_select it compiles as usual. Both read the one set of
    /// request matchers
    #[test]
    fn a_listener_label_compiles_in_pipeline_select_only() {
        let label = serde_json::json!([{ "type": "listener_label", "value": "lan" }]);
        let any = serde_json::json!([{ "type": "any" }]);
        let config = |select: &serde_json::Value, matchers: &serde_json::Value| {
            serde_json::json!({
                "settings": { "default_upstream": "1.1.1.1:53" },
                "pipeline_select": [{ "pipeline": "main", "matchers": select }],
                "pipelines": [{ "id": "main", "rules": [
                    rule("r", matchers.clone(), serde_json::json!([{ "type": "allow" }]))
                ] }]
            })
            .to_string()
        };
        validate(&config(&label, &any)).expect("pipeline_select reads listener_label");
        let refused = format!(
            "{:#}",
            validate(&config(&any, &label)).expect_err("a rule cannot read it")
        );
        assert!(
            refused.contains(
                "pipelines[0].rules[0].matchers[0]: listener_label works in pipeline_select only"
            ),
            "{refused}"
        );
    }

    /// 默认上游写了几个时，编译配置时就拆好（各项去掉空白、空项跳过）；只有一个时不拆
    /// Several default upstreams are split as the configuration compiles (each trimmed,
    /// empty ones skipped); a single one is not
    #[test]
    fn several_default_upstreams_are_split_ahead() {
        let split = |default_upstream: &str| {
            let config = serde_json::json!({
                "settings": { "default_upstream": default_upstream },
                "pipelines": [{ "id": "main", "rules": [] }]
            });
            super::compile(super::parse_config(&config.to_string()).expect("parses"))
                .expect("compiles")
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

    /// 配置里不写的设置读进来就是 `GlobalSettings::default()` 给的；每个默认值逐个钉在这里，文档和面板的基础设置都照
    /// 这些值写「默认 …」
    /// A setting a configuration leaves out reads as what `GlobalSettings::default()` gives;
    /// every default is pinned here one by one, as the docs and the panel's basic settings give
    /// these values as the defaults
    #[test]
    fn every_setting_has_the_default_written_here() {
        use super::GlobalSettings;
        let read: GlobalSettings =
            serde_json::from_str("{}").expect("an empty settings object reads");
        assert_eq!(
            format!("{read:?}"),
            format!("{:?}", GlobalSettings::default())
        );
        let settings = read;
        assert_eq!(settings.min_ttl, 0, "min_ttl");
        assert_eq!(settings.bind_udp, "0.0.0.0:5533", "bind_udp");
        assert_eq!(settings.bind_tcp, "0.0.0.0:5533", "bind_tcp");
        assert_eq!(settings.bind_doh, None, "bind_doh");
        assert_eq!(settings.doh_tls_cert, None, "doh_tls_cert");
        assert_eq!(settings.doh_tls_key, None, "doh_tls_key");
        assert_eq!(settings.doh_path, "/dns-query", "doh_path");
        assert_eq!(settings.cache_capacity, 10_000, "cache_capacity");
        assert_eq!(settings.cache_max_ttl, 86400, "cache_max_ttl");
        assert_eq!(settings.dashmap_shards, 0, "dashmap_shards");
        assert_eq!(settings.default_upstream, "1.1.1.1:53", "default_upstream");
        assert!(
            settings.default_upstream_pre_split.is_none(),
            "default_upstream_pre_split"
        );
        assert_eq!(settings.upstream_timeout_ms, 9000, "upstream_timeout_ms");
        assert_eq!(settings.request_timeout_ms, None, "request_timeout_ms");
        assert_eq!(settings.response_jump_limit, 10, "response_jump_limit");
        assert_eq!(settings.udp_pool_size, 64, "udp_pool_size");
        assert_eq!(settings.tcp_pool_size, 64, "tcp_pool_size");
        assert_eq!(settings.doh_pool_size, 8, "doh_pool_size");
        assert_eq!(
            settings.doh_health_check_error_threshold, 3,
            "doh_health_check_error_threshold"
        );
        assert_eq!(settings.dot_pool_size, 64, "dot_pool_size");
        assert_eq!(settings.doq_pool_size, 16, "doq_pool_size");
        assert_eq!(
            settings.tcp_connection_max_age_seconds, 300,
            "tcp_connection_max_age_seconds"
        );
        assert_eq!(
            settings.tcp_connection_idle_timeout_seconds, 60,
            "tcp_connection_idle_timeout_seconds"
        );
        assert_eq!(
            settings.doq_connection_idle_timeout_seconds, 60,
            "doq_connection_idle_timeout_seconds"
        );
        assert_eq!(
            settings.doq_keepalive_interval_ms, 15_000,
            "doq_keepalive_interval_ms"
        );
        assert!(settings.doq_enable_0rtt, "doq_enable_0rtt");
        assert!(settings.bootstrap.is_empty(), "bootstrap");
        assert!(!settings.flow_control_enabled, "flow_control_enabled");
        assert!(!settings.serve_stale, "serve_stale");
        assert_eq!(settings.serve_stale_ttl, 30, "serve_stale_ttl");
        assert_eq!(
            settings.serve_stale_expire_ttl, 86400,
            "serve_stale_expire_ttl"
        );
        assert!(!settings.serve_stale_ttl_reset, "serve_stale_ttl_reset");
        assert_eq!(
            settings.serve_stale_client_timeout_ms, 0,
            "serve_stale_client_timeout_ms"
        );
        assert!(
            !settings.cache_background_refresh,
            "cache_background_refresh"
        );
        assert_eq!(
            settings.cache_refresh_threshold_percent, 10,
            "cache_refresh_threshold_percent"
        );
        assert_eq!(settings.cache_refresh_min_ttl, 5, "cache_refresh_min_ttl");
        assert_eq!(settings.geoip_db_path, None, "geoip_db_path");
        assert_eq!(settings.geoip_dat_path, None, "geoip_dat_path");
        assert!(settings.geosite_data_paths.is_empty(), "geosite_data_paths");
        assert!(settings.enable_tcp_fallback, "enable_tcp_fallback");
    }

    /// 只写了一部分设置时，写了的照写的读，没写的取默认值。挑的十来个字段类型各不相同：字符串、
    /// 数字、bool、Option、列表
    /// With only some settings written, those are read as written and the rest take
    /// their defaults. The dozen or so fields picked are of different types: strings,
    /// numbers, bools, Options, lists
    #[test]
    fn written_settings_are_read_and_the_rest_take_their_defaults() {
        use super::GlobalSettings;
        {
            let read: GlobalSettings = serde_json::from_value(serde_json::json!({
                "bind_udp": "127.0.0.1:53",
                "bind_doh": "127.0.0.1:443",
                "default_upstream": "9.9.9.9:53",
                "cache_capacity": 5,
                "min_ttl": 7,
                "dashmap_shards": 4,
                "cache_refresh_threshold_percent": 50,
                "upstream_timeout_ms": 777,
                "request_timeout_ms": 1234,
                "doq_enable_0rtt": false,
                "flow_control_enabled": true,
                "geosite_data_paths": ["a.dat"]
            }))
            .expect("settings read");
            let expected = GlobalSettings {
                bind_udp: "127.0.0.1:53".to_string(),
                bind_doh: Some("127.0.0.1:443".to_string()),
                default_upstream: "9.9.9.9:53".to_string(),
                cache_capacity: 5,
                min_ttl: 7,
                dashmap_shards: 4,
                cache_refresh_threshold_percent: 50,
                upstream_timeout_ms: 777,
                request_timeout_ms: Some(1234),
                doq_enable_0rtt: false,
                flow_control_enabled: true,
                geosite_data_paths: vec!["a.dat".to_string()],
                ..GlobalSettings::default()
            };
            assert_eq!(format!("{read:?}"), format!("{expected:?}"));
        }
    }

    /// 会悄悄做成别的事的写法，每一种都报出来，按位置说在哪，和读不懂的键一样：`settings.` 下的设置、
    /// `pipeline_select[i]`、`pipelines[i].rules[j]`，匹配器的再往下写到 `.matchers[k]`、`.response_matchers[k]`。规则名
    /// 可以重复，以前按名字说在哪，重名时分不清是哪一条。不以 `/` 开头的 doh_path（DoH 对每个请求都回 404）以前不算问题，
    /// 空的 request_domain_suffix 以前让整份配置读不进来
    /// Every way of writing that silently does something else is named with its place, a path
    /// as for the keys not read: a setting under `settings.`, `pipeline_select[i]`,
    /// `pipelines[i].rules[j]`, a matcher's going on to `.matchers[k]` or
    /// `.response_matchers[k]`. Rule names may repeat, and the name a rule used to be raised by
    /// could not tell which it was. A doh_path not starting with `/` (DoH answering every query
    /// with 404) used to be no problem, and an empty request_domain_suffix used to keep the whole
    /// configuration from being read
    #[test]
    fn problems_name_what_would_silently_do_something_else() {
        let any = serde_json::json!([{ "type": "any" }]);
        let config = serde_json::json!({
            "settings": { "default_upstream": "dns.example:53", "bootstrap": "223.5.5.5:53, dns.google:53", "doh_path": "dns-query" },
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
                    "response_matchers": [
                        { "type": "request_domain_regex", "value": "" },
                        { "type": "request_domain_suffix", "value": "" }
                    ],
                    "response_actions_on_miss": [{ "type": "forward", "upstream": "udp+tcp://dns.example:53" }]
                }
            ]}]
        });
        let found = problems_of(config);
        for (place, fragment) in [
            ("settings.default_upstream", "dns.example:53"),
            ("settings.bootstrap", "dns.google:53"),
            (
                "settings.doh_path",
                "\"dns-query\" does not start with \"/\"",
            ),
            ("pipeline_select[0]", "no pipeline \"gone\""),
            ("pipeline_select[0].matchers[0]", "matches every name"),
            ("pipelines[0].rules[0]", "1.1.1.1:99999"),
            ("pipelines[0].rules[1]", "nonsense"),
            ("pipelines[0].rules[2]", "unknown prefix \"http://\""),
            ("pipelines[0].rules[3]", "sni"),
            ("pipelines[0].rules[4]", "WHATEVER"),
            ("pipelines[0].rules[5]", "192.0.2.1, nope"),
            ("pipelines[0].rules[6]", "ip \"\""),
            ("pipelines[0].rules[7]", "cname target"),
            ("pipelines[0].rules[8]", "256 bytes"),
            ("pipelines[0].rules[9]", "\"gone\", which does not exist"),
            ("pipelines[0].rules[10].matchers[0]", "matches every name"),
            ("pipelines[0].rules[11].matchers[0]", "matches every name"),
            (
                "pipelines[0].rules[12].response_matchers[0]",
                "matches every name",
            ),
            (
                "pipelines[0].rules[12].response_matchers[1]",
                "matches every name",
            ),
            ("pipelines[0].rules[12]", "udp+tcp://dns.example:53"),
        ] {
            assert!(
                found
                    .iter()
                    .any(|problem| problem.starts_with(&format!("{place}: "))
                        && problem.contains(fragment)),
                "missing {place} / {fragment} in {found:#?}"
            );
        }
        // 第 12 条的两个空匹配器各报一次 / The two empty matchers of rule 12 are raised once each
        assert_eq!(found.len(), 20, "{found:#?}");
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

    /// 两个规则组写了同一个 id：跳转和 pipeline_select 按 id 只找得到其中一个，另一个里的规则不会照写的执行。
    /// 这是一条配置问题，每个重复的 id 报一次
    /// Two pipelines written with one id: a jump or pipeline_select finds only one of them by
    /// the id, and the rules of the other do not run as written. A configuration problem,
    /// raised once for each id written more than once
    #[test]
    fn pipelines_sharing_an_id_are_a_problem() {
        let pipeline = |id: &str| serde_json::json!({ "id": id, "rules": [] });
        let config = serde_json::json!({
            "settings": { "default_upstream": "1.1.1.1:53" },
            "pipelines": [pipeline("main"), pipeline("other"), pipeline("main"), pipeline("main"), pipeline("third"), pipeline("other")]
        });
        let found = problems_of(config);
        assert_eq!(found.len(), 2, "{found:#?}");
        assert!(
            found[0].starts_with("pipelines[0]: ")
                && found[0].contains("3 pipelines are written with the id \"main\""),
            "{found:#?}"
        );
        assert!(
            found[1].starts_with("pipelines[1]: ")
                && found[1].contains("2 pipelines are written with the id \"other\""),
            "{found:#?}"
        );
    }

    /// 静态 ECS 的地址不是 IP：每个查询都记一条警告、什么也不发。这是一条配置问题；写对的不报
    /// A static ECS whose address is no IP: every query logged a warning and sent nothing. A
    /// configuration problem; one written right raises nothing
    #[test]
    fn a_static_ecs_address_that_is_no_ip_is_a_problem() {
        let any = serde_json::json!([{ "type": "any" }]);
        let forward = |ip: &str| serde_json::json!([{ "type": "forward", "upstream": "1.1.1.1:53", "ecs": { "mode": "static", "ip": ip } }]);
        let config = serde_json::json!({
            "settings": { "default_upstream": "1.1.1.1:53" },
            "pipelines": [{ "id": "main", "rules": [
                rule("wrong", any.clone(), forward("203.0.113.300")),
                rule("v4", any.clone(), forward("203.0.113.7")),
                rule("v6", any.clone(), forward("2001:db8::7")),
                {
                    "name": "late", "matchers": any, "actions": [{ "type": "forward", "upstream": "1.1.1.1:53" }],
                    "response_actions_on_miss": forward("somewhere")
                }
            ]}]
        });
        let found = problems_of(config);
        assert_eq!(found.len(), 2, "{found:#?}");
        for (place, ip) in [
            ("pipelines[0].rules[0]", "203.0.113.300"),
            ("pipelines[0].rules[3]", "somewhere"),
        ] {
            assert!(
                found.iter().any(|problem| {
                    problem.starts_with(&format!("{place}: "))
                        && problem.contains(&format!("ecs ip \"{ip}\""))
                }),
                "missing {place} in {found:#?}"
            );
        }
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
        assert_eq!(
            super::Problems::of(&err),
            super::problems(&super::parse_config(&config.to_string()).unwrap())
        );
        assert_eq!(super::Problems::of(&err).len(), 2);
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

    /// 读配置、编译配置在 info 级别什么也不记：配置生效了才记（重载记 `config reloaded`，启动记
    /// `dns server started`，都带着配置的 version）。以前读出来就记一条 `config loaded`，重载被拒时先说 loaded 再说
    /// failed；几个 forward 合并时每条规则记一条 info，面板每校验一次都刷一遍
    /// Reading and compiling a configuration log nothing at the info level: what is logged is the
    /// configuration taking effect (`config reloaded` on a reload, `dns server started` at
    /// startup, both with the configuration's version). `config loaded` used to be logged as soon
    /// as it was read, a refused reload saying loaded before it said failed, and merging several
    /// forwards logged an info for every such rule, all over again on every panel validation
    #[test]
    fn reading_and_compiling_a_configuration_log_nothing_at_info() {
        use tracing_subscriber::layer::SubscriberExt;
        struct Counted(std::sync::Arc<std::sync::atomic::AtomicUsize>);
        impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Counted {
            fn on_event(
                &self,
                event: &tracing::Event<'_>,
                _: tracing_subscriber::layer::Context<'_, S>,
            ) {
                if *event.metadata().level() <= tracing::Level::INFO {
                    self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pipeline.json");
        let forward =
            |upstream: &str| serde_json::json!({ "type": "forward", "upstream": upstream });
        std::fs::write(
            &path,
            serde_json::json!({
                "version": "v7",
                "settings": { "default_upstream": "1.1.1.1:53" },
                "pipelines": [{ "id": "main", "rules": [rule(
                    "both",
                    serde_json::json!([{ "type": "any" }]),
                    serde_json::json!([forward("1.1.1.1:53"), forward("8.8.8.8:53")])
                )] }]
            })
            .to_string(),
        )
        .unwrap();
        let logged = std::sync::Arc::default();
        let subscriber =
            tracing_subscriber::registry().with(Counted(std::sync::Arc::clone(&logged)));
        tracing::subscriber::with_default(subscriber, || {
            let (config, _) = super::load_config_with_source(&path).expect("reads");
            super::compile(config).expect("compiles");
        });
        assert_eq!(logged.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    /// 写成空的 geo_site_not 已经算一条问题，没有数据的 GeoSite 标签里不再列一个空名字：以前告警写成
    /// 「GeoSite tags , cn have no data」
    /// A geo_site_not written empty counts as a problem already, and the GeoSite tags without data
    /// no longer list an empty name: the warning used to say "GeoSite tags , cn have no data"
    #[test]
    fn a_geosite_tag_written_empty_is_no_tag_without_data() {
        let config = serde_json::json!({
            "pipelines": [{ "id": "main", "rules": [
                rule("empty", serde_json::json!([{ "type": "geo_site_not", "value": "" }]), serde_json::json!([{ "type": "allow" }])),
                rule("cn", serde_json::json!([{ "type": "geo_site", "value": "cn" }]), serde_json::json!([{ "type": "allow" }]))
            ]}]
        });
        let parsed = super::parse_config(&config.to_string()).expect("parses");
        assert_eq!(
            super::problems(&parsed),
            ["pipelines[0].rules[0].matchers[0]: geo_site_not \"\" matches every name"]
        );
        let runtime = crate::matcher::RuntimePipelineConfig::from_config(parsed).expect("compiles");
        assert_eq!(
            runtime.warnings,
            [
                "settings.geosite_data_paths: empty, so the GeoSite tags cn have no data to match against: geo_site never matches them and geo_site_not always does"
            ]
        );
    }
}
