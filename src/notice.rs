//! 内核报给面板的话：配置的问题和告警（见 `config::problems`、`config::warnings`）、校验和重载拒掉配置的原因（见
//! `config::Problems`）、Geo 数据眼下的问题（见 `Engine::geo_data_warnings`）。每种话在 [`Said`] 里写一次：稳定的代号、
//! 参数和英文说法，英文就是控制通道照旧给的那句原话；面板按代号和参数用自己的说法讲，认不出的代号照原话。一条话说的是哪
//! 一处（[`Notice::place`]）另外带着，原话里写在开头。代号表和每条写成 JSON 的样子见 docs/message-codes.md（英文是
//! docs/message-codes.en.md）
//! What the kernel tells the panel: the problems and warnings of a configuration (see
//! `config::problems`, `config::warnings`), why validation and reloads refuse one (see
//! `config::Problems`), and what is wrong with the Geo data right now (see
//! `Engine::geo_data_warnings`). Each kind is written once in [`Said`]: a stable code, the
//! arguments and the English, the very words the control channel has always given; the panel
//! says it its own way by the code and the arguments, and a code it does not know by the words.
//! Where a notice is about ([`Notice::place`]) comes along apart, written at the start of the
//! words. The table of codes, and how each one is written in JSON, is in
//! docs/message-codes.en.md (docs/message-codes.md in Chinese)

use std::fmt;

use serde_json::{Map, Value};

/// 一种参数在 JSON 里的样子：文字、数、文字的列表、Geo 数据文件的种类（见 [`GeoFile`]），或者另一种话（原因，写成
/// `{code, args, text}`）
/// How an argument looks in JSON: text, a number, a list of text, a kind of Geo data file (see
/// [`GeoFile`]), or another kind of saying (a reason, written as `{code, args, text}`)
trait Arg {
    fn json(&self) -> Value;
}

impl Arg for String {
    fn json(&self) -> Value {
        Value::from(self.as_str())
    }
}

impl Arg for &'static str {
    fn json(&self) -> Value {
        Value::from(*self)
    }
}

impl Arg for Vec<String> {
    fn json(&self) -> Value {
        Value::from(self.as_slice())
    }
}

impl Arg for Box<Said> {
    fn json(&self) -> Value {
        Said::json(self)
    }
}

macro_rules! numbers {
    ($($number:ty),*) => {
        $(impl Arg for $number {
            fn json(&self) -> Value {
                Value::from(*self)
            }
        })*
    };
}

numbers!(u8, u64, usize);

/// 一种 Geo 数据文件。原话里是它的英文名（`GeoSite data file`），参数里是它的代号：`geosite`、`geoip`（GeoIP 数据文件）、
/// `mmdb`（GeoIP 数据库）
/// A kind of Geo data file. The words name it in English (`GeoSite data file`), the arguments by
/// its code: `geosite`, `geoip` (a GeoIP data file) or `mmdb` (a GeoIP database)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeoFile {
    GeoSite,
    GeoIp,
    Mmdb,
}

impl GeoFile {
    /// 英文名，原话和日志里都这样叫 / The English name, as the words and the log call it
    pub const fn name(self) -> &'static str {
        match self {
            Self::GeoSite => "GeoSite data file",
            Self::GeoIp => "GeoIP data file",
            Self::Mmdb => "GeoIP database",
        }
    }
}

impl fmt::Display for GeoFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl Arg for GeoFile {
    fn json(&self) -> Value {
        Value::from(match self {
            Self::GeoSite => "geosite",
            Self::GeoIp => "geoip",
            Self::Mmdb => "mmdb",
        })
    }
}

/// 每种话写一次：`变体 "代号" { 参数: 类型, … } => "英文", 另外的格式参数…;`。由它生成 [`Said`]、它的代号
/// （[`Said::code`]）、参数（[`Said::args`]）、英文（`Display`）和代号清单 [`CODES`]。英文里每个参数都得用上，不然编译时
/// 报没用到的变量
/// Each kind of saying written once: `Variant "code" { arg: Type, … } => "English", further
/// format arguments…;`. It makes [`Said`], its code ([`Said::code`]), its arguments
/// ([`Said::args`]), its English (`Display`) and the list of codes [`CODES`]. The English has to
/// use every argument, or compiling reports an unused variable
macro_rules! sayings {
    ($(
        $name:ident $code:literal $({ $($arg:ident: $ty:ty),+ $(,)? })?
            => $english:literal $(, $more:expr)*;
    )+) => {
        /// 内核说的一种话：代号、参数和英文（见本模块）。原因（上游地址为什么用不了，见 [`Said::UpstreamUnusable`]）也是
        /// 一种话，套在说它的那种话的参数里
        /// One kind of thing the kernel says: its code, its arguments and its English (see this
        /// module). A reason (why an upstream address cannot be used, see
        /// [`Said::UpstreamUnusable`]) is a kind of saying too, held in the arguments of the one
        /// giving it
        #[derive(Debug, Clone, PartialEq, Eq)]
        #[non_exhaustive]
        pub enum Said {
            $($name $({ $($arg: $ty),+ })?,)+
        }

        impl Said {
            /// 稳定的代号，snake_case / The stable code, in snake_case
            pub fn code(&self) -> &'static str {
                match self {
                    $(Self::$name { .. } => $code,)+
                }
            }

            /// 参数，按名字（见 [`CODES`]）/ The arguments, by name (see [`CODES`])
            pub fn args(&self) -> Map<String, Value> {
                let mut args = Map::new();
                match self {
                    $(Self::$name $({ $($arg),+ })? => {
                        $($(args.insert(stringify!($arg).to_owned(), Arg::json($arg));)+)?
                    })+
                }
                args
            }
        }

        impl fmt::Display for Said {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    $(Self::$name $({ $($arg),+ })? => write!(f, $english $(, $more)*),)+
                }
            }
        }

        /// 每种话的代号和参数名，照 [`Said`] 里写的顺序。面板拿它核对每个代号都有自己的说法
        /// The code and argument names of every kind of saying, in the order [`Said`] writes
        /// them. The panel checks against it that it has words of its own for every code
        pub const CODES: &[(&str, &[&str])] = &[$(($code, &[$($(stringify!($arg)),+)?]),)+];
    };
}

sayings! {
    // 上游地址：settings.default_upstream 和规则的 forward 写的（见 `config::problems`）
    // Upstream addresses: those settings.default_upstream and the forwards of rules write (see
    // `config::problems`)
    NoUpstream "no_upstream" => "no upstream is written, so every query it gets would fail";
    UpstreamUnknownPrefix "upstream_unknown_prefix" { upstream: String, prefix: String }
        => "upstream \"{upstream}\" starts with an unknown prefix \"{prefix}://\"";
    UpstreamUnusable "upstream_unusable" { upstream: String, reason: Box<Said> }
        => "upstream \"{upstream}\" is not usable: {reason}";
    DefaultUpstreamOver "default_upstream_over" { transport: &'static str, problem: Box<Said> }
        => "a forward writing no upstream asks settings.default_upstream over {transport}, and {problem}";
    BootstrapServerUnusable "bootstrap_server_unusable" { server: String, reason: Box<Said> }
        => "server \"{server}\" is not usable: {reason}";

    // 上游地址为什么用不了（见 `engine::transport::check_upstream_address`）：上面几种话的 `reason`
    // Why an upstream address cannot be used (see `engine::transport::check_upstream_address`):
    // the `reason` of the sayings above
    AddressNotIpPort "address_not_ip_port" { error: String }
        => "expected an IP address and a port: {error}";
    PortZero "port_zero" => "port 0";
    AddressNotHostPort "address_not_host_port" => "expected a host and a port";
    PortInvalid "port_invalid" { error: String } => "invalid port: {error}";
    HostInvalid "host_invalid" { host: String } => "invalid host \"{host}\"";
    DohSecondPrefix "doh_second_prefix" { prefix: String }
        => "a second prefix \"{prefix}://\" after the first; a DoH upstream always goes over https";
    DohUrlInvalid "doh_url_invalid" { error: String } => "invalid doh url: {error}";
    TlsServerNameInvalid "tls_server_name_invalid" { error: String }
        => "invalid tls server name: {error}";
    SecondPrefix "second_prefix" { prefix: String } => "a second prefix \"{prefix}://\" after the first";
    TlsUrlInvalid "tls_url_invalid" { transport: &'static str, error: String }
        => "invalid {transport} upstream url: {error}";
    TlsHostMissing "tls_host_missing" { transport: &'static str } => "{transport} upstream missing host";
    TlsPathGiven "tls_path_given" { transport: &'static str }
        => "{transport} upstream should not contain path";
    ZeroRttInvalid "zero_rtt_invalid" { key: String, value: String }
        => "invalid {key} \"{value}\", expected true, false, 1, 0, yes, no, on or off";
    TlsParameterUnknown "tls_parameter_unknown" { transport: &'static str, key: String }
        => "{transport} upstream does not take the parameter \"{key}\"";
    DoqIpNeedsSni "doq_ip_needs_sni"
        => "doq upstream with IP address requires explicit sni (e.g. doq://223.5.5.5:853?sni=alidns.com)";

    // 设置（见 `config::problems`、`GlobalSettings::listeners`、`GlobalSettings::validate`），说的那个设置是位置
    // Settings (see `config::problems`, `GlobalSettings::listeners`, `GlobalSettings::validate`),
    // the setting spoken of being the place
    DohPathWithoutSlash "doh_path_without_slash" { path: String }
        => "\"{path}\" does not start with \"/\", so it matches no request and DoH answers every query with 404";
    SettingOverLimit "setting_over_limit" { value: u64, most: u64 }
        => "{value} is more than {most}, the most it may be; startup uses {most} instead";
    ListenAddressInvalid "listen_address_invalid" { value: String, error: String }
        => "\"{value}\" is not an IP address and port: {error}";
    DohSettingMissing "doh_setting_missing" { bind_doh: String }
        => "not set, though settings.bind_doh is \"{bind_doh}\" and DoH needs it";
    CacheCapacityZero "cache_capacity_zero"
        => "0 leaves the cache no room for any answer; it must be greater than 0";
    CacheMaxTtlZero "cache_max_ttl_zero"
        => "0 holds the TTL of every answer cached to 0, leaving the cache unused; it must be greater than 0";
    RefreshThresholdTooHigh "refresh_threshold_too_high" { value: u8 }
        => "{value} makes every cache hit refresh upstream; it must be below 100";
    UpstreamTimeoutZero "upstream_timeout_zero"
        => "0 expires every upstream request as it is sent; it must be greater than 0";
    DashmapShardsInvalid "dashmap_shards_invalid" { value: usize, most: usize }
        => "{value} is neither 0 (the default) nor a power of two from 2 to {most}";
    DoqIdleTimeoutTooLong "doq_idle_timeout_too_long" { value: u64 } => "{value} is more than QUIC can carry";
    RequestTimeoutBelowUpstream "request_timeout_below_upstream" { value: u64, upstream: u64 }
        => "{value} is less than settings.upstream_timeout_ms ({upstream}); it must be at least that";

    // pipeline_select、pipeline 和规则（见 `config::problems`）/ pipeline_select, pipelines and
    // rules (see `config::problems`)
    SelectPipelineMissing "select_pipeline_missing" { pipeline: String } => "no pipeline \"{pipeline}\"";
    NegationOnFirst "negation_on_first" { operator: &'static str, matchers: &'static str }
        => "{operator} on the first of {matchers} has nothing before it and does not negate it; to match what it does not, put {{\"type\": \"any\"}} first";
    PipelineIdRepeated "pipeline_id_repeated" { times: usize, id: String }
        => "{times} pipelines are written with the id \"{id}\"; only the first of them takes effect, and the rules of the others never run; give each pipeline its own id";
    KeyNotRead "key_not_read"
        => "the kernel does not read this key, so what it says has no effect; check its spelling and where it is written";
    ForwardEcsDiffer "forward_ecs_differ"
        => "its forward actions are asked together as one forward, which sends one ECS, but their ecs settings differ, so none of them is sent; write the same ecs on each, or split them into separate rules";
    EcsIpNotIp "ecs_ip_not_ip" { ip: String }
        => "ecs ip \"{ip}\" is not an IP address, so no subnet is set and the client's own ECS, if any, goes upstream";
    RcodeUnknown "rcode_unknown" { rcode: String }
        => "rcode \"{rcode}\" is none of NOERROR, FORMERR, SERVFAIL, NXDOMAIN, NOTIMP, REFUSED";
    StaticIpInvalid "static_ip_invalid" { ip: String }
        => "ip \"{ip}\" is not a comma-separated list of IP addresses";
    CnameTargetInvalid "cname_target_invalid" { target: String }
        => "cname target \"{target}\" is not a domain name";
    TxtNoString "txt_no_string"
        => "text names no string; a TXT record holds at least one, write \"\" for an empty one";
    TxtSegmentTooLong "txt_segment_too_long" { bytes: usize, most: usize }
        => "a TXT segment of {bytes} bytes is longer than {most}";
    TxtTooLong "txt_too_long" { bytes: usize, most: usize }
        => "TXT content takes {bytes} bytes in its record (one length byte per segment), more than the {most} that fit in an answer";
    LogLevelUnknown "log_level_unknown" { level: String }
        => "log level \"{level}\" is none of {}", crate::config::LOG_LEVELS.join(", ");
    JumpTargetMissing "jump_target_missing" { pipeline: String }
        => "jump to pipeline \"{pipeline}\", which does not exist";

    // 匹配器写的值（见 `config::problems`、`config::warnings`），`matcher` 是匹配器的种类（`domain_suffix`）
    // The values matchers write (see `config::problems`, `config::warnings`), `matcher` being the
    // kind of matcher (`domain_suffix`)
    MatchesEveryName "matches_every_name" { matcher: &'static str, value: String }
        => "{matcher} \"{value}\" matches every name";
    MatchesOnlyRoot "matches_only_root" { matcher: &'static str }
        => "{matcher} \"\" matches only the root name; write \".\" to mean the root";
    TxtEmptyMatchesEveryAnswer "txt_empty_matches_every_answer" { mode: String }
        => "response_txt_content in {mode} mode with an empty value matches every answer carrying a TXT record";
    ResponseRcodeUnknown "response_rcode_unknown" { rcode: String }
        => "response_rcode \"{rcode}\" is none of NOERROR, FORMERR, SERVFAIL, NXDOMAIN, NOTIMP, REFUSED, OTHER";
    NeverMatches "never_matches" { matcher: &'static str, value: String }
        => "{matcher} \"{value}\" never matches";
    NoCountryCode "no_country_code" { matcher: &'static str }
        => "{matcher} with no country code never matches";
    RegexCapitals "regex_capitals" { matcher: &'static str, pattern: String, capitals: Vec<String> }
        => "{matcher} \"{pattern}\": the capitals in {} never match, as the names rules see are lowercase; write them in lowercase or under (?i)",
            capitals.iter().map(|capital| format!("\"{capital}\"")).collect::<Vec<_>>().join(", ");

    // 编译不了的匹配器（见 `RuntimePipelineConfig::from_config`）/ Matchers that do not compile (see
    // `RuntimePipelineConfig::from_config`)
    ListenerLabelOutsideSelect "listener_label_outside_select"
        => "listener_label works in pipeline_select only";
    NetworkInvalid "network_invalid" { value: String, error: String }
        => "\"{value}\" is not an IP network: {error}";
    MacInvalid "mac_invalid" { value: String }
        => "\"{value}\" is not a MAC address; write six two-digit hexadecimal numbers separated by \":\" or \"-\", such as aa:bb:cc:dd:ee:ff";
    RegexTooLong "regex_too_long" { bytes: usize, most: usize }
        => "regex pattern too long: {bytes} bytes (max {most})";
    RegexInvalid "regex_invalid" { error: String } => "{error}";
    TxtRegexInvalid "txt_regex_invalid" { error: String } => "invalid regex: {error}";
    QclassUnknown "qclass_unknown" { qclass: String } => "unsupported qclass: {qclass}";
    QtypeUnknown "qtype_unknown" { qtype: String } => "unsupported qtype: {qtype}";
    TxtModeUnknown "txt_mode_unknown" { mode: String }
        => "invalid TXT match mode: {mode}, must be one of: exact, prefix, regex";

    // 告警（见 `config::warnings`）/ Warnings (see `config::warnings`)
    BackgroundRefreshRuleUnused "background_refresh_rule_unused"
        => "has no effect, as a background refresh replays the original request through its own rules; the entry can be removed";
    SettingRetired "setting_retired" => "no longer read, so it has no effect; the entry can be removed";
    CacheCapacityLarge "cache_capacity_large" { value: u64 }
        => "{value} is very large and may take a lot of memory";
    RequestTimeoutShort "request_timeout_short" { value: u64, upstream: u64 }
        => "{value} is under 2.5 times upstream_timeout_ms ({upstream}), which may cut the resend and the TCP fallback short";
    JumpCycle "jump_cycle" { target: String, back_to: String }
        => "jumping to \"{target}\" comes back round to \"{back_to}\", so a query that keeps going round is answered SERVFAIL once it has made every jump it may (response_jump_limit in the request phase, and as many again from an answer action's first jump on), and in the answer phase asks an upstream again on every jump";
    GeositeTagsWithoutData "geosite_tags_without_data" { tags: Vec<String> }
        => "empty, so the GeoSite tags {} have no data to match against: geo_site never matches them and geo_site_not always does",
            tags.join(", ");
    GeoipTagsWithoutData "geoip_tags_without_data" { tags: Vec<String> }
        => "not set and neither is settings.geoip_db_path, so the GeoIP tags {} have no data to match against: geoip_country never matches them",
            tags.join(", ");
    GeoipTagsBeyondMmdb "geoip_tags_beyond_mmdb" { tags: Vec<String> }
        => "not set, and settings.geoip_db_path answers two-letter country codes alone, so the GeoIP tags {} have no data to match against: geoip_country never matches them",
            tags.join(", ");
    HostNamesWithoutBootstrap "host_names_without_bootstrap" { host: String }
        => "not set, so upstream host names such as \"{host}\" are resolved by the system resolver; should that be KixDNS itself, resolving one comes back round to KixDNS and the upstream cannot be reached: set bootstrap to plain DNS servers written as IP:port";

    // Geo 数据眼下的问题（见 `Engine::geo_data_warnings`），没有位置 / What is wrong with the Geo
    // data right now (see `Engine::geo_data_warnings`), with no place
    DataFileMissing "data_file_missing" { file: GeoFile, path: String } => "{file} {path} does not exist";
    DataFileUnreadable "data_file_unreadable" { file: GeoFile, path: String, error: String }
        => "{file} {path} cannot be read: {error}";
    DataFileTagsGone "data_file_tags_gone" { file: GeoFile, path: String, tags: Vec<String> }
        => "{file} {path} now has none of the tags rules use; the data read from it before stays for {} until it changes again",
            tags.join(", ");
    // 一种数据的文件（`file` 是 `geosite` 或 `geoip`）都监视不了，英文说它们的复数 / The files of one kind of data
    // (`file` being `geosite` or `geoip`) cannot be watched at all, the English naming them in the plural
    DataWatchFailed "data_watch_failed" { file: GeoFile, error: String }
        => "{file}s cannot be watched for changes, which are read after a restart or a reload changing what is read (the files, or the tags rules use): {error}";
    DataFilePartlyWatched "data_file_partly_watched" { file: GeoFile, path: String, error: String }
        => "{file} {path} cannot be watched everywhere it leads, {}: {error}", crate::watcher::SEEN_WITHIN;
    GeositeTagsUnprovided "geosite_tags_unprovided" { tags: Vec<String> }
        => "GeoSite tags {} are in no data file: geo_site never matches them and geo_site_not always does",
            tags.join(", ");
    GeoipTagsUnprovided "geoip_tags_unprovided" { tags: Vec<String> }
        => "GeoIP tags {} are in no GeoIP data: geoip_country never matches them", tags.join(", ");
}

impl Said {
    /// 写成 JSON：`{code, args, text}`，`text` 是英文原话。说出它的那种话的参数里就这样写（见 [`Said`]）
    /// As JSON: `{code, args, text}`, `text` the English words. The arguments of the saying giving
    /// it write it so (see [`Said`])
    pub fn json(&self) -> Value {
        serde_json::json!({ "code": self.code(), "args": self.args(), "text": self.to_string() })
    }
}

/// 一些地方要的是错误（`anyhow` 包着的、建上游客户端时的），这些话照样当错误用 / Where an error is
/// wanted (wrapped in `anyhow`, as an upstream client is built), these sayings serve as one
impl std::error::Error for Said {}

/// 一条话：说的是哪一处（`settings.bootstrap`、`pipelines[0].rules[2].matchers[1]` 这样的路径，Geo 数据的话没有）和说了
/// 什么（见 [`Said`]）。原话是位置、冒号和英文，没有位置的就是英文
/// A notice: where it is about (a path such as `settings.bootstrap` or
/// `pipelines[0].rules[2].matchers[1]`, none for one on the Geo data) and what is said (see
/// [`Said`]). The words are the place, a colon and the English, or the English alone without a
/// place
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    place: Option<String>,
    said: Said,
}

impl Notice {
    /// 说 `place` 的一条 / One about `place`
    pub fn at(place: impl Into<String>, said: Said) -> Self {
        Self {
            place: Some(place.into()),
            said,
        }
    }

    /// 说的是哪一处，没有位置时为 None / Where it is about, None without a place
    pub fn place(&self) -> Option<&str> {
        self.place.as_deref()
    }

    /// 说了什么 / What is said
    pub fn said(&self) -> &Said {
        &self.said
    }

    /// 写成 JSON：`{place, code, args, text}`，没有位置时 `place` 为 null，`text` 是原话（见 [`Notice`]）
    /// As JSON: `{place, code, args, text}`, `place` null without one and `text` the words (see
    /// [`Notice`])
    pub fn json(&self) -> Value {
        serde_json::json!({
            "place": self.place,
            "code": self.said.code(),
            "args": self.said.args(),
            "text": self.to_string(),
        })
    }
}

/// 没有位置的一条 / One without a place
impl From<Said> for Notice {
    fn from(said: Said) -> Self {
        Self { place: None, said }
    }
}

impl fmt::Display for Notice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.place {
            Some(place) => write!(f, "{place}: {}", self.said),
            None => self.said.fmt(f),
        }
    }
}

/// 测试用：每条的原话 / For tests: the words of each
#[cfg(test)]
pub(crate) fn texts(notices: &[Notice]) -> Vec<String> {
    notices.iter().map(Notice::to_string).collect()
}

#[cfg(test)]
#[path = "notice_tests.rs"]
mod tests;
