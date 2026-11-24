use super::types::InflightMap;
use crate::matcher::RuntimePipelineConfig;
use bytes::Bytes;
use hickory_proto::op::ResponseCode;
use rustc_hash::FxHashSet;
use std::sync::Arc;

/// RAII Guard for cleaning up inflight request map
/// 为清理进行中请求映射的 RAII Guard
pub struct InflightCleanupGuard {
    pub inflight: Arc<InflightMap>,
    pub hash: u64,
    pub active: bool,
}

impl InflightCleanupGuard {
    pub fn new(inflight: Arc<InflightMap>, hash: u64) -> Self {
        Self {
            inflight,
            hash,
            active: true,
        }
    }

    pub fn defuse(&mut self) {
        self.active = false;
    }

    /// 把应答交给等在这个条目上的请求：移除条目，有请求在等时才构造 `reply` 发给它们；
    /// 之后丢弃守卫不再动这张表。TSIG 签过的应答只对签它的那个请求有效（RFC 8945），不交出去：
    /// 条目照样移除，等待者各自转发
    /// Hand the answer to the requests waiting on this entry: remove the entry, and build
    /// `reply` and send it only when someone waits; dropping the guard afterwards leaves
    /// the map alone. A TSIG-signed answer holds for the one request that was signed (RFC
    /// 8945) and is not handed on: the entry goes all the same, and the waiters forward
    /// themselves
    pub fn hand_over(&mut self, reply: impl FnOnce() -> Bytes) {
        self.defuse();
        if let Some((_, entry)) = self.inflight.remove(&self.hash)
            && let Some(tx) = entry.waiting()
        {
            let reply = reply();
            if !crate::proto_utils::last_record_is_tsig(&reply) {
                let _ = tx.send(Some(reply));
            }
        }
    }
}

impl Drop for InflightCleanupGuard {
    fn drop(&mut self) {
        if self.active {
            self.inflight.remove(&self.hash);
        }
    }
}

/// 把报文开头的事务 ID 改成 `id`；不到两个字节的报文原样不动
/// Set the transaction ID at the head of `message` to `id`; a message shorter than two
/// bytes stays as it is
#[inline]
pub(crate) fn set_id(message: &mut [u8], id: u16) {
    if let Some(head) = message.get_mut(..2) {
        head.copy_from_slice(&id.to_be_bytes());
    }
}

/// 正在刷新的条目：刷新标记 → 刷新结束时叫醒等着它的请求（见 `RefreshingGuard`）
/// The entries being refreshed: refresh mark → what wakes the requests waiting on the refresh
/// once it ends (see `RefreshingGuard`)
pub type Refreshing = dashmap::DashMap<u64, Arc<tokio::sync::Notify>>;

/// 刷新标记：打上的 guard 在 drop 时清掉它，叫醒等着这次刷新的请求。刷新先把新应答写进缓存、再放下 guard，所以被
/// 叫醒的请求一定看得到它
/// A refresh mark, cleared when its guard drops, which wakes the requests waiting on the
/// refresh. A refresh writes its fresh answer into the cache before it drops the guard, so a
/// request woken by it always sees that answer
pub struct RefreshingGuard {
    refreshing: Arc<Refreshing>,
    mark: u64,
}

impl RefreshingGuard {
    /// 打上刷新标记，返回一个 drop 时清掉它的 guard；标记已经有人打了就是 None。查和打是同一步，同时来的几个里只有
    /// 一个拿得到
    /// Set the refresh mark and return a guard that clears it on drop; None when it is
    /// set already. Checking and setting is one step, so of several arriving at once only one
    /// gets it
    pub fn try_new(refreshing: &Arc<Refreshing>, mark: u64) -> Option<Self> {
        match refreshing.entry(mark) {
            dashmap::Entry::Occupied(_) => None,
            dashmap::Entry::Vacant(entry) => {
                entry.insert(Arc::default());
                Some(Self {
                    refreshing: Arc::clone(refreshing),
                    mark,
                })
            }
        }
    }
}

impl Drop for RefreshingGuard {
    fn drop(&mut self) {
        if let Some((_, ended)) = self.refreshing.remove(&self.mark) {
            ended.notify_waiters();
        }
    }
}

/// 提取配置中使用的 GeoSite tags / Extract GeoSite tags used in configuration
///
/// 扫描配置以查找所有在匹配器中实际使用的GeoSite标签，这样可以只从数据文件中加载这些标签 / Scans the configuration to find all GeoSite tags actually used in matchers, so we can load only those tags from the data file.
pub fn extract_geosite_tags_from_config(cfg: &RuntimePipelineConfig) -> Vec<String> {
    let mut tags_set: FxHashSet<std::sync::Arc<str>> = FxHashSet::default();

    // Scan pipeline_select rules / 扫描 pipeline_select 规则
    for rule in &cfg.pipeline_select {
        for matcher in &rule.matchers {
            if let crate::matcher::RuntimePipelineSelectorMatcher::Request(
                crate::matcher::RuntimeMatcher::GeoSite { tag }
                | crate::matcher::RuntimeMatcher::GeoSiteNot { tag },
            ) = &matcher.matcher
            {
                tags_set.insert(tag.clone());
            }
        }
    }

    // Scan all pipeline rules / 扫描所有 pipeline 规则
    for pipeline in &cfg.pipelines {
        for rule in &pipeline.rules {
            // Scan request matchers / 扫描请求匹配器
            for matcher in rule.matchers.iter() {
                if let crate::matcher::RuntimeMatcher::GeoSite { tag } = &matcher.matcher {
                    tags_set.insert(tag.clone());
                }
                if let crate::matcher::RuntimeMatcher::GeoSiteNot { tag } = &matcher.matcher {
                    tags_set.insert(tag.clone());
                }
            }

            // Scan response matchers / 扫描响应匹配器
            for matcher in rule.response_matchers() {
                if let crate::matcher::RuntimeResponseMatcher::ResponseRequestDomainGeoSite {
                    value,
                } = &matcher.matcher
                {
                    tags_set.insert(value.clone());
                }
                if let crate::matcher::RuntimeResponseMatcher::ResponseRequestDomainGeoSiteNot {
                    value,
                } = &matcher.matcher
                {
                    tags_set.insert(value.clone());
                }
            }
        }
    }

    tags_set.into_iter().map(|s| s.to_string()).collect()
}

/// 规则按 GeoIP 匹配的国家代码和命名标签（已经是大写），排好序、去掉重复；`geoip_private` 不需要
/// GeoIP 数据，不算在内
/// The country codes and named tags rules match on GeoIP (uppercase already), sorted and
/// deduplicated; `geoip_private` needs no GeoIP data and does not count
pub fn extract_geoip_tags_from_config(cfg: &RuntimePipelineConfig) -> Vec<String> {
    let selector_codes = cfg
        .pipeline_select
        .iter()
        .flat_map(|rule| &rule.matchers)
        .filter_map(|matcher| match &matcher.matcher {
            crate::matcher::RuntimePipelineSelectorMatcher::Request(
                crate::matcher::RuntimeMatcher::GeoipCountry { country_codes },
            ) => Some(country_codes),
            _ => None,
        });
    let rules = cfg.pipelines.iter().flat_map(|pipeline| &pipeline.rules);
    let request_codes = rules
        .clone()
        .flat_map(|rule| rule.matchers.iter())
        .filter_map(|matcher| match &matcher.matcher {
            crate::matcher::RuntimeMatcher::GeoipCountry { country_codes } => Some(country_codes),
            _ => None,
        });
    let response_codes = rules
        .flat_map(crate::matcher::RuntimeRule::response_matchers)
        .filter_map(|matcher| match &matcher.matcher {
            crate::matcher::RuntimeResponseMatcher::ResponseAnswerIpGeoipCountry {
                country_codes,
            } => Some(country_codes),
            _ => None,
        });

    let mut tags: Vec<String> = selector_codes
        .chain(request_codes)
        .chain(response_codes)
        .flatten()
        .map(|code| code.to_string())
        .collect();
    tags.sort_unstable();
    tags.dedup();
    tags
}

/// 将字符串形式的 DNS Rcode 解析为 ResponseCode
/// Parse DNS Rcode string to ResponseCode
///
/// 支持的 Rcode: NOERROR, FORMERR, SERVFAIL, NXDOMAIN, NOTIMP, REFUSED
/// Supported Rcodes: NOERROR, FORMERR, SERVFAIL, NXDOMAIN, NOTIMP, REFUSED
#[inline]
pub(crate) fn parse_rcode(rcode: &str) -> Option<ResponseCode> {
    match rcode.to_ascii_uppercase().as_str() {
        "NOERROR" => Some(ResponseCode::NoError),
        "FORMERR" => Some(ResponseCode::FormErr),
        "SERVFAIL" => Some(ResponseCode::ServFail),
        "NXDOMAIN" => Some(ResponseCode::NXDomain),
        "NOTIMP" => Some(ResponseCode::NotImp),
        "REFUSED" => Some(ResponseCode::Refused),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::extract_geoip_tags_from_config;
    use crate::{config::PipelineConfig, matcher::RuntimePipelineConfig};

    fn runtime_config(json: &str) -> RuntimePipelineConfig {
        let config: PipelineConfig = serde_json::from_str(json).unwrap();
        RuntimePipelineConfig::from_config(config).unwrap()
    }

    #[test]
    fn geoip_tags_cover_selectors_but_not_private_matchers() {
        let selector = runtime_config(
            r#"{
                "pipeline_select": [{
                    "pipeline": "default",
                    "matchers": [{"type":"geoip_country","country_codes":["CN"]}]
                }],
                "pipelines": [{"id":"default"}]
            }"#,
        );
        assert_eq!(extract_geoip_tags_from_config(&selector), ["CN"]);

        let private_only = runtime_config(
            r#"{
                "pipelines": [{
                    "id":"default",
                    "rules": [{
                        "name":"private-only",
                        "matchers": [{"type":"geoip_private","expect":true}],
                        "response_matchers": [{
                            "type":"response_answer_ip_geoip_private",
                            "expect":true
                        }]
                    }]
                }]
            }"#,
        );
        assert!(extract_geoip_tags_from_config(&private_only).is_empty());
    }
}
