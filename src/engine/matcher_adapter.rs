use std::net::IpAddr;

pub fn log_match(level: Option<&str>, rule_name: &str, qname: &str, client_ip: IpAddr) {
    match level.unwrap_or("info") {
        "trace" => {
            tracing::trace!(event = "matcher_log", rule = %rule_name, qname = %qname, client_ip = %client_ip, level = "trace")
        }
        "debug" => {
            tracing::debug!(event = "matcher_log", rule = %rule_name, qname = %qname, client_ip = %client_ip, level = "debug")
        }
        "warn" => {
            tracing::warn!(event = "matcher_log", rule = %rule_name, qname = %qname, client_ip = %client_ip, level = "warn")
        }
        "error" => {
            tracing::error!(event = "matcher_log", rule = %rule_name, qname = %qname, client_ip = %client_ip, level = "error")
        }
        _ => {
            tracing::info!(event = "matcher_log", rule = %rule_name, qname = %qname, client_ip = %client_ip, level = "info")
        }
    }
}
