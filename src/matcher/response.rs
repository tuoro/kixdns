//! 回答阶段的匹配器：按上游的应答（rcode、记录类型、地址、TXT 内容）判断规则的回答检查命中没有
//! The response-phase matchers: whether a rule's answer check matches, judged by the upstream's
//! answer (rcode, record types, addresses, TXT content)

use super::*;
#[derive(Debug, Clone)]
pub enum RuntimeResponseMatcher {
    /// 回答来自 `value` 写的上游：`value` 和作答上游的名字（`udp:1.1.1.1:53`）逐字相同，或作答上游的地址是
    /// `addresses` 之一
    /// The answer came from the upstream `value` writes: `value` is the answering upstream's
    /// name (`udp:1.1.1.1:53`) to the letter, or that upstream's address is one of `addresses`
    UpstreamEquals {
        value: Arc<str>,
        /// 把 `value` 当转发里的上游来读得到的地址：逗号隔开的每一个，去掉前缀
        /// The addresses `value` gives read as a forward's upstream: each of those the commas
        /// separate, less its prefix
        addresses: Box<[Box<str>]>,
    },
    RequestDomainSuffix {
        value: Arc<str>,
    },
    RequestDomainExact {
        value: Arc<str>,
    },
    RequestDomainRegex {
        regex: Regex,
    },
    ResponseUpstreamIp {
        nets: Vec<IpNet>,
    },
    /// Match Answer A/AAAA addresses and HTTPS/SVCB IP hints.
    ResponseAnswerIp {
        nets: Vec<IpNet>,
    },
    /// 匹配 Answer 中第一个记录的记录类型 / Match the record type of the first record in the Answer
    ResponseType {
        value: RecordType,
    },
    /// 匹配响应码 / Match the response code
    /// `Some(rc)` 精确匹配指定响应码；`None` 表示"OTHER"回退，匹配任何非标准响应码
    /// `Some(rc)` for exact match; `None` for "OTHER" fallback matching any non-standard rcode
    ResponseRcode {
        value: Option<ResponseCode>,
    },
    ResponseQclass {
        value: DNSClass,
    },
    ResponseEdnsPresent {
        expect: bool,
    },
    /// 匹配响应中 IP 的 GeoIP 国家代码或命名标签 / Match GeoIP country codes or named tags of response IPs
    ResponseAnswerIpGeoipCountry {
        country_codes: Vec<Arc<str>>,
    },
    /// 匹配响应中 IP 是否为私有 IP / Match whether IPs in response are private
    ResponseAnswerIpGeoipPrivate {
        expect: bool,
    },
    /// 匹配响应中的请求域名是否属于指定 GeoSite 分类 / Match if request domain in response belongs to specified GeoSite category
    ResponseRequestDomainGeoSite {
        value: Arc<str>,
    },
    /// 匹配响应中的请求域名是否不属于指定 GeoSite 分类 / Match if request domain in response does NOT belong to specified GeoSite category
    ResponseRequestDomainGeoSiteNot {
        value: Arc<str>,
    },
    /// 匹配响应中的 TXT 记录内容 / Match TXT record content in response
    ResponseTxtContent {
        mode: TxtMatchMode,
        value: Arc<str>,
        regex: Option<Regex>,
    },
}

#[derive(Debug, Clone)]
pub struct RuntimeResponseMatcherWithOp {
    pub operator: MatchOperator,
    pub matcher: RuntimeResponseMatcher,
}

/// 作答上游 `upstream`（`udp:1.1.1.1:53`，不带传输名也行）的 IP：地址里的主机是 IP 字面量时有，是域名时没有。
/// 路径（DoH）和参数（`?sni=`）不看
/// The IP of the answering upstream `upstream` (`udp:1.1.1.1:53`, or without the transport):
/// there is one when the host in its address is an IP literal, none when it is a name. A path
/// (DoH) and parameters (`?sni=`) are not read
#[inline]
fn try_parse_upstream_ip(upstream: &str) -> Option<IpAddr> {
    let address = crate::engine::upstream::answered_address(upstream);
    let host = address.split(['/', '?']).next().unwrap_or(address);
    host.parse::<SocketAddr>()
        .ok()
        .map(|sa| sa.ip())
        .or_else(|| host.parse::<IpAddr>().ok())
}

impl RuntimeResponseMatcher {
    pub fn from_config(m: config::ResponseMatcher) -> anyhow::Result<Self> {
        Ok(match m {
            config::ResponseMatcher::UpstreamEquals { value } => {
                RuntimeResponseMatcher::UpstreamEquals {
                    addresses: crate::engine::upstream::addresses(&value)
                        .map(Box::from)
                        .collect(),
                    value: Arc::from(value),
                }
            }
            config::ResponseMatcher::RequestDomainSuffix { value } => {
                RuntimeResponseMatcher::RequestDomainSuffix {
                    value: domain_value(&value),
                }
            }
            config::ResponseMatcher::RequestDomainExact { value } => {
                RuntimeResponseMatcher::RequestDomainExact {
                    value: domain_value(&value),
                }
            }
            config::ResponseMatcher::RequestDomainRegex { value } => {
                RuntimeResponseMatcher::RequestDomainRegex {
                    regex: domain_regex(&value)?,
                }
            }
            config::ResponseMatcher::ResponseUpstreamIp { cidr } => {
                RuntimeResponseMatcher::ResponseUpstreamIp {
                    nets: cidr_list(&cidr)?,
                }
            }
            config::ResponseMatcher::ResponseAnswerIp { cidr } => {
                RuntimeResponseMatcher::ResponseAnswerIp {
                    nets: cidr_list(&cidr)?,
                }
            }
            config::ResponseMatcher::ResponseType { value } => {
                RuntimeResponseMatcher::ResponseType {
                    value: parse_dns_type(&value)?,
                }
            }
            // None 是 `OTHER`：上面几个以外的 RCODE。别的写法读配置时就报出来（见 `config::problems`）
            // None is `OTHER`: any RCODE besides those. Anything else written is raised when the
            // configuration is read (see `config::problems`)
            config::ResponseMatcher::ResponseRcode { value } => {
                RuntimeResponseMatcher::ResponseRcode {
                    value: crate::engine::utils::parse_rcode(&value),
                }
            }
            config::ResponseMatcher::ResponseQclass { value } => {
                RuntimeResponseMatcher::ResponseQclass {
                    value: parse_dns_class(&value)?,
                }
            }
            config::ResponseMatcher::ResponseEdnsPresent { expect } => {
                RuntimeResponseMatcher::ResponseEdnsPresent { expect }
            }
            config::ResponseMatcher::ResponseAnswerIpGeoipCountry { country_codes } => {
                RuntimeResponseMatcher::ResponseAnswerIpGeoipCountry {
                    country_codes: normalize_geoip_country_codes(country_codes),
                }
            }
            config::ResponseMatcher::ResponseAnswerIpGeoipPrivate { expect } => {
                RuntimeResponseMatcher::ResponseAnswerIpGeoipPrivate { expect }
            }
            config::ResponseMatcher::ResponseRequestDomainGeoSite { value } => {
                RuntimeResponseMatcher::ResponseRequestDomainGeoSite {
                    value: Arc::from(value),
                }
            }
            config::ResponseMatcher::ResponseRequestDomainGeoSiteNot { value } => {
                RuntimeResponseMatcher::ResponseRequestDomainGeoSiteNot {
                    value: Arc::from(value),
                }
            }
            config::ResponseMatcher::ResponseTxtContent { mode, value } => {
                let mode = TxtMatchMode::from_str(&mode)?;
                let regex = match mode {
                    TxtMatchMode::Regex => {
                        // ReDoS保护: 限制正则表达式大小 / ReDoS protection: limit regex size
                        const MAX_TXT_REGEX_LEN: usize = 1000;
                        regex_within(&value, MAX_TXT_REGEX_LEN)?;
                        // 编译后的大小和域名正则一个上限。以前限在 1000 字节，`.`、`\d+` 都编译不过。
                        // 字符类不像域名正则那样改成 ASCII：TXT 里本来就可以写任意文字，照写的编译
                        // The compiled size gets the limit domain regexes have. It was held to
                        // 1000 bytes, which `.` or `\d+` already exceed. Its classes are not made
                        // ASCII as a domain regex's are: TXT may hold any text, so it compiles as
                        // written
                        Some(
                            limited_regex(&value)
                                .map_err(|e| anyhow::anyhow!("invalid regex: {}", e))?,
                        )
                    }
                    _ => None,
                };
                RuntimeResponseMatcher::ResponseTxtContent {
                    mode,
                    value: Arc::from(value),
                    regex,
                }
            }
        })
    }

    pub fn matches(
        &self,
        upstream: &str,
        qname: &str,
        qtype: RecordType,
        qclass: DNSClass,
        msg: &Message,
        geoip_manager: Option<&crate::matcher::geoip::GeoIpManager>,
        geosite_manager: Option<&crate::matcher::geosite::GeoSiteManager>,
    ) -> bool {
        match self {
            RuntimeResponseMatcher::UpstreamEquals { value, addresses } => {
                upstream == value.as_ref() || {
                    let answered = crate::engine::upstream::answered_address(upstream);
                    addresses.iter().any(|address| **address == *answered)
                }
            }
            RuntimeResponseMatcher::RequestDomainSuffix { value } => {
                domain_suffix_matches(qname, value)
            }
            RuntimeResponseMatcher::RequestDomainExact { value } => {
                qname.eq_ignore_ascii_case(value)
            }
            RuntimeResponseMatcher::RequestDomainRegex { regex } => regex.is_match(qname),
            RuntimeResponseMatcher::ResponseUpstreamIp { nets } => try_parse_upstream_ip(upstream)
                .map(|ip| nets.iter().any(|net| net.contains(&ip)))
                .unwrap_or(false),
            RuntimeResponseMatcher::ResponseAnswerIp { nets } => {
                // 使用辅助函数检查是否有任意 IP 匹配 CIDR / Use helper to check if any IP matches CIDR
                matcher_helpers::any_ip_matches(msg, |ip| nets.iter().any(|net| net.contains(&ip)))
            }
            RuntimeResponseMatcher::ResponseType { value } => {
                let rrty = msg
                    .answers
                    .first()
                    .map(|r| r.record_type())
                    .unwrap_or(qtype);
                rrty == *value
            }
            RuntimeResponseMatcher::ResponseRcode { value } => {
                match value {
                    Some(rc) => msg.metadata.response_code == *rc,
                    None => {
                        // "OTHER" fallback: match any response code that is NOT one of the 6 standard codes
                        // "OTHER" 回退：匹配不在6个标准码中的任何响应码
                        !matches!(
                            msg.metadata.response_code,
                            ResponseCode::NoError
                                | ResponseCode::FormErr
                                | ResponseCode::ServFail
                                | ResponseCode::NXDomain
                                | ResponseCode::NotImp
                                | ResponseCode::Refused
                        )
                    }
                }
            }
            RuntimeResponseMatcher::ResponseQclass { value } => value == &qclass,
            RuntimeResponseMatcher::ResponseEdnsPresent { expect } => {
                let edns = msg.edns.is_some();
                edns == *expect
            }
            RuntimeResponseMatcher::ResponseAnswerIpGeoipCountry { country_codes } => {
                let Some(manager) = geoip_manager else {
                    return false;
                };
                let mut has_ip = false;
                let mut matches_country = |ip| manager.matches_any_tag(ip, country_codes);
                let all_match = msg.answers.iter().all(|record| {
                    matcher_helpers::all_rdata_ips_match(
                        &record.data,
                        &mut has_ip,
                        &mut matches_country,
                    )
                });
                all_match && has_ip
            }
            RuntimeResponseMatcher::ResponseAnswerIpGeoipPrivate { expect } => {
                matcher_helpers::any_ip_matches(msg, crate::matcher::geoip::is_private_ip)
                    == *expect
            }
            RuntimeResponseMatcher::ResponseRequestDomainGeoSite { value } => {
                // 使用辅助函数检查请求域名是否属于指定的 GeoSite 分类 / Use helper to check if request domain belongs to GeoSite category
                geosite_manager.is_some_and(|mgr| mgr.matches(value, qname))
            }
            RuntimeResponseMatcher::ResponseRequestDomainGeoSiteNot { value } => {
                // 使用辅助函数检查请求域名是否不属于指定的 GeoSite 分类 / Use helper to check if request domain does NOT belong to GeoSite category
                geosite_manager.is_some_and(|mgr| !mgr.matches(value, qname))
            }
            RuntimeResponseMatcher::ResponseTxtContent { mode, value, regex } => {
                // 每条 TXT 记录分开比较，有一条命中就算命中；一条记录里的几个字符串先不加空格连起来，和
                // RFC 7208 §3.3 读 SPF 记录一样（长过 255 字节的文字只能拆成几个字符串写）。以前所有记录
                // 连成一串再比：同时有两条记录时，exact 和带 `^…$` 的正则哪条都对不上，prefix 只看得到第一条
                // Each TXT record is compared on its own, and one matching is enough; a record's
                // strings are first joined without spaces, as RFC 7208 §3.3 reads an SPF record
                // (text longer than 255 bytes can only be written as several strings). All
                // records used to be joined into one string: with two records present, exact and
                // a regex anchored with `^…$` matched neither, and prefix saw only the first
                use hickory_proto::rr::RData;
                msg.answers.iter().any(|record| {
                    let RData::TXT(txt) = &record.data else {
                        return false;
                    };
                    let joined = txt.txt_data.concat();
                    let text = String::from_utf8_lossy(&joined);
                    match mode {
                        TxtMatchMode::Exact => text == value.as_ref(),
                        TxtMatchMode::Prefix => text.starts_with(value.as_ref()),
                        TxtMatchMode::Regex => regex.as_ref().is_some_and(|re| re.is_match(&text)),
                    }
                })
            }
        }
    }
}

#[cfg(test)]
mod upstream_ip_tests {
    use std::net::IpAddr;

    use super::try_parse_upstream_ip;

    /// 作答上游的 IP 从它的名字里读：去掉传输名、端口、路径和参数；主机是域名时没有
    /// The answering upstream's IP is read from its name, less the transport, the port, a path
    /// and parameters; there is none when the host is a name
    #[test]
    fn the_ip_of_an_answering_upstream_is_read_from_its_name() {
        let ip = |text: &str| Some(text.parse::<IpAddr>().unwrap());
        for (upstream, expected) in [
            ("udp:192.0.2.1:53", ip("192.0.2.1")),
            ("tcp:[2001:db8::1]:53", ip("2001:db8::1")),
            ("doh:192.0.2.1/dns-query", ip("192.0.2.1")),
            ("doh:192.0.2.1:8443/dns-query", ip("192.0.2.1")),
            ("dot:192.0.2.1:853?sni=dns.example", ip("192.0.2.1")),
            ("doq:[2001:db8::1]:853?sni=dns.example", ip("2001:db8::1")),
            ("192.0.2.1:53", ip("192.0.2.1")),
            ("192.0.2.1", ip("192.0.2.1")),
            ("doh:dns.example/dns-query", None),
            ("dot:dns.example:853", None),
        ] {
            assert_eq!(try_parse_upstream_ip(upstream), expected, "{upstream}");
        }
    }
}

#[cfg(test)]
mod txt_regex_tests {
    use super::RuntimeResponseMatcher;

    fn built(pattern: &str) -> anyhow::Result<RuntimeResponseMatcher> {
        RuntimeResponseMatcher::from_config(crate::config::ResponseMatcher::ResponseTxtContent {
            mode: "regex".to_string(),
            value: pattern.to_string(),
        })
    }

    /// `response_txt_content` 的正则和域名正则一个上限（编译后 1 MB）。以前限在 1000 字节，`.`、`\d+`、
    /// `^v=spf1 .*` 这样的平常写法都编译不过，整份配置跟着加载失败。大得离谱的照旧拒绝
    /// A `response_txt_content` regex gets the limit domain regexes have (1 MB compiled). It
    /// was held to 1000 bytes, which `.`, `\d+` or `^v=spf1 .*` already exceed, and the whole
    /// configuration then failed to load. One out of all proportion is refused as before
    #[test]
    fn a_txt_regex_takes_ordinary_patterns() {
        for pattern in [
            ".",
            r"\d+",
            "^v=spf1 .*",
            "google-site-verification=.*",
            r"^\s*v=DKIM1",
            r"^127\.0\.0\.\d+$",
            "(?i)^(forbidden|blocked)",
            r"^[\w.-]+@[\w.-]+$",
        ] {
            assert!(
                built(pattern).is_ok(),
                "{pattern}: {:?}",
                built(pattern).err()
            );
        }
        assert!(built(r"(\w{100}){100}").is_err(), "too large to compile");
        assert!(built(&"a".repeat(1001)).is_err(), "too long a pattern");
    }

    /// TXT 内容的正则不跟着域名正则改成 ASCII：TXT 里本来就可以写任意文字，`\w`、`\d`、`\s`、`\b` 照旧按 Unicode
    /// 理解，`\w` 认 `é` 和 `中`，`\d` 认 `٣`，`\s` 认不换行空格，`\b` 把 `é` 当作词里的字符
    /// TXT content regexes do not turn ASCII with the domain regexes: TXT may hold any text, so
    /// `\w`, `\d`, `\s` and `\b` keep their Unicode meaning: `\w` takes `é` and `中`, `\d`
    /// takes `٣`, `\s` takes a no-break space, and `\b` takes `é` as inside a word
    #[test]
    fn a_txt_regex_keeps_unicode_classes() {
        use hickory_proto::op::{Message, MessageType, OpCode};
        use hickory_proto::rr::rdata::TXT;
        use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
        let answer = |text: &str| {
            let mut message = Message::new(0, MessageType::Response, OpCode::Query);
            message.add_answer(Record::from_rdata(
                Name::from_ascii("example.com.").unwrap(),
                300,
                RData::TXT(TXT::new(vec![text.to_owned()])),
            ));
            message
        };
        for (pattern, text) in [
            (r"^\w+$", "café"),
            (r"^\w+$", "中文"),
            (r"^v\d$", "v٣"),
            (r"^a\sb$", "a\u{a0}b"),
            (r"\bcafé\b", "un café noir"),
        ] {
            let matcher = built(pattern).unwrap();
            assert!(
                matcher.matches(
                    "udp:test",
                    "example.com",
                    RecordType::TXT,
                    DNSClass::IN,
                    &answer(text),
                    None,
                    None,
                ),
                "{pattern} against {text}"
            );
        }
    }

    /// 每条 TXT 记录分开比较，有一条命中就算命中；一条记录里的几个字符串先不加空格连起来（RFC 7208 §3.3）。以前
    /// 所有记录连成一串再比：SPF 记录旁边还有一条验证记录时，exact 和带 `^…$` 的正则哪条都对不上，prefix 只对得上
    /// 第一条；没有 TXT 记录的应答反倒算作内容为空，`exact ""` 和 `.*` 这样的正则都命中
    /// Each TXT record is compared on its own, and one matching is enough; a record's strings
    /// are first joined without spaces (RFC 7208 §3.3). All records used to be joined into one
    /// string: with a verification record next to an SPF record, exact and a regex anchored
    /// with `^…$` matched neither, and prefix matched the first alone; and an answer without
    /// a TXT record counted as empty content, which `exact ""` and a regex such as `.*` matched
    #[test]
    fn each_txt_record_is_matched_on_its_own() {
        use hickory_proto::op::{Message, MessageType, OpCode};
        use hickory_proto::rr::rdata::TXT;
        use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
        let answer = |records: &[&[&str]]| {
            let mut message = Message::new(0, MessageType::Response, OpCode::Query);
            for strings in records {
                message.add_answer(Record::from_rdata(
                    Name::from_ascii("example.com.").unwrap(),
                    300,
                    RData::TXT(TXT::new(strings.iter().map(|s| s.to_string()).collect())),
                ));
            }
            message
        };
        let matches = |mode: &str, value: &str, message: &Message| {
            RuntimeResponseMatcher::from_config(
                crate::config::ResponseMatcher::ResponseTxtContent {
                    mode: mode.to_string(),
                    value: value.to_string(),
                },
            )
            .unwrap()
            .matches(
                "udp:test",
                "example.com",
                RecordType::TXT,
                DNSClass::IN,
                message,
                None,
                None,
            )
        };
        let two_records = answer(&[
            &["v=spf1 include:_spf.example", " -all"],
            &["site-verification=abc"],
        ]);
        for (mode, value) in [
            ("exact", "v=spf1 include:_spf.example -all"),
            ("exact", "site-verification=abc"),
            ("prefix", "site-verification="),
            ("regex", r"^v=spf1 .* -all$"),
            ("regex", r"^site-verification=\w+$"),
        ] {
            assert!(matches(mode, value, &two_records), "{mode} {value}");
        }
        // 两条记录之间不连 / Two records are not joined
        assert!(!matches("regex", "-allsite", &two_records));
        for (mode, value) in [("exact", ""), ("regex", ".*")] {
            assert!(!matches(mode, value, &answer(&[])), "{mode} {value}");
        }
    }

    /// 写 TXT 正则的人碰到的是配置校验（面板的校验、热重载都走 `config::validate`）：`.*`、`\d+`、`\w+`、
    /// `[a-z]{1,10}` 这样的平常写法都收，正则本身 1000 字节整的也收。编译后的上限是 1 MB：`\w{50}` 在 regex 库
    /// 默认的上限下编得出，这里拒绝（上面的 `(\w{100}){100}` 默认上限下也编不出，看不出用的是哪个上限）；超过
    /// 1000 字节的照旧拒绝。两种拒绝的原因原样说给用户
    /// Someone writing a TXT regex meets config validation (the panel's check and a reload both go
    /// through `config::validate`): ordinary patterns such as `.*`, `\d+`, `\w+` or `[a-z]{1,10}` are
    /// taken, and so is a pattern of exactly 1000 bytes. The compiled limit is 1 MB: `\w{50}`, which
    /// compiles under the regex library's default limits, is refused here (`(\w{100}){100}` above is
    /// refused under the defaults too, so it cannot tell which limit is in use); a pattern over 1000
    /// bytes is refused as before. Both refusals give the user their cause as written
    #[test]
    fn config_validation_takes_ordinary_txt_regexes_within_the_limits() {
        let validated = |pattern: &str| {
            let config = serde_json::json!({
                "settings": { "default_upstream": "192.0.2.1:53" },
                "pipelines": [{ "id": "main", "rules": [{
                    "name": "r",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "forward", "upstream": "192.0.2.1:53" }],
                    "response_matchers": [
                        { "type": "response_txt_content", "mode": "regex", "value": pattern }
                    ],
                    "response_actions_on_match": [{ "type": "allow" }]
                }] }]
            });
            crate::config::validate(&config.to_string()).map_err(|e| format!("{e:#}"))
        };
        for pattern in [
            ".*",
            r"\d+",
            r"\w+",
            "[a-z]{1,10}",
            "[ -~]*",
            "google-site-verification=.*",
            r"\w{20}",
            &"a".repeat(1000),
        ] {
            assert!(
                validated(pattern).is_ok(),
                "{pattern}: {:?}",
                validated(pattern).err()
            );
        }

        assert!(regex::Regex::new(r"\w{50}").is_ok());
        let too_large = validated(r"\w{50}").expect_err("over 1 MB compiled");
        assert!(
            too_large.contains("invalid regex: Compiled regex exceeds size limit of 1000000 bytes"),
            "{too_large}"
        );

        let too_long = validated(&"a".repeat(1001)).expect_err("over 1000 bytes");
        assert!(
            too_long.contains("regex pattern too long: 1001 bytes (max 1000)"),
            "{too_long}"
        );
    }
}
