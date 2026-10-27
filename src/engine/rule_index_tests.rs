//! 编译好的规则索引（`RuleIndex`）不会漏掉任何可能命中的规则：随机生成各种条件、各种运算符组合的
//! 规则和各式请求，凡是匹配器求值为命中的规则，都在索引给出的候选里。
//! The compiled rule index (`RuleIndex`) misses no rule that can match: for random rules
//! mixing every condition and operator and for varied requests, every rule whose matchers
//! match is among the candidates the index gives.

use std::net::IpAddr;
use std::str::FromStr;

use hickory_proto::rr::{DNSClass, RecordType};
use serde_json::{Value, json};

use crate::engine::matcher_adapter::{MatcherContext, matcher_matches};
use crate::engine::test_support::engine_from;
use crate::matcher::eval_match_chain;

const LABELS: [&str; 9] = ["a", "b", "ex", "cn", "com", "google", "ads", "x", "a\\046b"];
const OPERATORS: [&str; 4] = ["and", "or", "and_not", "or_not"];
const CLIENTS: [&str; 6] = [
    "10.1.2.3",
    "192.0.2.7",
    "203.0.113.9",
    "127.0.0.1",
    "2001:db8::1",
    "fe80::1",
];
const QTYPES: [&str; 4] = ["A", "AAAA", "TXT", "MX"];

/// 可重复的伪随机数 / Repeatable pseudo-random numbers
struct Rng(u64);

impl Rng {
    fn below(&mut self, bound: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 % bound as u64) as usize
    }

    fn pick<'a>(&mut self, from: &[&'a str]) -> &'a str {
        from[self.below(from.len())]
    }

    fn flag(&mut self) -> bool {
        self.below(2) == 0
    }

    /// 一到三段标签组成的名字，全小写，和请求名的写法一样 / A name of one to three labels,
    /// lowercase as request names are written
    fn name(&mut self) -> String {
        let labels = 1 + self.below(3);
        (0..labels)
            .map(|_| self.pick(&LABELS))
            .collect::<Vec<_>>()
            .join(".")
    }

    /// 写在配置里的域名值：可能带开头的点、结尾的点、大写，也可能是空的或只有一个点
    /// A domain value as a configuration writes it: maybe with a leading dot, a trailing
    /// dot or capitals, or empty, or a lone dot
    fn domain_value(&mut self) -> String {
        let name = self.name();
        match self.below(8) {
            0 => format!(".{name}"),
            1 => format!("{name}."),
            2 => name.to_ascii_uppercase(),
            3 => String::new(),
            4 => ".".to_string(),
            _ => name,
        }
    }

    fn matcher(&mut self) -> Value {
        match self.below(12) {
            0 => json!({ "type": "any" }),
            1 | 2 => json!({ "type": "domain_suffix", "value": self.domain_value() }),
            3 => json!({ "type": "domain_exact", "value": self.domain_value() }),
            4 => {
                json!({ "type": "domain_regex", "value": self.pick(&["^a\\.", "com$", "(?i)EX", "^$"]) })
            }
            5 => {
                json!({ "type": "client_ip", "cidr": self.pick(&["10.0.0.0/8", "192.0.2.0/24", "2001:db8::/32", "0.0.0.0/0"]) })
            }
            6 => json!({ "type": "geoip_private", "expect": self.flag() }),
            7 => json!({ "type": "edns_present", "expect": self.flag() }),
            8 => json!({ "type": "qclass", "value": self.pick(&["IN", "CH"]) }),
            9 => json!({ "type": "qtype", "value": self.pick(&QTYPES) }),
            10 => json!({ "type": "geo_site", "value": self.pick(&["g", "missing"]) }),
            _ => json!({ "type": "geo_site_not", "value": self.pick(&["g", "missing"]) }),
        }
    }

    fn rule(&mut self, index: usize) -> Value {
        let matchers: Vec<Value> = (0..1 + self.below(3))
            .map(|_| {
                let mut matcher = self.matcher();
                matcher["operator"] = json!(self.pick(&OPERATORS));
                matcher
            })
            .collect();
        json!({ "name": format!("r{index}"), "matchers": matchers, "actions": [{ "type": "allow" }] })
    }
}

#[tokio::test]
async fn the_compiled_index_misses_no_rule_that_matches() {
    let dir = tempfile::tempdir().unwrap();
    let geosite = dir.path().join("geosite.json");
    std::fs::write(
        &geosite,
        r#"{ "entries": [{ "tag": "g", "domains": ["domain:ex.com", "full:a.cn", "keyword:google", "regexp:^b\\."] }] }"#,
    )
    .unwrap();

    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut matched = 0usize;
    for round in 0..300 {
        let rules: Vec<Value> = (0..1 + rng.below(8)).map(|index| rng.rule(index)).collect();
        let engine = engine_from(json!({
            "settings": {
                "default_upstream": "127.0.0.1:9",
                "geosite_data_paths": [geosite.to_string_lossy()]
            },
            "pipelines": [{ "id": "main", "rules": rules }]
        }));
        let state = engine.state.load();
        let pipeline = &state.pipeline.pipelines[0];
        let index = &state.compiled_pipelines[0].index;
        for _ in 0..40 {
            let qname = if rng.below(20) == 0 {
                String::new()
            } else {
                rng.name()
            };
            let qtype = RecordType::from_str(rng.pick(&QTYPES)).unwrap();
            let ctx = MatcherContext {
                qname: &qname,
                qclass: if rng.below(10) == 0 {
                    DNSClass::CH
                } else {
                    DNSClass::IN
                },
                client_ip: IpAddr::from_str(rng.pick(&CLIENTS)).unwrap(),
                edns_present: rng.flag(),
                qtype,
                geoip_manager: Some(&engine.geoip_manager),
                geosite_manager: Some(&engine.geosite_manager),
            };
            let candidates = index.get_candidates(&qname, qtype);
            for (position, rule) in pipeline.rules.iter().enumerate() {
                if eval_match_chain(
                    &rule.matchers,
                    |m| m.operator,
                    |m| matcher_matches(&m.matcher, &ctx),
                ) {
                    matched += 1;
                    assert!(
                        candidates.contains(&position),
                        "round {round}: {qname:?} {qtype} matches rule {position} {:?} but the index gives {candidates:?}",
                        rules[position]
                    );
                }
            }
        }
    }
    // 规则真有命中，这个检查才有意义 / The check means something only if rules do match
    assert!(matched > 1000, "{matched}");
}
