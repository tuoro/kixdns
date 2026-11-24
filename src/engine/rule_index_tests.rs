//! 编译好的规则索引（`RuleIndex`）不会漏掉任何可能命中的规则：随机生成各种条件、各种运算符组合的
//! 规则和各式请求，凡是匹配器求值为命中的规则，都在索引给出的候选里。
//! The compiled rule index (`RuleIndex`) misses no rule that can match: for random rules
//! mixing every condition and operator and for varied requests, every rule whose matchers
//! match is among the candidates the index gives.

use std::net::IpAddr;
use std::str::FromStr;

use hickory_proto::rr::{DNSClass, RecordType};
use serde_json::{Value, json};

use crate::engine::test_support::engine_from;
use crate::matcher::{RequestFacts, RuntimePipelineConfig, eval_match_chain};

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

    // 引擎只建一个，为了读进 GeoSite 名单；每一轮的规则只编译出来，不建引擎。以前每轮建一个，每个引擎都开一池上游
    // socket，三百轮把同时在跑的测试要用的本机端口都用光了
    // One engine only, to read the GeoSite list in; each round's rules are compiled with no
    // engine of their own. One used to be built per round, each opening a pool of upstream
    // sockets, and three hundred rounds used up the local ports the tests running alongside need
    let settings = json!({
        "default_upstream": "127.0.0.1:9",
        "geosite_data_paths": [geosite.to_string_lossy()]
    });
    let engine = engine_from(json!({
        "settings": settings,
        "pipelines": [{ "id": "main", "rules": [{
            "name": "g", "matchers": [{ "type": "geo_site", "value": "g" }], "actions": [{ "type": "allow" }]
        }] }]
    }));
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut matched = 0usize;
    for round in 0..300 {
        let rules: Vec<Value> = (0..1 + rng.below(8)).map(|index| rng.rule(index)).collect();
        let config = serde_json::from_value(json!({
            "settings": settings,
            "pipelines": [{ "id": "main", "rules": rules }]
        }))
        .expect("parse config");
        let runtime = RuntimePipelineConfig::from_config(config).expect("build runtime config");
        let pipeline = &runtime.pipelines[0];
        let index = &pipeline.index;
        for _ in 0..40 {
            let qname = if rng.below(20) == 0 {
                String::new()
            } else {
                rng.name()
            };
            let qtype = RecordType::from_str(rng.pick(&QTYPES)).unwrap();
            let facts = RequestFacts {
                qname: &qname,
                qtype,
                qclass: if rng.below(10) == 0 {
                    DNSClass::CH
                } else {
                    DNSClass::IN
                },
                client_ip: IpAddr::from_str(rng.pick(&CLIENTS)).unwrap(),
                edns_present: rng.flag(),
            };
            let geo = engine.geo();
            let candidates = index.get_candidates(&qname, qtype);
            for (position, rule) in pipeline.rules.iter().enumerate() {
                if eval_match_chain(
                    &rule.matchers,
                    |m| m.operator,
                    |m| m.matcher.matches(&facts, geo),
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

/// 「且」连起来的规则记在最挑的那个条件下：先看精确的名字，再看后缀，最后看类型，和条件写的先后无关。以前记在第一个能记的
/// 条件下，「qtype A 且后缀 ads.example」的规则每个 A 查询都是候选
/// A rule joined by "and" is filed under its most selective condition, an exact name first, then
/// a suffix, then a type, whatever order the conditions are written in. It used to be filed under
/// the first condition that could be, and a rule "qtype A and suffix ads.example" was a candidate
/// for every A query
#[test]
fn a_rule_is_filed_under_its_most_selective_condition() {
    let rule = |name: &str, matchers: Value| json!({ "name": name, "matchers": matchers, "actions": [{ "type": "deny" }] });
    let config = serde_json::from_value(json!({
        "settings": { "default_upstream": "127.0.0.1:9" },
        "pipelines": [{ "id": "main", "rules": [
            rule("suffix", json!([
                { "type": "qtype", "value": "A" },
                { "type": "domain_suffix", "value": "ads.example" }
            ])),
            rule("exact", json!([
                { "type": "qtype", "value": "A" },
                { "type": "domain_suffix", "value": "example" },
                { "type": "domain_exact", "value": "x.example" }
            ]))
        ]}]
    }))
    .expect("parse config");
    let runtime = RuntimePipelineConfig::from_config(config).expect("build runtime config");
    let index = &runtime.pipelines[0].index;
    let candidates = |name: &str| index.get_candidates(name, RecordType::A).to_vec();
    assert_eq!(candidates("other.test"), Vec::<usize>::new());
    assert_eq!(candidates("y.example"), Vec::<usize>::new());
    assert_eq!(candidates("a.ads.example"), [0]);
    assert_eq!(candidates("x.example"), [1]);
}
