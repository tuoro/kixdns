//! 内核说的每种话都有测试说得出来：一批坏配置（被拒的原因）、几份收下却有告警的配置和 Geo 数据的每种问题，合起来正好是
//! 代号清单里的全部代号，清单和实际不脱节；每条都带着清单里的代号和参数，和原话一条对一条。文档的代号表和清单一致
//! Every kind of saying the kernel has is said by some test: a batch of broken configurations
//! (the reasons they are refused), a few accepted with warnings, and each kind of thing wrong
//! with the Geo data come together to exactly the codes of the list, so the list keeps up with
//! what is said; each one carries a code and the arguments of the list, one for one with the
//! words. The tables of codes in the docs agree with the list

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use super::{CODES, Notice};

/// 一份配置校验出来的话：被拒时是拒掉的原因，收下时是告警；原话和带代号的一条对一条
/// What validating a configuration says: the reasons when it is refused, the warnings when it
/// is accepted; the words and the coded ones one for one
fn said_by(config: &Value) -> Vec<Notice> {
    match crate::config::validate(&config.to_string()) {
        Ok(report) => {
            assert_eq!(report.warnings, super::texts(&report.coded_warnings));
            report.coded_warnings
        }
        Err(error) => {
            let coded = crate::config::Problems::coded(&error);
            assert!(!coded.is_empty(), "refused for no reason listed: {error:#}");
            assert_eq!(crate::config::Problems::of(&error), super::texts(coded));
            coded.to_vec()
        }
    }
}

/// JSON 里的一种话（一条，或者套在参数里的原因）合不合清单：代号在清单里，参数正是清单给这个代号列的那几个，套着的原因
/// 也这样查、原话就在外面那句里。记下见过的代号
/// Whether a saying in JSON (a notice, or a reason held in arguments) keeps to the list: its
/// code is in it, its arguments are just those the list gives the code, and a reason held in
/// them keeps to it too, its words found in the words around it. Notes the codes seen
fn keeps_to_the_list(said: &Value, seen: &mut BTreeSet<String>) {
    let list: BTreeMap<&str, &[&str]> = CODES.iter().copied().collect();
    let code = said["code"]
        .as_str()
        .unwrap_or_else(|| panic!("no code: {said}"));
    let names = list
        .get(code)
        .unwrap_or_else(|| panic!("{code} is not in CODES: {said}"));
    let args = said["args"]
        .as_object()
        .unwrap_or_else(|| panic!("no args: {said}"));
    assert_eq!(
        args.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        names.iter().copied().collect::<BTreeSet<_>>(),
        "{said}"
    );
    seen.insert(code.to_owned());
    for reason in args.values().filter(|arg| arg.is_object()) {
        let text = said["text"].as_str().unwrap();
        assert!(
            text.contains(reason["text"].as_str().unwrap()),
            "{text} does not hold {reason}"
        );
        keeps_to_the_list(reason, seen);
    }
}

/// 写成 JSON 的一条：位置、代号、参数和原话，原话开头写着位置 / A notice as JSON: the place, the
/// code, the arguments and the words, the words starting with the place
fn written(notice: &Notice) -> Value {
    let json = notice.json();
    let text = notice.to_string();
    assert_eq!(json["text"], text);
    assert_eq!(json["place"], json!(notice.place()));
    if let Some(place) = notice.place() {
        assert!(text.starts_with(&format!("{place}: ")), "{text}");
    }
    json
}

/// 一份把能写错的都写错了的配置：上游、bootstrap、设置、监听地址、pipeline_select、重复的 id、规则的动作和匹配器
/// A configuration with everything that can be written wrong written wrong: upstreams,
/// bootstrap, settings, listener addresses, pipeline_select, a repeated id, the actions and
/// matchers of rules
fn everything_wrong() -> Value {
    let any = json!([{ "type": "any" }]);
    let unusable = [
        "http://1.1.1.1",
        "udp://localhost:53",
        "1.1.1.1:0",
        "tcp://example",
        "tcp://example:x",
        "tcp://bad_host:53",
        "doh://http://dns.example",
        "doh://[::1",
        "dot://1.1.1.1:853?sni=%20",
        "dot://tcp://1.1.1.1",
        "dot://[::1",
        "dot://",
        "dot://1.1.1.1:853/path",
        "doq://dns.example?0rtt=ture",
        "dot://1.1.1.1?sin=x",
        "doq://223.5.5.5:853",
    ]
    .join(", ");
    json!({
        "settings": {
            "default_upstream": "",
            "bootstrap": "localhost:53",
            "doh_path": "dns-query",
            "tcp_pool_size": 2048,
            "bind_udp": "localhost:53",
            "bind_doh": "127.0.0.1:8443",
            "cache_capacity": 0,
            "cache_max_ttl": 0,
            "cache_refresh_threshold_percent": 100,
            "upstream_timeout_ms": 0,
            "dashmap_shards": 3,
            "doq_connection_idle_timeout_seconds": 10_000_000_000_000_000u64,
            "upstrem": "1.1.1.1:53"
        },
        "pipeline_select": [
            {
                "pipeline": "nowhere",
                "matchers": [{ "type": "domain_suffix", "value": "a.test", "operator": "and_not" }]
            },
            { "pipeline": "main", "matchers": [{ "type": "qtype", "value": "BOGUS" }] }
        ],
        "pipelines": [
            { "id": "main", "rules": [
                {
                    "name": "matchers",
                    "matchers": [
                        { "type": "domain_suffix", "value": "." },
                        { "type": "domain_exact", "value": "" },
                        { "type": "listener_label", "value": "udp" },
                        { "type": "client_ip", "cidr": "nope" },
                        { "type": "client_mac", "mac": "nope" },
                        { "type": "domain_regex", "value": "(" },
                        { "type": "domain_regex", "value": "a".repeat(16 * 1024 + 1) },
                        { "type": "qclass", "value": "XX" }
                    ],
                    "response_matchers": [
                        { "type": "response_txt_content", "mode": "prefix", "value": "" },
                        { "type": "response_rcode", "value": "NOPE" },
                        { "type": "response_txt_content", "mode": "bogus", "value": "x" },
                        { "type": "response_txt_content", "mode": "regex", "value": "(" }
                    ],
                    "actions": [{ "type": "forward", "upstream": "" }]
                },
                {
                    "name": "ecs",
                    "matchers": any.clone(),
                    "actions": [
                        { "type": "forward", "upstream": "1.1.1.1:53", "ecs": { "mode": "static", "ip": "nope" } },
                        { "type": "forward", "upstream": "8.8.8.8:53", "ecs": { "mode": "static", "ip": "192.0.2.1" } }
                    ]
                },
                {
                    "name": "upstreams",
                    "matchers": any.clone(),
                    "actions": [{ "type": "forward", "upstream": unusable }]
                },
                {
                    "name": "answers",
                    "matchers": any,
                    "actions": [
                        { "type": "static_response", "rcode": "WHATEVER" },
                        { "type": "static_ip_response", "ip": "nope" },
                        { "type": "static_cname_response", "target": "" },
                        { "type": "static_txt_response", "text": [] },
                        { "type": "static_txt_response", "text": ["a".repeat(256)] },
                        { "type": "static_txt_response", "text": vec!["a".repeat(255); 256] },
                        { "type": "log", "level": "WARN" },
                        { "type": "jump_to_pipeline", "pipeline": "gone" }
                    ]
                }
            ] },
            { "id": "main", "rules": [] }
        ]
    })
}

/// 几份配置，合起来说出每种配置的问题和告警：一份什么都写错了的，一份默认上游经 DoQ 问不了、整体超时短于上游超时的（都被
/// 拒），两份收下却有告警的
/// Configurations saying between them every kind of problem and warning of a configuration:
/// one with everything written wrong, one whose default upstream cannot be asked over DoQ and
/// whose overall timeout is under the upstream one (both refused), and two accepted with
/// warnings
fn configurations() -> Vec<Value> {
    let rule = |name: &str, matchers: Value, actions: Value| json!({ "name": name, "matchers": matchers, "actions": actions });
    let any = json!([{ "type": "any" }]);
    let allow = json!([{ "type": "allow" }]);
    let jump = |to: &str| json!([{ "type": "jump_to_pipeline", "pipeline": to }]);
    vec![
        everything_wrong(),
        json!({
            "settings": {
                "default_upstream": "1.1.1.1:53",
                "upstream_timeout_ms": 2000,
                "request_timeout_ms": 1000
            },
            "pipelines": [{ "id": "main", "rules": [
                rule("doq", any.clone(), json!([{ "type": "forward", "transport": "doq" }]))
            ] }]
        }),
        json!({
            "settings": {
                "default_upstream": "1.1.1.1:53",
                "prefetch": true,
                "cache_capacity": 2_000_000,
                "upstream_timeout_ms": 2000,
                "request_timeout_ms": 3000
            },
            "background_refresh_rule": { "name": "old" },
            "pipelines": [
                { "id": "a", "rules": [
                    rule("never", json!([
                        { "type": "geo_site", "value": "" },
                        { "type": "geoip_country", "country_codes": [] },
                        { "type": "domain_regex", "value": "^Ads\\.test$" }
                    ]), allow.clone()),
                    rule("geo", json!([
                        { "type": "geo_site", "value": "cn" },
                        { "type": "geoip_country", "country_codes": ["CN"] }
                    ]), json!([{ "type": "forward", "upstream": "tcp://dns.example:53" }])),
                    rule("jump", any.clone(), jump("b"))
                ] },
                { "id": "b", "rules": [rule("back", any.clone(), jump("a"))] }
            ]
        }),
        json!({
            "settings": { "default_upstream": "1.1.1.1:53", "geoip_db_path": "/data/country.mmdb" },
            "pipelines": [{ "id": "main", "rules": [
                rule("tag", json!([{ "type": "geoip_country", "country_codes": ["cloudflare"] }]), allow)
            ] }]
        }),
    ]
}

/// 清单里的代号各不相同，每个都是 snake_case / The codes of the list are all different, each in snake_case
#[test]
fn the_codes_are_distinct_and_in_snake_case() {
    let mut codes = BTreeSet::new();
    for (code, args) in CODES {
        assert!(codes.insert(*code), "{code} twice");
        for name in std::iter::once(code).chain(args.iter()) {
            assert!(
                !name.is_empty()
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                "{name}"
            );
        }
    }
}

/// 坏配置、有告警的配置和 Geo 数据的问题说出来的话，正好用到清单里的每一个代号：一个都不少（清单里没有哪个代号没人说），
/// 一个都不多（说出来的都在清单里、参数和清单一样）；每条的原话和带代号的一条对一条，位置写在原话开头，套着的原因也有代号
/// What the broken configurations, the ones with warnings and the trouble with the Geo data say
/// uses every code of the list, none missing (no code of the list goes unsaid) and none beyond it
/// (all said is in the list, with the arguments the list gives); each one's words and its coded
/// form go one for one, the place starting the words, and a reason held in one has a code too
#[test]
fn every_code_is_said_and_each_saying_keeps_to_the_list() {
    let dir = tempfile::tempdir().unwrap();
    let mut said: Vec<Notice> = configurations().iter().flat_map(said_by).collect();
    let data = crate::engine::every_data_warning(dir.path());
    assert!(
        data.iter().all(|notice| notice.place().is_none()),
        "{data:#?}"
    );
    said.extend(data);
    let mut seen = BTreeSet::new();
    for notice in &said {
        keeps_to_the_list(&written(notice), &mut seen);
    }
    let listed: BTreeSet<String> = CODES.iter().map(|(code, _)| code.to_string()).collect();
    assert_eq!(
        listed.difference(&seen).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "codes no test says"
    );
    assert_eq!(seen, listed);
}

/// 写成 JSON 的样子：没有位置时 `place` 为 null，参数按种类写成文字、数、列表、文件的种类或者套着的原因
/// As written in JSON: `place` null without a place, the arguments written by kind as text, a
/// number, a list, a kind of file or a reason held within
#[test]
fn notices_are_written_with_their_place_code_arguments_and_words() {
    use super::{GeoFile, Said};
    let reason = Said::DoqIpNeedsSni;
    let notice = Notice::at(
        "settings.default_upstream",
        Said::UpstreamUnusable {
            upstream: "doq://223.5.5.5:853".to_owned(),
            reason: Box::new(reason),
        },
    );
    let words = "settings.default_upstream: upstream \"doq://223.5.5.5:853\" is not usable: doq upstream with IP address requires explicit sni (e.g. doq://223.5.5.5:853?sni=alidns.com)";
    assert_eq!(
        notice.json(),
        json!({
            "place": "settings.default_upstream",
            "code": "upstream_unusable",
            "args": {
                "upstream": "doq://223.5.5.5:853",
                "reason": {
                    "code": "doq_ip_needs_sni",
                    "args": {},
                    "text": "doq upstream with IP address requires explicit sni (e.g. doq://223.5.5.5:853?sni=alidns.com)"
                }
            },
            "text": words
        })
    );
    let data = Notice::from(Said::DataFileTagsGone {
        file: GeoFile::Mmdb,
        path: "/data/country.mmdb".to_owned(),
        tags: vec!["CN".to_owned(), "US".to_owned()],
    });
    assert_eq!(
        data.json(),
        json!({
            "place": null,
            "code": "data_file_tags_gone",
            "args": { "file": "mmdb", "path": "/data/country.mmdb", "tags": ["CN", "US"] },
            "text": "GeoIP database /data/country.mmdb now has none of the tags rules use; the data read from it before stays for CN, US until it changes again"
        })
    );
    let over = Notice::at(
        "settings.tcp_pool_size",
        Said::SettingOverLimit {
            value: 2048,
            most: 1024,
        },
    );
    assert_eq!(over.json()["args"], json!({ "value": 2048, "most": 1024 }));
}

/// 中英两份代号表（`docs/message-codes*.md` 里「代号」一节下的第一张表）逐行是清单里的代号和参数，顺序一样
/// The two tables of codes (the first table under the codes heading of `docs/message-codes*.md`)
/// are, row by row, the codes of the list with their arguments, in its order
#[test]
fn the_docs_list_every_code_with_its_arguments() {
    for (doc, heading) in [
        (include_str!("../docs/message-codes.md"), "## 代号"),
        (include_str!("../docs/message-codes.en.md"), "## Codes"),
    ] {
        let rows: Vec<(String, Vec<String>)> = doc
            .lines()
            .skip_while(|line| line.trim() != heading)
            .skip_while(|line| !line.starts_with('|'))
            .take_while(|line| line.starts_with('|'))
            .skip(2)
            .map(|line| {
                let cells: Vec<&str> = line.split('|').map(str::trim).collect();
                let code = cells[1].trim_matches('`').to_owned();
                let args = cells[2]
                    .split(',')
                    .map(|arg| arg.trim().trim_matches('`').to_owned())
                    .filter(|arg| !arg.is_empty() && arg != "—")
                    .collect();
                (code, args)
            })
            .collect();
        let listed: Vec<(String, Vec<String>)> = CODES
            .iter()
            .map(|(code, args)| {
                (
                    code.to_string(),
                    args.iter().map(|a| a.to_string()).collect(),
                )
            })
            .collect();
        assert_eq!(rows, listed, "{heading}");
    }
}
