//! Geo 数据文件换了以后，用到这份数据的 Pipeline 换一个缓存命名空间：按旧名单、旧网段得出的应答和规则决定
//! 不再拿出来用，和配置重载换掉规则时一样。没用到这份数据的 Pipeline 留着它们的缓存。
//! Once a Geo data file changes, the pipelines that use that data move to a new cache
//! namespace: answers and rule decisions reached with the old list or networks are no
//! longer handed out, as when a configuration reload changes the rules. Pipelines that do
//! not use that data keep their caches.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use serde_json::{Value, json};

use crate::engine::Engine;
use crate::engine::geo_reload_tests::{field, replace, wait_for};
use crate::engine::test_support::{answering_upstream, ask, ask_like_a_listener, first_a};
use crate::matcher::RuntimePipelineConfig;

/// 名单命中时的应答 / The answer when the list matches
const MATCHED: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 50);
/// 上游的应答 / The upstream's answer
const UPSTREAM: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
/// 规则静态给出的其余应答 / The static answer rules give everything else
const OTHER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 60);

/// GeoSite .dat 内容：一个 `ads` 条目，列着 `names` 这些后缀 / GeoSite .dat content: one `ads` entry
/// listing the suffixes `names`
fn ads(names: &[&str]) -> Vec<u8> {
    let domains: Vec<u8> = names
        .iter()
        // Domain { type: 2 (suffix), value }
        .flat_map(|name| field(2, &[vec![0x08, 2], field(2, name.as_bytes())].concat()))
        .collect();
    field(1, &[field(1, b"ads"), domains].concat())
}

fn runtime(config: Value) -> RuntimePipelineConfig {
    let config: crate::config::PipelineConfig =
        serde_json::from_value(config).expect("parse config");
    RuntimePipelineConfig::from_config(config).expect("build runtime config")
}

fn settings(extra: Value) -> Value {
    let mut settings = json!({ "default_upstream": "127.0.0.1:9", "min_ttl": 0 });
    settings
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    settings
}

/// `geo_site: ads` 的名字静态回 [`MATCHED`]，其余的照 `otherwise` 处理
/// Names in `geo_site: ads` get [`MATCHED`] statically, the rest goes by `otherwise`
fn geosite_config(path: &Path, otherwise: Value) -> RuntimePipelineConfig {
    runtime(json!({
        "settings": settings(json!({ "geosite_data_paths": [path.to_str().unwrap()] })),
        "pipelines": [{ "id": "main", "rules": [
            {
                "name": "listed",
                "matchers": [{ "type": "geo_site", "value": "ads" }],
                "actions": [{ "type": "static_ip_response", "ip": MATCHED.to_string() }]
            },
            { "name": "rest", "matchers": [{ "type": "any" }], "actions": [otherwise] }
        ]}]
    }))
}

fn query(name: &str) -> Vec<u8> {
    let mut query = Message::new(0x6e6e, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(
        Name::from_ascii(format!("{name}.")).unwrap(),
        RecordType::A,
    ));
    query.to_vec().unwrap()
}

fn peer() -> SocketAddr {
    "203.0.113.9:53000".parse().unwrap()
}

/// 经完整路径和监听器的快速路径各问一次 / Asks once through the full path and once through the listener's fast path
async fn both_paths(engine: &Engine, name: &str) -> [Option<Ipv4Addr>; 2] {
    let packet = query(name);
    [
        first_a(&ask(engine, &packet, peer()).await),
        first_a(&ask_like_a_listener(engine, &packet, peer()).await),
    ]
}

fn namespace(engine: &Engine, pipeline: &str) -> u64 {
    engine.state.load().cache_namespace(pipeline)
}

/// 等新数据读进来（`landed`）、`pipeline` 也换了命名空间。数据先换、命名空间后换，两样都成立时，新命名空间里只有
/// 按新数据得出的东西。只看命名空间不够：一次替换文件会有不止一个监视事件，同样的内容再读一遍也换一次命名空间
/// Waits for the new data to be read in (`landed`) and for `pipeline` to move to a new
/// namespace. The data goes first and the namespace after, so once both hold the new
/// namespace holds only what the new data gave. The namespace alone is not enough: one file
/// replacement brings more than one watch event, and reading the same content again moves
/// the namespace once more
async fn wait_for_new_namespace(
    engine: &Engine,
    pipeline: &str,
    old: u64,
    landed: impl Fn(&Engine) -> bool,
) {
    wait_for(
        "the new data must be read in and the namespace move",
        || landed(engine) && namespace(engine, pipeline) != old,
    )
    .await;
}

/// GeoSite 的 `ads` 里有没有 `name` / Whether GeoSite's `ads` has `name`
fn listed(name: &'static str, expected: bool) -> impl Fn(&Engine) -> bool {
    move |engine| engine.geosite_manager.read().matches("ads", name) == expected
}

/// GeoIP 的 TESTNET 里有没有 `address` / Whether GeoIP's TESTNET has `address`
fn in_testnet(address: &'static str) -> impl Fn(&Engine) -> bool {
    move |engine| {
        engine
            .geoip_manager
            .read()
            .matches_any_tag(address.parse().unwrap(), &[std::sync::Arc::from("TESTNET")])
    }
}

/// 名单更新后新列进去的名字：缓存里上游给它的应答不再拿出来，快速路径和完整路径都按新名单作答，不再问上游。
/// 以前缓存里的应答一直用到 TTL 到期
/// A name newly on the list after an update: the upstream's answer to it in the cache is no
/// longer handed out, and the fast path and the full path both answer by the new list
/// without asking the upstream. The cached answer used to be served until its TTL ran out
#[tokio::test]
async fn a_geosite_update_drops_cached_answers_of_names_it_newly_lists() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("geosite.dat");
    std::fs::write(&data, ads(&["ads.example"])).unwrap();
    let up = answering_upstream(UPSTREAM, 3600).await;
    let engine = Engine::new(
        geosite_config(&data, json!({ "type": "forward", "upstream": up.address })),
        "test".to_string(),
    )
    .expect("engine");
    assert_eq!(
        both_paths(&engine, "tracker.example").await,
        [Some(UPSTREAM); 2]
    );
    assert_eq!(up.queries(), 1);

    let before = namespace(&engine, "main");
    replace(&data, &ads(&["ads.example", "tracker.example"]));
    wait_for_new_namespace(&engine, "main", before, listed("tracker.example", true)).await;
    assert_eq!(
        both_paths(&engine, "tracker.example").await,
        [Some(MATCHED); 2]
    );
    assert_eq!(up.queries(), 1, "nothing more went upstream");
}

/// 规则缓存里的决定也一样：名单更新前规则给出的静态应答，更新后不再拿出来。以前规则缓存一直按旧名单作答
/// The same for decisions in the rule cache: the static answer rules gave before the update
/// is no longer handed out after it. The rule cache used to answer by the old list
#[tokio::test]
async fn a_geosite_update_drops_rule_decisions_reached_with_the_old_list() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("geosite.dat");
    std::fs::write(&data, ads(&["ads.example"])).unwrap();
    let engine = Engine::new(
        geosite_config(
            &data,
            json!({ "type": "static_ip_response", "ip": OTHER.to_string() }),
        ),
        "test".to_string(),
    )
    .expect("engine");
    assert_eq!(
        both_paths(&engine, "tracker.example").await,
        [Some(OTHER); 2]
    );

    let before = namespace(&engine, "main");
    replace(&data, &ads(&["ads.example", "tracker.example"]));
    wait_for_new_namespace(&engine, "main", before, listed("tracker.example", true)).await;
    assert_eq!(
        both_paths(&engine, "tracker.example").await,
        [Some(MATCHED); 2]
    );
    // 名单里去掉的名字同样马上按新名单处理 / A name taken off the list goes by the new list at once too
    assert_eq!(both_paths(&engine, "ads.example").await, [Some(MATCHED); 2]);
    let before = namespace(&engine, "main");
    replace(&data, &ads(&["tracker.example"]));
    wait_for_new_namespace(&engine, "main", before, listed("ads.example", false)).await;
    assert_eq!(both_paths(&engine, "ads.example").await, [Some(OTHER); 2]);
}

/// GeoIP 数据也一样：按回答里的地址判断的规则，在网段更新后不再拿缓存里按旧网段放过的应答
/// GeoIP data likewise: a rule judging by the address in the answer no longer takes the
/// answer the old networks let through from the cache once the networks are updated
#[tokio::test]
async fn a_geoip_update_drops_cached_answers_judged_by_the_old_networks() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("geoip.json");
    let networks =
        |net: &str| format!(r#"{{"entries":[{{"country_code":"TESTNET","ips":["{net}"]}}]}}"#);
    std::fs::write(&data, networks("198.51.100.0/24")).unwrap();
    let up = answering_upstream(UPSTREAM, 3600).await;
    let engine = Engine::new(
        runtime(json!({
            "settings": settings(json!({ "geoip_dat_path": data.to_str().unwrap() })),
            "pipelines": [{ "id": "main", "rules": [{
                "name": "checked",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": up.address }],
                "response_matchers": [
                    { "type": "response_answer_ip_geoip_country", "country_codes": ["TESTNET"] }
                ],
                "response_actions_on_match": [
                    { "type": "static_ip_response", "ip": MATCHED.to_string() }
                ]
            }]}]
        })),
        "test".to_string(),
    )
    .expect("engine");
    assert_eq!(
        both_paths(&engine, "cdn.example").await,
        [Some(UPSTREAM); 2]
    );

    let before = namespace(&engine, "main");
    replace(&data, networks("192.0.2.0/24").as_bytes());
    wait_for_new_namespace(&engine, "main", before, in_testnet("192.0.2.1")).await;
    assert_eq!(both_paths(&engine, "cdn.example").await, [Some(MATCHED); 2]);
    // 回答阶段给的静态应答在 min_ttl 为 0 时不缓存，所以两条路各问一次 / With min_ttl 0 the static answer of
    // the response phase is not cached, so each path asks once
    assert_eq!(
        up.queries(),
        3,
        "the answer was asked for again and judged anew"
    );
}

/// 只有用到这份数据的 Pipeline 换命名空间：自己的规则用到的，或者跳转过去的 Pipeline 用到的。GeoSite 更新不动只用
/// GeoIP 的和什么都不用的 Pipeline，GeoIP 更新反过来；只按客户端地址判断 GeoIP 国家的 Pipeline 也不动（见下一个测试）
/// Only the pipelines that use the data change namespace: through their own rules, or
/// through a pipeline they jump to. A GeoSite update leaves pipelines using only GeoIP or
/// nothing alone, and a GeoIP update the other way round; a pipeline judging only the
/// client address's GeoIP country is left alone too (see the next test)
#[tokio::test]
async fn only_pipelines_that_use_the_data_change_namespace() {
    let dir = tempfile::tempdir().unwrap();
    let site = dir.path().join("geosite.dat");
    let ip = dir.path().join("geoip.json");
    let networks =
        |net: &str| format!(r#"{{"entries":[{{"country_code":"TESTNET","ips":["{net}"]}}]}}"#);
    std::fs::write(&site, ads(&["ads.example"])).unwrap();
    std::fs::write(&ip, networks("198.51.100.0/24")).unwrap();
    let answer = json!([{ "type": "static_ip_response", "ip": OTHER.to_string() }]);
    let engine = Engine::new(
        runtime(json!({
            "settings": settings(json!({
                "geosite_data_paths": [site.to_str().unwrap()],
                "geoip_dat_path": ip.to_str().unwrap()
            })),
            "pipelines": [
                { "id": "site", "rules": [
                    { "name": "a", "matchers": [{ "type": "geo_site", "value": "ads" }], "actions": answer }
                ]},
                { "id": "jumps", "rules": [
                    { "name": "b", "matchers": [{ "type": "any" }],
                      "actions": [{ "type": "jump_to_pipeline", "pipeline": "site" }] }
                ]},
                { "id": "ip", "rules": [
                    { "name": "c", "matchers": [{ "type": "any" }],
                      "actions": [{ "type": "forward", "upstream": "127.0.0.1:9" }],
                      "response_matchers": [
                          { "type": "response_answer_ip_geoip_country", "country_codes": ["TESTNET"] }
                      ],
                      "response_actions_on_match": answer }
                ]},
                { "id": "plain", "rules": [
                    { "name": "d", "matchers": [{ "type": "any" }], "actions": answer }
                ]},
                { "id": "client", "rules": [
                    { "name": "e", "matchers": [{ "type": "geoip_country", "country_codes": ["TESTNET"] }],
                      "actions": answer }
                ]},
                { "id": "answer_site", "rules": [
                    { "name": "f", "matchers": [{ "type": "any" }],
                      "actions": [{ "type": "forward", "upstream": "127.0.0.1:9" }],
                      "response_matchers": [
                          { "type": "response_request_domain_geo_site_not", "value": "ads" }
                      ],
                      "response_actions_on_match": answer }
                ]}
            ]
        })),
        "test".to_string(),
    )
    .expect("engine");
    let names = ["site", "jumps", "answer_site", "ip", "plain", "client"];
    let all = || names.map(|pipeline| (pipeline, namespace(&engine, pipeline)));
    // 换了命名空间的 pipeline / The pipelines whose namespace changed
    let moved = |before: &[(&'static str, u64); 6], after: &[(&'static str, u64); 6]| {
        before
            .iter()
            .zip(after)
            .filter(|(old, new)| old.1 != new.1)
            .map(|(old, _)| old.0)
            .collect::<Vec<_>>()
    };

    let start = all();
    replace(&site, &ads(&["ads.example", "more.example"]));
    wait_for_new_namespace(&engine, "site", start[0].1, listed("more.example", true)).await;
    let after_site = all();
    assert_eq!(
        moved(&start, &after_site),
        ["site", "jumps", "answer_site"],
        "a GeoSite update"
    );

    replace(&ip, networks("192.0.2.0/24").as_bytes());
    wait_for_new_namespace(&engine, "ip", after_site[3].1, in_testnet("192.0.2.1")).await;
    assert_eq!(moved(&after_site, &all()), ["ip"], "a GeoIP update");
}

/// 面板按内容给 Geo 数据和拦截列表的文件起名，每次更新都换一个文件、重载一次配置。用到 GeoSite 的 pipeline 照样换命名空间、
/// 按新名单作答；不读 Geo 数据的 pipeline 留着上游给的应答，不必再问一遍。以前 `geosite_data_paths` 算进了每个 pipeline 的
/// 命名空间，名单一更新整份缓存就作废，留着过期续用的应答也一起没了
/// The panel names the files of Geo data and blocklists by their content, so every update
/// brings another file and a configuration reload. The pipelines that use GeoSite move to a
/// new namespace as before and answer by the new list; the pipelines reading no Geo data keep
/// the upstream's answers and need not ask again. `geosite_data_paths` used to go into every
/// pipeline's namespace, so every list update dropped the whole cache, the answers kept for
/// serving stale with it
#[tokio::test]
async fn a_geosite_file_renamed_by_a_reload_leaves_pipelines_reading_no_geo_data_alone() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("blocklist-1.dat");
    let second = dir.path().join("blocklist-2.dat");
    std::fs::write(&first, ads(&["ads.example"])).unwrap();
    std::fs::write(&second, ads(&["ads.example", "tracker.example"])).unwrap();
    let up = answering_upstream(UPSTREAM, 3600).await;
    let config = |site: &Path| {
        runtime(json!({
            "settings": settings(json!({ "geosite_data_paths": [site.to_str().unwrap()] })),
            "pipeline_select": [
                { "pipeline": "blocked", "matchers": [{ "type": "geo_site", "value": "ads" }] },
                { "pipeline": "main", "matchers": [] }
            ],
            "pipelines": [
                { "id": "blocked", "rules": [{ "name": "block", "matchers": [],
                    "actions": [{ "type": "static_ip_response", "ip": MATCHED.to_string() }] }] },
                { "id": "main", "rules": [
                    { "name": "split", "matchers": [{ "type": "geo_site", "value": "ads" }],
                      "actions": [{ "type": "static_ip_response", "ip": OTHER.to_string() }] },
                    { "name": "rest", "matchers": [],
                      "actions": [{ "type": "jump_to_pipeline", "pipeline": "upstream" }] }
                ] },
                { "id": "upstream", "rules": [{ "name": "forward", "matchers": [],
                    "actions": [{ "type": "forward", "upstream": up.address }] }] }
            ]
        }))
    };
    let engine = Engine::new(config(&first), "test".to_string()).expect("engine");
    for name in ["www.example", "tracker.example"] {
        assert_eq!(
            both_paths(&engine, name).await,
            [Some(UPSTREAM); 2],
            "{name}"
        );
    }
    assert_eq!(up.queries(), 2);

    let (main, upstream) = (namespace(&engine, "main"), namespace(&engine, "upstream"));
    engine.reload(config(&second));
    assert_ne!(namespace(&engine, "main"), main, "main reads GeoSite");
    assert_eq!(
        both_paths(&engine, "tracker.example").await,
        [Some(MATCHED); 2],
        "the new list applies"
    );
    assert_eq!(
        namespace(&engine, "upstream"),
        upstream,
        "upstream reads no Geo data"
    );
    assert_eq!(
        both_paths(&engine, "www.example").await,
        [Some(UPSTREAM); 2]
    );
    assert_eq!(up.queries(), 2, "the upstream's answer stayed in the cache");
}

/// GeoIP 也一样：换了文件，按回答地址判断 GeoIP 的 pipeline 换命名空间，不读 Geo 数据的留着缓存
/// GeoIP likewise: with another file, the pipeline judging answer addresses by GeoIP moves to
/// a new namespace, and one reading no Geo data keeps its cache
#[tokio::test]
async fn a_geoip_file_renamed_by_a_reload_leaves_pipelines_reading_no_geo_data_alone() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("geoip-1.json");
    let second = dir.path().join("geoip-2.json");
    let networks =
        |net: &str| format!(r#"{{"entries":[{{"country_code":"TESTNET","ips":["{net}"]}}]}}"#);
    std::fs::write(&first, networks("198.51.100.0/24")).unwrap();
    std::fs::write(&second, networks("192.0.2.0/24")).unwrap();
    let up = answering_upstream(UPSTREAM, 3600).await;
    let config = |ip: &Path| {
        runtime(json!({
            "settings": settings(json!({ "geoip_dat_path": ip.to_str().unwrap() })),
            "pipelines": [
                { "id": "main", "rules": [
                    { "name": "checked", "matchers": [{ "type": "domain_suffix", "value": "checked.example" }],
                      "actions": [{ "type": "jump_to_pipeline", "pipeline": "ip" }] },
                    { "name": "rest", "matchers": [{ "type": "any" }],
                      "actions": [{ "type": "jump_to_pipeline", "pipeline": "plain" }] }
                ] },
                { "id": "ip", "rules": [{ "name": "c", "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "forward", "upstream": up.address }],
                    "response_matchers": [
                        { "type": "response_answer_ip_geoip_country", "country_codes": ["TESTNET"] }
                    ],
                    "response_actions_on_match": [{ "type": "static_ip_response", "ip": MATCHED.to_string() }] }] },
                { "id": "plain", "rules": [{ "name": "d", "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "forward", "upstream": up.address }] }] }
            ]
        }))
    };
    let engine = Engine::new(config(&first), "test".to_string()).expect("engine");
    assert_eq!(
        both_paths(&engine, "www.example").await,
        [Some(UPSTREAM); 2]
    );
    assert_eq!(
        both_paths(&engine, "www.checked.example").await,
        [Some(UPSTREAM); 2]
    );
    assert_eq!(up.queries(), 2);

    let (ip, plain) = (namespace(&engine, "ip"), namespace(&engine, "plain"));
    engine.reload(config(&second));
    assert!(in_testnet("192.0.2.1")(&engine), "the new networks are in");
    assert_ne!(namespace(&engine, "ip"), ip, "ip judges answers by GeoIP");
    assert_eq!(
        namespace(&engine, "plain"),
        plain,
        "plain reads no Geo data"
    );
    assert_eq!(
        both_paths(&engine, "www.example").await,
        [Some(UPSTREAM); 2]
    );
    assert_eq!(up.queries(), 2, "the upstream's answer stayed in the cache");
}

/// 按客户端地址判断 GeoIP 国家的规则不靠换命名空间：缓存的键带着客户端那次判断的结果，网段一换，判断结果跟着变，
/// 查到的就是另一个条目，所以照样按新网段作答
/// Rules judging the client address's GeoIP country need no namespace change: cache keys
/// carry the result of that judgement for the client, so once the networks change the
/// result changes with them, the lookup finds another entry, and the answer goes by the new
/// networks all the same
#[tokio::test]
async fn rules_judging_the_client_country_follow_new_networks_without_a_namespace_change() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("geoip.json");
    let networks =
        |net: &str| format!(r#"{{"entries":[{{"country_code":"TESTNET","ips":["{net}"]}}]}}"#);
    std::fs::write(&data, networks("198.51.100.0/24")).unwrap();
    let engine = Engine::new(
        runtime(json!({
            "settings": settings(json!({ "geoip_dat_path": data.to_str().unwrap() })),
            "pipelines": [{ "id": "main", "rules": [
                {
                    "name": "client",
                    "matchers": [{ "type": "geoip_country", "country_codes": ["TESTNET"] }],
                    "actions": [{ "type": "static_ip_response", "ip": MATCHED.to_string() }]
                },
                {
                    "name": "rest",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "static_ip_response", "ip": OTHER.to_string() }]
                }
            ]}]
        })),
        "test".to_string(),
    )
    .expect("engine");
    assert_eq!(both_paths(&engine, "a.example").await, [Some(OTHER); 2]);
    let before = namespace(&engine, "main");

    // 客户端 203.0.113.9 进了 TESTNET / The client 203.0.113.9 is now in TESTNET
    replace(&data, networks("203.0.113.0/24").as_bytes());
    let tags = [std::sync::Arc::<str>::from("TESTNET")];
    wait_for("the watch must read the new networks", || {
        engine
            .geoip_manager
            .read()
            .matches_any_tag(peer().ip(), &tags)
    })
    .await;
    assert_eq!(both_paths(&engine, "a.example").await, [Some(MATCHED); 2]);
    assert_eq!(namespace(&engine, "main"), before);
}

/// 配置重载换进来的新规则沿用数据更新后的命名空间，不会退回去拿按旧数据缓存的应答；重载时读进来的数据（配置里写了、
/// 此前还不存在的文件）同样换命名空间。以前重载后命名空间只看配置
/// New rules a configuration reload swaps in keep the namespace a data update moved to, and
/// do not go back to answers cached with the old data; data a reload reads in (a file the
/// configuration names that did not exist before) moves the namespace too. The namespace
/// after a reload used to depend on the configuration alone
#[tokio::test]
async fn a_configuration_reload_keeps_up_with_the_geo_data() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("geosite.dat");
    let otherwise = json!({ "type": "static_ip_response", "ip": OTHER.to_string() });
    // 文件还不存在 / The file does not exist yet
    let engine =
        Engine::new(geosite_config(&data, otherwise.clone()), "test".to_string()).expect("engine");
    assert_eq!(
        both_paths(&engine, "tracker.example").await,
        [Some(OTHER); 2]
    );
    std::fs::write(&data, ads(&["tracker.example"])).unwrap();
    let before = namespace(&engine, "main");
    engine.reload(geosite_config(&data, otherwise.clone()));
    assert_ne!(
        namespace(&engine, "main"),
        before,
        "the reload read the data in"
    );
    assert_eq!(
        both_paths(&engine, "tracker.example").await,
        [Some(MATCHED); 2]
    );

    let before = namespace(&engine, "main");
    replace(&data, &ads(&["ads.example"]));
    wait_for_new_namespace(&engine, "main", before, listed("tracker.example", false)).await;
    let updated = namespace(&engine, "main");
    assert_eq!(
        both_paths(&engine, "tracker.example").await,
        [Some(OTHER); 2]
    );
    // 同样的配置再重载一次：数据没变，命名空间也不变，缓存照用 / The same configuration reloaded: the data is unchanged, so is the namespace, and the cache stays in use
    engine.reload(geosite_config(&data, otherwise));
    assert_eq!(namespace(&engine, "main"), updated);
    assert_eq!(
        both_paths(&engine, "tracker.example").await,
        [Some(OTHER); 2]
    );
}

/// GeoIP 也一样：配置里写了、此前还不存在的数据文件在重载时读进来，按回答地址判断的 Pipeline 换命名空间
/// GeoIP likewise: a data file the configuration names that did not exist before is read in
/// on a reload, and a pipeline judging answer addresses moves to a new namespace
#[tokio::test]
async fn a_reload_reading_geoip_data_in_moves_the_namespace() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("geoip.json");
    let config = || {
        runtime(json!({
            "settings": settings(json!({ "geoip_dat_path": data.to_str().unwrap() })),
            "pipelines": [{ "id": "main", "rules": [{
                "name": "checked",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": "127.0.0.1:9" }],
                "response_matchers": [
                    { "type": "response_answer_ip_geoip_country", "country_codes": ["TESTNET"] }
                ],
                "response_actions_on_match": [
                    { "type": "static_ip_response", "ip": MATCHED.to_string() }
                ]
            }]}]
        }))
    };
    let engine = Engine::new(config(), "test".to_string()).expect("engine");
    let before = namespace(&engine, "main");
    std::fs::write(
        &data,
        r#"{"entries":[{"country_code":"TESTNET","ips":["192.0.2.0/24"]}]}"#,
    )
    .unwrap();
    engine.reload(config());
    assert!(
        in_testnet("192.0.2.1")(&engine),
        "the reload read the data in"
    );
    assert_ne!(namespace(&engine, "main"), before);
}
