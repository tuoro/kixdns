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
use crate::engine::geo_reload_tests::{field, geosite_dat, replace, wait_for};
use crate::engine::test_support::{
    answering_upstream, answering_upstream_held, ask, ask_like_a_listener, first_a,
};
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
/// 按新数据得出的东西
/// Waits for the new data to be read in (`landed`) and for `pipeline` to move to a new
/// namespace. The data goes first and the namespace after, so once both hold the new
/// namespace holds only what the new data gave
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
    move |engine| engine.geo().geosite.matches("ads", name) == expected
}

/// GeoIP 的 TESTNET 里有没有 `address` / Whether GeoIP's TESTNET has `address`
fn in_testnet(address: &'static str) -> impl Fn(&Engine) -> bool {
    move |engine| {
        engine
            .geo()
            .geoip
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
    // 更新以后先问的那条路重新问上游、按新网段判断，回答阶段给的静态应答按它的 TTL 缓存，另一条路拿缓存里的
    // After the update the path asking first asks the upstream again and judges by the new
    // networks; the static answer of the response phase is cached for its TTL, and the other
    // path takes it from the cache
    assert_eq!(
        up.queries(),
        2,
        "the answer was asked for again and judged anew"
    );
}

/// 只有读到换了的那个标签的 Pipeline 换命名空间：自己的规则读的，或者回答检查跳过去的 Pipeline 读的（那里拿到的应答缓存
/// 在它的键下）。请求阶段跳过去的不算：应答缓存在目标的键下，跳转前的 Pipeline 只存跳转这个决定。GeoSite 的 ads 换了不动
/// 读别的 GeoSite 标签的、只用 GeoIP 的和什么都不用的 Pipeline，GeoIP 的标签换了也只动读它的；只按客户端地址判断 GeoIP
/// 国家的 Pipeline 也不动（见下一个测试）。直接给出数据看命名空间，不经文件监视：macOS 的 FSEvents 在开始监视后不久会补报
/// 此前新建文件的事件，等文件更新的那段时间里两份数据都会重读
/// Only the pipelines reading the very tag that changed move to a new namespace: through their
/// own rules, or through a pipeline their answer checks jump to (the answers got there are
/// cached under their key). A request-phase jump does not count: the answers are cached under
/// the target's key, and the pipeline jumped from keeps only the decision to jump. GeoSite's
/// ads changing leaves pipelines reading other GeoSite tags, only GeoIP or nothing alone, and a
/// GeoIP tag changing moves only the pipelines reading it; a pipeline judging only the client
/// address's GeoIP country is left alone too (see the next test). The data is given directly,
/// not through the file watch: macOS FSEvents reports the creation of files made just before
/// the watch began shortly after it begins, and both kinds of data are read again while a file
/// update is waited for
#[test]
fn only_pipelines_reading_the_changed_tag_change_namespace() {
    use crate::engine::types::EngineInner;
    use crate::matcher::GeoManagers;
    use crate::matcher::geoip::GeoIpManager;
    use crate::matcher::geosite::GeoSiteManager;
    use std::sync::Arc;
    let answer = json!([{ "type": "static_ip_response", "ip": OTHER.to_string() }]);
    let forward = json!([{ "type": "forward", "upstream": "127.0.0.1:9" }]);
    let answer_ip = |tag: &str| {
        json!([
            { "name": "c", "matchers": [{ "type": "any" }], "actions": forward,
              "response_matchers": [
                  { "type": "response_answer_ip_geoip_country", "country_codes": [tag] }
              ],
              "response_actions_on_match": answer }
        ])
    };
    let state = std::sync::Arc::new(EngineInner::new(runtime(json!({
        "settings": settings(json!({
            "geosite_data_paths": ["/data/geosite.dat"],
            "geoip_dat_path": "/data/geoip.json"
        })),
        "pipelines": [
            { "id": "site", "rules": [
                { "name": "a", "matchers": [{ "type": "geo_site", "value": "ads" }], "actions": answer }
            ]},
            { "id": "other_site", "rules": [
                { "name": "a", "matchers": [{ "type": "geo_site", "value": "cn" }], "actions": answer }
            ]},
            { "id": "jumps", "rules": [
                { "name": "b", "matchers": [{ "type": "any" }],
                  "actions": [{ "type": "jump_to_pipeline", "pipeline": "site" }] }
            ]},
            { "id": "answer_jumps", "rules": [
                { "name": "g", "matchers": [{ "type": "any" }], "actions": forward,
                  "response_matchers": [{ "type": "response_rcode", "value": "NOERROR" }],
                  "response_actions_on_match": [{ "type": "jump_to_pipeline", "pipeline": "site" }] }
            ]},
            { "id": "ip", "rules": answer_ip("TESTNET") },
            { "id": "other_ip", "rules": answer_ip("OTHERNET") },
            { "id": "plain", "rules": [
                { "name": "d", "matchers": [{ "type": "any" }], "actions": answer }
            ]},
            { "id": "client", "rules": [
                { "name": "e", "matchers": [{ "type": "geoip_country", "country_codes": ["TESTNET"] }],
                  "actions": answer }
            ]},
            { "id": "answer_site", "rules": [
                { "name": "f", "matchers": [{ "type": "any" }], "actions": forward,
                  "response_matchers": [
                      { "type": "response_request_domain_geo_site_not", "value": "ads" }
                  ],
                  "response_actions_on_match": answer }
            ]}
        ]
    }))));
    let names = [
        "site",
        "other_site",
        "jumps",
        "answer_jumps",
        "answer_site",
        "ip",
        "other_ip",
        "plain",
        "client",
    ];
    // 从没有数据换到 `geo` 这份数据，换了命名空间的 pipeline / The pipelines whose namespace changes
    // from no data to the data `geo`
    let moved = |geo: GeoManagers| {
        let after = state.at_geo(geo);
        names
            .into_iter()
            .filter(|&pipeline| state.cache_namespace(pipeline) != after.cache_namespace(pipeline))
            .collect::<Vec<_>>()
    };
    // 只有标签 `tag` 有数据的 GeoSite、GeoIP / GeoSite and GeoIP with data for tag `tag` alone
    let site = |tag: &str| {
        let mut site = GeoSiteManager::default();
        site.load_from_v2ray_string(&format!(
            r#"{{"entries":[{{"tag":"{tag}","domains":["domain:example"]}}]}}"#
        ))
        .unwrap();
        GeoManagers {
            geosite: Arc::new(site),
            ..GeoManagers::default()
        }
    };
    let dir = tempfile::tempdir().unwrap();
    let ip = |tag: &str| {
        let path = dir.path().join("geoip.json");
        std::fs::write(
            &path,
            format!(r#"{{"entries":[{{"country_code":"{tag}","ips":["192.0.2.0/24"]}}]}}"#),
        )
        .unwrap();
        let mut ip = GeoIpManager::default();
        ip.load_from_v2ray_file(&path).unwrap();
        GeoManagers {
            geoip: Arc::new(ip),
            ..GeoManagers::default()
        }
    };
    assert_eq!(
        moved(site("ads")),
        ["site", "answer_jumps", "answer_site"],
        "a GeoSite update of ads"
    );
    assert_eq!(moved(site("cn")), ["other_site"], "a GeoSite update of cn");
    assert_eq!(moved(ip("TESTNET")), ["ip"], "a GeoIP update of TESTNET");
}

/// 热重载只多用了一个标签（加了一个读 ads 的 pipeline）：读 cn 的 main 读的还是同一份数据，不换命名空间，上游给它的应答
/// 留在缓存里。数据文件只改了 ads 时 main 也不换；改了 cn，main 才换
/// A hot reload using one tag more (a pipeline reading ads added): main, reading cn, reads the
/// very same data, keeps its namespace, and the upstream's answer stays in its cache. With the
/// data file changing ads alone main stays put too; once cn changes, main moves
#[tokio::test]
async fn a_reload_using_one_tag_more_leaves_pipelines_reading_other_tags_alone() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("geosite.dat");
    let lists = |cn: &str, ads: &str| geosite_dat(&[("cn", cn), ("ads", ads)]);
    std::fs::write(&data, lists("cn.example", "ads.example")).unwrap();
    let up = answering_upstream(UPSTREAM, 3600).await;
    let config = |with_ads: bool| {
        let mut pipelines = vec![json!({ "id": "main", "rules": [
            { "name": "cn", "matchers": [{ "type": "geo_site", "value": "cn" }],
              "actions": [{ "type": "static_ip_response", "ip": MATCHED.to_string() }] },
            { "name": "rest", "matchers": [],
              "actions": [{ "type": "forward", "upstream": up.address }] }
        ] })];
        if with_ads {
            pipelines.push(json!({ "id": "blocked", "rules": [
                { "name": "ads", "matchers": [{ "type": "geo_site", "value": "ads" }],
                  "actions": [{ "type": "static_ip_response", "ip": OTHER.to_string() }] }
            ] }));
        }
        runtime(json!({
            "settings": settings(json!({ "geosite_data_paths": [data.to_str().unwrap()] })),
            "pipelines": pipelines
        }))
    };
    let engine = Engine::new(config(false), "test".to_string()).expect("engine");
    assert_eq!(
        both_paths(&engine, "www.example").await,
        [Some(UPSTREAM); 2]
    );
    assert_eq!(up.queries(), 1);

    let main = namespace(&engine, "main");
    engine.reload(config(true));
    assert!(
        listed("x.ads.example", true)(&engine),
        "the reload read ads in"
    );
    assert_eq!(namespace(&engine, "main"), main, "main reads cn alone");
    assert_eq!(
        both_paths(&engine, "www.example").await,
        [Some(UPSTREAM); 2]
    );
    assert_eq!(up.queries(), 1, "the upstream's answer stayed in the cache");

    // blocked 读 ads，它换了命名空间，说明新数据已经换进来、命名空间也算过了 / blocked reads ads,
    // so its namespace moving tells the new data is in and the namespaces worked out
    let blocked = namespace(&engine, "blocked");
    replace(&data, &lists("cn.example", "tracker.example"));
    wait_for_new_namespace(
        &engine,
        "blocked",
        blocked,
        listed("x.tracker.example", true),
    )
    .await;
    assert_eq!(namespace(&engine, "main"), main, "only ads changed");

    replace(&data, &lists("www.example", "tracker.example"));
    wait_for_new_namespace(&engine, "main", main, |engine| {
        engine.geo().geosite.matches("cn", "www.example")
    })
    .await;
    assert_eq!(both_paths(&engine, "www.example").await, [Some(MATCHED); 2]);
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

/// Geo 数据换成别的、又换回先前的样子（面板按内容给文件起名，更新以后又退回先前那一份）：换的时候还在路上的请求从头到尾
/// 按它开始时的那份数据判断，得出的应答缓存在那份数据的命名空间下。换回来就回到先前的命名空间，里面的应答正是按换回来的
/// 这份数据判断的，照样拿出来用，不必再问上游
/// Geo data changing to other data and back to what it was (the panel naming files by their
/// content, an update rolled back to the earlier file): a request still on its way at the
/// change judges by the data it started with from start to end, and the answer it reaches is
/// cached under that data's namespace. Changing back brings back the earlier namespace, whose
/// answers were judged by the very data back in place, so they are handed out as they are,
/// with no need to ask the upstream again
#[tokio::test]
async fn data_changing_back_brings_back_only_answers_judged_by_that_data() {
    let dir = tempfile::tempdir().unwrap();
    let (first, second) = (
        dir.path().join("geoip-1.json"),
        dir.path().join("geoip-2.json"),
    );
    let networks =
        |net: &str| format!(r#"{{"entries":[{{"country_code":"TESTNET","ips":["{net}"]}}]}}"#);
    std::fs::write(&first, networks("198.51.100.0/24")).unwrap();
    std::fs::write(&second, networks("192.0.2.0/24")).unwrap();
    let (up, held) = answering_upstream_held(UPSTREAM, 3600).await;
    let config = |ip: &Path| {
        runtime(json!({
            "settings": settings(json!({ "geoip_dat_path": ip.to_str().unwrap() })),
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
        }))
    };
    let engine = Engine::new(config(&first), "test".to_string()).expect("engine");
    let earlier = namespace(&engine, "main");

    // 查询到了上游以后换成第二份，上游再应答 / The second file goes in once the query has reached
    // the upstream, and the upstream answers after
    let packet = query("cdn.example");
    let (answer, ()) = tokio::join!(ask(&engine, &packet, peer()), async {
        wait_for("the query must reach the upstream", || up.queries() == 1).await;
        engine.reload(config(&second));
        held.release();
    });
    assert_eq!(first_a(&answer), Some(UPSTREAM), "judged by the first file");
    assert_ne!(
        namespace(&engine, "main"),
        earlier,
        "the second file moved it"
    );

    engine.reload(config(&first));
    assert_eq!(
        namespace(&engine, "main"),
        earlier,
        "the first file is back"
    );
    assert_eq!(
        both_paths(&engine, "cdn.example").await,
        [Some(UPSTREAM); 2]
    );
    assert_eq!(
        up.queries(),
        1,
        "the answer judged by the first file stayed in use"
    );
}

/// 按客户端地址判断 GeoIP 国家、回答检查 continue 以后才求值的规则：请求在路上时 TESTNET 换了网段，规则照旧按请求开始时
/// 的那份数据判断，和算它的键用的是同一份，缓存在「在 TESTNET」键下的应答就是给 TESTNET 的，新进 TESTNET 的客户端拿到的
/// 也是它；换数据以后来的请求按新网段判断。`watch` 时由文件监视换数据，不然由热重载换
/// A rule judging the client address's GeoIP country, evaluated only once an answer check
/// continues: with TESTNET moving to other networks while a request is on its way, the rule
/// still judges by the data the request started with, the very data its key was worked out
/// from, so the answer cached under the key "in TESTNET" is the one for TESTNET, and the
/// clients newly in TESTNET get that one too; requests after the change judge by the new
/// networks. With `watch` the file watch swaps the data, a hot reload otherwise
async fn a_request_on_its_way_judges_the_client_country_by_the_data_it_started_with(watch: bool) {
    let dir = tempfile::tempdir().unwrap();
    let (first, second) = (
        dir.path().join("geoip-1.json"),
        dir.path().join("geoip-2.json"),
    );
    let networks =
        |net: &str| format!(r#"{{"entries":[{{"country_code":"TESTNET","ips":["{net}"]}}]}}"#);
    std::fs::write(&first, networks("203.0.113.0/24")).unwrap();
    std::fs::write(&second, networks("198.51.100.0/24")).unwrap();
    let (up, held) = answering_upstream_held(UPSTREAM, 3600).await;
    let config = |ip: &Path| {
        runtime(json!({
            "settings": settings(json!({ "geoip_dat_path": ip.to_str().unwrap() })),
            "pipelines": [{ "id": "main", "rules": [
                {
                    "name": "checked",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "forward", "upstream": up.address }],
                    "response_matchers": [{ "type": "response_rcode", "value": "NOERROR" }],
                    "response_actions_on_match": [{ "type": "continue" }]
                },
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
        }))
    };
    let engine = Engine::new(config(&first), "test".to_string()).expect("engine");
    // 203.0.113.9 在第一份的 TESTNET 里，198.51.100.7 在第二份的里 / 203.0.113.9 is in the first
    // file's TESTNET, 198.51.100.7 in the second's
    let (leaving, joining): (SocketAddr, SocketAddr) = (
        "203.0.113.9:53000".parse().unwrap(),
        "198.51.100.7:53000".parse().unwrap(),
    );
    let packet = query("cdn.example");
    let (answer, ()) = tokio::join!(ask(&engine, &packet, leaving), async {
        wait_for("the query must reach the upstream", || up.queries() == 1).await;
        if watch {
            replace(&first, networks("198.51.100.0/24").as_bytes());
            wait_for("the watch must read the new networks", || {
                in_testnet("198.51.100.7")(&engine)
            })
            .await;
        } else {
            engine.reload(config(&second));
        }
        held.release();
    });
    assert_eq!(
        first_a(&answer),
        Some(MATCHED),
        "judged by the networks the request started with"
    );

    let joined = query("cdn.example");
    assert_eq!(
        [
            first_a(&ask(&engine, &joined, joining).await),
            first_a(&ask_like_a_listener(&engine, &joined, joining).await),
        ],
        [Some(MATCHED); 2],
        "a client newly in TESTNET"
    );
    assert_eq!(
        up.queries(),
        1,
        "the answer cached under the key in TESTNET was the one for TESTNET"
    );
    assert_eq!(
        first_a(&ask(&engine, &query("cdn.example"), leaving).await),
        Some(OTHER),
        "the client no longer in TESTNET"
    );
}

#[tokio::test]
async fn a_request_on_its_way_keeps_its_data_through_a_hot_reload() {
    a_request_on_its_way_judges_the_client_country_by_the_data_it_started_with(false).await;
}

#[tokio::test]
async fn a_request_on_its_way_keeps_its_data_through_a_watched_change() {
    a_request_on_its_way_judges_the_client_country_by_the_data_it_started_with(true).await;
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
        engine.geo().geoip.matches_any_tag(peer().ip(), &tags)
    })
    .await;
    assert_eq!(both_paths(&engine, "a.example").await, [Some(MATCHED); 2]);
    assert_eq!(namespace(&engine, "main"), before);
}

/// 配置重载换进来的新规则沿用数据更新后的命名空间，不会退回去拿按旧数据缓存的应答；重载时读进来的数据（配置里写了、
/// 此前连所在的目录都不存在、监视不了的文件）同样换命名空间。以前重载后命名空间只看配置
/// New rules a configuration reload swaps in keep the namespace a data update moved to, and
/// do not go back to answers cached with the old data; data a reload reads in (a file the
/// configuration names that did not exist before, its directory neither, so nothing could
/// watch it) moves the namespace too. The namespace after a reload used to depend on the
/// configuration alone
#[tokio::test]
async fn a_configuration_reload_keeps_up_with_the_geo_data() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("later").join("geosite.dat");
    let otherwise = json!({ "type": "static_ip_response", "ip": OTHER.to_string() });
    // 文件还不存在 / The file does not exist yet
    let engine =
        Engine::new(geosite_config(&data, otherwise.clone()), "test".to_string()).expect("engine");
    assert_eq!(
        both_paths(&engine, "tracker.example").await,
        [Some(OTHER); 2]
    );
    std::fs::create_dir(data.parent().unwrap()).unwrap();
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

/// GeoIP 也一样：配置里写了、此前连所在的目录都不存在的数据文件在重载时读进来，按回答地址判断的 Pipeline 换命名空间
/// GeoIP likewise: a data file the configuration names that did not exist before, its
/// directory neither, is read in on a reload, and a pipeline judging answer addresses moves
/// to a new namespace
#[tokio::test]
async fn a_reload_reading_geoip_data_in_moves_the_namespace() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("later").join("geoip.json");
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
    std::fs::create_dir(data.parent().unwrap()).unwrap();
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
