//! 热重载换了 Geo 设置（GeoSite 的文件和用到的标签，GeoIP 的文件和是否用到）以后，规则用的是新
//! 配置要的数据，文件监视也跟着换到新的文件。
//! After a hot reload changes the Geo settings (GeoSite's files and the tags used, GeoIP's
//! files and whether it is used at all), rules use the data the new configuration asks for,
//! and the file watches move to the new files.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use serde_json::{Value, json};

use crate::engine::Engine;
use crate::engine::test_support::first_a;
use crate::matcher::RuntimePipelineConfig;

/// 规则命中时的应答 / The answer when the rule matches
const MATCHED: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 50);
/// 其余请求的应答 / The answer to everything else
const OTHER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 60);

/// 一个长度前缀字段 / One length-delimited field
pub(super) fn field(number: u8, bytes: &[u8]) -> Vec<u8> {
    assert!(bytes.len() < 128, "test fields stay below one length byte");
    let mut out = vec![(number << 3) | 2, bytes.len() as u8];
    out.extend_from_slice(bytes);
    out
}

/// GeoSite .dat 内容：每个 (标签, 后缀) 一个条目 / GeoSite .dat content: one entry per (tag, suffix)
pub(super) fn geosite_dat(entries: &[(&str, &str)]) -> Vec<u8> {
    entries
        .iter()
        .flat_map(|(tag, suffix)| {
            // Domain { type: 2 (suffix), value }
            let domain = [vec![0x08, 2], field(2, suffix.as_bytes())].concat();
            field(1, &[field(1, tag.as_bytes()), field(2, &domain)].concat())
        })
        .collect()
}

/// 唯一的 pipeline 里，带 `matcher` 的规则静态应答 [`MATCHED`]，其余请求得到 [`OTHER`]
/// One pipeline: a rule with `matcher` answers [`MATCHED`], and every other request gets
/// [`OTHER`]
fn config(settings: Value, matcher: Value) -> RuntimePipelineConfig {
    let mut all_settings = json!({ "default_upstream": "127.0.0.1:9" });
    all_settings
        .as_object_mut()
        .unwrap()
        .extend(settings.as_object().unwrap().clone());
    let config: crate::config::PipelineConfig = serde_json::from_value(json!({
        "settings": all_settings,
        "pipelines": [{ "id": "main", "rules": [
            {
                "name": "matched",
                "matchers": [matcher],
                "actions": [{ "type": "static_ip_response", "ip": MATCHED.to_string() }]
            },
            {
                "name": "other",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "static_ip_response", "ip": OTHER.to_string() }]
            }
        ]}]
    }))
    .expect("parse config");
    RuntimePipelineConfig::from_config(config).expect("build runtime config")
}

/// 只读 `paths` 里的 GeoSite 数据、规则按 `tag` 匹配的配置
/// A configuration reading GeoSite data from `paths`, its rule matching `tag`
fn geosite_config(paths: &[&Path], tag: &str) -> RuntimePipelineConfig {
    let paths: Vec<&str> = paths.iter().map(|path| path.to_str().unwrap()).collect();
    config(
        json!({ "geosite_data_paths": paths }),
        json!({ "type": "geo_site", "value": tag }),
    )
}

/// 同 [`geosite_config`]，规则命中 `tags` 里任何一个标签
/// As [`geosite_config`], with the rule matching any of the tags in `tags`
fn geosite_config_any_of(paths: &[&Path], tags: &[&str]) -> RuntimePipelineConfig {
    let paths: Vec<&str> = paths.iter().map(|path| path.to_str().unwrap()).collect();
    let matchers: Vec<Value> = tags
        .iter()
        .map(|tag| json!({ "type": "geo_site", "value": tag, "operator": "or" }))
        .collect();
    let config: crate::config::PipelineConfig = serde_json::from_value(json!({
        "settings": { "default_upstream": "127.0.0.1:9", "geosite_data_paths": paths },
        "pipelines": [{ "id": "main", "rules": [
            { "name": "matched", "matchers": matchers,
              "actions": [{ "type": "static_ip_response", "ip": MATCHED.to_string() }] },
            { "name": "other", "matchers": [{ "type": "any" }],
              "actions": [{ "type": "static_ip_response", "ip": OTHER.to_string() }] }
        ]}]
    }))
    .expect("parse config");
    RuntimePipelineConfig::from_config(config).expect("build runtime config")
}

fn engine(cfg: RuntimePipelineConfig) -> Engine {
    Engine::new(cfg, "test".to_string()).expect("engine")
}

/// 从 `peer` 问 `name` 的 A 记录 / Asks for `name`'s A record from `peer`
async fn ask_from(engine: &Engine, name: &str, peer: SocketAddr) -> Option<Ipv4Addr> {
    let mut request = Message::new(0x4d41, MessageType::Query, OpCode::Query);
    request.metadata.recursion_desired = true;
    request.add_query(Query::query(
        Name::from_str(&format!("{name}.")).unwrap(),
        RecordType::A,
    ));
    let packet = request.to_vec().unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(5), engine.handle_packet(&packet, peer))
        .await
        .expect("answer in time")
        .expect("answer");
    first_a(&reply)
}

async fn ask(engine: &Engine, name: &str) -> Option<Ipv4Addr> {
    ask_from(engine, name, "203.0.113.9:53000".parse().unwrap()).await
}

/// 等文件监视把改动读进来：`landed` 一成立就返回，只有监视坏了才会等满
/// Waits for a file watch to read a change in: returns as soon as `landed` holds, and only a
/// broken watch waits out the deadline
pub(super) async fn wait_for(what: &str, landed: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !landed() {
        assert!(Instant::now() < deadline, "{what}");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// 写到旁边的临时文件再改名盖过去，像面板和下载工具那样
/// Writes a sibling temporary file and renames it over `path`, as the panel and download
/// tools do
pub(super) fn replace(path: &Path, content: &[u8]) {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, content).unwrap();
    std::fs::rename(&tmp, path).unwrap();
}

/// .dat 只读规则用到的标签，所以热重载后新用到的标签必须读进来；不再用到的标签随之释放
/// A .dat is read only for the tags rules use, so a tag first used after a hot reload has to
/// be read in, and a tag no longer used goes away
#[tokio::test]
async fn a_geosite_tag_first_used_after_a_reload_is_loaded() {
    let dir = tempfile::tempdir().unwrap();
    let dat = dir.path().join("geosite.dat");
    std::fs::write(&dat, geosite_dat(&[("ads", "ads.test"), ("cn", "cn.test")])).unwrap();

    let engine = engine(geosite_config(&[&dat], "cn"));
    assert_eq!(ask(&engine, "www.cn.test").await, Some(MATCHED));
    assert_eq!(ask(&engine, "www.ads.test").await, Some(OTHER));

    engine.reload(geosite_config(&[&dat], "ads"));
    assert_eq!(ask(&engine, "x.ads.test").await, Some(MATCHED));
    assert_eq!(ask(&engine, "x.cn.test").await, Some(OTHER));
    assert!(
        !engine.geo().geosite.has_tag("cn"),
        "a tag no longer used must not stay loaded"
    );
}

/// 换了数据文件的路径（面板更新 Geo 数据就是写一份新文件再改路径），读的是新文件
/// A changed data file path (the panel updates Geo data by writing a new file and pointing the
/// configuration at it) reads the new file
#[tokio::test]
async fn a_changed_geosite_path_loads_the_new_file() {
    let dir = tempfile::tempdir().unwrap();
    let old = dir.path().join("old.dat");
    let new = dir.path().join("new.dat");
    std::fs::write(&old, geosite_dat(&[("ads", "old.test")])).unwrap();
    std::fs::write(&new, geosite_dat(&[("ads", "new.test")])).unwrap();

    let engine = engine(geosite_config(&[&old], "ads"));
    assert_eq!(ask(&engine, "www.old.test").await, Some(MATCHED));

    engine.reload(geosite_config(&[&new], "ads"));
    std::fs::remove_file(&old).unwrap();
    assert_eq!(ask(&engine, "x.new.test").await, Some(MATCHED));
    assert_eq!(ask(&engine, "x.old.test").await, Some(OTHER));
}

/// 规则里原本没有 GeoIP 匹配、热重载后才有，GeoIP 数据也要读进来
/// GeoIP data has to be read in when GeoIP matching first appears in the rules after a hot
/// reload
#[tokio::test]
async fn geoip_first_used_after_a_reload_is_loaded() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("geoip.json");
    std::fs::write(
        &data,
        r#"{"entries":[{"country_code":"TESTNET","ips":["198.51.100.0/24"]}]}"#,
    )
    .unwrap();
    let settings = json!({ "geoip_dat_path": data.to_str().unwrap() });
    let client: SocketAddr = "198.51.100.7:53000".parse().unwrap();

    let engine = engine(config(
        settings.clone(),
        json!({ "type": "client_ip", "cidr": "192.0.2.0/24" }),
    ));
    assert_eq!(ask_from(&engine, "a.test", client).await, Some(OTHER));

    engine.reload(config(
        settings,
        json!({ "type": "geoip_country", "country_codes": ["TESTNET"] }),
    ));
    assert_eq!(ask_from(&engine, "b.test", client).await, Some(MATCHED));
}

/// 配置里写了、启动时连所在的目录都不存在的文件监视不了，出现以后再热重载一次就读进来（目录在的见
/// `a_missing_geosite_file_is_read_once_it_appears`）
/// A configured file that did not exist at startup, its directory neither, cannot be watched,
/// and is read in by a hot reload after it appears (for one whose directory is there see
/// `a_missing_geosite_file_is_read_once_it_appears`)
#[tokio::test]
async fn a_data_file_that_appears_later_is_loaded_by_the_next_reload() {
    let dir = tempfile::tempdir().unwrap();
    let dat = dir.path().join("later").join("geosite.dat");

    let engine = engine(geosite_config(&[&dat], "ads"));
    assert_eq!(ask(&engine, "www.ads.test").await, Some(OTHER));

    std::fs::create_dir(dat.parent().unwrap()).unwrap();
    std::fs::write(&dat, geosite_dat(&[("ads", "ads.test")])).unwrap();
    engine.reload(geosite_config(&[&dat], "ads"));
    assert_eq!(ask(&engine, "x.ads.test").await, Some(MATCHED));
}

/// 热重载换了路径以后，监视的是新文件：新文件变了会读进来，旧文件再变也不会写进新数据
/// After a hot reload changes the path the new file is watched: its changes are read in, and
/// changes to the old file no longer reach the new data
#[tokio::test]
async fn after_a_reload_the_watch_follows_the_new_file() {
    let dir = tempfile::tempdir().unwrap();
    let old = dir.path().join("old.dat");
    let new = dir.path().join("new.dat");
    std::fs::write(&old, geosite_dat(&[("ads", "old.test")])).unwrap();
    std::fs::write(&new, geosite_dat(&[("ads", "new.test")])).unwrap();

    let engine = engine(geosite_config(&[&old], "ads"));
    engine.reload(geosite_config(&[&new], "ads"));

    // 两个文件在同一个目录里，同一个监视按顺序收到两次改动：新文件的改动读进来时，旧文件的那次
    // 已经处理过了
    // Both files share a directory, so one watch receives both changes in order: by the time
    // the new file's change is read in, the old file's has been handled
    replace(&old, &geosite_dat(&[("ads", "old-again.test")]));
    replace(&new, &geosite_dat(&[("ads", "new-again.test")]));
    wait_for("the watch must read the new file's change", || {
        engine.geo().geosite.matches("ads", "www.new-again.test")
    })
    .await;
    assert!(
        !engine.geo().geosite.matches("ads", "www.old-again.test"),
        "the old file must no longer be watched"
    );
}

/// 文件监视重读一个 JSON 文件时，只替换它自己贡献的标签，别的 .dat 文件贡献的标签留着
/// When the watch reads a JSON file again it replaces only the tags that file contributes,
/// keeping the tags another .dat file contributes
#[tokio::test]
async fn the_watch_reloading_json_keeps_the_tags_a_dat_file_provides() {
    let dir = tempfile::tempdir().unwrap();
    let dat = dir.path().join("a.dat");
    let json = dir.path().join("b.json");
    std::fs::write(&dat, geosite_dat(&[("cn", "baidu.com")])).unwrap();
    std::fs::write(
        &json,
        r#"{"entries":[{"tag":"ads","domains":["domain:before.example"]}]}"#,
    )
    .unwrap();

    let engine = engine(geosite_config_any_of(&[&dat, &json], &["cn", "ads"]));
    assert!(engine.geo().geosite.matches("cn", "www.baidu.com"));
    assert!(engine.geo().geosite.matches("ads", "before.example"));

    std::fs::write(
        &json,
        r#"{"entries":[{"tag":"ads","domains":["domain:after.example"]}]}"#,
    )
    .unwrap();
    wait_for("the watch must read the changed JSON file", || {
        engine.geo().geosite.matches("ads", "after.example")
    })
    .await;
    assert!(
        engine.geo().geosite.matches("cn", "www.baidu.com"),
        "reading the JSON file again must not take the .dat file's tags with it"
    );
}

/// GeoIP 数据文件换了路径以后，监视的也是新文件
/// After the GeoIP data file's path changes, the new file is the one watched
#[tokio::test]
async fn after_a_reload_the_geoip_watch_follows_the_new_file() {
    let dir = tempfile::tempdir().unwrap();
    let old = dir.path().join("old.json");
    let new = dir.path().join("new.json");
    let network =
        |net: &str| format!(r#"{{"entries":[{{"country_code":"TESTNET","ips":["{net}"]}}]}}"#);
    std::fs::write(&old, network("198.51.100.0/24")).unwrap();
    std::fs::write(&new, network("198.51.100.0/24")).unwrap();
    let matcher = json!({ "type": "geoip_country", "country_codes": ["TESTNET"] });

    let engine = engine(config(
        json!({ "geoip_dat_path": old.to_str().unwrap() }),
        matcher.clone(),
    ));
    engine.reload(config(
        json!({ "geoip_dat_path": new.to_str().unwrap() }),
        matcher,
    ));

    replace(&old, network("203.0.113.0/24").as_bytes());
    replace(&new, network("192.0.2.0/24").as_bytes());
    let tags: [Arc<str>; 1] = [Arc::from("TESTNET")];
    wait_for("the watch must read the new file's change", || {
        engine
            .geo()
            .geoip
            .matches_any_tag("192.0.2.1".parse().unwrap(), &tags)
    })
    .await;
    assert!(
        !engine
            .geo()
            .geoip
            .matches_any_tag("203.0.113.1".parse().unwrap(), &tags),
        "the old file must no longer be watched"
    );
}

/// GeoIP 数据文件只读规则用到的标签；热加载用到新标签时再读进来
/// A GeoIP data file is read only for the tags rules use; a tag first used after a hot reload
/// is read in then
#[tokio::test]
async fn only_the_geoip_tags_rules_use_are_loaded() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("geoip.json");
    std::fs::write(
        &data,
        r#"{"entries":[
            {"country_code":"TESTNET","ips":["198.51.100.0/24"]},
            {"country_code":"OTHERNET","ips":["203.0.113.0/24"]}
        ]}"#,
    )
    .unwrap();
    let settings = json!({ "geoip_dat_path": data.to_str().unwrap() });
    let rule = |codes: &[&str]| json!({ "type": "geoip_country", "country_codes": codes });

    let engine = engine(config(settings.clone(), rule(&["testnet"])));
    assert_eq!(engine.geo().geoip.ip_range_count(), 1);
    let other: SocketAddr = "203.0.113.7:53000".parse().unwrap();
    assert_eq!(ask_from(&engine, "a.test", other).await, Some(OTHER));

    engine.reload(config(settings, rule(&["TESTNET", "OTHERNET"])));
    assert_eq!(engine.geo().geoip.ip_range_count(), 2);
    assert_eq!(ask_from(&engine, "b.test", other).await, Some(MATCHED));
}

/// 有 MMDB 时国家代码只查它：数据文件只读命名标签，规则只用国家代码时数据文件不读；规则只用命名
/// 标签时 MMDB 不读
/// With an MMDB country codes are looked up there alone: the data file is read only for named
/// tags, and not at all when rules use country codes only; when rules use named tags only the
/// MMDB is not read
#[tokio::test]
async fn the_mmdb_answers_country_codes_and_the_data_file_named_tags() {
    let dir = tempfile::tempdir().unwrap();
    let mmdb_source = dir.path().join("mmdb-source.json");
    std::fs::write(
        &mmdb_source,
        r#"{"entries":[{"country_code":"US","ips":["198.51.100.0/24"]}]}"#,
    )
    .unwrap();
    let mmdb = dir.path().join("country.mmdb");
    crate::matcher::geoip_converter::convert_dat_to_mmdb(&mmdb_source, &mmdb, None).unwrap();
    let data = dir.path().join("geoip.json");
    std::fs::write(
        &data,
        r#"{"entries":[
            {"country_code":"US","ips":["192.0.2.0/24"]},
            {"country_code":"TESTNET","ips":["203.0.113.0/24"]}
        ]}"#,
    )
    .unwrap();
    let settings = json!({
        "geoip_db_path": mmdb.to_str().unwrap(),
        "geoip_dat_path": data.to_str().unwrap(),
    });
    let rule = |codes: &[&str]| json!({ "type": "geoip_country", "country_codes": codes });
    let us: SocketAddr = "198.51.100.7:53000".parse().unwrap();
    let testnet: SocketAddr = "203.0.113.7:53000".parse().unwrap();

    let engine = engine(config(settings.clone(), rule(&["US", "TESTNET"])));
    {
        let manager = engine.geo().geoip;
        assert!(manager.has_mmdb());
        assert_eq!(
            manager.ip_range_count(),
            1,
            "the data file's US entry must not be read when the MMDB answers US"
        );
    }
    assert_eq!(ask_from(&engine, "a.test", us).await, Some(MATCHED));
    assert_eq!(ask_from(&engine, "a.test", testnet).await, Some(MATCHED));

    engine.reload(config(settings.clone(), rule(&["US"])));
    {
        let manager = engine.geo().geoip;
        assert!(manager.has_mmdb());
        assert_eq!(
            manager.ip_range_count(),
            0,
            "the data file must not be read"
        );
    }
    assert_eq!(ask_from(&engine, "b.test", us).await, Some(MATCHED));

    engine.reload(config(settings, rule(&["TESTNET"])));
    {
        let manager = engine.geo().geoip;
        assert!(!manager.has_mmdb(), "the MMDB must not be read");
        assert_eq!(manager.ip_range_count(), 1);
    }
    assert_eq!(ask_from(&engine, "c.test", testnet).await, Some(MATCHED));
}

/// MMDB 不被监视：原地换成新的以后，配置不变的热重载也重读它，新库马上用上。以前配置里的 GeoIP 设置没变就不重读，新库要等
/// 重启
/// The MMDB is not watched: once replaced in place, a hot reload with the configuration unchanged
/// reads it again and the new database is used at once. It used not to be read again while the
/// configuration's GeoIP settings stayed the same, the new database waiting for a restart
#[tokio::test]
async fn a_hot_reload_reads_an_mmdb_replaced_in_place() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("mmdb-source.json");
    let mmdb = dir.path().join("country.mmdb");
    let convert = |country: &str| {
        let entries =
            format!(r#"{{"entries":[{{"country_code":"{country}","ips":["198.51.100.0/24"]}}]}}"#);
        std::fs::write(&source, entries).unwrap();
        crate::matcher::geoip_converter::convert_dat_to_mmdb(&source, &mmdb, None).unwrap();
    };
    convert("US");
    let cfg = || {
        config(
            json!({ "geoip_db_path": mmdb.to_str().unwrap() }),
            json!({ "type": "geoip_country", "country_codes": ["JP"] }),
        )
    };
    let client: SocketAddr = "198.51.100.7:53000".parse().unwrap();
    let engine = engine(cfg());
    assert_ne!(
        ask_from(&engine, "before.test", client).await,
        Some(MATCHED)
    );

    // 一样长的库，写明晚一秒，像隔了一阵才换上的那样 / A database as long, set a second later, as
    // for one replaced a while on
    convert("JP");
    let later = std::fs::metadata(&mmdb).unwrap().modified().unwrap() + Duration::from_secs(1);
    std::fs::File::options()
        .write(true)
        .open(&mmdb)
        .unwrap()
        .set_modified(later)
        .unwrap();
    engine.reload(cfg());
    assert_eq!(ask_from(&engine, "after.test", client).await, Some(MATCHED));
}

/// 存在却读不了的 MMDB，文件不换就不再读：别的配置改了的热重载不动 GeoIP 数据，用到它的 pipeline 留着缓存；换成读得
/// 了的，下一次热重载就读进来。在用的库被换成读不了的，那一次热重载读它、留着在用的，之后也不再读。以前读不了的和不存在的
/// 一样记成缺着的，文件又在，每次热重载都重读一遍、换一代，等于清掉这些 pipeline 的缓存
/// An MMDB that is there yet cannot be read is not read again until the file changes: a hot
/// reload changing other parts of the configuration leaves the GeoIP data, and the caches of
/// the pipelines using it, alone; once it is replaced by a readable one, the next
/// hot reload reads it in. When the database in use is replaced by an unreadable one, that one
/// hot reload reads it and keeps the database in use, and later ones do not read it again. An
/// unreadable file used to count as missing, as a file not there does, and being there it was
/// read again, and the data moved to a new generation, on every hot reload, clearing those
/// pipelines' caches
#[tokio::test]
async fn an_unreadable_mmdb_is_read_again_only_once_it_changes() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("mmdb-source.json");
    let mmdb = dir.path().join("country.mmdb");
    std::fs::write(&mmdb, b"not a database").unwrap();
    let cfg = |upstream: &str| {
        let mut cfg = config(
            json!({ "geoip_db_path": mmdb.to_str().unwrap() }),
            json!({ "type": "geoip_country", "country_codes": ["JP"] }),
        );
        cfg.settings.default_upstream = upstream.to_string();
        cfg
    };
    // 状态里的 GeoIP 数据，读了一遍就是新的一份 / The GeoIP data in the state, a new one for every read
    let geoip = |engine: &Engine| engine.geo().geoip;
    let client: SocketAddr = "198.51.100.7:53000".parse().unwrap();
    let engine = engine(cfg("127.0.0.1:9"));
    let unreadable = geoip(&engine);
    for upstream in ["127.0.0.1:10", "127.0.0.1:11"] {
        engine.reload(cfg(upstream));
        assert!(
            Arc::ptr_eq(&geoip(&engine), &unreadable),
            "an unrelated reload"
        );
    }

    let entries = r#"{"entries":[{"country_code":"JP","ips":["198.51.100.0/24"]}]}"#;
    std::fs::write(&source, entries).unwrap();
    crate::matcher::geoip_converter::convert_dat_to_mmdb(&source, &mmdb, None).unwrap();
    engine.reload(cfg("127.0.0.1:9"));
    assert!(
        !Arc::ptr_eq(&geoip(&engine), &unreadable),
        "a readable database"
    );
    assert_eq!(ask_from(&engine, "a.test", client).await, Some(MATCHED));

    replace(&mmdb, b"broken again");
    engine.reload(cfg("127.0.0.1:10"));
    let broken = geoip(&engine);
    engine.reload(cfg("127.0.0.1:11"));
    assert!(
        Arc::ptr_eq(&geoip(&engine), &broken),
        "the broken file is not read again"
    );
    assert_eq!(
        ask_from(&engine, "b.test", client).await,
        Some(MATCHED),
        "the database in use stays"
    );
}

/// 状态里说 `what` `path` 读得出来、却没有规则用到的标签了，`tags` 留着先前的数据的那句话
/// The status's sentence saying `what` `path` reads yet has none of the tags rules use, with
/// `tags` keeping the data from before
fn kept_sentence(what: &str, path: &Path, tags: &str) -> String {
    format!(
        "{what} {} now has none of the tags rules use; the data read from it before stays for {tags} until it changes again",
        path.display()
    )
}

/// GeoIP .dat 内容：一个标签一个 IPv4 网段 / GeoIP .dat content: one tag with one IPv4 network
fn geoip_dat(tag: &str, network: [u8; 4], prefix: u8) -> Vec<u8> {
    // CIDR { ip, prefix (varint) }
    let cidr = [field(1, &network), vec![0x10, prefix]].concat();
    field(1, &[field(1, tag.as_bytes()), field(2, &cidr)].concat())
}

/// `rounds` 次、每次一个新名字地问，绕开缓存；每次都要得到 `want`
/// Asks `rounds` times, a new name each time so no cache answers, expecting `want` every time
async fn keeps_answering(
    engine: &Engine,
    peer: SocketAddr,
    suffix: &str,
    want: Ipv4Addr,
    what: &str,
) {
    for round in 0..20 {
        let name = format!("n{round}.{suffix}");
        assert_eq!(
            ask_from(engine, &name, peer).await,
            Some(want),
            "{what}, round {round}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// GeoSite 数据文件被换成空文件（下载失败、磁盘写满会留下这样的文件），规则用到的标签照旧在，Geo 数据的问题里说一句，
/// 免得下次重启时规则不再命中、事先没有一点预兆；文件写好、读进来以后那句话跟着去掉。以前空文件被当成没有任何标签的
/// 合法数据读进去，规则一下子全不命中。
/// A GeoSite data file replaced by an empty one (what a failed download or a full disk leaves
/// behind) keeps the tags rules use, and the Geo data's problems say so, lest the next restart
/// leave the rules no longer matching with nothing to warn of it; once the file is written
/// right and read in, the sentence goes. The empty file used to be read as valid data with no
/// tags, and the rules stopped matching at once.
#[tokio::test]
async fn an_empty_geosite_file_keeps_the_tags_in_use() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("geosite.dat");
    std::fs::write(&path, geosite_dat(&[("testa", "geo.test")])).unwrap();
    let engine = engine(geosite_config(&[&path], "testa"));
    let peer = "203.0.113.9:53000".parse().unwrap();
    assert_eq!(ask(&engine, "first.geo.test").await, Some(MATCHED));

    replace(&path, b"");
    let kept = [kept_sentence("GeoSite data file", &path, "testa")];
    wait_for("the status must say the data stays", || {
        engine.geo_data_warnings() == kept
    })
    .await;
    keeps_answering(
        &engine,
        peer,
        "geo.test",
        MATCHED,
        "the empty file must not wipe the tag",
    )
    .await;

    // 文件再写好时照常读进来，那句话跟着去掉 / A good file written again is read in as usual,
    // and the sentence goes
    replace(&path, &geosite_dat(&[("testa", "geo2.test")]));
    wait_for("the good file must be read", || {
        engine.geo().geosite.matches("testa", "x.geo2.test")
    })
    .await;
    assert!(!engine.geo().geosite.matches("testa", "x.geo.test"));
    assert_eq!(engine.geo_data_warnings(), Vec::<String>::new());
}

/// 两个数据文件都提供一个标签时排在后面的说了算；它被换成空文件以后，这个标签用前面那个文件的数据，和全部重新读一遍
/// 一样，只有它提供的标签照旧留着正在用的数据。以前空文件的数据整个留着：前面那个文件明明还提供着这个标签，用的仍是
/// 后面那个文件被清空之前的数据，直到重启或者它再写一次
/// Of two data files providing one tag the later decides; once it is replaced by an empty
/// one, the tag takes the earlier file's data, as a full load would have it, and only the
/// tags it alone provided keep the data in use. The empty file's data used to be kept whole:
/// though the earlier file still provided the tag, it went on with the later file's data from
/// before it was emptied, until a restart or the file being written again
#[tokio::test]
async fn an_emptied_geosite_file_hands_a_shared_tag_back() {
    let dir = tempfile::tempdir().unwrap();
    let (first, last) = (dir.path().join("first.dat"), dir.path().join("last.dat"));
    std::fs::write(&first, geosite_dat(&[("shared", "first.test")])).unwrap();
    std::fs::write(
        &last,
        geosite_dat(&[("shared", "last.test"), ("only", "only.test")]),
    )
    .unwrap();
    let engine = engine(geosite_config_any_of(&[&first, &last], &["shared", "only"]));
    assert!(engine.geo().geosite.matches("shared", "x.last.test"));

    replace(&last, b"");
    wait_for("the shared tag must take the earlier file's data", || {
        engine.geo().geosite.matches("shared", "x.first.test")
    })
    .await;
    let manager = engine.geo().geosite;
    assert!(!manager.matches("shared", "x.last.test"));
    assert!(
        manager.matches("only", "x.only.test"),
        "a tag only the emptied file provided keeps the data in use"
    );
    assert_eq!(
        engine.geo_data_warnings(),
        [kept_sentence("GeoSite data file", &last, "only")]
    );
}

/// 热重载重新读入时遇到成了空文件的那个文件也一样：它此前说了算的共享标签用前面那个文件的数据，只有它提供的标签留着
/// 正在用的数据。以前它此前说了算的标签都留着它的旧数据，盖过了前面那个文件刚读出来的
/// The same for a hot reload reading the file that became empty: the shared tag it decided
/// takes the earlier file's data, and only the tags it alone provided keep the data in use.
/// Every tag it decided used to keep its old data, over what the earlier file had just given
#[tokio::test]
async fn a_reload_reading_an_emptied_geosite_file_hands_a_shared_tag_back() {
    let dir = tempfile::tempdir().unwrap();
    let [first, last, other] =
        ["first.dat", "last.dat", "other.dat"].map(|name| dir.path().join(name));
    std::fs::write(&first, geosite_dat(&[("shared", "first.test")])).unwrap();
    std::fs::write(
        &last,
        geosite_dat(&[("shared", "last.test"), ("only", "only.test")]),
    )
    .unwrap();
    std::fs::write(&other, geosite_dat(&[("else", "else.test")])).unwrap();
    let tags = ["shared", "only"];
    let engine = engine(geosite_config_any_of(&[&first, &last], &tags));
    assert!(engine.geo().geosite.matches("shared", "x.last.test"));

    // 多了一个文件，热重载把每个文件重新读一遍 / One more file, so the hot reload reads every
    // file again
    replace(&last, b"");
    engine.reload(geosite_config_any_of(&[&first, &last, &other], &tags));
    let manager = engine.geo().geosite;
    assert!(manager.matches("shared", "x.first.test"));
    assert!(!manager.matches("shared", "x.last.test"));
    assert!(
        manager.matches("only", "x.only.test"),
        "a tag only the emptied file provided keeps the data in use"
    );
    assert_eq!(
        engine.geo_data_warnings(),
        [kept_sentence("GeoSite data file", &last, "only")]
    );
}

/// GeoIP 的 .dat 数据文件被换成空文件，规则用到的标签照旧在，Geo 数据的问题里说一句，和 GeoSite 一样
/// A GeoIP .dat data file replaced by an empty one keeps the tags rules use, and the Geo data's
/// problems say so, as for GeoSite
#[tokio::test]
async fn an_empty_geoip_file_keeps_the_tags_in_use() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("geoip.dat");
    std::fs::write(&path, geoip_dat("TESTNET", [203, 0, 113, 0], 24)).unwrap();
    let engine = engine(config(
        json!({ "geoip_dat_path": path.to_str().unwrap() }),
        json!({ "type": "geoip_country", "country_codes": ["TESTNET"] }),
    ));
    let peer = "203.0.113.9:53000".parse().unwrap();
    assert_eq!(ask_from(&engine, "first.test", peer).await, Some(MATCHED));

    replace(&path, b"");
    let kept = [kept_sentence("GeoIP data file", &path, "TESTNET")];
    wait_for("the status must say the data stays", || {
        engine.geo_data_warnings() == kept
    })
    .await;
    keeps_answering(
        &engine,
        peer,
        "test",
        MATCHED,
        "the empty file must not wipe the tag",
    )
    .await;

    replace(&path, &geoip_dat("TESTNET", [198, 51, 100, 0], 24));
    let tags: [Arc<str>; 1] = [Arc::from("TESTNET")];
    wait_for("the good file must be read", || {
        engine
            .geo()
            .geoip
            .matches_any_tag("198.51.100.1".parse().unwrap(), &tags)
    })
    .await;
    assert_eq!(engine.geo_data_warnings(), Vec::<String>::new());
}

/// 数据文件已经成了空文件，在用的数据靠监视那一层留着。这时热重载改了要读的 Geo 数据（多了一个文件），所有文件
/// 重新读一遍：空文件读出来什么都没有，它此前提供、新配置也还用的标签照旧留着。以前这次重读把数据整个换掉，
/// 规则一下子全不命中，直到文件下次改动
/// A data file has become an empty one, and the data in use stays thanks to the watch. A hot
/// reload then changes the Geo data to read (one more file), so every file is read again: the
/// empty one gives nothing, and the tags it provided that the new configuration still uses
/// stay. This read used to replace the data whole, so the rules stopped matching at once
/// until the file changed again
#[tokio::test]
async fn a_reload_reading_an_empty_geosite_file_keeps_the_tags_still_in_use() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("geosite.dat");
    let other = dir.path().join("other.dat");
    std::fs::write(
        &path,
        geosite_dat(&[("testa", "geo.test"), ("testb", "b.test")]),
    )
    .unwrap();
    std::fs::write(&other, geosite_dat(&[("else", "else.test")])).unwrap();
    let engine = engine(geosite_config_any_of(&[&path], &["testa", "testb"]));
    assert_eq!(ask(&engine, "first.geo.test").await, Some(MATCHED));
    assert_eq!(ask(&engine, "first.b.test").await, Some(MATCHED));

    // 新配置只用 testa：留下的只有它，不再用的 testb 不留
    // The new configuration uses testa alone: it is what stays, and testb, no longer used,
    // does not
    replace(&path, b"");
    engine.reload(geosite_config(&[&path, &other], "testa"));
    assert_eq!(ask(&engine, "second.geo.test").await, Some(MATCHED));
    assert!(
        !engine.geo().geosite.has_tag("testb"),
        "only tags the rules use are kept"
    );
    assert_eq!(
        engine.geo_data_warnings(),
        [kept_sentence("GeoSite data file", &path, "testa")]
    );

    // 写坏了一半的文件（读不出来）也一样，状态里说的是它读不了 / The same for a file written
    // halfway (unreadable), the status saying it cannot be read
    replace(&path, &geosite_dat(&[("testa", "geo.test")])[..5]);
    engine.reload(geosite_config(&[&other, &path], "testa"));
    assert_eq!(ask(&engine, "third.geo.test").await, Some(MATCHED));
    let warnings = engine.geo_data_warnings();
    let unreadable = format!("GeoSite data file {} cannot be read: ", path.display());
    assert!(
        warnings.len() == 1 && warnings[0].starts_with(&unreadable),
        "{warnings:?}"
    );

    // 文件再写好时照常读进来 / A good file written again is read in as usual
    replace(&path, &geosite_dat(&[("testa", "geo2.test")]));
    wait_for("the good file must be read", || {
        engine.geo().geosite.matches("testa", "x.geo2.test")
    })
    .await;
    assert!(!engine.geo().geosite.matches("testa", "x.geo.test"));
}

/// GeoIP 的 .dat 数据文件也一样：成了空文件以后热重载改了规则用到的标签，原来在用、现在还用的标签照旧留着
/// The same for a GeoIP .dat data file: with it empty, a hot reload changing the tags rules use
/// keeps the tags that were in use and still are
#[tokio::test]
async fn a_reload_reading_an_empty_geoip_file_keeps_the_tags_still_in_use() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("geoip.dat");
    std::fs::write(&path, geoip_dat("TESTNET", [203, 0, 113, 0], 24)).unwrap();
    let using = |tags: &[&str]| {
        config(
            json!({ "geoip_dat_path": path.to_str().unwrap() }),
            json!({ "type": "geoip_country", "country_codes": tags }),
        )
    };
    let engine = engine(using(&["TESTNET"]));
    let peer = "203.0.113.9:53000".parse().unwrap();
    assert_eq!(ask_from(&engine, "first.test", peer).await, Some(MATCHED));

    replace(&path, b"");
    engine.reload(using(&["TESTNET", "ELSEWHERE"]));
    assert_eq!(ask_from(&engine, "second.test", peer).await, Some(MATCHED));
    assert_eq!(
        engine.geo_data_warnings(),
        [
            kept_sentence("GeoIP data file", &path, "TESTNET"),
            "GeoIP tags ELSEWHERE are in no GeoIP data: geoip_country never matches them"
                .to_string(),
        ]
    );

    replace(&path, &geoip_dat("TESTNET", [198, 51, 100, 0], 24));
    let tags: [Arc<str>; 1] = [Arc::from("TESTNET")];
    wait_for("the good file must be read", || {
        engine
            .geo()
            .geoip
            .matches_any_tag("198.51.100.1".parse().unwrap(), &tags)
    })
    .await;
}

/// 留着的只是同一个数据文件此前给的数据：配置换了一个数据文件、新文件是空的，旧文件的数据不沿用
/// Only the data the same file gave before is kept: with the configuration pointing at another
/// data file that is empty, the old file's data is not carried on
#[tokio::test]
async fn an_empty_geo_file_at_a_new_path_keeps_nothing_of_the_old_file() {
    let dir = tempfile::tempdir().unwrap();
    let peer = "203.0.113.9:53000".parse().unwrap();

    let (old, new) = (dir.path().join("old.dat"), dir.path().join("new.dat"));
    std::fs::write(&old, geoip_dat("TESTNET", [203, 0, 113, 0], 24)).unwrap();
    std::fs::write(&new, b"").unwrap();
    let using = |path: &Path| {
        config(
            json!({ "geoip_dat_path": path.to_str().unwrap() }),
            json!({ "type": "geoip_country", "country_codes": ["TESTNET"] }),
        )
    };
    let geoip = engine(using(&old));
    assert_eq!(ask_from(&geoip, "first.test", peer).await, Some(MATCHED));
    geoip.reload(using(&new));
    assert_eq!(ask_from(&geoip, "second.test", peer).await, Some(OTHER));

    let (old, new) = (
        dir.path().join("old-site.dat"),
        dir.path().join("new-site.dat"),
    );
    std::fs::write(&old, geosite_dat(&[("testa", "geo.test")])).unwrap();
    std::fs::write(&new, b"").unwrap();
    let geosite = engine(geosite_config(&[&old], "testa"));
    assert_eq!(ask(&geosite, "first.geo.test").await, Some(MATCHED));
    geosite.reload(geosite_config(&[&new], "testa"));
    assert_eq!(ask(&geosite, "second.geo.test").await, Some(OTHER));
}

/// 规则写的 GeoSite 标签编译时转成小写：写法不同的同一个标签只算一个，照样命中；没有数据文件提供的能被认出来（用来记
/// 告警）。以前按写法各算一个，`TestA` 和 `testa` 各从数据里读一遍、各建一份匹配器，大小写一改缓存也跟着换代
/// The GeoSite tags rules write are lowercased as they compile: one tag written in different
/// cases counts once and matches all the same, and those no data file provides are found (for
/// the warning). Each spelling used to count apart, `TestA` and `testa` each read from the data
/// and given matchers of their own, and a change of case moved the caches to a new namespace
#[tokio::test]
async fn geosite_tags_count_once_whatever_their_case() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("geosite.dat");
    std::fs::write(&path, geosite_dat(&[("testa", "geo.test")])).unwrap();
    let cfg = geosite_config_any_of(&[&path], &["TestA", "testa", "gone", "Gone"]);
    let used = cfg.geosite_tags();
    assert_eq!(used, ["gone", "testa"]);
    let engine = engine(cfg);
    assert_eq!(ask(&engine, "www.geo.test").await, Some(MATCHED));
    assert_eq!(engine.geo().geosite.missing_tags(&used), ["gone"]);
}

/// 配置了、启动时还不存在的数据文件也被监视（它所在的目录在就行）：文件一出现就读进来，不必等热重载。它在文件里的先后照
/// 配置写的算：几个文件声明同一个标签时排在后面的照旧说了算，后出现的文件不因此排到最后。以前不存在的文件不被监视，出现
/// 以后要等下一次热重载
/// A configured data file that is not there at startup is watched too (its directory being
/// there is enough): it is read in as soon as it appears, with no hot reload to wait for. Its
/// place among the files is the one the configuration writes: of files declaring one tag the
/// later still decides, and a file appearing later is not ranked last for it. A file not there
/// used not to be watched, and once it appeared it waited for the next hot reload
#[tokio::test]
async fn a_missing_geosite_file_is_read_once_it_appears() {
    let dir = tempfile::tempdir().unwrap();
    let (first, last) = (dir.path().join("first.dat"), dir.path().join("last.dat"));
    std::fs::write(&last, geosite_dat(&[("ads", "last.test")])).unwrap();
    let engine = engine(geosite_config_any_of(&[&first, &last], &["ads", "cn"]));
    assert_eq!(ask(&engine, "a.cn.test").await, Some(OTHER));

    replace(
        &first,
        &geosite_dat(&[("ads", "first.test"), ("cn", "cn.test")]),
    );
    wait_for("the file that appeared is read in", || {
        engine.geo().geosite.matches("cn", "x.cn.test")
    })
    .await;
    assert_eq!(ask(&engine, "b.cn.test").await, Some(MATCHED));
    // 两个文件都写着 ads，后面的说了算 / Both files write ads, and the later decides
    let manager = engine.geo().geosite;
    assert!(manager.matches("ads", "x.last.test"));
    assert!(!manager.matches("ads", "x.first.test"));
}

/// 引擎随时说得出 Geo 数据有什么不对，一样一句话（面板经控制通道读）：配置了却不存在的文件、读不了的文件和 MMDB、规则
/// 用到却没有数据提供的标签；文件改好了，监视读进来以后那句话就没了，MMDB 不被监视，下一次热重载读进来以后没了。以前
/// 这些只记在日志里，规则悄悄地一直不按数据判断，geo_site_not 对所有查询都成立
/// The engine can tell at any time what is wrong with the Geo data, a sentence each (the panel
/// reads them over the control channel): configured files that are not there, data files and
/// an MMDB that cannot be read, and tags rules use that no data provides; once a file is put
/// right its sentence goes as the watch reads it in, and the MMDB's, which is not watched,
/// once the next hot reload reads it in. These used to be in the log alone, rules quietly
/// never judging by the data, and geo_site_not holding for every query
#[tokio::test]
async fn geo_data_warnings_say_what_is_missing_or_unreadable() {
    let dir = tempfile::tempdir().unwrap();
    let site = dir.path().join("geosite.dat");
    let engine = engine(config(
        json!({ "geosite_data_paths": [site.to_str().unwrap()] }),
        json!({ "type": "geo_site_not", "value": "cn" }),
    ));
    assert_eq!(
        engine.geo_data_warnings(),
        [
            format!("GeoSite data file {} does not exist", site.display()),
            "GeoSite tags cn are in no data file: geo_site never matches them and geo_site_not always does".to_string(),
        ]
    );
    replace(&site, &geosite_dat(&[("cn", "cn.test")]));
    wait_for("the GeoSite file is read in", || {
        engine.geo_data_warnings().is_empty()
    })
    .await;
    assert_eq!(ask(&engine, "a.cn.test").await, Some(OTHER));

    let (mmdb, data) = (
        dir.path().join("country.mmdb"),
        dir.path().join("geoip.json"),
    );
    std::fs::write(&mmdb, b"not a database").unwrap();
    std::fs::write(&data, b"{ not json").unwrap();
    let cfg = || {
        config(
            json!({
                "geoip_db_path": mmdb.to_str().unwrap(),
                "geoip_dat_path": data.to_str().unwrap(),
            }),
            json!({ "type": "geoip_country", "country_codes": ["US", "TESTNET"] }),
        )
    };
    let engine = self::engine(cfg());
    let warnings = engine.geo_data_warnings();
    let unreadable =
        |what: &str, path: &Path| format!("{what} {} cannot be read: ", path.display());
    assert_eq!(warnings.len(), 3, "{warnings:?}");
    assert!(
        warnings[0].starts_with(&unreadable("GeoIP database", &mmdb)),
        "{warnings:?}"
    );
    assert!(
        warnings[1].starts_with(&unreadable("GeoIP data file", &data)),
        "{warnings:?}"
    );
    assert_eq!(
        warnings[2],
        "GeoIP tags TESTNET, US are in no GeoIP data: geoip_country never matches them"
    );

    replace(
        &data,
        br#"{"entries":[{"country_code":"TESTNET","ips":["203.0.113.0/24"]}]}"#,
    );
    wait_for("the GeoIP data file is read in", || {
        engine.geo_data_warnings().len() == 2
    })
    .await;
    let warnings = engine.geo_data_warnings();
    assert!(
        warnings[0].starts_with(&unreadable("GeoIP database", &mmdb)),
        "{warnings:?}"
    );
    // MMDB 读不了，国家代码改由数据文件答 / With the MMDB unreadable, the data file answers country codes
    assert_eq!(
        warnings[1],
        "GeoIP tags US are in no GeoIP data: geoip_country never matches them"
    );

    let source = dir.path().join("mmdb-source.json");
    std::fs::write(
        &source,
        r#"{"entries":[{"country_code":"US","ips":["198.51.100.0/24"]}]}"#,
    )
    .unwrap();
    crate::matcher::geoip_converter::convert_dat_to_mmdb(&source, &mmdb, None).unwrap();
    engine.reload(cfg());
    assert_eq!(engine.geo_data_warnings(), Vec::<String>::new());
}

/// 数据文件经符号链接改指到监视不上的地方（目录不存在）以后，Geo 数据的问题里说它在那里监视不上、改动由下一次热重载读，
/// 指回监视得上的地方以后这句话去掉，和配置文件的 `watch_error` 一样。说的是这一个文件：别的文件监视得好好的，不会把它
/// 去掉
/// Once a data file is pointed, through a symlink, somewhere that cannot be watched (a
/// directory that does not exist), the Geo data's problems say it cannot be watched there,
/// changes being read by the next hot reload, and once it points back somewhere watchable the
/// sentence goes, as the configuration file's `watch_error` does. It speaks of that one file:
/// another file being watched well does not take it away
#[cfg(unix)]
#[tokio::test]
async fn a_data_file_leading_where_nothing_can_be_watched_is_reported() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let (conf, good) = (dir.path().join("conf"), dir.path().join("good"));
    std::fs::create_dir(&conf).unwrap();
    std::fs::create_dir(&good).unwrap();
    std::fs::write(
        good.join("first.dat"),
        geosite_dat(&[("ads", "first.test")]),
    )
    .unwrap();
    let (first, last) = (conf.join("first.dat"), dir.path().join("last.dat"));
    symlink(good.join("first.dat"), &first).unwrap();
    std::fs::write(&last, geosite_dat(&[("cn", "cn1.test")])).unwrap();
    let point_at = |target: &Path| {
        let tmp = conf.join("first.dat.tmp");
        symlink(target, &tmp).unwrap();
        std::fs::rename(&tmp, &first).unwrap();
    };
    let engine = engine(geosite_config_any_of(&[&first, &last], &["ads", "cn"]));
    assert_eq!(engine.geo_data_warnings(), Vec::<String>::new());

    point_at(&dir.path().join("missing").join("first.dat"));
    let said = partly_watched("GeoSite data file", &first);
    let unwatched = || {
        engine
            .geo_data_warnings()
            .iter()
            .any(|sentence| sentence.starts_with(&said))
    };
    wait_for("the status says first.dat cannot be watched", unwatched).await;

    // last.dat 照常监视、读进来，first.dat 那句留着 / last.dat is watched and read in as
    // usual, and first.dat's sentence stays
    replace(&last, &geosite_dat(&[("cn", "cn2.test")]));
    wait_for("last.dat is read in", || {
        engine.geo().geosite.matches("cn", "x.cn2.test")
    })
    .await;
    assert!(unwatched(), "{:?}", engine.geo_data_warnings());

    point_at(&good.join("first.dat"));
    wait_for("the sentence goes once first.dat is watched again", || {
        engine.geo_data_warnings().is_empty()
    })
    .await;
    assert!(engine.geo().geosite.matches("ads", "x.first.test"));
}

/// 状态里说 `what` `path` 有位置监视不上的那句话的开头（后面是为什么）/ The start of the status's
/// sentence saying `what` `path` has places that cannot be watched (why follows)
#[cfg(unix)]
fn partly_watched(what: &str, path: &Path) -> String {
    format!(
        "{what} {} cannot be watched everywhere it leads, changes there are read at the next configuration reload: ",
        path.display()
    )
}

/// `link` 经符号链接指向 `dir` 下还不存在的目录里的同名文件，给出那个文件 / `link` leads, through a
/// symlink, to the file of its name in a directory under `dir` not there yet, which is given back
#[cfg(unix)]
fn link_into_a_missing_directory(dir: &Path, link: &Path) -> std::path::PathBuf {
    let target = dir.join("missing").join(link.file_name().unwrap());
    std::os::unix::fs::symlink(&target, link).unwrap();
    target
}

/// 启动时 GeoSite 数据文件经符号链接指向还不存在的目录：链接所在的目录监视得上，目录里的文件出现却看不到。状态里说它
/// 有位置监视不上、改动由下一次热重载读；目录建好、文件写进去以后，配置不变的热重载读进来，这句话跟着去掉。以前只要链接
/// 所在的目录监视得上就当监视着：状态只说它不存在，热重载也不读，直到重启
/// At startup a GeoSite data file leads, through a symlink, into a directory not there yet:
/// the link's directory is watched, yet the file showing up in that directory is not seen. The
/// status says it has places that cannot be watched, changes being read by the next hot
/// reload; once the directory is made and the file written, a hot reload with the
/// configuration unchanged reads it in, and the sentence goes. It used to count as watched as
/// long as the link's directory was: the status only said it did not exist, and hot reloads did
/// not read it either, until a restart
#[cfg(unix)]
#[tokio::test]
async fn a_geosite_file_partly_watched_at_startup_is_read_by_a_reload() {
    let dir = tempfile::tempdir().unwrap();
    let conf = dir.path().join("conf");
    std::fs::create_dir(&conf).unwrap();
    let site = conf.join("geosite.dat");
    let target = link_into_a_missing_directory(dir.path(), &site);
    let engine = engine(geosite_config(&[&site], "ads"));
    let warnings = engine.geo_data_warnings();
    assert_eq!(warnings.len(), 3, "{warnings:?}");
    assert_eq!(
        warnings[0],
        format!("GeoSite data file {} does not exist", site.display())
    );
    assert!(
        warnings[1].starts_with(&partly_watched("GeoSite data file", &site)),
        "{warnings:?}"
    );

    std::fs::create_dir(target.parent().unwrap()).unwrap();
    std::fs::write(&target, geosite_dat(&[("ads", "ads.test")])).unwrap();
    engine.reload(geosite_config(&[&site], "ads"));
    assert_eq!(ask(&engine, "x.ads.test").await, Some(MATCHED));
    assert_eq!(engine.geo_data_warnings(), Vec::<String>::new());
}

/// GeoIP 数据文件走同一套：启动时经符号链接指向还不存在的目录，状态里说它有位置监视不上；文件出现以后配置不变的热重载
/// 读进来
/// The GeoIP data file goes the same way: leading at startup, through a symlink, into a
/// directory not there yet, it is said to have places that cannot be watched; once the file
/// shows up a hot reload with the configuration unchanged reads it in
#[cfg(unix)]
#[tokio::test]
async fn a_geoip_file_partly_watched_at_startup_is_read_by_a_reload() {
    let dir = tempfile::tempdir().unwrap();
    let conf = dir.path().join("conf");
    std::fs::create_dir(&conf).unwrap();
    let data = conf.join("geoip.json");
    let target = link_into_a_missing_directory(dir.path(), &data);
    let cfg = || {
        config(
            json!({ "geoip_dat_path": data.to_str().unwrap() }),
            json!({ "type": "geoip_country", "country_codes": ["TESTNET"] }),
        )
    };
    let client: SocketAddr = "198.51.100.7:53000".parse().unwrap();
    let engine = engine(cfg());
    let warnings = engine.geo_data_warnings();
    assert_eq!(warnings.len(), 3, "{warnings:?}");
    assert!(
        warnings[1].starts_with(&partly_watched("GeoIP data file", &data)),
        "{warnings:?}"
    );
    assert_eq!(ask_from(&engine, "a.test", client).await, Some(OTHER));

    std::fs::create_dir(target.parent().unwrap()).unwrap();
    std::fs::write(
        &target,
        r#"{"entries":[{"country_code":"TESTNET","ips":["198.51.100.0/24"]}]}"#,
    )
    .unwrap();
    engine.reload(cfg());
    assert_eq!(ask_from(&engine, "b.test", client).await, Some(MATCHED));
    assert_eq!(engine.geo_data_warnings(), Vec::<String>::new());
}

/// 运行中数据文件经符号链接改指到还不存在的目录里：监视报它有位置监视不上，那个目录建好、文件写进去以后，配置不变的热
/// 重载读进来。以前这时状态里说它监视不上，热重载却当它监视着、不读，新文件直到重启都用不上
/// A data file pointed while running, through a symlink, into a directory not there yet: the
/// watch reports it has places that cannot be watched, and once that directory is made and the
/// file written, a hot reload with the configuration unchanged reads it in. The status used to
/// say it could not be watched there while hot reloads took it as watched and did not read it,
/// so the new file went unused until a restart
#[cfg(unix)]
#[tokio::test]
async fn a_data_file_pointed_where_it_is_partly_watched_is_read_by_a_reload() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let (conf, good) = (dir.path().join("conf"), dir.path().join("good"));
    std::fs::create_dir(&conf).unwrap();
    std::fs::create_dir(&good).unwrap();
    std::fs::write(
        good.join("geosite.dat"),
        geosite_dat(&[("ads", "good.test")]),
    )
    .unwrap();
    let site = conf.join("geosite.dat");
    symlink(good.join("geosite.dat"), &site).unwrap();
    let engine = engine(geosite_config(&[&site], "ads"));
    assert_eq!(ask(&engine, "x.good.test").await, Some(MATCHED));

    let target = dir.path().join("missing").join("geosite.dat");
    symlink(&target, conf.join("geosite.dat.tmp")).unwrap();
    std::fs::rename(conf.join("geosite.dat.tmp"), &site).unwrap();
    let said = partly_watched("GeoSite data file", &site);
    wait_for(
        "the status says geosite.dat cannot be watched there",
        || {
            engine
                .geo_data_warnings()
                .iter()
                .any(|sentence| sentence.starts_with(&said))
        },
    )
    .await;

    std::fs::create_dir(target.parent().unwrap()).unwrap();
    std::fs::write(&target, geosite_dat(&[("ads", "later.test")])).unwrap();
    engine.reload(geosite_config(&[&site], "ads"));
    assert_eq!(ask(&engine, "x.later.test").await, Some(MATCHED));
    assert_eq!(engine.geo_data_warnings(), Vec::<String>::new());
}

/// 启动时 GeoSite 数据文件经符号链接指向还不存在的目录；目录建好、文件写进去、链接照原样重建（`ln -sfn` 那样）以后，
/// 监视重新解析它，那个目录监视上，文件读进来，状态里不再说它监视不上。之后文件原地改写，监视照样读进来：状态说它都监
/// 视着，它就真的都监视着
/// At startup a GeoSite data file leads, through a symlink, into a directory not there yet;
/// once the directory is made, the file written and the link made anew as it was (as
/// `ln -sfn` does), the watch resolves it again, that directory is watched, the file is read in
/// and the status no longer says it cannot be watched. The file edited in place afterwards is
/// read in by the watch as well: when the status says it is watched everywhere, it is
#[cfg(unix)]
#[tokio::test]
async fn a_geosite_file_partly_watched_at_startup_is_watched_once_its_link_is_made_anew() {
    let dir = tempfile::tempdir().unwrap();
    let conf = dir.path().join("conf");
    std::fs::create_dir(&conf).unwrap();
    let site = conf.join("geosite.dat");
    let target = link_into_a_missing_directory(dir.path(), &site);
    let engine = engine(geosite_config(&[&site], "ads"));
    let said = partly_watched("GeoSite data file", &site);
    assert!(
        engine
            .geo_data_warnings()
            .iter()
            .any(|sentence| sentence.starts_with(&said)),
        "{:?}",
        engine.geo_data_warnings()
    );

    std::fs::create_dir(target.parent().unwrap()).unwrap();
    std::fs::write(&target, geosite_dat(&[("ads", "first.test")])).unwrap();
    let tmp = conf.join("geosite.dat.tmp");
    std::os::unix::fs::symlink(&target, &tmp).unwrap();
    std::fs::rename(&tmp, &site).unwrap();
    wait_for(
        "the watch reads the file once the link is made anew",
        || engine.geo().geosite.matches("ads", "x.first.test"),
    )
    .await;
    wait_for(
        "the status says nothing once it is watched everywhere",
        || engine.geo_data_warnings().is_empty(),
    )
    .await;

    std::fs::write(&target, geosite_dat(&[("ads", "second.test")])).unwrap();
    wait_for("the watch reads the file edited in place", || {
        engine.geo().geosite.matches("ads", "x.second.test")
    })
    .await;
    assert_eq!(engine.geo_data_warnings(), Vec::<String>::new());
}

/// 配置了却不存在、读不了的 Geo 数据文件和 MMDB 记成错误：默认日志级别是 error，记成 warn 的话没开面板时谁也看不到。
/// 以前都记成 warn
/// Geo data files and an MMDB that are configured yet not there or unreadable are logged as
/// errors: the default log level is error, and logged as warns they went unseen without the
/// panel. They used to be logged as warns
#[tokio::test]
async fn missing_and_unreadable_geo_files_are_logged_as_errors() {
    let dir = tempfile::tempdir().unwrap();
    let (site, mmdb, data) = (
        dir.path().join("geosite.dat"),
        dir.path().join("country.mmdb"),
        dir.path().join("geoip.json"),
    );
    std::fs::write(&mmdb, b"not a database").unwrap();
    std::fs::write(&data, b"{ not json").unwrap();
    let config: crate::config::PipelineConfig = serde_json::from_value(json!({
        "settings": {
            "default_upstream": "127.0.0.1:9",
            "geosite_data_paths": [site.to_str().unwrap()],
            "geoip_db_path": mmdb.to_str().unwrap(),
            "geoip_dat_path": data.to_str().unwrap(),
        },
        "pipelines": [{ "id": "main", "rules": [{
            "name": "r",
            "matchers": [
                { "type": "geo_site", "value": "ads" },
                { "type": "geoip_country", "country_codes": ["US", "TESTNET"], "operator": "or" }
            ],
            "actions": [{ "type": "static_ip_response", "ip": MATCHED.to_string() }]
        }]}]
    }))
    .unwrap();
    let cfg = RuntimePipelineConfig::from_config(config).unwrap();
    let (logged, guard) = crate::engine::test_support::Warnings::capture();
    let _engine = engine(cfg);
    drop(guard);
    let lines = logged.lines();
    let errors: Vec<&str> = lines
        .iter()
        .map(|line| line.trim_start())
        .filter(|line| line.starts_with("ERROR"))
        .collect();
    for wanted in [
        "GeoSite data file not found",
        "GeoIP database",
        "GeoIP data",
    ] {
        assert!(
            errors.iter().any(|message| message.contains(wanted)),
            "{wanted}: {errors:?}"
        );
    }
}

/// 像 Kubernetes 的卷那样换上一版数据：这一版写进它自己的目录 `version`，`..data` 改指到这个目录；头一回还建好
/// `..data` 和经它指到文件 `name` 的链接
/// Puts in a version of the data as a Kubernetes volume does: the version is written to a
/// directory of its own, `version`, and `..data` is pointed at that directory; the first time
/// also sets up `..data` and the link to file `name` through it
#[cfg(unix)]
fn kubernetes_volume(volume: &Path, name: &str, version: &str, content: &[u8]) {
    use std::os::unix::fs::symlink;
    std::fs::create_dir(volume.join(version)).unwrap();
    std::fs::write(volume.join(version).join(name), content).unwrap();
    let data = volume.join("..data");
    if data.symlink_metadata().is_ok() {
        symlink(version, volume.join("..data_tmp")).unwrap();
        std::fs::rename(volume.join("..data_tmp"), &data).unwrap();
    } else {
        symlink(version, &data).unwrap();
        symlink(Path::new("..data").join(name), volume.join(name)).unwrap();
    }
}

/// Kubernetes 卷换了 `..data` 以后，卷里的数据文件还排在配置写的位置：[卷里的 first.dat, last.dat] 都写着 shared 时
/// last.dat 说了算，first.dat 换了一版也一样
/// Once a Kubernetes volume swaps `..data`, the data file in it keeps the place the
/// configuration writes: with [first.dat in the volume, last.dat] both writing shared,
/// last.dat decides, and still does once first.dat has a new version
#[cfg(unix)]
#[tokio::test]
async fn a_kubernetes_volume_swap_keeps_the_file_in_its_place() {
    let dir = tempfile::tempdir().unwrap();
    let volume = dir.path().join("volume");
    std::fs::create_dir(&volume).unwrap();
    let version = |shared: &str, only: &str| geosite_dat(&[("shared", shared), ("only", only)]);
    kubernetes_volume(
        &volume,
        "first.dat",
        "..v1",
        &version("first1.test", "only1.test"),
    );
    let (first, last) = (volume.join("first.dat"), dir.path().join("last.dat"));
    std::fs::write(&last, geosite_dat(&[("shared", "last.test")])).unwrap();
    let engine = engine(geosite_config_any_of(&[&first, &last], &["shared", "only"]));
    let manager = engine.geo().geosite;
    assert!(manager.matches("shared", "x.last.test"), "last.dat decides");
    assert!(!manager.matches("shared", "x.first1.test"));

    kubernetes_volume(
        &volume,
        "first.dat",
        "..v2",
        &version("first2.test", "only2.test"),
    );
    wait_for("the new version is read in", || {
        engine.geo().geosite.matches("only", "x.only2.test")
    })
    .await;
    let manager = engine.geo().geosite;
    assert!(
        manager.matches("shared", "x.last.test"),
        "last.dat still comes after first.dat and decides shared"
    );
    assert!(!manager.matches("shared", "x.first2.test"));
}

/// Kubernetes 卷换上的一版不再写着某个标签时，这个标签和改写一个普通文件一样随之去掉，Geo 数据的问题里说一句它没有
/// 数据了
/// When the version a Kubernetes volume swaps in no longer writes some tag, the tag goes, as
/// when a plain file is written over, and the Geo data's problems say it has no data
#[cfg(unix)]
#[tokio::test]
async fn a_tag_a_kubernetes_volume_swap_removes_goes() {
    let dir = tempfile::tempdir().unwrap();
    let volume = dir.path();
    kubernetes_volume(
        volume,
        "site.dat",
        "..v1",
        &geosite_dat(&[("ads", "ads1.test"), ("cn", "cn.test")]),
    );
    let site = volume.join("site.dat");
    let engine = engine(geosite_config_any_of(&[&site], &["ads", "cn"]));
    assert!(engine.geo().geosite.matches("cn", "x.cn.test"));
    assert_eq!(engine.geo_data_warnings(), Vec::<String>::new());

    kubernetes_volume(
        volume,
        "site.dat",
        "..v2",
        &geosite_dat(&[("ads", "ads2.test")]),
    );
    let unprovided = [
        "GeoSite tags cn are in no data file: geo_site never matches them and geo_site_not always does",
    ];
    wait_for("the status says cn has no data", || {
        engine.geo_data_warnings() == unprovided
    })
    .await;
    let manager = engine.geo().geosite;
    assert!(manager.matches("ads", "x.ads2.test"));
    assert!(!manager.has_tag("cn"), "cn went with the old version");
}
