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
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use serde_json::{Value, json};

use crate::engine::Engine;
use crate::matcher::RuntimePipelineConfig;

/// 规则命中时的应答 / The answer when the rule matches
const MATCHED: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 50);
/// 其余请求的应答 / The answer to everything else
const OTHER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 60);

/// 一个长度前缀字段 / One length-delimited field
fn field(number: u8, bytes: &[u8]) -> Vec<u8> {
    assert!(bytes.len() < 128, "test fields stay below one length byte");
    let mut out = vec![(number << 3) | 2, bytes.len() as u8];
    out.extend_from_slice(bytes);
    out
}

/// GeoSite .dat 内容：每个 (标签, 后缀) 一个条目 / GeoSite .dat content: one entry per (tag, suffix)
fn geosite_dat(entries: &[(&str, &str)]) -> Vec<u8> {
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
    match Message::from_bytes(&reply)
        .expect("parse reply")
        .answers
        .first()
        .map(|record| &record.data)
    {
        Some(RData::A(address)) => Some(address.0),
        _ => None,
    }
}

async fn ask(engine: &Engine, name: &str) -> Option<Ipv4Addr> {
    ask_from(engine, name, "203.0.113.9:53000".parse().unwrap()).await
}

/// 等文件监视把改动读进来：`landed` 一成立就返回，只有监视坏了才会等满
/// Waits for a file watch to read a change in: returns as soon as `landed` holds, and only a
/// broken watch waits out the deadline
async fn wait_for(what: &str, landed: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !landed() {
        assert!(Instant::now() < deadline, "{what}");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// 写到旁边的临时文件再改名盖过去，像面板和下载工具那样
/// Writes a sibling temporary file and renames it over `path`, as the panel and download
/// tools do
fn replace(path: &Path, content: &[u8]) {
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
        !engine.geosite_manager.read().has_tag("cn"),
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

/// 配置里写了、启动时还不存在的文件，出现以后再热重载一次就读进来
/// A configured file that did not exist at startup is read in by a hot reload after it appears
#[tokio::test]
async fn a_data_file_that_appears_later_is_loaded_by_the_next_reload() {
    let dir = tempfile::tempdir().unwrap();
    let dat = dir.path().join("geosite.dat");

    let engine = engine(geosite_config(&[&dat], "ads"));
    assert_eq!(ask(&engine, "www.ads.test").await, Some(OTHER));

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
    let manager = &engine.geosite_manager;
    wait_for("the watch must read the new file's change", || {
        manager.read().matches("ads", "www.new-again.test")
    })
    .await;
    assert!(
        !manager.read().matches("ads", "www.old-again.test"),
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

    let engine = engine(geosite_config(&[&dat, &json], "cn"));
    let manager = &engine.geosite_manager;
    assert!(manager.read().matches("cn", "www.baidu.com"));

    std::fs::write(
        &json,
        r#"{"entries":[{"tag":"ads","domains":["domain:after.example"]}]}"#,
    )
    .unwrap();
    wait_for("the watch must read the changed JSON file", || {
        manager.read().matches("ads", "after.example")
    })
    .await;
    assert!(
        manager.read().matches("cn", "www.baidu.com"),
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
    let manager = &engine.geoip_manager;
    let tags: [Arc<str>; 1] = [Arc::from("TESTNET")];
    wait_for("the watch must read the new file's change", || {
        manager
            .read()
            .matches_any_tag("192.0.2.1".parse().unwrap(), &tags)
    })
    .await;
    assert!(
        !manager
            .read()
            .matches_any_tag("203.0.113.1".parse().unwrap(), &tags),
        "the old file must no longer be watched"
    );
}
