//! 配置了的 GeoSite 文件不存在时，控制通道 `config` 结果的 `data_warnings` 说出来；文件一出现，监视就把它读进来，
//! 这几句话跟着没了。
//!
//! 在真程序上跑：配置写着一个不存在的 geosite.dat 和一条 geo_site_not cn 规则。`data_warnings` 先列出缺失的文件和没有
//! 数据的标签 cn，这时 geo_site_not 对所有查询都成立，cn 下的名字也按它答（比如全都送去境外上游）；文件出现以后不用热
//! 重载就读进来，`data_warnings` 变空，cn 下的名字不再命中这条规则。以前这些只记成默认日志级别看不到的 warn，控制通道
//! 里这个字段是 null，缺失的文件也不监视，下载到了也要等热重载才读。
//!
//! With a configured GeoSite file missing, `data_warnings` in the control channel's `config`
//! result says so; once the file appears the watch reads it in and those sentences go.
//!
//! Runs the real binary on a configuration naming a geosite.dat that is not there and a
//! geo_site_not cn rule. `data_warnings` first lists the missing file and the tag cn as having
//! no data, and meanwhile geo_site_not holds for every query, names under cn answered by it
//! too (all sent to the upstream abroad, say); once the file appears it is read in with no hot
//! reload, `data_warnings` turns empty, and names under cn no longer match the rule. This used
//! to be only warnings the default log level does not show, the field null on the control
//! channel, and a missing file was not watched, so one downloaded later waited for a hot
//! reload to be read.
#![cfg(unix)]

use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;

mod common;
use common::{ask, control_get, eventually, first_a, free_port, start_with_control};

/// geo_site_not cn 成立时的应答 / The answer when geo_site_not cn holds
const ABROAD: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
/// 其余查询的应答 / The answer to every other query
const HOME: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

/// GeoSite .dat 的内容：标签 `tag` 下一条域名后缀 `suffix`，按 V2Ray 的 protobuf 写
/// GeoSite .dat content: one domain suffix `suffix` under the tag `tag`, in V2Ray's protobuf
fn geosite_dat(tag: &str, suffix: &str) -> Vec<u8> {
    // 一个长度前缀字段 / One length-delimited field
    let field = |number: u8, bytes: &[u8]| {
        assert!(bytes.len() < 128, "test fields stay below one length byte");
        [vec![(number << 3) | 2, bytes.len() as u8], bytes.to_vec()].concat()
    };
    // Domain { type: 2（后缀 / suffix）, value }
    let domain = [vec![0x08, 2], field(2, suffix.as_bytes())].concat();
    // GeoSiteList { entry: GeoSite { country_code, domain } }
    field(1, &[field(1, tag.as_bytes()), field(2, &domain)].concat())
}

/// 控制通道 `config` 结果里的 `data_warnings` / `data_warnings` in the control channel's `config` result
fn data_warnings(control: &Path) -> serde_json::Value {
    let (status, active) = control_get(control, "/v1/config/active");
    assert_eq!(status, 200, "{active}");
    active["data_warnings"].clone()
}

fn answer(port: u16, name: &str) -> Option<Ipv4Addr> {
    first_a(&ask(port, name)?)
}

#[test]
fn data_warnings_name_the_missing_file_until_it_appears() {
    let dir = tempfile::TempDir::new().unwrap();
    let geosite = dir.path().join("geosite.dat");
    let port = free_port();
    let config = serde_json::json!({
        "settings": {
            "bind_udp": format!("127.0.0.1:{port}"),
            "bind_tcp": format!("127.0.0.1:{port}"),
            "default_upstream": "127.0.0.1:9",
            "geosite_data_paths": [geosite],
        },
        "pipelines": [{
            "id": "main",
            "rules": [
                {
                    "name": "abroad",
                    "matchers": [{ "type": "geo_site_not", "value": "cn" }],
                    "actions": [{ "type": "static_ip_response", "ip": ABROAD.to_string() }],
                },
                {
                    "name": "home",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "static_ip_response", "ip": HOME.to_string() }],
                },
            ],
        }],
    });
    let (_kernel, _, control) = start_with_control(dir.path(), &config);

    // 文件不在：说出缺的文件和没有数据的标签，geo_site_not 对 cn 下的名字也成立
    // The file not there: the missing file and the tag with no data are named, and
    // geo_site_not holds for names under cn too
    assert_eq!(
        data_warnings(&control),
        serde_json::json!([
            format!("GeoSite data file {} does not exist", geosite.display()),
            "GeoSite tags cn are in no data file: geo_site never matches them and geo_site_not always does",
        ])
    );
    assert!(
        eventually(Duration::from_secs(10), || {
            answer(port, "a.cn.test") == Some(ABROAD)
        }),
        "geo_site_not cn holds for every name while the file is missing"
    );

    // 文件出现（像下载工具那样写到旁边再改名盖过去），不用热重载就读进来
    // The file appears (written beside it and renamed over, as download tools do) and is read
    // in with no hot reload
    let staged = geosite.with_extension("staged");
    std::fs::write(&staged, geosite_dat("cn", "cn.test")).unwrap();
    std::fs::rename(&staged, &geosite).unwrap();
    assert!(
        eventually(Duration::from_secs(10), || {
            data_warnings(&control) == serde_json::json!([])
        }),
        "the file that appeared is read in: {}",
        data_warnings(&control)
    );
    assert_eq!(answer(port, "b.cn.test"), Some(HOME));
    assert_eq!(answer(port, "b.other.test"), Some(ABROAD));
}
