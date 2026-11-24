//! 照文档写的配置必须能加载：文档表格里的类型名和程序认的写法一一对应，文档和 config/ 里的配置示例都编译得过，文档列的
//! 只在启动时读的设置就是改了要重启的那些。
//! A configuration written from the documentation has to load: the type names in the documentation tables match the
//! ones the program accepts one for one, the configuration examples in the docs and in config/ all compile, and the
//! settings the docs list as read at startup only are those whose change takes a restart.

use std::collections::BTreeSet;
use std::path::Path;

use kixdns::config::{Action, GlobalSettings, Matcher, ResponseMatcher, compile, parse_config};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

/// 中英文两份配置参考，各自三张类型表的标题 / The two configuration references and the headings of their three type tables
const DOCS: [(&str, [&str; 3]); 2] = [
    (
        "docs/configuration.md",
        [
            "### Pipeline selector 和请求匹配器",
            "### 响应匹配器",
            "### 动作",
        ],
    ),
    (
        "docs/configuration.en.md",
        [
            "### Pipeline selector and request matchers",
            "### Response matchers",
            "### Actions",
        ],
    ),
];

fn read(path: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
        .unwrap_or_else(|err| panic!("read {path}: {err}"))
}

/// 标题下第一张表第一列的值（跳过表头和分隔行） / The first column of the first table under a heading, header and separator rows skipped
fn table_types(doc: &str, heading: &str) -> BTreeSet<String> {
    let start = doc
        .lines()
        .position(|line| line.trim() == heading)
        .unwrap_or_else(|| panic!("heading {heading} not found"));
    doc.lines()
        .skip(start + 1)
        .skip_while(|line| !line.starts_with('|'))
        .take_while(|line| line.starts_with('|'))
        .skip(2)
        .map(|line| line.split('|').nth(1).unwrap_or_default().trim().to_owned())
        .collect()
}

/// 程序认的全部类型名：拿一个不存在的类型去解析，serde 会在报错里列出全部可选值
/// Every type name the program accepts: parsing a type that does not exist makes serde list all the choices in its error
fn accepted<T: DeserializeOwned>() -> BTreeSet<String> {
    let Err(err) = serde_json::from_str::<T>(r#"{"type":"?"}"#) else {
        panic!("? parsed as a type");
    };
    let err = err.to_string();
    let choices = err
        .split("expected one of ")
        .nth(1)
        .unwrap_or_else(|| panic!("serde did not list the choices: {err}"));
    choices
        .split('`')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect()
}

#[test]
fn documented_type_names_are_the_accepted_ones() {
    for (path, [requests, responses, actions]) in DOCS {
        let doc = read(path);
        // 请求匹配器表同时说 Pipeline selector 和请求规则，两边读的是同一套；写在规则里的 listener_label 编译不过（见
        // config 的测试）
        // The request matcher table covers the pipeline selector and request rules alike, both
        // reading the one set; a listener_label written in a rule does not compile (see the
        // config tests)
        assert_eq!(
            table_types(&doc, requests),
            accepted::<Matcher>(),
            "{path}: {requests}"
        );
        assert_eq!(
            table_types(&doc, responses),
            accepted::<ResponseMatcher>(),
            "{path}: {responses}"
        );
        assert_eq!(
            table_types(&doc, actions),
            accepted::<Action>(),
            "{path}: {actions}"
        );
    }
}

/// 全局设置表和程序认的设置一一对应：`GlobalSettings::default()` 写出来的每个设置在两份文档的表里各有一行，表里也没有
/// 不存在的设置。以前 doh_health_check_error_threshold 一直没写进表里
/// The global settings tables match the settings the program reads one for one: every setting
/// `GlobalSettings::default()` writes out has a row in the tables of both documents, and the
/// tables hold none that does not exist. doh_health_check_error_threshold used to be missing
#[test]
fn every_setting_has_a_row_in_the_settings_tables() {
    let settings: BTreeSet<String> =
        serde_json::to_value(kixdns::config::GlobalSettings::default())
            .expect("settings serialize")
            .as_object()
            .expect("settings are an object")
            .keys()
            .cloned()
            .collect();
    for (path, heading) in [
        ("docs/configuration.md", "### 全局设置"),
        ("docs/configuration.en.md", "### Global settings"),
    ] {
        assert_eq!(table_types(&read(path), heading), settings, "{path}");
    }
}

#[test]
fn documented_config_examples_load() {
    for (path, _) in DOCS {
        let doc = read(path);
        // 只有完整配置才单独解析；ECS 那段只是一个动作 / Only whole configurations parse on their own; the ECS snippet is a single action
        let examples: Vec<&str> = doc
            .split("~~~json\n")
            .skip(1)
            .filter_map(|block| block.split("~~~").next())
            .filter(|block| block.contains("\"pipelines\""))
            .collect();
        assert!(
            !examples.is_empty(),
            "{path}: no configuration examples found"
        );
        for example in examples {
            // 面板保存时会拒绝的，示例里也不能有：配置问题、编译不了的匹配器、说不通的设置和监听地址（见 config::compile）
            // Nothing the panel would refuse to save may appear in an example either: problems,
            // matchers that do not compile, settings and listeners that make no sense (see
            // config::compile)
            if let Err(err) = parse_config(example).and_then(compile) {
                panic!("{path}: example does not load: {err:#}\n{example}");
            }
        }
    }
}

#[test]
fn shipped_example_configs_load() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("config");
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).expect("read config/") {
        let path = entry.expect("config/ entry").path();
        if path.extension().is_none_or(|ext| ext != "json") {
            continue;
        }
        let raw = std::fs::read_to_string(&path).expect("read example config");
        if let Err(err) = parse_config(&raw).and_then(compile) {
            panic!("{} does not load: {err:#}", path.display());
        }
        checked += 1;
    }
    assert!(checked > 0, "no example configs in config/");
}

/// 只在启动时读的设置：每个设置换一个同类型的值，`restart_pending` 报出它的就是。写不出来的（`null` 换成字符串读不了）
/// 再换成数字
/// The settings read at startup only: each setting given another value of its kind, those
/// `restart_pending` names. One that does not read so (`null` turned into a string) is given a
/// number instead
fn startup_settings() -> BTreeSet<String> {
    let running = GlobalSettings::default();
    let written = serde_json::to_value(&running).expect("settings serialize");
    let changed = |key: &str| -> GlobalSettings {
        let others = match &written[key] {
            Value::Bool(on) => vec![json!(!on)],
            Value::Number(number) => vec![json!(number.as_u64().expect("a whole number") + 1)],
            Value::String(text) => vec![json!(format!("{text}x"))],
            Value::Array(_) => vec![json!(["x"])],
            Value::Null => vec![json!("x"), json!(1)],
            Value::Object(_) => panic!("{key} is an object"),
        };
        others
            .into_iter()
            .find_map(|other| {
                let mut settings = written.clone();
                settings[key] = other;
                serde_json::from_value(settings).ok()
            })
            .unwrap_or_else(|| panic!("no other value of {key} reads"))
    };
    written
        .as_object()
        .expect("settings are an object")
        .keys()
        .filter(|key| {
            changed(key)
                .restart_pending(&running)
                .contains(&key.as_str())
        })
        .cloned()
        .collect()
}

/// 文档里那句「只在启动时读取」列出的设置：从开头的那句话起，到说其余设置的地方为止，反引号里的每一个
/// The settings the docs list as read at startup only: every one in backquotes from the sentence
/// opening the list up to where the other settings are spoken of
fn documented_startup_settings(doc: &str, opening: &str, rest: &str) -> BTreeSet<String> {
    let line = doc
        .lines()
        .find(|line| line.starts_with(opening))
        .unwrap_or_else(|| panic!("no line starts with {opening}"));
    let list = &line[..line
        .find(rest)
        .unwrap_or_else(|| panic!("{rest} not found after {opening}"))];
    list.split('`')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect()
}

/// 两份文档列出的只在启动时读的设置，就是 `restart_pending` 改了要重启的那些，不多不少
/// The settings both documents list as read at startup only are exactly those `restart_pending`
/// takes a restart for
#[test]
fn the_documented_startup_settings_are_those_that_take_a_restart() {
    let startup = startup_settings();
    assert!(startup.contains("bind_udp"), "{startup:?}");
    assert!(!startup.contains("min_ttl"), "{startup:?}");
    for (path, opening, rest) in [
        (
            "docs/configuration.md",
            "下面这些全局设置只在启动时读取",
            "其余全局设置",
        ),
        (
            "docs/configuration.en.md",
            "These global settings are read at startup only",
            "Every other global setting",
        ),
    ] {
        assert_eq!(
            documented_startup_settings(&read(path), opening, rest),
            startup,
            "{path}"
        );
    }
}
