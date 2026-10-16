//! 照文档写的配置必须能加载：文档表格里的类型名和程序认的写法一一对应，文档和 config/ 里的配置示例都能解析。
//! A configuration written from the documentation has to load: the type names in the documentation tables match the
//! ones the program accepts one for one, and the configuration examples in the docs and in config/ all parse.

use std::collections::BTreeSet;
use std::path::Path;

use kixdns::config::{Action, Matcher, PipelineSelectorMatcher, ResponseMatcher, parse_config};
use serde::de::DeserializeOwned;

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
    let selector = accepted::<PipelineSelectorMatcher>();
    let request = accepted::<Matcher>();
    for (path, [requests, responses, actions]) in DOCS {
        let doc = read(path);
        // 请求匹配器表同时说 Pipeline selector 和请求规则：规则认表里除 listener_label 之外的全部
        // The request matcher table covers the pipeline selector and request rules alike: rules accept all of it but listener_label
        let table = table_types(&doc, requests);
        assert_eq!(table, selector, "{path}: {requests}");
        let rules: BTreeSet<String> = table
            .into_iter()
            .filter(|name| name != "listener_label")
            .collect();
        assert_eq!(rules, request, "{path}: request rules");
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

#[test]
fn documented_config_examples_parse() {
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
            if let Err(err) = parse_config(example) {
                panic!("{path}: example does not parse: {err:#}\n{example}");
            }
        }
    }
}

#[test]
fn shipped_example_configs_parse() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("config");
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).expect("read config/") {
        let path = entry.expect("config/ entry").path();
        if path.extension().is_none_or(|ext| ext != "json") {
            continue;
        }
        let raw = std::fs::read_to_string(&path).expect("read example config");
        if let Err(err) = parse_config(&raw) {
            panic!("{} does not parse: {err:#}", path.display());
        }
        checked += 1;
    }
    assert!(checked > 0, "no example configs in config/");
}
