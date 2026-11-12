//! 只写了全局设置、没有 pipeline 的配置，重载时缓存一样要换：全局设置变了，按旧设置得到的应答不再用。
//! A configuration of global settings alone, with no pipeline, moves to a new cache on reload
//! like any other: with a global setting changed, answers got under the old one are used no
//! more.

use std::net::Ipv4Addr;
use std::str::FromStr;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use serde_json::{Value, json};

use crate::engine::test_support::{
    answering_upstream, ask, counting_settings, engine_from, first_a, peer,
};
use crate::matcher::RuntimePipelineConfig;

fn query(name: &str) -> Vec<u8> {
    let mut query = Message::new(0x5a5a, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
    query.to_vec().unwrap()
}

fn settings_only(upstream: &str) -> Value {
    json!({ "settings": counting_settings(json!({ "default_upstream": upstream })), "pipelines": [] })
}

/// 换了默认上游再重载：同一个名字去问新上游，不再用旧上游留在缓存里的回答。以前没有 pipeline 时缓存的命名空间
/// 恒为 0，重载分不开新旧，旧上游的回答一直用到过期
/// Reloading with another default upstream: the same name is asked of the new upstream, and
/// the old upstream's answer left in the cache is used no more. With no pipeline the cache
/// namespace used to be 0 always, a reload told old from new by nothing, and the old
/// upstream's answer was served until it expired
#[tokio::test]
async fn a_reload_of_settings_alone_leaves_the_old_answers_behind() {
    let old = answering_upstream(Ipv4Addr::new(192, 0, 2, 1), 300).await;
    let new = answering_upstream(Ipv4Addr::new(192, 0, 2, 2), 300).await;
    let engine = engine_from(settings_only(&old.address));
    let before = ask(&engine, &query("name.test."), peer()).await;
    assert_eq!(first_a(&before), Some(Ipv4Addr::new(192, 0, 2, 1)));

    let reloaded: crate::config::PipelineConfig =
        serde_json::from_value(settings_only(&new.address)).unwrap();
    engine.reload(RuntimePipelineConfig::from_config(reloaded).unwrap());
    let after = ask(&engine, &query("name.test."), peer()).await;
    assert_eq!(
        first_a(&after),
        Some(Ipv4Addr::new(192, 0, 2, 2)),
        "asked of the new upstream"
    );
    assert_eq!(new.queries(), 1);
}
