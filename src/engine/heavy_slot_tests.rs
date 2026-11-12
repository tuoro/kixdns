//! 一个名字在几十个网段各有一份大应答时，缓存里它那个槽位会比一个分片还重。槽位自己先淘汰一些，不让整个槽位被
//! 缓存扔掉（见 `CacheSlot::fitting`）。
//! With a large answer for each of dozens of networks under one name, its slot in the cache
//! outweighs a shard. The slot sheds some answers itself, so that the cache does not throw the
//! whole slot away (see `CacheSlot::fitting`).

use std::sync::Arc;

use bytes::Bytes;
use hickory_proto::op::ResponseCode;
use serde_json::json;

use crate::cache::CacheEntry;
use crate::ecs::subnet;
use crate::ecs_scope::{EcsReach, EcsSource, ForwardEcs, ReplyEcs, Sent};
use crate::engine::test_support::{counting_settings, engine_from};
use crate::proto_utils::QueryFlags;

/// 一份 3 KB 的应答，适用于 `reach` / An answer of 3 KB applying to `reach`
fn large(reach: EcsReach) -> Arc<CacheEntry> {
    Arc::new(
        CacheEntry::from_response(
            Bytes::from(vec![0u8; 3 * 1024]),
            ResponseCode::NoError,
            Some(Arc::from("udp:192.0.2.53:53")),
            "name.test",
            Arc::from("main"),
            1,
            QueryFlags::RECURSIVE,
            (300, 300),
        )
        .with_reach(reach),
    )
}

/// 透传的 /24 子网、应答的作用范围也是 24 / A passed-through /24 whose reply has scope 24
fn for_network(network: u8) -> EcsReach {
    let client = subnet(&format!("198.51.{network}.0/24"));
    let mut reach = EcsReach::default();
    reach.record(
        ForwardEcs {
            source: EcsSource::Client,
            sent: Sent::Subnet(client),
        },
        ReplyEcs::Subnet {
            subnet: client,
            scope: 24,
        },
        true,
    );
    reach
}

/// 容量 64 的缓存只有一个分片。大家共用的那份应答先存进去，再来 30 个网段各一份 3 KB 的：槽位到 64 为止，先淘汰早存的
/// 网段，共用的那份一直在。以前槽位一超过分片就整个被扔掉，共用的那份跟着没了，这个名字缓存不住
/// A cache of capacity 64 has one shard. With the answer everyone shares stored first and then
/// one of 3 KB for each of 30 networks, the slot stays within 64 by shedding the networks stored
/// earliest, the shared answer staying throughout. A slot over the shard used to be thrown away
/// whole, the shared answer with it, and the name never stayed cached
#[tokio::test]
async fn a_name_with_large_answers_for_many_networks_stays_cached() {
    let engine = engine_from(json!({
        "settings": counting_settings(json!({ "cache_capacity": 64 })),
        "pipelines": []
    }));
    let slot = 7;
    let shared = large(EcsReach::default());
    engine.cache_insert(slot, Arc::clone(&shared));
    for network in 0..30 {
        engine.cache_insert(slot, large(for_network(network)));
        let held = engine.cached_entries(slot);
        assert!(
            held.iter().any(|entry| Arc::ptr_eq(entry, &shared)),
            "the shared answer is gone after network {network}"
        );
        let weight: usize = held
            .iter()
            .map(|entry| entry.bytes.len().div_ceil(1024))
            .sum();
        assert!(weight <= 64, "the slot weighs {weight}");
    }
    assert_eq!(engine.cached_entries(slot).len(), 21, "64 / 3 answers");
}
