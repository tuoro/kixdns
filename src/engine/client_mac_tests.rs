//! client_mac：照本机邻居表里客户端地址对应的 MAC 认客户端。这里换上一张假的表（见 `Engine::with_neighbors`），完整路径
//! 和像监听器那样先走快速路径的都问
//! client_mac: a client known by the MAC the host's neighbor table gives for its address. A fake
//! table is put in place here (see `Engine::with_neighbors`), and both the full path and the fast
//! path first, as a listener asks, are asked

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use serde_json::{Value, json};

use crate::engine::Engine;
use crate::engine::test_support::{self as support, answering_upstream, engine_from, first_a};
use crate::matcher::{Requester, RuntimePipelineConfig};
use crate::neighbor::{Mac, NeighborTable, Neighbors};

/// 不受拦截的那台设备 / The device kept out of blocking
const DEVICE: &str = "aa:bb:cc:dd:ee:ff";
/// 同一个局域网上的另一台设备 / Another device on the same LAN
const OTHER_DEVICE: &str = "02:00:00:00:00:20";
/// 规则命中时的应答 / The answer when the rule matches
const MATCHED: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 50);
/// 其余请求的应答 / The answer to everything else
const OTHER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 60);
/// 拦截时的应答 / The answer when blocking
const BLOCKED: Ipv4Addr = Ipv4Addr::UNSPECIFIED;

fn mac(written: &str) -> Mac {
    Mac::parse(written).expect("a MAC")
}

/// 假的邻居表：DEVICE 在 192.168.1.10 和 fd00::10，OTHER_DEVICE 在 192.168.1.20 和 fd00::20，一份一小时才旧；`reads`
/// 数着读了几次
/// The fake neighbor table: DEVICE at 192.168.1.10 and fd00::10, OTHER_DEVICE at 192.168.1.20
/// and fd00::20, a copy growing old in an hour; `reads` counts how often it is read
fn table(reads: Arc<AtomicUsize>) -> NeighborTable {
    let neighbors = Neighbors::from_iter([
        (IpAddr::from([192, 168, 1, 10]), mac(DEVICE)),
        (IpAddr::from_str("fd00::10").unwrap(), mac(DEVICE)),
        (IpAddr::from([192, 168, 1, 20]), mac(OTHER_DEVICE)),
        (IpAddr::from_str("fd00::20").unwrap(), mac(OTHER_DEVICE)),
    ]);
    NeighborTable::reading(
        move || {
            reads.fetch_add(1, Ordering::SeqCst);
            neighbors.clone()
        },
        Duration::from_secs(3600),
    )
}

/// 照 `config` 建、认得假表上的设备的引擎 / An engine built from `config`, knowing the devices of
/// the fake table
fn engine(config: Value) -> Engine {
    engine_from(config).with_neighbors(table(Arc::default()))
}

/// `matchers` 都成立时静态应答 `address` 的规则 / A rule answering `address` statically when
/// all its `matchers` hold
fn answering(name: &str, matchers: Value, address: Ipv4Addr) -> Value {
    json!({
        "name": name,
        "matchers": matchers,
        "actions": [{ "type": "static_ip_response", "ip": address.to_string() }]
    })
}

fn any() -> Value {
    json!([{ "type": "any" }])
}

fn query(name: &str) -> Vec<u8> {
    let mut request = Message::new(0x4d41, MessageType::Query, OpCode::Query);
    request.metadata.recursion_desired = true;
    request.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
    request.to_vec().unwrap()
}

/// `client` 问 `name` 的 A 记录得到的地址：先走完整路径，再像监听器那样先走快速路径
/// The address `client` gets asking for the A record of `name`: over the full path first, then
/// over the fast path first as a listener asks
async fn answers(engine: &Engine, name: &str, client: &str) -> [Option<Ipv4Addr>; 2] {
    let (packet, peer) = (query(name), SocketAddr::new(client.parse().unwrap(), 53000));
    let full = first_a(&support::ask(engine, &packet, peer).await);
    let fast = support::ask_fast_path_first(engine, &packet, peer)
        .await
        .expect("a query the fast path can read");
    [full, first_a(&fast)]
}

/// 邻居表里地址对应的是这台设备时命中：IPv4、IPv6 地址都一样，双栈套接字上 IPv4 映射形式的地址按它背后的 IPv4 地址查；
/// 另一台设备、表里没有的地址和回环地址不命中。配置里的 MAC 写成大写加 `-` 也一样。设备先问，它的决定进了规则缓存，后面的
/// 客户端照样各按自己的判定
/// It matches when the table maps the address to this device: IPv4 and IPv6 addresses alike,
/// an IPv4-mapped address on a dual-stack socket looked up by the IPv4 address it carries;
/// another device, an address not in the table and loopback do not match. The MAC written in
/// capitals with `-` in the configuration is the same. The device asks first, its decision
/// going into the rule cache, and the clients after it still go by their own judgement
#[tokio::test]
async fn client_mac_knows_a_device_by_its_address_in_the_neighbor_table() {
    let engine = engine(json!({
        "settings": { "default_upstream": "127.0.0.1:9" },
        "pipelines": [{ "id": "main", "rules": [
            answering("device", json!([{ "type": "client_mac", "mac": "AA-BB-CC-DD-EE-FF" }]), MATCHED),
            answering("rest", any(), OTHER)
        ]}]
    }));
    for (client, expected) in [
        ("192.168.1.10", MATCHED),
        ("fd00::10", MATCHED),
        ("::ffff:192.168.1.10", MATCHED),
        ("192.168.1.20", OTHER),
        ("fd00::20", OTHER),
        ("192.168.1.30", OTHER),
        ("127.0.0.1", OTHER),
    ] {
        assert_eq!(
            answers(&engine, "example.com", client).await,
            [Some(expected); 2],
            "{client}"
        );
    }
}

/// pipeline_select 里 `and_not client_mac`：这台设备不进拦截的 pipeline，落到第一个 pipeline；另一台设备和表里没有的
/// 地址照常拦截
/// `and_not client_mac` in pipeline_select: this device does not go to the blocking pipeline and
/// falls to the first one; another device and an address not in the table are blocked as usual
#[tokio::test]
async fn and_not_client_mac_in_pipeline_select_sends_two_clients_different_ways() {
    let engine = engine(json!({
        "settings": { "default_upstream": "127.0.0.1:9" },
        "pipeline_select": [{ "pipeline": "blocking", "matchers": [
            { "type": "any" },
            { "type": "client_mac", "mac": DEVICE, "operator": "and_not" }
        ] }],
        "pipelines": [
            { "id": "plain", "rules": [answering("rest", any(), OTHER)] },
            { "id": "blocking", "rules": [
                answering("ads", json!([{ "type": "domain_suffix", "value": "ads.example" }]), BLOCKED),
                answering("rest", any(), OTHER)
            ] }
        ]
    }));
    for (client, expected) in [
        ("192.168.1.10", OTHER),
        ("fd00::10", OTHER),
        ("192.168.1.20", BLOCKED),
        ("192.168.1.30", BLOCKED),
    ] {
        assert_eq!(
            answers(&engine, "ads.example", client).await,
            [Some(expected); 2],
            "{client}"
        );
    }
}

/// 拦截规则加上 `and_not client_mac`：这台设备的查询转发、缓存起来，另一台设备和表里没有的地址照样拦截，拿不到它缓存的
/// 应答；这台设备换成 IPv6 地址来问，判定一样，用的还是那一份缓存
/// A blocking rule with `and_not client_mac`: this device's query is forwarded and cached, while
/// another device and an address not in the table are still blocked, never handed its cached
/// answer; the device asking from its IPv6 address is judged alike and takes that cached answer
#[tokio::test]
async fn clients_judged_apart_by_their_mac_share_no_cached_answer() {
    let answer = Ipv4Addr::new(192, 0, 2, 1);
    let upstream = answering_upstream(answer, 300).await;
    let engine = engine(json!({
        "settings": { "default_upstream": "127.0.0.1:9" },
        "pipelines": [{ "id": "main", "rules": [
            answering("ads", json!([
                { "type": "domain_suffix", "value": "ads.example" },
                { "type": "client_mac", "mac": DEVICE, "operator": "and_not" }
            ]), BLOCKED),
            {
                "name": "rest",
                "matchers": any(),
                "actions": [{ "type": "forward", "upstream": upstream.address }]
            }
        ]}]
    }));
    assert_eq!(
        answers(&engine, "ads.example", "192.168.1.10").await,
        [Some(answer); 2]
    );
    assert_eq!(upstream.queries(), 1, "the second ask is a cache hit");
    for client in ["192.168.1.20", "fd00::20", "192.168.1.30"] {
        assert_eq!(
            answers(&engine, "ads.example", client).await,
            [Some(BLOCKED); 2],
            "{client}"
        );
    }
    assert_eq!(
        answers(&engine, "ads.example", "fd00::10").await,
        [Some(answer); 2]
    );
    assert_eq!(
        upstream.queries(),
        1,
        "the device's IPv6 address shares the entry"
    );
}

/// 请求方的键按 client_mac 的判定分：判定不同的分开，判定相同的（同一台设备的两个地址，或者两个都不是这台设备的客户端）
/// 共用，规则缓存的键也一样
/// Requester keys go by the client_mac judgement: requesters judged differently are kept apart,
/// those judged alike (two addresses of one device, or two clients neither of which is this
/// device) share, and so do rule cache keys
#[test]
fn requester_keys_keep_clients_with_different_macs_apart() {
    let config = serde_json::from_value(json!({
        "settings": { "default_upstream": "127.0.0.1:9" },
        "pipelines": [{ "id": "main", "rules": [
            answering("device", json!([{ "type": "client_mac", "mac": DEVICE }]), MATCHED)
        ]}]
    }))
    .unwrap();
    let runtime = RuntimePipelineConfig::from_config(config).unwrap();
    assert!(runtime.reads_client_mac);
    let pipeline = runtime.pipeline("main").unwrap();
    let geoip = crate::matcher::geoip::GeoIpManager::default();
    for scope in [&pipeline.requester, &pipeline.rule_requester] {
        let key = |address: &str, written: Option<&str>| {
            let requester = Requester {
                address: address.parse().unwrap(),
                mac: written.map(mac),
                edns: false,
                ecs: None,
            };
            scope.key(requester, &geoip)
        };
        let device = key("192.168.1.10", Some(DEVICE));
        assert_ne!(device, key("192.168.1.20", Some(OTHER_DEVICE)));
        assert_ne!(device, key("192.168.1.30", None));
        assert_eq!(device, key("fd00::10", Some(DEVICE)));
        assert_eq!(
            key("192.168.1.20", Some(OTHER_DEVICE)),
            key("192.168.1.30", None)
        );
    }
}

/// 没写 client_mac 的配置一次邻居表也不读；写了的读一次，一份没旧之前不再读
/// A configuration without client_mac never reads the neighbor table; one with it reads it
/// once, and not again before the copy grows old
#[tokio::test]
async fn the_table_is_read_only_for_a_configuration_writing_client_mac() {
    let config = |matcher: Value| {
        json!({
            "settings": { "default_upstream": "127.0.0.1:9" },
            "pipelines": [{ "id": "main", "rules": [
                answering("one", json!([matcher]), MATCHED),
                answering("rest", any(), OTHER)
            ]}]
        })
    };
    let reads = Arc::new(AtomicUsize::new(0));
    let without = engine_from(config(
        json!({ "type": "client_ip", "cidr": "192.168.1.0/24" }),
    ))
    .with_neighbors(table(Arc::clone(&reads)));
    assert!(!without.state.load().pipeline.reads_client_mac);
    assert_eq!(
        answers(&without, "example.com", "192.168.1.10").await,
        [Some(MATCHED); 2]
    );
    assert_eq!(reads.load(Ordering::SeqCst), 0);

    let with = engine_from(config(json!({ "type": "client_mac", "mac": DEVICE })))
        .with_neighbors(table(Arc::clone(&reads)));
    for client in ["192.168.1.10", "192.168.1.20", "fd00::99"] {
        answers(&with, "example.com", client).await;
    }
    assert_eq!(reads.load(Ordering::SeqCst), 1);
}
