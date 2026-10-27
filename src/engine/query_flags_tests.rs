//! 问题之外，RD、CD、DO 三个查询位也决定应答（见 `proto_utils::QueryFlags`）：缓存、合并
//! 在途查询和后台刷新都按它们把请求分开。
//! Besides the question, the RD, CD and DO query bits decide the answer (see
//! `proto_utils::QueryFlags`): the cache, the merging of inflight queries and the
//! background refresh keep requests apart by them.

use std::net::Ipv4Addr;
use std::str::FromStr;
use std::time::Duration;

use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;

use crate::engine::Engine;
use crate::engine::test_support::{
    self as support, Upstream, counting_settings, engine_from, first_a, peer,
};
use crate::matcher::RequesterKey;
use crate::proto_utils::QueryFlags;

/// 三个查询位的全部八种组合 / All eight combinations of the three query bits
fn every_flags() -> Vec<QueryFlags> {
    let mut all = Vec::new();
    for recursion_desired in [true, false] {
        for checking_disabled in [false, true] {
            for dnssec_ok in [false, true] {
                all.push(QueryFlags::new(
                    recursion_desired,
                    checking_disabled,
                    dnssec_ok,
                ));
            }
        }
    }
    all
}

fn sorted(mut flags: Vec<QueryFlags>) -> Vec<QueryFlags> {
    flags.sort_by_key(|flags| flags.bits());
    flags
}

/// 假上游对带着 `flags` 的查询给的地址 / The address the fake upstream gives a query with `flags`
fn address_for(flags: QueryFlags) -> Ipv4Addr {
    Ipv4Addr::new(192, 0, 2, 10 + flags.bits())
}

/// 查询带来的查询位 / The query bits a query carries
fn flags_of(query: &Message) -> QueryFlags {
    QueryFlags::new(
        query.metadata.recursion_desired,
        query.metadata.checking_disabled,
        query
            .edns
            .as_ref()
            .is_some_and(|edns| edns.flags().dnssec_ok),
    )
}

/// 上游收到的每个查询带来的查询位 / The query bits each query the upstream received carried
fn seen(up: &Upstream) -> Vec<QueryFlags> {
    up.received().iter().map(flags_of).collect()
}

/// 按查询位作答的本机上游：应答的地址是 [`address_for`] 查询位，TTL 为 `ttl`，每个应答晚
/// `delay` 发出；RD、CD 和 DO 照抄查询的，和真正的上游一样。
/// A local upstream answering by the query bits: the address is [`address_for`]
/// them, at TTL `ttl`, every reply `delay` late; RD, CD and DO are copied from the
/// query, as a real upstream does.
async fn upstream(ttl: u32, delay: Duration) -> Upstream {
    support::upstream(move |query| {
        let Some(question) = query.queries.first() else {
            return Vec::new();
        };
        let flags = flags_of(query);
        let mut resp = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
        resp.metadata.recursion_desired = flags.recursion_desired();
        resp.metadata.checking_disabled = flags.checking_disabled();
        resp.metadata.recursion_available = true;
        resp.add_query(question.clone());
        resp.add_answer(Record::from_rdata(
            question.name().clone(),
            ttl,
            RData::A(A(address_for(flags))),
        ));
        if query.edns.is_some() {
            let mut edns = Edns::new();
            edns.set_max_payload(1232);
            edns.set_dnssec_ok(flags.dnssec_ok());
            resp.edns = Some(edns);
        }
        vec![(delay, resp.to_vec().unwrap())]
    })
    .await
}

/// 把所有请求转发给 `upstream` 的引擎，再加上 `settings` / An engine forwarding everything
/// to `upstream`, with `settings` on top
fn engine(upstream: &str, settings: serde_json::Value) -> Engine {
    engine_from(serde_json::json!({
        "settings": counting_settings(settings),
        "pipeline_select": [],
        "pipelines": [{ "id": "main", "rules": [{
            "name": "all", "matchers": [{ "type": "any" }],
            "actions": [{ "type": "forward", "upstream": upstream }]
        }] }]
    }))
}

/// 带着 `flags` 查询 example.com A，都带 EDNS，所以 DO 是唯一可能的不同
/// A query for example.com A with `flags`, always with EDNS, so DO is the only
/// thing that can differ there
fn query(flags: QueryFlags) -> Vec<u8> {
    let mut request = Message::new(0x5157, MessageType::Query, OpCode::Query);
    request.metadata.recursion_desired = flags.recursion_desired();
    request.metadata.checking_disabled = flags.checking_disabled();
    request.add_query(Query::query(
        Name::from_str("example.com.").unwrap(),
        RecordType::A,
    ));
    let mut edns = Edns::new();
    edns.set_max_payload(1232);
    edns.set_dnssec_ok(flags.dnssec_ok());
    request.edns = Some(edns);
    request.to_vec().unwrap()
}

/// 像监听器那样问（见 [`support::ask_fast_path_first`]）；返回应答里的地址
/// Ask as a listener does (see [`support::ask_fast_path_first`]); the address in the reply
async fn ask_like_a_listener(engine: &Engine, flags: QueryFlags) -> Option<Ipv4Addr> {
    let reply = support::ask_fast_path_first(engine, &query(flags), peer())
        .await
        .expect("a query the fast path can read");
    first_a(&reply)
}

/// 每种查询位各拿各的应答；同样的查询位再问一次由缓存作答，不再问上游
/// Each set of query bits gets its own answer; asking again with the same bits is
/// answered from the cache without asking the upstream
#[tokio::test]
async fn each_set_of_query_bits_gets_its_own_answer() {
    let up = upstream(300, Duration::ZERO).await;
    let engine = engine(&up.address, serde_json::json!({}));
    for round in 0..2 {
        for flags in every_flags() {
            assert_eq!(
                ask_like_a_listener(&engine, flags).await,
                Some(address_for(flags)),
                "round {round}, {flags:?}"
            );
        }
    }
    // The upstream was asked once per set of bits, with those bits
    // 上游对每种查询位只被问了一次，问的时候带着那几位
    assert_eq!(up.queries(), 8);
    assert_eq!(sorted(seen(&up)), sorted(every_flags()));
}

/// 只差 DO 位的两个查询同时到达，各问各的上游，不合并
/// Two queries at once that differ only in the DO bit each ask the upstream: they
/// are not merged
#[tokio::test]
async fn queries_differing_only_in_do_are_not_merged() {
    // Late replies, so the second query arrives while the first is in flight
    // 应答来得晚，第二个查询到达时第一个还在途中
    let up = upstream(300, Duration::from_millis(200)).await;
    let engine = engine(&up.address, serde_json::json!({}));
    let plain = QueryFlags::RECURSIVE;
    let dnssec = QueryFlags::new(true, false, true);
    let (plain_query, dnssec_query) = (query(plain), query(dnssec));
    let (one, two) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            engine.handle_packet(&plain_query, peer()),
            engine.handle_packet(&dnssec_query, peer()),
        )
    })
    .await
    .expect("answers in time");
    assert_eq!(
        [
            first_a(&one.expect("answer")),
            first_a(&two.expect("answer"))
        ],
        [Some(address_for(plain)), Some(address_for(dnssec))]
    );
    assert_eq!(up.queries(), 2);
}

/// 后台刷新带着条目的查询位重放请求，刷新回来的应答仍然只给同样查询位的请求
/// A background refresh replays the request with its entry's query bits, and the
/// refreshed answer still goes only to requests with the same bits
#[tokio::test]
async fn a_background_refresh_asks_with_the_entrys_query_bits() {
    let up = upstream(10, Duration::ZERO).await;
    let engine = engine(
        &up.address,
        serde_json::json!({
            "cache_background_refresh": true,
            "cache_refresh_threshold_percent": 95,
            "cache_refresh_min_ttl": 0
        }),
    );
    for flags in every_flags() {
        ask_like_a_listener(&engine, flags).await;
    }
    // A second on, every entry is due for a refresh (9 of 10 seconds left)
    // 一秒之后每条都到了刷新时机（10 秒还剩 9 秒）
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let refreshes_started = std::time::Instant::now();
    // Hits that start a refresh of each entry / 每次命中各自发起一次刷新
    for flags in every_flags() {
        assert_eq!(
            ask_like_a_listener(&engine, flags).await,
            Some(address_for(flags)),
            "{flags:?}"
        );
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        while up.queries() < 16 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("every refresh reaches the upstream");
    assert_eq!(sorted(seen(&up)[8..].to_vec()), sorted(every_flags()));
    // Each refreshed answer replaced the entry for its own bits
    // 每份刷新回来的应答都换下了它那几位的条目
    let namespace = engine.state.load().cache_namespace("main");
    for flags in every_flags() {
        let slot = Engine::cache_slot(
            namespace,
            "main",
            b"example.com",
            RecordType::A,
            DNSClass::IN,
            flags,
            &RequesterKey::NONE,
        );
        tokio::time::timeout(Duration::from_secs(5), async {
            while !engine
                .cached_entries(slot)
                .iter()
                .any(|entry| entry.fetched_at > refreshes_started)
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the refreshed answer is cached");
        let entries = engine.cached_entries(slot);
        assert_eq!(entries.len(), 1, "{flags:?}");
        assert_eq!(entries[0].flags, flags);
        assert_eq!(first_a(&entries[0].bytes), Some(address_for(flags)));
    }
}

/// 重放的请求带着给它的查询位；DO 只能放在 EDNS 里，所以 DO 置位时总带 EDNS
/// A replayed request carries the query bits it is given; DO only travels inside
/// EDNS, so a set DO always brings EDNS
#[tokio::test]
async fn a_refresh_packet_carries_the_given_query_bits() {
    let engine = engine("127.0.0.1:9", serde_json::json!({}));
    for flags in every_flags() {
        for edns in [false, true] {
            let packet = engine
                .construct_dns_packet(
                    "example.com",
                    RecordType::A,
                    DNSClass::IN,
                    edns,
                    None,
                    flags,
                )
                .expect("refresh packet");
            let request = Message::from_bytes(&packet).expect("parse refresh packet");
            let case = format!("{flags:?}, edns {edns}");
            assert_eq!(QueryFlags::of(&packet), flags, "{case}");
            assert_eq!(
                request.metadata.recursion_desired,
                flags.recursion_desired(),
                "{case}"
            );
            assert_eq!(
                request.metadata.checking_disabled,
                flags.checking_disabled(),
                "{case}"
            );
            assert_eq!(
                request.edns.as_ref().map(|edns| edns.flags().dnssec_ok),
                (edns || flags.dnssec_ok()).then_some(flags.dnssec_ok()),
                "{case}"
            );
        }
    }
}

/// 查询位不同，槽位和 inflight 键都不同；快速路径算的槽位和 `cache_keys` 的一样
/// Other query bits give another slot and inflight key; the slot the fast path
/// computes is the one `cache_keys` gives
#[test]
fn the_keys_carry_the_query_bits() {
    let keys = |flags| {
        Engine::cache_keys(
            0,
            "main",
            b"example.com",
            RecordType::A,
            DNSClass::IN,
            flags,
            &RequesterKey::NONE,
            None,
        )
    };
    let all = every_flags();
    for (index, flags) in all.iter().enumerate() {
        assert_eq!(keys(*flags).flags, *flags);
        assert_eq!(
            Engine::cache_slot(
                0,
                "main",
                b"example.com",
                RecordType::A,
                DNSClass::IN,
                *flags,
                &RequesterKey::NONE,
            ),
            keys(*flags).slot
        );
        for other in &all[index + 1..] {
            assert_ne!(keys(*flags).slot, keys(*other).slot, "{flags:?} {other:?}");
            assert_ne!(
                keys(*flags).inflight,
                keys(*other).inflight,
                "{flags:?} {other:?}"
            );
        }
    }
}
