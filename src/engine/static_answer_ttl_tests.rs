//! 回答检查以后缓存的应答不比这一路上回答检查据过的上游应答的 TTL（收进 min_ttl 到 cache_max_ttl 之间）留得久，交出去的
//! 记录也不比它长（见 `Route::answer_ttl`）：回答检查的动作给出的，或者回答检查在上游的应答上 continue、跳转以后给出的，
//! 静态应答和转发拿到的应答都一样。静态应答按它带的 TTL 缓存，即记录里最小的；不带记录的没有自己的 TTL，就按那些应答里最短
//! 的。规则直接给出的不进响应缓存，规则下次照样直接给出；上游失败以后兜底给出的静态应答也不进，那只是那一次请求的，改问备用
//! 上游拿到的回答照常缓存；回答检查看到的失败应答也算上游失败。按「谁在问」给的静态应答照样缓存，槽位按规则对请求方的判定分开。
//! An answer cached after an answer check stays no longer, and carries no record longer, than
//! the TTLs of the upstream answers the checks on the way went by, brought into min_ttl to
//! cache_max_ttl (see `Route::answer_ttl`): given by an answer check's actions, or after an
//! answer check continued or jumped on an upstream's answer, static answers and answers
//! fetched by forwards alike. A static answer is cached for the TTL it carries, the least of
//! its records'; one without records has no TTL of its own and goes by the least of those
//! answers. One the rules give outright stays out of the response cache, the rules giving it
//! again outright; so does a static answer given as a fallback after an upstream failure,
//! which is for that one request, while a backup upstream's answer is cached as usual; a
//! failure reply an answer check sees counts as an upstream failure too. A static answer given
//! by who is asking is cached all the same, its slot kept apart by how the rules judge the
//! requester.

use std::net::Ipv4Addr;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, CNAME, SOA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use serde_json::{Value, json};

use crate::engine::Engine;
use crate::engine::test_support::{
    answering_rcode, answering_upstream, answering_upstream_after, ask, engine_from, first_a, peer,
    upstream,
};

/// 上游的回答 / The upstream's answer
const UPSTREAM_ANSWER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
/// 规则给的地址 / The address the rules give
const STATIC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 5);
/// 回答检查以后转发去问的上游的回答 / The answer of the upstream a forward asks after an answer check
const FORWARDED: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 9);
/// 这里没有监听，转发过去的都失败 / Nothing listens here, so every forward to it fails
const DEAD_UPSTREAM: &str = "127.0.0.1:9";

fn query() -> Vec<u8> {
    let mut query = Message::new(0x5151, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(
        Name::from_ascii("static.test.").unwrap(),
        RecordType::A,
    ));
    query.to_vec().unwrap()
}

fn engine_with(settings: &Value, pipelines: Value) -> Engine {
    let mut all = json!({ "default_upstream": DEAD_UPSTREAM, "upstream_timeout_ms": 200 });
    for (key, value) in settings.as_object().unwrap() {
        all[key] = value.clone();
    }
    engine_from(json!({ "settings": all, "pipelines": pipelines }))
}

fn rule(name: &str, matcher: Value, actions: Value) -> Value {
    json!({ "name": name, "matchers": [matcher], "actions": actions })
}

fn any() -> Value {
    json!({ "type": "any" })
}

/// 转发给 `upstream`，回答检查执行 `on_match`（没有响应匹配器，每份回答都算通过）
/// Forwarding to `upstream`, the answer check running `on_match` (with no response
/// matchers every answer passes)
fn checked(upstream: &str, on_match: Value) -> Value {
    let mut rule = rule(
        "checked",
        any(),
        json!([{ "type": "forward", "upstream": upstream }]),
    );
    rule["response_actions_on_match"] = on_match;
    rule
}

/// 缓存里每份应答的 TTL / The TTL of every answer in the cache
fn cached_ttls(engine: &Engine) -> Vec<u32> {
    engine
        .cache
        .values()
        .iter()
        .flat_map(|slot| slot.entries().map(|entry| entry.original_ttl))
        .collect()
}

/// 应答里每条答案记录的 TTL / The TTL of every answer record in a reply
fn record_ttls(reply: &[u8]) -> Vec<u32> {
    Message::from_bytes(reply)
        .expect("parse reply")
        .answers
        .iter()
        .map(|record| record.ttl)
        .collect()
}

/// 缓存里每份应答的答案记录 TTL / The answer record TTLs of every answer in the cache
fn cached_record_ttls(engine: &Engine) -> Vec<Vec<u32>> {
    engine
        .cache
        .values()
        .iter()
        .flat_map(|slot| slot.entries().map(|entry| record_ttls(&entry.bytes)))
        .collect()
}

/// 带 TTL 120 的静态 CNAME、带 TTL 300 的静态地址、不带记录的 deny，依据不同 TTL 的上游回答、在不同的设置下缓存多久：
/// 回答检查的动作给出的、回答检查 continue 或跳转以后的规则给出的都一样。带记录的取自己的 TTL 和那份回答在缓存里能留的
/// 时间中短的那个，交出去的记录也是这个 TTL；不带记录的就按那份回答的；那份回答不进缓存（TTL 为 0）时据它给的也不缓存，
/// 记录的 TTL 交出去也是 0。以前不看那份回答：静态地址写死的 300 秒比回答的 60 秒长，规则早该给别的了还在用；deny 按
/// min_ttl，默认为 0 时不缓存，防重绑定的 deny 每次都要再问一遍上游。后来条目照那份回答缓存了，记录却照原样交出 300 秒
/// How long a static CNAME with TTL 120, a static address with TTL 300 and a deny with no
/// records are cached, going by upstream answers of various TTLs under various settings:
/// given by an answer check's actions, or by the rules after an answer check continued or
/// jumped, alike. One with records takes the shorter of its own TTL and how long that answer
/// may stay in the cache, its records going out with that TTL too; one without takes that
/// answer's; with that answer kept out of the cache (TTL 0) nothing given by it is cached
/// either, its records going out with a TTL of 0. It used to ignore that answer: the static
/// address's hard-coded 300 seconds outlasted an answer's 60, in use long after the rules
/// would have given something else; a deny went by min_ttl, and with the default 0 was not
/// cached, a deny against rebinding asking the upstream again every time. The entry then went
/// by that answer while the records still went out with their 300 seconds
#[tokio::test]
async fn a_static_answer_on_an_upstream_answer_is_cached_no_longer_than_that_answer() {
    let cname = json!({ "type": "static_cname_response", "target": "target.test.", "ttl": 120 });
    let address = json!({ "type": "static_ip_response", "ip": STATIC.to_string() });
    let deny = json!({ "type": "deny" });
    let cases = [
        (600, &cname, json!({}), Some(120)),
        (600, &cname, json!({ "min_ttl": 600 }), Some(120)),
        (600, &address, json!({}), Some(300)),
        (600, &address, json!({ "cache_max_ttl": 100 }), Some(100)),
        (60, &address, json!({}), Some(60)),
        (0, &address, json!({}), None),
        (600, &deny, json!({}), Some(600)),
        (60, &deny, json!({ "min_ttl": 120 }), Some(120)),
        (0, &deny, json!({}), None),
    ];
    for (answer_ttl, action, settings, cached) in cases {
        let upstream = answering_upstream(UPSTREAM_ANSWER, answer_ttl)
            .await
            .address;
        let paths = [
            (
                "answer check",
                json!([{ "id": "main", "rules": [checked(&upstream, json!([action]))] }]),
            ),
            (
                "after a continue",
                json!([{ "id": "main", "rules": [
                    checked(&upstream, json!([{ "type": "continue" }])),
                    rule("static", any(), json!([action])),
                ]}]),
            ),
            (
                "after a jump",
                json!([
                    { "id": "main", "rules": [checked(
                        &upstream,
                        json!([{ "type": "jump_to_pipeline", "pipeline": "static" }]),
                    )]},
                    { "id": "static", "rules": [rule("static", any(), json!([action]))] },
                ]),
            ),
        ];
        let records = if action == &deny {
            Vec::new()
        } else {
            vec![cached.unwrap_or(0)]
        };
        for (path, pipelines) in paths {
            let engine = engine_with(&settings, pipelines);
            let reply = ask(&engine, &query(), peer()).await;
            let case = format!("{path}: {action} on an answer of TTL {answer_ttl} with {settings}");
            assert_eq!(cached_ttls(&engine), Vec::from_iter(cached), "{case}");
            assert_eq!(record_ttls(&reply), records, "{case}");
        }
    }
}

/// 一路上经过几次回答检查时，此后的静态应答按它们据过的应答里最短的那个缓存，不论那份应答排在前面还是后面：60 秒的应答
/// 到期以后，它的回答检查就可能走另一条路。continue 和回答检查跳转都一样。以前只看最后一次，排在后面的 3600 秒顶掉了前面的
/// 60 秒
/// After several answer checks on the way, a static answer from there on is cached by the
/// least of the answers they went by, whether that answer came first or last: once the
/// answer of 60 seconds expires its check may take another way. A continue and an answer
/// check's jump alike. Only the last used to count, the 3600 seconds coming later taking the
/// place of the 60 before
#[tokio::test]
async fn a_static_answer_after_several_checks_is_cached_by_the_least_answer() {
    let short = answering_upstream(UPSTREAM_ANSWER, 60).await.address;
    let long = answering_upstream(UPSTREAM_ANSWER, 3600).await.address;
    let address = json!({ "type": "static_ip_response", "ip": STATIC.to_string() });
    let deny = json!({ "type": "deny" });
    for (first, second) in [(&short, &long), (&long, &short)] {
        for action in [&address, &deny] {
            let paths = [
                (
                    "two continues",
                    json!([{ "id": "main", "rules": [
                        checked(first, json!([{ "type": "continue" }])),
                        checked(second, json!([{ "type": "continue" }])),
                        rule("static", any(), json!([action])),
                    ]}]),
                ),
                (
                    "a continue, then a jump",
                    json!([
                        { "id": "main", "rules": [
                            checked(first, json!([{ "type": "continue" }])),
                            checked(
                                second,
                                json!([{ "type": "jump_to_pipeline", "pipeline": "static" }]),
                            ),
                        ]},
                        { "id": "static", "rules": [rule("static", any(), json!([action]))] },
                    ]),
                ),
                (
                    "a continue, then the check's own action",
                    json!([{ "id": "main", "rules": [
                        checked(first, json!([{ "type": "continue" }])),
                        checked(second, json!([action])),
                    ]}]),
                ),
            ];
            for (path, pipelines) in paths {
                let engine = engine_with(&json!({}), pipelines);
                ask(&engine, &query(), peer()).await;
                assert_eq!(
                    cached_ttls(&engine),
                    [60],
                    "{path}: {action} after answers from {first} and then {second}"
                );
            }
        }
    }
}

/// 回答检查以后转发拿到的应答按它自己的 TTL 缓存，但不比回答检查据的那份上游应答留得久：回答检查的动作转发的、continue
/// 以后的规则转发的、跳转以后的规则转发的都一样。那份应答到期了，回答检查就可能走另一条路，不再去问这个上游
/// An answer a forward fetches after an answer check is cached for its own TTL, yet no longer
/// than the upstream answer the check went by: forwarded by the check's actions, by a rule after
/// its continue or by a rule after its jump alike. Once that answer expires the check may take
/// another way, asking this upstream no more
#[tokio::test]
async fn an_answer_forwarded_after_a_check_is_cached_no_longer_than_the_checked_answer() {
    for (checked_ttl, forwarded_ttl) in [(60, 3600), (3600, 60)] {
        let first = answering_upstream(UPSTREAM_ANSWER, checked_ttl)
            .await
            .address;
        let then = answering_upstream(FORWARDED, forwarded_ttl).await.address;
        let forward = json!([{ "type": "forward", "upstream": then }]);
        let paths = [
            (
                "the check's own forward",
                json!([{ "id": "main", "rules": [checked(&first, forward.clone())] }]),
            ),
            (
                "a rule after a continue",
                json!([{ "id": "main", "rules": [
                    checked(&first, json!([{ "type": "continue" }])),
                    rule("forward", any(), forward.clone()),
                ]}]),
            ),
            (
                "a pipeline jumped to",
                json!([
                    { "id": "main", "rules": [checked(
                        &first,
                        json!([{ "type": "jump_to_pipeline", "pipeline": "then" }]),
                    )]},
                    { "id": "then", "rules": [rule("forward", any(), forward.clone())] },
                ]),
            ),
        ];
        for (path, pipelines) in paths {
            let engine = engine_with(&json!({}), pipelines);
            assert_eq!(
                first_a(&ask(&engine, &query(), peer()).await),
                Some(FORWARDED),
                "{path}"
            );
            assert_eq!(
                cached_ttls(&engine),
                [60],
                "{path}: an answer of TTL {forwarded_ttl} after a check on one of {checked_ttl}"
            );
        }
    }
}

/// 回答检查以后交出去的应答，每条记录的 TTL 都不比回答检查据的那份上游回答的 TTL 长（记录里最短的那个比它短时也一样，见
/// `every_record_after_a_check_goes_out_no_longer_than_the_checked_answer`）：客户端、同时等着它的请求拿到的，和缓存里
/// 存的、之后命中缓存交出的是同一份，客户端留它的时间和缓存一样长。回答检查的动作转发的、continue 以后的规则转发的、跳去的
/// pipeline 转发的、规则给的静态应答都一样。以前只封了条目的 TTL，记录照原样交出：据 60 秒的回答转发拿到 3600 秒的，客户端
/// 和等待者拿 3600，命中缓存交出 3599，条目却 60 秒就过期
/// An answer going out after an answer check carries no record TTL longer than the TTL of the
/// upstream answer the check went by (nor when the least of its records is shorter, see
/// `every_record_after_a_check_goes_out_no_longer_than_the_checked_answer`): the client and
/// the requests waiting on it get the copy the cache keeps and later serves, the client keeping
/// it as long as the cache does. Forwarded by the check's actions, by a rule after its continue
/// or by the pipeline it jumps to, or a static answer of the rules, alike. Only the entry's TTL
/// used to be bounded and the records went out as they were: forwarding to an answer of 3600
/// seconds on one of 60, the client and the waiters got 3600 and a cache hit 3599, while the
/// entry expired at 60
#[tokio::test]
async fn an_answer_after_a_check_goes_out_with_ttls_no_longer_than_the_checked_answer() {
    // 回答晚一点到，同时问的第二个请求等在第一个登记的条目上 / The answer comes a little late, so the
    // second request asking at the same time waits on the entry the first registered
    let checked_upstream =
        answering_upstream_after(UPSTREAM_ANSWER, 60, Duration::from_millis(100)).await;
    let checked_at = &checked_upstream.address;
    let then = answering_upstream(FORWARDED, 3600).await.address;
    let forward = json!([{ "type": "forward", "upstream": then }]);
    let address = json!([{ "type": "static_ip_response", "ip": STATIC.to_string() }]);
    let paths = [
        (
            "the check's own forward",
            json!([{ "id": "main", "rules": [checked(checked_at, forward.clone())] }]),
            FORWARDED,
        ),
        (
            "a rule after a continue",
            json!([{ "id": "main", "rules": [
                checked(checked_at, json!([{ "type": "continue" }])),
                rule("forward", any(), forward.clone()),
            ]}]),
            FORWARDED,
        ),
        (
            "a pipeline jumped to",
            json!([
                { "id": "main", "rules": [checked(
                    checked_at,
                    json!([{ "type": "jump_to_pipeline", "pipeline": "then" }]),
                )]},
                { "id": "then", "rules": [rule("forward", any(), forward.clone())] },
            ]),
            FORWARDED,
        ),
        (
            "a static answer after a continue",
            json!([{ "id": "main", "rules": [
                checked(checked_at, json!([{ "type": "continue" }])),
                rule("static", any(), address.clone()),
            ]}]),
            STATIC,
        ),
    ];
    for (path, pipelines, answer) in paths {
        // UDP 过了预算的三分之一再发一次（`upstream::hedge_timeout`）：预算留够，晚到的回答之前不重发
        // UDP sends again past a third of the budget (`upstream::hedge_timeout`): with budget to
        // spare, nothing is sent again before the late answer
        let engine = engine_with(&json!({ "upstream_timeout_ms": 3000 }), pipelines);
        let asked_before = checked_upstream.queries();
        let packet = query();
        let (one, two) = tokio::join!(ask(&engine, &packet, peer()), ask(&engine, &packet, peer()));
        assert_eq!(
            checked_upstream.queries(),
            asked_before + 1,
            "{path}: the second request waited on the first"
        );
        for reply in [&one, &two] {
            assert_eq!(first_a(reply), Some(answer), "{path}");
            assert_eq!(record_ttls(reply), [60], "{path}");
        }
        assert_eq!(cached_record_ttls(&engine), [[60]], "{path}");
        let hit = ask(&engine, &query(), peer()).await;
        assert!(
            record_ttls(&hit).iter().all(|&ttl| ttl <= 60),
            "{path}: {:?} from the cache",
            record_ttls(&hit)
        );
    }
}

/// 回答检查据的是否定应答时，此后的应答照那份应答的 TTL 封顶，那个 TTL 和每条记录的一样收进 min_ttl 到 cache_max_ttl
/// 之间：负缓存 TTL 出自 SOA 的 minimum（在 RDATA 里，上游把关时不改写）比 min_ttl 短，min_ttl 照样抬它，那份否定应答
/// 自己就在缓存里留 min_ttl 这么久，据它做的决定也一样；没有 SOA 的否定应答没有可依据的 TTL，自己不进缓存（RFC 2308 第
/// 4 节），据它做的决定也照 min_ttl 算。此后交出去的记录都不封到 min_ttl 以下。min_ttl 为 0 时没有 SOA 的那份 TTL 就是
/// 0，此后的应答不缓存，记录交出去也是 0。以前没有 SOA 的一律按 0 算，开着 min_ttl 也把后面的记录压到 0、不缓存
/// After an answer check on a negative answer, what answers next is bounded by that answer's
/// TTL, brought into min_ttl to cache_max_ttl as every record's is: its negative TTL comes
/// from the SOA's minimum (in the RDATA, which the upstream guards leave as it is) and is
/// shorter than min_ttl, which raises it all the same, so the negative answer itself stays in
/// the cache for min_ttl and so does a decision taken on it; a negative answer without SOA has
/// no TTL to go by and stays out of the cache itself (RFC 2308 section 4), a decision taken on
/// it going by min_ttl all the same. No record going out after it is brought below min_ttl.
/// With min_ttl 0 the one without SOA has a TTL of 0, nothing after it is cached and its
/// records go out with 0. One without SOA used to count as 0 whatever min_ttl, the records
/// after it brought down to 0 and left uncached with min_ttl on
#[tokio::test]
async fn an_answer_after_a_check_on_a_negative_answer_keeps_min_ttl() {
    let then = answering_upstream(FORWARDED, 3600).await.address;
    for (soa, min_ttl, carried) in [(true, 60, 60), (false, 60, 60), (false, 0, 0)] {
        let negative = upstream(move |query| {
            let mut reply = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
            reply.metadata.recursion_desired = query.metadata.recursion_desired;
            reply.metadata.response_code = ResponseCode::NXDomain;
            reply.add_queries(query.queries.iter().cloned());
            if soa {
                let zone = Name::from_ascii("test.").unwrap();
                reply.add_authority(Record::from_rdata(
                    zone.clone(),
                    300,
                    RData::SOA(SOA::new(zone.clone(), zone, 1, 3600, 900, 1_209_600, 5)),
                ));
            }
            vec![(Duration::ZERO, reply.to_vec().unwrap())]
        })
        .await
        .address;
        let engine = engine_with(
            &json!({ "min_ttl": min_ttl }),
            json!([{ "id": "main", "rules": [
                checked(&negative, json!([{ "type": "continue" }])),
                rule("forward", any(), json!([{ "type": "forward", "upstream": then }])),
            ]}]),
        );
        let reply = ask(&engine, &query(), peer()).await;
        let case = format!("SOA {soa}, min_ttl {min_ttl}");
        assert_eq!(first_a(&reply), Some(FORWARDED), "{case}");
        assert_eq!(record_ttls(&reply), [carried], "{case}");
        assert_eq!(
            cached_ttls(&engine),
            Vec::from_iter((carried > 0).then_some(carried)),
            "{case}"
        );
    }
}

/// 回答检查以后交出去的每条记录都封到回答检查据的那份回答的 TTL，不论这份应答记录里最短的那个比它短还是长：短 A 记录旁边
/// 的长 CNAME、没有 SOA 的否定应答（不进缓存）带的别名都一样，缓存里存的、命中缓存交出的也是封过的。以前只在记录里最短的
/// 那个比它长时才封：300 秒的回答检查之后拿到 3600 秒的 CNAME 和 60 秒的 A，客户端照原样拿 [3600, 60]，按记录集缓存的
/// 下游留着这条 CNAME 3600 秒
/// Every record going out after an answer check is brought down to the TTL of the answer the
/// check went by, whether the least of this answer's records is shorter than that or longer:
/// a long CNAME next to a short A record and the aliases of a negative answer without SOA
/// (which stays out of the cache) alike, as are what the cache keeps and serves on a hit. They
/// used to be brought down only when the least of the records was longer: after a check on an
/// answer of 300 seconds, a CNAME of 3600 and an A of 60 went to the client as [3600, 60], a
/// downstream caching by record set keeping the CNAME for 3600 seconds
#[tokio::test]
async fn every_record_after_a_check_goes_out_no_longer_than_the_checked_answer() {
    let checked_at = answering_upstream(UPSTREAM_ANSWER, 300).await.address;
    let cases = [
        (ResponseCode::NoError, true, vec![300, 60]),
        (ResponseCode::NXDomain, false, vec![300]),
    ];
    for (rcode, with_address, carried) in cases {
        let then = upstream(move |query| {
            let mut reply = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
            reply.metadata.recursion_desired = query.metadata.recursion_desired;
            reply.metadata.response_code = rcode;
            reply.add_queries(query.queries.iter().cloned());
            let alias = Name::from_ascii("alias.test.").unwrap();
            reply.add_answer(Record::from_rdata(
                query.queries[0].name().clone(),
                3600,
                RData::CNAME(CNAME(alias.clone())),
            ));
            if with_address {
                reply.add_answer(Record::from_rdata(alias, 60, RData::A(A(FORWARDED))));
            }
            vec![(Duration::ZERO, reply.to_vec().unwrap())]
        })
        .await
        .address;
        let engine = engine_with(
            &json!({}),
            json!([{ "id": "main", "rules": [
                checked(&checked_at, json!([{ "type": "continue" }])),
                rule("forward", any(), json!([{ "type": "forward", "upstream": then }])),
            ]}]),
        );
        let reply = ask(&engine, &query(), peer()).await;
        assert_eq!(record_ttls(&reply), carried, "{rcode}");
        let cached = if with_address {
            vec![carried.clone()]
        } else {
            Vec::new()
        };
        assert_eq!(cached_record_ttls(&engine), cached, "{rcode}");
        if with_address {
            let hit = ask(&engine, &query(), peer()).await;
            assert!(
                record_ttls(&hit)
                    .iter()
                    .zip(&carried)
                    .all(|(hit, at_most)| hit <= at_most),
                "{:?} from the cache",
                record_ttls(&hit)
            );
        }
    }
}

/// 上游失败以后改问备用上游拿到的回答照常缓存：miss 动作转发的、miss 动作 continue 以后的规则转发的都一样，故障期间的请求
/// 不必每次都先等失败的那个上游。只有规则给的静态兜底不缓存（见下）。此前的回答检查据过上游应答的，照样不比它留得久
/// A backup upstream's answer after an upstream failure is cached as usual, forwarded by the
/// miss actions or by a rule after their continue alike, so the requests during the failure
/// need not each wait on the failing upstream first. Only a static fallback the rules give
/// stays out (see below). With an earlier answer check having gone by an upstream answer, it
/// stays no longer than that answer all the same
#[tokio::test]
async fn a_backup_upstreams_answer_after_a_failure_is_cached() {
    let checked_first = answering_upstream(UPSTREAM_ANSWER, 60).await.address;
    let backup = answering_upstream(FORWARDED, 600).await.address;
    let forward = json!([{ "type": "forward", "upstream": backup }]);
    let failing = |on_miss: Value| {
        let mut rule = rule(
            "failing",
            any(),
            json!([{ "type": "forward", "upstream": DEAD_UPSTREAM }]),
        );
        rule["response_actions_on_miss"] = on_miss;
        rule
    };
    let paths = [
        (
            "the miss actions",
            json!([{ "id": "main", "rules": [failing(forward.clone())] }]),
            600,
        ),
        (
            "a rule after a continue",
            json!([{ "id": "main", "rules": [
                failing(json!([{ "type": "continue" }])),
                rule("backup", any(), forward.clone()),
            ]}]),
            600,
        ),
        (
            "the miss actions after a check",
            json!([{ "id": "main", "rules": [
                checked(&checked_first, json!([{ "type": "continue" }])),
                failing(forward.clone()),
            ]}]),
            60,
        ),
    ];
    for (path, pipelines, cached) in paths {
        let engine = engine_with(&json!({}), pipelines);
        assert_eq!(
            first_a(&ask(&engine, &query(), peer()).await),
            Some(FORWARDED),
            "{path}"
        );
        assert_eq!(cached_ttls(&engine), [cached], "{path}");
    }
}

/// 回答检查看到上游回了失败应答（SERVFAIL、REFUSED；只问一个上游时它回的，几个上游一起问、都回了失败应答时最先收到的）
/// 也算上游失败，和上游没回答时一样：改问备用上游拿到的回答照常缓存，回答检查的动作转发的、continue 以后的规则转发的、
/// 跳去的 pipeline 转发的（面板「上游回 SERVFAIL 或 REFUSED 时改问」的备用组就是这样）都一样。此前的回答检查据过上游
/// 回答的，照样不比它留得久。以前失败应答当作 TTL 为 0 的回答据过，此后的应答一律不进缓存，故障期间每个请求都先等失败的
/// 上游
/// A failure reply the answer check sees (SERVFAIL, REFUSED; the one upstream's when one is
/// asked, the first received when several asked together all reply with a failure) counts as
/// an upstream failure, as when the upstream gives no answer: a backup upstream's answer is
/// cached as usual, forwarded by the check's actions, by a rule after its continue or by the
/// pipeline it jumps to (as the panel's fallback group for 「上游回 SERVFAIL 或 REFUSED 时改问」
/// does) alike. With an earlier answer check having gone by an upstream answer, it stays no
/// longer than that answer all the same. A failure reply used to be gone by as an answer of
/// TTL 0, no answer after it cached, every request during the failure waiting on the failing
/// upstream first
#[tokio::test]
async fn a_backup_upstreams_answer_after_a_failure_reply_is_cached() {
    let servfail = answering_rcode(ResponseCode::ServFail).await.address;
    let refused = answering_rcode(ResponseCode::Refused).await.address;
    let checked_first = answering_upstream(UPSTREAM_ANSWER, 60).await.address;
    let backup = answering_upstream(FORWARDED, 600).await.address;
    let forward = json!([{ "type": "forward", "upstream": backup }]);
    for failing in [
        servfail.clone(),
        refused.clone(),
        format!("{servfail},{refused}"),
    ] {
        let paths = [
            (
                "the check's own forward",
                json!([{ "id": "main", "rules": [checked(&failing, forward.clone())] }]),
                600,
            ),
            (
                "a rule after a continue",
                json!([{ "id": "main", "rules": [
                    checked(&failing, json!([{ "type": "continue" }])),
                    rule("backup", any(), forward.clone()),
                ]}]),
                600,
            ),
            (
                "a pipeline jumped to",
                json!([
                    { "id": "main", "rules": [checked(
                        &failing,
                        json!([{ "type": "jump_to_pipeline", "pipeline": "backup" }]),
                    )]},
                    { "id": "backup", "rules": [rule("backup", any(), forward.clone())] },
                ]),
                600,
            ),
            (
                "the check's own forward after a check",
                json!([{ "id": "main", "rules": [
                    checked(&checked_first, json!([{ "type": "continue" }])),
                    checked(&failing, forward.clone()),
                ]}]),
                60,
            ),
        ];
        for (path, pipelines, cached) in paths {
            let engine = engine_with(&json!({}), pipelines);
            assert_eq!(
                first_a(&ask(&engine, &query(), peer()).await),
                Some(FORWARDED),
                "{path} on {failing}"
            );
            assert_eq!(cached_ttls(&engine), [cached], "{path} on {failing}");
        }
    }
}

/// 上游失败以后 miss 动作 continue 了，后面的规则即使又据一份上游应答做了决定，给出的静态应答也只是这一次请求的兜底，不进缓存
/// （见 `Route::fell_back`）：缓存了的话，上游恢复了还一直用到条目到期
/// After the miss actions continued on an upstream failure, a static answer a later rule gives
/// is still a fallback for this request, even with another upstream answer decided on in
/// between, and it stays out of the cache (see `Route::fell_back`): cached, it would be served
/// after the upstream recovered, until the entry expired
#[tokio::test]
async fn a_fallback_after_an_upstream_failure_stays_uncached_past_a_later_check() {
    let answering = answering_upstream(UPSTREAM_ANSWER, 600).await.address;
    let mut failing = rule(
        "failing",
        any(),
        json!([{ "type": "forward", "upstream": DEAD_UPSTREAM }]),
    );
    failing["response_actions_on_miss"] = json!([{ "type": "continue" }]);
    let fallback = json!([{ "type": "static_ip_response", "ip": STATIC.to_string() }]);
    let engine = engine_with(
        &json!({}),
        json!([{ "id": "main", "rules": [
            failing,
            checked(&answering, json!([{ "type": "continue" }])),
            rule("fallback", any(), fallback),
        ]}]),
    );
    assert_eq!(first_a(&ask(&engine, &query(), peer()).await), Some(STATIC));
    assert_eq!(cached_ttls(&engine), Vec::<u32>::new());
}

/// 规则直接给出的静态应答不进响应缓存：快速路径、规则缓存下次照样直接给出，记在这条规则名下。请求阶段跳过去以后直接给出的也
/// 一样，哪怕跳之前越过了一份应答：那是目标 pipeline 直接给的，直接进它的请求也照样直接拿到。以前开着 min_ttl 时按它缓存，
/// 之后的请求从响应缓存拿到它，查询日志和规则计数里就没有这条规则
/// A static answer the rules give outright stays out of the response cache: the fast path
/// and the rule cache give it again outright, under its rule. So does one given outright
/// after a request-phase jump, even with an answer passed over before the jump: the target
/// pipeline gives it outright, to the requests entering it directly too. With min_ttl on it
/// used to be cached for min_ttl, later requests taking it from the response cache, absent
/// from the query log and rule counts under the rule
#[tokio::test]
async fn a_static_answer_the_rules_give_outright_is_not_cached() {
    let upstream = answering_upstream(UPSTREAM_ANSWER, 600).await.address;
    for action in [
        json!({ "type": "static_ip_response", "ip": STATIC.to_string() }),
        json!({ "type": "deny" }),
    ] {
        let paths = [
            (
                "outright",
                json!([{ "id": "main", "rules": [rule("static", any(), json!([action]))] }]),
            ),
            (
                "after a request-phase jump",
                json!([
                    { "id": "main", "rules": [
                        checked(&upstream, json!([{ "type": "continue" }])),
                        rule("jump", any(), json!([{ "type": "jump_to_pipeline", "pipeline": "static" }])),
                    ]},
                    { "id": "static", "rules": [rule("static", any(), json!([action]))] },
                ]),
            ),
        ];
        for (path, pipelines) in paths {
            let engine = engine_with(&json!({ "min_ttl": 60 }), pipelines);
            ask(&engine, &query(), peer()).await;
            assert_eq!(cached_ttls(&engine), Vec::<u32>::new(), "{path}: {action}");
        }
    }
}

/// 上游失败以后兜底给出的静态应答交给这一次请求，不进缓存：miss 动作直接给的、miss 动作 continue 到下一条规则给的、miss
/// 动作跳到别的规则组给的、回答检查看到失败应答时它的动作给的都一样。上游恢复以后，下一个请求拿到的是上游的回答。以前按
/// min_ttl 缓存，这段时间里所有请求方都拿兜底的那个
/// A static answer given as a fallback after an upstream failure goes to this request and
/// stays out of the cache, whether the miss actions give it, a rule after their continue, a
/// pipeline they jump to, or the answer check's actions on a failure reply. Once the upstream
/// is back, the next request gets its answer. It used to be cached for min_ttl, every
/// requester getting the fallback meanwhile
#[tokio::test]
async fn a_static_fallback_after_an_upstream_failure_is_not_cached() {
    let servfail = answering_rcode(ResponseCode::ServFail).await.address;
    let fallback = json!([{ "type": "static_ip_response", "ip": STATIC.to_string() }]);
    let failing = |on_miss: Value| {
        let mut rule = rule(
            "failing",
            any(),
            json!([{ "type": "forward", "upstream": DEAD_UPSTREAM }]),
        );
        rule["response_actions_on_miss"] = on_miss;
        rule
    };
    let paths = [
        (
            "the miss actions",
            json!([{ "id": "main", "rules": [failing(fallback.clone())] }]),
        ),
        (
            "a rule after a continue",
            json!([{ "id": "main", "rules": [
                failing(json!([{ "type": "continue" }])),
                rule("fallback", any(), fallback.clone()),
            ]}]),
        ),
        (
            "a pipeline jumped to",
            json!([
                { "id": "main", "rules": [
                    failing(json!([{ "type": "jump_to_pipeline", "pipeline": "fallback" }]))
                ]},
                { "id": "fallback", "rules": [rule("fallback", any(), fallback.clone())] },
            ]),
        ),
        (
            "the check's actions on a failure reply",
            json!([{ "id": "main", "rules": [checked(&servfail, fallback.clone())] }]),
        ),
    ];
    for (path, pipelines) in paths {
        for settings in [json!({ "min_ttl": 60 }), json!({})] {
            let engine = engine_with(&settings, pipelines.clone());
            assert_eq!(
                first_a(&ask(&engine, &query(), peer()).await),
                Some(STATIC),
                "{path} with {settings}"
            );
            assert_eq!(
                cached_ttls(&engine),
                Vec::<u32>::new(),
                "{path} with {settings}"
            );
        }
    }
}

/// 按客户端地址给不同静态应答的 pipeline，应答照样缓存：槽位按规则对请求方的判定分开（见 `RequesterScope`），判定一样的
/// 请求方共用一份，判定不一样的各有各的。以前这样的 pipeline 的静态应答一律不进缓存
/// A pipeline giving static answers by client address has them cached all the same: slots
/// are kept apart by how the rules judge the requester (see `RequesterScope`), requesters
/// judged alike sharing one and the others having their own. Such a pipeline's static answers
/// used to stay out of the cache altogether
#[tokio::test]
async fn a_static_answer_by_client_address_is_cached_for_the_requesters_judged_alike() {
    let upstream = answering_upstream(UPSTREAM_ANSWER, 600).await;
    let engine = engine_with(
        &json!({}),
        json!([{ "id": "main", "rules": [
            checked(&upstream.address, json!([{ "type": "continue" }])),
            rule(
                "device",
                json!({ "type": "client_ip", "cidr": "10.0.0.1/32" }),
                json!([{ "type": "static_ip_response", "ip": "0.0.0.0" }]),
            ),
            rule(
                "rest",
                any(),
                json!([{ "type": "static_ip_response", "ip": STATIC.to_string() }]),
            ),
        ]}]),
    );
    for (client, answer) in [
        ("10.0.0.1:53000", Ipv4Addr::UNSPECIFIED),
        ("10.0.0.2:53000", STATIC),
        ("10.0.0.3:53000", STATIC),
        ("10.0.0.1:53001", Ipv4Addr::UNSPECIFIED),
    ] {
        assert_eq!(
            first_a(&ask(&engine, &query(), client.parse().unwrap()).await),
            Some(answer),
            "{client}"
        );
    }
    assert_eq!(
        cached_ttls(&engine),
        [300, 300],
        "one answer for 10.0.0.1, one for the rest"
    );
    assert_eq!(
        upstream.queries(),
        2,
        "the requesters judged alike were answered from the cache"
    );
}
