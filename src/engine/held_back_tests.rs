//! 开了流控时，一台设备在一个上游上的等待多半没等到回答，就先不替它等这个上游，隔一秒放一个去试，试到了回答就放开；它等
//! 别的上游、别的设备等这个上游都照常（见 `PermitManager::ask`）。卡住的等待留到每台设备的那一份为止，再卡住的不等上游
//! 超时就照上游失败处理（见 `Asking::wait`）。
//! With flow control on, once most of a device's waits on an upstream go unanswered the
//! upstream is not waited on for it for now, one going to try every second and an answer to it
//! letting them all through; its waits on another upstream and another device's on this one go
//! on (see `PermitManager::ask`). Stuck waits are kept up to each device's share, and one stuck
//! after that is treated as the upstream failing without waiting out its timeout (see
//! `Asking::wait`).

use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use serde_json::json;

use crate::engine::Engine;
use crate::engine::test_support::{
    self as support, Upstream, Warnings, answering_upstream, ask, counting_settings, engine_from,
    first_a,
};

/// 会回答的上游给的地址 / The address the answering upstream gives
const ANSWER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 44);

fn query(name: &str) -> Vec<u8> {
    let mut query = Message::new(0x4b42, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
    query.to_vec().unwrap()
}

fn client(last: u8) -> SocketAddr {
    format!("198.51.100.{last}:53000").parse().unwrap()
}

fn rcode(reply: &[u8]) -> ResponseCode {
    Message::from_vec(reply).unwrap().metadata.response_code
}

/// `dead.test` 下的名字转给 `dead`、别的转给 `good` 的引擎，上游超时 `timeout_ms`
/// An engine forwarding names under `dead.test` to `dead` and the rest to `good`, with an
/// upstream timeout of `timeout_ms`
fn engine(dead: &Upstream, good: &Upstream, flow_control: bool, timeout_ms: u64) -> Arc<Engine> {
    Arc::new(engine_from(json!({
        "settings": counting_settings(json!({
            "flow_control_enabled": flow_control,
            "upstream_timeout_ms": timeout_ms,
        })),
        "pipelines": [{ "id": "main", "rules": [
            { "name": "dead", "matchers": [{ "type": "domain_suffix", "value": "dead.test" }],
              "actions": [{ "type": "forward", "upstream": dead.address }] },
            { "name": "rest", "matchers": [{ "type": "any" }],
              "actions": [{ "type": "forward", "upstream": good.address }] },
        ]}]
    })))
}

/// 像监听器那样先问 20 个会回答的名字，让内核知道回答一般很快：之后等了 100 毫秒以上还没结果的才算卡住。哪个上游都还没
/// 等到过回答时，算卡住的时间是上游时限的三分之一
/// Asks 20 names that get answered, as a listener does, so the kernel knows answers are
/// quick as a rule: from then on a wait of over 100 ms with nothing counts as stuck. With no
/// answer from any upstream yet, a wait counts as stuck after a third of the upstream's timeout
async fn know_answers_are_quick(engine: &Arc<Engine>) {
    for n in 0..20 {
        let (_, answered) =
            ask_as_a_listener(engine, format!("quick{n}.alive.test."), client(9)).await;
        assert_eq!(answered, Some(ResponseCode::NoError));
    }
}

/// 等到 `upstream` 收到的查询达到 `count` 个：领头的查询已经发给上游，它登记的条目也就在了，这时再让别的查询来等
/// 它。等的是这件事本身，不是猜一段够长的时间（忙的机器上 20 毫秒不够 70 个查询都发出去）；一直等不到才在 5 秒后失败
/// Waits until `upstream` has received `count` queries: the leading queries have gone to the
/// upstream, so the entries they registered are there, and only then do other queries come to
/// wait on them. What is waited for is that itself, not a guessed stretch of time (on a busy
/// machine 20 ms is not enough for 70 queries to go out); only if it never comes does this
/// fail, after 5 seconds
async fn sent_to(upstream: &Upstream, count: usize) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while upstream.queries() < count {
        assert!(
            Instant::now() < deadline,
            "the upstream got {} of {count} queries",
            upstream.queries()
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

/// `from` 一起问 `dead.test` 下的 `count` 个不同名字，都答完才返回 / `from` asks `count` different
/// names under `dead.test` at once, returning once all are answered
async fn ask_dead_names(engine: &Arc<Engine>, from: SocketAddr, tag: &str, count: usize) {
    let asked: Vec<_> = (0..count)
        .map(|n| {
            let engine = Arc::clone(engine);
            let packet = query(&format!("{tag}{n}.dead.test."));
            tokio::spawn(async move { ask(&engine, &packet, from).await })
        })
        .collect();
    for one in asked {
        assert_eq!(rcode(&one.await.unwrap()), ResponseCode::ServFail);
    }
}

/// 一台设备对着不回答的上游问了 64 个都没等到回答：它再问这个上游的名字当场回 SERVFAIL，查询不再发给上游；它问别的上游
/// 照常有回答，别的设备问这个上游照常发出去
/// A device has 64 queries to an upstream that does not answer go unanswered: its next name
/// for that upstream gets SERVFAIL on the spot with no query sent upstream; its names for
/// another upstream are answered as usual, and another device's for this one still go out
#[tokio::test]
async fn a_device_is_held_back_from_the_upstream_that_does_not_answer_it() {
    let dead = support::upstream(|_| Vec::new()).await;
    let good = answering_upstream(ANSWER, 300).await;
    let engine = engine(&dead, &good, true, 150);
    know_answers_are_quick(&engine).await;
    ask_dead_names(&engine, client(1), "a", 64).await;
    let sent = dead.queries();
    assert!(sent >= 64, "{sent} sent upstream");

    let started = Instant::now();
    let refused = ask(&engine, &query("more.dead.test."), client(1)).await;
    assert_eq!(rcode(&refused), ResponseCode::ServFail);
    assert!(
        started.elapsed() < Duration::from_millis(100),
        "answered without waiting on the upstream, took {:?}",
        started.elapsed()
    );
    assert_eq!(dead.queries(), sent, "not sent upstream");

    let answered = ask(&engine, &query("alive.test."), client(1)).await;
    assert_eq!(first_a(&answered), Some(ANSWER), "another upstream");

    ask_dead_names(&engine, client(2), "b", 1).await;
    assert!(dead.queries() > sent, "another device's is sent");
}

/// 被拦住的查询不逐个记警告日志：洪泛的设备被拦住以后每秒可以有几万个，逐个记的话写日志比处理查询还费劲。流控每十万次
/// 拒绝记的那一行汇总照旧，上游真失败时的警告也照旧
/// A query held back logs no warning of its own: a flooding device held back can have tens
/// of thousands a second, and a line for each would cost more than handling them. The summary
/// line flow control writes every hundred thousand refusals stays, as does the warning for an
/// upstream really failing
#[tokio::test]
async fn a_query_held_back_logs_no_warning() {
    let dead = support::upstream(|_| Vec::new()).await;
    let good = answering_upstream(ANSWER, 300).await;
    let engine = engine(&dead, &good, true, 150);
    know_answers_are_quick(&engine).await;
    let (warnings, guard) = Warnings::capture();
    ask_dead_names(&engine, client(1), "a", 64).await;
    let failed = warnings.lines().len();
    assert!(failed >= 64, "{failed} warnings for the upstream failing");
    for n in 0..20 {
        let refused = ask(&engine, &query(&format!("more{n}.dead.test.")), client(1)).await;
        assert_eq!(rcode(&refused), ResponseCode::ServFail);
    }
    drop(guard);
    // 只多出流控隔很久才记一次的那一行汇总（第一次拒绝时记一行）
    // Only the summary line flow control writes once in a long while is added (one at the
    // first refusal)
    let lines = warnings.lines();
    let added = &lines[failed..];
    assert_eq!(added.len(), 1, "{added:?}");
    assert!(
        added[0].contains("flow control is refusing queries"),
        "{added:?}"
    );
}

/// 拦着的时候隔一秒放一个去试：上游恢复回答以后，一秒之内的还是当场回 SERVFAIL，过了一秒的那一个发给上游、等到回答，之后
/// 都照常
/// While held back one goes to try every second: once the upstream answers again, a query
/// within the second still gets SERVFAIL on the spot, the one after it is sent upstream and
/// answered, and all go on as usual from then
#[tokio::test]
async fn a_try_answered_lets_the_device_through_again() {
    let dead = answering_upstream(ANSWER, 300).await;
    dead.silence(true);
    let good = answering_upstream(ANSWER, 300).await;
    let engine = engine(&dead, &good, true, 150);
    know_answers_are_quick(&engine).await;
    ask_dead_names(&engine, client(1), "a", 64).await;
    dead.silence(false);

    let held = ask(&engine, &query("soon.dead.test."), client(1)).await;
    assert_eq!(rcode(&held), ResponseCode::ServFail, "within the second");

    tokio::time::sleep(Duration::from_millis(1100)).await;
    let tried = ask(&engine, &query("try.dead.test."), client(1)).await;
    assert_eq!(first_a(&tried), Some(ANSWER), "the try is answered");
    for n in 0..5 {
        let after = ask(&engine, &query(&format!("after{n}.dead.test.")), client(1)).await;
        assert_eq!(first_a(&after), Some(ANSWER), "let through again");
    }
}

/// 对每个查询过 `delay` 回 SERVFAIL 的上游 / An upstream answering every query SERVFAIL after
/// `delay`
async fn failing_upstream(delay: Duration) -> Upstream {
    support::upstream(move |query| {
        let mut reply = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
        reply.metadata.response_code = ResponseCode::ServFail;
        reply.add_queries(query.queries.clone());
        vec![(delay, reply.to_vec().unwrap())]
    })
    .await
}

/// 上游很快回来的失败应答不算没回答：一台设备问的名字上游全都当场回 SERVFAIL（一个程序反复问坏掉的名字），问多少个都照常
/// 发给上游，不连累这台设备问别的名字
/// A failure reply an upstream sends quickly is not "no answer": with the upstream answering
/// SERVFAIL on the spot to every name a device asks (a program asking broken names over and
/// over), they all go upstream however many it asks, and the device's other names are not
/// dragged down
#[tokio::test]
async fn failure_replies_that_come_quickly_do_not_hold_a_device_back() {
    let failing = failing_upstream(Duration::ZERO).await;
    let good = answering_upstream(ANSWER, 300).await;
    let engine = engine(&failing, &good, true, 150);
    know_answers_are_quick(&engine).await;
    ask_dead_names(&engine, client(1), "a", 100).await;
    let sent = failing.queries();
    ask_dead_names(&engine, client(1), "b", 1).await;
    assert!(failing.queries() > sent, "still sent upstream");
}

/// 上游过了很久才回来的失败应答也不算没回答：上游是回了的。知道回答一般很快以后，一台设备问的名字上游都过 300 毫秒才回
/// SERVFAIL，问了一百个，下一个照样发给上游。对着这种名字洪泛的设备由卡住的那一份拦住（见
/// `a_flood_of_names_failing_late_is_held_by_the_share_of_stuck_queries`）
/// A failure reply an upstream sends after a long while is not "no answer" either: the upstream
/// did reply. Once answers are known to be quick, with the upstream answering SERVFAIL only
/// after 300 ms to every name a device asks, a hundred of them and the next still goes
/// upstream. A device flooding such names is held by the share of stuck queries (see
/// `a_flood_of_names_failing_late_is_held_by_the_share_of_stuck_queries`)
#[tokio::test]
async fn failure_replies_that_come_late_do_not_hold_a_device_back() {
    let failing = failing_upstream(Duration::from_millis(300)).await;
    let good = answering_upstream(ANSWER, 300).await;
    let engine = engine(&failing, &good, true, 1000);
    know_answers_are_quick(&engine).await;
    ask_dead_names(&engine, client(1), "a", 100).await;
    let sent = failing.queries();
    ask_dead_names(&engine, client(1), "b", 1).await;
    assert!(failing.queries() > sent, "still sent upstream");
}

/// 对着上游要等很久才回失败的名字洪泛（随机子域名打到一个答不上的域）：先卡住的一千个留着等到上游回话，后面的不等了——
/// 它们没等到上游回话，记没回答，这台设备接着就被拦住，再问的不发给上游
/// A flood of names the upstream takes long to fail (random subdomains of a zone that cannot
/// be answered): the thousand stuck first are kept until the upstream replies and those after
/// wait no more; with no word from the upstream they are noted as no answer, the device is
/// held back from then on, and what it asks next is not sent upstream
#[tokio::test]
async fn a_flood_of_names_failing_late_is_held_by_the_share_of_stuck_queries() {
    let failing = failing_upstream(Duration::from_millis(600)).await;
    let good = answering_upstream(ANSWER, 300).await;
    let engine = engine(&failing, &good, true, 3000);
    know_answers_are_quick(&engine).await;
    let flood = flood(&engine, client(1), "f", 1100);
    // 超出那一份的一百个不等了 / The hundred past the share have given up
    done_of(&flood, 100).await;
    let sent = failing.queries();
    let started = Instant::now();
    let (_, answered) = ask_as_a_listener(&engine, "more.dead.test.".to_string(), client(1)).await;
    assert_eq!(answered, Some(ResponseCode::ServFail));
    assert!(
        started.elapsed() < Duration::from_millis(100),
        "answered without waiting on the upstream, took {:?}",
        started.elapsed()
    );
    assert_eq!(failing.queries(), sent, "not sent upstream");
    for one in flood {
        assert_eq!(one.await.unwrap().1, Some(ResponseCode::ServFail));
    }
}

/// 没开流控时不拦：问多少个没回答的，下一个照样发给上游
/// Without flow control nothing is held back: however many go unanswered, the next is still
/// sent upstream
#[tokio::test]
async fn without_flow_control_no_device_is_held_back() {
    let dead = support::upstream(|_| Vec::new()).await;
    let good = answering_upstream(ANSWER, 300).await;
    let engine = engine(&dead, &good, false, 150);
    ask_dead_names(&engine, client(1), "a", 100).await;
    let sent = dead.queries();
    ask_dead_names(&engine, client(1), "b", 1).await;
    assert!(dead.queries() > sent, "still sent upstream");
}

/// 像监听器那样走完整路径，返回等了多久，以及应答的 RCODE（等到请求的时限时没有应答，是 None）
/// Through the full path as a listener goes, giving how long it took and the answer's RCODE
/// (None with no answer, at the request timeout)
async fn ask_as_a_listener(
    engine: &Arc<Engine>,
    name: String,
    from: SocketAddr,
) -> (Duration, Option<ResponseCode>) {
    let started = Instant::now();
    let answer = engine
        .answer_after_fast_path(&query(&name), from, None)
        .await;
    (started.elapsed(), answer.map(|answer| rcode(&answer)))
}

/// `from` 一下子问 `dead.test` 下的 `count` 个不同名字，不等结果 / `from` asks `count` different names
/// under `dead.test` at once, without waiting for the outcomes
fn flood(
    engine: &Arc<Engine>,
    from: SocketAddr,
    tag: &'static str,
    count: usize,
) -> Vec<tokio::task::JoinHandle<(Duration, Option<ResponseCode>)>> {
    (0..count)
        .map(|n| {
            let engine = Arc::clone(engine);
            tokio::spawn(async move {
                ask_as_a_listener(&engine, format!("{tag}{n}.dead.test."), from).await
            })
        })
        .collect()
}

/// 同 [`flood`]，但一次只问一小批，等 `upstream` 都收到了再问下一批：假上游的接收缓冲只放得下一百多个查询，一千个任务挨着
/// 发出去时它还没轮到读，多出来的系统就丢了，上游根本没见过它们
/// The same as [`flood`], asking a small lot at a time and the next once `upstream` has
/// received them all: a fake upstream's receive buffer holds a hundred-odd queries, and with a
/// thousand tasks sending one after another before it gets to read, the system drops the rest,
/// which the upstream never sees
async fn flood_reaching(
    engine: &Arc<Engine>,
    from: SocketAddr,
    tag: &'static str,
    count: usize,
    upstream: &Upstream,
) -> Vec<tokio::task::JoinHandle<(Duration, Option<ResponseCode>)>> {
    const LOT: usize = 50;
    let before = upstream.queries();
    let mut asked = Vec::with_capacity(count);
    while asked.len() < count {
        for n in asked.len()..count.min(asked.len() + LOT) {
            let engine = Arc::clone(engine);
            asked.push(tokio::spawn(async move {
                ask_as_a_listener(&engine, format!("{tag}{n}.dead.test."), from).await
            }));
        }
        sent_to(upstream, before + asked.len()).await;
    }
    asked
}

/// 卡住的查询：知道回答一般很快以后，一台设备对着不回答的上游一下子问了 1100 个，先卡住的一千个留着等，后面的一百个不等
/// 上游超时就回 SERVFAIL；另一台设备的一个也卡住了，照样留着等
/// Stuck queries: once answers are known to be quick, a device asks an upstream that does
/// not answer 1100 at once; the thousand stuck first are kept waiting and the hundred after
/// get SERVFAIL without waiting out the upstream's timeout; one of another device's, stuck
/// too, is kept waiting all the same
#[tokio::test]
async fn stuck_queries_past_a_devices_share_give_up_early() {
    let dead = support::upstream(|_| Vec::new()).await;
    let good = answering_upstream(ANSWER, 300).await;
    let engine = engine(&dead, &good, true, 2000);
    know_answers_are_quick(&engine).await;

    let flood = flood(&engine, client(1), "f", 1100);
    let other = {
        let engine = Arc::clone(&engine);
        tokio::spawn(async move {
            ask_as_a_listener(&engine, "other.dead.test.".to_string(), client(2)).await
        })
    };
    let mut gave_up_early = 0;
    for one in flood {
        let (took, answered) = one.await.unwrap();
        assert_eq!(answered, Some(ResponseCode::ServFail));
        if took < Duration::from_millis(1500) {
            gave_up_early += 1;
        }
    }
    assert!(
        (80..=120).contains(&gave_up_early),
        "{gave_up_early} gave up early"
    );
    let (took, answered) = other.await.unwrap();
    assert_eq!(answered, Some(ResponseCode::ServFail));
    assert!(
        took >= Duration::from_millis(2000),
        "another device's waits out the upstream, took {took:?}"
    );
}

/// 记进回答要多久的，是和上游的一次收发用了多久，不是查询一共等了多久：上游头一次不回、重发才回时（上游超时 900 毫秒，
/// 过 300 毫秒重发），查询一共等了 300 多毫秒，记下的还是重发那一次的几毫秒，算卡住的时间还是 100 毫秒。以前按查询一共等了
/// 多久记，上游限速时靠重发才等到的回答把这个时间拉到几秒，谁都不再算卡住
/// What is noted in how long answers take is how long one exchange with an upstream took, not
/// how long the query waited in all: with an upstream ignoring the first try and answering the
/// resend (an upstream timeout of 900 ms, resent after 300 ms), the query waits over 300 ms in
/// all while the few milliseconds of the resend are what is noted, and a query still counts as
/// stuck after 100 ms. Noted by the whole wait, the answers won by resending under an upstream's
/// rate limit stretched that time to seconds, with nothing stuck any more
#[tokio::test]
async fn an_answer_won_by_resending_is_noted_by_its_own_exchange() {
    let seen = Arc::new(std::sync::Mutex::new(std::collections::HashSet::new()));
    let answers_second_try = {
        let seen = Arc::clone(&seen);
        support::upstream(move |query| {
            let Some(question) = query.queries.first() else {
                return Vec::new();
            };
            // 每个名字头一次不回，再问才回 / Each name goes unanswered the first time and is
            // answered when asked again
            if seen.lock().unwrap().insert(question.name().to_string()) {
                return Vec::new();
            }
            let mut reply = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
            reply.add_query(question.clone());
            reply.add_answer(hickory_proto::rr::Record::from_rdata(
                question.name().clone(),
                300,
                hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A(ANSWER)),
            ));
            vec![(Duration::ZERO, reply.to_vec().unwrap())]
        })
        .await
    };
    let good = answering_upstream(ANSWER, 300).await;
    let engine = engine(&answers_second_try, &good, true, 900);
    // 收发每 8 次量一次：8 个名字各两次收发，量到的两次都是重发的那一次
    // One exchange in 8 is timed: 8 names with two exchanges each, the two timed being resends
    for n in 0..8 {
        let (took, answered) =
            ask_as_a_listener(&engine, format!("again{n}.dead.test."), client(1)).await;
        assert_eq!(answered, Some(ResponseCode::NoError));
        assert!(took >= Duration::from_millis(300), "took {took:?}");
    }
    // 记的要是查询一共等的 300 多毫秒，这里至少是 600 毫秒 / Had the 300-odd ms each query waited
    // been noted, this would be 600 ms at least
    let stuck_after = engine
        .permit_manager
        .stuck_after(&answers_second_try.address, Duration::from_millis(900));
    assert!(stuck_after < Duration::from_millis(600), "{stuck_after:?}");
}

/// 等到 `asked` 里有 `count` 个有了结果 / Waits until `count` of `asked` have their outcome
async fn done_of<T>(asked: &[tokio::task::JoinHandle<T>], count: usize) {
    let deadline = Instant::now() + Duration::from_secs(10);
    let done = || asked.iter().filter(|one| one.is_finished()).count();
    while done() < count {
        assert!(Instant::now() < deadline, "{} of {count} done", done());
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

/// 上游只是慢时，留着等的那些等到回答以后，同样慢的查询不再算卡住。知道回答一般很快以后，一台设备问一个慢上游 1100 个：
/// 先卡住的一千个留着、后面的一百个不等了；留着的等到了回答，内核就知道这个上游要这么久，这以后再问 1100 个，等过了原先算卡住的
/// 时间也都接着等，都等到回答。上游什么时候回答由测试放行，查询也等上游收到了再接着问。以前 1100 个一下子问出去、上游固定
/// 300 毫秒回答：假上游的接收缓冲放不下，多出来的查询系统直接丢了，要等内核重发才有回答；又要 1100 个在 300 毫秒里全都卡住
/// 才数得对。机器一忙两样都不成立，这个测试时过时不过
/// With an upstream that is only slow, once those kept waiting get their answers, queries as
/// slow no longer count as stuck. Answers known to be quick, a device asks a slow upstream
/// 1100: the thousand stuck first are kept and the hundred after wait no more; with those kept
/// answered the kernel knows this upstream takes that long, and 1100 more after that go on
/// waiting past what counted as stuck before and are all answered. When the upstream answers is
/// for the test to say, and each lot of queries is asked once the upstream has received the
/// last. All 1100 used to be asked at once of an upstream answering after a fixed 300 ms: they
/// did not fit the fake upstream's receive buffer, the system dropping the rest, which were
/// answered only once the kernel sent them again; and the count came out right only with all
/// 1100 stuck within those 300 ms. A busy machine manages neither, so the test passed at times
/// and failed at others
#[tokio::test]
async fn a_slow_upstream_is_not_stuck_once_its_answers_arrive() {
    /// 上游超时，长到这个测试里不会重发 / The upstream's timeout, long enough for nothing to be
    /// sent again within this test
    const LIMIT: Duration = Duration::from_secs(30);
    /// 留着等的那些卡住以后，上游还要这么久才回答 / How much longer the upstream takes once
    /// those kept waiting are stuck
    const SLOW: Duration = Duration::from_millis(400);
    let (slow, answers) = support::answering_upstream_held(ANSWER, 300).await;
    let good = answering_upstream(ANSWER, 300).await;
    let engine = engine(&slow, &good, true, LIMIT.as_millis() as u64);
    know_answers_are_quick(&engine).await;
    let stuck_after = || engine.permit_manager.stuck_after(&slow.address, LIMIT);
    let quick = stuck_after();
    let outcomes = |asked: Vec<tokio::task::JoinHandle<(Duration, Option<ResponseCode>)>>| async {
        let (mut answered, mut gave_up) = (0, 0);
        for one in asked {
            match one.await.unwrap().1 {
                Some(ResponseCode::NoError) => answered += 1,
                Some(ResponseCode::ServFail) => gave_up += 1,
                other => panic!("{other:?}"),
            }
        }
        (answered, gave_up)
    };

    let first = flood_reaching(&engine, client(1), "a", 1100, &slow).await;
    done_of(&first, 100).await;
    assert_eq!(engine.permit_manager.stuck(), 1000, "the thousand kept");
    tokio::time::sleep(SLOW).await;
    answers.release();
    assert_eq!(outcomes(first).await, (1000, 100));
    assert!(
        stuck_after() >= 2 * SLOW,
        "this upstream takes that long: {:?}",
        stuck_after()
    );

    answers.hold();
    let second = flood_reaching(&engine, client(1), "b", 1100, &slow).await;
    // 过了原先算卡住的时间 / Past what counted as stuck before
    tokio::time::sleep(quick + Duration::from_millis(50)).await;
    assert_eq!(engine.permit_manager.stuck(), 0, "none stuck any more");
    assert!(second.iter().all(|one| !one.is_finished()));
    answers.release();
    assert_eq!(outcomes(second).await, (1100, 0));
}

/// 回答要多久是每个上游自己的：快的上游答了八百多个、慢的上游（250 毫秒）只答了十几个，合在一起看慢的排不进最慢的百分之一。
/// 慢上游过 250 毫秒回的 SERVFAIL 对它来说是答得干脆，不是等了很久：一个程序反复问慢上游上一个坏掉的名字，问一百次也不拦
/// 这台设备。以前所有上游合在一起看，这种失败应答都算「没回答」，一个坏名字就把这台设备在这个上游上的查询全拦住
/// How long answers take is each upstream's own: with a quick upstream having answered over
/// eight hundred and a slow one (250 ms) a dozen or so, looked at together the slow ones never
/// make the slowest hundredth. A SERVFAIL the slow upstream sends after 250 ms is a ready
/// answer for it, not a long wait: a program asking one broken name on the slow upstream over
/// and over, a hundred times, does not hold its device back. Looked at together as all
/// upstreams used to be, every such failure reply counted as "no answer", and one broken name
/// held back all the device's queries to that upstream
#[tokio::test]
async fn a_slow_upstreams_failure_replies_are_judged_by_its_own_answers() {
    let delay = Duration::from_millis(250);
    let slow = support::upstream(move |query| {
        let Some(question) = query.queries.first() else {
            return Vec::new();
        };
        let mut reply = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
        reply.add_query(question.clone());
        if question.name().to_string().starts_with("broken") {
            reply.metadata.response_code = ResponseCode::ServFail;
        } else {
            reply.add_answer(hickory_proto::rr::Record::from_rdata(
                question.name().clone(),
                300,
                hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A(ANSWER)),
            ));
        }
        vec![(delay, reply.to_vec().unwrap())]
    })
    .await;
    let good = answering_upstream(ANSWER, 300).await;
    let engine = engine(&slow, &good, true, 2000);
    for round in 0..8 {
        let quick: Vec<_> = (0..100)
            .map(|n| {
                let engine = Arc::clone(&engine);
                tokio::spawn(async move {
                    ask_as_a_listener(&engine, format!("q{round}x{n}.alive.test."), client(9)).await
                })
            })
            .collect();
        for one in quick {
            assert_eq!(one.await.unwrap().1, Some(ResponseCode::NoError));
        }
    }
    for one in flood(&engine, client(9), "fine", 16) {
        assert_eq!(one.await.unwrap().1, Some(ResponseCode::NoError));
    }
    let limit = Duration::from_millis(2000);
    let manager = &engine.permit_manager;
    let (of_good, of_slow) = (
        manager.stuck_after(&good.address, limit),
        manager.stuck_after(&slow.address, limit),
    );
    assert!(
        of_slow >= Duration::from_millis(500),
        "the slow upstream by its own answers"
    );
    // 比的是两个上游谁长谁短，不是量到的毫秒数：机器忙的时候快上游量出来也有几十毫秒
    // What is compared is which of the two is longer, not the milliseconds measured: on a busy
    // machine the quick upstream measures at tens of milliseconds too
    assert!(
        of_good < of_slow,
        "the quick upstream by its own answers: {of_good:?} against {of_slow:?}"
    );

    for one in flood(&engine, client(1), "broken", 100) {
        assert_eq!(one.await.unwrap().1, Some(ResponseCode::ServFail));
    }
    let sent = slow.queries();
    let (_, answered) = ask_as_a_listener(&engine, "fine.dead.test.".to_string(), client(1)).await;
    assert_eq!(answered, Some(ResponseCode::NoError), "not held back");
    assert!(slow.queries() > sent, "sent upstream");
}

/// 流控没让等的失败是这台设备自己的事，不交给等在同一个转发上的别的设备：一台设备留着等的已经满了，它问的一个慢名字到
/// 算卡住的时候就不等了、回 SERVFAIL；另一台设备同时问了同一个名字、等在它的转发上，这时自己去问，照样等到回答。以前
/// 领头的失败了就把 SERVFAIL 交给所有等着的，别的设备跟着拿到 SERVFAIL
/// A failure with flow control keeping the query from waiting is the device's own affair, and
/// is not handed to another device waiting on the same forward: with a device keeping all it
/// may, a slow name it asks waits no more when it counts as stuck and gets SERVFAIL; another
/// device asking the same name meanwhile, waiting on its forward, then asks for itself and is
/// answered all the same. A leader failing used to hand SERVFAIL to everyone waiting, so the
/// other device got SERVFAIL along with it
#[tokio::test]
async fn another_device_waiting_on_the_same_forward_asks_for_itself() {
    let slow = support::answering_upstream_after(ANSWER, 300, Duration::from_millis(400)).await;
    let good = answering_upstream(ANSWER, 300).await;
    let engine = engine(&slow, &good, true, 3000);
    know_answers_are_quick(&engine).await;
    let slot = engine.permit_manager.slot_of(client(1).ip());
    let kept = engine.permit_manager.keep_all_stuck_for_tests(slot);

    let had = slow.queries();
    let leader = {
        let engine = Arc::clone(&engine);
        tokio::spawn(async move {
            ask_as_a_listener(&engine, "same.dead.test.".to_string(), client(1)).await
        })
    };
    sent_to(&slow, had + 1).await;
    let (waited, answered) =
        ask_as_a_listener(&engine, "same.dead.test.".to_string(), client(2)).await;
    assert_eq!(
        answered,
        Some(ResponseCode::NoError),
        "the other device is answered"
    );
    assert!(waited >= Duration::from_millis(400), "took {waited:?}");
    let (took, answered) = leader.await.unwrap();
    assert_eq!(answered, Some(ResponseCode::ServFail));
    assert!(took < Duration::from_millis(350), "gave up, took {took:?}");
    drop(kept);
}

/// 等别人正在做的同一个转发，和自己转发一样受流控管：留着等的已经满了的设备，等在另一台设备的转发上的查询到算卡住的
/// 时候也不等了，不用陪着等到上游超时。以前等别人的转发不看这些，对着同一个不回答的名字洪泛的设备，在途的全都等到超时
/// Waiting on the same forward another request is making comes under flow control as a forward
/// of its own does: for a device keeping all it may, a query waiting on another device's
/// forward waits no more either once it counts as stuck, instead of waiting out the upstream's
/// timeout with it. Waiting on another's forward used to look at none of this, so a device
/// flooding one name with no answer had everything in flight wait for the timeout
#[tokio::test]
async fn a_wait_on_another_devices_forward_gives_up_as_its_own_would() {
    let dead = support::upstream(|_| Vec::new()).await;
    let good = answering_upstream(ANSWER, 300).await;
    let engine = engine(&dead, &good, true, 2000);
    know_answers_are_quick(&engine).await;
    let slot = engine.permit_manager.slot_of(client(1).ip());
    let kept = engine.permit_manager.keep_all_stuck_for_tests(slot);

    let had = dead.queries();
    let leader = {
        let engine = Arc::clone(&engine);
        tokio::spawn(async move {
            ask_as_a_listener(&engine, "same.dead.test.".to_string(), client(2)).await
        })
    };
    sent_to(&dead, had + 1).await;
    let sent = dead.queries();
    let (took, answered) =
        ask_as_a_listener(&engine, "same.dead.test.".to_string(), client(1)).await;
    assert_eq!(answered, Some(ResponseCode::ServFail));
    assert!(
        took >= Duration::from_millis(80) && took < Duration::from_millis(1000),
        "gave up when stuck, took {took:?}"
    );
    assert_eq!(dead.queries(), sent, "it waited and sent nothing itself");
    let (took, _) = leader.await.unwrap();
    assert!(
        took >= Duration::from_millis(2000),
        "the leader waits out the upstream, took {took:?}"
    );
    drop(kept);
}

/// 后台刷新不替谁问，规则自己的转发、响应动作里的转发都一样，不记在哪台设备头上。一条规则直接问不回答的上游，另一条
/// 先问答得上的上游、拿到回答以后响应动作再问那个不回答的上游：以原来那台设备的名义各刷新 70 次，它照常问那个不回答
/// 的上游；它自己问了 70 次、都没等到回答，才不再替它问
/// A background refresh is asked for nobody, the rule's own forward and a forward among the
/// response actions alike: nothing of it is noted against a device. With one rule asking an
/// upstream that does not answer outright, and another asking one that answers and then, with
/// its answer in, a response action asking the one that does not: 70 refreshes of each run for
/// the device that once asked leave it going to the upstream that does not answer as before; only 70 asked by the device itself and unanswered stop it being
/// asked
#[tokio::test]
async fn a_refresh_is_asked_for_nobody() {
    let dead = support::upstream(|_| Vec::new()).await;
    let good = answering_upstream(ANSWER, 300).await;
    let engine = Arc::new(engine_from(json!({
        "settings": counting_settings(json!({
            "flow_control_enabled": true,
            "upstream_timeout_ms": 150,
        })),
        "pipelines": [{ "id": "main", "rules": [
            { "name": "dead", "matchers": [{ "type": "domain_suffix", "value": "dead.test" }],
              "actions": [{ "type": "forward", "upstream": dead.address }] },
            { "name": "then-dead", "matchers": [{ "type": "any" }],
              "actions": [{ "type": "forward", "upstream": good.address }],
              "response_matchers": [{ "type": "upstream_equals", "value": good.address }],
              "response_actions_on_match": [{ "type": "forward", "upstream": dead.address }] },
        ]}]
    })));
    let device = client(1);
    let asked_70_times = |refresh: bool, zone: &'static str| {
        let engine = Arc::clone(&engine);
        async move {
            let made: Vec<_> = (0..70)
                .map(|n| {
                    let engine = Arc::clone(&engine);
                    let packet = query(&format!("n{n}.{zone}"));
                    tokio::spawn(async move {
                        engine
                            .handle_packet_internal(&packet, device, refresh, None, None, None)
                            .await
                    })
                })
                .collect();
            for one in made {
                let _ = one.await.unwrap();
            }
        }
    };
    let flow = engine.flow_control_state.as_ref().expect("flow control");
    let asked = || {
        engine
            .permit_manager
            .ask(flow, device.ip(), &dead.address, Duration::from_millis(150))
            .is_some()
    };
    // 规则自己的转发 / The rule's own forward
    asked_70_times(true, "dead.test.").await;
    assert!(dead.queries() >= 70, "the refreshes did ask it");
    assert!(asked(), "a refresh's own forward is asked for nobody");
    // 响应动作里的转发 / A forward among the response actions
    let sent = dead.queries();
    asked_70_times(true, "refreshed.test.").await;
    assert!(dead.queries() >= sent + 70, "the refreshes did ask it");
    assert!(asked(), "nor is a response action's forward on a refresh");
    asked_70_times(false, "asked.test.").await;
    assert!(!asked(), "those asked by the device hold it back");
}

/// 先问 `first`（50 毫秒回答）、拿到回答以后再问 `second` 的引擎，`pipelines` 给出两种走法之一。一台设备在 `second` 上被
/// 拦住以后领头问一个名字，另一台设备同时问同一个名字、等在它登记的条目上：领头的在 `second` 那一步被流控拦下，另一台设备
/// 不拿它的失败，自己去问，照样等到回答
/// An engine asking `first` (answering after 50 ms) and then, with its answer in, `second`,
/// `pipelines` giving one of two ways there. With a device held back from `second` leading a
/// name and another device asking the same name meanwhile, waiting on the entry it registered:
/// the leader is kept from `second` by flow control, and the other device gets nothing of its
/// failure, asks for itself and is answered all the same
async fn the_other_device_is_answered_when_a_held_back_one_led(
    pipelines: impl Fn(&Upstream, &Upstream) -> serde_json::Value,
) {
    let first = support::answering_upstream_after(ANSWER, 300, Duration::from_millis(50)).await;
    let second = answering_upstream(ANSWER, 300).await;
    second.silence(true);
    let engine = Arc::new(engine_from(json!({
        "settings": counting_settings(json!({
            "flow_control_enabled": true,
            "upstream_timeout_ms": 450,
        })),
        "pipelines": pipelines(&first, &second),
    })));
    for one in flood(&engine, client(1), "held", 64) {
        assert_ne!(one.await.unwrap().1, Some(ResponseCode::NoError));
    }
    second.silence(false);

    let had = first.queries();
    let leader = {
        let engine = Arc::clone(&engine);
        tokio::spawn(async move {
            ask_as_a_listener(&engine, "same.test.".to_string(), client(1)).await
        })
    };
    sent_to(&first, had + 1).await;
    let (_, answered) = ask_as_a_listener(&engine, "same.test.".to_string(), client(2)).await;
    assert_eq!(
        answered,
        Some(ResponseCode::NoError),
        "the other device is answered"
    );
    assert_ne!(
        leader.await.unwrap().1,
        Some(ResponseCode::NoError),
        "the leader was held back"
    );
}

/// 规则 continue 以后请求还留着它登记的条目（等最后的结果交给等着的请求）：后面那条规则的转发被流控拦下时，留着的条目也
/// 放下，不把这台设备自己的 SERVFAIL 交给等着的别的设备
/// After a rule continues the request still holds the entry it registered (for the final
/// outcome to be handed to the requests waiting): with the next rule's forward kept back by
/// flow control, the entry held goes too, and the device's own SERVFAIL is not handed to the
/// other devices waiting
#[tokio::test]
async fn an_entry_held_after_a_continue_hands_no_flow_control_failure_on() {
    the_other_device_is_answered_when_a_held_back_one_led(|first, second| {
        json!([{ "id": "main", "rules": [
            { "name": "first", "matchers": [{ "type": "any" }],
              "actions": [{ "type": "forward", "upstream": first.address }],
              "response_matchers": [{ "type": "upstream_equals", "value": first.address }],
              "response_actions_on_match": [{ "type": "continue" }] },
            { "name": "second", "matchers": [{ "type": "any" }],
              "actions": [{ "type": "forward", "upstream": second.address }] },
        ]}])
    })
    .await;
}

/// 响应跳转到的 pipeline 里的转发被流控拦下时也一样：跳转之前登记的条目、跳转路上登记的条目都放下，等着的别的设备各自去问
/// The same with the forward in a pipeline a response jumped to being kept back by flow
/// control: the entry registered before the jump and those registered along it all go, and the
/// other devices waiting ask for themselves
#[tokio::test]
async fn a_response_jump_hands_no_flow_control_failure_on() {
    the_other_device_is_answered_when_a_held_back_one_led(|first, second| {
        json!([
            { "id": "main", "rules": [
                { "name": "first", "matchers": [{ "type": "any" }],
                  "actions": [{ "type": "forward", "upstream": first.address }],
                  "response_matchers": [{ "type": "upstream_equals", "value": first.address }],
                  "response_actions_on_match": [{ "type": "jump_to_pipeline", "pipeline": "other" }] },
            ]},
            { "id": "other", "rules": [
                { "name": "second", "matchers": [{ "type": "any" }],
                  "actions": [{ "type": "forward", "upstream": second.address }] },
            ]},
        ])
    })
    .await;
}

/// 规则 continue 以后留着条目，下一条规则的响应跳转到的 pipeline 里的转发又被流控拦下：留着的条目一样放下。这条路上
/// 失败是一层层交回最外面的，最外面以前把它当成一般的失败，照样把 SERVFAIL 交给等着的别的设备
/// With an entry held after a rule continued and the forward in a pipeline the next rule's
/// response jumped to kept back by flow control, the entry held goes all the same. On this
/// path the failure is passed back out layer by layer, and the outermost used to take it for
/// any failure and hand SERVFAIL to the other devices waiting just the same
#[tokio::test]
async fn an_entry_held_after_a_continue_hands_no_failure_from_a_later_jump_on() {
    the_other_device_is_answered_when_a_held_back_one_led(|first, second| {
        json!([
            { "id": "main", "rules": [
                { "name": "first", "matchers": [{ "type": "any" }],
                  "actions": [{ "type": "forward", "upstream": first.address }],
                  "response_matchers": [{ "type": "upstream_equals", "value": first.address }],
                  "response_actions_on_match": [{ "type": "continue" }] },
                { "name": "again", "matchers": [{ "type": "any" }],
                  "actions": [{ "type": "forward", "upstream": first.address }],
                  "response_matchers": [{ "type": "upstream_equals", "value": first.address }],
                  "response_actions_on_match": [{ "type": "jump_to_pipeline", "pipeline": "other" }] },
            ]},
            { "id": "other", "rules": [
                { "name": "second", "matchers": [{ "type": "any" }],
                  "actions": [{ "type": "forward", "upstream": second.address }] },
            ]},
        ])
    })
    .await;
}

/// 响应跳转到的 pipeline 里的转发被流控拦下，也不逐个记警告日志：被拦住的设备接着问了 20 个，只多出流控隔很久才记
/// 一次的那一行汇总
/// A forward in a pipeline a response jumped to being kept back by flow control logs no
/// warning for each either: with 20 more names from the held-back device, only the summary
/// line flow control writes once in a long while is added
#[tokio::test]
async fn a_forward_kept_back_after_a_response_jump_logs_no_warning() {
    let first = answering_upstream(ANSWER, 300).await;
    let second = support::upstream(|_| Vec::new()).await;
    let engine = Arc::new(engine_from(json!({
        "settings": counting_settings(json!({
            "flow_control_enabled": true,
            "upstream_timeout_ms": 150,
        })),
        "pipelines": [
            { "id": "main", "rules": [
                { "name": "first", "matchers": [{ "type": "any" }],
                  "actions": [{ "type": "forward", "upstream": first.address }],
                  "response_matchers": [{ "type": "upstream_equals", "value": first.address }],
                  "response_actions_on_match": [{ "type": "jump_to_pipeline", "pipeline": "other" }] },
            ]},
            { "id": "other", "rules": [
                { "name": "second", "matchers": [{ "type": "any" }],
                  "actions": [{ "type": "forward", "upstream": second.address }] },
            ]},
        ]
    })));
    for one in flood(&engine, client(1), "held", 64) {
        assert_ne!(one.await.unwrap().1, Some(ResponseCode::NoError));
    }
    let sent = second.queries();
    let (warnings, guard) = Warnings::capture();
    for n in 0..20 {
        let (_, answered) = ask_as_a_listener(&engine, format!("more{n}.test."), client(1)).await;
        assert_eq!(answered, Some(ResponseCode::ServFail));
    }
    drop(guard);
    assert_eq!(second.queries(), sent, "none of them sent upstream");
    let lines = warnings.lines();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(
        lines[0].contains("flow control is refusing queries"),
        "{lines:?}"
    );
}

/// 响应动作里的转发被流控拦下时，这个请求出错（监听器回 SERVFAIL），而不是拿一个 SERVFAIL 当结果交给等着的别的请求：这台
/// 设备在这个上游上被拦住以后，替它做的响应动作转发交回的是流控的失败
/// With a forward among the response actions kept back by flow control the request fails (the
/// listener answering SERVFAIL), instead of a SERVFAIL being taken as the outcome and handed
/// to the other requests waiting: once the device is held back from the upstream, a response
/// action's forward made for it gives back flow control's failure
#[tokio::test]
async fn a_response_actions_forward_kept_back_fails_the_request() {
    let dead = support::upstream(|_| Vec::new()).await;
    let good = answering_upstream(ANSWER, 300).await;
    let engine = engine(&dead, &good, true, 150);
    know_answers_are_quick(&engine).await;
    ask_dead_names(&engine, client(1), "a", 64).await;
    let actions = [serde_json::from_value::<crate::config::Action>(
        json!({ "type": "forward", "upstream": dead.address }),
    )
    .unwrap()];
    let packet = query("more.dead.test.");
    let request = Message::from_vec(&packet).unwrap();
    let outcome = crate::engine::rules::apply_response_actions_observed(
        crate::engine::rules::ApplyResponseActionsContext {
            engine: &engine,
            actions: &actions,
            ctx_opt: None,
            req: &request,
            packet: &packet,
            upstream_timeout: Duration::from_millis(150),
            qname: "more.dead.test",
            qtype: RecordType::A,
            client_ip: client(1).ip(),
            asker: Some(client(1).ip()),
            upstream_default: &dead.address,
            pipeline_id: "main",
            rule_name: "dead",
            remaining_jumps: 4,
            trail: None,
        },
        None,
    )
    .await;
    let failure = outcome.expect_err("the request fails");
    assert!(
        crate::engine::upstream::UpstreamFailure::was_withheld(&failure),
        "{failure:#}"
    );
}

/// 放去试的那一个等到的是失败应答，不算等到回答，接着拦：上游不回答时一台设备被拦住，之后上游对每个名字都当场回
/// SERVFAIL，过一秒放去试的那一个发给了上游、拿到 SERVFAIL，紧接着的下一个照样不发
/// The one that went to try getting a failure reply is no answer, and the device stays held
/// back: held back while the upstream did not answer, with the upstream then replying SERVFAIL
/// to every name on the spot, the one going to try a second later is sent upstream and gets
/// SERVFAIL, and the next right after it is still not sent
#[tokio::test]
async fn a_try_getting_a_failure_reply_keeps_the_device_held_back() {
    let failing = failing_upstream(Duration::ZERO).await;
    failing.silence(true);
    let good = answering_upstream(ANSWER, 300).await;
    let engine = engine(&failing, &good, true, 150);
    know_answers_are_quick(&engine).await;
    ask_dead_names(&engine, client(1), "a", 64).await;
    failing.silence(false);

    tokio::time::sleep(Duration::from_millis(1100)).await;
    let before = failing.queries();
    let tried = ask(&engine, &query("try.dead.test."), client(1)).await;
    assert_eq!(rcode(&tried), ResponseCode::ServFail);
    let sent = failing.queries();
    assert!(sent > before, "the try is sent upstream");
    let next = ask(&engine, &query("next.dead.test."), client(1)).await;
    assert_eq!(rcode(&next), ResponseCode::ServFail);
    assert_eq!(failing.queries(), sent, "still held back");
}

/// 规则写了两个上游、两个都回了失败应答时也一样：上游是回了的，不记没回答。两个上游都过 300 毫秒才回 SERVFAIL，一台设备
/// 问了一百个，下一个照样发给上游
/// The same where a rule writes two upstreams and both reply with a failure: the upstreams did
/// reply, and it is not noted as no answer. With both replying SERVFAIL only after 300 ms, a
/// hundred names from one device and the next still goes upstream
#[tokio::test]
async fn failure_replies_from_every_upstream_of_a_rule_do_not_hold_a_device_back() {
    let one = failing_upstream(Duration::from_millis(300)).await;
    let other = failing_upstream(Duration::from_millis(300)).await;
    let good = answering_upstream(ANSWER, 300).await;
    let both = format!("{},{}", one.address, other.address);
    let engine = Arc::new(engine_from(json!({
        "settings": counting_settings(json!({
            "flow_control_enabled": true,
            "upstream_timeout_ms": 1000,
        })),
        "pipelines": [{ "id": "main", "rules": [
            { "name": "dead", "matchers": [{ "type": "domain_suffix", "value": "dead.test" }],
              "actions": [{ "type": "forward", "upstream": both }] },
            { "name": "rest", "matchers": [{ "type": "any" }],
              "actions": [{ "type": "forward", "upstream": good.address }] },
        ]}]
    })));
    know_answers_are_quick(&engine).await;
    ask_dead_names(&engine, client(1), "a", 100).await;
    let sent = one.queries();
    ask_dead_names(&engine, client(1), "b", 1).await;
    assert!(one.queries() > sent, "still sent upstream");
}

/// 等别的设备正在做的转发，不记进「设备、上游」的结果：这个查询自己没有问上游。一台设备的 70 个查询都等在另一台设备
/// 对着不回答的上游做的转发上，跟着等到上游超时，之后它自己问这个上游的照常发出去
/// A wait on a forward another device is making is not noted for the device and upstream: the
/// query asked no upstream itself. With 70 queries of one device waiting on another device's
/// forwards to an upstream that does not answer, out to the upstream's timeout with them, what
/// it then asks of that upstream itself goes out as usual
#[tokio::test]
async fn waits_on_another_devices_forwards_are_not_noted_against_the_upstream() {
    let dead = support::upstream(|_| Vec::new()).await;
    let good = answering_upstream(ANSWER, 300).await;
    // 上游时限 600 毫秒：领头的 70 个查询在途这么久，另一台设备的查询有足够的时间等上去
    // An upstream timeout of 600 ms: the 70 leading queries stay in flight that long, time
    // enough for the other device's queries to come and wait on them
    let engine = engine(&dead, &good, true, 600);
    know_answers_are_quick(&engine).await;
    let had = dead.queries();
    let leaders = {
        let engine = Arc::clone(&engine);
        tokio::spawn(async move { ask_dead_names(&engine, client(2), "same", 70).await })
    };
    sent_to(&dead, had + 70).await;
    let before = dead.queries();
    ask_dead_names(&engine, client(1), "same", 70).await;
    leaders.await.unwrap();
    // 重发是领头的那些自己做的 / The resends are the leaders' own
    assert!(
        dead.queries() <= before + 70,
        "the waiting device sent nothing itself"
    );
    let sent = dead.queries();
    ask_dead_names(&engine, client(1), "own", 1).await;
    assert!(dead.queries() > sent, "not held back: sent upstream");
}

/// 被拦着的设备照样能等别的设备正在做的转发，等到了回答就拿到；这不算它自己问到了回答，它接着问这个上游的还是拦着
/// A device held back can still wait on a forward another device is making and takes the
/// answer when it comes; that is no answer to a query of its own, and what it goes on to ask
/// of that upstream is still held back
#[tokio::test]
async fn a_held_back_device_waits_on_another_devices_forward_and_stays_held_back() {
    // 上游 300 毫秒后才答：领头的查询在途这么久，被拦着的设备有足够的时间等上去；上游时限 1200 毫秒，领头的
    // 400 毫秒才重发，在那之前已经答了
    // The upstream answers after 300 ms: the leading query stays in flight that long, time
    // enough for the held-back device to come and wait on it; with an upstream timeout of
    // 1200 ms the leader resends only at 400 ms, by when it has been answered
    let slow = support::answering_upstream_after(ANSWER, 300, Duration::from_millis(300)).await;
    slow.silence(true);
    let good = answering_upstream(ANSWER, 300).await;
    let engine = engine(&slow, &good, true, 1200);
    know_answers_are_quick(&engine).await;
    ask_dead_names(&engine, client(1), "a", 64).await;
    slow.silence(false);

    let had = slow.queries();
    let leader = {
        let engine = Arc::clone(&engine);
        tokio::spawn(async move { ask(&engine, &query("same.dead.test."), client(2)).await })
    };
    sent_to(&slow, had + 1).await;
    let sent = slow.queries();
    let joined = ask(&engine, &query("same.dead.test."), client(1)).await;
    assert_eq!(
        first_a(&joined),
        Some(ANSWER),
        "answered through the other's forward"
    );
    assert_eq!(slow.queries(), sent, "it waited and sent nothing itself");
    assert_eq!(first_a(&leader.await.unwrap()), Some(ANSWER));
    let next = ask(&engine, &query("next.dead.test."), client(1)).await;
    assert_eq!(rcode(&next), ResponseCode::ServFail, "still held back");
    assert_eq!(slow.queries(), sent, "and not sent upstream");
}

/// 流控没让等的请求此后得到的应答都不进缓存：缓存是所有设备共用的。规则在上游失败时回一个固定地址、改问备用上游、continue 到
/// 后面问备用上游的规则、跳到问备用上游的规则组，四种写法都一样：一台设备被拦住以后问一个新名字，拿到备用的答案；另一台设备
/// 接着问同一个名字，照常去问上游、拿到上游的回答，不是缓存里备用的答案。以前只有固定地址不进缓存，备用上游的回答照常写进去：
/// 一台被拦着的设备问过哪个名字，哪个名字在缓存有效期里对所有设备都换成了备用上游的答案
/// Nothing a request gets once flow control kept it from waiting goes into the cache, which
/// all devices share. With a rule that on an upstream failure answers a fixed address, asks a
/// fallback upstream, continues to a later rule asking the fallback, or jumps to a pipeline
/// asking it, all four alike: a device held back asks a new name and gets the fallback's
/// answer; another device asking the same name next goes to the upstream as usual and gets its
/// answer, not the fallback's out of the cache. Only the fixed address used to stay out of the
/// cache while a fallback upstream's answer went in as usual: every name a device held back
/// asked became the fallback upstream's answer for all devices for as long as the entry lived
#[tokio::test]
async fn what_a_held_back_device_gets_is_not_cached_for_others() {
    let fixed = Ipv4Addr::new(192, 0, 2, 99);
    let fallback = answering_upstream(fixed, 300).await;
    let asking_the_fallback = json!([{ "type": "forward", "upstream": fallback.address }]);
    // 最后一项：上游真的没回答时，备用的答案进不进这条规则的缓存。跳到别的规则组得到的回答记在那个规则组名下，不在这里
    // The last of each: whether, with the upstream truly not answering, the fallback's answer
    // goes into this rule's cache. What a jump to another pipeline gets is kept under that
    // pipeline, not here
    let on_failure = [
        (
            "a fixed address",
            json!([{ "type": "static_ip_response", "ip": fixed.to_string() }]),
            true,
        ),
        ("a fallback upstream", asking_the_fallback.clone(), true),
        ("a later rule", json!([{ "type": "continue" }]), true),
        (
            "another pipeline",
            json!([{ "type": "jump_to_pipeline", "pipeline": "fallback" }]),
            false,
        ),
    ];
    for (which, actions, cached_here) in on_failure {
        let upstream = answering_upstream(ANSWER, 300).await;
        upstream.silence(true);
        let engine = Arc::new(engine_from(json!({
            "settings": counting_settings(json!({
                "flow_control_enabled": true,
                "upstream_timeout_ms": 150,
                "min_ttl": 60,
            })),
            "pipelines": [
                { "id": "main", "rules": [
                    { "name": "all", "matchers": [{ "type": "any" }],
                      "actions": [{ "type": "forward", "upstream": upstream.address }],
                      "response_actions_on_miss": actions },
                    { "name": "later", "matchers": [{ "type": "any" }], "actions": asking_the_fallback },
                ]},
                { "id": "fallback", "rules": [
                    { "name": "all", "matchers": [{ "type": "any" }], "actions": asking_the_fallback },
                ]},
            ]
        })));
        let held: Vec<_> = (0..64)
            .map(|n| {
                let engine = Arc::clone(&engine);
                let packet = query(&format!("held{n}.test."));
                tokio::spawn(async move { ask(&engine, &packet, client(1)).await })
            })
            .collect();
        for one in held {
            assert_eq!(first_a(&one.await.unwrap()), Some(fixed), "{which}");
        }
        upstream.silence(false);

        let sent = upstream.queries();
        let withheld = ask(&engine, &query("fresh.test."), client(1)).await;
        assert_eq!(
            first_a(&withheld),
            Some(fixed),
            "{which}: what the rules give on a failure"
        );
        assert_eq!(
            upstream.queries(),
            sent,
            "{which}: held back, not sent upstream"
        );
        let other = ask(&engine, &query("fresh.test."), client(2)).await;
        assert_eq!(
            first_a(&other),
            Some(ANSWER),
            "{which}: the upstream's own answer"
        );
        // 上游真的没回答时备用的答案照常进缓存：那 64 个名字别的设备问到的也是它，不再去问上游
        // With the upstream truly not answering the fallback's answer is cached as usual:
        // another device asking one of those 64 names gets it too, the upstream not asked again
        if cached_here {
            let sent = upstream.queries();
            let cached = ask(&engine, &query("held7.test."), client(2)).await;
            assert_eq!(first_a(&cached), Some(fixed), "{which}: cached");
            assert_eq!(upstream.queries(), sent, "{which}: out of the cache");
        }
    }
}
