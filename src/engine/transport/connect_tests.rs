//! 建连、老化和连接池的测试 / Tests of connecting, aging and pools

use super::*;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::timeout;

/// 建连失败以后的退避按 tokio 的时钟算，和老化一样：暂停的时钟推过退避，下一次就去连
/// The backing off after a failed connect runs on tokio's clock, as aging does: with the
/// paused clock moved past it, the next connect is made
#[tokio::test(start_paused = true)]
async fn backing_off_runs_on_tokio_clock() {
    let refused = || async { Err::<(), _>(anyhow::anyhow!("refused")) };
    let mut connect = Connect::default();
    let attempt = connect.attempt(refused).expect("the first connect is made");
    assert!(attempt.await.is_err());
    assert!(connect.attempt(refused).is_err(), "backing off");
    tokio::time::advance(CONNECT_BACKOFF + Duration::from_millis(1)).await;
    assert!(connect.attempt(refused).is_ok(), "connects again past it");
}

/// 连接活满最长时间、或者最晚的期限过后空闲满时限就用旧了，看哪个先到；中途来的查询把空闲往后推，用旧的时刻按单调时钟
/// 算；都不限时一直不会用旧
/// A connection is worn once it has lived its max age, or sat idle its limit past the latest
/// deadline, whichever comes first; a query coming meanwhile puts idleness later, and the
/// moment counts on the monotonic clock; with neither limited it never wears out
#[tokio::test(start_paused = true)]
async fn a_connection_wears_out_by_age_or_idleness_whichever_comes_first() {
    let second = Duration::from_secs(1);
    let started = tokio::time::Instant::now();
    let (wear, aging) = (Wear::new(), Aging::new(1800 * second, 60 * second));
    wear.note(started + 2 * second);
    let (why, ()) = tokio::join!(aging.worn(&wear), async {
        tokio::time::sleep(30 * second).await;
        wear.note(tokio::time::Instant::now() + 2 * second);
    });
    assert_eq!((why, started.elapsed()), ("idle", 92 * second));

    let (started, wear) = (tokio::time::Instant::now(), Wear::new());
    let why = Aging::new(10 * second, 60 * second).worn(&wear).await;
    assert_eq!((why, started.elapsed()), ("too old", 10 * second));

    let never = Aging::new(Duration::ZERO, Duration::ZERO);
    assert!(timeout(3600 * second, never.worn(&wear)).await.is_err());
}

/// 配置写了极大的时限（比如 u64::MAX 秒，想表示永不）：那个时限不限，另一个照样起作用。时钟表示不了那么远，
/// 照直加上去会 panic，每条 TCP、DoT 连接的写入任务一起来就死掉
/// A huge limit configured (u64::MAX seconds, say, meant as never) is no limit, while the
/// other still applies. The clock cannot hold a moment that far off, and adding it as it is
/// would panic, killing every TCP and DoT connection's writer as it starts
#[tokio::test(start_paused = true)]
async fn a_limit_too_far_off_for_the_clock_is_no_limit() {
    let (second, huge) = (Duration::from_secs(1), Duration::from_secs(u64::MAX));
    let (started, wear) = (tokio::time::Instant::now(), Wear::new());
    let why = Aging::new(huge, 60 * second).worn(&wear).await;
    assert_eq!((why, started.elapsed()), ("idle", 60 * second));

    let (started, wear) = (tokio::time::Instant::now(), Wear::new());
    let why = Aging::new(10 * second, huge).worn(&wear).await;
    assert_eq!((why, started.elapsed()), ("too old", 10 * second));

    let never = Aging::new(huge, huge);
    assert!(timeout(3600 * second, never.worn(&wear)).await.is_err());
}

/// 两族交替排开，第一个地址那一族在前，同一族里照原来的先后 / The families alternate, the first
/// address's family first, each family in its own order
#[test]
fn addresses_alternate_by_family() {
    let parse = |addresses: &[&str]| -> Vec<SocketAddr> {
        addresses
            .iter()
            .map(|address| address.parse().unwrap())
            .collect()
    };
    let (a, b, c) = ("192.0.2.1:53", "192.0.2.2:53", "192.0.2.3:53");
    let (x, y) = ("[2001:db8::1]:53", "[2001:db8::2]:53");
    assert_eq!(
        interleaved(parse(&[a, b, c, x, y])),
        parse(&[a, x, b, y, c])
    );
    assert_eq!(interleaved(parse(&[x, a, y, b])), parse(&[x, a, y, b]));
    assert_eq!(interleaved(parse(&[x, y, a])), parse(&[x, a, y]));
    assert!(interleaved(Vec::new()).is_empty());
}

/// 错开着连（RFC 8305）：第一个尝试不回应，过了 [`ATTEMPT_DELAY`] 才起第二个，用先连上的那个；一个失败了马上起下一个，
/// 不等；都失败时列出每个地址和它的失败。TCP、DoT、直连的 DoH 都经这里连（见 [`connect_tcp`]），DoQ 也是。以前 TCP、DoT
/// 一个个依次连，第一个不回应就等到建连的时限
/// Connecting staggered (RFC 8305): with the first attempt not answering, the second starts
/// only after [`ATTEMPT_DELAY`] and the first to connect is used; a failed attempt has the next
/// one started at once, with no wait; with all failed every address is reported with its
/// failure. TCP, DoT and direct DoH all connect through here (see [`connect_tcp`]), DoQ too. TCP
/// and DoT used to try one after another, waiting out the connect's time limit on a first one
/// not answering
#[tokio::test(start_paused = true)]
async fn attempts_are_staggered_and_a_failure_moves_on_at_once() {
    let (a, b): (SocketAddr, SocketAddr) = (
        "192.0.2.1:53".parse().unwrap(),
        "[2001:db8::1]:53".parse().unwrap(),
    );
    let started = tokio::time::Instant::now();
    let connected = staggered(vec![a, b], |address| async move {
        if address == a {
            std::future::pending::<anyhow::Result<SocketAddr>>().await
        } else {
            Ok(address)
        }
    })
    .await
    .expect("the second connects");
    assert_eq!((connected, started.elapsed()), (b, ATTEMPT_DELAY));

    let started = tokio::time::Instant::now();
    let connected = staggered(vec![a, b], |address| async move {
        anyhow::ensure!(address != a, "{address} refused");
        Ok(address)
    })
    .await
    .expect("the second connects");
    assert_eq!((connected, started.elapsed()), (b, Duration::ZERO));

    let failed = staggered(vec![a, b], |_| async move {
        Err::<SocketAddr, _>(anyhow::anyhow!("refused"))
    })
    .await
    .expect_err("none connects");
    assert_eq!(
        failed.to_string(),
        format!("connect {a}: refused; connect {b}: refused")
    );
}
