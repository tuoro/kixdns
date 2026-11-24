//! 建连、老化和连接池的测试 / Tests of connecting, aging and pools

use super::*;
use futures::future;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::timeout;

/// 建连失败以后的退避按 tokio 的时钟算，和老化一样：暂停的时钟推过退避，下一次就去连
/// The backing off after a failed connect runs on tokio's clock, as aging does: with the
/// paused clock moved past it, the next connect is made
#[tokio::test(start_paused = true)]
async fn backing_off_runs_on_tokio_clock() {
    let refused = |_| async { Err::<(), _>(anyhow::anyhow!("refused")) };
    let mut connect = Connect::default();
    let attempt = connect.attempt(refused).expect("the first connect is made");
    assert!(attempt.await.is_err());
    assert!(connect.attempt(refused).is_err(), "backing off");
    tokio::time::advance(CONNECT_BACKOFF + Duration::from_millis(1)).await;
    assert!(connect.attempt(refused).is_ok(), "connects again past it");
}

/// 退避期间的错误说着上一次建连为什么失败、多久以前，还要等多久再连：拒绝、证书不对、RST 这样很快的失败几乎都落在
/// 退避里，抽样记下的多半是这一句
/// An error while backing off tells why the last connect failed and how long ago, and how long
/// until the next: fast failures (refused, a bad certificate, a reset) mostly fall within the
/// backing off, so this is mostly the line a sampled log keeps
#[tokio::test(start_paused = true)]
async fn backing_off_tells_why_the_last_connect_failed() {
    let refused = |_| async { Err::<(), _>(anyhow::anyhow!("connect 192.0.2.1:853: refused")) };
    let mut connect = Connect::default();
    let attempt = connect.attempt(refused).expect("the first connect is made");
    assert!(attempt.await.is_err());
    tokio::time::advance(Duration::from_millis(100)).await;
    let err = connect.attempt(refused).expect_err("backing off");
    assert_eq!(
        err.to_string(),
        "connect failed 100ms ago: connect 192.0.2.1:853: refused; trying again in 150ms"
    );
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
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let started = tokio::time::Instant::now();
    let pending_at_a = |address| async move {
        if address == a {
            std::future::pending::<anyhow::Result<SocketAddr>>().await
        } else {
            Ok(address)
        }
    };
    let connected = staggered(vec![a, b], deadline, pending_at_a, future::ok)
        .await
        .expect("the second connects");
    assert_eq!((connected, started.elapsed()), (b, ATTEMPT_DELAY));

    let started = tokio::time::Instant::now();
    let refused_at_a = |address| async move {
        anyhow::ensure!(address != a, "{address} refused");
        Ok(address)
    };
    let connected = staggered(vec![a, b], deadline, refused_at_a, future::ok)
        .await
        .expect("the second connects");
    assert_eq!((connected, started.elapsed()), (b, Duration::ZERO));

    let refused = |_| async move { Err::<SocketAddr, _>(anyhow::anyhow!("refused")) };
    let failed = staggered(vec![a, b], deadline, refused, future::ok)
        .await
        .expect_err("none connects");
    assert_eq!(
        failed.to_string(),
        format!("connect {a}: refused; connect {b}: refused")
    );
}

/// 连上了地址、握手还没完：从连上的那一刻起再给握手一个 [`ATTEMPT_DELAY`]，下一个地址才起。往返 200 ms 的链路上 TCP 200 ms
/// 连上、TLS 再要 200 ms：只连一个地址，400 ms 握手完；握手不回的，TCP 连上 250 ms 以后连下一个。以前 TCP 和 TLS 算在同一个
/// 250 ms 里，往返超过 125 ms 的链路上每次建连都多起一路握手
/// An address reached and its handshake not through yet: the handshake is given another
/// [`ATTEMPT_DELAY`] from the moment it was reached before the next address starts. On a path of
/// a 200 ms round trip TCP takes 200 ms and TLS 200 ms more: one address alone is dialled, through
/// its handshake at 400 ms; with the handshake never answered, the next is dialled 250 ms after
/// TCP was through. TCP and TLS used to count in the one 250 ms, so on a path with a round trip
/// over 125 ms every connect started a handshake more
#[tokio::test(start_paused = true)]
async fn a_handshake_has_its_own_attempt_delay() {
    let (a, b): (SocketAddr, SocketAddr) = (
        "192.0.2.1:853".parse().unwrap(),
        "[2001:db8::1]:853".parse().unwrap(),
    );
    let round_trip = Duration::from_millis(200);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let dialled = std::sync::Mutex::new(Vec::new());
    let reach = |address| {
        dialled.lock().unwrap().push(address);
        async move {
            tokio::time::sleep(round_trip).await;
            Ok(address)
        }
    };

    let started = tokio::time::Instant::now();
    let shake = |address| async move {
        tokio::time::sleep(round_trip).await;
        Ok(address)
    };
    let connected = staggered(vec![a, b], deadline, reach, shake)
        .await
        .expect("the first connects");
    assert_eq!((connected, started.elapsed()), (a, 2 * round_trip));
    assert_eq!(*dialled.lock().unwrap(), [a], "the second never dialled");

    dialled.lock().unwrap().clear();
    let started = tokio::time::Instant::now();
    let silent_at_a = |address| async move {
        if address == a {
            std::future::pending::<anyhow::Result<SocketAddr>>().await
        } else {
            Ok(address)
        }
    };
    let connected = staggered(vec![a, b], deadline, reach, silent_at_a)
        .await
        .expect("the second connects");
    assert_eq!(
        (connected, started.elapsed()),
        (b, round_trip + ATTEMPT_DELAY + round_trip)
    );
    assert_eq!(*dialled.lock().unwrap(), [a, b]);
}

/// 到了建连的期限还没连上：已经失败的照列，还在连的记成多久没回应，看得出是哪些地址。以前外层的时限先到，连过的地址和
/// 攒下的失败一起丢掉，只剩「connect timeout after 5000ms」（DoQ 握手不回的那种见 doq 的测试
/// `a_doq_handshake_left_unanswered_names_the_address`）
/// Not through by the connect's deadline: those failed are reported as ever and those still
/// connecting as unanswered for so long, showing which addresses they were. The outer time limit
/// used to come first, dropping the addresses dialled along with the failures gathered, leaving
/// "connect timeout after 5000ms" alone (see the DoQ test
/// `a_doq_handshake_left_unanswered_names_the_address` for a DoQ handshake never answered)
#[tokio::test(start_paused = true)]
async fn attempts_still_connecting_at_the_deadline_are_named() {
    let [a, b, c]: [SocketAddr; 3] =
        ["192.0.2.1:53", "192.0.2.2:53", "192.0.2.3:53"].map(|address| address.parse().unwrap());
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    let refused_at_b = |address| async move {
        anyhow::ensure!(address != b, "refused");
        std::future::pending::<anyhow::Result<()>>().await
    };
    let failed = staggered(vec![a, b, c], deadline, refused_at_b, future::ok)
        .await
        .expect_err("none connects");
    // a 一开始就连，b 过了 ATTEMPT_DELAY 才连、马上失败，c 紧跟着连 / a is dialled at once, b after
    // ATTEMPT_DELAY failing at once, and c straight after
    assert_eq!(
        failed.to_string(),
        format!(
            "connect {b}: refused; connect {a}: no answer in 1000ms; connect {c}: no answer in 750ms"
        )
    );
}
