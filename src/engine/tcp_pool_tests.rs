//! 配置里写明的 TCP 上游启动时就建好连接池（见 `TcpMultiplexer::warm_up_pools`），大小和发送时现建
//! 的一样，是 `tcp_pool_size`；同一轮里的查询都上池里的同一条连接。
//! The TCP upstreams a configuration names get their pools at start-up (see
//! `TcpMultiplexer::warm_up_pools`), as large as one built on first send: `tcp_pool_size`;
//! the queries of one round all go on the same connection of the pool.

use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::engine::test_support::{self as support, counting_settings, engine_from, peer};
use crate::engine::transport::TcpMultiplexer;

/// 本机 TCP 上游：把每个查询置上 QR 位原样答回 / A local TCP upstream answering each query with itself, QR set
struct TcpUpstream {
    address: String,
    /// 收到的连接数 / The connections it accepted
    connections: Arc<AtomicUsize>,
    /// 每条连接收到的查询数，按接受的先后 / The queries each connection brought, in the order accepted
    queries: Arc<std::sync::Mutex<Vec<usize>>>,
}

async fn tcp_upstream() -> TcpUpstream {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let connections = Arc::new(AtomicUsize::new(0));
    let queries = Arc::new(std::sync::Mutex::new(Vec::new()));
    let (counted, seen) = (Arc::clone(&connections), Arc::clone(&queries));
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            counted.fetch_add(1, Ordering::SeqCst);
            let index = {
                let mut seen = seen.lock().unwrap();
                seen.push(0);
                seen.len() - 1
            };
            let seen = Arc::clone(&seen);
            tokio::spawn(async move {
                let mut len = [0u8; 2];
                while stream.read_exact(&mut len).await.is_ok() {
                    let mut frame = vec![0u8; u16::from_be_bytes(len) as usize];
                    if stream.read_exact(&mut frame).await.is_err() {
                        return;
                    }
                    seen.lock().unwrap()[index] += 1;
                    frame[2] |= 0x80;
                    let _ = stream.write_all(&len).await;
                    let _ = stream.write_all(&frame).await;
                }
            });
        }
    });
    TcpUpstream {
        address,
        connections,
        queries,
    }
}

fn query(name: &str) -> Vec<u8> {
    let mut request = Message::new(0x5157, MessageType::Query, OpCode::Query);
    request.metadata.recursion_desired = true;
    request.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
    request.to_vec().unwrap()
}

/// 两个连接的池：先后两个查询轮到两个客户端，各用一条连接。以前预热只建 1 个客户端，发送时又不再
/// 扩大，配置里的 TCP 上游整个运行期只有 1 条连接
/// A pool of two: two queries in turn go to its two clients, one connection each. The
/// warm-up used to build a single client that sending never grew, so a TCP upstream in
/// the configuration had one connection for as long as the kernel ran
#[tokio::test]
async fn a_tcp_upstream_in_the_config_gets_the_whole_pool() {
    let TcpUpstream {
        address,
        connections,
        ..
    } = tcp_upstream().await;
    let engine = engine_from(json!({
        "settings": counting_settings(json!({ "tcp_pool_size": 2 })),
        "pipelines": [{ "id": "main", "rules": [{
            "name": "all", "matchers": [{ "type": "any" }],
            "actions": [{ "type": "forward", "upstream": address, "transport": "tcp" }]
        }] }]
    }));
    for name in ["a.example.", "b.example."] {
        support::ask(&engine, &query(name), peer()).await;
    }
    assert_eq!(
        connections.load(Ordering::SeqCst),
        2,
        "each client of the pool opens its own connection"
    );
}

/// 同一轮里的查询都上池里的同一条连接，一次写出去；这一批写走了，下一个查询才轮到下一条连接。以前一个接
/// 一个轮流分，64 条连接的池里同一轮的查询各占一条，各写一次。一个工作线程，查询都从这个线程上起，和收到
/// 一批查询时一样
/// The queries of one round all go on the same connection of the pool and out in one write;
/// only once that batch is written does the next query move on to the next connection. They
/// used to be dealt out in turn, so in a pool of 64 each query of a round had a connection
/// and a write of its own. One worker thread, with the queries started on it, as when a batch
/// of queries arrives
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn a_round_of_queries_shares_one_connection() {
    let upstream = tcp_upstream().await;
    let mux = Arc::new(TcpMultiplexer::new(4, 3, 0, 0));
    // 一个接一个问四次：每次都轮到下一个客户端，四条连接都连好 / Four queries one after
    // another: each moves on to the next client, so all four connections are made
    for index in 0..4 {
        mux.send(
            &query(&format!("warm{index}.example.")),
            &upstream.address,
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    }
    assert_eq!(upstream.connections.load(Ordering::SeqCst), 4);
    let before = upstream.queries.lock().unwrap().clone();

    let (asking, address) = (Arc::clone(&mux), upstream.address.clone());
    tokio::spawn(async move {
        let asked: Vec<_> = (0..8)
            .map(|index| {
                let (mux, address) = (Arc::clone(&asking), address.clone());
                tokio::spawn(async move {
                    mux.send(
                        &query(&format!("q{index}.example.")),
                        &address,
                        Duration::from_secs(5),
                    )
                    .await
                })
            })
            .collect();
        for answer in futures::future::join_all(asked).await {
            answer.unwrap().unwrap();
        }
    })
    .await
    .unwrap();
    let after = upstream.queries.lock().unwrap().clone();
    let grew: Vec<usize> = after
        .iter()
        .zip(&before)
        .map(|(after, before)| after - before)
        .collect();
    assert_eq!(grew.iter().filter(|&&n| n > 0).count(), 1, "{grew:?}");
    assert_eq!(upstream.connections.load(Ordering::SeqCst), 4);
}
