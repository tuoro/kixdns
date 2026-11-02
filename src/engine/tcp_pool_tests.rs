//! 配置里写明的 TCP 上游启动时就建好连接池（见 `TcpMultiplexer::warm_up_pools`），大小和发送时现建
//! 的一样，是 `tcp_pool_size`；平常只用池里的第一条连接，忙了才用后面的（见 `transport::BUSY_AT`）。
//! The TCP upstreams a configuration names get their pools at start-up (see
//! `TcpMultiplexer::warm_up_pools`), as large as one built on first send: `tcp_pool_size`;
//! normally only the pool's first connection is used, the later ones once it is busy (see
//! `transport::BUSY_AT`).

use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::engine::test_support::{self as support, counting_settings, engine_from, peer};
use crate::engine::transport::{BUSY_AT, TcpMultiplexer};

/// 本机 TCP 上游：每个查询过 `after` 置上 QR 位原样答回；返回它的地址和收到的连接数
/// A local TCP upstream answering each query with itself, QR set, after `after`; its address
/// and the number of connections it accepted
async fn tcp_upstream(after: Duration) -> (String, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let connections = Arc::new(AtomicUsize::new(0));
    let counted = connections.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            counted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let (mut reader, writer) = stream.into_split();
                let writer = Arc::new(tokio::sync::Mutex::new(writer));
                let mut len = [0u8; 2];
                while reader.read_exact(&mut len).await.is_ok() {
                    let mut frame = vec![0u8; u16::from_be_bytes(len) as usize];
                    if reader.read_exact(&mut frame).await.is_err() {
                        return;
                    }
                    frame[2] |= 0x80;
                    let writer = Arc::clone(&writer);
                    tokio::spawn(async move {
                        tokio::time::sleep(after).await;
                        let mut writer = writer.lock().await;
                        let _ = writer.write_all(&len).await;
                        let _ = writer.write_all(&frame).await;
                    });
                }
            });
        }
    });
    (address, connections)
}

fn query(name: &str) -> Vec<u8> {
    let mut request = Message::new(0x5157, MessageType::Query, OpCode::Query);
    request.metadata.recursion_desired = true;
    request.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
    request.to_vec().unwrap()
}

/// 两个连接的池：第一条连接忙起来以后，再来的查询上第二条。以前预热只建 1 个客户端，发送时又不再扩大，
/// 配置里的 TCP 上游整个运行期只有 1 条连接
/// A pool of two: once the first connection is busy, further queries go on the second. The
/// warm-up used to build a single client that sending never grew, so a TCP upstream in the
/// configuration had one connection for as long as the kernel ran
#[tokio::test]
async fn a_tcp_upstream_in_the_config_gets_the_whole_pool() {
    let (address, connections) = tcp_upstream(Duration::from_millis(200)).await;
    let engine = engine_from(json!({
        "settings": counting_settings(json!({ "tcp_pool_size": 2 })),
        "pipelines": [{ "id": "main", "rules": [{
            "name": "all", "matchers": [{ "type": "any" }],
            "actions": [{ "type": "forward", "upstream": address, "transport": "tcp" }]
        }] }]
    }));
    let packets: Vec<Vec<u8>> = (0..=BUSY_AT)
        .map(|index| query(&format!("q{index}.example.")))
        .collect();
    futures::future::join_all(
        packets
            .iter()
            .map(|packet| support::ask(&engine, packet, peer())),
    )
    .await;
    assert_eq!(
        connections.load(Ordering::SeqCst),
        2,
        "each client of the pool opens its own connection"
    );
}

/// 平常只用池里的第一条连接：一个接一个的查询，和一阵子同时到、但没多到让它忙起来的查询，都在它上面，后面
/// 的不去连。以前一个查询轮一条，64 条的池里每条隔 64 个查询才轮到一次，查询稀疏时早过了空闲时限，几乎每个
/// 查询都要新建连接（DoT 还要握手）
/// Normally only the pool's first connection is used: queries one after another, and a burst of
/// them at once that is not enough to make it busy, all go on it, and the later ones do not
/// connect. Each query used to take the next connection, so in a pool of 64 each came round once
/// every 64 queries; with sparse queries that was long past the idle limit, and nearly every
/// query opened a new connection (DoT with a handshake too)
#[tokio::test]
async fn light_load_stays_on_one_connection() {
    let (address, connections) = tcp_upstream(Duration::from_millis(20)).await;
    let mux = TcpMultiplexer::new(4, 3, 0, 0);
    for index in 0..10 {
        mux.send(
            &query(&format!("one{index}.example.")),
            &address,
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    }
    let burst = (1..BUSY_AT).map(|index| {
        let (mux, address, packet) = (&mux, &address, query(&format!("burst{index}.example.")));
        async move { mux.send(&packet, address, Duration::from_secs(5)).await }
    });
    for answer in futures::future::join_all(burst).await {
        answer.unwrap();
    }
    assert_eq!(connections.load(Ordering::SeqCst), 1);
}

/// 第一条连接上同时在途的查询到了 `BUSY_AT` 个，再来的上第二条，那条也忙了再上第三条
/// Once the first connection has `BUSY_AT` queries in flight, further ones go on the second,
/// and once that is busy too, on the third
#[tokio::test]
async fn a_busy_connection_spills_to_the_next() {
    let (address, connections) = tcp_upstream(Duration::from_millis(200)).await;
    let mux = TcpMultiplexer::new(4, 3, 0, 0);
    let many = (0..2 * BUSY_AT + BUSY_AT / 2).map(|index| {
        let (mux, address, packet) = (&mux, &address, query(&format!("many{index}.example.")));
        async move { mux.send(&packet, address, Duration::from_secs(5)).await }
    });
    for answer in futures::future::join_all(many).await {
        answer.unwrap();
    }
    assert_eq!(connections.load(Ordering::SeqCst), 3);
}
