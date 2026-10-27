//! 配置里写明的 TCP 上游启动时就建好连接池（见 `TcpMultiplexer::warm_up_pools`），大小和发送时现建
//! 的一样，是 `tcp_pool_size`。
//! The TCP upstreams a configuration names get their pools at start-up (see
//! `TcpMultiplexer::warm_up_pools`), as large as one built on first send: `tcp_pool_size`.

use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::engine::test_support::{self as support, counting_settings, engine_from, peer};

/// 本机 TCP 上游：把每个查询置上 QR 位原样答回；返回它的地址和收到的连接数
/// A local TCP upstream answering each query with itself, QR set; its address and the
/// number of connections it accepted
async fn tcp_upstream() -> (String, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let connections = Arc::new(AtomicUsize::new(0));
    let counted = connections.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            counted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut len = [0u8; 2];
                while stream.read_exact(&mut len).await.is_ok() {
                    let mut frame = vec![0u8; u16::from_be_bytes(len) as usize];
                    if stream.read_exact(&mut frame).await.is_err() {
                        return;
                    }
                    frame[2] |= 0x80;
                    let _ = stream.write_all(&len).await;
                    let _ = stream.write_all(&frame).await;
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

/// 两个连接的池：先后两个查询轮到两个客户端，各用一条连接。以前预热只建 1 个客户端，发送时又不再
/// 扩大，配置里的 TCP 上游整个运行期只有 1 条连接
/// A pool of two: two queries in turn go to its two clients, one connection each. The
/// warm-up used to build a single client that sending never grew, so a TCP upstream in
/// the configuration had one connection for as long as the kernel ran
#[tokio::test]
async fn a_tcp_upstream_in_the_config_gets_the_whole_pool() {
    let (address, connections) = tcp_upstream().await;
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
