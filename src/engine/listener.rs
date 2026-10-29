//! 三个监听器（UDP、TCP、DoH）在快速路径之后共用的部分：缓存命中怎么写出来，要等上游的查询怎么在
//! 时限内答完。各监听器怎么构造 SERVFAIL、过载时怎么办，留在它们自己那里。
//! What the three listeners (UDP, TCP, DoH) share after the fast path: how a cache hit is
//! written out, and how a query that waits on an upstream is answered within the timeout.
//! How each listener builds its SERVFAIL, and what it does under overload, stay with it.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use tracing::{debug, warn};

use super::{Engine, PreParsedData, utils};
use crate::observe::ClientTransport;
use crate::proto_utils;

/// 把缓存命中的应答写进 `buf`（先清空）：TTL 按应答在缓存里停留的整秒数调低（RFC 1035 §5.2），
/// 事务 ID 换成这条查询的
/// Write a cache hit's answer into `buf` (cleared first): its TTLs lowered by the whole
/// seconds the answer sat in the cache (RFC 1035 §5.2), and the query's transaction ID
pub fn write_cache_hit(buf: &mut BytesMut, cached: &[u8], tx_id: u16, inserted_at: Instant) {
    buf.clear();
    buf.extend_from_slice(cached);
    proto_utils::patch_all_ttls(
        buf,
        proto_utils::saturating_u64_to_u32(inserted_at.elapsed().as_secs()),
    );
    utils::set_id(buf, tx_id);
}

impl Engine {
    /// 快速路径没能当场回答的查询：在整体请求时限内走完整处理。出错或超时时记一条日志、返回
    /// None，由监听器回它自己的 SERVFAIL。`pre_parsed` 为 None 时快速解析没成，从头解析。
    /// A query the fast path could not answer on the spot: the full path within the overall
    /// request timeout. On an error or a timeout it logs and returns None, and the listener
    /// answers its own SERVFAIL. With `pre_parsed` None the quick parse failed, and the query
    /// is parsed from scratch.
    pub async fn answer_after_fast_path(
        &self,
        packet: &[u8],
        peer: SocketAddr,
        pre_parsed: Option<PreParsedData>,
    ) -> Option<Bytes> {
        // 每个查询重新取整体请求时限（含 hedge 与 TCP fallback）。RFC 7766 的客户端会把一条连接用
        // 很久，热重载改了 request_timeout 之后，这条连接上的后续查询必须跟着新值走。
        // Re-read the overall request timeout (hedge and TCP fallback included) per query. An
        // RFC 7766 client keeps one connection open for a long time, so queries that follow a
        // reload must use the new request_timeout.
        let timeout_ms = self.get_request_timeout_ms();
        let answered = tokio::time::timeout(Duration::from_millis(timeout_ms), async {
            match pre_parsed {
                Some(pre_parsed) => {
                    self.handle_packet_internal_with_pre_parsed(packet, peer, false, pre_parsed)
                        .await
                }
                None => self.handle_packet(packet, peer).await,
            }
        })
        .await;
        let listener = self.listener_name();
        match answered {
            Ok(Ok(answer)) => return Some(answer),
            Ok(Err(error)) => {
                debug!(%error, "{listener} request processing error, returning SERVFAIL");
            }
            Err(_) => {
                warn!(
                    timeout_ms,
                    upstream_timeout_ms = self.get_upstream_timeout_ms(),
                    "{listener} request timeout"
                );
            }
        }
        None
    }

    /// 快速路径出错：记一条日志，由监听器回它自己的 SERVFAIL
    /// The fast path failed: log it, and the listener answers its own SERVFAIL
    pub fn log_fast_path_error(&self, error: &anyhow::Error) {
        debug!(
            %error,
            "{} fast-path error, returning SERVFAIL for valid query",
            self.listener_name()
        );
    }

    /// 日志里的监听器名 / The listener's name in the logs
    fn listener_name(&self) -> &'static str {
        match self.client_transport {
            Some(ClientTransport::Udp) => "UDP",
            Some(ClientTransport::Tcp) => "TCP",
            Some(ClientTransport::Doh) => "DoH",
            None => "DNS",
        }
    }
}
