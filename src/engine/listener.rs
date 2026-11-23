//! 三个监听器（UDP、TCP、DoH）共用的部分：快速路径当场答什么（见 [`Engine::on_the_spot`]），要等上游的查询
//! 怎么在时限内答完。各监听器过载时怎么办、答不上的报文回不回，留在它们自己那里。
//! What the three listeners (UDP, TCP, DoH) share: what the fast path answers on the spot (see
//! [`Engine::on_the_spot`]), and how a query that waits on an upstream is answered within the
//! timeout. What each listener does under overload, and whether it answers a message nothing
//! can answer, stay with it.

use std::net::SocketAddr;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use tracing::debug;

use super::{Engine, FastPathResponse, PreParsedData, utils};
use crate::observe::ClientTransport;
use crate::proto_utils;

/// 把缓存命中的应答写进 `buf`（先清空）：TTL 按应答在缓存里停留的整秒数调低（RFC 1035 §5.2），
/// 事务 ID 换成这条查询的
/// Write a cache hit's answer into `buf` (cleared first): its TTLs lowered by the whole
/// seconds the answer sat in the cache (RFC 1035 §5.2), and the query's transaction ID
pub fn write_cache_hit(buf: &mut BytesMut, cached: &[u8], tx_id: u16, elapsed_secs: u32) {
    buf.clear();
    buf.extend_from_slice(cached);
    proto_utils::patch_all_ttls(buf, elapsed_secs);
    utils::set_id(buf, tx_id);
}

/// 快速路径对一个查询做了什么（见 [`Engine::on_the_spot`]）/ What the fast path did with a query (see
/// [`Engine::on_the_spot`])
pub enum OnTheSpot {
    /// 当场答了，应答写在给的缓冲里 / Answered on the spot, the answer written to the buffer given
    Answered,
    /// 要走完整路径（见 [`Engine::answer_after_fast_path`]），带着快速路径解析出的内容；快速解析读不了时为 None
    /// To take the full path (see [`Engine::answer_after_fast_path`]), with what the fast path
    /// parsed; None when the quick parse could not read it
    Forward(Option<PreParsedData>),
    /// 快速路径出了错（已经记下），连失败应答也构造不出（见
    /// `engine_helpers::try_build_listener_failure_from_wire`）：UDP、TCP 不回，DoH 总得回点什么
    /// The fast path failed (as logged), and not even a failure answer can be built (see
    /// `engine_helpers::try_build_listener_failure_from_wire`): UDP and TCP send nothing, while
    /// DoH has to answer something
    Unanswered,
}

impl Engine {
    /// 让快速路径当场处理 `packet`：答得上的（静态应答、缓存命中、出错时的失败应答）写进 `reply`（先清空），缓存命中
    /// 的 TTL 按它在缓存里停留的时间调低。三个监听器都从这里进来
    /// Let the fast path handle `packet` on the spot: what it can answer (a static answer, a cache
    /// hit, the failure answer for an error) is written to `reply` (cleared first), a cache hit's
    /// TTLs lowered by its time in the cache. All three listeners come in through here
    pub fn on_the_spot(&self, packet: &[u8], peer: SocketAddr, reply: &mut BytesMut) -> OnTheSpot {
        let answer = match self.handle_packet_fast(packet, peer) {
            Ok(Some(FastPathResponse::Direct(answer))) => answer,
            Ok(Some(FastPathResponse::CacheHit {
                cached,
                tx_id,
                elapsed_secs,
            })) => {
                write_cache_hit(reply, &cached, tx_id, elapsed_secs);
                return OnTheSpot::Answered;
            }
            Ok(Some(FastPathResponse::AsyncNeeded(pre_parsed))) => {
                return OnTheSpot::Forward(Some(pre_parsed));
            }
            Ok(None) => return OnTheSpot::Forward(None),
            Err(error) => {
                self.log_fast_path_error(&error);
                match utils::engine_helpers::try_build_listener_failure_from_wire(packet) {
                    Some(failure) => failure,
                    None => return OnTheSpot::Unanswered,
                }
            }
        };
        reply.clear();
        reply.extend_from_slice(&answer);
        OnTheSpot::Answered
    }

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
                    self.handle_packet_internal_with_pre_parsed(packet, peer, pre_parsed)
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
                crate::warn_sparse!(
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
    fn log_fast_path_error(&self, error: &anyhow::Error) {
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
