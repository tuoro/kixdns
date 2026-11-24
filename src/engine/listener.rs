//! 三个监听器（UDP、TCP、DoH）共用的部分：快速路径当场答什么（见 [`Engine::on_the_spot`]），要等上游的查询
//! 怎么在时限内答完、答不上回什么。各监听器过载时怎么办，留在它们自己那里。
//! What the three listeners (UDP, TCP, DoH) share: what the fast path answers on the spot (see
//! [`Engine::on_the_spot`]), and how a query that waits on an upstream is answered within the
//! timeout, and what when it cannot be. What each listener does under overload stays with it.

use std::net::SocketAddr;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use tracing::debug;

use super::execution::UnreadableQuery;
use super::{Engine, FastPathResponse, PreParsedData, utils};
use crate::observe::ClientTransport;
use crate::proto_utils;

/// 把缓存命中的应答写进 `buf`（先清空）：TTL 按应答在缓存里停留的整秒数调低（RFC 1035 §5.2），
/// 事务 ID 换成这条查询的
/// Write a cache hit's answer into `buf` (cleared first): its TTLs lowered by the whole
/// seconds the answer sat in the cache (RFC 1035 §5.2), and the query's transaction ID
pub fn write_cache_hit(buf: &mut BytesMut, cached: &[u8], tx_id: u16, elapsed_secs: u32) {
    buf.clear();
    proto_utils::extend_aged(buf, cached, elapsed_secs);
    utils::set_id(buf, tx_id);
}

/// 快速路径对一个报文做了什么（见 [`Engine::on_the_spot`]）/ What the fast path did with a message (see
/// [`Engine::on_the_spot`])
pub enum OnTheSpot {
    /// 当场答了，回答写在给的缓冲里 / Answered on the spot, the answer written to the buffer given
    Reply,
    /// 要走完整路径（见 [`Engine::answer_after_fast_path`]），带着快速路径解析出的内容；快速解析读不了时为 None
    /// To take the full path (see [`Engine::answer_after_fast_path`]), with what the fast path
    /// parsed; None when the quick parse could not read it
    Forward(Option<PreParsedData>),
    /// 不回：应答（QR=1）和不足 12 字节的报文（见 `proto_utils::header_reply`）。UDP 丢掉，TCP 断开连接，DoH 回 400
    /// No answer: a response (QR=1) or a message under 12 bytes (see `proto_utils::header_reply`).
    /// UDP drops it, TCP closes the connection, DoH answers 400
    Drop,
}

impl Engine {
    /// 让快速路径当场处理 `packet`：答得上的写进 `reply`（先清空），缓存命中的 TTL 按它在缓存里停留的时间调低。答得上的有
    /// 静态应答、缓存命中、不支持的 EDNS 版本的 BADVERS、OPT 的选项不合规（选项结构不对、ECS 不合规，见
    /// `proto_utils::malformed_options`）的 FORMERR，以及请求头不是标准查询的 NOTIMP 和 FORMERR（见
    /// `proto_utils::header_reply`）。三个监听器都从这里进来
    /// Let the fast path handle `packet` on the spot: what it can answer is written to `reply`
    /// (cleared first), a cache hit's TTLs lowered by its time in the cache. It answers a static
    /// answer, a cache hit, the BADVERS for an unsupported EDNS version, the FORMERR for improper
    /// OPT options (an option malformed, an improper ECS, see `proto_utils::malformed_options`),
    /// and the NOTIMP and FORMERR for a header that is no standard query (see
    /// `proto_utils::header_reply`). All three listeners come in through here
    pub fn on_the_spot(&self, packet: &[u8], peer: SocketAddr, reply: &mut BytesMut) -> OnTheSpot {
        let answer = if proto_utils::is_standard_query_header(packet) {
            match self.handle_packet_fast(packet, peer) {
                Some(FastPathResponse::Direct(answer)) => answer,
                Some(FastPathResponse::CacheHit {
                    cached,
                    tx_id,
                    elapsed_secs,
                }) => {
                    write_cache_hit(reply, &cached, tx_id, elapsed_secs);
                    return OnTheSpot::Reply;
                }
                Some(FastPathResponse::AsyncNeeded(pre_parsed)) => {
                    return OnTheSpot::Forward(Some(pre_parsed));
                }
                // OPT 的选项不合规的查询快速解析不收，当场回 FORMERR（ECS 见 RFC 7871 第 6 节），不去问上游
                // A query with improper OPT options, which the quick parse does not take, is
                // answered FORMERR on the spot (for ECS, RFC 7871 section 6) rather than asked of
                // an upstream
                None if proto_utils::malformed_options(packet) => {
                    proto_utils::formerr_reply(packet)
                }
                None => return OnTheSpot::Forward(None),
            }
        } else {
            match proto_utils::header_reply(packet) {
                Some(refused) => refused,
                None => return OnTheSpot::Drop,
            }
        };
        reply.clear();
        reply.extend_from_slice(&answer);
        OnTheSpot::Reply
    }

    /// 快速路径没能当场回答的查询：在整体请求时限内走完整处理，完整路径读得了的总有应答（见
    /// `Engine::handle_packet_full`）。读不了的查询回 FORMERR（RFC 6891 第 6.1.1 节，见
    /// `proto_utils::formerr_reply`），读得了读不了在读的那一刻就定下了（见 [`UnreadableQuery`]），不必为此再解析一遍；超时
    /// 回 SERVFAIL（见 `proto_utils::servfail_reply`）。这两种各记一条日志。`pre_parsed` 为 None 时快速解析没成，从头解析。
    /// A query the fast path could not answer on the spot: the full path within the overall
    /// request timeout, which always answers a query it can read (see
    /// `Engine::handle_packet_full`). A query that cannot be read gets FORMERR (RFC 6891
    /// section 6.1.1, see `proto_utils::formerr_reply`), which was settled the moment it was
    /// read (see [`UnreadableQuery`]) with no second parse for it; a timeout gets SERVFAIL (see
    /// `proto_utils::servfail_reply`). Each of the two is logged. With `pre_parsed` None the
    /// quick parse failed, and the query is parsed from scratch.
    pub async fn answer_after_fast_path(
        &self,
        packet: &[u8],
        peer: SocketAddr,
        pre_parsed: Option<PreParsedData>,
    ) -> Bytes {
        // 每个查询重新取整体请求时限（含 hedge 与 TCP fallback）。RFC 7766 的客户端会把一条连接用
        // 很久，热重载改了 request_timeout 之后，这条连接上的后续查询必须跟着新值走。
        // Re-read the overall request timeout (hedge and TCP fallback included) per query. An
        // RFC 7766 client keeps one connection open for a long time, so queries that follow a
        // reload must use the new request_timeout.
        let timeout_ms = self.get_request_timeout_ms();
        let answered = tokio::time::timeout(Duration::from_millis(timeout_ms), async {
            match pre_parsed {
                Some(pre_parsed) => Ok(self.handle_packet_full(packet, peer, pre_parsed).await),
                None => self.handle_packet(packet, peer).await,
            }
        })
        .await;
        let listener = self.listener_name();
        match answered {
            Ok(Ok(answer)) => answer,
            Ok(Err(UnreadableQuery)) => {
                debug!("{listener} query cannot be read, answering FORMERR");
                proto_utils::formerr_reply(packet)
            }
            // 每个监听器各算各的节流：UDP 上一直在超时，TCP、DoH 的超时照样看得见 / Each listener
            // throttles on its own: with UDP timing out all the time, TCP and DoH timeouts still show
            Err(_) => {
                crate::warn_sparse!(
                    per listener;
                    timeout_ms,
                    upstream_timeout_ms = self.get_upstream_timeout_ms(),
                    qname = %question_text(packet).unwrap_or_default(),
                    client_ip = %peer.ip(),
                    "{listener} request timeout"
                );
                proto_utils::servfail_reply(packet)
            }
        }
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

/// 日志里的问题名：第一个问题的名字，写法同 [`proto_utils::name_text`]，读不出时没有。只在记日志时读
/// The question name for the logs: the first question's, written as [`proto_utils::name_text`]
/// writes it, and none when it cannot be read. It is read only when logging
fn question_text(packet: &[u8]) -> Option<String> {
    use hickory_proto::rr::Name;
    use hickory_proto::serialize::binary::{BinDecodable, BinDecoder};
    let name = Name::read(&mut BinDecoder::new(packet).clone(12)).ok()?;
    Some(proto_utils::name_text(&name))
}
