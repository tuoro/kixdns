//! 三个监听器（UDP、TCP、DoH）共用的部分：快速路径当场答什么（见 [`Engine::on_the_spot`]），要等上游的查询
//! 怎么在时限内答完、答不上回什么。各监听器过载时怎么办，留在它们自己那里。
//! What the three listeners (UDP, TCP, DoH) share: what the fast path answers on the spot (see
//! [`Engine::on_the_spot`]), and how a query that waits on an upstream is answered within the
//! timeout, and what when it cannot be. What each listener does under overload stays with it.

use std::net::SocketAddr;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use hickory_proto::rr::RecordType;
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
                Some(reply) => reply,
                None => return OnTheSpot::Drop,
            }
        };
        reply.clear();
        reply.extend_from_slice(&answer);
        OnTheSpot::Reply
    }

    /// 快速路径没能当场回答的查询：在整体请求时限内走完整处理，完整路径读得了的总有应答（见
    /// `Engine::handle_packet_full`）。`pre_parsed` 为 None 时快速解析没成，先从头读（见 `Engine::read_full`）；读不了的查询回
    /// FORMERR（RFC 6891 第 6.1.1 节，见 `proto_utils::formerr_reply`），读得了读不了在读的那一刻就定下了（见
    /// `UnreadableQuery`），不必为此再解析一遍；超时回 SERVFAIL（见 `proto_utils::servfail_reply`）。这两种各记一条日志
    /// A query the fast path could not answer on the spot: the full path within the overall
    /// request timeout, which always answers a query it can read (see
    /// `Engine::handle_packet_full`). With `pre_parsed` None the quick parse failed, and the query
    /// is read from scratch first (see `Engine::read_full`); a query that cannot be read gets
    /// FORMERR (RFC 6891 section 6.1.1, see `proto_utils::formerr_reply`), which was settled the
    /// moment it was read (see `UnreadableQuery`) with no second parse for it; a timeout gets
    /// SERVFAIL (see `proto_utils::servfail_reply`). Each of the two is logged
    pub async fn answer_after_fast_path(
        &self,
        packet: &[u8],
        peer: SocketAddr,
        pre_parsed: Option<PreParsedData>,
    ) -> Bytes {
        let listener = self.listener_name();
        let Ok(pre_parsed) = pre_parsed.map_or_else(|| self.read_full(packet, peer), Ok) else {
            debug!("{listener} query cannot be read, answering FORMERR");
            return proto_utils::formerr_reply(packet);
        };
        // 时限（含 hedge 与 TCP 回落）和告警里的上游超时都照请求自己的那份配置（见 [`PreParsedData`]）：请求里面等上游、等过期
        // 应答的刷新都按它定上限，外层的时限换成别的配置的，照它等着的应答就会被截成 SERVFAIL。重载以后来的查询照新配置
        // The time limit (hedge and TCP fallback included) and the upstream timeout in the
        // warning come from the request's own configuration (see [`PreParsedData`]): the waits
        // within the request, for an upstream or a stale answer's refresh, are bounded by it, and
        // an outer limit of another configuration would cut what they wait for into SERVFAIL.
        // Queries after a reload follow the new configuration
        let settings = pre_parsed.settings();
        let (timeout_ms, upstream_timeout_ms) =
            (settings.request_budget_ms(), settings.upstream_timeout_ms);
        tokio::time::timeout(
            Duration::from_millis(timeout_ms),
            self.handle_packet_full(packet, peer, pre_parsed),
        )
        .await
        .unwrap_or_else(|_| {
            // 每个监听器各算各的节流：UDP 上一直在超时，TCP、DoH 的超时照样看得见 / Each listener
            // throttles on its own: with UDP timing out all the time, TCP and DoH timeouts still show
            let (qname, qtype) = question_text(packet).unzip();
            crate::warn_sparse!(
                per listener;
                event = "request_timeout",
                timeout_ms,
                upstream_timeout_ms,
                qname = qname.map(tracing::field::display),
                qtype = qtype.map(tracing::field::debug),
                client_ip = %peer.ip(),
                "{listener} request timeout"
            );
            proto_utils::servfail_reply(packet)
        })
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

/// 日志里的问题：第一个问题的名字（写法同 [`proto_utils::name_text`]）和类型，一次读出，读不出时没有。只在记日志时读
/// The question for the logs: the first question's name (written as [`proto_utils::name_text`]
/// writes it) and type, read in one pass, and none when they cannot be read. It is read only
/// when logging
fn question_text(packet: &[u8]) -> Option<(String, RecordType)> {
    use hickory_proto::op::Query;
    use hickory_proto::serialize::binary::{BinDecodable, BinDecoder};
    let question = Query::read(&mut BinDecoder::new(packet).clone(12)).ok()?;
    Some((
        proto_utils::name_text(question.name()),
        question.query_type(),
    ))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::{Duration, Instant};

    use bytes::BytesMut;
    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::{Name, RecordType};
    use hickory_proto::serialize::binary::BinDecodable;
    use serde_json::{Value, json};

    use super::OnTheSpot;
    use crate::engine::test_support::{
        Warnings, answering_upstream, ask, counting_settings, engine_from, first_a, peer,
        silent_upstream,
    };
    use crate::engine::{Engine, PreParsedData};
    use crate::matcher::RuntimePipelineConfig;

    const ANSWER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

    /// 客户端等过期应答的刷新最多等这么久 / How long a client waits at most for a stale answer's refresh
    const CLIENT_WAIT: Duration = Duration::from_millis(600);

    fn query() -> Vec<u8> {
        let mut query = Message::new(0x4c4c, MessageType::Query, OpCode::Query);
        query.metadata.recursion_desired = true;
        query.add_query(Query::query(
            Name::from_ascii("xslow.test.").unwrap(),
            RecordType::A,
        ));
        query.to_vec().unwrap()
    }

    /// 快速解析读不了、要从头读的同一个查询：第一个标签以空格开头 / The same query, which the quick
    /// parse cannot read and which is read from scratch: its first label starts with a space
    fn query_read_from_scratch() -> Vec<u8> {
        let mut packet = query();
        packet[13] = b' ';
        packet
    }

    /// 全部转发给 `upstream`、设置照 `settings` 的配置 / A configuration forwarding everything to
    /// `upstream`, with `settings`
    fn forwarding(upstream: &str, settings: Value) -> Value {
        json!({
            "settings": counting_settings(settings),
            "pipelines": [{ "id": "main", "rules": [{
                "name": "all", "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": upstream }]
            }]}]
        })
    }

    fn reload(engine: &Engine, config: Value) {
        let config: crate::config::PipelineConfig = serde_json::from_value(config).unwrap();
        engine.reload(RuntimePipelineConfig::from_config(config).unwrap());
    }

    /// 快速路径交给完整路径的：读好的查询，快速解析读不了时为 None / What the fast path hands on to
    /// the full path: the query as read, None when the quick parse cannot read it
    fn handed_on(engine: &Engine, packet: &[u8]) -> Option<PreParsedData> {
        match engine.on_the_spot(packet, peer(), &mut BytesMut::new()) {
            OnTheSpot::Forward(pre_parsed) => pre_parsed,
            OnTheSpot::Reply | OnTheSpot::Drop => panic!("not handed on to the full path"),
        }
    }

    /// 快速路径之后、读时限之前重载成短得多的时限：请求照选它的那份配置等过期应答的刷新，等到头交出过期应答，不被新配置的
    /// 时限截成 SERVFAIL
    /// A reload to far shorter limits after the fast path and before the limit is read: the
    /// request waits for the stale answer's refresh as the configuration that picked it says,
    /// and hands out the stale answer when the wait is over, not cut into SERVFAIL by the new
    /// configuration's limit
    #[tokio::test]
    async fn a_reload_after_the_fast_path_still_serves_the_stale_answer() {
        let upstream = answering_upstream(ANSWER, 1).await;
        let config = |upstream_ms: u64, request_ms: u64| {
            forwarding(
                &upstream.address,
                json!({
                    "min_ttl": 0,
                    "serve_stale": true,
                    "serve_stale_client_timeout_ms": CLIENT_WAIT.as_millis() as u64,
                    "upstream_timeout_ms": upstream_ms,
                    "request_timeout_ms": request_ms
                }),
            )
        };
        let engine = engine_from(config(1000, 4000));
        assert_eq!(first_a(&ask(&engine, &query(), peer()).await), Some(ANSWER));
        upstream.silence(true);
        tokio::time::sleep(Duration::from_millis(1200)).await;

        let pre_parsed = handed_on(&engine, &query());
        assert!(
            pre_parsed.is_some(),
            "the stale answer waits on the refresh"
        );
        reload(&engine, config(200, 300));
        let started = Instant::now();
        let reply = engine
            .answer_after_fast_path(&query(), peer(), pre_parsed)
            .await;
        let took = started.elapsed();
        assert_eq!(first_a(&reply), Some(ANSWER), "the stale answer");
        assert!(
            took >= CLIENT_WAIT,
            "handed out after the wait, took {took:?}"
        );
    }

    /// 请求等着上游时重载成别的时限：到点照选它的那份配置回 SERVFAIL，告警里的整体时限和上游超时都是那份配置的。快速解析
    /// 读得了的查询和要从头读的一样
    /// A reload to other limits while the request waits on the upstream: it is answered
    /// SERVFAIL when the limit of the configuration that picked it runs out, and the warning's
    /// overall limit and upstream timeout are both that configuration's. A query the quick
    /// parse reads and one read from scratch alike
    #[tokio::test]
    async fn the_timeout_warning_names_the_limits_of_one_configuration() {
        // 上游从不回答：引擎先用 UDP 试、再改用 TCP，加起来比请求时限长，所以先到点的是监听器的计时 / The upstream never
        // answers: the engine tries UDP and then TCP, longer in all than the request timeout, so
        // the listener's timer runs out first
        let upstream = silent_upstream().await.to_string();
        let config = |upstream_ms: u64, request_ms: u64| {
            forwarding(
                &upstream,
                json!({
                    "upstream_timeout_ms": upstream_ms,
                    "request_timeout_ms": request_ms,
                    "enable_tcp_fallback": true
                }),
            )
        };
        let (warnings, guard) = Warnings::capture();
        for (case, packet) in [
            ("quick parse", query()),
            ("read from scratch", query_read_from_scratch()),
        ] {
            let engine = engine_from(config(300, 450));
            let pre_parsed = handed_on(&engine, &packet);
            assert_eq!(pre_parsed.is_some(), case == "quick parse", "{case}");
            let started = Instant::now();
            let (reply, ()) = tokio::join!(
                engine.answer_after_fast_path(&packet, peer(), pre_parsed),
                async {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    reload(&engine, config(1000, 3000));
                }
            );
            let took = started.elapsed();
            assert_eq!(
                Message::from_bytes(&reply).unwrap().metadata.response_code,
                ResponseCode::ServFail,
                "{case}"
            );
            assert!(
                took >= Duration::from_millis(450) && took < Duration::from_millis(1000),
                "{case} took {took:?}"
            );
        }
        drop(guard);
        let lines = warnings.lines();
        let of_one_configuration = lines
            .iter()
            .filter(|line| {
                line.contains("DNS request timeout")
                    && line.contains("timeout_ms=450 upstream_timeout_ms=300 ")
            })
            .count();
        assert_eq!(of_one_configuration, 2, "{lines:#?}");
    }
}
