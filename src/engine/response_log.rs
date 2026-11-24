//! 引擎产出的每个应答记一条 INFO 应答记录，快速路径的也算；它不是送达回执。没等到应答就被取消的请求记另一种事件（以错误
//! 结束的客户端请求也有应答：SERVFAIL）；重试和后台刷新不是给客户端的应答，不记。
//! One INFO response record per answer produced by the engine, including fast paths.
//! This is not a delivery receipt. A request cancelled before its answer uses a separate
//! event (a client request ending in an error still has one: SERVFAIL); retries and
//! background refresh are not client responses.
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::RecordType;
use hickory_proto::serialize::binary::BinDecodable;

#[derive(Default)]
pub(crate) struct ResponseInfo {
    pub pipeline: Option<Arc<str>>,
    pub upstream: Option<Source>,
    pub cache_hit: bool,
}

/// 应答从哪里来，记在响应日志的 upstream 里。规则给的、等到的两种是固定的名字，不必每个请求都为它分配一个 `Arc<str>`
/// Where an answer came from, the upstream of the response record. The two of the rules and
/// of a wait are fixed names, with no `Arc<str>` to allocate for them on every request
pub(crate) enum Source {
    /// 规则给的本地应答 / A local answer the rules gave
    Static,
    /// 等到的别人那次同样的转发的应答 / The answer of the same forward another made, waited on
    Inflight,
    /// 作答的上游 / The upstream that answered
    Upstream(Arc<str>),
}

impl Source {
    fn as_str(&self) -> &str {
        match self {
            Self::Static => "static",
            Self::Inflight => "inflight",
            Self::Upstream(upstream) => upstream,
        }
    }
}

impl ResponseInfo {
    /// 应答取自缓存的 `hit`：来源记成它的上游，规则给的本地应答记成 [`Source::Static`]
    /// The answer comes from the cached `hit`: its upstream is the source, or
    /// [`Source::Static`] for a local answer the rules gave
    pub(crate) fn served_from_cache(&mut self, hit: &crate::cache::CacheEntry) {
        self.cache_hit = true;
        self.upstream = Some(
            hit.upstream
                .clone()
                .map_or(Source::Static, Source::Upstream),
        );
    }
}

pub(crate) struct ResponseLog<'a> {
    pub info: ResponseInfo,
    qname: &'a str,
    qtype: RecordType,
    peer: SocketAddr,
    start: Instant,
    enabled: bool,
    rcode: Option<ResponseCode>,
    answered: bool,
}

impl<'a> ResponseLog<'a> {
    pub fn new(
        qname: &'a str,
        qtype: RecordType,
        peer: SocketAddr,
        pipeline: Arc<str>,
        start: Instant,
        background: bool,
    ) -> Self {
        Self::with_pipeline(qname, qtype, peer, || pipeline, start, background)
    }

    /// 同 [`Self::new`]，这条日志不写时不去要 Pipeline 的名字：要一次就是所有核都写的引用计数加减各一次
    /// As [`Self::new`], not asking for the pipeline's name when this record will not be written: asking
    /// takes the reference count every core writes up and down once
    pub fn with_pipeline(
        qname: &'a str,
        qtype: RecordType,
        peer: SocketAddr,
        pipeline: impl FnOnce() -> Arc<str>,
        start: Instant,
        background: bool,
    ) -> Self {
        let enabled = !background
            && tracing::enabled!(target: "kixdns::engine::phases", tracing::Level::INFO);
        Self {
            info: ResponseInfo {
                pipeline: enabled.then(pipeline),
                ..Default::default()
            },
            qname,
            qtype,
            peer,
            start,
            enabled,
            // No response exists yet; never infer an RCODE from a dropped future.
            rcode: None,
            answered: false,
        }
    }

    pub fn answered(&mut self, bytes: &[u8]) {
        if !self.enabled {
            return;
        }
        self.rcode = crate::proto_utils::parse_response_quick(bytes)
            .map(|response| response.rcode)
            .or_else(|| {
                Message::from_bytes(bytes)
                    .ok()
                    .map(|message| message.metadata.response_code)
            });
        // An answer exists even if it does not parse as DNS.
        self.answered = true;
    }
}

impl Drop for ResponseLog<'_> {
    fn drop(&mut self) {
        if !self.enabled {
            return;
        }
        let rcode = self
            .rcode
            .map(|code| crate::observe::rcode_name(code.into()));
        // Keep the existing target so deployed RUST_LOG filters still work.
        tracing::info!(
            target: "kixdns::engine::phases",
            event = if self.answered { "dns_response" } else { "dns_request_finished" },
            qname = %self.qname,
            qtype = ?self.qtype,
            client_ip = %self.peer.ip(),
            pipeline = self.info.pipeline.as_deref().unwrap_or(""),
            upstream = self.info.upstream.as_ref().map_or("", Source::as_str),
            rcode = rcode.as_deref(),
            cache_hit = self.info.cache_hit,
            latency_ms = self.start.elapsed().as_millis() as u64,
            status = if self.answered { "completed" } else { "cancelled" },
            "client request finished"
        );
    }
}
