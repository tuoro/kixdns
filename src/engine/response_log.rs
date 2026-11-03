//! One INFO response record per answer produced by the engine, including fast paths.
//! This is not a delivery receipt. Failed/cancelled requests use a separate event;
//! retries and background refresh are not client responses.
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::RecordType;
use hickory_proto::serialize::binary::BinDecodable;

#[derive(Default)]
pub(crate) struct ResponseInfo {
    pub pipeline: Option<Arc<str>>,
    pub upstream: Option<Arc<str>>,
    pub cache_hit: bool,
}

impl ResponseInfo {
    /// 应答取自缓存的 `hit`：来源记成它的上游，规则给的本地应答记成 "static"
    /// The answer comes from the cached `hit`: its upstream is the source, or "static"
    /// for a local answer the rules gave
    pub(crate) fn served_from_cache(&mut self, hit: &crate::cache::CacheEntry) {
        self.cache_hit = true;
        self.upstream = Some(hit.upstream.clone().unwrap_or_else(|| Arc::from("static")));
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
    status: &'static str,
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
            status: "cancelled",
        }
    }

    /// 这条日志会写下来；不写的话不必为它准备什么 / This record will be written; otherwise nothing need be
    /// prepared for it
    pub fn is_enabled(&self) -> bool {
        self.enabled
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
        self.status = "completed";
    }

    pub fn finish(&mut self, result: &anyhow::Result<Bytes>) {
        match result {
            Ok(bytes) => self.answered(bytes),
            Err(_) => self.status = "failed",
        }
    }
}

impl Drop for ResponseLog<'_> {
    fn drop(&mut self) {
        if !self.enabled {
            return;
        }
        // 头部和 OPT 合起来的 16 只会是 BADVERS（TSIG 的 BADSIG 写在 TSIG 记录里，头部是 NOTAUTH），
        // hickory 却把它读成 BADSIG
        // 16 from the header and the OPT together can only be BADVERS (TSIG's BADSIG goes in
        // the TSIG record, with NOTAUTH in the header), which hickory reads as BADSIG
        let rcode = self.rcode.map(|code| match u16::from(code) {
            16 => "BADVERS".to_owned(),
            _ => format!("{code:?}"),
        });
        // Keep the existing target so deployed RUST_LOG filters still work.
        tracing::info!(
            target: "kixdns::engine::phases",
            event = if self.answered { "dns_response" } else { "dns_request_finished" },
            qname = %self.qname,
            qtype = ?self.qtype,
            client_ip = %self.peer.ip(),
            pipeline = self.info.pipeline.as_deref().unwrap_or(""),
            upstream = self.info.upstream.as_deref().unwrap_or(""),
            rcode = rcode.as_deref(),
            cache_hit = self.info.cache_hit,
            latency_ms = self.start.elapsed().as_millis() as u64,
            status = self.status,
            "client request finished"
        );
    }
}
